"""임시 HTTP 서버. 출발지(peer) IP와 Caddy가 전달한 X-Request-ID / X-Client-IP를 응답과 로그에 남긴다.
쿠키·Authorization·본문은 기록하지 않는다. (4일 차에 Flask ERP로 교체되는 임시 서버)"""
import json
import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        peer = self.client_address[0]
        rid = (self.headers.get("X-Request-ID") or "-")[:64]
        cip = (self.headers.get("X-Client-IP") or "-")[:64]
        body = f"ok peer={peer} xcip={cip} xrid={rid}\n".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        rec = {
            "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
            "source": "web", "peer_ip": peer, "x_client_ip": cip, "x_request_id": rid,
            "http_method": "GET", "http_path": self.path.split("?", 1)[0], "status_code": 200,
        }
        print(json.dumps(rec), flush=True)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
