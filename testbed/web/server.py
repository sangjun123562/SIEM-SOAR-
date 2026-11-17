"""1일 차 임시 HTTP 서버. 출발지(peer) IP를 응답과 로그에 남긴다. 본문·쿠키는 기록하지 않는다."""
import json, sys, datetime
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        peer = self.client_address[0]
        body = f"ok peer={peer}\n".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        rec = {
            "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
            "source": "web", "peer_ip": peer, "http_method": "GET",
            "http_path": self.path, "status_code": 200,
        }
        print(json.dumps(rec), flush=True)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
