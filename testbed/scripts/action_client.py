"""조치 API 시험 클라이언트 — action-probe 컨테이너(조치망 전용)에서만 실행한다.

출력은 한 줄 JSON {"http_status": ..., "body": ...}. 토큰은 출력하지 않는다.
  raw <METHOD> <path> [json]                 직접 HTTP 요청(상태 코드 확인용)
  badtoken <path>                            틀린 토큰으로 GET
  block <aid> <target> <+초|UTC> <incident> <approver>
  get <aid> | release <aid>
  b-block / b-get / b-release (같은 인자)     B의 src/soc/incident_service.ActionApiClient 사용(읽기 전용 마운트)
  serve                                      표준입력 한 줄 = 위 명령 하나. CPU 상한(0.05)에서 Python 재시작을 피한다.
"""
import datetime as dt
import json
import os
import sys
import urllib.error
import urllib.request

URL = os.environ["GW_ACTION_URL"].rstrip("/")
TOKEN = os.environ["GW_ACTION_TOKEN"]


def call(method, path, body=None, token=TOKEN):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(URL + path, data=data, method=method,
                                 headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or "{}")


def expiry(arg):
    if arg.startswith("+"):
        t = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=int(arg[1:]))
        return t.strftime("%Y-%m-%dT%H:%M:%SZ")
    return arg


def b_client():
    sys.path.insert(0, "/b_src")
    from soc.incident_service import ActionApiClient  # B 소유 코드, 수정하지 않음
    return ActionApiClient(URL, TOKEN, timeout_seconds=5.0)


def main(argv):
    cmd, args = argv[0], argv[1:]
    if cmd == "raw":
        status, out = call(args[0], args[1], json.loads(args[2]) if len(args) > 2 else None)
    elif cmd == "badtoken":
        status, out = call("GET", args[0], token="x" * 48)
    elif cmd == "block":
        status, out = call("POST", "/actions/block", {
            "approval_id": args[0], "target_ip": args[1], "expires_at_utc": expiry(args[2]),
            "incident_id": args[3], "approved_by": args[4]})
    elif cmd == "get":
        status, out = call("GET", "/actions/" + args[0])
    elif cmd == "release":
        status, out = call("POST", "/actions/" + args[0] + "/release", {})
    elif cmd == "b-block":
        out = b_client().block(approval_id=args[0], target_ip=args[1], expires_at_utc=expiry(args[2]),
                               incident_id=args[3], approved_by=args[4])
        status = out.pop("http_status", "2xx")
    elif cmd == "b-get":
        out = b_client().get_status(args[0])
        status = out.pop("http_status", "2xx")
    elif cmd == "b-release":
        out = b_client().release(args[0])
        status = out.pop("http_status", "2xx")
    else:
        status, out = "client_error", {"error": "unknown command"}
    print(json.dumps({"http_status": status, "body": out}, ensure_ascii=False, separators=(",", ":")), flush=True)


def serve():
    b_client()  # B 모듈을 미리 불러 첫 요청 지연을 줄인다
    for line in sys.stdin:
        argv = line.split()
        if not argv:
            continue
        try:
            main(argv)
        except Exception as e:  # 한 명령의 실패가 시험 전체를 멈추지 않게 한 줄로 보고
            print(json.dumps({"http_status": "client_error", "body": {"error": type(e).__name__}}), flush=True)


if __name__ == "__main__":
    serve() if sys.argv[1:] == ["serve"] else main(sys.argv[1:])
