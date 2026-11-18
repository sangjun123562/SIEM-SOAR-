"""caddy.jsonl 검증기 (caddy-log 컨테이너 안에서 stdin으로 실행).
사용: python -I - FROM TO EXPECT FORBID < check_caddy_log.py
  FROM/TO : 검사할 줄 범위(1부터 포함, TO=0이면 끝까지)
  EXPECT  : "client_ip=status,..." 범위 안에서 관찰된 (client_ip, status_code) 집합과 정확히 일치해야 함
  FORBID  : 파일 전체에 나타나면 안 되는 문자열(쉼표 구분; 쿼리·쿠키 값이 로그에 새는지 확인)
docs/log_contract.md의 caddy 형식을 어기거나 계약에 없는 필드가 있으면 실패한다.
"""
import json
import re
import sys

PATH = "/out/caddy.jsonl"
FROM, TO, EXPECT, FORBID = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4]
REQUIRED = {"timestamp_utc": str, "source": str, "event_type": str, "outcome": str, "ingest_mode": str,
            "request_id": str, "client_ip": str, "peer_ip": str, "http_method": str, "http_path": str,
            "status_code": int}
TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
errors, seen = [], set()

raw = open(PATH, "rb").read()
if raw and not raw.endswith(b"\n"):
    errors.append("파일이 개행으로 끝나지 않음(미완성 줄)")
text = raw.decode("utf-8")
for bad in [x for x in FORBID.split(",") if x]:
    if bad in text:
        errors.append(f"금지 문자열이 로그에 있음: {bad}")
lines = text.split("\n")
if lines and lines[-1] == "":
    lines.pop()
sel = lines[FROM - 1:(TO if TO else len(lines))]
if not sel:
    errors.append("검사할 줄이 없음")
for i, l in enumerate(sel, FROM):
    try:
        r = json.loads(l)
    except ValueError:
        errors.append(f"줄 {i}: JSON 아님")
        continue
    for k, t in REQUIRED.items():
        if not isinstance(r.get(k), t) or isinstance(r.get(k), bool):
            errors.append(f"줄 {i}: 필드 {k} 누락/타입 오류")
    extra = set(r) - set(REQUIRED)
    if extra:
        errors.append(f"줄 {i}: 계약에 없는 필드 {sorted(extra)}")
    if not TS.match(str(r.get("timestamp_utc", ""))):
        errors.append(f"줄 {i}: timestamp_utc가 UTC(Z) 형식이 아님")
    if r.get("source") != "caddy" or r.get("event_type") != "http_request" or r.get("ingest_mode") != "live":
        errors.append(f"줄 {i}: source/event_type/ingest_mode 값 오류")
    sc = r.get("status_code")
    if isinstance(sc, int) and r.get("outcome") != ("success" if sc < 400 else "failure"):
        errors.append(f"줄 {i}: outcome이 status_code와 불일치")
    if not UUID.match(str(r.get("request_id", ""))):
        errors.append(f"줄 {i}: request_id가 Caddy 생성 UUID 형식이 아님(클라이언트 값이 새어 들어옴?)")
    if r.get("client_ip") != r.get("peer_ip"):
        errors.append(f"줄 {i}: client_ip != peer_ip (게이트웨이 NAT 없이 직접 연결이면 같아야 함)")
    path = str(r.get("http_path", ""))
    if not path.startswith("/") or "?" in path:
        errors.append(f"줄 {i}: http_path 형식 오류(쿼리 문자열 포함?)")
    seen.add((r.get("client_ip"), str(sc)))

expected = {tuple(x.split("=")) for x in EXPECT.split(",")}
if seen != expected:
    errors.append(f"관찰된 (client_ip,status)={sorted(seen)} != 기대={sorted(expected)}")
print(f"lines={len(sel)} seen={sorted(seen)}")
for e in errors:
    print("ERR", e)
sys.exit(1 if errors else 0)
