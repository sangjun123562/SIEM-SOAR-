"""erp.jsonl 검증기 (호스트에서 실행). B의 정규화기·탐지기(src/soc)를 그대로 사용해 end-to-end로 확인한다.

확인하는 것
1. 계약 형식: 필수 필드·타입, source=erp, ingest_mode=live, 개행으로 끝나는 완성된 줄
2. 민감 정보: 비밀번호 값(맞는 것·틀린 것)이 파일 어디에도 없고, password/cookie/token 같은 키가 없다
3. 신뢰 규칙: client_ip_trusted=true면 peer_ip가 Caddy이고 request_id가 caddy.jsonl에 있다(같은 요청 추적)
             false면 client_ip==peer_ip이고 request_id는 local- 로 시작(위조 헤더를 믿지 않음)
4. 탐지(B 규칙): 실패 4건까지는 경보 0, 5건째에 첫 경보 1, 끝까지 봐도 경보 1(다른 단말·미신뢰 실패는 따로/제외)
5. 기대 이벤트: 정상 로그인 1, 로그아웃 1, 실패 8(신뢰7+미신뢰1); 구매/결재 이벤트 없음
값(비밀번호)은 출력하지 않는다.
"""
import argparse
import json
import re
import sys

ap = argparse.ArgumentParser()
for name in ("--erp", "--caddy", "--src", "--client", "--proxy", "--untrusted-ip", "--forbid"):
    ap.add_argument(name, required=True)
for name in ("--from", "--cut4", "--cut5"):
    ap.add_argument(name, type=int, required=True)
a = ap.parse_args()
sys.stdout.reconfigure(encoding="utf-8")   # Windows 콘솔에서도 한글이 깨지지 않게
sys.path.insert(0, a.src)
from soc.detector import detect_login_failures  # noqa: E402  (B 담당 코드, 읽기만)
from soc.normalizer import normalize_log_line  # noqa: E402

errors = []
REQUIRED = {"timestamp_utc": str, "source": str, "event_type": str, "outcome": str, "ingest_mode": str,
            "request_id": str, "client_ip": str, "peer_ip": str, "client_ip_trusted": bool,
            "http_method": str, "http_path": str, "status_code": int}
OPTIONAL = {"username", "department", "role", "action", "resource_type", "resource_id", "resource_department"}
BAD_KEYS = {"password", "passwd", "cookie", "cookies", "token", "authorization", "body", "request_body"}
TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")

raw = open(a.erp, "rb").read()
if raw and not raw.endswith(b"\n"):
    errors.append("erp.jsonl이 개행으로 끝나지 않음(미완성 줄)")
text = raw.decode("utf-8")
for i, secret in enumerate([s for s in a.forbid.split(",") if s], 1):
    if secret in text:
        errors.append(f"금지 문자열 #{i}(비밀번호 값)이 erp.jsonl에 있음")
caddy_ids = set()
for line in open(a.caddy, encoding="utf-8"):
    if line.strip():
        caddy_ids.add(json.loads(line)["request_id"])

lines = text.split("\n")
if lines and lines[-1] == "":
    lines.pop()
records = []
for lineno in range(a.__dict__["from"], len(lines) + 1):
    r = json.loads(lines[lineno - 1])
    records.append((lineno, r))
    for k, t in REQUIRED.items():
        if type(r.get(k)) is not t:
            errors.append(f"줄 {lineno}: 필드 {k} 누락/타입 오류")
    if set(r) - set(REQUIRED) - OPTIONAL:
        errors.append(f"줄 {lineno}: 계약에 없는 필드 {sorted(set(r) - set(REQUIRED) - OPTIONAL)}")
    if {k.lower() for k in r} & BAD_KEYS:
        errors.append(f"줄 {lineno}: 민감 정보 키 존재")
    if r.get("source") != "erp" or r.get("ingest_mode") != "live" or r.get("outcome") not in ("success", "failure"):
        errors.append(f"줄 {lineno}: source/ingest_mode/outcome 값 오류")
    if not TS.match(str(r.get("timestamp_utc"))):
        errors.append(f"줄 {lineno}: timestamp_utc 형식 오류")
    if r.get("client_ip_trusted") is True:
        if r.get("peer_ip") != a.proxy:
            errors.append(f"줄 {lineno}: 신뢰로 표시됐는데 peer_ip가 Caddy가 아님")
        if r.get("request_id") not in caddy_ids:
            errors.append(f"줄 {lineno}: request_id가 caddy.jsonl에 없음(같은 요청 추적 실패)")
    else:
        if r.get("client_ip") != r.get("peer_ip") or not str(r.get("request_id")).startswith("local-"):
            errors.append(f"줄 {lineno}: 미신뢰 요청인데 전달 헤더를 사용함")

def count(**cond):
    return sum(1 for _, r in records if all(r.get(k) == v for k, v in cond.items()))

checks = [
    ("정상 로그인 1건(alice)", count(event_type="login_success", client_ip_trusted=True) == 1),
    ("로그인 실패 8건(test 5 + ref 2 + 미신뢰 1)", count(event_type="login_failed") == 8),
    ("test 단말 alice 실패 5건(신뢰)", count(event_type="login_failed", username="alice", client_ip=a.client, client_ip_trusted=True) == 5),
    ("미신뢰 실패 1건: client_ip=직접 연결한 쪽, 위조값(6.6.6.6) 무시",
     count(event_type="login_failed", client_ip_trusted=False, client_ip=a.untrusted_ip) == 1 and "6.6.6.6" not in text),
    ("로그아웃 1건", count(event_type="logout", username="alice") == 1),
    ("구매/결재 이벤트 생성 없음", not any(r["event_type"].startswith("purchase_") for _, r in records)),
]
for name, okay in checks:
    print(("PASS " if okay else "FAIL ") + name)
    if not okay:
        errors.append(name)

# B의 정규화기 → 탐지기
events = []
for lineno, _ in records:
    _, ev = normalize_log_line(lines[lineno - 1], source="erp", file_path="erp.jsonl", line_offset=lineno)
    events.append((lineno, ev))
def alerts_until(n):
    return detect_login_failures([ev for ln, ev in events if ln <= n])
a4, a5, a_all = alerts_until(a.cut4), alerts_until(a.cut5), alerts_until(len(lines))
det = [
    ("탐지: 실패 4건(N-1)까지 경보 0", len(a4) == 0),
    ("탐지: 5건째(N)에 첫 경보 1(alice, test 단말, 근거 5건)",
     len(a5) == 1 and a5[0].username == "alice" and a5[0].client_ip == a.client
     and a5[0].failure_count == 5 and len(a5[0].evidence_raw_ids) == 5),
    ("탐지: 끝까지 봐도 경보 1(다른 단말 2건·미신뢰 1건은 경보 안 됨)",
     len(a_all) == 1 and a5 and a_all[0].dedup_key == a5[0].dedup_key),
]
for name, okay in det:
    print(("PASS " if okay else "FAIL ") + name)
    if not okay:
        errors.append(name)
if a5:
    print(f"INFO 경보 {a5[0].alert_id} rule={a5[0].rule_id} window={a5[0].window_start_utc}~{a5[0].window_end_utc}")
print(f"INFO 검사한 줄 {len(records)}, caddy request_id {len(caddy_ids)}개")
for e in errors:
    print("ERR", e)
sys.exit(1 if errors else 0)
