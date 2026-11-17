"""gateway.jsonl 검증기 (게이트웨이 컨테이너 안에서 stdin으로 실행).
사용: python3 - FROM TO EXPECT [DENY_RULE] < check_gateway_log.py
  FROM/TO : 검사할 줄 범위(1부터, 양끝 포함, TO가 0이면 끝까지)
  EXPECT  : "src_ip=event_type,..." 범위 안에서 관찰되어야 하는 (출발지, 이벤트) 집합과 정확히 일치해야 함
  DENY_RULE: (선택) 모든 fw_deny 줄의 rule_id
docs/log_contract.md 형식 위반이 하나라도 있으면 실패한다.
"""
import json
import re
import sys

PATH = "/var/log/gw/gateway.jsonl"
FROM, TO, EXPECT = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
DENY_RULE = sys.argv[4] if len(sys.argv) > 4 else None
REQUIRED = {"timestamp_utc": str, "source": str, "event_type": str, "outcome": str, "ingest_mode": str,
            "src_ip": str, "src_port": int, "dst_ip": str, "dst_port": int, "protocol": str, "action": str}
OPTIONAL = {"rule_id": str}
TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")
errors, seen = [], set()

raw = open(PATH, "rb").read()
if raw and not raw.endswith(b"\n"):
    errors.append("파일이 개행으로 끝나지 않음(미완성 줄)")
lines = raw.decode("utf-8").split("\n")
if lines and lines[-1] == "":
    lines.pop()
sel = lines[FROM - 1:(TO if TO else len(lines))]
if not sel:
    errors.append("검사할 줄이 없음")
for i, l in enumerate(sel, FROM):
    try:
        r = json.loads(l)
    except ValueError:
        errors.append(f"줄 {i}: JSON 아님"); continue
    for k, t in REQUIRED.items():
        if not isinstance(r.get(k), t) or isinstance(r.get(k), bool):
            errors.append(f"줄 {i}: 필드 {k} 누락/타입 오류")
    extra = set(r) - set(REQUIRED) - set(OPTIONAL)
    if extra:
        errors.append(f"줄 {i}: 계약에 없는 필드 {sorted(extra)}")
    if not TS.match(str(r.get("timestamp_utc", ""))):
        errors.append(f"줄 {i}: timestamp_utc가 UTC(Z) 형식이 아님")
    et = r.get("event_type")
    if et not in ("fw_allow", "fw_deny"):
        errors.append(f"줄 {i}: event_type 값 오류 {et}")
    want = "allow" if et == "fw_allow" else "deny"
    if not (r.get("outcome") == r.get("action") == want):
        errors.append(f"줄 {i}: outcome/action이 event_type과 불일치")
    if r.get("source") != "gateway" or r.get("ingest_mode") != "live" or r.get("protocol") not in ("TCP", "UDP"):
        errors.append(f"줄 {i}: source/ingest_mode/protocol 값 오류")
    if et == "fw_deny":
        if "rule_id" not in r:
            errors.append(f"줄 {i}: fw_deny에 rule_id 없음")
        elif DENY_RULE and r["rule_id"] != DENY_RULE:
            errors.append(f"줄 {i}: rule_id {r['rule_id']} != {DENY_RULE}")
    elif "rule_id" in r:
        errors.append(f"줄 {i}: fw_allow에 rule_id가 있음")
    seen.add((r.get("src_ip"), et))

expected = {tuple(x.split("=")) for x in EXPECT.split(",")}
if seen != expected:
    errors.append(f"관찰된 (src_ip,event_type)={sorted(seen)} != 기대={sorted(expected)}")
print(f"lines={len(sel)} seen={sorted(seen)}")
for e in errors:
    print("ERR", e)
sys.exit(1 if errors else 0)
