#!/usr/bin/env bash
# C(Mg)가 추가한 조사용 탐지 규칙 2개의 실환경 시험.
#   spray    : 같은 IP(시험 단말 .11)에서 서로 다른 계정명 3개 실패 -> MULTI-ACCOUNT 사건, 차단 승인 거부
#   multi-ip : 같은 계정명이 서로 다른 단말 3대(.11/.12/.13)에서 실패 -> MULTI-SOURCE 사건, 차단 승인 거부
# 실제 트래픽(live)만 사용한다. 요청 총 20건 이하, 동시성 1, 요청 간 1초 이상, 요청당 5초, 전체 120초 상한.
# 기대: 조사용 사건 생성 / 승인 시도는 거부 / 게이트웨이 조치 기록 증가 0 / GW_BLOCK 규칙 0 / 대조 단말 정상.
# 사용법: bash verify_mg_rules.sh spray | multi-ip
export MSYS_NO_PATHCONV=1
MODE="${1:-spray}"
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../.." && pwd)"
set -a; . "$HERE/../.env"; set +a
GW=capstone-a-gateway; T=client-A; R=client-B; X=capstone-a-client-x
BASE=https://172.28.20.5:8443; DASH=http://127.0.0.1:8050
START=$(date +%s); JARU="$(mktemp)"; JAR="$(cygpath -w "$JARU" 2>/dev/null || echo "$JARU")"
pass=0; fail=0; nreq=0; INC=""; CSRF=""
ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }
ok()  { echo "PASS $(ts) $1"; pass=$((pass+1)); }
bad() { echo "FAIL $(ts) $1"; fail=$((fail+1)); }
guard() { nreq=$((nreq+1)); [ $nreq -le 20 ] || { echo "ABORT: 요청 20건 초과"; exit 1; }
          [ $(( $(date +%s) - START )) -lt 120 ] || { echo "ABORT: 120초 초과"; exit 1; }; }
envval() { awk -F= -v k="$1" '$1==k{sub(/^[^=]*=/,""); print}' "$ROOT/.env"; }
erpfail() {  # $1=컨테이너 $2=계정명
  guard; OUT=$(docker exec "$1" curl -sS --max-time 5 --cacert /trust/root.crt -H "Origin: $BASE" -H "Content-Type: application/json" \
    --data-binary "{\"username\":\"$2\",\"password\":\"MgWrong$RANDOM\"}" -o /dev/null -w '%{http_code}' "$BASE/api/login" 2>/dev/null); sleep 1; }
web() { guard; OUT=$(docker exec "$1" curl -sS --max-time 5 --cacert /trust/root.crt -o /dev/null -w '%{http_code}' "$BASE/" 2>/dev/null); sleep 1; }
dash() { guard; OUT=$(curl -sS --max-time 5 -b "$JAR" -c "$JAR" -o /dev/null -w '%{http_code}' "$@" 2>/dev/null); sleep 1; }
incidents() { guard; curl -sS --max-time 5 -b "$JAR" "$DASH/api/incidents" 2>/dev/null; sleep 1; }
rules() { docker exec $GW iptables -S GW_BLOCK 2>/dev/null | grep -c -- '-A'; }
audit_n() { docker exec $GW sh -c 'wc -l < /var/lib/gw-actions/audit.jsonl 2>/dev/null || echo 0' | tr -d ' \r'; }
# $1=사건 제목 일부  $2=since  $3..=근거에 모두 있어야 하는 값(계정명 또는 IP). 사건 JSON 값은 출력하지 않고 id만 낸다.
pick() { python -c '
import sys, json
title, since, *need = sys.argv[1:]
try: data = json.load(sys.stdin)
except ValueError: data = []
def ev_ok(i): return i.get("evidence_events") and all(e.get("ingest_mode")=="live" and e.get("client_ip_trusted") is True for e in i["evidence_events"])
c = []
for i in data:
    t = json.dumps(i, ensure_ascii=False)
    if title in t and ev_ok(i) and all(n in t for n in need) \
       and max(str(e.get("event_ts_utc","")) for e in i["evidence_events"]) >= since:
        c.append(i["incident_id"])
print(c[-1] if c else "")
' "$@"; }
cleanup() { rm -f "$JARU" "$JARU.form"; }
trap cleanup EXIT

echo "== 시작 $(ts) 모드=$MODE"
[ "$(rules)" = 0 ] && ok "시작 전 잔여 차단 규칙 0" || { bad "시작 전 잔여 규칙 존재"; exit 1; }
A0=$(audit_n); SINCE=$(ts)
if [ "$MODE" = spray ]; then
  TITLE="RULE-ERP-LOGIN-MULTI-ACCOUNT-001"; NEED=(mgx1 mgx2 mgx3); TIP=172.28.10.11   # 영문 규칙 ID로 찾는다(Windows에서 한글 인자가 깨짐)
  echo "== 1. 시험 단말($TIP)에서 서로 다른 계정명 3개로 실제 로그인 실패"
  for u in mgx1 mgx2 mgx3; do erpfail $T $u; [ "$OUT" = 401 ] && ok "실패($u) → 401" || bad "실패($u) 응답 $OUT"; done
elif [ "$MODE" = multi-ip ]; then
  docker ps --format '{{.Names}}' | grep -qx "$X" || { echo "ABORT: $X 컨테이너 없음"; exit 1; }
  TITLE="RULE-ERP-LOGIN-MULTI-SOURCE-001"; NEED=(mgtarget 172.28.10.11 172.28.10.12 172.28.10.13); TIP=172.28.10.13
  echo "== 1. 같은 계정명(mgtarget)이 단말 3대(.11/.12/.13)에서 실제 로그인 실패"
  for c in $T $R $X; do erpfail $c mgtarget; [ "$OUT" = 401 ] && ok "실패($c) → 401" || bad "실패($c) 응답 $OUT"; done
else echo "사용법: $0 spray|multi-ip"; exit 2; fi

echo "== 2. 담당자 로그인 → 조사용 사건 조회(최대 15초 대기)"
envval SOC_OPERATOR_PASSWORD | { read -r PW; printf 'username=%s&password=%s' "$(envval SOC_OPERATOR_USER)" "$PW"; } > "$JARU.form"
dash -X POST "$DASH/login" --data-binary "@$JAR.form"; rm -f "$JARU.form"
{ [ "$OUT" = 303 ] || [ "$OUT" = 302 ]; } && ok "담당자 로그인($OUT)" || { bad "로그인 $OUT"; exit 1; }
for i in 1 2 3; do sleep 5; INC=$(incidents | pick "$TITLE" "$SINCE" "${NEED[@]}"); [ -n "$INC" ] && break; done
[ -n "$INC" ] && ok "조사용 사건 생성 $INC (근거 전부 live·신뢰 IP)" || { bad "조사용 사건 없음"; exit 1; }

echo "== 3. 조사용 사건에 차단 승인 시도 → 서버가 거부해야 함"
guard; CSRF=$(curl -sS --max-time 5 -b "$JAR" "$DASH/incidents/$INC" 2>/dev/null | grep -o 'name="csrf_token" value="[^"]*"' | head -1 | sed 's/.*value="//; s/"$//'); sleep 1
dash -X POST "$DASH/incidents/$INC/approve" -d "duration_minutes=10" --data-urlencode "csrf_token=$CSRF"
echo "INFO $(ts) 승인 POST 응답 코드 $OUT (거부는 오류 문구와 함께 사건 화면으로 되돌리는 303)"
guard; BODY=$(curl -sS --max-time 5 -b "$JAR" "$DASH/incidents/$INC" 2>/dev/null)
echo "$BODY" | grep -q "조사용" && ok "화면에 '조사용 · 차단 불가' 표시" || bad "조사용 표시 없음"
[ "$(rules)" = 0 ] && ok "승인 시도 후에도 GW_BLOCK 규칙 0" || bad "승인 시도 후 규칙 생성됨"
A1=$(audit_n); [ "$A1" = "$A0" ] && ok "게이트웨이 조치 기록 증가 0($A0→$A1): 방화벽 요청 자체가 없음" || bad "게이트웨이 조치 기록 증가($A0→$A1)"
guard; L=$(curl -sS --max-time 5 -b "$JAR" "$DASH/api/incidents" 2>/dev/null | python -c '
import sys, json
d = [i for i in json.load(sys.stdin) if i.get("incident_id") == sys.argv[1]]
print("approvals=%d" % len(d[0].get("approvals", [])) if d else "approvals=?")' "$INC" | tr -d '\r'); sleep 1
[ "$L" = "approvals=0" ] && ok "사건에 승인 기록 0건" || bad "승인 기록 확인: $L"   # 파이프 하위 셸이 아니라 본 셸에서 집계해야 fail이 종료 코드에 반영된다

echo "== 4. 대조 단말 정상"
web $R; [ "$OUT" = 200 ] && ok "대조 단말 200" || bad "대조 단말 $OUT"

echo "== 결과 $(ts) mode=$MODE pass=$pass fail=$fail requests=$nreq elapsed=$(( $(date +%s) - START ))s incident=$INC"
[ "$fail" = 0 ]
