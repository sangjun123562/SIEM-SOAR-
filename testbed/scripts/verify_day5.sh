#!/usr/bin/env bash
# 5일 차 시험: 조치 API(DESIGN.md 3절)로 시험 단말만 차단 → 대조 단말 정상 → 해제 → 복구.
# 실제 트래픽(ingest_mode=live). 요청 총 19건(조치 API 11 = 준비 조회 1 포함, Caddy/ERP 8). 동시성 1(유지 연결 시험의
# 대기 중 연결 1개 제외), 요청 간 1초 이상, 요청당 5초, 시험 구간 120초 상한(조치 클라이언트 기동 시간 제외).
# 조치 호출은 조치망 전용 action-probe 컨테이너에서 B의 ActionApiClient(읽기 전용)를 사용한다.
# 이 시험의 승인 ID는 사람이 실행한 격리 시험용이며 관제 앱의 사람 승인을 대체하지 않는다.
# 주의: 시험 단말(172.28.10.11)을 차단하므로 같은 단말을 쓰는 localhost:18888 브라우저 입구도 차단 중 끊긴다.
set -u
export MSYS_NO_PATHCONV=1
cd "$(dirname "$0")/.."
GW=capstone-a-gateway; T=capstone-a-client-test; R=capstone-a-client-ref; P=capstone-a-action-probe
TIP=172.28.10.11; RIP=172.28.10.12; URL=https://172.28.20.5:8443/
AID="APR-D5-$(date -u +%H%M%S)"; INC="INC-D5-VERIFY"; WHO="a-tester"
pass=0; fail=0; nreq=0; OUT=""
ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }
ok()  { echo "PASS $(ts) $1"; pass=$((pass+1)); }
bad() { echo "FAIL $(ts) $1"; fail=$((fail+1)); }
cleanup() {
  # 중간 실패 시에도 이 시험의 승인만 해제하고 시험 클라이언트만 제거한다.
  if docker exec $GW iptables -S GW_BLOCK 2>/dev/null | grep -q -- "apr:$AID"; then
    echo "CLEANUP: $AID 해제 요청"; docker exec $P python -I /app/action_client.py release "$AID" 2>/dev/null
  fi
  [ -n "${PROBE_PID:-}" ] && kill "$PROBE_PID" 2>/dev/null
  docker compose --profile probe rm -sf action-probe >/dev/null 2>&1
}
trap cleanup EXIT
guard() {
  nreq=$((nreq+1))
  [ $nreq -le 20 ] || { echo "ABORT: 요청 20건 초과"; exit 1; }
  [ $(( $(date +%s) - START )) -lt 120 ] || { echo "ABORT: 120초 초과"; exit 1; }
}
api() { guard; echo "$*" >&"${PROBE[1]}"; OUT=""; read -r -t 8 OUT <&"${PROBE[0]}"; sleep 1; }
web() { guard; OUT=$(docker exec "$1" curl -sS --max-time 5 --cacert /trust/root.crt -o /dev/null -w '%{http_code}' "$URL" 2>/dev/null); sleep 1; }
j() { python -c 'import sys,json
try: d=json.loads(sys.argv[1])
except ValueError: d=None
for k in sys.argv[2].split("."): d=d.get(k) if isinstance(d,dict) else None
print("" if d is None else d)' "$1" "$2"; }
drops() { docker exec $GW iptables -L GW_BLOCK -v -n -x | awk '$3=="DROP"{s+=$1} END{print s+0}'; }
nrules() { docker exec $GW iptables -S GW_BLOCK | grep -c -- "apr:$AID"; }
gwlines() { docker exec $GW sh -c 'wc -l < /var/log/gw/gateway.jsonl' | tr -d '[:space:]'; }

docker exec $GW iptables -S GW_BLOCK | grep -q -- '-A' && { echo "ABORT: 이전 차단 규칙이 남아 있음"; trap - EXIT; exit 1; }
docker compose --profile probe up -d --no-deps --pull never action-probe >/dev/null 2>&1 || { echo "ABORT: 조치 클라이언트 기동 실패"; exit 1; }
for i in 1 2 3 4 5; do docker exec $P true 2>/dev/null && break; sleep 1; done
# 조치 클라이언트 프로세스 하나를 유지하고 한 줄씩 명령을 보낸다(기동은 시험 시간에서 제외).
coproc PROBE { docker exec -i $P python -I -u /app/action_client.py serve 2>/dev/null; }
PROBE_PID=$PROBE_PID
echo "get APR-D5-WARMUP" >&"${PROBE[1]}"; WARM=""; read -r -t 60 WARM <&"${PROBE[0]}"; nreq=1
[ "$(j "$WARM" body.error)" = not_found ] || { echo "ABORT: 조치 클라이언트 준비 실패: $WARM"; exit 1; }
START=$(date +%s)
echo "== 시작 $(ts) approval_id=$AID"
g0=$(gwlines)

echo "== 1. 조치 API 입력 검증(차단 규칙이 생기면 안 됨)"
api badtoken /actions/$AID; [ "$(j "$OUT" http_status)" = 401 ] && [ "$(j "$OUT" body.error)" = unauthorized ] && ok "틀린 토큰 401" || bad "틀린 토큰: $OUT"
api block $AID $RIP +600 $INC $WHO; [ "$(j "$OUT" http_status)" = 422 ] && [ "$(j "$OUT" body.error)" = target_not_allowed ] && ok "대조 단말 대상 422 target_not_allowed" || bad "대조 대상: $OUT"
api block $AID $TIP +1860 $INC $WHO; [ "$(j "$OUT" http_status)" = 422 ] && [ "$(j "$OUT" body.error)" = invalid_expiry ] && ok "31분 만료 422 invalid_expiry" || bad "만료 상한: $OUT"
[ "$(docker exec $GW iptables -S GW_BLOCK | grep -c -- '-A')" = 0 ] && ok "거부된 요청으로 생긴 규칙 없음" || bad "거부 요청 후 규칙 존재"

echo "== 2. 차단 전 접속"
web $T; [ "$OUT" = 200 ] && ok "차단 전 test 200" || bad "차단 전 test: $OUT"
web $R; [ "$OUT" = 200 ] && ok "차단 전 ref 200" || bad "차단 전 ref: $OUT"

echo "== 3. 기존 연결 열기(10초 간격 2회 요청, 같은 TCP 연결 재사용)"
guard; guard
docker exec $T sh -c "curl -sS --cacert /trust/root.crt --max-time 5 --rate 1/10s -o /dev/null -o /dev/null -w '%{http_code}:%{num_connects}@%{time_total} ' $URL $URL > /tmp/keep.out 2>/dev/null; echo \"rc=\$?\" >> /tmp/keep.out" &
KEEP=$!; KSTART=$(date +%s); sleep 2

echo "== 4. B ActionApiClient로 차단 요청"
d0=$(drops)
api b-block $AID $TIP +600 $INC $WHO; echo "   $OUT"
BLOCKED_AT=$(date +%s)
[ "$(j "$OUT" body.status)" = applied ] && [ "$(j "$OUT" body.target_ip)" = $TIP ] && ok "차단 적용(applied)" || bad "차단 응답: $OUT"
EXP=$(j "$OUT" body.expires_at_utc); RID=$(j "$OUT" body.rule_id)
[ "$(nrules)" = 3 ] && ok "실제 규칙 3개(NFLOG+양방향 DROP) $RID" || bad "규칙 수 $(nrules)"
docker exec $GW iptables -S GW_BLOCK | grep -q -- "$RIP" && bad "대조 단말 규칙 존재" || ok "대조 단말 관련 규칙 없음"
api b-get $AID; [ "$(j "$OUT" body.status)" = applied ] && [ "$(j "$OUT" body.rule_present)" = True ] && ok "조회 applied rule_present=true" || bad "조회: $OUT"

echo "== 5. 차단 중 접속"
wait $KEEP; kout=$(docker exec $T cat /tmp/keep.out); echo "   keep-alive: $kout (차단은 시작 후 $((BLOCKED_AT-KSTART))초, 두 번째 요청은 약 10초)"
if [ $((BLOCKED_AT-KSTART)) -ge 9 ]; then bad "유지 연결 시험 무효: 두 번째 요청 전에 차단되지 않음"
else echo "$kout" | grep -Eq '^200:1@[0-9.]+ 000:0@' && ok "차단 전에 연 연결의 후속 요청도 차단됨(재연결 없이 실패)" || bad "기존 연결 후속 요청: $kout"; fi
web $T; [ "$OUT" = 000 ] && ok "차단 중 test 새 연결 실패(000)" || bad "차단 중 test: $OUT"
d1=$(drops); [ "$d1" -gt "$d0" ] && ok "DROP 카운터 증가 $d0 -> $d1 (타임아웃만으로 판정하지 않음)" || bad "DROP 카운터 불변 $d0 -> $d1"
web $R; [ "$OUT" = 200 ] && ok "차단 중 ref 200" || bad "차단 중 ref: $OUT"

echo "== 6. 같은 승인 재시도·다른 내용 재사용"
api block $AID $TIP "$EXP" $INC $WHO
[ "$(j "$OUT" http_status)" = 200 ] && [ "$(j "$OUT" body.expires_at_utc)" = "$EXP" ] && [ "$(nrules)" = 3 ] && ok "재시도 200, 만료 그대로($EXP), 규칙 증가 없음" || bad "재시도: $OUT"
api block $AID $TIP +900 $INC $WHO; [ "$(j "$OUT" http_status)" = 409 ] && [ "$(j "$OUT" body.error)" = approval_conflict ] && ok "다른 만료로 재사용 409 approval_conflict" || bad "충돌: $OUT"

echo "== 7. 해제와 복구"
api b-release $AID; [ "$(j "$OUT" body.status)" = released ] && ok "해제 released $(j "$OUT" body.released_at_utc)" || bad "해제: $OUT"
[ "$(nrules)" = 0 ] && ok "해제 조회: 실제 규칙 없음" || bad "해제 후 규칙 남음"
api get $AID; [ "$(j "$OUT" body.status)" = released ] && [ "$(j "$OUT" body.rule_present)" = False ] && ok "조회 released rule_present=false" || bad "해제 조회: $OUT"
web $T; [ "$OUT" = 200 ] && ok "해제 후 test 복구 200" || bad "해제 후 test: $OUT"
web $R; [ "$OUT" = 200 ] && ok "해제 후 ref 200" || bad "해제 후 ref: $OUT"
api block $AID $TIP "$EXP" $INC $WHO; [ "$(j "$OUT" http_status)" = 409 ] && [ "$(j "$OUT" body.error)" = approval_closed ] && [ "$(nrules)" = 0 ] && ok "해제된 승인 재차단 409 approval_closed" || bad "종료 승인 재차단: $OUT"

echo "== 8. 로그·감사 기록"
sleep 2
n=$(docker exec $GW sh -c "sed -n '$((g0+1)),\$p' /var/log/gw/gateway.jsonl | grep '\"event_type\":\"fw_deny\"' | grep '\"src_ip\":\"$TIP\"' | grep -c '\"rule_id\":\"$AID\"'")
[ "${n:-0}" -ge 1 ] && ok "gateway.jsonl fw_deny rule_id=$AID ${n}건" || bad "fw_deny 기록 없음"
n=$(docker exec $GW sh -c "sed -n '$((g0+1)),\$p' /var/log/gw/gateway.jsonl | grep '\"event_type\":\"fw_deny\"' | grep -c '\"src_ip\":\"$RIP\"'")
[ "${n:-1}" = 0 ] && ok "대조 단말 fw_deny 0건" || bad "대조 단말 fw_deny ${n}건"
a=$(docker exec $GW sh -c "grep -F '\"$AID\"' /var/lib/gw-actions/audit.jsonl | sed -E 's/.*\"event\":\"([a-z_]+)\".*/\1/' | tr '\n' ' '")
echo "$a" | grep -q "block_applied" && echo "$a" | grep -q "block_retry" && echo "$a" | grep -q "released" && ok "감사 기록: $a" || bad "감사 기록: $a"
leak=$(docker exec $GW sh -c 'cat /var/lib/gw-actions/audit.jsonl /var/lib/gw-actions/approvals.json /var/log/gw/gateway.jsonl | grep -c -F "$GW_ACTION_TOKEN"')
[ "$leak" = 0 ] && ok "감사·승인·게이트웨이 로그에 토큰 없음" || bad "토큰 문자열 발견(${leak}줄)"

echo "== 결과 $(ts) pass=$pass fail=$fail requests=$nreq elapsed=$(( $(date +%s) - START ))s"
[ "$fail" = 0 ]
