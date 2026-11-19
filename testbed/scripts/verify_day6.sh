#!/usr/bin/env bash
# 6일 차 시험: 조치 API가 금지 대상·잘못된 요청을 실제로 거부하고 규칙을 만들지 않는지 확인한다.
# 실제 조치 API 호출(조치망 전용 action-probe). 차단은 일어나지 않는다(거부만 기대).
# 요청 총 15건 이하(준비 조회 1 + 거부 시험 12 + 단말 접속 2), 동시성 1, 요청 간 1초 이상, 요청당 5초, 전체 120초.
set -u
export MSYS_NO_PATHCONV=1
cd "$(dirname "$0")/.."
GW=capstone-a-gateway; T=capstone-a-client-test; R=capstone-a-client-ref; P=capstone-a-action-probe
URL=https://172.28.20.5:8443/; TIP=172.28.10.11
S=$(date -u +%H%M%S); INC="INC-D6-VERIFY"; WHO="a-tester"
pass=0; fail=0; nreq=0; OUT=""
ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }
ok()  { echo "PASS $(ts) $1"; pass=$((pass+1)); }
bad() { echo "FAIL $(ts) $1"; fail=$((fail+1)); }
j() { python -c 'import sys,json
try: d=json.loads(sys.argv[1])
except ValueError: d=None
for k in sys.argv[2].split("."): d=d.get(k) if isinstance(d,dict) else None
print("" if d is None else d)' "$1" "$2"; }
nrules() { docker exec $GW iptables -S GW_BLOCK | grep -c -- '-A'; }
cleanup() { [ -n "${PROBE_PID:-}" ] && kill "$PROBE_PID" 2>/dev/null; docker compose --profile probe rm -sf action-probe >/dev/null 2>&1; }
trap cleanup EXIT
guard() { nreq=$((nreq+1)); [ $nreq -le 20 ] || { echo "ABORT: 요청 20건 초과"; exit 1; }
          [ $(( $(date +%s) - START )) -lt 120 ] || { echo "ABORT: 120초 초과"; exit 1; }; }
api() { guard; echo "$*" >&"${PROBE[1]}"; OUT=""; read -r -t 8 OUT <&"${PROBE[0]}"; sleep 1; }
web() { guard; OUT=$(docker exec "$1" curl -sS --max-time 5 --cacert /trust/root.crt -o /dev/null -w '%{http_code}' "$URL" 2>/dev/null); sleep 1; }
expect() { # 설명 HTTP코드 오류코드
  if [ "$(j "$OUT" http_status)" = "$2" ] && [ "$(j "$OUT" body.error)" = "$3" ] && [ "$(nrules)" = 0 ]; then ok "$1 → $2 $3, 규칙 0"
  else bad "$1 → 기대 $2 $3, 실제 $OUT, 규칙 $(nrules)"; fi; }

[ "$(nrules)" = 0 ] || { echo "ABORT: 이전 차단 규칙이 남아 있음"; trap - EXIT; exit 1; }
docker compose --profile probe up -d --no-deps --pull never action-probe >/dev/null 2>&1 || { echo "ABORT: 조치 클라이언트 기동 실패"; exit 1; }
for i in 1 2 3 4 5; do docker exec $P true 2>/dev/null && break; sleep 1; done
START=$(date +%s)
coproc PROBE { docker exec -i $P python -I -u /app/action_client.py serve 2>/dev/null; }
PROBE_PID=$PROBE_PID
echo "get APR-D6-WARMUP" >&"${PROBE[1]}"; W=""; read -r -t 60 W <&"${PROBE[0]}"; nreq=1
[ "$(j "$W" body.error)" = not_found ] || { echo "ABORT: 조치 클라이언트 준비 실패"; exit 1; }
echo "== 시작 $(ts)"

echo "== 1. 금지 대상 (허용 목록은 시험 단말 172.28.10.11 하나)"
n=0
for tgt in 172.28.10.12 172.28.10.2 172.28.20.2 172.28.20.5 172.28.20.20 10.250.30.2 10.250.29.20 172.28.10.0/24 0.0.0.0; do
  n=$((n+1)); api block "APR-D6-$S-T$n" "$tgt" +300 $INC $WHO; expect "대상 $tgt" 422 target_not_allowed
done

echo "== 2. 잘못된 형식"
api raw POST /actions/block "{\"approval_id\":\"APR-D6-$S-X1\",\"target_ip\":\"$TIP\",\"expires_at_utc\":\"2030-01-01T00:00:00+09:00\",\"incident_id\":\"$INC\",\"approved_by\":\"$WHO\"}"
expect "UTC Z가 아닌 만료 시각" 422 invalid_expiry
api raw POST /actions/block "{\"approval_id\":\"APR-../x\",\"target_ip\":\"$TIP\",\"expires_at_utc\":\"2030-01-01T00:00:00Z\",\"incident_id\":\"$INC\",\"approved_by\":\"$WHO\"}"
expect "승인 ID 형식 위반" 400 invalid_request
api raw POST /actions/block "{\"approval_id\":\"APR-D6-$S-X3\",\"target_ip\":\"$TIP\",\"expires_at_utc\":\"2030-01-01T00:00:00Z\",\"incident_id\":\"$INC\",\"approved_by\":\"a\u0020b;rm\",\"extra\":\"x\"}"
expect "허용되지 않은 필드·승인자 형식" 400 invalid_request

echo "== 3. 거부 시험 뒤에도 접속 정상 (차단 없음)"
web $T; [ "$OUT" = 200 ] && ok "시험 단말 200" || bad "시험 단말 $OUT"
web $R; [ "$OUT" = 200 ] && ok "대조 단말 200" || bad "대조 단말 $OUT"
c=$(docker exec $GW sh -c "grep -c '\"event\":\"rejected\"' /var/lib/gw-actions/audit.jsonl")
echo "   감사 기록 rejected 누적 ${c}건 (거부도 기록됨)"

echo "== 결과 $(ts) pass=$pass fail=$fail requests=$nreq elapsed=$(( $(date +%s) - START ))s"
[ "$fail" = 0 ]
