#!/usr/bin/env bash
# 5일 차 보조 시험: 만료 자동 해제와 게이트웨이 재시작 시 승인 기록↔실제 규칙 대조.
# A=유효(10분) 승인, B=짧은(20초) 승인. B 만료 후 게이트웨이를 재시작하면 A만 복원되고 B는 재생성되지 않아야 한다.
# 실제 트래픽. 요청 총 11건(조치 API 8 = 준비 조회 2 포함, Caddy/ERP 3), 동시성 1, 요청 간 1초 이상, 요청당 5초,
# 전체 120초 상한(조치 클라이언트 준비·게이트웨이 재기동 대기 포함).
# 게이트웨이 재시작은 capstone-a-gateway 하나만 대상으로 한다. 볼륨은 유지한다.
set -u
export MSYS_NO_PATHCONV=1
cd "$(dirname "$0")/.."
GW=capstone-a-gateway; T=client-A; R=client-B; P=capstone-a-action-probe
TIP=172.28.10.11; URL=https://172.28.20.5:8443/
S=$(date -u +%H%M%S); A="APR-D5L-A-$S"; B="APR-D5L-B-$S"; INC="INC-D5-LIFECYCLE"; WHO="a-tester"
pass=0; fail=0; nreq=0; OUT=""
ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }
ok()  { echo "PASS $(ts) $1"; pass=$((pass+1)); }
bad() { echo "FAIL $(ts) $1"; fail=$((fail+1)); }
j() { python -c 'import sys,json
try: d=json.loads(sys.argv[1])
except ValueError: d=None
for k in sys.argv[2].split("."): d=d.get(k) if isinstance(d,dict) else None
print("" if d is None else d)' "$1" "$2"; }
n_of() { docker exec $GW iptables -S GW_BLOCK | grep -c -- "apr:$1"; }
start_probe() {  # 0.05 CPU에서 Python 기동이 느려 준비 조회(404) 1건으로 확인한다
  coproc PROBE { docker exec -i $P python -I -u /app/action_client.py serve 2>/dev/null; }
  PROBE_PID=$PROBE_PID
  echo "get APR-D5-WARMUP" >&"${PROBE[1]}"; W=""; read -r -t 60 W <&"${PROBE[0]}"; nreq=$((nreq+1))
  [ "$(j "$W" body.error)" = not_found ] || { echo "ABORT: 조치 클라이언트 준비 실패"; exit 1; }
}
cleanup() {
  for id in "$A" "$B"; do
    if docker exec $GW iptables -S GW_BLOCK 2>/dev/null | grep -q -- "apr:$id"; then
      echo "CLEANUP: $id 해제"; docker exec $P python -I /app/action_client.py release "$id" 2>/dev/null
    fi
  done
  [ -n "${PROBE_PID:-}" ] && kill "$PROBE_PID" 2>/dev/null
  docker compose --profile probe rm -sf action-probe >/dev/null 2>&1
}
trap cleanup EXIT
guard() { nreq=$((nreq+1)); [ $nreq -le 20 ] || { echo "ABORT: 요청 20건 초과"; exit 1; }
          [ $(( $(date +%s) - START )) -lt 120 ] || { echo "ABORT: 120초 초과"; exit 1; }; }
api() { guard; echo "$*" >&"${PROBE[1]}"; OUT=""; read -r -t 8 OUT <&"${PROBE[0]}"; sleep 1; }
web() { guard; OUT=$(docker exec "$1" curl -sS --max-time 5 --cacert /trust/root.crt -o /dev/null -w '%{http_code}' "$URL" 2>/dev/null); sleep 1; }

docker exec $GW iptables -S GW_BLOCK | grep -q -- '-A' && { echo "ABORT: 이전 차단 규칙이 남아 있음"; trap - EXIT; exit 1; }
docker compose --profile probe up -d --no-deps --pull never action-probe >/dev/null 2>&1 || { echo "ABORT: 조치 클라이언트 기동 실패"; exit 1; }
for i in 1 2 3 4 5; do docker exec $P true 2>/dev/null && break; sleep 1; done
START=$(date +%s)
start_probe
echo "== 시작 $(ts) A=$A B=$B"

echo "== 1. 유효 승인 A(10분)와 짧은 승인 B(20초)"
api block "$A" $TIP +600 $INC $WHO; [ "$(j "$OUT" http_status)" = 201 ] && ok "A 적용 201" || bad "A: $OUT"
api block "$B" $TIP +20 $INC $WHO; BEXP=$(j "$OUT" body.expires_at_utc); [ "$(j "$OUT" http_status)" = 201 ] && ok "B 적용 201 만료 $BEXP" || bad "B: $OUT"
[ "$(n_of "$A")" = 3 ] && [ "$(n_of "$B")" = 3 ] && ok "실제 규칙 A3·B3" || bad "규칙 A$(n_of "$A") B$(n_of "$B")"

echo "== 2. B 만료 자동 해제(대기 약 25초, 요청 없음)"
sleep 25
[ "$(n_of "$B")" = 0 ] && [ "$(n_of "$A")" = 3 ] && ok "만료 후 B 규칙 제거, A 유지" || bad "만료 후 규칙 A$(n_of "$A") B$(n_of "$B")"
api get "$B"; [ "$(j "$OUT" body.status)" = expired ] && [ "$(j "$OUT" body.rule_present)" = False ] && ok "B 조회 expired rule_present=false" || bad "B 조회: $OUT"

echo "== 3. 게이트웨이 재시작 → 기록과 실제 규칙 대조"
kill "$PROBE_PID" 2>/dev/null; PROBE_PID=""
docker restart -t 5 $GW >/dev/null && ok "게이트웨이 재시작" || bad "게이트웨이 재시작 실패"
for i in $(seq 1 30); do docker logs --since 60s $GW 2>&1 | grep -q "action api listening" && break; sleep 1; done
docker logs --since 60s $GW 2>&1 | grep "action api reconcile" | tail -1
[ "$(n_of "$A")" = 3 ] && ok "재시작 후 유효 승인 A 복원(3규칙)" || bad "재시작 후 A 규칙 $(n_of "$A")"
[ "$(n_of "$B")" = 0 ] && ok "재시작 후 만료 승인 B 재생성 없음" || bad "재시작 후 B 규칙 $(n_of "$B")"
start_probe
api get "$A"; [ "$(j "$OUT" body.status)" = applied ] && [ "$(j "$OUT" body.rule_present)" = True ] && ok "A 조회 applied rule_present=true" || bad "A 조회: $OUT"
web $T; [ "$OUT" = 000 ] && ok "재시작 후에도 test 차단(000)" || bad "재시작 후 test: $OUT"
api block "$B" $TIP "$BEXP" $INC $WHO; [ "$(j "$OUT" body.error)" = approval_closed ] && [ "$(n_of "$B")" = 0 ] && ok "같은 내용의 만료 승인 B 재차단 409 approval_closed" || bad "B 재차단: $OUT"

echo "== 4. A 해제와 복구"
api release "$A"; [ "$(j "$OUT" body.status)" = released ] && ok "A 해제" || bad "A 해제: $OUT"
[ "$(docker exec $GW iptables -S GW_BLOCK | grep -c -- '-A')" = 0 ] && ok "GW_BLOCK 규칙 0" || bad "규칙 남음"
web $T; [ "$OUT" = 200 ] && ok "해제 후 test 200" || bad "해제 후 test: $OUT"
web $R; [ "$OUT" = 200 ] && ok "ref 200" || bad "ref: $OUT"

echo "== 결과 $(ts) pass=$pass fail=$fail requests=$nreq elapsed=$(( $(date +%s) - START ))s"
[ "$fail" = 0 ]
