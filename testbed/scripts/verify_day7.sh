#!/usr/bin/env bash
# 7일 차 시험: 조치 API 프로세스 재시작 시 "저장된 승인 기록 ↔ 실제 방화벽 규칙" 대조.
#  - 유효 승인 A의 규칙 일부를 사람이 지워 기록과 실제가 어긋난 상태(drift)를 만든다 → 조회가 rule_present=false로 드러내야 함
#  - 기록에 없는 고아 규칙을 넣는다
#  - 컨테이너가 아니라 조치 API 프로세스만 재시작 → A는 복원, 고아는 제거, 기록과 실제 일치
#  - 해제 후 다시 재시작해도 해제된 승인 규칙을 다시 만들지 않음
# 실제 트래픽. 요청 총 12건 이하, 동시성 1, 요청 간 1초 이상, 요청당 5초, 전체 120초.
# 주의: 약 30~40초 동안 시험 단말(172.28.10.11)이 차단되어 localhost:18888 브라우저 입구도 끊긴다.
set -u
export MSYS_NO_PATHCONV=1
cd "$(dirname "$0")/.."
GW=capstone-a-gateway; T=client-A; R=client-B; P=capstone-a-action-probe
URL=https://172.28.20.5:8443/; TIP=172.28.10.11
S=$(date -u +%H%M%S); A="APR-D7-A-$S"; ORPH="APR-D7-ORPHAN-$S"; INC="INC-D7-VERIFY"; WHO="a-tester"
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
nall() { docker exec $GW iptables -S GW_BLOCK | grep -c -- '-A'; }
listening() { docker logs $GW 2>&1 | grep -c "action api listening"; }
cleanup() {
  for id in "$A" "$ORPH"; do docker exec $GW iptables -S GW_BLOCK 2>/dev/null | grep -- "apr:$id" | sed 's/^-A/-D/' | while read -r line; do echo "CLEANUP: 규칙 제거 ($id)"; eval docker exec $GW iptables $line; done; done
  [ -n "${PROBE_PID:-}" ] && kill "$PROBE_PID" 2>/dev/null; docker compose --profile probe rm -sf action-probe >/dev/null 2>&1; }
trap cleanup EXIT
guard() { nreq=$((nreq+1)); [ $nreq -le 20 ] || { echo "ABORT: 요청 20건 초과"; exit 1; }
          [ $(( $(date +%s) - START )) -lt 120 ] || { echo "ABORT: 120초 초과"; exit 1; }; }
api() { guard; echo "$*" >&"${PROBE[1]}"; OUT=""; read -r -t 8 OUT <&"${PROBE[0]}"; sleep 1; }
web() { guard; OUT=$(docker exec "$1" curl -sS --max-time 5 --cacert /trust/root.crt -o /dev/null -w '%{http_code}' "$URL" 2>/dev/null); sleep 1; }
restart_api() { # 조치 API 프로세스만 종료 → gw-entry.sh 루프가 2초 뒤 재시작(시작 시 대조 수행)
  local before; before=$(listening)
  docker exec $GW pkill -f actionapi.py || return 1
  for i in $(seq 1 20); do [ "$(listening)" -gt "$before" ] && return 0; sleep 1; done; return 1; }
consistent() { # 저장 기록의 applied 승인 집합 == 실제 규칙의 승인 집합
  local rec rules
  rec=$(docker exec $GW python3 -c 'import json; d=json.load(open("/var/lib/gw-actions/approvals.json")); print(" ".join(sorted(k for k,v in d.items() if v["status"]=="applied")))')
  rules=$(docker exec $GW iptables -S GW_BLOCK | grep -o 'apr:APR-[A-Za-z0-9-]*' | sed 's/apr://' | sort -u | tr '\n' ' ' | sed 's/ $//')
  echo "   기록(applied)=[${rec}] 실제 규칙=[${rules}]"; [ "$rec" = "$rules" ]; }

[ "$(nall)" = 0 ] || { echo "ABORT: 이전 차단 규칙이 남아 있음"; trap - EXIT; exit 1; }
docker compose --profile probe up -d --no-deps --pull never action-probe >/dev/null 2>&1 || { echo "ABORT: 조치 클라이언트 기동 실패"; exit 1; }
for i in 1 2 3 4 5; do docker exec $P true 2>/dev/null && break; sleep 1; done
START=$(date +%s)
coproc PROBE { docker exec -i $P python -I -u /app/action_client.py serve 2>/dev/null; }
PROBE_PID=$PROBE_PID
echo "get APR-D7-WARMUP" >&"${PROBE[1]}"; W=""; read -r -t 60 W <&"${PROBE[0]}"; nreq=1
[ "$(j "$W" body.error)" = not_found ] || { echo "ABORT: 조치 클라이언트 준비 실패"; exit 1; }
echo "== 시작 $(ts) A=$A"

echo "== 1. 유효 승인 A 적용"
api block "$A" $TIP +300 $INC $WHO; [ "$(j "$OUT" http_status)" = 201 ] && [ "$(n_of "$A")" = 3 ] && ok "A 적용 201, 규칙 3" || bad "A: $OUT"

echo "== 2. 기록과 실제를 일부러 어긋나게 만듦"
docker exec $GW iptables -D GW_BLOCK -d $TIP -m comment --comment "apr:$A" -j DROP && ok "A의 응답 방향 DROP 규칙 1개를 수동 삭제(drift)" || bad "drift 생성 실패"
api get "$A"; [ "$(j "$OUT" body.status)" = applied ] && [ "$(j "$OUT" body.rule_present)" = False ] && ok "조회가 어긋남을 드러냄: applied 이지만 rule_present=false" || bad "drift 조회: $OUT"
docker exec $GW iptables -A GW_BLOCK -s $TIP -m comment --comment "apr:$ORPH" -j DROP && ok "기록에 없는 고아 규칙 추가 ($ORPH)" || bad "고아 규칙 추가 실패"
consistent && bad "어긋난 상태인데 일치로 판정됨" || ok "대조 결과 불일치 확인"

echo "== 3. 조치 API 프로세스만 재시작 (컨테이너·네트워크는 그대로)"
restart_api && ok "프로세스 재시작 완료" || bad "프로세스 재시작 실패"
docker logs --since 30s $GW 2>&1 | grep "action api reconcile" | tail -1 | sed 's/^/   /'
[ "$(n_of "$A")" = 3 ] && ok "A 규칙 3개로 복원" || bad "A 규칙 $(n_of "$A")"
[ "$(n_of "$ORPH")" = 0 ] && ok "고아 규칙 제거" || bad "고아 규칙 남음"
consistent && ok "기록 ↔ 실제 규칙 일치" || bad "기록 ↔ 실제 불일치"
api get "$A"; [ "$(j "$OUT" body.status)" = applied ] && [ "$(j "$OUT" body.rule_present)" = True ] && ok "조회 applied rule_present=true" || bad "재시작 후 조회: $OUT"
web $T; [ "$OUT" = 000 ] && ok "재시작 후에도 시험 단말 차단(000)" || bad "시험 단말 $OUT"
web $R; [ "$OUT" = 200 ] && ok "대조 단말 200" || bad "대조 단말 $OUT"

echo "== 4. 해제 후 재시작해도 해제된 승인 재생성 없음"
api release "$A"; [ "$(j "$OUT" body.status)" = released ] && [ "$(nall)" = 0 ] && ok "A 해제, 규칙 0" || bad "해제: $OUT"
restart_api && ok "프로세스 재시작 완료" || bad "프로세스 재시작 실패"
[ "$(nall)" = 0 ] && ok "재시작 후에도 규칙 0 (해제된 승인 재생성 없음)" || bad "재시작 후 규칙 $(nall)"
consistent && ok "기록 ↔ 실제 규칙 일치 (둘 다 비어 있음)" || bad "불일치"
web $T; [ "$OUT" = 200 ] && ok "시험 단말 복구 200" || bad "복구 $OUT"
web $R; [ "$OUT" = 200 ] && ok "대조 단말 200" || bad "대조 $OUT"

echo "== 결과 $(ts) pass=$pass fail=$fail requests=$nreq elapsed=$(( $(date +%s) - START ))s"
[ "$fail" = 0 ]
