#!/usr/bin/env bash
# 8일 차 시험: ERP 초기화 후에도 관제 증거(raw_id)가 그대로 조회되는지 확인한다.
#   bash scripts/verify_day8.sh [백업폴더]
# 1) 실제 ERP 로그인 → 수집기가 live로 저장한 raw_id와 원본 해시를 기록
# 2) erp_reset.sh --yes 로 ERP DB만 초기화(백업 포함)
# 3) 같은 raw_id·같은 원본 내용이 관제 DB에 남아 있는지, ERP 로그 파일이 줄지 않았는지 확인
# 4) 초기화 후 다시 로그인되고 새 기록도 live로 수집되는지 확인
# 실제 트래픽. 요청 4건(로그인 2, 접속 2), 동시성 1, 요청 간 1초 이상, 요청당 5초. 차단은 없다.
set -u
export MSYS_NO_PATHCONV=1
HERE="$(cd "$(dirname "$0")" && pwd)"; cd "$HERE/.."
set -a; . ./.env; set +a
T=client-A; R=client-B; ERP=capstone-a-erp; SDB=capstone-soc-postgres; EDB=capstone-a-erp-db
BASE=https://172.28.20.5:8443
pass=0; fail=0
ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }
ok()  { echo "PASS $(ts) $1"; pass=$((pass+1)); }
bad() { echo "FAIL $(ts) $1"; fail=$((fail+1)); }
q() { docker exec $SDB psql -U soc_admin -d soc_db -Atc "$1"; }
erplines() { docker exec $ERP sh -c 'wc -l < /var/log/erp/erp.jsonl' | tr -d '[:space:]'; }
login_bob() { docker exec $T curl -sS --max-time 5 --cacert /trust/root.crt -H "Origin: $BASE" -H "Content-Type: application/json" \
  --data-binary "{\"username\":\"bob\",\"password\":\"$DEMO_PW_BOB\"}" -o /dev/null -w '%{http_code}' "$BASE/api/login" 2>/dev/null; sleep 1; }
last_rid() { docker exec $ERP sh -c 'tail -n 1 /var/log/erp/erp.jsonl' | python -c 'import sys,json; d=json.loads(sys.stdin.read()); print(d.get("request_id",""), d.get("event_type",""))'; }
wait_raw() { for i in $(seq 1 10); do r=$(q "select r.raw_id||' '||r.ingest_mode||' '||md5(r.raw_payload) from raw_logs r join normalized_events n on n.raw_id=r.raw_id where r.source='erp' and n.request_id='$1'"); [ -n "$r" ] && { echo "$r"; return 0; }; sleep 2; done; return 1; }

docker exec capstone-a-gateway iptables -S GW_BLOCK | grep -q -- '-A' && { echo "ABORT: 차단 규칙이 남아 있음"; exit 1; }
echo "== 시작 $(ts)"

echo "== 1. 초기화 전: 실제 로그인 → 관제 DB의 raw_id 기록"
c=$(login_bob); [ "$c" = 200 ] && ok "bob 로그인 200" || bad "로그인 $c"
read -r RID EV <<< "$(last_rid)"; [ "$EV" = login_success ] && ok "ERP 로그 login_success request_id=${RID:0:13}…" || bad "ERP 마지막 기록 $EV"
read -r RAW MODE HASH <<< "$(wait_raw "$RID")"
[ -n "${RAW:-}" ] && [ "$MODE" = live ] && ok "관제 DB 저장 raw_id=${RAW:0:16}… (live)" || { bad "관제 DB에서 찾지 못함"; exit 1; }
SOC0=$(q "select count(*) from raw_logs"); E0=$(erplines)
INC0=$(q "select count(*) from incidents"); APR0=$(q "select count(*) from action_approvals")
echo "   관제 raw_logs=$SOC0 incidents=$INC0 approvals=$APR0, erp.jsonl=${E0}줄"

echo "== 2. ERP 초기화 (ERP DB만)"
bash "$HERE/erp_reset.sh" --yes ${1:+"$1"} && ok "erp_reset.sh 완료" || { bad "erp_reset.sh 실패"; exit 1; }
[ "$(docker exec $EDB psql -U erp_app -d erp_db -Atc 'select count(*) from purchase_requests')" = 0 ] && ok "ERP 업무 데이터 0건 (초기화됨)" || bad "ERP 데이터 남음"

echo "== 3. 초기화 후 관제 증거 확인"
r=$(q "select ingest_mode||' '||md5(raw_payload) from raw_logs where raw_id='$RAW'")
[ "$r" = "live $HASH" ] && ok "같은 raw_id 조회, 원본 내용 해시 동일" || bad "raw_id 조회 결과: '$r'"
n=$(q "select count(*) from normalized_events where raw_id='$RAW' and request_id='$RID'"); [ "$n" = 1 ] && ok "정규화 이벤트·request_id 연결 유지" || bad "이벤트 $n"
[ "$(q "select count(*) from raw_logs")" -ge "$SOC0" ] && ok "관제 raw_logs 감소 없음" || bad "관제 raw_logs 감소"
[ "$(q "select count(*) from incidents")" -ge "$INC0" ] && [ "$(q "select count(*) from action_approvals")" -ge "$APR0" ] && ok "사건·승인 기록 감소 없음" || bad "사건·승인 기록 감소"
[ "$(erplines)" -ge "$E0" ] && ok "ERP 로그 파일 보존 ($(erplines)줄 ≥ ${E0}줄)" || bad "ERP 로그 파일이 줄어듦"

echo "== 4. 초기화 후 다시 로그인·수집"
c=$(login_bob); [ "$c" = 200 ] && ok "초기화 후 bob 로그인 200 (계정 재생성)" || bad "초기화 후 로그인 $c"
read -r RID2 EV2 <<< "$(last_rid)"
read -r RAW2 MODE2 HASH2 <<< "$(wait_raw "$RID2")"
[ -n "${RAW2:-}" ] && [ "$RAW2" != "$RAW" ] && ok "새 기록 수집 raw_id=${RAW2:0:16}… ($MODE2)" || bad "새 기록 수집 실패"
c=$(docker exec $R curl -sS --max-time 5 --cacert /trust/root.crt -o /dev/null -w '%{http_code}' "$BASE/" 2>/dev/null); sleep 1
[ "$c" = 200 ] && ok "대조 단말 200" || bad "대조 단말 $c"

echo "== 결과 $(ts) pass=$pass fail=$fail raw_id=$RAW"
[ "$fail" = 0 ]
