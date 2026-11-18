#!/usr/bin/env bash
# 4일 차 시험: 실제 ERP 로그인·권한·업무 로그 + B의 탐지 규칙까지 end-to-end.
# 요청 총 17건(상한 20건 이내, 동시성 1, 요청마다 1초 쉼, 요청당 5초 제한). 실제 트래픽이며 ingest_mode=live.
# 시험 계정 비밀번호는 testbed/.env 에서 읽고 화면에 출력하지 않는다.
set -u
export MSYS_NO_PATHCONV=1   # Windows Git Bash가 컨테이너 경로를 변환하지 않도록
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../.." && pwd)"
[ -f "$HERE/../.env" ] || { echo "ABORT: testbed/.env 없음(scripts/init_env.sh 먼저 실행)"; exit 1; }
set -a; . "$HERE/../.env"; set +a
GW=capstone-a-gateway; T=capstone-a-client-test; R=capstone-a-client-ref; WEBC=capstone-a-web
ERP=capstone-a-erp; CL=capstone-a-caddy-log
TIP=172.28.10.11; RIP=172.28.10.12; CIP=172.28.20.5; WEBIP=172.28.20.10; ERPIP=172.28.20.20
BASE="https://$CIP:8443"; RUN=$(date +%s)
pass=0; fail=0
ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }
ok()  { echo "PASS $(ts) $1"; pass=$((pass+1)); }
bad() { echo "FAIL $(ts) $1"; fail=$((fail+1)); }
winpath() { if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else echo "$1"; fi; }
PY=""; for p in python3 python; do if $p -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1; then PY=$p; break; fi; done
[ -n "$PY" ] || { echo "ABORT: python 3.10 이상 필요"; exit 1; }

# req 컨테이너 쿠키이름 메서드 경로 [JSON] -> CODE, BODY  (Caddy 경유 HTTPS, Caddy 루트 인증서로 검증)
req() {
  local c=$1 jar="/tmp/j_${RUN}_$2" m=$3 p=$4 d=${5:-} out
  local args=(curl -sS --max-time 5 --cacert /trust/root.crt -c "$jar" -b "$jar" -H "Origin: $BASE" -X "$m" -w $'\n%{http_code}')
  [ -n "$d" ] && args+=(-H "Content-Type: application/json" --data-binary "$d")
  out=$(docker exec "$c" "${args[@]}" "$BASE$p" 2>&1)
  CODE=${out##*$'\n'}; BODY=${out%$'\n'*}
  sleep 1
}
login() { req "$1" "$2" POST /api/login "{\"username\":\"$3\",\"password\":\"$4\"}"; }
erplines() { docker exec $ERP sh -c 'wc -l < /var/log/erp/erp.jsonl 2>/dev/null || echo 0' | tr -d '[:space:]'; }
gwlines() { docker exec $GW sh -c 'wc -l < /var/log/gw/gateway.jsonl 2>/dev/null || echo 0' | tr -d '[:space:]'; }

e0=$(erplines); echo "== 시작: erp.jsonl=${e0}줄"

echo "== 1. 정상 로그인 (alice, 시험 단말, Caddy 경유)"
login $T alice alice "$DEMO_PW_ALICE"; [ "$CODE" = 200 ] && ok "alice 로그인 200" || bad "alice 로그인 $CODE"

echo "== 2. 로그인 실패 4건 (N-1): 경보가 나면 안 됨"
for i in 1 2 3 4; do
  login $T x alice "WrongPw${i}XYZ"; [ "$CODE" = 401 ] && ok "실패 $i/5 → 401" || bad "실패 $i 응답 $CODE"
done
e4=$(erplines)

echo "== 3. 5번째 실패 (N): 첫 경보"
login $T x alice "WrongPw5XYZ"; [ "$CODE" = 401 ] && ok "실패 5/5 → 401" || bad "실패 5 응답 $CODE"
e5=$(erplines)

echo "== 4. 다른 단말(대조)에서 같은 계정 실패 2건: 단말별로 따로 센다"
for i in 1 2; do login $R y alice "WrongPwRef${i}XYZ"; [ "$CODE" = 401 ] && ok "대조 단말 실패 $i → 401" || bad "대조 단말 실패 $i 응답 $CODE"; done

echo "== 5. 업무: alice(영업 사원)가 구매 요청 등록"
req $T alice POST /api/requests '{"title":"노트북","amount":1500000,"reason":"개발 장비 교체"}'
PID=$(echo "$BODY" | sed -n 's/.*"id":"\([0-9a-f-]*\)".*/\1/p')
[ "$CODE" = 201 ] && [ -n "$PID" ] && ok "등록 201 (id=$PID)" || bad "등록 $CODE"

echo "== 6. 권한 위반: carol(개발 사원)이 영업 부서 요청 열람"
login $R carol carol "$DEMO_PW_CAROL"; [ "$CODE" = 200 ] && ok "carol 로그인 200" || bad "carol 로그인 $CODE"
req $R carol GET "/api/requests/$PID"; [ "$CODE" = 403 ] && ok "타 부서 열람 거부 403" || bad "타 부서 열람 응답 $CODE"

echo "== 7. 권한 위반: alice(사원)가 자기 요청 승인 시도"
req $T alice POST "/api/requests/$PID/approve"; [ "$CODE" = 403 ] && ok "사원 승인 거부 403" || bad "사원 승인 응답 $CODE"

echo "== 8. 정상 승인: bob(영업 팀장)"
login $T bob bob "$DEMO_PW_BOB"; [ "$CODE" = 200 ] && ok "bob 로그인 200" || bad "bob 로그인 $CODE"
req $T bob POST "/api/requests/$PID/approve"; [ "$CODE" = 200 ] && ok "팀장 승인 200" || bad "팀장 승인 $CODE"
req $T bob GET /api/requests; echo "$BODY" | grep -q "\"id\":\"$PID\"" && echo "$BODY" | grep -q '"status":"approved"' && ok "팀장 목록에 승인 상태로 보임" || bad "팀장 목록 확인 실패 ($CODE)"

echo "== 9. Caddy를 거치지 않은 요청: X-Client-IP·X-Request-ID를 위조해도 믿지 않는다"
dcode=$(docker exec $WEBC python -I -c "
import json, urllib.request, urllib.error
r = urllib.request.Request('http://$ERPIP:8000/api/login', method='POST',
    data=json.dumps({'username': 'alice', 'password': 'WrongPwDirectXYZ'}).encode(),
    headers={'Content-Type': 'application/json', 'Origin': 'http://$ERPIP:8000',
             'X-Client-IP': '6.6.6.6', 'X-Request-ID': 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'})
try:
    print(urllib.request.urlopen(r, timeout=5).status)
except urllib.error.HTTPError as e:
    print(e.code)
" 2>&1); sleep 1
[ "$dcode" = 401 ] && ok "미신뢰 경로 로그인 실패 401" || bad "미신뢰 경로 응답 $dcode"

echo "== 10. 시험 단말이 ERP(8000)에 직접 접속 → 게이트웨이 정책으로 차단"
g0=$(gwlines)
dc=$(docker exec $T curl -sS --max-time 3 -o /dev/null -w '%{http_code}' "http://$ERPIP:8000/" 2>/dev/null); sleep 1
[ "$dc" = 000 ] && ok "ERP 직접 접속 실패(응답 없음)" || bad "ERP 직접 접속 응답 $dc"
sleep 1; g1=$(gwlines)
if out=$(docker exec -i $GW python3 - $((g0+1)) $g1 "$TIP=fw_deny" POLICY-CLIENT-CADDY-ONLY < "$HERE/check_gateway_log.py" 2>&1); then ok "게이트웨이 정책 차단 기록 :: $out"; else bad "게이트웨이 정책 차단 기록 :: $out"; fi

echo "== 11. 로그 검증: 형식·민감정보·신뢰 규칙·request_id 연결·B 탐지 규칙"
sleep 2
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
docker exec $ERP cat /var/log/erp/erp.jsonl > "$TMP/erp.jsonl"
docker exec $CL cat /out/caddy.jsonl > "$TMP/caddy.jsonl"
if $PY -I "$(winpath "$HERE/check_erp_log.py")" --erp "$(winpath "$TMP/erp.jsonl")" --caddy "$(winpath "$TMP/caddy.jsonl")" \
     --src "$(winpath "$ROOT/src")" --from $((e0+1)) --cut4 "$e4" --cut5 "$e5" \
     --client $TIP --proxy $CIP --untrusted-ip $WEBIP \
     --forbid "$DEMO_PW_ALICE,$DEMO_PW_BOB,$DEMO_PW_CAROL,WrongPw"; then ok "erp.jsonl 검증 통과"; else bad "erp.jsonl 검증 실패"; fi

echo "== 결과 pass=$pass fail=$fail"; [ $fail -eq 0 ]
