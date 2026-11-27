#!/usr/bin/env bash
# 4일 차 시험: 실제 로그인·세션·감사 로그와 탐지 함수 검증(관제 DB/UI 통합과 별도).
# 주의: 5번째 실패에서 ERP가 alice 계정을 10분 잠근다. 다시 실행하려면 대시보드에서 해제하거나 10분 기다린다.
# 요청 총 17건(상한 20건 이내, 동시성 1, 요청마다 1초 쉼, 요청당 5초 제한). 실제 트래픽이며 ingest_mode=live.
# 시험 계정 비밀번호는 testbed/.env 에서 읽고 화면에 출력하지 않는다.
set -u
export MSYS_NO_PATHCONV=1   # Windows Git Bash가 컨테이너 경로를 변환하지 않도록
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../.." && pwd)"
[ -f "$HERE/../.env" ] || { echo "ABORT: testbed/.env 없음(scripts/init_env.sh 먼저 실행)"; exit 1; }
set -a; . "$HERE/../.env"; set +a
GW=capstone-a-gateway; T=client-A; R=client-B; WEBC=capstone-a-web
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
login $T alice alice "$DEMO_PW_ALICE"
[ "$CODE" = 403 ] && { echo "ABORT: alice 계정이 잠겨 있음(이전 시험 후 10분 이내). 대시보드에서 해제하거나 10분 뒤 다시 실행"; exit 1; }
[ "$CODE" = 200 ] && ok "alice 로그인 200" || bad "alice 로그인 $CODE"

echo "== 2. 세션 조회·로그아웃·세션 해제 (잠금 시험 전에 확인: 잠기면 기존 세션이 끊김)"
req $T alice GET /api/session; [ "$CODE" = 200 ] && ok "세션 조회 200" || bad "세션 조회 $CODE"
req $T alice POST /api/logout; [ "$CODE" = 200 ] && ok "로그아웃 200" || bad "로그아웃 $CODE"
req $T alice GET /api/session; [ "$CODE" = 401 ] && ok "로그아웃 후 세션 401" || bad "로그아웃 후 세션 $CODE"

echo "== 3. 로그인 실패 4건 (N-1): 경보·잠금이 나면 안 됨"
for i in 1 2 3 4; do
  login $T x alice "WrongPw${i}XYZ"; [ "$CODE" = 401 ] && ok "실패 $i/5 → 401" || bad "실패 $i 응답 $CODE"
done
e4=$(erplines)

echo "== 4. 5번째 실패 (N): 첫 경보 + ERP가 계정을 10분 자동 잠금 (403)"
login $T x alice "WrongPw5XYZ"; [ "$CODE" = 403 ] && ok "실패 5/5 → 403(계정 자동 잠금)" || bad "실패 5 응답 $CODE"
e5=$(erplines)

echo "== 5. 다른 단말(대조)에서 같은 계정 2건: 잠금은 계정 단위라 단말이 달라도 403"
for i in 1 2; do login $R y alice "WrongPwRef${i}XYZ"; [ "$CODE" = 403 ] && ok "대조 단말 시도 $i → 403(잠긴 계정)" || bad "대조 단말 시도 $i 응답 $CODE"; done

echo "== 7. 제거한 구매·결재 API가 열리지 않는지"
req $T alice GET /api/requests; [ "$CODE" = 404 ] && ok "구매 조회 API 없음" || bad "구매 조회 $CODE"
req $T alice POST /api/requests '{}'; [ "$CODE" = 404 ] && ok "구매 생성 API 없음" || bad "구매 생성 $CODE"
req $T alice GET /api/catalog; [ "$CODE" = 404 ] && ok "품목 API 없음" || bad "품목 조회 $CODE"
req $T alice POST /api/requests/00000000-0000-0000-0000-000000000000/approve; [ "$CODE" = 404 ] && ok "결재 API 없음" || bad "결재 $CODE"

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
[ "$dcode" = 403 ] && ok "미신뢰 경로 로그인 403(허용하지 않은 출발지)" || bad "미신뢰 경로 응답 $dcode"

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
