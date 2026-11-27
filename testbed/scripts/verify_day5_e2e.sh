#!/usr/bin/env bash
# 5일 차 완료 기준 시험(A·B 통합): ERP 로그인 실패 → live 수집 → 사건 → 담당자 로그인·승인
# → 게이트웨이가 시험 단말만 차단 → 대조 단말 정상 → 해제 → 복구.
# 실제 트래픽(live). 요청 총 20건 이하(ERP 실패 5, 단말 접속 5, 대시보드 9+CSRF 토큰 조회 1), 동시성 1, 요청 간 1초 이상,
# 요청당 5초, 전체 120초 상한. 대시보드는 127.0.0.1:8050(관제 Compose의 live profile)이 실행 중이어야 한다.
# 담당자 비밀번호는 저장소 루트 .env에서 읽어 표준입력으로만 전달하며 출력하지 않는다.
set -u
export MSYS_NO_PATHCONV=1
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../.." && pwd)"
set -a; . "$HERE/../.env"; set +a
GW=capstone-a-gateway; T=client-A; R=client-B
TIP=172.28.10.11; BASE=https://172.28.20.5:8443; DASH=http://127.0.0.1:8050
USERX=bob; RUN=$(date +%s); START=$(date +%s)
JARU="$(mktemp)"; JAR="$(cygpath -w "$JARU" 2>/dev/null || echo "$JARU")"   # Windows curl은 Windows 경로가 필요
pass=0; fail=0; nreq=0; APR=""; INC=""; CSRF=""
ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }
ok()  { echo "PASS $(ts) $1"; pass=$((pass+1)); }
bad() { echo "FAIL $(ts) $1"; fail=$((fail+1)); }
guard() { nreq=$((nreq+1)); [ $nreq -le 20 ] || { echo "ABORT: 요청 20건 초과"; exit 1; }
          [ $(( $(date +%s) - START )) -lt 120 ] || { echo "ABORT: 120초 초과"; exit 1; }; }
envval() { awk -F= -v k="$1" '$1==k{sub(/^[^=]*=/,""); print}' "$ROOT/.env"; }
web() { guard; OUT=$(docker exec "$1" curl -sS --max-time 5 --cacert /trust/root.crt -o /dev/null -w '%{http_code}' "$BASE/" 2>/dev/null); sleep 1; }
erpfail() { guard; OUT=$(docker exec $T curl -sS --max-time 5 --cacert /trust/root.crt -H "Origin: $BASE" -H "Content-Type: application/json" \
  --data-binary "{\"username\":\"$USERX\",\"password\":\"E2EWrong$1x\"}" -o /dev/null -w '%{http_code}' "$BASE/api/login" 2>/dev/null); sleep 1; }
dash() { guard; OUT=$(curl -sS --max-time 5 -b "$JAR" -c "$JAR" -o /dev/null -w '%{http_code}' "$@" 2>/dev/null); sleep 1; }
noauth() { guard; OUT=$(curl -sS --max-time 5 -o /dev/null -w '%{http_code}' "$@" 2>/dev/null); sleep 1; }   # 쿠키 없이(미로그인)
incidents() { guard; curl -sS --max-time 5 -b "$JAR" "$DASH/api/incidents" 2>/dev/null; sleep 1; }
pick() { python -c '
import sys, json
mode, since, target, user = sys.argv[1:5]
try: data = json.load(sys.stdin)
except ValueError: data = []   # 401 등 JSON이 아닌 응답은 "없음"으로 처리
def ev_ok(i): return i.get("evidence_events") and all(e.get("ingest_mode")=="live" and e.get("client_ip_trusted") is True for e in i["evidence_events"])
cands = [i for i in data if i.get("target_ip")==target and i.get("username")==user and ev_ok(i)
         and any(a.get("rule_id") == "RULE-ERP-LOGIN-BRUTE-001" for a in i.get("alerts", []))
         and max(str(e.get("event_ts_utc","")) for e in i["evidence_events"]) >= since]
if mode == "incident": print(cands[-1]["incident_id"] if cands else "")
elif mode == "approval":
    inc = [i for i in data if i["incident_id"]==sys.argv[5]]
    aps = inc[0].get("approvals", []) if inc else []
    print((aps[-1]["approval_id"] + " " + aps[-1]["status"]) if aps else "")
' "$@"; }
drops() { docker exec $GW iptables -L GW_BLOCK -v -n -x | awk '$3=="DROP"{s+=$1} END{print s+0}'; }
cleanup() {
  if [ -n "$APR" ] && docker exec $GW iptables -S GW_BLOCK 2>/dev/null | grep -q -- "apr:$APR"; then
    echo "CLEANUP: $APR 해제 요청"; curl -sS -m 5 -b "$JAR" -o /dev/null --data-urlencode "approval_id=$APR" --data-urlencode "csrf_token=$CSRF" "$DASH/incidents/$INC/release" --data-urlencode "reason=e2e verification complete"
  fi
  rm -f "$JARU" "$JARU.form"
}
trap cleanup EXIT

docker exec $GW iptables -S GW_BLOCK | grep -q -- '-A' && { echo "ABORT: 이전 차단 규칙이 남아 있음"; exit 1; }
SINCE=$(ts); echo "== 시작 $SINCE (대상 $USERX@$TIP)"

echo "== 1. 시험 단말에서 실제 ERP 로그인 실패 5건(임계값 5/300초)"
for i in 1 2 3 4 5; do
  erpfail $i
  expected=401; [ "$i" = 5 ] && expected=403  # 다섯 번째 실패는 ERP 계정 자동 잠금
  [ "$OUT" = "$expected" ] && ok "실패 $i/5 → $expected" || bad "실패 $i 응답 $OUT (예상 $expected)"
done

echo "== 2. 담당자 로그인 → live 수집 사건 조회(최대 15초 대기)"
noauth "$DASH/api/incidents"; [ "$OUT" = 401 ] && ok "미로그인 사건 API 401" || bad "미로그인 사건 API $OUT"
envval SOC_OPERATOR_PASSWORD | { read -r PW; printf 'username=%s&password=%s' "$(envval SOC_OPERATOR_USER)" "$PW"; } > "$JARU.form"
dash -X POST "$DASH/login" --data-binary "@$JAR.form"; rm -f "$JARU.form"
[ "$OUT" = 303 ] || [ "$OUT" = 302 ] && ok "담당자 로그인($OUT)" || { bad "로그인 $OUT"; exit 1; }
for i in 1 2 3; do sleep 5; INC=$(incidents | pick incident "$SINCE" $TIP $USERX); [ -n "$INC" ] && break; done
[ -n "$INC" ] && ok "새 사건 $INC (근거 전부 live·신뢰 IP)" || { bad "live 사건 없음"; exit 1; }
# 세션 바인딩 CSRF 토큰(B 16건 #11). 토큰이 없는 구버전 관제 앱이면 빈 값으로 진행한다. 요청 1건 추가.
guard; CSRF=$(curl -sS --max-time 5 -b "$JAR" "$DASH/incidents/$INC" 2>/dev/null | grep -o 'name="csrf_token" value="[^"]*"' | head -1 | sed 's/.*value="//; s/"$//'); sleep 1
[ -n "$CSRF" ] && ok "CSRF 토큰 확보(값은 출력하지 않음)" || echo "INFO $(ts) CSRF 토큰 없음(구버전 관제 앱으로 간주)"

echo "== 3. 승인 (미인증 거부 → 인증 승인)"
noauth -X POST "$DASH/incidents/$INC/approve" -d "duration_minutes=10"; [ "$OUT" = 401 ] && ok "미인증 승인 401" || bad "미인증 승인 $OUT"
[ "$(docker exec $GW iptables -S GW_BLOCK | grep -c -- '-A')" = 0 ] && ok "미인증 요청으로 규칙 생성 없음" || bad "미인증 후 규칙 존재"
d0=$(drops)
dash -X POST "$DASH/incidents/$INC/approve" -d "duration_minutes=10" --data-urlencode "csrf_token=$CSRF"
read -r APR ST <<< "$(incidents | pick approval "$SINCE" $TIP $USERX "$INC")"
[ "$ST" = applied ] && ok "승인 → 게이트웨이 applied ($APR)" || bad "승인 결과: ${APR:-없음} ${ST:-}"
n=$(docker exec $GW iptables -S GW_BLOCK | grep -c -- "apr:$APR"); [ "$n" = 3 ] && ok "실제 규칙 3개" || bad "규칙 수 $n"
docker exec $GW sh -c "grep -F '\"$APR\"' /var/lib/gw-actions/audit.jsonl | grep -q '\"peer_ip\":\"10.250.30.60\"'" && ok "감사 기록: 대시보드(10.250.30.60)가 요청" || bad "감사 기록 출처 불일치"

echo "== 4. 차단 중"
web $T; [ "$OUT" = 000 ] && ok "시험 단말 접속 실패(000)" || bad "시험 단말 $OUT"
d1=$(drops); [ "$d1" -gt "$d0" ] && ok "DROP 카운터 $d0 -> $d1" || bad "DROP 카운터 불변"
web $R; [ "$OUT" = 200 ] && ok "대조 단말 정상 200" || bad "대조 단말 $OUT"

echo "== 5. 대시보드에서 해제 → 복구"
dash -X POST "$DASH/incidents/$INC/release" --data-urlencode "approval_id=$APR" --data-urlencode "csrf_token=$CSRF" --data-urlencode "reason=e2e verification complete"
read -r _ ST <<< "$(incidents | pick approval "$SINCE" $TIP $USERX "$INC")"
[ "$ST" = released ] && ok "해제 released" || bad "해제 상태: ${ST:-없음}"
[ "$(docker exec $GW iptables -S GW_BLOCK | grep -c -- '-A')" = 0 ] && ok "규칙 0" || bad "해제 후 규칙 남음"
web $T; [ "$OUT" = 200 ] && ok "시험 단말 복구 200" || bad "복구 $OUT"
web $R; [ "$OUT" = 200 ] && ok "대조 단말 200" || bad "대조 $OUT"

echo "== 결과 $(ts) pass=$pass fail=$fail requests=$nreq elapsed=$(( $(date +%s) - START ))s incident=$INC approval=$APR"
[ "$fail" = 0 ]
