#!/usr/bin/env bash
# 3일 차 시험: Caddy HTTPS 경유, 헤더 덮어쓰기, caddy.jsonl 계약 형식, HTTPS에서의 차단/복구.
# 요청 총 13건(상한 20건 이내, 동시성 1, 요청당 3초 타임아웃). 실제 트래픽이며 ingest_mode=live.
# 8단계는 Caddy 우회(서버 직접 접속) 차단과 단말의 우회 불가(경로 변경·외부 경로)를 확인한다.
# 단말은 Caddy 내부 CA의 공개 루트 인증서만 신뢰하며(SSL_CERT_FILE), 인증서 검증이 실제로 강제되는지도 확인한다.
set -u
export MSYS_NO_PATHCONV=1   # Windows Git Bash가 컨테이너 경로를 변환하지 않도록
GW=capstone-a-gateway; CL=capstone-a-caddy-log; T=capstone-a-client-test; R=capstone-a-client-ref
TIP=172.28.10.11; RIP=172.28.10.12; CIP=172.28.20.5
# /echo = 임시 서버(4일 차부터 / 는 ERP)
URL="https://$CIP:8443/echo"; RULE=APR-DAY3-001; HERE="$(cd "$(dirname "$0")" && pwd)"
pass=0; fail=0
ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }
ok()  { echo "PASS $(ts) $1"; pass=$((pass+1)); }
bad() { echo "FAIL $(ts) $1"; fail=$((fail+1)); }
get() { local c="$1"; shift; docker exec "$c" wget -q -O- -T 3 "$@" 2>&1; }
nlines() { docker exec "$1" sh -c "wc -l < $2 2>/dev/null || echo 0" | tr -d '[:space:]'; }
gwlines() { nlines $GW /var/log/gw/gateway.jsonl; }
cdlines() { nlines $CL /out/caddy.jsonl; }
chk_caddy() { # 설명 FROM TO EXPECT FORBID
  local d="$1"; shift
  if out=$(docker exec -i $CL python -I - "$@" < "$HERE/check_caddy_log.py" 2>&1); then ok "$d :: $out"; else bad "$d :: $out"; fi
}
chk_gw() { # 설명 FROM TO EXPECT [RULE]
  local d="$1"; shift
  if out=$(docker exec -i $GW python3 - "$@" < "$HERE/check_gateway_log.py" 2>&1); then ok "$d :: $out"; else bad "$d :: $out"; fi
}
gwctl() { docker exec $GW gwctl.sh "$@" 2>&1; }

docker exec $GW sh -c 'iptables -S GW_BLOCK' | grep -q -- '-A' && { echo "ABORT: 이전 차단 규칙이 남아 있음"; exit 1; }
g0=$(gwlines); c0=$(cdlines); echo "== 시작: gateway.jsonl=${g0}줄, caddy.jsonl=${c0}줄"

echo "== 1. HTTPS 경유와 서버가 본 값"
o1=$(get $T $URL); echo "test: $o1"
echo "$o1" | grep -q "^ok peer=$CIP xcip=$TIP xrid=" && ok "HTTPS 접속, 서버 peer=Caddy($CIP), X-Client-IP=실제 단말($TIP)" || bad "test HTTPS 응답 불일치"
o2=$(get $R $URL); echo "ref : $o2"
echo "$o2" | grep -q "^ok peer=$CIP xcip=$RIP xrid=" && ok "대조 단말도 HTTPS 접속, X-Client-IP=$RIP" || bad "ref HTTPS 응답 불일치"
o1b=$(docker exec -e SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt $T wget -q -O- -T 3 $URL 2>&1 || true)
echo "$o1b" | grep -q "certificate verify failed" && ok "다른 신뢰 저장소로는 인증서 검증 실패(검증이 실제로 강제됨)" || bad "인증서 검증이 강제되지 않음: $o1b"
rid=$(echo "$o1" | sed -E 's/.*xrid=//')
sleep 2
n=$(docker exec $CL grep -c "\"request_id\":\"$rid\"" /out/caddy.jsonl)
[ "$n" = 1 ] && ok "서버가 받은 X-Request-ID가 caddy.jsonl의 request_id와 일치(1건)" || bad "request_id 불일치(n=$n)"

echo "== 2. 헤더 위조 시도: 클라이언트가 보낸 값은 무시되어야 함"
o3=$(get $T --header "X-Request-ID: evil-id" --header "X-Client-IP: 6.6.6.6" $URL); echo "spoof: $o3"
echo "$o3" | grep -q "xcip=$TIP " && ok "X-Client-IP 위조(6.6.6.6) 무시, 실제 IP로 덮어씀" || bad "X-Client-IP가 덮어써지지 않음"
echo "$o3" | grep -q "xrid=evil-id" && bad "X-Request-ID 위조값이 전달됨" || ok "X-Request-ID 위조(evil-id) 무시, Caddy가 새로 생성"

echo "== 3. 평문 HTTP 거부"
o4=$(get $T "http://$CIP:8443/" || true); echo "http: ${o4:-<empty>}"
echo "$o4" | grep -q "^ok peer=" && bad "평문 HTTP로 업스트림 응답을 받음" || ok "평문 HTTP는 업스트림에 도달하지 못함"

echo "== 4. 민감 정보가 로그에 남지 않는지(쿼리, 쿠키)"
get $T --header "Cookie: sid=COOKIESECRET99" "$URL?password=QUERYSECRET77&token=TOK88" >/dev/null
sleep 2
c1=$(cdlines)
chk_caddy "caddy.jsonl 계약 형식과 금지 문자열" $((c0+1)) $c1 "$TIP=200,$RIP=200" "COOKIESECRET99,QUERYSECRET77,TOK88,evil-id,6.6.6.6"

echo "== 5. 게이트웨이 로그: 단말은 8443(Caddy)로, Caddy는 web으로 가는 연결도 게이트웨이를 지남"
g1=$(gwlines)
chk_gw "게이트웨이 허용 로그(단말->Caddy, Caddy->web)" $((g0+1)) $g1 "$TIP=fw_allow,$RIP=fw_allow,$CIP=fw_allow"
cnt=$(docker exec $GW sh -c "sed -n '$((g0+1)),\$p' /var/log/gw/gateway.jsonl | grep -c '\"dst_port\":8443'")
[ "${cnt:-0}" -ge 1 ] && ok "dst_port 8443(Caddy) 허용 기록 ${cnt}건" || bad "8443 허용 기록 없음"

echo "== 6. HTTPS 상태에서 차단 (test 단말 -> Caddy 만)"
gwctl block $TIP $CIP $RULE | grep -qx blocked && ok "block 적용" || bad "block 적용"
cd0=$(cdlines)
b0=$(docker exec $GW iptables -L GW_BLOCK -v -n -x | awk '$3=="DROP"{print $1}')
get $T $URL >/dev/null && bad "차단 중 test HTTPS 접속이 성공함" || ok "차단 중 test HTTPS 접속 실패"
b1=$(docker exec $GW iptables -L GW_BLOCK -v -n -x | awk '$3=="DROP"{print $1}')
[ "${b1:-0}" -gt "${b0:-0}" ] && ok "DROP 카운터 증가 $b0 -> $b1 (타임아웃만으로 판정하지 않음)" || bad "DROP 카운터 불변"
o5=$(get $R $URL); echo "$o5" | grep -q "^ok peer=$CIP xcip=$RIP" && ok "차단 중 ref HTTPS 접속 성공" || bad "차단 중 ref 실패"
sleep 2
c2=$(cdlines)
chk_caddy "차단된 요청은 Caddy에 도달하지 않음(ref 요청만 기록)" $((cd0+1)) $c2 "$RIP=200" ""
g2=$(gwlines)
chk_gw "차단 로그(test=deny+rule_id, ref와 Caddy=allow)" $((g1+1)) $g2 "$TIP=fw_deny,$RIP=fw_allow,$CIP=fw_allow" $RULE

echo "== 7. 해제와 복구"
gwctl unblock $TIP $CIP $RULE | grep -qx unblocked && ok "unblock" || bad "unblock"
[ "$(gwctl list | grep -c -- '-A GW_BLOCK')" = 0 ] && ok "해제 조회: 규칙 없음" || bad "해제 후 규칙 남음"
o6=$(get $T $URL); echo "$o6" | grep -q "^ok peer=$CIP xcip=$TIP" && ok "해제 후 test HTTPS 복구" || bad "해제 후 test 실패"
o7=$(get $R $URL); echo "$o7" | grep -q "^ok peer=$CIP xcip=$RIP" && ok "해제 후 ref HTTPS 접속" || bad "해제 후 ref 실패"

echo "== 8. Caddy 우회 차단(임시 HTTP 직접 접속 제거): 단말은 서버(web:8080)에 직접 접속할 수 없다"
docker exec $GW iptables -S GW_POLICY | grep -q -- "POLICY-CLIENT-CADDY-ONLY" && ok "정책 체인(GW_POLICY) 규칙 존재" || bad "정책 체인 규칙 없음"
sleep 2   # 7단계 요청의 로그가 다 기록된 뒤에 범위 시작점을 잡는다(NFLOG→ulogd→변환기 지연)
gB0=$(gwlines)
p0=$(docker exec $GW iptables -L GW_POLICY -v -n -x | awk '$3=="DROP"{print $1}')
get $T "http://172.28.20.10:8080/" | grep -q "^ok peer=" && bad "test가 web(8080)에 직접 접속함: Caddy 우회 가능" || ok "test의 web 직접 접속 차단"
get $R "http://172.28.20.10:8080/" | grep -q "^ok peer=" && bad "ref가 web(8080)에 직접 접속함: Caddy 우회 가능" || ok "ref의 web 직접 접속 차단(정책은 모든 단말에 적용)"
p1=$(docker exec $GW iptables -L GW_POLICY -v -n -x | awk '$3=="DROP"{print $1}')
[ "${p1:-0}" -gt "${p0:-0}" ] && ok "GW_POLICY DROP 카운터 증가 $p0 -> $p1 (타임아웃만으로 판정하지 않음)" || bad "GW_POLICY DROP 카운터 불변"
sleep 1
gB1=$(gwlines)
chk_gw "우회 시도가 정책 규칙으로 기록됨(fw_deny + rule_id)" $((gB0+1)) $gB1 "$TIP=fw_deny,$RIP=fw_deny" POLICY-CLIENT-CADDY-ONLY
docker exec $T ip route add 172.28.20.10 dev eth0 2>&1 | grep -qi "not permitted" && ok "단말은 경로를 바꿀 수 없다(NET_ADMIN 없음)" || bad "단말이 경로 변경을 시도할 수 있음"
[ "$(docker exec $T ip route | grep -c '^default')" = 0 ] && ok "단말에 기본 경로가 없다(외부로 나가는 경로 없음)" || bad "단말에 기본 경로가 있음"
o8=$(get $R $URL); echo "$o8" | grep -q "^ok peer=$CIP xcip=$RIP" && ok "정상 경로(Caddy HTTPS)는 그대로 동작" || bad "정상 경로가 막힘"

echo "== 결과 pass=$pass fail=$fail"; [ $fail -eq 0 ]
