#!/usr/bin/env bash
# 1일 차 수동 격리 시험 (사람이 직접 실행하는 시험이며 자동 승인 기능이 아님).
# 요청 총 6건: 기준 2 + 차단 중 2 + 복구 2 (상한 20건 이내, 동시성 1, 요청당 5초 이내).
# 호스트 방화벽은 건드리지 않고, 게이트웨이 컨테이너 안에서 테스트 단말 IP 하나만 차단한다.
# 3일 차 이후: 단말은 서버(web:8080)에 직접 접속할 수 없고 Caddy(HTTPS 8443)로만 접속하므로 시험 대상도 Caddy다.
set -u
GW=capstone-a-gateway; T=capstone-a-client-test; R=capstone-a-client-ref
TIP=172.28.10.11; RIP=172.28.10.12; WEB=172.28.20.5; URL="https://$WEB:8443/echo"   # WEB = 단말이 접속하는 대상(Caddy). /echo = 임시 서버(4일 차부터 / 는 ERP)
pass=0; fail=0
ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }
req() { docker exec "$1" wget -q -O- -T 3 "$URL" 2>&1; }
check() { # 설명, 기대(0=성공 기대,1=실패 기대), 컨테이너
  local out rc; out=$(req "$3"); rc=$?
  if { [ "$2" = 0 ] && [ $rc -eq 0 ]; } || { [ "$2" = 1 ] && [ $rc -ne 0 ]; }; then
    echo "PASS $(ts) $1 rc=$rc out=[$out]"; pass=$((pass+1))
  else echo "FAIL $(ts) $1 rc=$rc out=[$out]"; fail=$((fail+1)); fi
  LAST="$out"
}
rule() { docker exec $GW iptables -S FORWARD; }
echo "== 0. 사전 확인"
echo "web 네트워크 internal:"; docker network inspect capstone-a_lab_net --format '{{.Name}} internal={{.Internal}}'
rule | grep -q -- "-s $TIP" && { echo "FAIL 기존 차단 규칙이 남아 있음"; exit 1; }
echo "== 1. 기준: 두 단말 모두 성공, 서버가 본 출발지가 단말 IP(=게이트웨이 NAT 없이 경유)"
fwd0=$(docker exec $GW iptables -L FORWARD -v -n -x | head -1 | sed -E "s/.* ([0-9]+) packets.*/\1/")
check "test 접속" 0 $T; echo "$LAST" | grep -q "xcip=$TIP" && echo "PASS 서버가 본 X-Client-IP=$TIP 확인" || { echo "FAIL X-Client-IP 불일치"; fail=$((fail+1)); }
check "ref 접속" 0 $R;  echo "$LAST" | grep -q "xcip=$RIP" && echo "PASS 서버가 본 X-Client-IP=$RIP 확인" || { echo "FAIL X-Client-IP 불일치"; fail=$((fail+1)); }
fwd1=$(docker exec $GW iptables -L FORWARD -v -n -x | head -1 | sed -E "s/.* ([0-9]+) packets.*/\1/")
[ "${fwd1:-0}" -gt "${fwd0:-0}" ] && echo "PASS 게이트웨이 FORWARD 통과 패킷 증가 $fwd0 -> $fwd1 (요청·응답 경유)" || { echo "FAIL 게이트웨이 경유 증거 없음"; fail=$((fail+1)); }
echo "== 2. 수동 차단 (test 단말 IP -> web 만)"
docker exec $GW iptables -I FORWARD 1 -s $TIP -d $WEB -j DROP
echo "적용 조회:"; rule | grep -- "-s $TIP/32" && echo "PASS 규칙 적용 확인" || { echo "FAIL 규칙 없음"; fail=$((fail+1)); }
before=$(docker exec $GW iptables -L FORWARD -v -n -x | awk -v ip=$TIP '$8==ip{print $1}')
check "차단 중 test 접속 실패" 1 $T
after=$(docker exec $GW iptables -L FORWARD -v -n -x | awk -v ip=$TIP '$8==ip{print $1}')
[ "${after:-0}" -gt "${before:-0}" ] && echo "PASS DROP 패킷 카운터 증가 $before -> $after (타임아웃만으로 판정하지 않음)" || { echo "FAIL 카운터 불변"; fail=$((fail+1)); }
check "차단 중 ref 접속 성공" 0 $R
echo "== 3. 해제"
docker exec $GW iptables -D FORWARD -s $TIP -d $WEB -j DROP
rule | grep -q -- "-s $TIP/32" && { echo "FAIL 해제 후에도 규칙 존재"; fail=$((fail+1)); } || echo "PASS 해제 조회: 규칙 없음"
check "해제 후 test 복구" 0 $T
check "해제 후 ref 접속" 0 $R
echo "== 결과 pass=$pass fail=$fail"; [ $fail -eq 0 ]
