#!/usr/bin/env bash
# 2일 차 시험: 게이트웨이 허용·차단 로그가 계약 형식으로 파일에 남는지 (실제 트래픽, ingest_mode=live).
# 요청 총 6건(상한 20건 이내, 동시성 1). gwctl 거부 시험은 패킷을 보내지 않는다.
set -u
export MSYS_NO_PATHCONV=1   # Windows Git Bash가 컨테이너 경로를 변환하지 않도록
GW=capstone-a-gateway; T=client-A; R=client-B
TIP=172.28.10.11; RIP=172.28.10.12; CIP=172.28.20.5; WEB=$CIP; URL="https://$CIP:8443/echo"   # /echo = 임시 서버(4일 차부터 / 는 ERP)
# 3일 차 이후 단말은 Caddy(8443)로만 접속한다(WEB = 단말이 접속·차단하는 대상 = Caddy). Caddy->web 연결도 게이트웨이를 지나
# 출발지 Caddy(172.28.20.5)의 허용 기록이 함께 남으므로 기대 집합에 포함한다.
RULE=APR-DAY2-001; HERE="$(cd "$(dirname "$0")" && pwd)"
pass=0; fail=0
ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }
ok()  { echo "PASS $(ts) $1"; pass=$((pass+1)); }
bad() { echo "FAIL $(ts) $1"; fail=$((fail+1)); }
req() { docker exec "$1" wget -q -O- -T 3 "$URL" >/dev/null 2>&1; }
nlines() { docker exec $GW sh -c 'wc -l < /var/log/gw/gateway.jsonl 2>/dev/null || echo 0' | tr -d '[:space:]'; }
validate() { # 설명 FROM TO EXPECT [RULE]
  local d="$1"; shift
  if out=$(docker exec -i $GW python3 - "$@" < "$HERE/check_gateway_log.py" 2>&1); then ok "$d :: $out"; else bad "$d :: $out"; fi
}
gwctl() { docker exec $GW gwctl.sh "$@" 2>&1; }

docker exec $GW sh -c 'iptables -S GW_BLOCK' | grep -q -- '-A' && { echo "ABORT: 이전 차단 규칙이 남아 있음"; exit 1; }
n0=$(nlines); echo "== 시작 줄 수 $n0"

echo "== 1. 허용 로그"
req $T && ok "test 접속" || bad "test 접속"; req $R && ok "ref 접속" || bad "ref 접속"; sleep 1
n1=$(nlines); validate "허용 로그 형식·내용" $((n0+1)) $n1 "$TIP=fw_allow,$RIP=fw_allow,$CIP=fw_allow"

echo "== 2. 차단 로그 (test만)"
gwctl block $TIP $WEB $RULE | grep -qx blocked && ok "block 적용" || bad "block 적용"
req $T && bad "차단 중 test가 접속됨" || ok "차단 중 test 접속 실패"
req $R && ok "차단 중 ref 접속 성공" || bad "차단 중 ref 접속 실패"; sleep 1
n2=$(nlines); validate "차단 로그 형식·내용(test=deny, ref=allow, rule_id)" $((n1+1)) $n2 "$TIP=fw_deny,$RIP=fw_allow,$CIP=fw_allow" $RULE

echo "== 3. 같은 요청 재시도(멱등) 및 거부 시험(패킷 없음)"
gwctl block $TIP $WEB $RULE | grep -qx already-blocked && ok "재시도: already-blocked" || bad "재시도 응답"
[ "$(gwctl list | grep -c -- '-A GW_BLOCK')" = 2 ] && ok "규칙 수 유지(2)" || bad "규칙 수 변동"
gwctl block $RIP $WEB EVIL-1 | grep -q DENIED && ok "대조 단말 차단 거부" || bad "대조 단말 차단이 허용됨"
gwctl block "$TIP;id" $WEB X | grep -q DENIED && ok "주입 시도 거부" || bad "주입 시도 허용"
gwctl block 172.28.10.0 $WEB X | grep -q DENIED && ok "임의 주소 거부" || bad "임의 주소 허용"

echo "== 4. 해제와 복구"
gwctl unblock $TIP $WEB $RULE | grep -qx unblocked && ok "unblock" || bad "unblock"
[ "$(gwctl list | grep -c -- '-A GW_BLOCK')" = 0 ] && ok "해제 조회: 규칙 없음" || bad "해제 후 규칙 남음"
req $T && ok "해제 후 test 복구" || bad "해제 후 test 실패"; req $R && ok "해제 후 ref 접속" || bad "해제 후 ref 실패"; sleep 1
n3=$(nlines); validate "복구 허용 로그" $((n2+1)) $n3 "$TIP=fw_allow,$RIP=fw_allow,$CIP=fw_allow"

echo "== 결과 pass=$pass fail=$fail"; [ $fail -eq 0 ]
