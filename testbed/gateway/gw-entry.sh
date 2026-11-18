#!/bin/sh
# 게이트웨이 시작: 기본 규칙(허용 기록, 차단 체인) 적용 후 NFLOG 수신기 실행.
set -eu
mkdir -p /run/ulogd /var/log/gw
[ -p /run/ulogd/ulogd.json ] || mkfifo /run/ulogd/ulogd.json

# 변환기: ulogd JSON(FIFO) -> /var/log/gw/gateway.jsonl. ulogd 재시작 시 FIFO EOF가 나므로 반복 실행.
( while true; do python3 /usr/local/bin/nflog2jsonl.py < /run/ulogd/ulogd.json || sleep 1; done ) &

# 차단 체인(GW_BLOCK)이 먼저, 그다음 새 연결(NEW)의 허용 기록. 정책은 ACCEPT.
iptables -N GW_BLOCK 2>/dev/null || true
iptables -C FORWARD -j GW_BLOCK 2>/dev/null || iptables -I FORWARD 1 -j GW_BLOCK

# 정책 체인(GW_POLICY, 항상 가장 먼저): 단말망(172.28.10.0/24)은 Caddy(172.28.20.5:8443)로만 서버망에 접속할 수 있다.
# 그 밖의 서버망 접속(예: 임시 서버 8080 직접 접속 = Caddy 우회)은 fw_deny로 기록한 뒤 DROP한다.
# 승인으로 걸리는 차단(GW_BLOCK, gwctl)과 섞이지 않도록 체인을 분리한다.
iptables -N GW_POLICY 2>/dev/null || true
POLICY_ID="POLICY-CLIENT-CADDY-ONLY"
iptables -C GW_POLICY -s 172.28.10.0/24 -d 172.28.20.5 -p tcp --dport 8443 -j RETURN 2>/dev/null \
  || iptables -A GW_POLICY -s 172.28.10.0/24 -d 172.28.20.5 -p tcp --dport 8443 -j RETURN
iptables -C GW_POLICY -s 172.28.10.0/24 -d 172.28.20.0/24 -j NFLOG --nflog-group 1 --nflog-prefix "fw_deny|$POLICY_ID" 2>/dev/null \
  || iptables -A GW_POLICY -s 172.28.10.0/24 -d 172.28.20.0/24 -j NFLOG --nflog-group 1 --nflog-prefix "fw_deny|$POLICY_ID"
iptables -C GW_POLICY -s 172.28.10.0/24 -d 172.28.20.0/24 -j DROP 2>/dev/null \
  || iptables -A GW_POLICY -s 172.28.10.0/24 -d 172.28.20.0/24 -j DROP
iptables -C FORWARD -j GW_POLICY 2>/dev/null || iptables -I FORWARD 1 -j GW_POLICY
for p in tcp udp; do
  iptables -C FORWARD -p "$p" -m conntrack --ctstate NEW -j NFLOG --nflog-group 1 --nflog-prefix "fw_allow|-" 2>/dev/null \
    || iptables -A FORWARD -p "$p" -m conntrack --ctstate NEW -j NFLOG --nflog-group 1 --nflog-prefix "fw_allow|-"
done
echo "gateway ready"
exec ulogd -c /etc/ulogd.conf
