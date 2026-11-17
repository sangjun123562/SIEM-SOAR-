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
for p in tcp udp; do
  iptables -C FORWARD -p "$p" -m conntrack --ctstate NEW -j NFLOG --nflog-group 1 --nflog-prefix "fw_allow|-" 2>/dev/null \
    || iptables -A FORWARD -p "$p" -m conntrack --ctstate NEW -j NFLOG --nflog-group 1 --nflog-prefix "fw_allow|-"
done
echo "gateway ready"
exec ulogd -c /etc/ulogd.conf
