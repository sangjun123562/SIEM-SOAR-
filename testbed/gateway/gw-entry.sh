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

# IP 브로드캐스트는 커널 전달 기본값(0)과 별도로, 라우팅 전 기록하고 폐기한다.
# raw PREROUTING은 커널이 FORWARD 전에 버리는 패킷도 관제 근거로 남긴다.
for spec in 'eth0 172.28.20.255' 'eth1 172.28.10.255'; do
  set -- $spec
  iface=$1 dest=$2
  iptables -t raw -C PREROUTING -i "$iface" -d "$dest" -p icmp --icmp-type echo-request \
    -j NFLOG --nflog-group 1 --nflog-prefix 'fw_deny|POLICY-ICMP-BROADCAST' 2>/dev/null \
    || iptables -t raw -A PREROUTING -i "$iface" -d "$dest" -p icmp --icmp-type echo-request \
      -j NFLOG --nflog-group 1 --nflog-prefix 'fw_deny|POLICY-ICMP-BROADCAST'
  iptables -t raw -C PREROUTING -i "$iface" -d "$dest" -p icmp --icmp-type echo-request -j DROP 2>/dev/null \
    || iptables -t raw -A PREROUTING -i "$iface" -d "$dest" -p icmp --icmp-type echo-request -j DROP
done

for p in tcp udp; do
  iptables -C FORWARD -p "$p" -m conntrack --ctstate NEW -j NFLOG --nflog-group 1 --nflog-prefix "fw_allow|-" 2>/dev/null \
    || iptables -A FORWARD -p "$p" -m conntrack --ctstate NEW -j NFLOG --nflog-group 1 --nflog-prefix "fw_allow|-"
done
# 5일 차 조치망 보호: 조치망(action_net) 인터페이스는 전달(FORWARD)하지 않는다.
# 조치 API 포트는 조치망 인터페이스·대역에서 온 연결만 받는다(바인딩 주소와 별개로 이중 검사).
ACT_IP="${GW_ACTION_BIND:-10.250.30.2}"; ACT_PORT="${GW_ACTION_PORT:-8081}"
ACT_IF=$(ip -o -4 addr show | awk -v ip="$ACT_IP" '{split($4,a,"/")} a[1]==ip {print $2; exit}')
[ -n "$ACT_IF" ] || { echo "action interface for $ACT_IP missing" >&2; exit 1; }
for dir in -i -o; do
  iptables -C FORWARD "$dir" "$ACT_IF" -j DROP 2>/dev/null || iptables -I FORWARD 1 "$dir" "$ACT_IF" -j DROP
done
iptables -C INPUT -p tcp --dport "$ACT_PORT" ! -i "$ACT_IF" -j DROP 2>/dev/null \
  || iptables -A INPUT -p tcp --dport "$ACT_PORT" ! -i "$ACT_IF" -j DROP
iptables -C INPUT -p tcp --dport "$ACT_PORT" ! -s 10.250.30.0/24 -j DROP 2>/dev/null \
  || iptables -A INPUT -p tcp --dport "$ACT_PORT" ! -s 10.250.30.0/24 -j DROP

# 조치 API: 종료되면 다시 시작한다. 시작할 때마다 승인 기록과 실제 규칙을 대조한다.
# 토큰이 없거나 짧으면 API는 시작하지 않고(종료 코드 3) 게이트웨이 전달 기능은 유지한다.
( while true; do
    rc=0; python3 -I /usr/local/bin/actionapi.py || rc=$?
    [ "$rc" -eq 3 ] && { echo "action api not started (token)" >&2; break; }
    sleep 2
  done ) &

echo "gateway ready"
exec ulogd -c /etc/ulogd.conf
