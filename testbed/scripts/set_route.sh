#!/bin/sh
# 대상 컨테이너의 네트워크 namespace 안에서만 실행한다.
# default route를 만들지 않는다. DB망의 connected route도 보존한다.
set -eu
ROW=$(ip -o -4 addr show | awk '$4 ~ /^172\.28\.(10|20)\./ {print $2, $4; exit}')
set -- $ROW
[ "$#" -eq 2 ] || { echo "testbed interface missing" >&2; exit 1; }
DEV=$1
case "$2" in
  172.28.10.*) GW=172.28.10.2; LOCAL=172.28.10.0/24 ;;
  172.28.20.*) GW=172.28.20.2; LOCAL=172.28.20.0/24 ;;
  *) exit 1 ;;
esac
ip route replace "$GW" dev "$DEV" scope link
# 같은 서버망 내부 통신도 게이트웨이를 경유한다.
ip route replace "$LOCAL" via "$GW" dev "$DEV"
ip route replace 172.28.0.0/16 via "$GW" dev "$DEV"
echo "route set via $GW on $DEV"
