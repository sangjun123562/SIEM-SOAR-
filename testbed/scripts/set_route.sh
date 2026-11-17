#!/bin/sh
# 경로 사이드카가 대상 컨테이너 안에서 실행하는 스크립트.
# 172.28.x 주소를 가진 인터페이스를 찾아, 같은 대역(172.28.0.0/16)으로 가는 경로를 게이트웨이(172.28.0.2) 경유로 바꾼다.
# 컨테이너가 네트워크를 여러 개 가져도(예: ERP는 시험망 + ERP DB망) 올바른 장치를 고른다.
# replace를 쓰므로 여러 번 실행해도 결과가 같다(멱등).
set -eu
DEV=$(ip -o -4 addr show | awk '$4 ~ /^172\.28\./ {print $2; exit}')
[ -n "$DEV" ] || { echo "172.28.x 인터페이스를 찾지 못함" >&2; exit 1; }
ip route replace 172.28.0.2 dev "$DEV" scope link
ip route replace 172.28.0.0/16 via 172.28.0.2 dev "$DEV"
echo "route set via 172.28.0.2 on $DEV"
