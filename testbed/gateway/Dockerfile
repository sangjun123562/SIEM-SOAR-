# 게이트웨이: alpine + iptables + ulogd(NFLOG 수신) + python3(계약 형식 변환).
# 빌드(패키지 설치)는 준비 단계이며 시험 트래픽과 분리된다.
FROM alpine:3.20
RUN apk add --no-cache iptables ulogd ulogd-json python3
COPY ulogd.conf /etc/ulogd.conf
COPY nflog2jsonl.py gwctl.sh gw-entry.sh actionapi.py /usr/local/bin/
RUN chmod 0755 /usr/local/bin/nflog2jsonl.py /usr/local/bin/gwctl.sh /usr/local/bin/gw-entry.sh /usr/local/bin/actionapi.py \
 && mkdir -p /var/lib/gw-actions && chmod 0700 /var/lib/gw-actions
ENV PYTHONDONTWRITEBYTECODE=1
ENTRYPOINT ["/usr/local/bin/gw-entry.sh"]
