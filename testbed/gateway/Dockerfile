# 게이트웨이: alpine + iptables. 빌드(패키지 설치)는 준비 단계이며 시험 트래픽과 분리된다.
FROM alpine:3.20
RUN apk add --no-cache iptables
CMD ["sh", "-c", "echo gateway ready; exec tail -f /dev/null"]
