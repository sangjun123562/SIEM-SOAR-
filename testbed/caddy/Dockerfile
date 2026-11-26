FROM caddy:2.11.9-builder-alpine AS builder
COPY build-coraza.sh /tmp/build-coraza.sh
RUN sh /tmp/build-coraza.sh && install -m 0755 /usr/bin/caddy /tmp/caddy

FROM caddy:2.11.9-alpine
COPY --from=builder /tmp/caddy /usr/bin/caddy
