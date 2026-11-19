FROM alpine:3.20

ARG TARGETARCH

RUN apk add --no-cache ca-certificates tzdata libcap && \
    addgroup -S openchat && adduser -S openchat -G openchat && \
    mkdir -p /var/lib/openchat /app && \
    chown -R openchat:openchat /var/lib/openchat /app

COPY openchat-node-linux-${TARGETARCH} /app/openchat-node
COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /app/openchat-node /entrypoint.sh && \
    setcap cap_net_bind_service=+ep /app/openchat-node || true

WORKDIR /app

EXPOSE 4433/udp 8443/tcp 443/tcp 44888/udp 1080/tcp

VOLUME ["/var/lib/openchat"]

ENTRYPOINT ["/entrypoint.sh"]
