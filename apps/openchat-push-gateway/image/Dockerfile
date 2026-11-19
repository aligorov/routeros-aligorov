FROM alpine:3.20

ARG TARGETARCH

RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S openchat && adduser -S openchat -G openchat && \
    mkdir -p /var/lib/openchat-push /app/keys /app && \
    chown -R openchat:openchat /var/lib/openchat-push /app/keys /app

COPY push-gateway-linux-${TARGETARCH} /app/push-gateway
COPY entrypoint.sh /entrypoint.sh
COPY healthcheck.sh /usr/local/bin/healthcheck.sh

RUN chmod +x /app/push-gateway /entrypoint.sh /usr/local/bin/healthcheck.sh

WORKDIR /app

EXPOSE 8088/tcp

VOLUME ["/var/lib/openchat-push", "/app/keys"]

HEALTHCHECK --interval=60s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/healthcheck.sh"]

ENTRYPOINT ["/entrypoint.sh"]
