# Перед сборкой положите в этот каталог бинарники из репозитория ligament-relay:
#   GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X github.com/aligorov/ligament-relay/internal/buildinfo.Version=1.3.2-ros" -o relay-linux-arm64 ./cmd/relay
#   GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X github.com/aligorov/ligament-relay/internal/buildinfo.Version=1.3.2-ros" -o relay-linux-amd64 ./cmd/relay
# Затем:
#   ./scripts/ghcr-push.sh apps/ligament-relay/image ligament-relay 1
FROM alpine:3.21

ARG TARGETARCH

RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -g 1000 relay && adduser -D -u 1000 -G relay relay && \
    mkdir -p /app/config /app/data /app/keys /app/certs && \
    chown -R relay:relay /app

WORKDIR /app

COPY relay-linux-${TARGETARCH} /app/relay
COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /app/relay /entrypoint.sh

EXPOSE 1812/udp 8082/tcp
VOLUME ["/app/config", "/app/data", "/app/keys", "/app/certs"]

ENTRYPOINT ["/entrypoint.sh"]
