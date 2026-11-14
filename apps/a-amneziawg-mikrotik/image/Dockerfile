ARG GO_VERSION=1.25-alpine3.21
ARG ALPINE_VERSION=3.21
ARG AWG_GO_REF=v3.1.20260828
ARG AWG_TOOLS_REF=v3.1.20260812

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION} AS build-go
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
ARG AWG_GO_REF

WORKDIR /src
RUN apk add --no-cache git make bash
RUN git clone --depth=1 --branch "${AWG_GO_REF}" https://github.com/amnezia-vpn/amneziawg-go.git
RUN set -eux; \
    GOARM=""; \
    if [ "$TARGETARCH" = "arm" ]; then \
        GOARM="${TARGETVARIANT#v}"; \
    fi; \
    cd /src/amneziawg-go && \
    CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" GOARM="$GOARM" \
    GOFLAGS="-trimpath" \
    sh -c 'go build -ldflags="-s -w" -o amneziawg-go'

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION} AS build-ctl
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT

WORKDIR /src/awg-ctl
COPY awg-ctl/go.mod awg-ctl/go.sum ./
RUN go mod download
COPY awg-ctl/ ./
RUN set -eux; \
    GOARM=""; \
    if [ "$TARGETARCH" = "arm" ]; then \
        GOARM="${TARGETVARIANT#v}"; \
    fi; \
    CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" GOARM="$GOARM" \
    go build -trimpath -ldflags="-s -w" -o /tmp/awg-ctl .

FROM golang:${GO_VERSION} AS build-tools
ARG AWG_TOOLS_REF

WORKDIR /src
RUN apk add --no-cache git make bash build-base linux-headers
RUN git clone --depth=1 --branch "${AWG_TOOLS_REF}" https://github.com/amnezia-vpn/amneziawg-tools.git
RUN cd /src/amneziawg-tools/src && make && strip wg

FROM alpine:${ALPINE_VERSION}

RUN apk add --no-cache bash iptables iptables-legacy openresolv iproute2 && \
    rm -f /usr/sbin/iptables /usr/sbin/iptables-save /usr/sbin/iptables-restore && \
    ln -s /usr/sbin/iptables-legacy /usr/sbin/iptables && \
    ln -s /usr/sbin/iptables-legacy-save /usr/sbin/iptables-save && \
    ln -s /usr/sbin/iptables-legacy-restore /usr/sbin/iptables-restore && \
    rm -f /usr/sbin/ip6tables /usr/sbin/ip6tables-save /usr/sbin/ip6tables-restore && \
    ln -s /usr/sbin/ip6tables-legacy /usr/sbin/ip6tables && \
    ln -s /usr/sbin/ip6tables-legacy-save /usr/sbin/ip6tables-save && \
    ln -s /usr/sbin/ip6tables-legacy-restore /usr/sbin/ip6tables-restore && \
    mkdir -p /etc/amnezia/amneziawg /run/awg

COPY --from=build-go /src/amneziawg-go/amneziawg-go /usr/bin/amneziawg-go
COPY --from=build-ctl /tmp/awg-ctl /usr/bin/awg-ctl
COPY --from=build-tools /src/amneziawg-tools/src/wg /usr/bin/awg
COPY --from=build-tools /src/amneziawg-tools/src/wg-quick/linux.bash /usr/bin/awg-quick
COPY rt_tables /etc/iproute2/rt_tables
COPY entrypoint.sh /entrypoint.sh
COPY healthcheck.sh /usr/local/bin/healthcheck.sh

RUN chmod +x /usr/bin/amneziawg-go /usr/bin/awg-ctl /usr/bin/awg /usr/bin/awg-quick /entrypoint.sh /usr/local/bin/healthcheck.sh

ENV WG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go \
    LOG_LEVEL=error \
    AWG_AUTO_ROUTE=on \
    AWG_KILLSWITCH=on \
    DNS_ENABLE=on \
    DNS_LISTEN=:53 \
    DNS_UPSTREAM=1.1.1.1:53,8.8.8.8:53 \
    UI_LISTEN=:8080 \
    HEALTH_LISTEN=:8081 \
    AWG_HEALTH_MAX_HANDSHAKE_SEC=0 \
    TZ=UTC

EXPOSE 53/udp 53/tcp 8080/tcp 8081/tcp 51820/udp

HEALTHCHECK --interval=60s --timeout=10s --start-period=15s --retries=3 \
    CMD ["/usr/local/bin/healthcheck.sh"]

ENTRYPOINT ["/entrypoint.sh"]
