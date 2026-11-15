#!/bin/sh
set -eu

DOMAIN="${REALM:-turn.example.com}"
USER_NAME="${TURN_USER:-ligament}"
USER_PASS="${TURN_PASSWORD:-change-me}"
MIN_PORT="${TURN_MIN_PORT:-49152}"
MAX_PORT="${TURN_MAX_PORT:-49250}"
EXT_IP="${EXTERNAL_IP:-auto}"

mkdir -p /etc/coturn /etc/coturn/certs
if [ ! -f /etc/coturn/turnserver.conf ]; then
    cp /usr/local/share/ligament-ice/turnserver.conf /etc/coturn/turnserver.conf
    echo "[Coturn] Initialized /etc/coturn/turnserver.conf"
fi

RESOLVED_IP=""
case "$EXT_IP" in
    ""|auto|AUTO|YOUR_SERVER_PUBLIC_IPV4|none)
        if command -v detect-external-ip >/dev/null 2>&1; then
            RESOLVED_IP="$(timeout 5 detect-external-ip --ipv4 2>/dev/null || true)"
        fi
        if [ -n "$RESOLVED_IP" ]; then
            echo "[Coturn] Auto-detected external IPv4: $RESOLVED_IP"
        else
            echo "[Coturn] Notice: external IPv4 auto-detection unavailable; starting without --external-ip"
        fi
        ;;
    *)
        RESOLVED_IP="$EXT_IP"
        ;;
esac

CERT_FILE="/etc/coturn/certs/live/$DOMAIN/fullchain.pem"
KEY_FILE="/etc/coturn/certs/live/$DOMAIN/privkey.pem"

# If a real domain is configured, give certbot up to 20s on fresh install
case "$DOMAIN" in
    ""|turn.example.com|example.com|*.example.com|*.local|localhost) ;;
    *)
        i=0
        while [ $i -lt 10 ]; do
            if [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ]; then
                break
            fi
            sleep 2
            i=$((i + 1))
        done
        ;;
esac

set -- turnserver -c /etc/coturn/turnserver.conf \
    --realm="$DOMAIN" \
    --user="$USER_NAME:$USER_PASS" \
    --min-port="$MIN_PORT" \
    --max-port="$MAX_PORT"

if [ -n "$RESOLVED_IP" ]; then
    set -- "$@" --external-ip="$RESOLVED_IP"
fi

if [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ]; then
    echo "[Coturn] TLS certificates found for $DOMAIN. Starting TURNS TLS (:443, :5349) + STUN/TURN (:3478)..."
    exec "$@" \
        --tls-listening-port=443 \
        --listening-port=3478 \
        --alt-tls-listening-port=5349 \
        --cert="$CERT_FILE" \
        --pkey="$KEY_FILE"
else
    echo "[Coturn] Notice: TLS certificates not found for $DOMAIN. Starting plain STUN/TURN (:443 + :3478)..."
    exec "$@" \
        --listening-port=443 \
        --alt-listening-port=3478 \
        --tls-listening-port=0 \
        --alt-tls-listening-port=0
fi
