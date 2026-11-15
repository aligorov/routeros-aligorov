#!/bin/sh
set -eu

DOMAIN="${REALM:-turn.example.com}"
EMAIL="${ACME_EMAIL:-admin@example.com}"

is_placeholder_domain() {
    case "$1" in
        ""|turn.example.com|example.com|*.example.com|*.local|localhost) return 0 ;;
        *) return 1 ;;
    esac
}

if is_placeholder_domain "$DOMAIN"; then
    echo "[Certbot] REALM='$DOMAIN' — placeholder domain. Skipping Let's Encrypt issuance until REALM is configured."
    trap 'exit 0' TERM INT
    while :; do
        sleep 3600 &
        wait $! || true
    done
fi

echo "[Certbot] Checking TLS certificates for $DOMAIN..."
if [ ! -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
    echo "[Certbot] Certificate not found. Requesting initial certificate via HTTP-01 (:80)..."
    if certbot certonly --standalone --agree-tos --non-interactive --no-eff-email \
        -m "$EMAIL" -d "$DOMAIN" --preferred-challenges http; then
        chmod -R 755 /etc/letsencrypt/live /etc/letsencrypt/archive 2>/dev/null || true
        chmod 644 "/etc/letsencrypt/live/$DOMAIN/privkey.pem" 2>/dev/null || true
        echo "[Certbot] Certificate issued for $DOMAIN."
    else
        echo "[Certbot] Warning: failed to issue certificate for $DOMAIN. Check DNS A-record and port 80/tcp."
    fi
else
    echo "[Certbot] Existing certificate found for $DOMAIN."
    chmod -R 755 /etc/letsencrypt/live /etc/letsencrypt/archive 2>/dev/null || true
    chmod 644 "/etc/letsencrypt/live/$DOMAIN/privkey.pem" 2>/dev/null || true
fi

echo "[Certbot] Starting renewal loop (every 12h)..."
trap 'exit 0' TERM INT
while :; do
    certbot renew --quiet \
        --deploy-hook "chmod -R 755 /etc/letsencrypt/live /etc/letsencrypt/archive && chmod 644 /etc/letsencrypt/live/$DOMAIN/privkey.pem" \
        || true
    sleep 43200 &
    wait $! || true
done
