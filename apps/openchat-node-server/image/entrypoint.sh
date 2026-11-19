#!/bin/sh
set -eu

OPENCHAT_DIR="${OPENCHAT_DIR:-/var/lib/openchat}"
OPENCHAT_PORT="${OPENCHAT_PORT:-4433}"
OPENCHAT_TLS_PORT="${OPENCHAT_TLS_PORT:-8443}"
OPENCHAT_SNI_DONOR="${OPENCHAT_SNI_DONOR:-yastatic.net}"
OPENCHAT_STRICT_NOISE="${OPENCHAT_STRICT_NOISE:-true}"
OPENCHAT_PIN="${OPENCHAT_PIN:-auto}"
OPENCHAT_ENABLE_TG="${OPENCHAT_ENABLE_TG:-false}"
OPENCHAT_SPONSOR="${OPENCHAT_SPONSOR:-@openchat_freedom}"
OPENCHAT_PUSH_GATEWAY_URL="${OPENCHAT_PUSH_GATEWAY_URL:-none}"

mkdir -p "$OPENCHAT_DIR"

if [ "$OPENCHAT_PIN" = "auto" ] || [ -z "$OPENCHAT_PIN" ]; then
    PIN_FILE="$OPENCHAT_DIR/.node_pin"
    if [ -s "$PIN_FILE" ]; then
        NODE_PIN="$(tr -d ' \r\n' < "$PIN_FILE")"
    else
        RAW_HEX="$(od -An -tx1 -N4 /dev/urandom | tr -d ' \n')"
        RAW_NUM="$(printf '%u' "0x$RAW_HEX" 2>/dev/null || echo 778899)"
        NODE_PIN="$(printf '%06d' $((RAW_NUM % 1000000)))"
        printf '%s\n' "$NODE_PIN" > "$PIN_FILE"
        chmod 600 "$PIN_FILE"
        echo "[openchat-node-server] Generated persistent node PIN in $PIN_FILE"
    fi
else
    NODE_PIN="$OPENCHAT_PIN"
fi

chown -R openchat:openchat "$OPENCHAT_DIR"
chmod 700 "$OPENCHAT_DIR"

export OPENCHAT_DIR OPENCHAT_PORT OPENCHAT_TLS_PORT OPENCHAT_SNI_DONOR OPENCHAT_STRICT_NOISE NODE_PIN OPENCHAT_ENABLE_TG OPENCHAT_SPONSOR

if [ -n "${OPENCHAT_PUSH_GATEWAY_URL:-}" ] && [ "${OPENCHAT_PUSH_GATEWAY_URL}" != "none" ]; then
    export OPENCHAT_PUSH_GATEWAY_URL
else
    unset OPENCHAT_PUSH_GATEWAY_URL 2>/dev/null || true
fi

exec su -s /bin/sh openchat -c '
set -- \
    -dir "$OPENCHAT_DIR" \
    -rendezvous-port "$OPENCHAT_PORT" \
    -tls-port "$OPENCHAT_TLS_PORT" \
    -sni-donor "$OPENCHAT_SNI_DONOR" \
    -strict-noise="$OPENCHAT_STRICT_NOISE" \
    -pin "$NODE_PIN" \
    -enable-tg-gateway="$OPENCHAT_ENABLE_TG" \
    -sponsor "$OPENCHAT_SPONSOR"
if [ -n "${OPENCHAT_PUSH_GATEWAY_URL:-}" ]; then
    set -- "$@" -push-gateway "$OPENCHAT_PUSH_GATEWAY_URL"
fi
exec /app/openchat-node "$@"
'
