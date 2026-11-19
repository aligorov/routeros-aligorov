#!/bin/sh
set -eu

PUSH_DATA_DIR="${PUSH_DATA_DIR:-/var/lib/openchat-push}"
PUSH_KEYS_DIR="${PUSH_KEYS_DIR:-/app/keys}"
PUSH_GATEWAY_PORT="${PUSH_GATEWAY_PORT:-8088}"
PUSH_CAP_KEY="${PUSH_CAP_KEY:-auto}"
APNS_KEY_PATH="${APNS_KEY_PATH:-auto}"
APNS_KEY_ID="${APNS_KEY_ID:-none}"
APNS_TEAM_ID="${APNS_TEAM_ID:-none}"
APNS_BUNDLE_ID="${APNS_BUNDLE_ID:-org.openchat.ios}"
APNS_SANDBOX="${APNS_SANDBOX:-false}"
FCM_KEY_PATH="${FCM_KEY_PATH:-auto}"

mkdir -p "$PUSH_DATA_DIR" "$PUSH_KEYS_DIR"

if [ "$PUSH_CAP_KEY" = "auto" ] || [ -z "$PUSH_CAP_KEY" ]; then
    KEY_FILE="$PUSH_DATA_DIR/.push_cap_key"
    if [ -s "$KEY_FILE" ]; then
        RESOLVED_CAP_KEY="$(tr -d ' \r\n' < "$KEY_FILE")"
    else
        RESOLVED_CAP_KEY="$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')"
        printf '%s\n' "$RESOLVED_CAP_KEY" > "$KEY_FILE"
        chmod 600 "$KEY_FILE"
        echo "[openchat-push-gateway] Generated persistent PushCapability key in $KEY_FILE"
    fi
else
    RESOLVED_CAP_KEY="$PUSH_CAP_KEY"
fi

RESOLVED_APNS_KEY=""
if [ "$APNS_KEY_PATH" = "auto" ]; then
    if [ -s "$PUSH_KEYS_DIR/apns.p8" ]; then
        RESOLVED_APNS_KEY="$PUSH_KEYS_DIR/apns.p8"
    else
        for candidate in "$PUSH_KEYS_DIR"/*.p8; do
            if [ -s "$candidate" ]; then
                RESOLVED_APNS_KEY="$candidate"
                break
            fi
        done
    fi
elif [ "$APNS_KEY_PATH" != "none" ] && [ -n "$APNS_KEY_PATH" ]; then
    RESOLVED_APNS_KEY="$APNS_KEY_PATH"
fi

RESOLVED_FCM_KEY=""
if [ "$FCM_KEY_PATH" = "auto" ]; then
    if [ -s "$PUSH_KEYS_DIR/fcm-service-account.json" ]; then
        RESOLVED_FCM_KEY="$PUSH_KEYS_DIR/fcm-service-account.json"
    elif [ -s "$PUSH_KEYS_DIR/fcm.json" ]; then
        RESOLVED_FCM_KEY="$PUSH_KEYS_DIR/fcm.json"
    fi
elif [ "$FCM_KEY_PATH" != "none" ] && [ -n "$FCM_KEY_PATH" ]; then
    RESOLVED_FCM_KEY="$FCM_KEY_PATH"
fi

[ "$APNS_KEY_ID" = "none" ] && APNS_KEY_ID=""
[ "$APNS_TEAM_ID" = "none" ] && APNS_TEAM_ID=""

chown -R openchat:openchat "$PUSH_DATA_DIR" "$PUSH_KEYS_DIR"
chmod 700 "$PUSH_DATA_DIR" "$PUSH_KEYS_DIR"

export PUSH_GATEWAY_PORT RESOLVED_CAP_KEY RESOLVED_APNS_KEY APNS_KEY_ID APNS_TEAM_ID APNS_BUNDLE_ID APNS_SANDBOX RESOLVED_FCM_KEY
unset PUSH_CAP_KEY APNS_KEY_PATH FCM_KEY_PATH 2>/dev/null || true

exec su -s /bin/sh openchat -c '
set -- \
    -port "$PUSH_GATEWAY_PORT" \
    -cap-key "$RESOLVED_CAP_KEY" \
    -apns-bundle-id "$APNS_BUNDLE_ID" \
    -apns-sandbox="$APNS_SANDBOX"
if [ -n "${RESOLVED_APNS_KEY:-}" ]; then
    set -- "$@" -apns-key "$RESOLVED_APNS_KEY"
fi
if [ -n "${APNS_KEY_ID:-}" ]; then
    set -- "$@" -apns-key-id "$APNS_KEY_ID"
fi
if [ -n "${APNS_TEAM_ID:-}" ]; then
    set -- "$@" -apns-team-id "$APNS_TEAM_ID"
fi
if [ -n "${RESOLVED_FCM_KEY:-}" ]; then
    set -- "$@" -fcm-key "$RESOLVED_FCM_KEY"
fi
exec /app/push-gateway "$@"
'
