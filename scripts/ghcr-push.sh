#!/usr/bin/env bash
# Сборка своего образа (arm64 + amd64 для MikroTik ARM64 и CHR) и пуш в GHCR.
#   usage: ./scripts/ghcr-push.sh <путь-к-контексту> <имя> <тег> [dockerfile]
# Переопределить платформы: PLATFORMS=linux/arm64 ./scripts/ghcr-push.sh ...
# Пример:
#   ./scripts/ghcr-push.sh ~/src/vpn-manager vpn-manager 1.0.0
#   -> ghcr.io/aligorov/routeros-aligorov/vpn-manager:1.0.0
#
# Разовый вход (токен с write:packages, https://github.com/settings/tokens):
#   echo <GHCR_TOKEN> | docker login ghcr.io -u aligorov --password-stdin
set -euo pipefail
[ $# -ge 3 ] || { grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 1; }
SRC="$1"; NAME="$2"; TAG="$3"; DF="${4:-Dockerfile}"
GHCR=ghcr.io/aligorov/routeros-aligorov
PLATFORMS="${PLATFORMS:-linux/arm64,linux/amd64}"

[ -f "$SRC/$DF" ] || { echo "ERROR: нет $SRC/$DF"; exit 1; }

BUILDER_ARGS=()
if docker buildx inspect multiarch >/dev/null 2>&1; then
    BUILDER_ARGS=(--builder multiarch)
fi

docker buildx build \
    "${BUILDER_ARGS[@]}" \
    --platform "$PLATFORMS" \
    -f "$SRC/$DF" \
    -t "$GHCR/$NAME:$TAG" \
    --push "$SRC"

echo
echo "Образ ($PLATFORMS): $GHCR/$NAME:$TAG"
echo "В apps/<имя-приложения>/app.yaml укажите:"
echo "  image: $GHCR/$NAME:$TAG"
