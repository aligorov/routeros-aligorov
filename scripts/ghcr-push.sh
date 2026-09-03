#!/usr/bin/env bash
# Сборка своего образа (arm64 — архитектура роутера) и пуш в GHCR.
#   usage: ./scripts/ghcr-push.sh <путь-к-контексту> <имя> <тег> [dockerfile]
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

[ -f "$SRC/$DF" ] || { echo "ERROR: нет $SRC/$DF"; exit 1; }
docker buildx build \
    --platform linux/arm64 \
    -f "$SRC/$DF" \
    -t "$GHCR/$NAME:$TAG" \
    --push "$SRC"

echo
echo "Образ: $GHCR/$NAME:$TAG"
echo "В apps/<имя-приложения>/app.yaml укажите:"
echo "  image: $GHCR/$NAME:$TAG"
