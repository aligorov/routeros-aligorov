#!/usr/bin/env bash
# Создание нового приложения из шаблона apps/_template/
#   usage: ./scripts/new-app.sh <имя> ["Описание"]
#   имя: [a-z0-9-] — станет именем папки и приложения
set -euo pipefail
[ $# -ge 1 ] || { echo "usage: $0 <app-name> [\"Описание\"]"; exit 1; }
NAME="$1"
DESC="${2:-TODO: описание}"
[[ "$NAME" =~ ^[a-z0-9][a-z0-9-]*$ ]] || {
    echo "ERROR: имя должно быть [a-z0-9-] (получено: '$NAME')"; exit 1; }
cd "$(dirname "$0")/.."
DEST="apps/$NAME"
[ -e "$DEST" ] && { echo "ERROR: уже существует: $DEST"; exit 1; }

cp -R apps/_template "$DEST"
sed -i '' -e "s/^name: my-app/name: $NAME/" \
          -e "s/^descr: \"TODO: короткое описание приложения\"/descr: \"$DESC\"/" \
    "$DEST/app.yaml"

echo "Создано: $DEST"
echo "Дальше: 1) правьте $DEST/app.yaml   2) положите свою icon.png"
echo "        3) ./scripts/build.sh && ./scripts/validate.sh"
echo "        4) git add -A && git commit -m \"add $NAME\" && git push"
