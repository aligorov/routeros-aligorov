#!/usr/bin/env bash
# Валидация всех apps/*/app.yaml и store.yaml по официальной
# JSON-схеме манифеста RouterOS-приложения.
# При первом запуске создаёт .venv с pyyaml+jsonschema.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ ! -x .venv/bin/python3 ]; then
    echo ">> создаём .venv (pyyaml, jsonschema)..."
    python3 -m venv .venv
    .venv/bin/pip install --quiet --upgrade pip
    .venv/bin/pip install --quiet pyyaml jsonschema
fi

exec .venv/bin/python3 scripts/_validate.py
