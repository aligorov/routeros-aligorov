#!/bin/sh
set -eu
PORT="${PUSH_GATEWAY_PORT:-8088}"
wget -qO- "http://127.0.0.1:${PORT}/health" >/dev/null 2>&1
