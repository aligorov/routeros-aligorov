#!/bin/sh
set -eu
exec wget -q -T 3 -O /dev/null http://127.0.0.1:8080/health
