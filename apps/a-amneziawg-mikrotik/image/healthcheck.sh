#!/bin/sh
set -eu

expected=0
for conf in /run/awg/*.conf; do
    [ -f "$conf" ] || continue
    expected=$((expected + 1))
    iface=$(basename "$conf" .conf)
    if ! /usr/bin/awg show "$iface" >/dev/null 2>&1; then
        echo "interface $iface is down"
        exit 1
    fi
done

if [ "$expected" -eq 0 ]; then
    echo "no active configs in /run/awg"
    exit 1
fi

exit 0
