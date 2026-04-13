#!/bin/bash
set -euo pipefail

FRIDA_PORT_HEX="$(printf '%04X' 27042)"

boot_completed="$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r' || true)"
if [ "$boot_completed" != "1" ]; then
    exit 1
fi

if adb shell "pidof frida-server >/dev/null 2>&1 || ps -A 2>/dev/null | grep -q '[f]rida-server'" >/dev/null 2>&1 \
    && adb shell "cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | grep -i ':${FRIDA_PORT_HEX}' | grep -Eq '[[:space:]]0A[[:space:]]'" >/dev/null 2>&1; then
    exit 0
fi

exit 1
