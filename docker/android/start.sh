#!/bin/bash
set -euo pipefail

FRIDA_REMOTE_PATH="/data/local/tmp/frida-server"
FRIDA_PORT="27042"
FRIDA_PORT_HEX="$(printf '%04X' "${FRIDA_PORT}")"

log() {
    echo "[mobilytix] $*"
}

warn() {
    echo "[mobilytix] WARNING: $*"
}

wait_for_boot() {
    log "Waiting for Android emulator to boot..."
    for _ in $(seq 1 180); do
        boot_completed="$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r' || true)"
        if [ "$boot_completed" = "1" ]; then
            log "Emulator booted."
            return 0
        fi
        sleep 2
    done

    warn "Android emulator did not report boot completion in time."
    return 1
}

start_frida_server() {
    log "Starting Frida server..."
    adb push /opt/frida-server "${FRIDA_REMOTE_PATH}"
    adb shell "chmod 755 ${FRIDA_REMOTE_PATH}"

    if adb shell "nohup ${FRIDA_REMOTE_PATH} >/dev/null 2>&1 &" >/dev/null 2>&1; then
        return 0
    fi

    warn "Direct Frida launch failed; retrying with su -c..."
    if adb shell "su -c 'nohup ${FRIDA_REMOTE_PATH} >/dev/null 2>&1 &'" >/dev/null 2>&1; then
        return 0
    fi

    return 1
}

frida_process_running() {
    adb shell "pidof frida-server >/dev/null 2>&1 || ps -A 2>/dev/null | grep -q '[f]rida-server'" >/dev/null 2>&1
}

frida_port_listening() {
    adb shell "cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | grep -i ':${FRIDA_PORT_HEX}' | grep -Eq '[[:space:]]0A[[:space:]]'" >/dev/null 2>&1
}

log_frida_diagnostics() {
    warn "Frida diagnostics: process=$(adb shell 'pidof frida-server 2>/dev/null || true' | tr -d '\r')"
    warn "Frida diagnostics: listening ports=$(adb shell \"cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | grep -i ':${FRIDA_PORT_HEX}' || true\" | tr -d '\r')"
}

stop_frida_server() {
    adb shell "sh -c 'for p in \$(pidof frida-server 2>/dev/null); do kill \"\$p\" 2>/dev/null; done'" >/dev/null 2>&1 || true
    adb shell "su -c 'for p in \$(pidof frida-server 2>/dev/null); do kill \"\$p\" 2>/dev/null; done'" >/dev/null 2>&1 || true
}

wait_for_frida_server() {
    for _ in $(seq 1 30); do
        if frida_process_running && frida_port_listening; then
            log "Frida server is running."
            return 0
        fi
        sleep 2
    done

    warn "Frida server did not become ready."
    log_frida_diagnostics
    return 1
}

wait_for_boot

# Restart adbd as root when available so Frida can run with elevated privileges.
log "Restarting adbd as root..."
if adb root >/dev/null 2>&1; then
    sleep 2
    adb wait-for-device
else
    warn "adb root is not available; continuing with the current shell context."
fi

stop_frida_server

if ! start_frida_server; then
    warn "Initial Frida launch attempt failed."
fi

if ! wait_for_frida_server; then
    exit 1
fi

# Install drozer agent if available
if [ -s /opt/drozer-agent.apk ]; then
    log "Installing drozer agent..."
    adb install -r /opt/drozer-agent.apk || warn "drozer install failed (non-fatal)"
else
    log "drozer agent not present; drozer tools will require a manually installed agent."
fi

# Clear any stale global HTTP proxy so the emulator has direct network
# access by default. Traffic interception is enabled explicitly later.
log "Clearing global proxy configuration..."
adb shell "settings put global http_proxy :0"

log "Android environment ready."
