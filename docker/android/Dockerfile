FROM budtmo/docker-android:emulator_13.0

# ---------------------------------------------------------------------------
# Frida server — must match the locked frida Python client in the static container
# ---------------------------------------------------------------------------
ARG FRIDA_VERSION=17.9.1
ARG ARCH=x86_64

USER 0
RUN apt-get update -qq \
    && apt-get install -y --no-install-recommends xz-utils \
    && rm -rf /var/lib/apt/lists/* \
    && wget -q https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-server-${FRIDA_VERSION}-android-${ARCH}.xz \
    && unxz frida-server-*.xz \
    && mv frida-server-* /opt/frida-server \
    && chmod +x /opt/frida-server

# ---------------------------------------------------------------------------
# drozer agent APK — downloaded best-effort during build and installed on
# first boot by start.sh when present.
# ---------------------------------------------------------------------------
ARG DROZER_AGENT_VERSION=3.1.0
ARG DROZER_AGENT_URL=https://github.com/ReversecLabs/drozer-agent/releases/download/${DROZER_AGENT_VERSION}/drozer-agent.apk
RUN if wget -q "${DROZER_AGENT_URL}" -O /opt/drozer-agent.apk; then \
        echo "[mobilytix] drozer agent downloaded."; \
    else \
        rm -f /opt/drozer-agent.apk; \
        echo "[mobilytix] drozer agent download skipped."; \
    fi

# ---------------------------------------------------------------------------
# Startup helpers
# ---------------------------------------------------------------------------
COPY docker/android/start.sh /start.sh
COPY docker/android/mobilytix-entrypoint.sh /mobilytix-entrypoint.sh
COPY docker/android/healthcheck.sh /healthcheck.sh
COPY LICENSE NOTICE /opt/mobilytix/
RUN chmod +x /start.sh /mobilytix-entrypoint.sh /healthcheck.sh

EXPOSE 5555
EXPOSE 27042

HEALTHCHECK --interval=15s --timeout=10s --retries=20 --start-period=120s CMD ["/healthcheck.sh"]

ENTRYPOINT ["/mobilytix-entrypoint.sh"]
