FROM python:3.12-slim

LABEL maintainer="Mobilytix Contributors"
LABEL description="Mobilytix MCP server + static analysis tools"

ENV DEBIAN_FRONTEND=noninteractive
ENV HOME=/root

# Install system dependencies (includes ADB for talking to android container)
RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-21-jdk-headless \
    wget \
    curl \
    unzip \
    xz-utils \
    git \
    build-essential \
    cmake \
    meson \
    ninja-build \
    pkg-config \
    binutils \
    libicu-dev \
    libcapstone-dev \
    openssl \
    ripgrep \
    sqlite3 \
    android-tools-adb \
    && rm -rf /var/lib/apt/lists/*

# Set JAVA_HOME
ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
ENV PATH="${JAVA_HOME}/bin:${PATH}"

# -------------------------------------------------------------------------
# Install radare2 (rabin2) from upstream release tarball
# Debian slim does not reliably ship a radare2 package.
# -------------------------------------------------------------------------
ARG RADARE2_VERSION=5.9.8
RUN wget -q "https://github.com/radareorg/radare2/releases/download/${RADARE2_VERSION}/radare2-${RADARE2_VERSION}.tar.xz" \
    -O /tmp/radare2.tar.xz \
    && mkdir -p /tmp/radare2-src \
    && tar -xJf /tmp/radare2.tar.xz -C /tmp/radare2-src --strip-components=1 \
    && cd /tmp/radare2-src \
    && ./sys/install.sh --without-pull --install \
    && command -v rabin2 \
    && rabin2 -v \
    && rm -rf /tmp/radare2.tar.xz /tmp/radare2-src

# -------------------------------------------------------------------------
# Install r2dec via the official radare2 package manager.
# `pdd`/`pddj` come from r2dec; only `pdc` ships by default.
# -------------------------------------------------------------------------
RUN r2pm -U
RUN r2pm -i r2dec
RUN r2pm -l | grep -q r2dec
RUN r2 -q -c 'pdd?' /bin/ls > /tmp/r2dec-help.txt 2>&1
RUN grep -q 'pdd' /tmp/r2dec-help.txt
RUN rm -f /tmp/r2dec-help.txt

# -------------------------------------------------------------------------
# Install jadx (latest release from GitHub)
# -------------------------------------------------------------------------
ARG JADX_VERSION=1.5.1
RUN wget -q "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" \
    -O /tmp/jadx.zip \
    && mkdir -p /opt/jadx \
    && unzip -q /tmp/jadx.zip -d /opt/jadx \
    && chmod +x /opt/jadx/bin/jadx /opt/jadx/bin/jadx-gui \
    && ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx \
    && rm /tmp/jadx.zip

# -------------------------------------------------------------------------
# Install apktool
# -------------------------------------------------------------------------
ARG APKTOOL_VERSION=2.10.0
RUN wget -q "https://raw.githubusercontent.com/iBotPeaches/Apktool/v${APKTOOL_VERSION}/scripts/linux/apktool" \
    -O /usr/local/bin/apktool \
    && chmod +x /usr/local/bin/apktool \
    && wget -q "https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_VERSION}/apktool_${APKTOOL_VERSION}.jar" \
    -O /usr/local/bin/apktool.jar

# -------------------------------------------------------------------------
# Install Android SDK build-tools (for aapt2 and apksigner)
# -------------------------------------------------------------------------
ARG BUILD_TOOLS_VERSION=35.0.0
ARG ANDROID_CMDLINE_TOOLS_VERSION=11076708
ENV ANDROID_HOME=/opt/android-sdk
RUN mkdir -p ${ANDROID_HOME}/cmdline-tools \
    && wget -q "https://dl.google.com/android/repository/commandlinetools-linux-${ANDROID_CMDLINE_TOOLS_VERSION}_latest.zip" \
    -O /tmp/cmdline-tools.zip \
    && unzip -q /tmp/cmdline-tools.zip -d ${ANDROID_HOME}/cmdline-tools \
    && mv ${ANDROID_HOME}/cmdline-tools/cmdline-tools ${ANDROID_HOME}/cmdline-tools/latest \
    && rm /tmp/cmdline-tools.zip \
    && yes | ${ANDROID_HOME}/cmdline-tools/latest/bin/sdkmanager --licenses > /dev/null 2>&1 || true \
    && ${ANDROID_HOME}/cmdline-tools/latest/bin/sdkmanager "build-tools;${BUILD_TOOLS_VERSION}" \
    && ln -s ${ANDROID_HOME}/build-tools/${BUILD_TOOLS_VERSION}/aapt2 /usr/local/bin/aapt2 \
    && ln -s ${ANDROID_HOME}/build-tools/${BUILD_TOOLS_VERSION}/apksigner /usr/local/bin/apksigner

# -------------------------------------------------------------------------
# Install Python security tools + MCP server dependencies
# -------------------------------------------------------------------------
ARG ANDROGUARD_VERSION=4.1.3
ARG APKINSPECTOR_VERSION=1.3.6
ARG APKLEAKS_VERSION=2.6.3
ARG PYELFTOOLS_VERSION=0.32
ARG REQUESTS_VERSION=2.32.3
ARG SEMGREP_VERSION=1.111.0
ARG FRIDA_VERSION=17.9.1
ARG FRIDA_TOOLS_VERSION=14.8.0
ARG STARLETTE_VERSION=0.46.2
ARG UVICORN_VERSION=0.34.0
RUN pip install --no-cache-dir \
    androguard==${ANDROGUARD_VERSION} \
    apkInspector==${APKINSPECTOR_VERSION} \
    apkleaks==${APKLEAKS_VERSION} \
    drozer==3.1.0 \
    pyelftools==${PYELFTOOLS_VERSION} \
    requests==${REQUESTS_VERSION} \
    semgrep==${SEMGREP_VERSION} \
    frida==${FRIDA_VERSION} \
    frida-tools==${FRIDA_TOOLS_VERSION} \
    starlette==${STARLETTE_VERSION} \
    uvicorn==${UVICORN_VERSION}

# -------------------------------------------------------------------------
# Install blutter (Flutter AOT reverse engineering helper)
# -------------------------------------------------------------------------
ARG BLUTTER_REF=129377f65dffecd59535eb35041de534c4dea2ea
RUN git clone https://github.com/worawit/blutter /opt/blutter \
    && cd /opt/blutter \
    && git checkout "${BLUTTER_REF}"
ENV BLUTTER_HOME=/opt/blutter

# -------------------------------------------------------------------------
# Install hermes-dec (React Native Hermes bytecode parser/disassembler/decompiler)
# -------------------------------------------------------------------------
ARG HERMES_DEC_REF=1c112f85e3fb49442c57a0ed31b83bb3825db639
RUN git clone https://github.com/P1sec/hermes-dec /opt/hermes-dec \
    && cd /opt/hermes-dec \
    && git checkout "${HERMES_DEC_REF}" \
    && chmod +x /opt/hermes-dec/hbc-decompiler /opt/hermes-dec/hbc-disassembler /opt/hermes-dec/hbc-file-parser
ENV HERMES_DEC_PATH=/opt/hermes-dec/hbc-decompiler

# -------------------------------------------------------------------------
# Install .NET SDK + ILSpy CLI (managed assembly decompiler for Xamarin/.NET)
# Also install the .NET 6 runtime because current Il2CppDumper releases are
# shipped as framework-dependent net6 binaries.
# -------------------------------------------------------------------------
ARG DOTNET_VERSION=8.0
ARG IL2CPPDUMPER_RUNTIME=6.0
ARG ILSPYCMD_VERSION=9.1.0.7988
RUN wget -q https://dot.net/v1/dotnet-install.sh -O /tmp/dotnet-install.sh \
    && chmod +x /tmp/dotnet-install.sh \
    && /tmp/dotnet-install.sh --channel ${DOTNET_VERSION} --install-dir /opt/dotnet \
    && /tmp/dotnet-install.sh --runtime dotnet --channel ${IL2CPPDUMPER_RUNTIME} --install-dir /opt/dotnet \
    && rm /tmp/dotnet-install.sh
ENV DOTNET_ROOT=/opt/dotnet
ENV PATH="${DOTNET_ROOT}:${PATH}"
# Install ilspycmd globally so it is on PATH as 'ilspycmd'
RUN /opt/dotnet/dotnet tool install ilspycmd --version ${ILSPYCMD_VERSION} --tool-path /opt/ilspy
ENV PATH="/opt/ilspy:${PATH}"

# -------------------------------------------------------------------------
# Install Il2CppDumper (Unity IL2CPP metadata extractor)
# -------------------------------------------------------------------------
ARG IL2CPPDUMPER_VERSION=6.7.46
RUN wget -q "https://github.com/Perfare/Il2CppDumper/releases/download/v${IL2CPPDUMPER_VERSION}/Il2CppDumper-net6-v${IL2CPPDUMPER_VERSION}.zip" \
    -O /tmp/il2cppdumper.zip \
    && mkdir -p /opt/il2cppdumper \
    && unzip -q /tmp/il2cppdumper.zip -d /opt/il2cppdumper \
    && printf '%s\n' '#!/bin/sh' 'exec /opt/dotnet/dotnet /opt/il2cppdumper/Il2CppDumper.dll "$@"' > /usr/local/bin/il2cppdumper \
    && chmod +x /usr/local/bin/il2cppdumper \
    && rm /tmp/il2cppdumper.zip

# -------------------------------------------------------------------------
# Copy and install MCP server
# -------------------------------------------------------------------------
COPY mcp_server/ /opt/mobilytix/mcp_server/
COPY pyproject.toml /opt/mobilytix/
COPY config/ /opt/mobilytix/config/
COPY prompts/ /opt/mobilytix/prompts/
COPY README.md /opt/mobilytix/
COPY LICENSE NOTICE /opt/mobilytix/
WORKDIR /opt/mobilytix
RUN pip install --no-cache-dir -e .

# -------------------------------------------------------------------------
# Workspace (volume-mounted for APK exchange)
# -------------------------------------------------------------------------
ENV MOBILYTIX_WORKSPACE=/workspace
ENV MOBILYTIX_TRANSPORT=http
ENV MOBILYTIX_LOG_LEVEL=INFO
RUN mkdir -p /workspace
VOLUME /workspace

EXPOSE 3000

CMD ["python", "-m", "mcp_server", "--http"]
