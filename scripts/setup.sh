#!/usr/bin/env bash
# Mobilytix — First-run bootstrap script
# Usage: ./scripts/setup.sh
#
# This script builds and starts the Mobilytix Docker containers.
# After running, the MCP server is available at http://localhost:3000/mcp
set -euo pipefail

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info()  { echo -e "${CYAN}[mobilytix]${NC} $*"; }
ok()    { echo -e "${GREEN}[   ok   ]${NC} $*"; }
warn()  { echo -e "${YELLOW}[ warn  ]${NC} $*"; }
fail()  { echo -e "${RED}[ FAIL  ]${NC} $*"; }

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"
APK_INPUT_DIR="${MOBILYTIX_APK_INPUT_DIR:-$PROJECT_ROOT/inbox}"
WORKSPACE_DIR="${MOBILYTIX_WORKSPACE_DIR:-$PROJECT_ROOT/workspace}"

# -----------------------------------------------------------------------
# 1. Check prerequisites (just Docker)
# -----------------------------------------------------------------------
info "Checking prerequisites..."

DOCKER="docker"
DOCKER_COMPOSE="docker compose"

if command -v docker &>/dev/null; then
    ok "docker found ($(command -v docker))"
else
    fail "docker not found — please install Docker first."
    fail "  Ubuntu/Debian: sudo apt install docker.io docker-compose-v2"
    fail "  Or: https://docs.docker.com/engine/install/"
    exit 1
fi

if docker info &>/dev/null 2>&1; then
    ok "Docker daemon is running"
elif sudo docker info &>/dev/null 2>&1; then
    DOCKER="sudo docker"
    DOCKER_COMPOSE="sudo docker compose"
    warn "Docker requires sudo (user not in docker group)"
    warn "Tip: run 'sudo usermod -aG docker \$USER' and re-login to avoid sudo"
    ok "Docker daemon is running (via sudo)"
else
    fail "Docker daemon is not running — start Docker first."
    exit 1
fi

# KVM check (only needed for Android emulator)
HAS_KVM=false
if [ -e /dev/kvm ]; then
    ok "KVM available at /dev/kvm"
    HAS_KVM=true
else
    warn "KVM not available — Android emulator won't work."
    warn "Static analysis will still work fine."
fi

# -----------------------------------------------------------------------
# 2. Create directories for bind mounts
# -----------------------------------------------------------------------
info "Creating directories..."
mkdir -p "$APK_INPUT_DIR"
mkdir -p "$WORKSPACE_DIR"
ok "APK input  — $APK_INPUT_DIR (mounted to /inbox in Docker)"
ok "workspace  — $WORKSPACE_DIR (mounted to /workspace in Docker)"

# -----------------------------------------------------------------------
# 3. Build Docker images
# -----------------------------------------------------------------------
info "Building Mobilytix container (this may take a while on first run)..."

cd "$PROJECT_ROOT/docker"

$DOCKER_COMPOSE build static
ok "mobilytix-static image built (includes MCP server + all analysis tools)"

if [ "$HAS_KVM" = true ]; then
    info "Building Android emulator container..."
    $DOCKER_COMPOSE build android
    ok "mobilytix-android image built"
else
    warn "Skipping Android emulator image (no KVM). Static analysis only."
fi

cd "$PROJECT_ROOT"

# -----------------------------------------------------------------------
# 4. Start the services
# -----------------------------------------------------------------------
info "Starting Mobilytix..."

cd "$PROJECT_ROOT/docker"
$DOCKER_COMPOSE up -d static mitmproxy
ok "MCP server starting on http://localhost:3000"

if [ "$HAS_KVM" = true ]; then
    $DOCKER_COMPOSE up -d android
    ok "Android emulator starting (may take 2-3 minutes to boot)"

    info "Waiting for Android emulator to become healthy..."
    ANDROID_READY=false
    for i in $(seq 1 120); do
        ANDROID_STATUS="$($DOCKER inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' mobilytix-android 2>/dev/null || true)"
        case "$ANDROID_STATUS" in
            healthy)
                ANDROID_READY=true
                break
                ;;
            unhealthy)
                warn "Android emulator reported unhealthy."
                break
                ;;
        esac
        sleep 5
    done

    if [ "$ANDROID_READY" != "true" ]; then
        fail "Android emulator never became healthy."
        fail "Check logs with: cd docker && $DOCKER_COMPOSE logs -f android"
        exit 1
    fi
fi

cd "$PROJECT_ROOT"

# -----------------------------------------------------------------------
# 5. Health check — wait for MCP server
# -----------------------------------------------------------------------
info "Waiting for MCP server to be ready..."
for i in $(seq 1 30); do
    if curl -sf http://localhost:3000/health > /dev/null 2>&1; then
        ok "MCP server is healthy"
        HEALTH=$(curl -sf http://localhost:3000/health)
        echo "  $HEALTH"
        break
    fi
    sleep 2
done

if ! curl -sf http://localhost:3000/health > /dev/null 2>&1; then
    warn "MCP server not responding yet — it may still be starting."
    warn "Check logs with: cd docker && $DOCKER_COMPOSE logs -f static"
fi

# -----------------------------------------------------------------------
# Done
# -----------------------------------------------------------------------
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Mobilytix is running!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo ""
info "MCP Server:  http://localhost:3000/mcp"
info "Health:      http://localhost:3000/health"
echo ""
info "To analyze an APK:"
echo "  1. Put your APK into the mounted APK input folder:"
echo "     cp /path/to/app.apk $APK_INPUT_DIR/"
echo ""
echo "  2. Then just tell your AI:"
echo "     \"Analyze the APK\""
echo ""
echo "  The AI will use list_inbox to discover your files automatically."
echo "  Analysis results will appear in $WORKSPACE_DIR/"
echo ""
info "Configure your AI tool with this MCP endpoint:"
echo ""
echo '  {
    "mcpServers": {
      "mobilytix": {
        "url": "http://localhost:3000/mcp"
      }
    }
  }'
echo ""
info "Then tell your AI: \"Analyze the APK\" (it will find it automatically)"
echo ""
info "Useful commands:"
echo "  View logs:     cd docker && $DOCKER_COMPOSE logs -f static"
echo "  Stop:          cd docker && $DOCKER_COMPOSE down"
echo "  Restart:       cd docker && $DOCKER_COMPOSE restart static"
echo ""
