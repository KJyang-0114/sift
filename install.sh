#!/usr/bin/env bash
set -euo pipefail

# Sift — AI-powered code security scanner
# One-line install: curl -fsSL https://raw.githubusercontent.com/KJyang-0114/sift/main/install.sh | bash

REPO="KJyang-0114/sift"
BIN_NAME="sift"
INSTALL_DIR="/usr/local/bin"

# ── Colors ──
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { printf "${CYAN}  • %s${NC}\n" "$@"; }
ok()    { printf "${GREEN}  ✅ %s${NC}\n" "$@"; }
warn()  { printf "${YELLOW}  ⚠️  %s${NC}\n" "$@"; }
err()   { printf "${RED}  ❌ %s${NC}\n" "$@"; exit 1; }

echo ""
echo "  🔍 Sift Installer"
echo "  ─────────────────"
echo ""

# ── Detect OS/Arch ──
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$ARCH" in
    x86_64)  ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
    arm64)   ARCH="arm64" ;;
    *)       err "Unsupported architecture: $ARCH" ;;
esac

case "$OS" in
    darwin)  OS="darwin" ;;
    linux)   OS="linux" ;;
    *)       err "Unsupported operating system: $OS" ;;
esac

info "Detected: ${OS}/${ARCH}"

# ── Get latest version ──
if command -v curl >/dev/null 2>&1; then
    LATEST=$(curl -sL "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
elif command -v wget >/dev/null 2>&1; then
    LATEST=$(wget -qO- "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
else
    err "curl or wget is required to download the installer."
fi

if [ -z "$LATEST" ]; then
    warn "Unable to determine latest version, falling back to v0.1.0"
    LATEST="v0.1.0"
fi

info "Version: ${LATEST}"

# ── Download ──
URL="https://github.com/${REPO}/releases/download/${LATEST}/${BIN_NAME}_${OS}_${ARCH}.tar.gz"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

info "Downloading: ${URL}"

if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$URL" -o "${TMPDIR}/${BIN_NAME}.tar.gz" || err "Download failed: ${URL}"
else
    wget -q "$URL" -O "${TMPDIR}/${BIN_NAME}.tar.gz" || err "Download failed: ${URL}"
fi

# ── Extract and install ──
tar -xz -C "$TMPDIR" -f "${TMPDIR}/${BIN_NAME}.tar.gz"

if [ "$(id -u)" -eq 0 ]; then
    cp "${TMPDIR}/${BIN_NAME}" "${INSTALL_DIR}/${BIN_NAME}"
else
    if [ -w "${INSTALL_DIR}" ]; then
        cp "${TMPDIR}/${BIN_NAME}" "${INSTALL_DIR}/${BIN_NAME}"
    else
        warn "Admin privileges required to write to ${INSTALL_DIR}"
        sudo cp "${TMPDIR}/${BIN_NAME}" "${INSTALL_DIR}/${BIN_NAME}" || err "Installation failed (sudo required)"
    fi
fi

chmod +x "${INSTALL_DIR}/${BIN_NAME}"

ok "Sift ${LATEST} installed successfully!"
echo ""
echo "  Next steps:"
echo "    sift init       # Configure LLM (3 questions max)"
echo "    sift scan .     # Scan your project"
echo ""
