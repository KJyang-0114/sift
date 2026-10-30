#!/usr/bin/env bash
set -euo pipefail

# Sift — AI-powered code security scanner
# One-line install: curl -fsSL https://raw.githubusercontent.com/KJyang-0114/sift/main/install.sh | bash
#
# Environment overrides:
#   SIFT_VERSION=v1.5.0              install a specific release (default: latest)
#   SIFT_INSTALL_DIR=$HOME/.local/bin install location (default: /usr/local/bin if writable, else ~/.local/bin)

REPO="KJyang-0114/sift"
BIN_NAME="sift"

# ── Colors ──
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { printf "${CYAN}  • %s${NC}\n" "$@"; }
ok()    { printf "${GREEN}  ✅ %s${NC}\n" "$@"; }
warn()  { printf "${YELLOW}  ⚠️  %s${NC}\n" "$@"; }
err()   { printf "${RED}  ❌ %s${NC}\n" "$@" >&2; exit 1; }

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
    *)       err "Unsupported operating system: $OS (Windows: use install.ps1)" ;;
esac

info "Detected: ${OS}/${ARCH}"

# ── HTTP helpers ──
if command -v curl >/dev/null 2>&1; then
    fetch()    { curl -fsSL "$1"; }
    download() { curl -fsSL "$1" -o "$2"; }
elif command -v wget >/dev/null 2>&1; then
    fetch()    { wget -qO- "$1"; }
    download() { wget -q "$1" -O "$2"; }
else
    err "curl or wget is required to download the installer."
fi

if command -v sha256sum >/dev/null 2>&1; then
    sha256() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
    sha256() { shasum -a 256 "$1" | awk '{print $1}'; }
else
    err "sha256sum or shasum is required to verify the download."
fi

# ── Resolve version ──
VERSION="${SIFT_VERSION:-}"
if [ -z "$VERSION" ]; then
    VERSION=$(fetch "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null \
        | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' || true)
    [ -n "$VERSION" ] || err "Unable to determine the latest release. Set SIFT_VERSION=vX.Y.Z and retry."
fi
case "$VERSION" in
    v*) ;;
    *)  VERSION="v${VERSION}" ;;
esac

info "Version: ${VERSION}"

# ── Resolve install dir ──
INSTALL_DIR="${SIFT_INSTALL_DIR:-}"
if [ -z "$INSTALL_DIR" ]; then
    if [ -w /usr/local/bin ] || [ "$(id -u)" -eq 0 ]; then
        INSTALL_DIR="/usr/local/bin"
    else
        INSTALL_DIR="${HOME}/.local/bin"
    fi
fi
mkdir -p "$INSTALL_DIR" || err "Cannot create ${INSTALL_DIR}"
[ -w "$INSTALL_DIR" ] || err "${INSTALL_DIR} is not writable. Set SIFT_INSTALL_DIR to a writable directory."

# ── Download and verify ──
ARCHIVE="${BIN_NAME}_${OS}_${ARCH}.tar.gz"
BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

info "Downloading: ${BASE_URL}/${ARCHIVE}"
download "${BASE_URL}/${ARCHIVE}" "${TMPDIR}/${ARCHIVE}" || err "Download failed: ${BASE_URL}/${ARCHIVE}"
download "${BASE_URL}/checksums.txt" "${TMPDIR}/checksums.txt" || err "Download failed: ${BASE_URL}/checksums.txt"

EXPECTED=$(awk -v name="$ARCHIVE" '$2 == name || $2 == "*" name {print $1}' "${TMPDIR}/checksums.txt")
[ -n "$EXPECTED" ] || err "No checksum entry for ${ARCHIVE} in checksums.txt"
ACTUAL=$(sha256 "${TMPDIR}/${ARCHIVE}")
[ "$EXPECTED" = "$ACTUAL" ] || err "Checksum mismatch for ${ARCHIVE} (expected ${EXPECTED}, got ${ACTUAL})"
ok "Checksum verified"

# ── Extract and install (atomic replace keeps the old binary on failure) ──
tar -xz -C "$TMPDIR" -f "${TMPDIR}/${ARCHIVE}" "$BIN_NAME" || err "Archive does not contain ${BIN_NAME}"
STAGED="${INSTALL_DIR}/.${BIN_NAME}.new.$$"
cp "${TMPDIR}/${BIN_NAME}" "$STAGED" || err "Failed to write ${STAGED}"
chmod +x "$STAGED"
mv -f "$STAGED" "${INSTALL_DIR}/${BIN_NAME}" || { rm -f "$STAGED"; err "Failed to install ${INSTALL_DIR}/${BIN_NAME}"; }

ok "Sift ${VERSION} installed to ${INSTALL_DIR}/${BIN_NAME}"

case ":${PATH}:" in
    *":${INSTALL_DIR}:"*) ;;
    *) warn "${INSTALL_DIR} is not on PATH. Add: export PATH=\"${INSTALL_DIR}:\$PATH\"" ;;
esac

if ! command -v semgrep >/dev/null 2>&1; then
    warn "Semgrep not found. Static analysis requires it: pip install semgrep"
fi

echo ""
echo "  Next steps:"
echo "    sift init       # Configure LLM (3 questions max)"
echo "    sift scan .     # Scan your project"
echo ""
