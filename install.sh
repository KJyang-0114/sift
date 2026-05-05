#!/usr/bin/env bash
set -euo pipefail

# Sift — 全自動 AI 程式碼安全掃描工具
# 一行安裝腳本: curl -fsSL https://get.sift.dev | bash

REPO="sift-dev/sift"
BIN_NAME="sift"
INSTALL_DIR="/usr/local/bin"

# ── 顏色 ──
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

# ── 偵測 OS/Arch ──
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$ARCH" in
    x86_64)  ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
    arm64)   ARCH="arm64" ;;
    *)       err "不支援的架構: $ARCH" ;;
esac

case "$OS" in
    darwin)  OS="darwin" ;;
    linux)   OS="linux" ;;
    *)       err "不支援的作業系統: $OS" ;;
esac

info "偵測到: ${OS}/${ARCH}"

# ── 取得最新版本 ──
if command -v curl >/dev/null 2>&1; then
    LATEST=$(curl -sL "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
elif command -v wget >/dev/null 2>&1; then
    LATEST=$(wget -qO- "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
else
    err "需要 curl 或 wget 來下載安裝檔。"
fi

if [ -z "$LATEST" ]; then
    warn "無法取得最新版本號，嘗試從 main 安裝"
    LATEST="v0.1.0"
fi

info "版本: ${LATEST}"

# ── 下載 ──
URL="https://github.com/${REPO}/releases/download/${LATEST}/${BIN_NAME}_${OS}_${ARCH}.tar.gz"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

info "下載中: ${URL}"

if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$URL" -o "${TMPDIR}/${BIN_NAME}.tar.gz" || err "下載失敗: ${URL}"
else
    wget -q "$URL" -O "${TMPDIR}/${BIN_NAME}.tar.gz" || err "下載失敗: ${URL}"
fi

# ── 解壓並安裝 ──
tar -xz -C "$TMPDIR" -f "${TMPDIR}/${BIN_NAME}.tar.gz"

if [ "$(id -u)" -eq 0 ]; then
    cp "${TMPDIR}/${BIN_NAME}" "${INSTALL_DIR}/${BIN_NAME}"
else
    if [ -w "${INSTALL_DIR}" ]; then
        cp "${TMPDIR}/${BIN_NAME}" "${INSTALL_DIR}/${BIN_NAME}"
    else
        warn "需要管理員權限來寫入 ${INSTALL_DIR}"
        sudo cp "${TMPDIR}/${BIN_NAME}" "${INSTALL_DIR}/${BIN_NAME}" || err "安裝失敗 (需要 sudo)"
    fi
fi

chmod +x "${INSTALL_DIR}/${BIN_NAME}"

ok "Sift ${LATEST} 安裝成功！"
echo ""
echo "  下一步："
echo "    sift init       # 設定 LLM (最多三題)"
echo "    sift scan .     # 掃描專案"
echo ""
