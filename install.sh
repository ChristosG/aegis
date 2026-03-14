#!/usr/bin/env bash
set -euo pipefail

# Aegis installer — downloads the latest release binary from GitHub and installs it.
# Usage: curl -fsSL https://raw.githubusercontent.com/ChristosG/aegis/main/install.sh | sudo bash

REPO="ChristosG/aegis"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/aegis"
SERVICE_DIR="/etc/systemd/system"

# --- Helpers ---
info()  { echo -e "\033[1;32m[+]\033[0m $*"; }
warn()  { echo -e "\033[1;33m[!]\033[0m $*"; }
error() { echo -e "\033[1;31m[-]\033[0m $*"; exit 1; }

# --- Check root ---
if [ "$(id -u)" -ne 0 ]; then
    error "This installer must be run as root (try: sudo bash install.sh)"
fi

# --- Detect arch ---
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  TARGET="x86_64-unknown-linux-gnu" ;;
    aarch64) TARGET="aarch64-unknown-linux-gnu" ;;
    *)       error "Unsupported architecture: $ARCH" ;;
esac

# --- Find latest release ---
info "Fetching latest release from GitHub..."
LATEST=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"v?([^"]+)".*/\1/')
if [ -z "$LATEST" ]; then
    error "Could not determine latest release. Check https://github.com/${REPO}/releases"
fi
info "Latest version: v${LATEST}"

# --- Download ---
TARBALL="aegis-v${LATEST}-${TARGET}.tar.gz"
URL="https://github.com/${REPO}/releases/download/v${LATEST}/${TARBALL}"

info "Downloading ${TARBALL}..."
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

curl -fSL "$URL" -o "${TMP}/${TARBALL}" || error "Download failed. Check the release at:\n  https://github.com/${REPO}/releases/tag/v${LATEST}"

# --- Extract & install ---
tar -xzf "${TMP}/${TARBALL}" -C "$TMP"

install -Dm755 "${TMP}/aegis" "${INSTALL_DIR}/aegis"
info "Binary installed to ${INSTALL_DIR}/aegis"

# --- Service file ---
if [ -f "${TMP}/aegis.service" ]; then
    install -Dm644 "${TMP}/aegis.service" "${SERVICE_DIR}/aegis.service"
    info "Service installed to ${SERVICE_DIR}/aegis.service"
fi

# --- Default config ---
mkdir -p "$CONFIG_DIR"
if [ ! -f "${CONFIG_DIR}/aegis.toml" ]; then
    if [ -f "${TMP}/aegis.toml" ]; then
        install -Dm644 "${TMP}/aegis.toml" "${CONFIG_DIR}/aegis.toml"
        info "Default config installed to ${CONFIG_DIR}/aegis.toml"
    fi
else
    warn "Config ${CONFIG_DIR}/aegis.toml already exists, not overwriting"
fi

# --- Done ---
echo ""
info "Aegis v${LATEST} installed successfully!"
echo ""
echo "  Next steps:"
echo "    1. sudo aegis init            # system hardening setup"
echo "    2. sudo aegis init-mail       # (optional) email alerts"
echo "    3. sudo systemctl enable --now aegis"
echo ""
