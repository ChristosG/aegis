#!/usr/bin/env bash
set -euo pipefail

# Aegis installer — downloads the latest release binary from GitHub and installs it.
# Usage:
#   CLI-only (default):  curl -fsSL .../install.sh | sudo bash
#   Full (web dashboard): curl -fsSL .../install.sh | sudo bash -s -- --full

REPO="ChristosG/aegis"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/aegis"
SERVICE_DIR="/etc/systemd/system"
VARIANT="cli"

# --- Helpers ---
info()  { echo -e "\033[1;32m[+]\033[0m $*"; }
warn()  { echo -e "\033[1;33m[!]\033[0m $*"; }
error() { echo -e "\033[1;31m[-]\033[0m $*"; exit 1; }

# --- Parse args ---
while [ $# -gt 0 ]; do
    case "$1" in
        --full) VARIANT="full"; shift ;;
        --help|-h)
            echo "Usage: install.sh [--full]"
            echo ""
            echo "Options:"
            echo "  --full    Install with web dashboard support"
            echo ""
            exit 0
            ;;
        *) error "Unknown option: $1" ;;
    esac
done

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
if [ "$VARIANT" = "full" ]; then
    PREFIX="aegis-full"
    info "Installing full variant (with web dashboard)"
else
    PREFIX="aegis"
    info "Installing CLI-only variant"
fi

TARBALL="${PREFIX}-v${LATEST}-${TARGET}.tar.gz"
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

# --- Config ---
mkdir -p "$CONFIG_DIR"
if [ -f "${CONFIG_DIR}/aegis.toml" ] && [ -f "${TMP}/aegis.toml" ]; then
    # Upgrade: back up old config and install new one
    BACKUP="${CONFIG_DIR}/aegis.toml.bak.$(date +%s)"
    cp "${CONFIG_DIR}/aegis.toml" "$BACKUP"
    install -Dm644 "${TMP}/aegis.toml" "${CONFIG_DIR}/aegis.toml"
    info "Config updated (backup: $BACKUP)"
    warn "Review ${CONFIG_DIR}/aegis.toml and re-apply any custom settings from the backup"
elif [ ! -f "${CONFIG_DIR}/aegis.toml" ] && [ -f "${TMP}/aegis.toml" ]; then
    install -Dm644 "${TMP}/aegis.toml" "${CONFIG_DIR}/aegis.toml"
    info "Default config installed to ${CONFIG_DIR}/aegis.toml"
fi

# --- Enable dashboard for --full installs ---
if [ "$VARIANT" = "full" ]; then
    if command -v sed &>/dev/null; then
        # Enable dashboard in the config
        sed -i 's/^\[dashboard\]/[dashboard]/' "${CONFIG_DIR}/aegis.toml"
        sed -i '/^\[dashboard\]$/,/^\[/{s/^enabled = false/enabled = true/}' "${CONFIG_DIR}/aegis.toml"
        info "Web dashboard enabled in config"
    fi
fi

# --- Reload systemd and restart service ---
if command -v systemctl &>/dev/null; then
    systemctl daemon-reload 2>/dev/null && info "Systemd units reloaded"
    if systemctl is-active --quiet aegis 2>/dev/null; then
        systemctl restart aegis
        info "Aegis service restarted"
    elif systemctl is-enabled --quiet aegis 2>/dev/null; then
        systemctl start aegis
        info "Aegis service started"
    fi
fi

# --- Done ---
echo ""
info "Aegis v${LATEST} installed successfully! (variant: ${VARIANT})"
echo ""
echo "  Next steps:"
if ! systemctl is-active --quiet aegis 2>/dev/null; then
    echo "    1. sudo aegis init            # system hardening setup"
    echo "    2. sudo systemctl enable --now aegis"
fi
if [ "$VARIANT" = "full" ]; then
    echo ""
    echo "  Web dashboard: http://127.0.0.1:9443"
    echo "  Token: sudo cat /etc/aegis/api.token"
fi
echo ""
