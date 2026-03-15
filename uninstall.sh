#!/usr/bin/env bash
set -euo pipefail

# Aegis uninstaller — completely removes aegis from the system.
# Usage: curl -fsSL .../uninstall.sh | sudo bash
#   or:  sudo bash uninstall.sh
#   or:  sudo bash uninstall.sh --yes   (skip confirmation prompts)

# --- Helpers ---
info()  { echo -e "\033[1;32m[+]\033[0m $*"; }
warn()  { echo -e "\033[1;33m[!]\033[0m $*"; }
error() { echo -e "\033[1;31m[-]\033[0m $*"; exit 1; }

AUTO_YES=false
for arg in "$@"; do
    case "$arg" in
        --yes|-y) AUTO_YES=true ;;
    esac
done

confirm() {
    if [ "$AUTO_YES" = true ]; then return 0; fi
    read -rp "    $1 [y/N] " ans
    case "$ans" in [yY]*) return 0 ;; *) return 1 ;; esac
}

# --- Check root ---
if [ "$(id -u)" -ne 0 ]; then
    error "This uninstaller must be run as root (try: sudo bash uninstall.sh)"
fi

echo ""
echo "  Aegis Uninstaller"
echo "  ================="
echo ""
warn "This will completely remove aegis from your system."
echo ""

if [ "$AUTO_YES" = false ]; then
    confirm "Continue with uninstall?" || { echo "  Aborted."; exit 0; }
    echo ""
fi

# --- 1. Stop and disable service ---
if systemctl is-active --quiet aegis 2>/dev/null; then
    systemctl stop aegis
    info "Stopped aegis service"
fi
if systemctl is-enabled --quiet aegis 2>/dev/null; then
    systemctl disable aegis 2>/dev/null
    info "Disabled aegis service"
fi

# --- 2. Remove firewall rules ---

# iptables: remove AEGIS_BLOCK chain
if command -v iptables &>/dev/null; then
    if iptables -L AEGIS_BLOCK -n &>/dev/null 2>&1; then
        # Remove jump rule from INPUT
        while iptables -D INPUT -j AEGIS_BLOCK 2>/dev/null; do true; done
        # Flush and delete chain
        iptables -F AEGIS_BLOCK 2>/dev/null || true
        iptables -X AEGIS_BLOCK 2>/dev/null || true
        info "Removed iptables AEGIS_BLOCK chain"
    fi
fi

# nftables: remove aegis table
if command -v nft &>/dev/null; then
    if nft list table inet aegis &>/dev/null 2>&1; then
        nft delete table inet aegis 2>/dev/null || true
        info "Removed nftables inet aegis table"
    fi
fi

# --- 3. Remove binary ---
if [ -f /usr/local/bin/aegis ]; then
    rm -f /usr/local/bin/aegis
    info "Removed /usr/local/bin/aegis"
fi

# --- 4. Remove systemd service file ---
if [ -f /etc/systemd/system/aegis.service ]; then
    rm -f /etc/systemd/system/aegis.service
    systemctl daemon-reload 2>/dev/null
    info "Removed /etc/systemd/system/aegis.service"
fi

# --- 5. Remove sysctl hardening ---
if [ -f /etc/sysctl.d/99-aegis-hardening.conf ]; then
    rm -f /etc/sysctl.d/99-aegis-hardening.conf
    sysctl --system &>/dev/null 2>&1 || true
    info "Removed /etc/sysctl.d/99-aegis-hardening.conf (sysctl reloaded)"
fi

# --- 6. Remove fail2ban configs ---
REMOVED_F2B=false
if [ -f /etc/fail2ban/filter.d/aegis-threat.conf ]; then
    rm -f /etc/fail2ban/filter.d/aegis-threat.conf
    REMOVED_F2B=true
fi
if [ -f /etc/fail2ban/jail.d/aegis-threat.conf ]; then
    rm -f /etc/fail2ban/jail.d/aegis-threat.conf
    REMOVED_F2B=true
fi
if [ "$REMOVED_F2B" = true ]; then
    systemctl reload fail2ban 2>/dev/null || true
    info "Removed fail2ban aegis configs"
fi

# --- 7. Remove config directory ---
if [ -d /etc/aegis ]; then
    if confirm "Remove config directory /etc/aegis/ (aegis.toml, api.token, mail.env)?"; then
        rm -rf /etc/aegis
        info "Removed /etc/aegis/"
    else
        warn "Kept /etc/aegis/ (remove manually if needed)"
    fi
fi

# --- 8. Remove data directories ---
# Check both root's home and the invoking user's home
DATA_DIRS=()
[ -d /root/.aegis ] && DATA_DIRS+=("/root/.aegis")
if [ -n "${SUDO_USER:-}" ]; then
    USER_HOME=$(eval echo "~${SUDO_USER}")
    [ -d "${USER_HOME}/.aegis" ] && DATA_DIRS+=("${USER_HOME}/.aegis")
fi

if [ ${#DATA_DIRS[@]} -gt 0 ]; then
    echo ""
    warn "Found data directories:"
    for d in "${DATA_DIRS[@]}"; do
        echo "    $d"
    done
    echo ""
    warn "These contain threat logs, baselines, blocked IPs, and quarantined files."
    if confirm "Remove all data directories?"; then
        for d in "${DATA_DIRS[@]}"; do
            rm -rf "$d"
            info "Removed $d"
        done
    else
        warn "Kept data directories (remove manually if needed)"
    fi
fi

# --- Done ---
echo ""
info "Aegis has been uninstalled."
echo ""
echo "  What was removed:"
echo "    - Binary (/usr/local/bin/aegis)"
echo "    - Systemd service"
echo "    - Firewall rules (AEGIS_BLOCK chain)"
echo "    - Sysctl hardening (99-aegis-hardening.conf)"
echo "    - fail2ban integration"
echo ""
echo "  Note: kernel sysctl parameters were reset to system defaults."
echo "  Note: any ufw rules added by aegis (ufw deny from <ip>) must be removed manually."
echo ""
