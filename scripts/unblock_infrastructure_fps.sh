#!/bin/bash
# ---------------------------------------------------------------------------
# Phase A0 — Unblock confirmed infrastructure false positives from AEGIS_BLOCK
# ---------------------------------------------------------------------------
#
# This script removes IPs from Aegis's block list and iptables chain that
# were false-positively blocked and belong to well-known CDN / cloud / code-host
# infrastructure. See docs/TRIAGE_PHASE_A0.md for the full classification and
# evidence behind every IP listed below.
#
# USAGE:
#   1. Read docs/TRIAGE_PHASE_A0.md
#   2. Verify each IP in the ips=(...) array below is actually in your
#      AEGIS_BLOCK chain and that you agree it should be unblocked
#   3. Pick one of the following invocations (all equivalent):
#
#        sudo DISABLE_SAFETY=1 bash scripts/unblock_infrastructure_fps.sh
#        sudo bash scripts/unblock_infrastructure_fps.sh --force
#        DISABLE_SAFETY=1 sudo -E bash scripts/unblock_infrastructure_fps.sh
#
#      (The naive `DISABLE_SAFETY=1 sudo bash ...` does NOT work because
#      sudo strips environment variables by default — use one of the above.)
#
# SAFETY:
#   - Uses `aegis unblock <ip>` which atomically updates both the kernel
#     firewall rule AND block_list.json. No partial state possible.
#   - Script exits non-zero on any failure.
#   - Script is idempotent: running twice on the same IP is a no-op.
#   - Runs sequentially, not in parallel, so if something goes wrong you can
#     Ctrl-C and be in a consistent state.
#
# WHAT THIS WILL NOT DO:
#   - Touch any manually-added "Blocked via web dashboard" entries
#   - Touch any Microsoft Azure (20.x.x.x, 4.x.x.x) IPs (see Tier 2 in triage doc)
#   - Touch the Greek ISP IP 31.152.235.241 (see Tier 4)
#   - Modify /etc/aegis/aegis.toml
#   - Restart the aegis daemon
#
set -euo pipefail

# -----------------------------------------------------------------------------
# SAFETY GATE — three ways to bypass, pick whichever you prefer
# -----------------------------------------------------------------------------
# Accept either DISABLE_SAFETY=1 in the environment (set INSIDE sudo, not
# before it — sudo strips env by default) or a --force CLI flag.
force_flag=0
if [[ "${1:-}" == "--force" || "${1:-}" == "-f" ]]; then
    force_flag=1
fi

if [[ "${DISABLE_SAFETY:-}" != "1" && $force_flag -eq 0 ]]; then
    echo ""
    echo "  This script will unblock ~30 IPs from AEGIS_BLOCK and block_list.json."
    echo "  It has not been authorized yet."
    echo ""
    echo "  Before running:"
    echo "    1. Read docs/TRIAGE_PHASE_A0.md end-to-end"
    echo "    2. Verify the 'ips' array below matches your expectations"
    echo "    3. Pick one of these invocations (all equivalent):"
    echo ""
    echo "         sudo DISABLE_SAFETY=1 bash $0"
    echo "         sudo bash $0 --force"
    echo "         DISABLE_SAFETY=1 sudo -E bash $0"
    echo ""
    echo "  (The naive 'DISABLE_SAFETY=1 sudo bash ...' does NOT work because"
    echo "  sudo strips environment variables by default.)"
    echo ""
    echo "  Refusing to run with safety gate enabled."
    exit 1
fi
# -----------------------------------------------------------------------------
# END SAFETY GATE
# -----------------------------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
    echo "This script needs root (for aegis unblock → iptables)." >&2
    echo "Run with: sudo bash $0" >&2
    exit 1
fi

if ! command -v aegis >/dev/null 2>&1; then
    echo "Error: aegis binary not found in PATH" >&2
    exit 1
fi

# Tier 1 — confirmed infrastructure. Every IP has whois evidence in the triage doc.
ips=(
    # Amazon CloudFront edge (NetName: AT-88-Z / OrgName: Amazon Technologies Inc.)
    "13.224.185.97"
    "13.224.185.100"
    "13.224.185.102"
    "13.224.185.127"
    "13.250.101.110"
    "13.218.94.63"

    # GitHub (NetName: GITHU / OrgName: GitHub, Inc.)
    "140.82.112.25"
    "140.82.112.26"
    "140.82.114.22"
    "140.82.114.26"

    # Cloudflare (NetName: CLOUDFLARENET / OrgName: Cloudflare, Inc.)
    "104.28.164.48"
    "104.28.156.138"
    "104.28.157.140"
    "104.28.163.100"
    "172.71.184.177"
    "172.68.10.6"
    "172.70.248.64"
    "172.69.151.108"

    # Google (NetName: GOOGLE / OrgName: Google LLC)
    "66.102.9.4"
    "66.102.9.5"
    "66.102.9.6"
    "142.250.32.6"
    "142.250.32.7"
    "142.250.32.8"
    "74.125.210.134"
    "66.249.66.35"   # Googlebot
    "66.249.93.160"  # Googlebot
)

total=${#ips[@]}
success=0
skipped=0
failed=0

echo ""
echo "=== Unblocking $total infrastructure IPs from AEGIS_BLOCK ==="
echo ""

for ip in "${ips[@]}"; do
    printf "  %-18s ... " "$ip"
    if output=$(aegis unblock "$ip" 2>&1); then
        if echo "$output" | grep -qi "was not in the block list\|not in.*block\|WARN"; then
            echo "not present (already clean)"
            skipped=$((skipped+1))
        else
            echo "unblocked"
            success=$((success+1))
        fi
    else
        echo "FAILED: $output"
        failed=$((failed+1))
    fi
done

echo ""
echo "=== Summary ==="
echo "  Unblocked:       $success"
echo "  Already clean:   $skipped"
echo "  Failed:          $failed"
echo ""

if [[ $failed -gt 0 ]]; then
    echo "  One or more unblock commands failed. Review output above."
    exit 2
fi

echo "  Verify with:"
echo "    sudo aegis status"
echo "    sudo iptables -L AEGIS_BLOCK -n -v | grep -E '(13\\.224\\.185|140\\.82\\.112|104\\.28\\.16|66\\.102\\.9)'"
echo "    cat /root/.aegis/block_list.json | python3 -m json.tool | grep -B1 -A3 13.224.185"
echo ""
echo "  None of the above should return matches for the unblocked IPs."
echo ""

exit 0
