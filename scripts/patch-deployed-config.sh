#!/usr/bin/env bash
# Patches /etc/aegis/aegis.toml with the v2.8.2 [web] tuning knobs that the
# deployed config is missing (endpoint_thresholds, ddos_high_traffic_paths,
# ddos_high_traffic_threshold, ddos_static_paths). Idempotent.
#
# Usage:  sudo bash scripts/patch-deployed-config.sh
set -euo pipefail

CFG=/etc/aegis/aegis.toml
[ -f "$CFG" ] || { echo "no $CFG"; exit 1; }

if grep -q '^endpoint_thresholds\|^\[\[web.endpoint_thresholds\]\]' "$CFG"; then
    echo "endpoint_thresholds already present — nothing to do."
    exit 0
fi

cp -a "$CFG" "$CFG.bak.$(date +%s)"

awk '
  /^scanner_agents = / && !done {
    print
    print ""
    print "# v2.6.1: high-traffic / streaming path knobs."
    print "# Auto-detected for /sse, /events, /stream, /v1/chat/completions, /api/chat,"
    print "# /api/stream, /api/sse and any WebSocket (HTTP 101)."
    print "ddos_high_traffic_paths = []"
    print "ddos_high_traffic_threshold = 2000"
    print ""
    print "# Extra static-asset path prefixes (merged with built-in /_next/static/, /static/,"
    print "# /assets/, common extensions). Counted as static (excluded entirely)."
    print "ddos_static_paths = []"
    print ""
    print "# v2.8.3: per-endpoint DDoS thresholds. Manage via /web-rules WebUI page."
    print "# Each request matching a rule is counted ONLY against that rule (not the"
    print "# global threshold). On overlap, longest path wins; exact beats prefix on tie."
    print "#"
    print "# Example (uncomment & edit, or use the WebUI):"
    print "# [[web.endpoint_thresholds]]"
    print "# path = \"/api/positions/integrity\""
    print "# threshold = 500"
    print "# match_type = \"exact\""
    print "#"
    print "# [[web.endpoint_thresholds]]"
    print "# path = \"/api/login\""
    print "# threshold = 10"
    print "# match_type = \"exact\""
    done=1
    next
  }
  { print }
' "$CFG" > "$CFG.new"

mv "$CFG.new" "$CFG"
chown root:root "$CFG"
chmod 644 "$CFG"
echo "patched. backup at $CFG.bak.*"
echo "validate:  aegis check"
echo "restart:   systemctl restart aegis"
