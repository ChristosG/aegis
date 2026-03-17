 # Full system hardening init (recommended first-run)
  # Sets up config, sysctl, baseline, firewall dedup, fail2ban, systemd
  sudo ./target/release/aegis init

  # Init with selective skips
  sudo ./target/release/aegis init --skip-sysctl
  sudo ./target/release/aegis init --skip-baseline
  sudo ./target/release/aegis init --skip-service
  sudo ./target/release/aegis init --skip-firewall-cleanup
  sudo ./target/release/aegis init --skip-fail2ban

  # One-shot full scan (needs sudo for /proc access + firewall)
  sudo ./target/release/aegis scan

  # Scan specific modules only
  sudo ./target/release/aegis scan --auth
  sudo ./target/release/aegis scan --network --web
  sudo ./target/release/aegis scan --processes
  sudo ./target/release/aegis scan --files
  sudo ./target/release/aegis scan --intel
  sudo ./target/release/aegis scan --anomaly
  sudo ./target/release/aegis scan --honeypot
  sudo ./target/release/aegis scan --cert
  sudo ./target/release/aegis scan --dns
  sudo ./target/release/aegis scan --rootkit
  sudo ./target/release/aegis scan --ssh-session

  # Scan with auto-response (blocks IPs, kills miners)
  sudo ./target/release/aegis scan --auto-respond

  # Run a second scan immediately — duplicate threats are suppressed
  # (dedup TTL defaults to 1h, configurable via dedup_ttl in aegis.toml)
  sudo ./target/release/aegis scan --auto-respond

  # Create file integrity baseline first, then scan for changes
  sudo ./target/release/aegis baseline
  sudo ./target/release/aegis scan --files

  # Start daemon mode (continuous monitoring)
  # - file_integrity uses inotify for real-time detection
  # - other modules scan every 60 seconds
  # - duplicate threats are suppressed within the dedup TTL window
  sudo ./target/release/aegis watch --foreground

  # View threat history (loads from ~/.aegis/threats.jsonl)
  ./target/release/aegis threats

  # View security posture with threat history
  ./target/release/aegis status

  # Manual IP blocking
  sudo ./target/release/aegis block 203.0.113.42 -d 24h
  sudo ./target/release/aegis block 198.51.100.1 -d 7d
  sudo ./target/release/aegis block 192.0.2.1 -d 1h
  sudo ./target/release/aegis unblock 203.0.113.42

  # Generate report (includes persisted threat history)
  sudo ./target/release/aegis report

  # Global options (work with any subcommand)
  aegis --config /path/to/aegis.toml scan
  aegis --verbose scan
  aegis --help
  aegis --version

  # CIS benchmark compliance audit
  sudo ./target/release/aegis audit
  sudo ./target/release/aegis audit --profile workstation
  sudo ./target/release/aegis audit --format json --output audit.json

  # Enterprise features (build with feature flags)
  cargo build --release --features "web-dashboard,ebpf"
  cargo build --release --features "web-dashboard,tls-fingerprint,yara,server"

  sudo is needed for reading auth logs, /proc inspection, and iptables. Without it, modules degrade gracefully but some detections will be limited.

  Key data files in ~/.aegis/:
    threats.jsonl          — append-only JSONL log of all detected threats
    seen_fingerprints.json — dedup state (which threats were already seen)
    block_list.json        — persisted firewall block list
    baseline.json          — file integrity baseline hashes
    feeds/                 — cached threat intelligence feed data
    quarantine/            — quarantined files and their .meta.json sidecars
    email_cooldowns.json   — email alert rate-limit state per threat type
    outbound_baseline.json — known outbound destinations baseline (auto-capped at 5000)
    anomaly_cron_baseline.json    — cron file baseline for change detection
    anomaly_sudoers_baseline.json — sudoers baseline for change detection
    anomaly_users_baseline.json   — known user accounts baseline
    kernel_modules_baseline.json  — loaded kernel modules baseline
    enrichment_cache.json  — cached threat intel enrichment results
    sessions/              — SSH session metadata
    forensic/              — automated forensic snapshots
    yara_rules/            — YARA rule files (.yar)
    yara_cache.json        — SHA-256 known-good binary cache

  System files created by `aegis init`:
    /etc/aegis/aegis.toml                       — main config
    /etc/sysctl.d/99-aegis-hardening.conf       — kernel hardening params
    /etc/fail2ban/filter.d/aegis-threat.conf    — fail2ban filter
    /etc/fail2ban/jail.d/aegis-threat.conf      — fail2ban jail
    /etc/systemd/system/aegis.service           — systemd unit
    /usr/local/bin/aegis                        — installed binary

  # Web Dashboard (optional, feature-gated)
  cargo build --release --features web-dashboard
  sudo ./target/release/aegis watch --foreground
  # Dashboard available at http://localhost:3000
  # Auth token printed to stdout on first run

  Web Dashboard pages:
    /              — Dashboard (real-time overview, threat stats)
    /threats       — Searchable threat log with pagination
    /firewall      — Active blocks, whitelist management
    /status        — System health and module status
    /config        — Live configuration viewer
    /logs          — Structured log viewer

  API endpoints (27 total):
    GET  /api/threats    — threat list with search/pagination
    GET  /api/blocks     — active firewall blocks
    POST /api/block      — block an IP
    POST /api/unblock    — unblock an IP
    GET  /api/whitelist  — list whitelisted IPs
    POST /api/whitelist  — add to whitelist
    GET  /api/config     — current configuration
    POST /api/check      — validate config
    POST /api/scan       — trigger on-demand scan
    POST /api/respond    — trigger auto-response
    GET  /api/stats      — dashboard statistics
    GET  /api/status     — system health
    GET  /api/report     — generate report
    GET  /api/logs       — structured logs
    GET  /ws/threats     — WebSocket live threat stream
    GET  /health         — health check
    GET  /api/audit      — run CIS audit and return results
    GET  /api/enrich/:ip — enrich IP with threat intelligence

  New modules in aegis.toml:
    [anomaly]    — login time, cron/sudoers monitoring, new users, kernel modules
    [honeypot]   — decoy port listeners with auto-block
    [cert]       — TLS certificate expiry monitoring
    [dns]          — DGA domain detection, DNS tunneling
    [rootkit]      — hidden process/file detection, LD_PRELOAD scanning
    [ssh_session]  — audit log analysis for suspicious commands
    [container]    — Docker/containerd/podman awareness
    [ebpf]         — eBPF real-time monitoring (auto-fallback)
    [enrichment]   — AbuseIPDB/Shodan/GreyNoise integration
    [audit]        — CIS benchmark compliance checks
    [forensic]     — automated forensic snapshots on critical threats

  To install system-wide manually (alternative to `aegis init`):

  sudo cp target/release/aegis /usr/local/bin/
  sudo mkdir -p /etc/aegis
  sudo cp aegis.toml /etc/aegis/aegis.toml
  sudo cp aegis.service /etc/systemd/system/
  sudo systemctl daemon-reload
  sudo systemctl enable aegis
  sudo systemctl start aegis
