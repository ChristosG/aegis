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

  sudo is needed for reading auth logs, /proc inspection, and iptables. Without it, modules degrade gracefully but some detections will be limited.

  Key data files in ~/.aegis/:
    threats.jsonl          — append-only JSONL log of all detected threats
    seen_fingerprints.json — dedup state (which threats were already seen)
    block_list.json        — persisted firewall block list
    baseline.json          — file integrity baseline hashes
    feeds/                 — cached threat intelligence feed data
    quarantine/            — quarantined files and their .meta.json sidecars

  System files created by `aegis init`:
    /etc/aegis/aegis.toml                       — main config
    /etc/sysctl.d/99-aegis-hardening.conf       — kernel hardening params
    /etc/fail2ban/filter.d/aegis-threat.conf    — fail2ban filter
    /etc/fail2ban/jail.d/aegis-threat.conf      — fail2ban jail
    /etc/systemd/system/aegis.service           — systemd unit
    /usr/local/bin/aegis                        — installed binary

  To install system-wide manually (alternative to `aegis init`):

  sudo cp target/release/aegis /usr/local/bin/
  sudo mkdir -p /etc/aegis
  sudo cp aegis.toml /etc/aegis/aegis.toml
  sudo cp aegis.service /etc/systemd/system/
  sudo systemctl daemon-reload
  sudo systemctl enable aegis
  sudo systemctl start aegis
