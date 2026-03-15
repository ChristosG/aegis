<p align="center">
  <pre>
   ___    ____________  _____
  /   |  / ____/ ____/ /  _/ ____
 / /| | / __/ / / __   / / / ___/
/ ___ |/ /___/ /_/ / _/ / (__  )
/_/  |_/_____/\____/ /___//____/
  </pre>
</p>

<h3 align="center">Linux Security Monitoring & Automated Response</h3>

<p align="center">
  <em>A lightweight, single-binary security tool that detects network attacks, malware, brute-force attempts, file tampering, web exploits, and known-malicious IPs &mdash; then automatically blocks them.</em>
</p>

<p align="center">
  <img alt="Language" src="https://img.shields.io/badge/language-Rust-orange">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-blue">
  <img alt="Platform" src="https://img.shields.io/badge/platform-Linux-green">
  <img alt="Tests" src="https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/ChristosG/aegis/main/.github/badges/tests.json">
  <img alt="unsafe" src="https://img.shields.io/badge/unsafe-forbidden-red">
</p>

<h4 align="center">Get Aegis running in 30 seconds</h4>

**CLI only** — terminal monitoring & automated response:
```bash
curl -fsSL https://raw.githubusercontent.com/ChristosG/aegis/main/install.sh | sudo bash
```

**Full install** — includes the web dashboard:
```bash
curl -fsSL https://raw.githubusercontent.com/ChristosG/aegis/main/install.sh | sudo bash -s -- --full
```

---

## Why Aegis?

After spending days manually defending a Linux web server against a botnet SYN flood, SSH brute-force attacks, and vulnerability scanners, we automated everything we did into a single Rust binary.

Aegis is what you get when incident response hardens into permanent infrastructure.

Zero runtime dependencies, ~7.6 MB binary, installs in seconds, detects real threats in milliseconds.

```
$ sudo aegis scan

[*] Scanning: auth
------------------------------------------------------------
  high [2026-03-13 02:58:09 UTC] Brute Force -- SSH brute force detected: 221 failed attempts from 203.0.113.42
       Source IP : 203.0.113.42
       Target    : sshd

[*] Scanning: web
------------------------------------------------------------
  high [2026-03-13 02:58:09 UTC] SQL Injection -- SQL injection attempt detected from 198.51.100.77
       Source IP : 198.51.100.77
  high [2026-03-13 02:58:09 UTC] Web DDoS -- Potential DDoS: 198.51.100.77 sent 2097 requests
       Source IP : 198.51.100.77

============================================================
 SCAN SUMMARY
============================================================
  Duration     : 0.02s
  Modules      : network, process, auth, file_integrity, web, threat_intel
  Total threats: 91
    high       : 76
    low        : 14
    info       : 1
============================================================
```

---

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Usage](#usage)
  - [System Hardening Init](#system-hardening-init)
  - [One-Shot Scan](#one-shot-scan)
  - [Threat Deduplication](#threat-deduplication)
  - [Daemon Mode](#daemon-mode)
  - [File Integrity Baseline](#file-integrity-baseline)
  - [Manual IP Blocking](#manual-ip-blocking)
  - [Security Reports](#security-reports)
- [Detection Modules](#detection-modules)
  - [Network Module](#network-module)
  - [Process Module](#process-module)
  - [Authentication Module](#authentication-module)
  - [Web Module](#web-module)
  - [File Integrity Module](#file-integrity-module)
  - [Threat Intelligence Module](#threat-intelligence-module)
  - [Anomaly Detection Module](#anomaly-detection-module)
  - [Honeypot Module](#honeypot-module)
  - [Certificate Monitoring Module](#certificate-monitoring-module)
- [Automated Response](#automated-response)
  - [Response Actions](#response-actions)
  - [Firewall Backends](#firewall-backends)
  - [Safety Mechanisms](#safety-mechanisms)
- [Alerting](#alerting)
  - [Terminal Output](#terminal-output)
  - [JSON Log File](#json-log-file)
  - [Email Alerts](#email-alerts)
  - [Webhook Alerts](#webhook-alerts)
  - [Slack Alerts](#slack-alerts)
  - [Telegram Alerts](#telegram-alerts)
- [Web Dashboard](#web-dashboard)
- [Configuration Reference](#configuration-reference)
- [Threat Reference](#threat-reference)
- [Architecture](#architecture)
- [Security Hardening](#security-hardening)
- [Deployment](#deployment)
  - [systemd Service](#systemd-service)
  - [Capabilities Mode](#capabilities-mode)
- [Building from Source](#building-from-source)
- [Contributing](#contributing)
- [License](#license)

---

## Features

| Category | What it does |
|----------|-------------|
| **Network** | Detects SYN floods, port scans, suspicious outbound connections, C2 beacons |
| **Process** | Catches crypto miners, reverse shells, binaries running from /tmp or /dev/shm |
| **Auth** | SSH brute-force detection, root login alerts, login anomaly tracking |
| **Web** | Nginx log analysis for DDoS, SQL injection, path traversal, vulnerability scanners |
| **File Integrity** | SHA-256 baseline comparison with optional real-time inotify monitoring |
| **Threat Intel** | Cross-references active connections against 6 curated blocklists |
| **Anomaly** | Unusual login times, cron/sudoers changes, new user accounts, kernel module integrity |
| **Honeypot** | Decoy port listeners with automatic IP blocking on connection |
| **Cert Monitoring** | TLS certificate expiry monitoring with configurable warning threshold |
| **Web Dashboard** | Real-time security dashboard with 6 pages, WebSocket live feed, token auth (opt-in) |
| **Auto-Response** | Blocks IPs via iptables/nftables/ufw, kills malicious processes |
| **Threat Dedup** | Cross-run deduplication with configurable TTL &mdash; same threat won't re-alert within the window |
| **JSONL Logging** | All threats persisted to `~/.aegis/threats.jsonl` for history, reports, and `aegis threats` |
| **Alerting** | Terminal, JSON log, SMTP email, Slack, Telegram, webhooks |
| **Connection Rate** | Per-IP connection rate monitoring with configurable threshold |
| **Outbound Anomaly** | Detects new outbound destinations not in established baseline |

**Design principles:**
- Single static binary &mdash; no Python, no JVM, no containers
- Zero `unsafe` code &mdash; eliminates memory corruption attack surface
- No listening sockets in core &mdash; web dashboard is opt-in via feature flag
- No shell invocation &mdash; all external commands use safe `Command::new()` with explicit args
- Minimal dependencies &mdash; every crate justified and auditable

---

## Quick Start

```bash
# Build
git clone https://github.com/chrismannina/aegis.git
cd aegis
cargo build --release

# Full system hardening (config, sysctl, baseline, firewall, fail2ban, systemd)
sudo ./target/release/aegis init

# Run a full scan
sudo ./target/release/aegis scan

# Run with auto-response (blocks attackers, kills miners)
sudo ./target/release/aegis scan --auto-respond

# Start daemon mode
sudo ./target/release/aegis watch --foreground
```

---

## Installation

### From source (recommended)

```bash
git clone https://github.com/chrismannina/aegis.git
cd aegis
cargo build --release
```

### System-wide setup (automated)

The recommended way to set up Aegis system-wide is via `aegis init`, which handles everything in one command:

```bash
sudo ./target/release/aegis init
```

This runs 7 phases: prerequisite checks, config/data directory creation, kernel hardening (sysctl), file integrity baseline, iptables dedup cleanup, fail2ban jail installation, and systemd service setup. See [System Hardening Init](#system-hardening-init) for details.

### Manual setup (alternative)

If you prefer to set up each piece manually:

```bash
# Install binary
sudo cp target/release/aegis /usr/local/bin/

# Install config
sudo mkdir -p /etc/aegis
sudo cp aegis.toml /etc/aegis/aegis.toml

# Create data directory
sudo mkdir -p /root/.aegis

# Install systemd service (optional)
sudo cp aegis.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable aegis
```

### Requirements

- Linux kernel 3.x+ (for `/proc` and inotify support)
- Rust 1.70+ (for building)
- Root access or `CAP_NET_ADMIN + CAP_DAC_READ_SEARCH + CAP_KILL` capabilities

---

## Usage

### System Hardening Init

`aegis init` is a comprehensive first-run command that sets up everything needed for a hardened Linux server in one shot. It requires root and is fully idempotent (safe to run multiple times).

```bash
sudo aegis init
```

**Phases:**

| Phase | What it does |
|-------|-------------|
| 1. Prerequisites | Verifies root, checks for iptables/systemctl/sysctl, auto-installs fail2ban if missing |
| 2. Config & Data | Creates `/etc/aegis/aegis.toml` (never overwrites), `~/.aegis/`, `~/.aegis/feeds/`, `~/.aegis/quarantine/` |
| 3. Kernel Hardening | Writes 15 sysctl parameters to `/etc/sysctl.d/99-aegis-hardening.conf` (SYN cookies, rp_filter, ASLR, etc.) |
| 4. Baseline | Generates SHA-256 file integrity baseline (skips if one already exists) |
| 5. Firewall Cleanup | Removes duplicate rules from the `AEGIS_BLOCK` iptables chain, audits INPUT policy |
| 6. fail2ban | Installs `aegis-threat` filter + jail that reads `threats.jsonl` and bans source IPs (never touches existing jails) |
| 7. Systemd Service | Copies binary to `/usr/local/bin/aegis`, installs and enables `aegis.service` (does NOT auto-start) |

**Skip individual phases:**

```bash
sudo aegis init --skip-sysctl              # Skip kernel hardening
sudo aegis init --skip-baseline            # Skip file integrity baseline
sudo aegis init --skip-service             # Skip systemd service install
sudo aegis init --skip-firewall-cleanup    # Skip iptables dedup cleanup
sudo aegis init --skip-fail2ban            # Skip fail2ban jail setup
```

**Safety guarantees:**
- Never overwrites existing `/etc/aegis/aegis.toml`
- Never modifies existing fail2ban configs (only adds new `aegis-threat` files)
- Never changes the INPUT chain policy (advisory warning only)
- Never starts the service automatically (you review config first)
- Never touches Docker iptables chains
- All sysctl changes are reversible: delete `/etc/sysctl.d/99-aegis-hardening.conf` and run `sysctl --system`

---

### One-Shot Scan

Run all enabled modules:

```bash
sudo aegis scan
```

Scan specific modules:

```bash
sudo aegis scan --network          # Network connections only
sudo aegis scan --processes        # Running processes only
sudo aegis scan --auth             # Authentication logs only
sudo aegis scan --web              # Web server logs only
sudo aegis scan --files            # File integrity only
sudo aegis scan --intel            # Threat intelligence only
sudo aegis scan --network --auth   # Combine modules
```

Enable automated response during scan:

```bash
sudo aegis scan --auto-respond
```

This will:
- Block attacking IPs via the configured firewall backend
- Kill crypto miners and reverse shells
- Log all actions taken
- Write all threats to `~/.aegis/threats.jsonl`
- Track seen threats for deduplication across runs

**Threat deduplication:** Running the same scan again immediately will suppress already-seen threats within the TTL window (default: 1 hour). The scan summary shows how many were suppressed:

```
  Total threats: 3
  Suppressed   : 88 (previously seen within 1h)
```

Configure or disable dedup in `aegis.toml`:

```toml
[general]
dedup_ttl = "1h"    # "30m", "2h", "0s" to disable
```

### Daemon Mode

Start continuous monitoring:

```bash
sudo aegis watch --foreground
```

In daemon mode:
- **File integrity** uses inotify for real-time change detection (instant alerts on file changes)
- **All other modules** scan on a 60-second interval loop
- Threat deduplication with configurable TTL prevents repeated alerts for the same active threat
- Dedup state and block list are persisted to disk on shutdown
- Threat intel feeds refresh automatically (default: every 6 hours)
- All detected threats are written to `~/.aegis/threats.jsonl`
- Auto-response is always active
- Graceful shutdown on SIGINT/SIGTERM

### File Integrity Baseline

Create a baseline of critical system files:

```bash
sudo aegis baseline
```

This computes SHA-256 hashes for all files in the configured watch paths (default: `/etc`, `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`) and saves the baseline to `~/.aegis/baseline.json`.

After creating a baseline, file integrity scans will detect:
- **Modified files** &mdash; hash mismatch
- **New files** &mdash; present on disk but not in baseline
- **Deleted files** &mdash; in baseline but missing from disk

```bash
# After creating baseline, scan for changes
sudo aegis scan --files
```

### Manual IP Blocking

Block an IP with a duration:

```bash
sudo aegis block 203.0.113.42 -d 24h    # Block for 24 hours
sudo aegis block 198.51.100.1 -d 7d     # Block for 7 days
sudo aegis block 192.0.2.1 -d 1h        # Block for 1 hour
```

Unblock:

```bash
sudo aegis unblock 203.0.113.42
```

### Security Reports

Generate a comprehensive text report:

```bash
sudo aegis report
```

The report includes:
- Executive summary with threat counts by severity
- All threats grouped by severity (Critical first)
- Top 10 attacking IPs with event counts
- Per-module findings breakdown
- Currently blocked IPs with expiration times
- Actionable recommendations based on detected threats

Check current security posture (includes threat history from JSONL):

```bash
sudo aegis status
```

View threat history (loaded from `~/.aegis/threats.jsonl`):

```bash
aegis threats
```

These commands load persisted threat data from the JSONL log, so they show results from previous scans and daemon sessions &mdash; not just the current run.

### Global Options

```bash
aegis --config /path/to/aegis.toml scan    # Custom config file
aegis --verbose scan                        # Debug-level output
aegis --help                                # Full help text
aegis --version                             # Version info
```

Config file search order (when `--config` is not specified):
1. `./aegis.toml`
2. `/etc/aegis/aegis.toml`
3. `~/.config/aegis/aegis.toml`

---

## Detection Modules

### Network Module

**Data source:** `/proc/net/tcp`, `/proc/net/tcp6`

Parses the kernel's TCP connection table directly &mdash; no packet capture, no eBPF, no performance impact.

#### SYN Flood Detection

Counts connections in `SYN_RECV` state. When a SYN flood occurs, the kernel accumulates half-open connections waiting for the final ACK that never comes.

```
Trigger: SYN_RECV count > syn_flood_threshold (default: 50)
Severity: High
Includes: Total count, top source IPs
```

#### Port Scan Detection

Groups inbound connections by remote IP and counts unique destination ports. A single IP touching many ports indicates reconnaissance.

```
Trigger: Unique ports from single IP > port_scan_threshold (default: 15)
Severity: Medium
Skips: Private/loopback IPs
Includes: Port count, sample ports scanned
```

#### Suspicious Outbound Connections

Identifies ESTABLISHED connections to public IPs on non-standard ports. Legitimate traffic typically uses well-known ports (80, 443, 53, etc.). Unexpected outbound connections may indicate malware callbacks, data exfiltration, or backdoors.

```
Trigger: Outbound to public IP on port not in known_outbound_ports
Severity: Medium
Skips: Connections to private IPs
Includes: Remote IP, remote port, local port
```

#### C2 Beacon Detection

Detects multiple simultaneous connections to the same remote IP:port combination. Command-and-control infrastructure often maintains persistent connections or rapid reconnects.

```
Trigger: Connection count to same IP:port > c2_beacon_threshold (default: 10)
Severity: Critical
Skips: Private IPs
Includes: Remote IP:port, connection count
```

#### Connection Rate Detection

Monitors the total number of concurrent connections per remote IP. Detects distributed or aggressive connection patterns.

```
Trigger: Connections from single IP > connection_rate_threshold (default: 100)
Severity: High
Skips: Private IPs
Includes: IP, connection count, threshold
```

#### New Outbound Destination Detection

Maintains a baseline of known outbound destinations (IP:port pairs). Alerts when connections are made to previously unseen destinations, which may indicate new C2 channels or data exfiltration.

```
Trigger: Outbound connection to IP:port not in baseline
Severity: Medium
Baseline: Auto-maintained in ~/.aegis/outbound_baseline.json (capped at 5000 entries)
Includes: Destination IP, port
```

**Configuration:**

```toml
[network]
enabled = true
syn_flood_threshold = 50
port_scan_threshold = 15
port_scan_window = 60
known_outbound_ports = [80, 443, 53, 22, 25, 587]
c2_beacon_threshold = 10
c2_beacon_window = 300
connection_rate_threshold = 100
```

---

### Process Module

**Data source:** `/proc/[pid]/*` (stat, cmdline, exe, fd)

Enumerates all running processes and inspects them for malicious characteristics.

#### Crypto Miner Detection

Three-layer detection:

1. **Name matching** &mdash; process name compared against known miner names (xmrig, minerd, cpuminer, cgminer, bfgminer, ethminer, nbminer, t-rex, phoenixminer, ccminer)
2. **Command-line analysis** &mdash; scans cmdline for mining indicators: `--algo`, `--pool`, `stratum+tcp://`, `--donate-level`, `randomx`, `cryptonight`, `--coin`
3. **CPU usage** &mdash; calculates CPU% from `/proc/[pid]/stat` (utime + stime vs system uptime). High CPU with mining indicators confirms detection.

```
Severity: High
Includes: PID, process name, exe path, CPU%, full cmdline
```

#### Reverse Shell Detection

Two detection methods:

1. **Pattern matching** &mdash; cmdline checked for known reverse shell patterns:
   - `bash -i >& /dev/tcp/`
   - `nc -e /bin/sh`, `ncat -e`
   - `socat exec:`, `socat tcp:`
   - `python -c "import socket"`, `python -c 'import pty'`
   - `perl -e 'use Socket'`
   - `php -r '$sock=fsockopen'`
   - `ruby -rsocket`

2. **File descriptor analysis** &mdash; for shell processes (bash, sh, zsh, dash, fish, python, perl, ruby, php, nc, ncat, socat), checks `/proc/[pid]/fd/` for `socket:` symlinks. Cross-references socket inodes with `/proc/net/tcp` to find remote IP connections. A shell with a network socket to a public IP is a strong indicator of compromise.

```
Severity: Critical
Includes: PID, process name, remote address, detection method
```

#### Suspicious Binary Detection

Flags processes running from directories that should not contain executables:

- `/tmp`
- `/dev/shm`
- `/var/tmp`
- `/run/shm`

Also detects binaries marked `(deleted)` &mdash; the executable has been removed from disk but is still running in memory, a common malware persistence technique.

```
Severity: High
Includes: PID, process name, exe path, directory
```

**Configuration:**

```toml
[process]
enabled = true
miner_cpu_threshold = 80.0
miner_names = ["xmrig", "minerd", "cpuminer", "cgminer", "bfgminer",
               "ethminer", "nbminer", "t-rex", "phoenixminer", "ccminer"]
suspicious_dirs = ["/tmp", "/dev/shm", "/var/tmp", "/run/shm"]
detect_reverse_shells = true
```

---

### Authentication Module

**Data source:** `/var/log/auth.log`, `/var/log/secure`

Parses SSH authentication logs using regex patterns to extract failed/successful login attempts with source IPs.

#### Brute Force Detection

Groups failed login attempts by source IP. When failures from a single IP exceed the threshold, it's flagged as a brute-force attack.

```
Trigger: Failed attempts from single IP >= brute_force_threshold (default: 5)
Severity: High
Includes: Failure count, targeted usernames, threshold value
```

#### Root Login Detection

Flags any successful login as the root user. Direct root access is a security risk &mdash; organizations should use sudo instead.

```
Trigger: Successful root login (any source)
Severity: Medium
Includes: Source IP, authentication method
```

#### Login Anomaly Detection

Reports successful logins from external (non-private) IP addresses. In scan mode, this provides visibility into who is accessing the system.

```
Trigger: Successful login from non-RFC1918 IP
Severity: Info
Includes: Username, source IP
```

**Configuration:**

```toml
[auth]
enabled = true
brute_force_threshold = 5
brute_force_window = 300
alert_root_login = true
alert_new_ip = true
log_paths = ["/var/log/auth.log", "/var/log/secure"]
```

---

### Web Module

**Data source:** Nginx/Apache access logs (combined format)

Parses web server access logs to detect application-layer attacks. Processes the last 10,000 lines of each log file.

#### Scanner Detection

Identifies automated vulnerability scanners by:

1. **User-Agent matching** &mdash; checks against known scanner tools (nikto, sqlmap, nmap, masscan, zgrab, gobuster, dirbuster, wfuzz, nuclei, httpx)
2. **Path probing** &mdash; detects requests to common attack paths:
   - `/.env`, `/.git/config`, `/wp-admin`, `/wp-login.php`
   - `/phpmyadmin`, `/phpinfo.php`, `/admin`
   - `/actuator`, `/console`, `/manager/html`
   - `/solr`, `/debug`, `/server-status`, `/server-info`

```
Severity: Low
Deduplicated: Per source IP
```

#### DDoS Detection

Counts requests per IP and estimates requests-per-minute from log timestamps. A single IP sending excessive requests indicates an application-layer DDoS.

```
Trigger: Requests per minute from single IP > ddos_threshold (default: 200)
Severity: High
Includes: Request count, threshold, estimated RPM
```

#### SQL Injection Detection

Scans request URIs for 15 SQLi patterns (with URL-decoded normalization):

| Pattern | Example |
|---------|---------|
| UNION SELECT | `/page?id=1 UNION SELECT username,password FROM users` |
| Boolean injection | `/page?id=1' OR 1=1--` |
| Stacked queries | `/page?id=1'; DROP TABLE users--` |
| Time-based blind | `/page?id=1 AND SLEEP(5)` |
| Schema enumeration | `/page?id=1 AND table_name=` |
| Comment injection | `/page?id=1/*`, `/page?id=1--` |

```
Severity: High
Includes: Matched pattern, request URI, source IP
```

#### Path Traversal Detection

Detects directory traversal attempts in request URIs:

| Pattern | Example |
|---------|---------|
| Relative paths | `/download?file=../../../etc/passwd` |
| System files | `/page?f=/etc/shadow` |
| Proc filesystem | `/read?path=/proc/self/environ` |
| URL-encoded | `/path?f=%2e%2e%2f%2e%2e%2fetc%2fpasswd` |
| Null byte | `/image.php?f=shell.php%00.jpg` |

```
Severity: High
Includes: Matched pattern, request URI, source IP
```

**Configuration:**

```toml
[web]
enabled = true
access_log_paths = ["/var/log/nginx/access.log"]
ddos_threshold = 200
detect_sqli = true
detect_path_traversal = true
detect_scanners = true
scanner_agents = ["nikto", "sqlmap", "nmap", "masscan", "zgrab",
                  "gobuster", "dirbuster", "wfuzz", "nuclei", "httpx"]
```

---

### File Integrity Module

**Data source:** Filesystem (SHA-256 hashing), inotify (daemon mode)

Compares current file state against a stored baseline of cryptographic hashes.

#### Scan Mode

1. Loads baseline from `~/.aegis/baseline.json`
2. For each file in the baseline:
   - Computes current SHA-256 hash
   - Compares against stored hash
   - Reports modifications and deletions
3. Walks watch directories for new files not in the baseline

| Detection | Severity | Details |
|-----------|----------|---------|
| File Modified | Medium | Old hash, new hash, file path |
| File Deleted | Medium | Expected hash, file path |
| File Added | Low | File path, directory |

#### Daemon Mode (inotify)

Uses Linux inotify for real-time monitoring. Watches for:
- `IN_MODIFY` &mdash; file content changed
- `IN_CREATE` &mdash; new file created
- `IN_DELETE` &mdash; file removed
- `IN_MOVED_FROM` / `IN_MOVED_TO` &mdash; file renamed or moved

Events are sent immediately through the event bus for auto-response.

**Configuration:**

```toml
[file_integrity]
enabled = true
watch_paths = ["/etc", "/usr/bin", "/usr/sbin", "/bin", "/sbin"]
exclude_paths = ["/etc/mtab", "/etc/resolv.conf",
                 "/etc/hosts.allow", "/etc/hosts.deny"]
baseline_path = "~/.aegis/baseline.json"
use_inotify = true
```

---

### Threat Intelligence Module

**Data source:** Curated blocklists (cached locally), `/proc/net/tcp`

Cross-references every active network connection against community-maintained threat feeds.

#### Default Feeds

| Feed | Coverage | Weight | Update Frequency |
|------|----------|--------|-----------------|
| [FireHOL Level 1](https://github.com/firehol/blocklist-ipsets) | Worst-of-the-worst IPs | 90 | Daily |
| [Spamhaus DROP](https://www.spamhaus.org/drop/) | Hijacked netblocks (CIDRs) | 95 | Hourly |
| [blocklist.de](https://www.blocklist.de/) | Active attackers (SSH, web, mail) | 70 | 15 min |
| [CINS Army](https://cinsscore.com/) | Sentinel network detections | 60 | Daily |
| [Emerging Threats](https://rules.emergingthreats.net/) | Known compromised hosts | 65 | Daily |
| [Tor Exit Nodes](https://check.torproject.org/) | Tor anonymization endpoints | 30 | Hourly |

All feeds are free and require no API key.

#### How It Works

1. **Feed sync** &mdash; Downloads/refreshes enabled feeds to `~/.aegis/feeds/`. Each feed is stored as a dated text file. Stale feeds (>24h) trigger a warning but are still used as fallback.

2. **IP set construction** &mdash; Parses all feeds into a single in-memory lookup table. Handles plain IPs, CIDR ranges, and various comment formats (`#`, `;`). Typical total: ~50K entries, ~2 MB RAM.

3. **Cross-reference** &mdash; Reads active TCP connections from `/proc/net/tcp{,6}`. Every remote IP is checked against the lookup table.

4. **Scoring** &mdash; IPs found on multiple feeds get the maximum weight. Feed confidence weights are configurable per-feed.

| Detection | Severity | Details |
|-----------|----------|---------|
| Threat Intel Match | High | Feed names, weights, connection details |
| Tor Exit Node | Info | Tor is flagged separately (not inherently malicious) |

**Configuration:**

```toml
[threat_intel]
enabled = true
feed_dir = "~/.aegis/feeds"
update_on_scan = true
update_interval = "6h"

[threat_intel.feeds.firehol]
url = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"
enabled = true
weight = 90

# Add custom feeds:
[threat_intel.feeds.my_custom_feed]
url = "https://example.com/my-blocklist.txt"
enabled = true
weight = 80
```

---

### Anomaly Detection Module

**Data source:** `/var/log/auth.log`, `/etc/crontab`, `/etc/sudoers`, `/etc/passwd`, `/proc/modules`

Detects behavioral anomalies that may indicate compromise or unauthorized changes.

#### Unusual Login Time

Flags successful logins outside configured business hours. Useful for detecting compromised credentials used by attackers in different time zones.

```
Trigger: Login hour outside login_time_start..login_time_end range
Severity: Medium
Includes: Username, login time, configured range
```

#### Cron/Sudoers Monitoring

Detects changes to scheduled task configurations and privilege escalation files. Maintains a baseline of known cron files and sudoers state, alerting on additions or modifications.

```
Trigger: New or changed crontab/sudoers file vs. baseline
Severity: Medium (cron), High (sudoers)
Includes: File path, change type
```

#### New User Detection

Alerts on new user accounts by comparing `/etc/passwd` against a stored baseline. New accounts may indicate persistence mechanisms.

```
Trigger: Username in /etc/passwd not in baseline
Severity: Medium
Includes: Username
```

#### Kernel Module Integrity

Compares loaded kernel modules against a baseline. New modules may indicate rootkit installation.

```
Trigger: Kernel module in /proc/modules not in baseline
Severity: High
Includes: Module name
```

**Configuration:**

```toml
[anomaly]
enabled = true
login_time_start = 6
login_time_end = 22
monitor_cron = true
monitor_sudoers = true
detect_new_users = true
detect_kernel_modules = true
```

---

### Honeypot Module

**Data source:** TCP socket listeners

Deploys decoy service listeners on commonly-targeted ports. Any connection to these ports is inherently suspicious since no legitimate service is running there.

```
Trigger: Any TCP connection to a honeypot port
Severity: High
Auto-response: Block source IP (if auto_block enabled)
Includes: Source IP, honeypot port
```

**Configuration:**

```toml
[honeypot]
enabled = true
ports = [2222, 8080, 3389, 4444, 5555]
auto_block = true
```

---

### Certificate Monitoring Module

**Data source:** TLS connections to configured domains

Connects to configured domains and checks TLS certificate expiry dates. Alerts when certificates are approaching expiration.

```
Trigger: Certificate expires within warn_days
Severity: Medium
Includes: Domain, days until expiry, expiry date
```

**Configuration:**

```toml
[cert]
enabled = true
domains = ["example.com", "api.example.com:8443"]
warn_days = 14
```

---

## Automated Response

### Response Actions

Aegis can take five automated actions when threats are detected:

| Action | What it does |
|--------|-------------|
| `log` | Record the event in logs only |
| `alert` | Send notifications (terminal, email, webhook) |
| `block` | Add a firewall DROP rule for the source IP |
| `kill` | Terminate the offending process (SIGTERM then SIGKILL) |
| `block+kill` | Block the IP and kill the process |

### Action Determination

Actions are resolved in priority order:

1. **Per-threat-type overrides** &mdash; check `[response.overrides]` for the specific threat type
2. **Severity defaults** &mdash; if no override exists:

| Severity | Default Action |
|----------|---------------|
| Info | `log` |
| Low | `log` |
| Medium | `alert` |
| High | `block` |
| Critical | `block+kill` |

**Default overrides** (from `aegis.toml`):

```toml
[response.overrides]
crypto_miner = "kill"         # Kill the miner process
reverse_shell = "kill"        # Kill the shell immediately
scanner_probe = "log"         # Scanners are noisy, just log
syn_flood = "block"           # Block flood source IPs
brute_force = "block"         # Block brute-force IPs
port_scan = "block"           # Block scanner IPs
c2_beacon = "block"           # Block C2 destinations
web_ddos = "block"            # Block DDoS source IPs
sqli_attempt = "block"        # Block SQLi attackers
path_traversal = "block"      # Block traversal attempts
file_modified = "alert"       # Alert on file changes
file_added = "alert"          # Alert on new files
file_deleted = "alert"        # Alert on deleted files
suspicious_binary = "alert"   # Alert on suspicious binaries
tor_exit = "log"              # Tor isn't inherently malicious
```

### Firewall Backends

Aegis supports three firewall backends:

#### iptables (default)

Creates an isolated `AEGIS_BLOCK` chain to avoid interfering with existing rules:

```
iptables -N AEGIS_BLOCK              # Create chain (once)
iptables -I INPUT -j AEGIS_BLOCK     # Insert jump rule (once)
iptables -C AEGIS_BLOCK -s <IP> -j DROP  # Check if rule exists (dedup)
iptables -A AEGIS_BLOCK -s <IP> -j DROP  # Block IP (only if not present)
iptables -D AEGIS_BLOCK -s <IP> -j DROP  # Unblock IP
```

All three backends (iptables, nftables, ufw) check for existing rules before adding to prevent duplicate entries. The `aegis init` firewall cleanup phase also deduplicates any existing rules in the `AEGIS_BLOCK` chain.

#### nftables

Creates a dedicated `inet aegis` table:

```
nft add table inet aegis
nft add chain inet aegis input { type filter hook input priority 0; }
nft add rule inet aegis input ip saddr <IP> drop
```

#### ufw

Uses UFW's high-level interface:

```
ufw deny from <IP>
ufw delete deny from <IP>
```

Select the backend in config:

```toml
[response]
firewall_backend = "iptables"   # or "nftables" or "ufw"
```

### Safety Mechanisms

#### Rate Limiting

Prevents a spoofed-IP flood from filling the firewall with thousands of rules:

```toml
max_blocks_per_minute = 100    # Hard limit on block rate
```

Uses a 60-second sliding window. When exceeded, new blocks are skipped with a warning.

#### IP Whitelist

Critical infrastructure is never blocked:

```toml
whitelist = [
    "127.0.0.0/8",       # Loopback
    "::1/128",            # IPv6 loopback
    "10.0.0.0/8",         # Private
    "172.16.0.0/12",      # Private
    "192.168.0.0/16",     # Private
]
```

Add your own trusted IPs/ranges to prevent accidental lockouts.

#### Block Expiry

All auto-blocks have a TTL (default: 24 hours). No permanent blocks without explicit manual action:

```toml
default_block_duration = "24h"   # Auto-blocks expire after 24h
```

#### Firewall Rule Cap

```toml
max_firewall_rules = 10000   # Hard limit on AEGIS_BLOCK chain size
```

#### Dry Run Mode

Test your response policy without taking any real actions:

```toml
[response]
dry_run = true   # Log what would happen without executing
```

#### Process Killing Safety

Process termination uses a graceful escalation:
1. Send `SIGTERM` (allow clean shutdown)
2. Wait 2 seconds
3. Check if process is still alive
4. If alive, send `SIGKILL` (force termination)

Uses `nix::sys::signal::kill()` &mdash; never shell commands.

---

## Alerting

### Terminal Output

Threat events are printed to stderr with severity-appropriate coloring:

| Severity | Color |
|----------|-------|
| Info | Cyan |
| Low | Blue |
| Medium | Yellow |
| High | Red |
| Critical | Red + Bold |

Format:
```
  high [2026-03-13 14:22:01 UTC] Brute Force -- SSH brute force detected: 50 attempts
       Source IP : 203.0.113.42
       Target    : sshd
       Response  : auto-responded
```

### JSON Log File

All threat events are automatically appended as JSON lines to a structured log file during both scan and daemon modes. This file is also the data source for `aegis threats`, `aegis status`, and `aegis report`.

```toml
[alerting]
log_file = "~/.aegis/threats.jsonl"
```

Each line is a complete `ThreatEvent` object:

```json
{
  "id": "20260313142201123-0042",
  "threat_type": "brute_force",
  "severity": "high",
  "source_module": "auth",
  "description": "SSH brute force detected: 50 failed attempts from 203.0.113.42",
  "source_ip": "203.0.113.42",
  "target": "sshd",
  "details": {"failed_count": "50", "usernames": "root, admin, ubuntu"},
  "timestamp": "2026-03-13T14:22:01.123456Z",
  "auto_responded": true
}
```

The log file is created with `0600` permissions (owner read/write only).

### Email Alerts

SMTP integration via the `lettre` crate for critical threat notifications.

```toml
[alerting.email]
enabled = true
smtp_host = "smtp.gmail.com"
smtp_port = 587
smtp_username = "alerts@yourdomain.com"
smtp_password = ""                  # Or use SMTP_PASSWORD env var (preferred)
use_tls = true
from = "aegis@yourdomain.com"
to = ["admin@yourdomain.com", "security@yourdomain.com"]
subject_prefix = "[AEGIS]"
min_severity = "high"               # Only email for High + Critical
cooldown = "5m"                     # Max 1 email per threat type per 5 minutes
```

Features:
- **Threshold-based** &mdash; only sends for threats at or above `min_severity`
- **Rate-limited** &mdash; per-threat-type cooldown prevents inbox flooding
- **HTML formatting** &mdash; structured email with threat details table
- **Retry logic** &mdash; 3 attempts with exponential backoff (1s, 2s, 4s)
- **Non-blocking** &mdash; email failures never block the response pipeline
- **Credential security** &mdash; supports `SMTP_PASSWORD` environment variable

### Webhook Alerts

Send threat data to Slack, Discord, or any HTTP endpoint:

```toml
[alerting.webhook]
enabled = true
url = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
min_severity = "high"
```

Sends a POST request with the full `ThreatEvent` serialized as JSON. 10-second timeout. Failures are logged but never block processing.

### Slack Alerts

Native Slack integration via incoming webhooks.

```toml
[alerting.slack]
enabled = true
webhook_url = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
min_severity = "high"
```

### Telegram Alerts

Native Telegram integration via Bot API.

```toml
[alerting.telegram]
enabled = true
bot_token = "123456:ABC-DEF..."
chat_id = "-1001234567890"
min_severity = "high"
```

---

## Web Dashboard

Aegis includes an optional web-based security dashboard, enabled via feature flag:

```bash
cargo build --release --features web-dashboard
```

### Pages

| Page | Description |
|------|-------------|
| **Dashboard** | Real-time overview with threat stats, severity breakdown, recent events |
| **Threats** | Searchable threat log with pagination, severity filters, detail modals |
| **Firewall** | Active blocks, whitelist management, manual block/unblock |
| **Status** | System health, module status, security posture score |
| **Config** | Live configuration viewer with validation |
| **Logs** | Structured log viewer with filtering |

### Features

- **WebSocket live feed** — threats stream to the dashboard in real-time
- **Token-based auth** — constant-time comparison, secure cookie storage
- **Rate limiting** — 120 req/min for reads, 10 req/min for mutative operations
- **CORS protection** — configurable allowed origins
- **Mobile responsive** — works on all screen sizes
- **PDF reports** — downloadable security reports

### Running

```bash
# Start Aegis with web dashboard
sudo aegis watch --foreground
# Dashboard available at http://localhost:3000
# Auth token is printed to stdout on first run
```

### API

27 routes including:
- `GET /api/threats` — threat list with search/pagination
- `GET /api/blocks` — active firewall blocks
- `POST /api/block` / `POST /api/unblock` — manual IP management
- `GET /api/whitelist` — whitelist management
- `POST /api/scan` — trigger on-demand scan
- `GET /api/stats` — dashboard statistics
- `GET /api/status` — system health
- `GET /api/report` — generate report
- `GET /ws/threats` — WebSocket live threat stream

---

## Configuration Reference

Generate a default configuration and set up the full system:

```bash
sudo aegis init
```

This creates `/etc/aegis/aegis.toml` with all options documented with comments, plus sets up data directories, kernel hardening, fail2ban, and the systemd service.

<details>
<summary><strong>Full configuration file with all options</strong></summary>

```toml
# Aegis Security Monitor Configuration

[general]
modules = ["network", "process", "file_integrity", "auth", "web", "threat_intel", "anomaly", "honeypot", "cert"]
log_level = "info"
data_dir = "~/.aegis"
dedup_ttl = "1h"              # Suppress duplicate threats within this window ("0s" to disable)

[network]
enabled = true
syn_flood_threshold = 50
port_scan_threshold = 15
port_scan_window = 60
known_outbound_ports = [80, 443, 53, 22, 25, 587]
c2_beacon_threshold = 10
c2_beacon_window = 300
connection_rate_threshold = 100

[process]
enabled = true
miner_cpu_threshold = 80.0
miner_names = ["xmrig", "minerd", "cpuminer", "cgminer", "bfgminer",
               "ethminer", "nbminer", "t-rex", "phoenixminer", "ccminer"]
suspicious_dirs = ["/tmp", "/dev/shm", "/var/tmp", "/run/shm"]
detect_reverse_shells = true

[file_integrity]
enabled = true
watch_paths = ["/etc", "/usr/bin", "/usr/sbin", "/bin", "/sbin"]
exclude_paths = ["/etc/mtab", "/etc/resolv.conf",
                 "/etc/hosts.allow", "/etc/hosts.deny"]
baseline_path = "~/.aegis/baseline.json"
use_inotify = true

[auth]
enabled = true
brute_force_threshold = 5
brute_force_window = 300
alert_root_login = true
alert_new_ip = true
log_paths = ["/var/log/auth.log", "/var/log/secure"]

[web]
enabled = true
access_log_paths = ["/var/log/nginx/access.log"]
ddos_threshold = 200
detect_sqli = true
detect_path_traversal = true
detect_scanners = true
scanner_agents = ["nikto", "sqlmap", "nmap", "masscan", "zgrab",
                  "gobuster", "dirbuster", "wfuzz", "nuclei", "httpx"]

[threat_intel]
enabled = true
feed_dir = "~/.aegis/feeds"
update_on_scan = true
update_interval = "6h"

[threat_intel.feeds.firehol]
url = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"
enabled = true
weight = 90

[threat_intel.feeds.spamhaus_drop]
url = "https://www.spamhaus.org/drop/drop.txt"
enabled = true
weight = 95

[threat_intel.feeds.blocklist_de]
url = "https://lists.blocklist.de/lists/all.txt"
enabled = true
weight = 70

[threat_intel.feeds.cins_army]
url = "https://cinsscore.com/list/ci-badguys.txt"
enabled = true
weight = 60

[threat_intel.feeds.emerging_threats]
url = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
enabled = true
weight = 65

[threat_intel.feeds.tor_exit]
url = "https://check.torproject.org/torbulkexitlist"
enabled = true
weight = 30

[anomaly]
enabled = true
login_time_start = 6
login_time_end = 22
monitor_cron = true
monitor_sudoers = true
detect_new_users = true
detect_kernel_modules = true

[honeypot]
enabled = true
ports = [2222, 8080, 3389, 4444, 5555]
auto_block = true

[cert]
enabled = true
domains = ["example.com"]
warn_days = 14

[response]
enabled = true
dry_run = false
max_blocks_per_minute = 100
default_block_duration = "24h"
max_firewall_rules = 10000
firewall_backend = "iptables"
whitelist = ["127.0.0.0/8", "::1/128", "10.0.0.0/8",
             "172.16.0.0/12", "192.168.0.0/16"]

[response.overrides]
crypto_miner = "kill"
reverse_shell = "kill"
scanner_probe = "log"
syn_flood = "block"
brute_force = "block"
port_scan = "block"
c2_beacon = "block"
web_ddos = "block"
sqli_attempt = "block"
path_traversal = "block"
file_modified = "alert"
suspicious_binary = "alert"
tor_exit = "log"

[alerting]
terminal = true
log_file = "~/.aegis/threats.jsonl"

[alerting.email]
enabled = false
smtp_host = "smtp.example.com"
smtp_port = 587
smtp_username = ""
smtp_password = ""
use_tls = true
from = "aegis@yourdomain.com"
to = ["admin@yourdomain.com"]
subject_prefix = "[AEGIS]"
min_severity = "high"
cooldown = "5m"

[alerting.webhook]
enabled = false
url = ""
min_severity = "high"

[alerting.slack]
enabled = false
webhook_url = ""
min_severity = "high"

[alerting.telegram]
enabled = false
bot_token = ""
chat_id = ""
min_severity = "high"
```

</details>

---

## Threat Reference

Complete list of all threat types Aegis can detect:

| Threat Type | Default Severity | Module | Default Action | Description |
|------------|-----------------|--------|---------------|-------------|
| SYN Flood | High | network | block | TCP SYN flood detected |
| Port Scan | Medium | network | block | Port scanning from single IP |
| Suspicious Connection | Medium | network | alert | Outbound connection on unusual port |
| C2 Beacon | Critical | network | block | Repeated connections to same remote host |
| Crypto Miner | High | process | kill | Cryptocurrency mining process |
| Reverse Shell | Critical | process | kill | Shell with network socket (active compromise) |
| Suspicious Binary | High | process | alert | Binary running from /tmp or /dev/shm |
| Brute Force | High | auth | block | SSH login failures exceed threshold |
| Root Login | Medium | auth | alert | Direct root login detected |
| Login Anomaly | Info | auth | log | Login from external IP |
| File Modified | Medium | file_integrity | alert | File hash changed from baseline |
| File Added | Low | file_integrity | log | New file not in baseline |
| File Deleted | Medium | file_integrity | alert | Baselined file removed |
| Scanner Probe | Low | web | log | Vulnerability scanner detected |
| Web DDoS | High | web | block | Request rate exceeds threshold |
| SQL Injection | High | web | block | SQLi pattern in request URI |
| Path Traversal | High | web | block | Directory traversal attempt |
| Threat Intel Match | High | threat_intel | block | IP found on threat intelligence feed |
| Tor Exit Node | Info | threat_intel | log | Connection involving Tor exit node |
| Unusual Login Time | Medium | anomaly | alert | Login outside configured hours |
| Cron Modified | Medium | anomaly | alert | Crontab file added or changed |
| Sudoers Modified | High | anomaly | alert | Sudoers configuration changed |
| New User Created | Medium | anomaly | alert | New user account detected |
| Honeypot Connection | High | honeypot | block | Connection to decoy port |
| Connection Rate Exceeded | High | network | block | Too many connections from single IP |
| Cert Expiring Soon | Medium | cert | alert | TLS certificate approaching expiry |
| Kernel Module Loaded | High | anomaly | alert | New kernel module detected (rootkit indicator) |
| New Outbound Destination | Medium | network | alert | Connection to previously unseen destination |

---

## Architecture

```
                         ┌─────────────┐
                         │   CLI (clap) │
                         └──────┬──────┘
                                │
                         ┌──────▼──────┐
                         │   Engine    │
                         └──────┬──────┘
                                │
              ┌─────────────────┼─────────────────┐
              │                 │                 │
     ┌────────▼────────┐ ┌─────▼─────┐ ┌────────▼────────┐
     │  Scan Modules   │ │ Event Bus │ │  Shared State   │
     │  (10 modules)   │ │(broadcast)│ │ (Arc<RwLock>)   │
     └────────┬────────┘ └─────┬─────┘ └────────┬────────┘
              │                 │                 │
     ┌────────▼────────────────▼────────────────▼────────┐
     │                Response Pipeline                   │
     │  Event → Whitelist → Rate Limit → Action → Record │
     └────────┬───────────────┬──────────────────┬───────┘
              │               │                  │
     ┌────────▼──────┐ ┌─────▼─────┐ ┌─────────▼───────┐
     │   Firewall    │ │  Process  │ │    Alerting     │
     │ (iptables/    │ │   Kill    │ │ (term/log/email │
     │  nftables/ufw)│ │(TERM→KILL)│ │  /webhook)      │
     └───────────────┘ └───────────┘ └─────────────────┘
```

**Two execution modes:**

- **`aegis scan`** &mdash; Iterates modules sequentially, collects threats, deduplicates against `seen_fingerprints.json`, optionally auto-responds, writes to `threats.jsonl`, prints results
- **`aegis watch`** &mdash; Spawns each module in its own tokio task. Modules with native watch support (file_integrity/inotify) use real-time monitoring; others use a 60-second scan loop. Threats flow through a central event loop with TTL-aware deduplication.

**Core trait:**

```rust
#[async_trait]
pub trait ScanModule: Send + Sync {
    fn name(&self) -> &str;
    async fn scan(&self) -> Result<Vec<ThreatEvent>>;
    async fn watch(&self, tx: Sender<ThreatEvent>, cancel: CancellationToken) -> Result<()>;
    fn supports_watch(&self) -> bool;
}
```

Every module implements `scan()` for one-shot mode. The default `watch()` polls `scan()` on a timer. File integrity overrides `watch()` with inotify.

---

## Security Hardening

### Input Validation

- **No shell invocation** &mdash; All external commands (iptables, nft, kill) use `Command::new()` with explicit `.arg()` calls. Never `sh -c` or string interpolation.
- **IP validation** &mdash; All IPs round-trip through `std::net::IpAddr` parsing before use in any command.
- **Path canonicalization** &mdash; File integrity paths are validated against allowed directories.

### Anti-Self-DoS

- **Rate-limited blocking** &mdash; Configurable `max_blocks_per_minute` prevents spoofed-IP floods from filling the firewall.
- **Whitelist-first** &mdash; Whitelist is checked before any action. Private ranges are always protected.
- **Block expiry** &mdash; All auto-blocks have a TTL. No accidental permanent lockouts.
- **Firewall rule cap** &mdash; Hard limit on chain size. Oldest entries expire first.

### Privilege Management

- **Capability-aware** &mdash; Documents and supports `CAP_NET_ADMIN + CAP_DAC_READ_SEARCH + CAP_KILL` instead of full root.
- **No listening ports** &mdash; Aegis core opens zero network sockets. The web dashboard is opt-in via feature flag.
- **No `unsafe` code** &mdash; Zero `unsafe` blocks in Aegis source. Dependencies (tokio, procfs, nix) are well-audited.

### Credential Security

- SMTP password supports `SMTP_PASSWORD` environment variable (preferred over config file)
- Warns at startup if config file has overly permissive permissions
- Passwords are never logged, never included in status output

---

## Deployment

### systemd Service

The easiest way to deploy is via `aegis init`, which handles binary installation, service setup, and system hardening in one command:

```bash
sudo aegis init
sudo systemctl start aegis      # Start after reviewing config
```

Or install the service file manually:

```bash
sudo cp aegis.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now aegis
```

Check status:

```bash
sudo systemctl status aegis
sudo journalctl -u aegis -f    # Follow logs
```

The service file includes security hardening:

```ini
[Service]
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
```

### Capabilities Mode

Run without full root by setting Linux capabilities:

```bash
sudo setcap 'cap_net_admin,cap_dac_read_search,cap_kill+ep' /usr/local/bin/aegis
```

Then run as a regular user:

```bash
aegis scan    # Works without sudo
```

**Required capabilities:**
| Capability | Why |
|-----------|-----|
| `CAP_NET_ADMIN` | Read `/proc/net/*`, manage iptables |
| `CAP_DAC_READ_SEARCH` | Read auth logs, `/proc/[pid]/*` |
| `CAP_KILL` | Terminate malicious processes |

---

## Building from Source

### Prerequisites

- Rust 1.70+ (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)
- Linux (any distribution)

### Build

```bash
git clone https://github.com/chrismannina/aegis.git
cd aegis
cargo build --release
```

The optimized binary is at `target/release/aegis` (~7.6 MB, stripped with LTO).

### Run Tests

```bash
cargo test
```

123 unit tests cover:
- Config parsing and serialization round-trips
- Threat event builder and severity ordering
- IP parsing, CIDR matching, whitelist logic
- Hex IP/port parsing (proc/net/tcp format)
- SHA-256 hashing
- Auth log regex patterns
- Web log parsing and attack detection (SQLi, path traversal, DDoS, scanners)
- Event bus publish/subscribe
- Scheduler duration parsing
- State management (blocking, expiry, posture calculation)
- Engine scan and daemon lifecycle
- Report generation

### Project Stats

```
Language:     Rust
Source files: 66
Lines of code: ~11,200
Tests:        123
Binary size:  ~7.6 MB (release, stripped)
Dependencies: 48 direct crates
unsafe blocks: 0
```

---

## Contributing

Contributions are welcome. Areas where help is needed:

- **Additional detection modules** &mdash; container escape detection, eBPF-based packet analysis
- **Log format support** &mdash; Apache, Caddy, HAProxy log parsing
- **Additional threat feeds** &mdash; AbuseIPDB API integration, custom feed formats
- **Packaging** &mdash; .deb, .rpm, AUR, Nix packages
- **Testing** &mdash; integration tests with mock environments

### Development

```bash
# Run in development mode
cargo run -- scan --verbose

# Run specific tests
cargo test modules::auth

# Check for warnings
cargo clippy
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

<p align="center">
  <em>Built from real-world incident response. Designed for the servers that can't afford downtime.</em>
</p>
