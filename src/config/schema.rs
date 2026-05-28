use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Top-level Aegis configuration, typically loaded from aegis.toml.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AegisConfig {
    pub general: GeneralConfig,
    pub network: NetworkConfig,
    pub process: ProcessConfig,
    pub file_integrity: FileIntegrityConfig,
    pub auth: AuthConfig,
    pub web: WebConfig,
    pub threat_intel: ThreatIntelConfig,
    pub response: ResponseConfig,
    pub alerting: AlertingConfig,
    pub anomaly: AnomalyConfig,
    pub honeypot: HoneypotConfig,
    pub dashboard: DashboardConfig,
    pub cert: CertConfig,
    pub ebpf: EbpfConfig,
    pub dns: DnsConfig,
    pub container: ContainerConfig,
    pub rootkit: RootkitConfig,
    pub ssh_session: SshSessionConfig,
    pub enrichment: EnrichmentConfig,
    pub audit: AuditConfig,
    pub forensic: ForensicConfig,
    #[cfg(feature = "tls-fingerprint")]
    #[serde(default)]
    pub tls_fingerprint: TlsFingerprintConfig,
    #[cfg(feature = "yara")]
    #[serde(default)]
    pub yara: YaraConfig,
    #[cfg(feature = "server")]
    #[serde(default)]
    pub server: ServerConfig,
}

/// General daemon / runtime settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GeneralConfig {
    /// List of module names to enable (e.g. "network", "process").
    pub modules: Vec<String>,
    /// Tracing log level: trace, debug, info, warn, error.
    pub log_level: String,
    /// Directory for persistent data (baselines, feeds, etc.).
    pub data_dir: String,
    /// How long to suppress duplicate threat detections (e.g. "1h", "30m").
    /// Set to "0s" to disable deduplication entirely.
    #[serde(default = "default_dedup_ttl")]
    pub dedup_ttl: String,
}

fn default_dedup_ttl() -> String {
    "1h".into()
}

fn default_ddos_high_traffic_threshold() -> u32 {
    2000
}

fn default_repeat_offender_threshold() -> u32 {
    3
}

fn default_repeat_offender_window() -> String {
    "30d".into()
}

fn default_max_strike_records() -> usize {
    10_000
}

/// Default list of CIDR ranges for major infrastructure providers that Aegis
/// should never auto-block. These are user-facing CDN/edge/cloud-service IPs
/// where a "threat" hit is almost always a false positive caused by an attacker
/// routing through the CDN (and the real block should happen at the origin,
/// not at the shared edge).
///
/// The list covers the most common sources of false positives we've observed:
/// Anthropic API, Cloudflare, GitHub, AWS CloudFront, Google infrastructure,
/// and Fastly CDN. Users can extend or override this list via the
/// `[response] well_known_destinations` config key.
///
/// See docs/specs/2026-04-05-aegis-v2-design.md §1.2 for the decision rationale
/// and §2 for how the safety pin uses this list.
fn default_well_known_destinations() -> Vec<String> {
    vec![
        // Anthropic API (claude.ai, api.anthropic.com) — ARIN AP-2440
        "160.79.104.0/21".into(),
        // Cloudflare (https://www.cloudflare.com/ips-v4/)
        "103.21.244.0/22".into(),
        "103.22.200.0/22".into(),
        "103.31.4.0/22".into(),
        // 104.16.0.0/12 covers Cloudflare's full 104.16-104.31 allocation.
        // Broader than Cloudflare's published /13 list because whois data
        // shows 104.28.x.x is also CLOUDFLARENET (acquired later).
        "104.16.0.0/12".into(),
        "108.162.192.0/18".into(),
        "131.0.72.0/22".into(),
        "141.101.64.0/18".into(),
        "162.158.0.0/15".into(),
        "172.64.0.0/13".into(),
        "173.245.48.0/20".into(),
        "188.114.96.0/20".into(),
        "190.93.240.0/20".into(),
        "197.234.240.0/22".into(),
        "198.41.128.0/17".into(),
        // GitHub (https://api.github.com/meta — web, api, git, pages, importer)
        "140.82.112.0/20".into(),
        "143.55.64.0/20".into(),
        "185.199.108.0/22".into(),
        "192.30.252.0/22".into(),
        // AWS CloudFront edge locations
        // (subset of https://ip-ranges.amazonaws.com/ip-ranges.json where service=CLOUDFRONT)
        "13.32.0.0/15".into(),
        "13.35.0.0/16".into(),
        "13.224.0.0/14".into(),
        "18.160.0.0/15".into(),
        "18.172.0.0/15".into(),
        "18.244.0.0/15".into(),
        "52.46.0.0/18".into(),
        "52.84.0.0/15".into(),
        "54.182.0.0/16".into(),
        "54.192.0.0/16".into(),
        "54.230.0.0/16".into(),
        "54.239.128.0/18".into(),
        "54.239.192.0/19".into(),
        "54.240.128.0/18".into(),
        "64.252.64.0/18".into(),
        "70.132.0.0/18".into(),
        "99.84.0.0/16".into(),
        "99.86.0.0/16".into(),
        "108.138.0.0/15".into(),
        "108.156.0.0/14".into(),
        "143.204.0.0/16".into(),
        "205.251.192.0/19".into(),
        "216.137.32.0/19".into(),
        // Google / Googlebot / GCP edge (subset of https://www.gstatic.com/ipranges/goog.json)
        "8.8.4.0/24".into(),
        "8.8.8.0/24".into(),
        "34.64.0.0/10".into(),
        "34.128.0.0/10".into(),
        "35.184.0.0/13".into(),
        "35.192.0.0/14".into(),
        "35.196.0.0/15".into(),
        "35.198.0.0/16".into(),
        "35.199.0.0/17".into(),
        "64.233.160.0/19".into(),
        "66.102.0.0/20".into(),
        "66.249.64.0/19".into(),
        "72.14.192.0/18".into(),
        "74.125.0.0/16".into(),
        "108.177.0.0/17".into(),
        "130.211.0.0/16".into(),
        "142.250.0.0/15".into(),
        "172.217.0.0/16".into(),
        "173.194.0.0/16".into(),
        "209.85.128.0/17".into(),
        "216.58.192.0/19".into(),
        "216.239.32.0/19".into(),
        // Fastly (https://api.fastly.com/public-ip-list)
        "23.235.32.0/20".into(),
        "43.249.72.0/22".into(),
        "103.244.50.0/24".into(),
        "103.245.222.0/23".into(),
        "103.245.224.0/24".into(),
        "104.156.80.0/20".into(),
        "140.248.64.0/18".into(),
        "140.248.128.0/17".into(),
        "146.75.0.0/17".into(),
        "151.101.0.0/16".into(),
        "157.52.64.0/18".into(),
        "167.82.0.0/17".into(),
        "172.111.64.0/18".into(),
        "185.31.16.0/22".into(),
        "199.27.72.0/21".into(),
        "199.232.0.0/16".into(),
    ]
}

/// Default list of threat type config keys that should trigger an immediate
/// permanent ban (first-offense, no strike counter). These are threat types
/// where a single confirmed hit is already strong evidence of hostile intent
/// and where the false-positive rate is low enough to justify permaban.
///
/// Conservative default — does NOT include `web_ddos`, `brute_force`, or
/// `scanner_probe` because those have higher FP rates (a single traffic
/// spike from a legitimate client could trigger permaban). Users can add
/// them via config if they want more aggressive policy.
///
/// See docs/specs/2026-04-05-aegis-v2-design.md §3 for design rationale.
fn default_zero_tolerance_threats() -> Vec<String> {
    vec![
        "path_traversal".into(),
        "sqli_attempt".into(),
        "reverse_shell".into(),
    ]
}

/// Default for `response.auto_reconcile_firewall`. Defaults to false
/// (warn-only) because auto-reconciliation modifies kernel firewall state
/// and is a high-blast-radius operation. Users opt in after verifying the
/// drift reports look correct.
fn default_auto_reconcile_firewall() -> bool {
    false
}

/// Default interval (minutes) for the drift-detection reconciliation task.
/// 15 minutes is frequent enough to catch manual tampering quickly without
/// generating excessive iptables-list subprocess overhead.
fn default_reconcile_interval_minutes() -> u64 {
    15
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            modules: vec![
                "network".into(),
                "process".into(),
                "file_integrity".into(),
                "auth".into(),
                "web".into(),
                "threat_intel".into(),
            ],
            log_level: "info".into(),
            data_dir: "~/.aegis".into(),
            dedup_ttl: default_dedup_ttl(),
        }
    }
}

/// Network monitoring module configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkConfig {
    pub enabled: bool,
    /// Number of SYN_RECV sockets to trigger a SYN flood alert.
    pub syn_flood_threshold: u32,
    /// Connections from a single IP to trigger a port scan alert.
    pub port_scan_threshold: u32,
    /// Time window in seconds for port scan detection.
    pub port_scan_window: u64,
    /// Ports considered normal for outbound traffic.
    pub known_outbound_ports: Vec<u16>,
    /// Maximum beacon events per scan cycle (v2.6.0: repurposed). In v2.5.0
    /// and earlier this was the raw parallel-socket count threshold. In
    /// v2.6.0+ the time-series detector uses `c2_beacon_cov_threshold` and
    /// `c2_beacon_min_samples` instead; this field becomes the per-scan
    /// event cap (anti-flap). Default 1 = at most one C2 beacon event per
    /// (local_exe, remote_ip, remote_port) per scan tick.
    pub c2_beacon_threshold: u32,
    /// Window in seconds for C2 beacon time-series analysis.
    /// v2.6.0: now actually used by the time-series detector (was dead code
    /// in v2.5.0). Samples older than this window are pruned from the
    /// beacon history before CoV computation.
    pub c2_beacon_window: u64,
    /// Connections per minute from a single IP to trigger rate alert.
    pub connection_rate_threshold: u32,
    /// v2.6.0 Bucket E: minimum samples in the window before the CoV
    /// beacon detector fires. Lower = more sensitive, more false positives.
    /// Default 4 is the lowest value with meaningful statistics.
    #[serde(default = "default_c2_beacon_min_samples")]
    pub c2_beacon_min_samples: usize,
    /// v2.6.0 Bucket E: coefficient of variation threshold below which
    /// inter-arrival timing is considered "periodic enough" to be a beacon.
    /// Strict beacons have CoV ≈ 0, jittered beacons ≈ 0.2–0.4, random
    /// traffic ≈ 1.0. Default 0.3 catches jittered beacons without
    /// false-positiving on moderately regular human browsing patterns.
    #[serde(default = "default_c2_beacon_cov_threshold")]
    pub c2_beacon_cov_threshold: f64,
    /// v2.6.0 Bucket E: minimum mean inter-arrival interval (seconds) for
    /// a beacon candidate. Shorter than this is probably application
    /// traffic (WebSocket keepalives, SSE reconnects), not C2.
    #[serde(default = "default_c2_beacon_min_interval_secs")]
    pub c2_beacon_min_interval_secs: f64,
    /// v2.6.0 Bucket E: maximum mean inter-arrival interval (seconds).
    /// Longer than this and the daemon scan cadence (60s) would likely
    /// miss samples anyway.
    #[serde(default = "default_c2_beacon_max_interval_secs")]
    pub c2_beacon_max_interval_secs: f64,
    /// v2.6.0 Bucket E: max distinct (local_exe, remote_ip, remote_port)
    /// tuples tracked in beacon history. Memory bound.
    #[serde(default = "default_c2_beacon_max_keys")]
    pub c2_beacon_max_keys: usize,
    /// v2.6.0 Bucket E: max samples retained per key.
    #[serde(default = "default_c2_beacon_max_samples_per_key")]
    pub c2_beacon_max_samples_per_key: usize,
    /// v2.6.1: CIDR ranges whose connections must NEVER be considered
    /// suspicious by network detectors and must NEVER be auto-blocked by
    /// the response engine. Defense-in-depth complement to the existing
    /// `is_private` filter and the `[response] well_known_destinations`
    /// safety pin: applied at BOTH detection time (excluded destinations
    /// don't increment the C2 beacon counter / don't trigger
    /// suspicious-outbound alerts) AND at response time (the response
    /// engine refuses to install a firewall rule against them, even if a
    /// future detector path forgets to filter).
    ///
    /// Defaults to the four "obviously not a remote attacker" ranges:
    ///   - `127.0.0.0/8`   (RFC 1122 IPv4 loopback)
    ///   - `::1/128`       (RFC 4291 IPv6 loopback)
    ///   - `169.254.0.0/16`(RFC 3927 IPv4 link-local)
    ///   - `fe80::/10`     (RFC 4291 IPv6 link-local)
    ///
    /// Operator note: this is intentionally NOT a general-purpose
    /// allowlist. Public-internet CIDRs do not belong here — use
    /// `[response] whitelist` for user-curated never-block IPs and
    /// `[response] well_known_destinations` for shipped CDN ranges.
    /// Entries are validated as CIDRs at startup; invalid entries are
    /// logged and skipped.
    #[serde(default = "default_excluded_destinations")]
    pub excluded_destinations: Vec<String>,
}

/// Default loopback + link-local CIDRs that are excluded from network
/// detection and from auto-block. See `NetworkConfig::excluded_destinations`
/// for the rationale. Prevents Aegis from interfering with local development
/// tools (Gradle daemon, adb fork-server, systemd-resolved, Docker bridge
/// loopback binds, etc.) that rapidly poll loopback ports and would otherwise
/// trip the C2 beacon detector.
pub fn default_excluded_destinations() -> Vec<String> {
    vec![
        "127.0.0.0/8".into(),
        "::1/128".into(),
        "169.254.0.0/16".into(),
        "fe80::/10".into(),
    ]
}

fn default_c2_beacon_min_samples() -> usize {
    4
}
fn default_c2_beacon_cov_threshold() -> f64 {
    0.3
}
fn default_c2_beacon_min_interval_secs() -> f64 {
    30.0
}
fn default_c2_beacon_max_interval_secs() -> f64 {
    900.0
}
fn default_c2_beacon_max_keys() -> usize {
    10_000
}
fn default_c2_beacon_max_samples_per_key() -> usize {
    20
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            syn_flood_threshold: 50,
            port_scan_threshold: 15,
            port_scan_window: 60,
            known_outbound_ports: vec![
                80, 443, 53, 22, 25, 587, 993, 995, 465, 143, 110, // web, DNS, SSH, mail
                5228, 5229, 5230, // Google FCM/GCM (push notifications)
                8080, 8443, // common alt HTTP/HTTPS
                123,  // NTP
                853,  // DNS over TLS
                3478, 3479, 5349, // STUN/TURN (WebRTC)
                // v2.6.1: common dev-tool ports. These show up on local Docker
                // bridges and remote dev hosts and are not interesting to a
                // security monitor — treating them as suspicious produced
                // alert noise that masked real findings.
                5037, // adb fork-server
                9229, // Node.js inspector / V8 debug
                5005, // JDWP (JVM debug)
            ],
            // v2.6.0: repurposed as per-scan event cap (was parallel-socket
            // count in v2.5.0). Default 1 = at most 1 beacon event per key
            // per scan tick.
            c2_beacon_threshold: 1,
            c2_beacon_window: 300,
            connection_rate_threshold: 100,
            c2_beacon_min_samples: default_c2_beacon_min_samples(),
            c2_beacon_cov_threshold: default_c2_beacon_cov_threshold(),
            c2_beacon_min_interval_secs: default_c2_beacon_min_interval_secs(),
            c2_beacon_max_interval_secs: default_c2_beacon_max_interval_secs(),
            c2_beacon_max_keys: default_c2_beacon_max_keys(),
            c2_beacon_max_samples_per_key: default_c2_beacon_max_samples_per_key(),
            excluded_destinations: default_excluded_destinations(),
        }
    }
}

/// Process monitoring module configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ProcessConfig {
    pub enabled: bool,
    /// CPU usage percent threshold for crypto miner detection.
    pub miner_cpu_threshold: f64,
    /// Known miner process names (substring match).
    pub miner_names: Vec<String>,
    /// Directories considered suspicious for running binaries.
    pub suspicious_dirs: Vec<String>,
    /// Whether to attempt reverse shell detection.
    pub detect_reverse_shells: bool,
    /// v2.6.2: Process names that, when they are the parent of a
    /// reverse-shell match, downgrade severity from `critical` to `medium`
    /// and the auto-action from `kill` to `alert`. The detection itself
    /// still fires and is recorded with `degraded_by_dev_parent: true`.
    /// Exact match, lower-cased; path-like entries are rejected at
    /// startup with a warning.
    #[serde(default = "default_dev_parent_allowlist")]
    pub dev_parent_allowlist: Vec<String>,
    /// v2.6.2: If true, ignore `dev_parent_allowlist` and treat every
    /// reverse-shell match at full critical severity even when the parent
    /// is an interactive dev tool. Use to "opt back in" to strict mode
    /// in environments where dev-tool processes shouldn't be running.
    #[serde(default)]
    pub strict_under_dev_tools: bool,
}

/// v2.6.2 default list of interactive dev-tool process names whose child
/// reverse-shell-shaped commands should be demoted from kill→alert.
/// Source: the false-positive incident
/// `20260509004453373-1434` where Aegis killed a benign Python loopback
/// test launched by Claude Code.
pub fn default_dev_parent_allowlist() -> Vec<String> {
    vec![
        "claude".into(),
        "code".into(),
        "code-insiders".into(),
        "cursor".into(),
        "zed".into(),
        "vim".into(),
        "nvim".into(),
        "tmux".into(),
        "screen".into(),
        "jupyter".into(),
        "jupyter-lab".into(),
        "jupyter-notebook".into(),
        "ipython".into(),
        "android-studio".into(),
        "studio".into(),
        "idea".into(),
        "fleet".into(),
        "rider".into(),
        "pycharm".into(),
    ]
}

impl Default for ProcessConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            miner_cpu_threshold: 80.0,
            miner_names: vec![
                "xmrig".into(),
                "minerd".into(),
                "cpuminer".into(),
                "cgminer".into(),
                "bfgminer".into(),
                "ethminer".into(),
                "nbminer".into(),
                "t-rex".into(),
                "phoenixminer".into(),
                "ccminer".into(),
            ],
            suspicious_dirs: vec![
                "/tmp".into(),
                "/dev/shm".into(),
                "/var/tmp".into(),
                "/run/shm".into(),
            ],
            detect_reverse_shells: true,
            dev_parent_allowlist: default_dev_parent_allowlist(),
            strict_under_dev_tools: false,
        }
    }
}

/// File integrity monitoring module configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FileIntegrityConfig {
    pub enabled: bool,
    /// Directories to monitor for changes.
    pub watch_paths: Vec<String>,
    /// Paths to exclude from monitoring.
    pub exclude_paths: Vec<String>,
    /// Where to store the baseline hash database.
    pub baseline_path: String,
    /// Use inotify for real-time monitoring in daemon mode.
    pub use_inotify: bool,
    /// Days before auto-accepting detected changes into baseline (0 = disabled).
    pub auto_accept_days: u64,
}

impl Default for FileIntegrityConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            watch_paths: vec![
                "/etc".into(),
                "/usr/bin".into(),
                "/usr/sbin".into(),
                "/bin".into(),
                "/sbin".into(),
            ],
            exclude_paths: vec![
                "/etc/mtab".into(),
                "/etc/resolv.conf".into(),
                "/etc/hosts.allow".into(),
                "/etc/hosts.deny".into(),
            ],
            baseline_path: "~/.aegis/baseline.json".into(),
            use_inotify: true,
            auto_accept_days: 3,
        }
    }
}

/// Authentication / login monitoring module configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AuthConfig {
    pub enabled: bool,
    /// Failed attempts before triggering brute force alert.
    pub brute_force_threshold: u32,
    /// Window in seconds for brute force detection.
    pub brute_force_window: u64,
    /// Alert on root logins.
    pub alert_root_login: bool,
    /// Alert on logins from previously unseen IP addresses.
    pub alert_new_ip: bool,
    /// Auth log files to monitor.
    pub log_paths: Vec<String>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            brute_force_threshold: 5,
            brute_force_window: 300,
            alert_root_login: true,
            alert_new_ip: true,
            log_paths: vec!["/var/log/auth.log".into(), "/var/log/secure".into()],
        }
    }
}

/// Web / HTTP log analysis module configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WebConfig {
    pub enabled: bool,
    /// Paths to Nginx/Apache access logs.
    pub access_log_paths: Vec<String>,
    /// Requests per IP per minute to trigger DDoS alert.
    pub ddos_threshold: u32,
    /// Detect SQL injection patterns in request URIs.
    pub detect_sqli: bool,
    /// Detect path traversal attempts.
    pub detect_path_traversal: bool,
    /// Detect known vulnerability scanners.
    pub detect_scanners: bool,
    /// User-agent substrings for scanner detection.
    pub scanner_agents: Vec<String>,
    /// Path prefixes with higher DDoS thresholds for high-frequency
    /// legitimate traffic (WebSocket, chat, streaming). Requests matching
    /// these prefixes use `ddos_high_traffic_threshold` instead of `ddos_threshold`.
    /// Example: ["/ws/", "/api/v1/chat/"]
    #[serde(default)]
    pub ddos_high_traffic_paths: Vec<String>,
    /// DDoS threshold for high-traffic paths (requests per IP per minute).
    /// Should be significantly higher than ddos_threshold.
    #[serde(default = "default_ddos_high_traffic_threshold")]
    pub ddos_high_traffic_threshold: u32,
    /// Additional path prefixes to treat as static assets and exclude from
    /// DDoS counting entirely. Merged with the built-in defaults
    /// (`/_next/static/`, `/static/`, `/assets/`, common asset extensions
    /// like `.ico`, `.css`, `.js`, `.woff2`, images, etc.). Browser SPAs
    /// emit dozens of asset requests per page load; counting them as DDoS
    /// traffic produces false positives on legitimate users.
    #[serde(default)]
    pub ddos_static_paths: Vec<String>,
    /// Per-endpoint DDoS thresholds. Each rule overrides `ddos_threshold` /
    /// `ddos_high_traffic_threshold` for requests whose path matches. When
    /// multiple rules could match a path, the longest matching `path` wins;
    /// on equal length, `match_type = "exact"` beats `"prefix"`.
    /// Managed at runtime via the /web-rules WebUI page.
    #[serde(default)]
    pub endpoint_thresholds: Vec<EndpointThreshold>,
}

/// A per-endpoint DDoS threshold rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EndpointThreshold {
    /// Request path to match (e.g. "/api/login", "/api/admin/").
    pub path: String,
    /// Requests per IP per minute allowed against this path.
    pub threshold: u32,
    /// "exact" — match `path` exactly; "prefix" — match any path starting with `path`.
    #[serde(default = "default_match_type")]
    pub match_type: String,
}

fn default_match_type() -> String {
    "prefix".to_string()
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            access_log_paths: vec!["/var/log/nginx/access.log".into()],
            ddos_threshold: 200,
            detect_sqli: true,
            detect_path_traversal: true,
            detect_scanners: true,
            scanner_agents: vec![
                "nikto".into(),
                "sqlmap".into(),
                "nmap".into(),
                "masscan".into(),
                "zgrab".into(),
                "gobuster".into(),
                "dirbuster".into(),
                "wfuzz".into(),
                "nuclei".into(),
                "httpx".into(),
            ],
            ddos_high_traffic_paths: Vec::new(),
            ddos_high_traffic_threshold: default_ddos_high_traffic_threshold(),
            ddos_static_paths: Vec::new(),
            endpoint_thresholds: Vec::new(),
        }
    }
}

/// Threat intelligence feed configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ThreatIntelConfig {
    pub enabled: bool,
    /// Directory for cached feed data.
    pub feed_dir: String,
    /// Whether to refresh feeds on every scan.
    pub update_on_scan: bool,
    /// How often to refresh feeds in daemon mode (e.g. "6h").
    pub update_interval: String,
    /// Named feed configurations.
    pub feeds: HashMap<String, FeedConfig>,
}

impl Default for ThreatIntelConfig {
    fn default() -> Self {
        let mut feeds = HashMap::new();
        feeds.insert(
            "firehol".into(),
            FeedConfig {
                url: "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset".into(),
                enabled: true,
                weight: 90,
                api_key: None,
                min_confidence: None,
            },
        );
        feeds.insert(
            "spamhaus_drop".into(),
            FeedConfig {
                url: "https://www.spamhaus.org/drop/drop.txt".into(),
                enabled: true,
                weight: 95,
                api_key: None,
                min_confidence: None,
            },
        );
        feeds.insert(
            "blocklist_de".into(),
            FeedConfig {
                url: "https://lists.blocklist.de/lists/all.txt".into(),
                enabled: true,
                weight: 70,
                api_key: None,
                min_confidence: None,
            },
        );
        feeds.insert(
            "cins_army".into(),
            FeedConfig {
                url: "https://cinsscore.com/list/ci-badguys.txt".into(),
                enabled: true,
                weight: 60,
                api_key: None,
                min_confidence: None,
            },
        );
        feeds.insert(
            "emerging_threats".into(),
            FeedConfig {
                url: "https://rules.emergingthreats.net/blockrules/compromised-ips.txt".into(),
                enabled: true,
                weight: 65,
                api_key: None,
                min_confidence: None,
            },
        );
        feeds.insert(
            "tor_exit".into(),
            FeedConfig {
                url: "https://check.torproject.org/torbulkexitlist".into(),
                enabled: true,
                weight: 30,
                api_key: None,
                min_confidence: None,
            },
        );

        Self {
            enabled: true,
            feed_dir: "~/.aegis/feeds".into(),
            update_on_scan: true,
            update_interval: "6h".into(),
            feeds,
        }
    }
}

/// Configuration for a single threat intelligence feed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedConfig {
    /// URL to fetch the feed from.
    pub url: String,
    /// Whether this feed is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Confidence weight (0-100) applied to matches from this feed.
    #[serde(default = "default_weight")]
    pub weight: u32,
    /// Optional API key for authenticated feeds.
    #[serde(default)]
    pub api_key: Option<String>,
    /// Minimum confidence threshold for matches from this feed.
    #[serde(default)]
    pub min_confidence: Option<u32>,
}

fn default_weight() -> u32 {
    50
}

/// Automated response configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ResponseConfig {
    pub enabled: bool,
    /// If true, log what would be done without actually blocking/killing.
    pub dry_run: bool,
    /// Rate limit: maximum IP blocks per minute.
    pub max_blocks_per_minute: u32,
    /// Default duration for IP blocks (e.g. "24h").
    pub default_block_duration: String,
    /// Maximum firewall rules in the AEGIS_BLOCK chain.
    pub max_firewall_rules: u32,
    /// Firewall backend: "iptables", "nftables", or "ufw".
    pub firewall_backend: String,
    /// CIDR ranges that must never be blocked.
    pub whitelist: Vec<String>,
    /// Per-threat-type action overrides: threat_key -> action string.
    pub overrides: HashMap<String, String>,
    /// GeoIP-based blocking settings.
    pub geoip: GeoipConfig,
    /// Number of auto-blocks within the window before permanent ban (0 = disabled).
    #[serde(default = "default_repeat_offender_threshold")]
    pub repeat_offender_threshold: u32,
    /// Time window for counting repeat offences (e.g. "30d").
    #[serde(default = "default_repeat_offender_window")]
    pub repeat_offender_window: String,
    /// Maximum number of strike records to keep in memory.
    #[serde(default = "default_max_strike_records")]
    pub max_strike_records: usize,
    /// Bucket A safety pin: CIDR ranges for well-known infrastructure
    /// providers (CDNs, major clouds, code hosts) that must NEVER be
    /// auto-blocked even if a detection rule fires against them. Events are
    /// still logged at Low severity with a `safety_pin_reason` detail for
    /// admin visibility, but the firewall rule is not installed.
    ///
    /// Unlike `whitelist`, this list is shipped with Aegis and updated by
    /// the project on each release. Users can add their own entries but
    /// don't need to maintain it from scratch.
    ///
    /// Backwards-compat: if this field is missing from an existing config
    /// file, the hardcoded default list is used. Set to `[]` to disable
    /// the safety pin entirely (not recommended — you'll lose protection
    /// against Aegis accidentally blocking Anthropic/GitHub/Cloudflare/etc).
    #[serde(default = "default_well_known_destinations")]
    pub well_known_destinations: Vec<String>,
    /// Bucket B: threat type config keys that should trigger a permanent
    /// ban on first offense, bypassing the strike counter. See
    /// `default_zero_tolerance_threats` for rationale behind the default list.
    ///
    /// Interaction with repeat_offender: zero-tolerance short-circuits the
    /// strike counter; a single hit escalates to permanent ban regardless
    /// of history. `repeat_offender_threshold` continues to handle the
    /// "N strikes across time" case for non-zero-tolerance types.
    ///
    /// Interaction with safety pin: well_known_destinations still wins over
    /// zero_tolerance_threats (we never auto-block infra, even for zero-tolerance
    /// types).
    #[serde(default = "default_zero_tolerance_threats")]
    pub zero_tolerance_threats: Vec<String>,
    /// Bucket D: if true, the daemon housekeeping loop will not just warn
    /// about drift between block_list.json and the live AEGIS_BLOCK chain,
    /// it will actively reconcile them (re-add missing rules, optionally
    /// remove orphaned rules).
    ///
    /// Defaults to false (warn-only) because reconciliation modifies kernel
    /// firewall state. Flip to true only after verifying drift reports look
    /// correct for a few cycles.
    #[serde(default = "default_auto_reconcile_firewall")]
    pub auto_reconcile_firewall: bool,
    /// Bucket D: how often (in minutes) to run the drift-detection
    /// reconciliation task. Default 15 minutes.
    #[serde(default = "default_reconcile_interval_minutes")]
    pub reconcile_interval_minutes: u64,
    /// v2.6.2: emit a desktop notification (libnotify / notify-send) when
    /// Aegis takes a kill or block action with `auto_responded=true`.
    /// Best-effort — failure to deliver a notification never crashes the
    /// response engine. Disable in headless environments where notify-send
    /// is unavailable. Default true.
    #[serde(default = "default_true")]
    pub desktop_notifications: bool,
}

impl Default for ResponseConfig {
    fn default() -> Self {
        let mut overrides = HashMap::new();
        overrides.insert("crypto_miner".into(), "kill".into());
        overrides.insert("reverse_shell".into(), "kill".into());
        overrides.insert("scanner_probe".into(), "block".into());
        overrides.insert("syn_flood".into(), "block".into());
        overrides.insert("brute_force".into(), "block".into());
        overrides.insert("port_scan".into(), "block".into());
        // TEMPORARY downgrade to "alert" until v2.6.0's time-series beacon
        // detector (Bucket E) has soaked in production. The legacy count-based
        // detector produces too many false positives against legitimate
        // high-throughput API clients; blocking on it causes the exact
        // problem documented in docs/TRIAGE_PHASE_A0.md (CloudFront/GitHub
        // getting firewalled). Flip back to "block" after verifying the new
        // detector's precision.
        overrides.insert("c2_beacon".into(), "alert".into());
        overrides.insert("web_ddos".into(), "block".into());
        overrides.insert("sqli_attempt".into(), "block".into());
        overrides.insert("path_traversal".into(), "block".into());
        overrides.insert("file_modified".into(), "alert".into());
        overrides.insert("file_added".into(), "alert".into());
        overrides.insert("file_deleted".into(), "alert".into());
        overrides.insert("suspicious_binary".into(), "kill".into());
        overrides.insert("tor_exit".into(), "log".into());

        Self {
            enabled: true,
            dry_run: false,
            max_blocks_per_minute: 100,
            default_block_duration: "24h".into(),
            max_firewall_rules: 10_000,
            firewall_backend: "iptables".into(),
            whitelist: vec![
                "127.0.0.0/8".into(),
                "::1/128".into(),
                "10.0.0.0/8".into(),
                "172.16.0.0/12".into(),
                "192.168.0.0/16".into(),
            ],
            overrides,
            geoip: GeoipConfig::default(),
            repeat_offender_threshold: default_repeat_offender_threshold(),
            repeat_offender_window: default_repeat_offender_window(),
            max_strike_records: default_max_strike_records(),
            well_known_destinations: default_well_known_destinations(),
            zero_tolerance_threats: default_zero_tolerance_threats(),
            auto_reconcile_firewall: default_auto_reconcile_firewall(),
            reconcile_interval_minutes: default_reconcile_interval_minutes(),
            desktop_notifications: true,
        }
    }
}

/// Alerting and notification configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AlertingConfig {
    /// Print alerts to the terminal.
    pub terminal: bool,
    /// Path to the JSONL threat log file.
    pub log_file: String,
    /// Email notification settings.
    pub email: EmailConfig,
    /// Webhook notification settings.
    pub webhook: WebhookConfig,
    /// Slack notification settings.
    pub slack: SlackConfig,
    /// Telegram notification settings.
    pub telegram: TelegramConfig,
}

impl Default for AlertingConfig {
    fn default() -> Self {
        Self {
            terminal: true,
            log_file: "~/.aegis/threats.jsonl".into(),
            email: EmailConfig::default(),
            webhook: WebhookConfig::default(),
            slack: SlackConfig::default(),
            telegram: TelegramConfig::default(),
        }
    }
}

/// Email notification settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EmailConfig {
    pub enabled: bool,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_username: String,
    pub smtp_password: String,
    pub use_tls: bool,
    pub from: String,
    pub to: Vec<String>,
    pub subject_prefix: String,
    /// Minimum severity to trigger an email alert.
    pub min_severity: String,
    /// Cooldown period between emails (e.g. "5m").
    pub cooldown: String,
}

impl Default for EmailConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            smtp_host: "smtp.example.com".into(),
            smtp_port: 587,
            smtp_username: String::new(),
            smtp_password: String::new(),
            use_tls: true,
            from: "aegis@yourdomain.com".into(),
            to: vec!["admin@yourdomain.com".into()],
            subject_prefix: "[AEGIS]".into(),
            min_severity: "high".into(),
            cooldown: "5m".into(),
        }
    }
}

/// Webhook notification settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WebhookConfig {
    pub enabled: bool,
    pub url: String,
    /// Minimum severity to trigger a webhook notification.
    pub min_severity: String,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: String::new(),
            min_severity: "high".into(),
        }
    }
}

fn default_true() -> bool {
    true
}

/// Slack webhook notification settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SlackConfig {
    pub enabled: bool,
    pub webhook_url: String,
    /// Minimum severity to trigger a Slack notification.
    pub min_severity: String,
}

impl Default for SlackConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            webhook_url: String::new(),
            min_severity: "high".into(),
        }
    }
}

/// Telegram bot notification settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TelegramConfig {
    pub enabled: bool,
    /// Bot token (prefer AEGIS_TELEGRAM_BOT_TOKEN env var).
    pub bot_token: String,
    pub chat_id: String,
    /// Minimum severity to trigger a Telegram notification.
    pub min_severity: String,
}

impl Default for TelegramConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bot_token: String::new(),
            chat_id: String::new(),
            min_severity: "high".into(),
        }
    }
}

/// GeoIP-based blocking configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GeoipConfig {
    pub enabled: bool,
    /// Path to the MaxMind GeoLite2-Country.mmdb file.
    pub database_path: String,
    /// MaxMind license key for downloading the GeoIP database.
    #[serde(default)]
    pub maxmind_license_key: String,
    /// ISO country codes to block (e.g. ["CN", "RU"]).
    pub blocked_countries: Vec<String>,
    /// ISO country codes to allow (if non-empty, only these are allowed).
    pub allowed_countries: Vec<String>,
}

impl Default for GeoipConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            database_path: "~/.aegis/GeoLite2-Country.mmdb".into(),
            maxmind_license_key: String::new(),
            blocked_countries: Vec::new(),
            allowed_countries: Vec::new(),
        }
    }
}

/// Log anomaly detection module configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AnomalyConfig {
    pub enabled: bool,
    /// Hour range considered normal for logins [start, end] in 24h format.
    pub normal_login_hours: Vec<u32>,
    /// Watch for cron changes.
    pub watch_cron: bool,
    /// Watch for sudoers changes.
    pub watch_sudoers: bool,
    /// Watch for new user accounts.
    pub watch_user_changes: bool,
    /// Kernel module names to ignore (supports glob suffix, e.g. "xt_*").
    #[serde(default)]
    pub kernel_module_whitelist: Vec<String>,
}

impl Default for AnomalyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            normal_login_hours: vec![6, 22],
            watch_cron: true,
            watch_sudoers: true,
            watch_user_changes: true,
            kernel_module_whitelist: Vec::new(),
        }
    }
}

/// SSH honeypot module configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct HoneypotConfig {
    pub enabled: bool,
    /// TCP ports to listen on as decoy SSH servers.
    pub ports: Vec<u16>,
    /// Automatically block IPs that connect to honeypot ports.
    pub auto_block: bool,
    /// How long to keep the connection open before closing (seconds).
    pub linger_seconds: u64,
}

impl Default for HoneypotConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ports: vec![2222, 2223, 8022],
            auto_block: true,
            linger_seconds: 10,
        }
    }
}

/// TLS certificate monitoring configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CertConfig {
    pub enabled: bool,
    /// Domains to check (e.g. "example.com:443").
    pub domains: Vec<String>,
    /// Days before expiry to start warning.
    pub warn_days: u32,
}

impl Default for CertConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            domains: Vec::new(),
            warn_days: 14,
        }
    }
}

/// Web dashboard configuration (requires web-dashboard feature).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DashboardConfig {
    pub enabled: bool,
    /// Address to bind the web server to.
    pub bind: String,
    /// Port for the web server.
    pub port: u16,
    /// Path to the API authentication token file.
    pub token_file: String,
}

impl Default for DashboardConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            bind: "127.0.0.1".into(),
            port: 9443,
            token_file: "/etc/aegis/api.token".into(),
        }
    }
}

/// eBPF real-time monitoring configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EbpfConfig {
    /// Auto-fallback to polling if eBPF/BTF unavailable.
    pub enabled: bool,
    /// Trace process execution via execve.
    pub probe_execve: bool,
    /// Trace outbound network connections.
    pub probe_connect: bool,
    /// Trace file opens (noisy, off by default).
    pub probe_open: bool,
    /// Fallback polling interval when eBPF unavailable.
    pub fallback_poll_secs: u64,
}

impl Default for EbpfConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            probe_execve: true,
            probe_connect: true,
            probe_open: false,
            fallback_poll_secs: 60,
        }
    }
}

/// DNS monitoring module configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsConfig {
    pub enabled: bool,
    /// Log files to parse for DNS queries.
    pub log_paths: Vec<String>,
    /// Shannon entropy threshold for DGA detection.
    pub dga_entropy_threshold: f64,
    /// Minimum domain label length for DGA check.
    pub dga_min_length: usize,
    /// Queries per minute per domain to flag tunneling.
    pub tunnel_query_rate_threshold: u32,
    /// Domains to never flag.
    pub whitelist_domains: Vec<String>,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            log_paths: vec!["/var/log/syslog".into()],
            dga_entropy_threshold: 3.5,
            dga_min_length: 12,
            tunnel_query_rate_threshold: 50,
            whitelist_domains: Vec::new(),
        }
    }
}

/// Container awareness configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ContainerConfig {
    pub enabled: bool,
    /// Detect container escape attempts.
    pub detect_escapes: bool,
    /// Processes allowed to run privileged inside containers.
    pub privileged_process_whitelist: Vec<String>,
}

impl Default for ContainerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            detect_escapes: true,
            privileged_process_whitelist: Vec::new(),
        }
    }
}

/// Rootkit detection module configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RootkitConfig {
    pub enabled: bool,
    /// Compare readdir vs kill(pid,0) for hidden processes.
    pub check_hidden_processes: bool,
    /// Scan for LD_PRELOAD in process environments.
    pub check_ld_preload: bool,
    /// Verify shared library checksums.
    pub check_shared_libraries: bool,
    /// Inspect /proc/kallsyms for suspicious hooks.
    pub check_kernel_symbols: bool,
    /// Compare readdir vs stat in suspicious directories.
    pub check_hidden_files: bool,
    /// Directories to scan for hidden files.
    pub hidden_files_dirs: Vec<String>,
}

impl Default for RootkitConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            check_hidden_processes: true,
            check_ld_preload: true,
            check_shared_libraries: true,
            check_kernel_symbols: true,
            check_hidden_files: true,
            hidden_files_dirs: vec!["/tmp".into(), "/var/tmp".into(), "/dev/shm".into()],
        }
    }
}

/// SSH session recording and analysis configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SshSessionConfig {
    pub enabled: bool,
    /// Auth log paths to monitor for SSH sessions.
    pub log_paths: Vec<String>,
    /// Audit log path for EXECVE records.
    pub audit_log_path: String,
    /// Directory to store session metadata.
    pub session_store_dir: String,
    /// Maximum age before session data is pruned.
    pub max_session_age: String,
    /// Additional suspicious command patterns.
    pub suspicious_patterns: Vec<String>,
}

impl Default for SshSessionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            log_paths: vec!["/var/log/auth.log".into()],
            audit_log_path: "/var/log/audit/audit.log".into(),
            session_store_dir: "~/.aegis/sessions".into(),
            max_session_age: "30d".into(),
            suspicious_patterns: Vec::new(),
        }
    }
}

/// Threat intelligence enrichment configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EnrichmentConfig {
    pub enabled: bool,
    /// AbuseIPDB API key.
    pub abuseipdb_key: String,
    /// Shodan API key.
    pub shodan_key: String,
    /// GreyNoise API key.
    pub greynoise_key: String,
    /// Cache TTL for enrichment results.
    pub cache_ttl: String,
    /// API rate limit per minute.
    pub rate_limit_per_minute: u32,
}

impl Default for EnrichmentConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            abuseipdb_key: String::new(),
            shodan_key: String::new(),
            greynoise_key: String::new(),
            cache_ttl: "24h".into(),
            rate_limit_per_minute: 30,
        }
    }
}

/// CIS benchmark auditing configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AuditConfig {
    pub enabled: bool,
    /// Audit profile: "server" or "workstation".
    pub profile: String,
    /// Report output format: "json", "html", or "text".
    pub report_format: String,
    /// Whether to suggest remediation steps.
    pub remediate: bool,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            profile: "server".into(),
            report_format: "text".into(),
            remediate: false,
        }
    }
}

/// Automated forensic snapshot configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ForensicConfig {
    pub enabled: bool,
    /// Minimum severity to trigger a snapshot.
    pub trigger_severity: String,
    /// Threat types that trigger a snapshot.
    pub trigger_types: Vec<String>,
    /// Directory to store forensic snapshots.
    pub snapshot_dir: String,
    /// Whether to capture process memory.
    pub capture_memory: bool,
    /// Maximum number of snapshots to retain.
    pub max_snapshots: u32,
    /// Days to retain snapshots.
    pub retention_days: u32,
}

impl Default for ForensicConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            trigger_severity: "critical".into(),
            trigger_types: vec!["reverse_shell".into(), "rootkit_detected".into()],
            snapshot_dir: "~/.aegis/forensic".into(),
            capture_memory: false,
            max_snapshots: 50,
            retention_days: 90,
        }
    }
}

/// TLS fingerprinting (JA3/JA4) configuration.
#[cfg(feature = "tls-fingerprint")]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TlsFingerprintConfig {
    pub enabled: bool,
    /// Network interface to capture on.
    pub interface: String,
    /// Path to known-bad fingerprint database.
    pub known_bad_file: String,
    /// Log all fingerprints, not just matches.
    pub log_all_fingerprints: bool,
}

#[cfg(feature = "tls-fingerprint")]
impl Default for TlsFingerprintConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interface: "eth0".into(),
            known_bad_file: "~/.aegis/ja3_bad.json".into(),
            log_all_fingerprints: false,
        }
    }
}

/// YARA rule scanning configuration.
#[cfg(feature = "yara")]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct YaraConfig {
    pub enabled: bool,
    /// Directory containing .yar rule files.
    pub rules_dir: String,
    /// Scan newly executed processes.
    pub scan_new_processes: bool,
    /// Scan files dropped in suspicious directories.
    pub scan_dropped_files: bool,
    /// Cache SHA-256 of known-good binaries.
    pub cache_known_good: bool,
    /// Maximum file size to scan (MB).
    pub max_file_size_mb: u32,
}

#[cfg(feature = "yara")]
impl Default for YaraConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            rules_dir: "~/.aegis/yara_rules".into(),
            scan_new_processes: true,
            scan_dropped_files: true,
            cache_known_good: true,
            max_file_size_mb: 100,
        }
    }
}

/// Central aggregation server configuration.
#[cfg(feature = "server")]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub enabled: bool,
    /// gRPC bind address.
    pub bind: String,
    /// TLS certificate path.
    pub tls_cert: String,
    /// TLS key path.
    pub tls_key: String,
    /// Maximum connected hosts.
    pub max_hosts: u32,
    /// Days to retain events.
    pub retention_days: u32,
}

#[cfg(feature = "server")]
impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: "0.0.0.0:50051".into(),
            tls_cert: String::new(),
            tls_key: String::new(),
            max_hosts: 100,
            retention_days: 30,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_serializes() {
        let config = AegisConfig::default();
        let toml_str = toml::to_string_pretty(&config).unwrap();
        assert!(toml_str.contains("[general]"));
        assert!(toml_str.contains("[network]"));
        assert!(toml_str.contains("[response]"));
    }

    #[test]
    fn test_roundtrip() {
        let config = AegisConfig::default();
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: AegisConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.general.log_level, config.general.log_level);
        assert_eq!(
            parsed.network.syn_flood_threshold,
            config.network.syn_flood_threshold
        );
    }

    #[test]
    fn test_feed_config_has_api_key_field() {
        let feed = FeedConfig {
            url: "https://example.com/feed".into(),
            enabled: true,
            weight: 80,
            api_key: Some("secret-key".into()),
            min_confidence: Some(75),
        };
        let serialized = toml::to_string(&feed).unwrap();
        assert!(serialized.contains("api_key"));
        assert!(serialized.contains("min_confidence"));
    }

    #[test]
    fn test_partial_config_uses_defaults() {
        let partial = r#"
[general]
modules = ["network"]
log_level = "debug"
"#;
        let config: AegisConfig = toml::from_str(partial).unwrap();
        assert_eq!(config.general.log_level, "debug");
        // Everything else should be defaults
        assert!(config.network.enabled);
        assert_eq!(config.network.syn_flood_threshold, 50);
        assert!(config.process.enabled);
    }
}
