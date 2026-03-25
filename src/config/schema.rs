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
    /// Minimum beacons in window to flag as C2.
    pub c2_beacon_threshold: u32,
    /// Window in seconds for C2 beacon detection.
    pub c2_beacon_window: u64,
    /// Connections per minute from a single IP to trigger rate alert.
    pub connection_rate_threshold: u32,
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
            ],
            c2_beacon_threshold: 10,
            c2_beacon_window: 300,
            connection_rate_threshold: 100,
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
        overrides.insert("c2_beacon".into(), "block".into());
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
