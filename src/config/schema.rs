use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Top-level Aegis configuration, typically loaded from aegis.toml.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
}

impl Default for AegisConfig {
    fn default() -> Self {
        Self {
            general: GeneralConfig::default(),
            network: NetworkConfig::default(),
            process: ProcessConfig::default(),
            file_integrity: FileIntegrityConfig::default(),
            auth: AuthConfig::default(),
            web: WebConfig::default(),
            threat_intel: ThreatIntelConfig::default(),
            response: ResponseConfig::default(),
            alerting: AlertingConfig::default(),
        }
    }
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
}

impl Default for FileIntegrityConfig {
    fn default() -> Self {
        Self {
            enabled: true,
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
}

impl Default for AlertingConfig {
    fn default() -> Self {
        Self {
            terminal: true,
            log_file: "~/.aegis/threats.jsonl".into(),
            email: EmailConfig::default(),
            webhook: WebhookConfig::default(),
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
