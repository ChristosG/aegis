use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};

static EVENT_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Severity levels for detected threats, ordered from least to most severe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ThreatSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for ThreatSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ThreatSeverity::Info => write!(f, "info"),
            ThreatSeverity::Low => write!(f, "low"),
            ThreatSeverity::Medium => write!(f, "medium"),
            ThreatSeverity::High => write!(f, "high"),
            ThreatSeverity::Critical => write!(f, "critical"),
        }
    }
}

impl ThreatSeverity {
    /// Parse a severity string (case-insensitive).
    pub fn from_str_loose(s: &str) -> Option<ThreatSeverity> {
        match s.to_lowercase().as_str() {
            "info" => Some(ThreatSeverity::Info),
            "low" => Some(ThreatSeverity::Low),
            "medium" | "med" => Some(ThreatSeverity::Medium),
            "high" => Some(ThreatSeverity::High),
            "critical" | "crit" => Some(ThreatSeverity::Critical),
            _ => None,
        }
    }
}

/// Classification of the type of threat detected.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatType {
    SynFlood,
    PortScan,
    SuspiciousConnection,
    C2Beacon,
    CryptoMiner,
    ReverseShell,
    SuspiciousBinary,
    BruteForce,
    RootLogin,
    LoginAnomaly,
    FileModified,
    FileAdded,
    FileDeleted,
    ScannerProbe,
    WebDdos,
    SqlInjection,
    PathTraversal,
    ThreatIntelMatch,
    TorExit,
    UnusualLoginTime,
    CronModified,
    SudoersModified,
    NewUserCreated,
    HoneypotConnection,
}

impl fmt::Display for ThreatType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ThreatType::SynFlood => write!(f, "SYN Flood"),
            ThreatType::PortScan => write!(f, "Port Scan"),
            ThreatType::SuspiciousConnection => write!(f, "Suspicious Connection"),
            ThreatType::C2Beacon => write!(f, "C2 Beacon"),
            ThreatType::CryptoMiner => write!(f, "Crypto Miner"),
            ThreatType::ReverseShell => write!(f, "Reverse Shell"),
            ThreatType::SuspiciousBinary => write!(f, "Suspicious Binary"),
            ThreatType::BruteForce => write!(f, "Brute Force"),
            ThreatType::RootLogin => write!(f, "Root Login"),
            ThreatType::LoginAnomaly => write!(f, "Login Anomaly"),
            ThreatType::FileModified => write!(f, "File Modified"),
            ThreatType::FileAdded => write!(f, "File Added"),
            ThreatType::FileDeleted => write!(f, "File Deleted"),
            ThreatType::ScannerProbe => write!(f, "Scanner Probe"),
            ThreatType::WebDdos => write!(f, "Web DDoS"),
            ThreatType::SqlInjection => write!(f, "SQL Injection"),
            ThreatType::PathTraversal => write!(f, "Path Traversal"),
            ThreatType::ThreatIntelMatch => write!(f, "Threat Intel Match"),
            ThreatType::TorExit => write!(f, "Tor Exit Node"),
            ThreatType::UnusualLoginTime => write!(f, "Unusual Login Time"),
            ThreatType::CronModified => write!(f, "Cron Modified"),
            ThreatType::SudoersModified => write!(f, "Sudoers Modified"),
            ThreatType::NewUserCreated => write!(f, "New User Created"),
            ThreatType::HoneypotConnection => write!(f, "Honeypot Connection"),
        }
    }
}

impl ThreatType {
    /// Return the default severity for a given threat type.
    pub fn default_severity(&self) -> ThreatSeverity {
        match self {
            ThreatType::SynFlood => ThreatSeverity::High,
            ThreatType::PortScan => ThreatSeverity::Medium,
            ThreatType::SuspiciousConnection => ThreatSeverity::Medium,
            ThreatType::C2Beacon => ThreatSeverity::Critical,
            ThreatType::CryptoMiner => ThreatSeverity::High,
            ThreatType::ReverseShell => ThreatSeverity::Critical,
            ThreatType::SuspiciousBinary => ThreatSeverity::High,
            ThreatType::BruteForce => ThreatSeverity::High,
            ThreatType::RootLogin => ThreatSeverity::Medium,
            ThreatType::LoginAnomaly => ThreatSeverity::Low,
            ThreatType::FileModified => ThreatSeverity::Medium,
            ThreatType::FileAdded => ThreatSeverity::Low,
            ThreatType::FileDeleted => ThreatSeverity::Medium,
            ThreatType::ScannerProbe => ThreatSeverity::Low,
            ThreatType::WebDdos => ThreatSeverity::High,
            ThreatType::SqlInjection => ThreatSeverity::High,
            ThreatType::PathTraversal => ThreatSeverity::High,
            ThreatType::ThreatIntelMatch => ThreatSeverity::High,
            ThreatType::TorExit => ThreatSeverity::Info,
            ThreatType::UnusualLoginTime => ThreatSeverity::Medium,
            ThreatType::CronModified => ThreatSeverity::High,
            ThreatType::SudoersModified => ThreatSeverity::High,
            ThreatType::NewUserCreated => ThreatSeverity::Medium,
            ThreatType::HoneypotConnection => ThreatSeverity::High,
        }
    }

    /// Map a config key string (snake_case) to the corresponding ThreatType.
    pub fn from_config_key(key: &str) -> Option<ThreatType> {
        match key {
            "syn_flood" => Some(ThreatType::SynFlood),
            "port_scan" => Some(ThreatType::PortScan),
            "suspicious_connection" => Some(ThreatType::SuspiciousConnection),
            "c2_beacon" => Some(ThreatType::C2Beacon),
            "crypto_miner" => Some(ThreatType::CryptoMiner),
            "reverse_shell" => Some(ThreatType::ReverseShell),
            "suspicious_binary" => Some(ThreatType::SuspiciousBinary),
            "brute_force" => Some(ThreatType::BruteForce),
            "root_login" => Some(ThreatType::RootLogin),
            "login_anomaly" => Some(ThreatType::LoginAnomaly),
            "file_modified" => Some(ThreatType::FileModified),
            "file_added" => Some(ThreatType::FileAdded),
            "file_deleted" => Some(ThreatType::FileDeleted),
            "scanner_probe" => Some(ThreatType::ScannerProbe),
            "web_ddos" => Some(ThreatType::WebDdos),
            "sql_injection" | "sqli_attempt" => Some(ThreatType::SqlInjection),
            "path_traversal" => Some(ThreatType::PathTraversal),
            "threat_intel_match" => Some(ThreatType::ThreatIntelMatch),
            "tor_exit" => Some(ThreatType::TorExit),
            "unusual_login_time" => Some(ThreatType::UnusualLoginTime),
            "cron_modified" => Some(ThreatType::CronModified),
            "sudoers_modified" => Some(ThreatType::SudoersModified),
            "new_user_created" => Some(ThreatType::NewUserCreated),
            "honeypot_connection" => Some(ThreatType::HoneypotConnection),
            _ => None,
        }
    }
}

/// A single threat event detected by a security module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEvent {
    /// Unique identifier for this event (timestamp-based with counter suffix).
    pub id: String,
    /// Classification of the threat.
    pub threat_type: ThreatType,
    /// Severity level.
    pub severity: ThreatSeverity,
    /// Name of the module that generated this event.
    pub source_module: String,
    /// Human-readable description of the threat.
    pub description: String,
    /// Source IP address if applicable.
    pub source_ip: Option<IpAddr>,
    /// Target resource (file path, port, URL, etc.) if applicable.
    pub target: Option<String>,
    /// Arbitrary key-value details for this event.
    pub details: HashMap<String, String>,
    /// When this event was detected.
    pub timestamp: DateTime<Utc>,
    /// Whether an automated response action was taken.
    pub auto_responded: bool,
}

impl ThreatEvent {
    /// Create a new ThreatEvent with the given type, module name, and description.
    /// Severity is set to the default for the threat type. Other fields default to None/empty.
    pub fn new(
        threat_type: ThreatType,
        source_module: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        let now = Utc::now();
        let count = EVENT_COUNTER.fetch_add(1, Ordering::SeqCst);
        let id = format!("{}-{:04}", now.format("%Y%m%d%H%M%S%3f"), count);
        let severity = threat_type.default_severity();

        Self {
            id,
            severity,
            threat_type,
            source_module: source_module.into(),
            description: description.into(),
            source_ip: None,
            target: None,
            details: HashMap::new(),
            timestamp: now,
            auto_responded: false,
        }
    }

    /// Set the severity, overriding the default.
    pub fn with_severity(mut self, severity: ThreatSeverity) -> Self {
        self.severity = severity;
        self
    }

    /// Set the source IP address.
    pub fn with_source_ip(mut self, ip: IpAddr) -> Self {
        self.source_ip = Some(ip);
        self
    }

    /// Set the target string.
    pub fn with_target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }

    /// Add a detail key-value pair.
    pub fn with_detail(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.details.insert(key.into(), value.into());
        self
    }

    /// Merge multiple detail key-value pairs.
    pub fn with_details(mut self, details: HashMap<String, String>) -> Self {
        self.details.extend(details);
        self
    }

    /// Mark this event as having had an automated response.
    pub fn with_auto_responded(mut self, responded: bool) -> Self {
        self.auto_responded = responded;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_ordering() {
        assert!(ThreatSeverity::Info < ThreatSeverity::Low);
        assert!(ThreatSeverity::Low < ThreatSeverity::Medium);
        assert!(ThreatSeverity::Medium < ThreatSeverity::High);
        assert!(ThreatSeverity::High < ThreatSeverity::Critical);
    }

    #[test]
    fn test_threat_event_builder() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let event = ThreatEvent::new(ThreatType::PortScan, "network", "Detected port scan")
            .with_source_ip(ip)
            .with_target("192.168.1.1:22")
            .with_detail("ports_scanned", "22,80,443")
            .with_severity(ThreatSeverity::High);

        assert_eq!(event.threat_type, ThreatType::PortScan);
        assert_eq!(event.severity, ThreatSeverity::High);
        assert_eq!(event.source_ip, Some(ip));
        assert_eq!(event.target.as_deref(), Some("192.168.1.1:22"));
        assert_eq!(event.details.get("ports_scanned").unwrap(), "22,80,443");
    }

    #[test]
    fn test_unique_ids() {
        let e1 = ThreatEvent::new(ThreatType::SynFlood, "network", "test1");
        let e2 = ThreatEvent::new(ThreatType::SynFlood, "network", "test2");
        assert_ne!(e1.id, e2.id);
    }

    #[test]
    fn test_from_config_key() {
        assert_eq!(
            ThreatType::from_config_key("syn_flood"),
            Some(ThreatType::SynFlood)
        );
        assert_eq!(
            ThreatType::from_config_key("sqli_attempt"),
            Some(ThreatType::SqlInjection)
        );
        assert_eq!(ThreatType::from_config_key("unknown_thing"), None);
    }

    #[test]
    fn test_default_severity() {
        assert_eq!(
            ThreatType::C2Beacon.default_severity(),
            ThreatSeverity::Critical
        );
        assert_eq!(ThreatType::TorExit.default_severity(), ThreatSeverity::Info);
        assert_eq!(
            ThreatType::PortScan.default_severity(),
            ThreatSeverity::Medium
        );
    }
}
