use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::debug;

use super::threat::{ThreatEvent, ThreatSeverity};
use crate::config::schema::AegisConfig;

/// Type alias for thread-safe shared state.
pub type SharedState = Arc<RwLock<AppState>>;

/// Create a new shared state wrapped in Arc<RwLock>.
pub fn shared_state(config: AegisConfig) -> SharedState {
    Arc::new(RwLock::new(AppState::with_config(config)))
}

/// Information about a blocked IP address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockEntry {
    pub ip: IpAddr,
    pub reason: String,
    pub blocked_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    /// Whether this block was automatically applied.
    pub auto: bool,
}

/// File integrity baseline: maps file paths to their SHA-256 hashes.
pub type FileBaseline = HashMap<PathBuf, String>;

/// IP lookup set for threat intelligence: stores known-bad IPs and their feed source/weight.
///
/// Feed names are interned into a name table to avoid cloning strings per-IP.
/// All CIDR ranges (including /24s) are stored as CIDRs rather than enumerated
/// into individual IPs, drastically reducing memory usage.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IpLookup {
    /// Interned feed names: index → name. Keeps one copy of each string.
    feed_names: Vec<String>,
    /// Individual IPs: maps to a list of (feed_index, weight) pairs.
    entries: HashMap<IpAddr, Vec<(u8, u32)>>,
    /// CIDR ranges checked via linear scan on lookup.
    #[serde(skip)]
    cidrs: Vec<(IpNet, u8, u32)>,
}

impl IpLookup {
    pub fn new() -> Self {
        Self {
            feed_names: Vec::new(),
            entries: HashMap::new(),
            cidrs: Vec::new(),
        }
    }

    /// Return (or create) the interned index for a feed name.
    pub fn intern_feed(&mut self, name: &str) -> u8 {
        if let Some(idx) = self.feed_names.iter().position(|n| n == name) {
            idx as u8
        } else {
            let idx = self.feed_names.len();
            assert!(idx < 256, "More than 255 feeds is not supported");
            self.feed_names.push(name.to_string());
            idx as u8
        }
    }

    /// Resolve a feed index back to its name.
    pub fn feed_name(&self, idx: u8) -> &str {
        &self.feed_names[idx as usize]
    }

    /// Check if an IP is in any threat feed. Returns the maximum weight if found.
    pub fn lookup(&self, ip: &IpAddr) -> Option<u32> {
        let mut max_w: Option<u32> = None;

        if let Some(feeds) = self.entries.get(ip) {
            max_w = feeds.iter().map(|&(_, w)| w).max();
        }

        for &(ref cidr, _, w) in &self.cidrs {
            if cidr.contains(ip) {
                max_w = Some(max_w.map_or(w, |prev| prev.max(w)));
            }
        }

        max_w
    }

    /// Look up an IP and return the max weight plus feed details (resolved names).
    pub fn lookup_with_details(&self, ip: &IpAddr) -> Option<(u32, Vec<(String, u32)>)> {
        let mut results: Vec<(String, u32)> = Vec::new();

        if let Some(feeds) = self.entries.get(ip) {
            for &(idx, w) in feeds {
                results.push((self.feed_names[idx as usize].clone(), w));
            }
        }

        for &(ref cidr, idx, w) in &self.cidrs {
            if cidr.contains(ip) {
                results.push((self.feed_names[idx as usize].clone(), w));
            }
        }

        if results.is_empty() {
            None
        } else {
            let max_w = results.iter().map(|(_, w)| *w).max().unwrap_or(0);
            Some((max_w, results))
        }
    }

    /// Add an individual IP with its feed index and weight.
    pub fn insert(&mut self, ip: IpAddr, feed_idx: u8, weight: u32) {
        self.entries.entry(ip).or_default().push((feed_idx, weight));
    }

    /// Add a CIDR range with its feed index and weight.
    pub fn insert_cidr(&mut self, cidr: IpNet, feed_idx: u8, weight: u32) {
        self.cidrs.push((cidr, feed_idx, weight));
    }

    /// Total number of unique individual IPs (excludes CIDR ranges).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Total number of CIDR ranges stored.
    pub fn cidr_count(&self) -> usize {
        self.cidrs.len()
    }

    /// Whether the lookup table is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.cidrs.is_empty()
    }
}

/// Record of an IP's auto-block history for repeat offender escalation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrikeRecord {
    /// Timestamps of each auto-block event.
    pub strikes: Vec<DateTime<Utc>>,
    /// Reason from the most recent block.
    pub last_reason: String,
    /// Whether this IP has been permanently banned via escalation.
    pub escalated: bool,
}

/// Per-IP strike history for repeat offender tracking.
pub type StrikeHistory = HashMap<IpAddr, StrikeRecord>;

/// Scan statistics for tracking activity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStats {
    pub scans_run: u64,
    pub threats_found: u64,
    pub ips_blocked: u64,
    pub start_time: DateTime<Utc>,
}

impl Default for ScanStats {
    fn default() -> Self {
        Self {
            scans_run: 0,
            threats_found: 0,
            ips_blocked: 0,
            start_time: Utc::now(),
        }
    }
}

/// Summary security posture based on current threats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SecurityPosture {
    /// No threats detected.
    Secure,
    /// Only informational or low-severity findings.
    Guarded,
    /// Medium-severity threats present.
    Elevated,
    /// High-severity threats present.
    High,
    /// Critical threats detected - immediate action required.
    Critical,
}

impl std::fmt::Display for SecurityPosture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecurityPosture::Secure => write!(f, "SECURE"),
            SecurityPosture::Guarded => write!(f, "GUARDED"),
            SecurityPosture::Elevated => write!(f, "ELEVATED"),
            SecurityPosture::High => write!(f, "HIGH"),
            SecurityPosture::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Centralized application state shared across all modules and the CLI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppState {
    /// Active configuration.
    pub config: AegisConfig,
    /// When the engine was started or the last scan was initiated.
    pub started_at: DateTime<Utc>,
    /// All detected threat events in this session.
    pub threats: Vec<ThreatEvent>,
    /// IP addresses currently blocked by the response engine.
    pub blocked_ips: HashMap<IpAddr, BlockEntry>,
    /// File integrity baseline (path -> SHA-256 hash).
    #[serde(skip)]
    pub baseline: Option<FileBaseline>,
    /// Threat intelligence IP lookup table.
    #[serde(skip)]
    pub threat_intel: Option<IpLookup>,
    /// Scan statistics.
    pub stats: ScanStats,
    /// Per-IP strike history for repeat offender auto-escalation.
    #[serde(default)]
    pub strike_history: StrikeHistory,
    /// Set of modules that have been run.
    pub modules_run: HashSet<String>,
    /// Whether the engine is currently running in daemon mode.
    pub daemon_running: bool,
    /// Overall security posture assessment.
    pub posture: SecurityPosture,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            config: AegisConfig::default(),
            started_at: Utc::now(),
            threats: Vec::new(),
            blocked_ips: HashMap::new(),
            baseline: None,
            threat_intel: None,
            stats: ScanStats::default(),
            strike_history: HashMap::new(),
            modules_run: HashSet::new(),
            daemon_running: false,
            posture: SecurityPosture::Secure,
        }
    }
}

impl AppState {
    /// Create a new default AppState (for backward compatibility and tests).
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new AppState with the given configuration.
    pub fn with_config(config: AegisConfig) -> Self {
        Self {
            config,
            started_at: Utc::now(),
            threats: Vec::new(),
            blocked_ips: HashMap::new(),
            baseline: None,
            threat_intel: None,
            stats: ScanStats::default(),
            strike_history: HashMap::new(),
            modules_run: HashSet::new(),
            daemon_running: false,
            posture: SecurityPosture::Secure,
        }
    }

    /// Add a threat event, update stats, and recalculate the security posture.
    pub fn add_threat(&mut self, threat: ThreatEvent) {
        debug!(
            threat_id = %threat.id,
            threat_type = %threat.threat_type,
            severity = %threat.severity,
            "Adding threat to state"
        );
        self.stats.threats_found += 1;
        self.threats.push(threat);
        self.recalculate_posture();
    }

    /// Add multiple threat events.
    pub fn add_threats(&mut self, threats: Vec<ThreatEvent>) {
        self.stats.threats_found += threats.len() as u64;
        self.threats.extend(threats);
        self.recalculate_posture();
    }

    /// Maximum number of threats to keep in memory.
    const MAX_IN_MEMORY_THREATS: usize = 1000;

    /// Trim the in-memory threats list to the most recent MAX_IN_MEMORY_THREATS.
    /// Returns the number of evicted entries.
    pub fn cap_threats(&mut self) -> usize {
        if self.threats.len() <= Self::MAX_IN_MEMORY_THREATS {
            return 0;
        }
        let excess = self.threats.len() - Self::MAX_IN_MEMORY_THREATS;
        self.threats.drain(..excess);
        self.recalculate_posture();
        debug!(evicted = excess, "Capped in-memory threats");
        excess
    }

    /// Check if an IP address is currently blocked.
    pub fn is_ip_blocked(&self, ip: &IpAddr) -> bool {
        if let Some(entry) = self.blocked_ips.get(ip) {
            // Check if the block has expired
            if let Some(expires) = entry.expires_at {
                if Utc::now() > expires {
                    return false;
                }
            }
            true
        } else {
            false
        }
    }

    /// Block an IP address and update stats.
    pub fn block_ip(&mut self, entry: BlockEntry) {
        debug!(ip = %entry.ip, reason = %entry.reason, "Blocking IP");
        self.stats.ips_blocked += 1;
        self.blocked_ips.insert(entry.ip, entry);
    }

    /// Unblock an IP address. Returns true if it was previously blocked.
    pub fn unblock_ip(&mut self, ip: &IpAddr) -> bool {
        self.blocked_ips.remove(ip).is_some()
    }

    /// Remove expired block entries. Returns the number of entries removed.
    pub fn expire_blocks(&mut self) -> usize {
        let now = Utc::now();
        let before = self.blocked_ips.len();
        self.blocked_ips
            .retain(|_, entry| entry.expires_at.is_none_or(|exp| now <= exp));
        before - self.blocked_ips.len()
    }

    /// Record that a module has been run.
    pub fn mark_module_run(&mut self, module: &str) {
        self.modules_run.insert(module.to_string());
    }

    /// Increment the scan counter.
    pub fn record_scan(&mut self) {
        self.stats.scans_run += 1;
    }

    /// Count threats by severity.
    pub fn threat_counts(&self) -> HashMap<ThreatSeverity, usize> {
        let mut counts = HashMap::new();
        for threat in &self.threats {
            *counts.entry(threat.severity).or_insert(0) += 1;
        }
        counts
    }

    /// Get the highest severity among unresponded threats.
    /// Responded threats (blocked IPs, killed processes) no longer
    /// contribute to the security posture.
    pub fn max_severity(&self) -> Option<ThreatSeverity> {
        self.threats
            .iter()
            .filter(|t| !t.auto_responded)
            .map(|t| t.severity)
            .max()
    }

    /// Recalculate the security posture based on the current threat list.
    pub fn recalculate_posture(&mut self) {
        self.posture = match self.max_severity() {
            None => SecurityPosture::Secure,
            Some(ThreatSeverity::Info) => SecurityPosture::Guarded,
            Some(ThreatSeverity::Low) => SecurityPosture::Guarded,
            Some(ThreatSeverity::Medium) => SecurityPosture::Elevated,
            Some(ThreatSeverity::High) => SecurityPosture::High,
            Some(ThreatSeverity::Critical) => SecurityPosture::Critical,
        };
    }

    /// Get threats filtered by minimum severity.
    pub fn threats_at_least(&self, min: ThreatSeverity) -> Vec<&ThreatEvent> {
        self.threats.iter().filter(|t| t.severity >= min).collect()
    }

    /// Get all unique source IPs from threats, sorted by frequency (descending).
    pub fn top_attacking_ips(&self, limit: usize) -> Vec<(IpAddr, usize)> {
        let mut ip_counts: HashMap<IpAddr, usize> = HashMap::new();
        for threat in &self.threats {
            if let Some(ip) = threat.source_ip {
                *ip_counts.entry(ip).or_insert(0) += 1;
            }
        }
        let mut sorted: Vec<_> = ip_counts.into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        sorted.truncate(limit);
        sorted
    }

    /// Set the file integrity baseline.
    pub fn set_baseline(&mut self, baseline: FileBaseline) {
        self.baseline = Some(baseline);
    }

    /// Set the threat intelligence lookup table.
    pub fn set_threat_intel(&mut self, lookup: IpLookup) {
        self.threat_intel = Some(lookup);
    }

    // -------------------------------------------------------------------
    // Strike history (repeat offender tracking)
    // -------------------------------------------------------------------

    /// Record a new strike for an IP, pruning timestamps outside the window.
    /// Returns the number of strikes within the window after recording.
    pub fn record_strike(&mut self, ip: IpAddr, reason: &str, window: chrono::Duration) -> usize {
        let now = Utc::now();
        let cutoff = now - window;
        let record = self
            .strike_history
            .entry(ip)
            .or_insert_with(|| StrikeRecord {
                strikes: Vec::new(),
                last_reason: String::new(),
                escalated: false,
            });
        // Prune old timestamps outside the window.
        record.strikes.retain(|ts| *ts >= cutoff);
        record.strikes.push(now);
        record.last_reason = reason.to_string();
        record.strikes.len()
    }

    /// Count strikes for an IP within the given window (read-only).
    pub fn strike_count(&self, ip: &IpAddr, window: chrono::Duration) -> usize {
        let cutoff = Utc::now() - window;
        self.strike_history
            .get(ip)
            .map(|r| r.strikes.iter().filter(|ts| **ts >= cutoff).count())
            .unwrap_or(0)
    }

    /// Check whether an IP has been permanently escalated.
    pub fn is_escalated(&self, ip: &IpAddr) -> bool {
        self.strike_history.get(ip).is_some_and(|r| r.escalated)
    }

    /// Mark an IP as permanently escalated.
    pub fn mark_escalated(&mut self, ip: &IpAddr) {
        if let Some(record) = self.strike_history.get_mut(ip) {
            record.escalated = true;
        }
    }

    /// Prune old strike records outside the window and cap total records.
    /// Escalated entries are always preserved. Returns the number of entries removed.
    pub fn prune_strikes(&mut self, window: chrono::Duration, max_records: usize) -> usize {
        let cutoff = Utc::now() - window;
        let before = self.strike_history.len();

        // Remove non-escalated entries with no strikes in the window.
        self.strike_history.retain(|_, record| {
            if record.escalated {
                return true;
            }
            record.strikes.retain(|ts| *ts >= cutoff);
            !record.strikes.is_empty()
        });

        // Cap total records if over limit (remove oldest non-escalated first).
        if self.strike_history.len() > max_records {
            // Collect non-escalated IPs sorted by oldest last-strike.
            let mut candidates: Vec<(IpAddr, DateTime<Utc>)> = self
                .strike_history
                .iter()
                .filter(|(_, r)| !r.escalated)
                .map(|(ip, r)| {
                    let oldest = r.strikes.iter().copied().max().unwrap_or(cutoff);
                    (*ip, oldest)
                })
                .collect();
            candidates.sort_by_key(|(_, ts)| *ts);

            let to_remove = self.strike_history.len() - max_records;
            for (ip, _) in candidates.into_iter().take(to_remove) {
                self.strike_history.remove(&ip);
            }
        }

        before - self.strike_history.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::threat::ThreatType;

    fn test_config() -> AegisConfig {
        AegisConfig::default()
    }

    #[test]
    fn test_posture_calculation() {
        let mut state = AppState::with_config(test_config());
        assert_eq!(state.posture, SecurityPosture::Secure);

        state.add_threat(ThreatEvent::new(
            ThreatType::TorExit,
            "threat_intel",
            "Tor exit node detected",
        ));
        assert_eq!(state.posture, SecurityPosture::Guarded);

        state.add_threat(
            ThreatEvent::new(ThreatType::PortScan, "network", "Port scan detected")
                .with_severity(ThreatSeverity::Medium),
        );
        assert_eq!(state.posture, SecurityPosture::Elevated);

        state.add_threat(ThreatEvent::new(
            ThreatType::ReverseShell,
            "process",
            "Reverse shell detected",
        ));
        assert_eq!(state.posture, SecurityPosture::Critical);

        // Responding to all threats should lower posture back to Secure
        for t in &mut state.threats {
            t.auto_responded = true;
        }
        state.recalculate_posture();
        assert_eq!(state.posture, SecurityPosture::Secure);
    }

    #[test]
    fn test_ip_blocking() {
        let mut state = AppState::with_config(test_config());
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        assert!(!state.is_ip_blocked(&ip));

        state.block_ip(BlockEntry {
            ip,
            reason: "test".into(),
            blocked_at: Utc::now(),
            expires_at: None,
            auto: true,
        });
        assert!(state.is_ip_blocked(&ip));
        assert_eq!(state.stats.ips_blocked, 1);

        assert!(state.unblock_ip(&ip));
        assert!(!state.is_ip_blocked(&ip));
    }

    #[test]
    fn test_expired_block() {
        let mut state = AppState::with_config(test_config());
        let ip: IpAddr = "10.0.0.2".parse().unwrap();

        // Block with an already-expired time
        state.block_ip(BlockEntry {
            ip,
            reason: "expired".into(),
            blocked_at: Utc::now() - chrono::Duration::hours(2),
            expires_at: Some(Utc::now() - chrono::Duration::hours(1)),
            auto: true,
        });

        // is_ip_blocked should see it as expired
        assert!(!state.is_ip_blocked(&ip));

        // expire_blocks should clean it up
        let removed = state.expire_blocks();
        assert_eq!(removed, 1);
        assert!(state.blocked_ips.is_empty());
    }

    #[test]
    fn test_top_attacking_ips() {
        let mut state = AppState::with_config(test_config());
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();

        for _ in 0..5 {
            state.add_threat(
                ThreatEvent::new(ThreatType::BruteForce, "auth", "brute force").with_source_ip(ip1),
            );
        }
        for _ in 0..3 {
            state.add_threat(
                ThreatEvent::new(ThreatType::PortScan, "network", "port scan").with_source_ip(ip2),
            );
        }

        let top = state.top_attacking_ips(10);
        assert_eq!(top[0], (ip1, 5));
        assert_eq!(top[1], (ip2, 3));
    }

    #[test]
    fn test_stats_tracking() {
        let mut state = AppState::with_config(test_config());
        state.record_scan();
        state.record_scan();
        assert_eq!(state.stats.scans_run, 2);

        state.add_threat(ThreatEvent::new(ThreatType::SynFlood, "network", "flood"));
        assert_eq!(state.stats.threats_found, 1);
    }

    #[test]
    fn test_ip_lookup() {
        let mut lookup = IpLookup::new();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        assert!(lookup.lookup(&ip).is_none());

        let fh = lookup.intern_feed("firehol");
        let sp = lookup.intern_feed("spamhaus");
        lookup.insert(ip, fh, 90);
        lookup.insert(ip, sp, 95);

        assert_eq!(lookup.lookup(&ip), Some(95));
        assert_eq!(lookup.len(), 1);

        // Verify feed name resolution
        assert_eq!(lookup.feed_name(fh), "firehol");
        assert_eq!(lookup.feed_name(sp), "spamhaus");

        // Verify lookup_with_details returns resolved names
        let (max_w, details) = lookup.lookup_with_details(&ip).unwrap();
        assert_eq!(max_w, 95);
        assert_eq!(details.len(), 2);
    }

    #[test]
    fn test_shared_state() {
        let ss = shared_state(test_config());
        // Verify we can clone the Arc
        let ss2 = ss.clone();
        assert!(Arc::ptr_eq(&ss, &ss2));
    }

    // -------------------------------------------------------------------
    // Strike history tests
    // -------------------------------------------------------------------

    #[test]
    fn test_record_strike_increments() {
        let mut state = AppState::with_config(test_config());
        let ip: IpAddr = "10.0.0.99".parse().unwrap();
        let window = chrono::Duration::days(30);

        assert_eq!(state.record_strike(ip, "ddos", window), 1);
        assert_eq!(state.record_strike(ip, "scan", window), 2);
        assert_eq!(state.record_strike(ip, "brute", window), 3);
        assert_eq!(state.strike_count(&ip, window), 3);
    }

    #[test]
    fn test_strike_window_filtering() {
        let mut state = AppState::with_config(test_config());
        let ip: IpAddr = "10.0.0.100".parse().unwrap();
        let window = chrono::Duration::days(30);

        // Insert an old strike manually (outside window).
        state.strike_history.insert(
            ip,
            StrikeRecord {
                strikes: vec![Utc::now() - chrono::Duration::days(60)],
                last_reason: "old".into(),
                escalated: false,
            },
        );

        // record_strike prunes old ones and adds new.
        let count = state.record_strike(ip, "new", window);
        assert_eq!(count, 1); // old strike was outside window

        // strike_count should also only see the recent one.
        assert_eq!(state.strike_count(&ip, window), 1);
    }

    #[test]
    fn test_escalation_persists() {
        let mut state = AppState::with_config(test_config());
        let ip: IpAddr = "10.0.0.101".parse().unwrap();
        let window = chrono::Duration::days(30);

        state.record_strike(ip, "test", window);
        assert!(!state.is_escalated(&ip));

        state.mark_escalated(&ip);
        assert!(state.is_escalated(&ip));
    }

    #[test]
    fn test_prune_removes_old_preserves_escalated() {
        let mut state = AppState::with_config(test_config());
        let window = chrono::Duration::days(30);

        // IP with old-only strikes (should be pruned).
        let old_ip: IpAddr = "10.0.0.200".parse().unwrap();
        state.strike_history.insert(
            old_ip,
            StrikeRecord {
                strikes: vec![Utc::now() - chrono::Duration::days(60)],
                last_reason: "old".into(),
                escalated: false,
            },
        );

        // IP that is escalated (should be kept even with old strikes).
        let esc_ip: IpAddr = "10.0.0.201".parse().unwrap();
        state.strike_history.insert(
            esc_ip,
            StrikeRecord {
                strikes: vec![Utc::now() - chrono::Duration::days(60)],
                last_reason: "perma".into(),
                escalated: true,
            },
        );

        let removed = state.prune_strikes(window, 10_000);
        assert_eq!(removed, 1);
        assert!(!state.strike_history.contains_key(&old_ip));
        assert!(state.strike_history.contains_key(&esc_ip));
    }

    #[test]
    fn test_prune_caps_size() {
        let mut state = AppState::with_config(test_config());
        let window = chrono::Duration::days(30);

        // Insert 100 recent strike records.
        for i in 0..100u8 {
            let ip: IpAddr = format!("10.1.0.{}", i).parse().unwrap();
            state.record_strike(ip, "test", window);
        }
        assert_eq!(state.strike_history.len(), 100);

        // Cap at 50.
        state.prune_strikes(window, 50);
        assert!(state.strike_history.len() <= 50);
    }
}
