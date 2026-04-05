//! Time-series C2 beacon detection state (v2.6.0 Bucket E).
//!
//! The legacy beacon detector (v2.5.0 and earlier) counted *currently-established*
//! parallel sockets to the same remote endpoint, which produces massive false
//! positives against any HTTP/2 / gRPC client (browsers, API clients, streaming
//! apps) — see docs/TRIAGE_PHASE_A0.md for the real-world impact. The
//! `c2_beacon_window` config field was read but never actually used.
//!
//! This module replaces that with **true time-series detection**: we track
//! *new* outbound connection initiations over time, grouped by
//! `(local_exe, remote_ip, remote_port)`, and flag sets of samples that
//! exhibit periodic timing with low jitter.
//!
//! # Algorithm
//!
//! On each daemon scan tick (~60s):
//!
//! 1. Build the current set of `BeaconKey`s from ESTABLISHED outbound
//!    connections in `/proc/net/tcp`.
//! 2. For any `BeaconKey` NOT seen in the previous tick, record the
//!    current timestamp as a "new connection observed" sample in
//!    `BeaconHistory.entries[key]`.
//! 3. Trim samples older than `window` from each key's deque.
//! 4. For each key with `>= min_samples` samples in the window, compute
//!    the coefficient of variation (CoV = σ/μ) of the inter-arrival times.
//! 5. If `CoV < cov_threshold` AND the mean interval is in the beacon
//!    range (e.g., 30s–15min), flag the key as a beacon candidate.
//!
//! # Why CoV and not FFT?
//!
//! - CoV works with as few as 4 samples (FFT needs many more).
//! - CoV handles jitter naturally: pure-random traffic has CoV ≈ 1.0,
//!   strict beacons have CoV < 0.1, jittered beacons sit around 0.2–0.4.
//! - O(n) in sample count vs O(n log n) for FFT.
//! - Standard blue-team technique (Mandiant whitepapers, SecurityOnion Corelight).
//!
//! # Persistence
//!
//! Serialized to `{data_dir}/beacon_history.json` on daemon shutdown and
//! every housekeeping tick. Loaded on startup. Survives daemon restarts
//! so short-cycle beacons aren't forgotten between scans.
//!
//! # Memory bounds
//!
//! - `max_keys`: cap on distinct (local_exe, remote_ip, remote_port) tuples
//!   (default 10k). On overflow, the key with the oldest last-sample is
//!   evicted.
//! - `max_samples_per_key`: cap on samples held per key (default 20).
//!   Oldest samples drop off as new ones arrive.
//!
//! Worst-case memory footprint: 10k × 20 × ~64 bytes ≈ 12 MB. Bounded.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

/// Composite key identifying a beacon candidate: which local process,
/// which remote endpoint. We use the local executable path (not just PID)
/// so that a process restart doesn't reset the beacon tracking — e.g. a
/// compromised service that gets OOM-killed and respawned continues to
/// beacon under the same key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BeaconKey {
    /// The absolute path of `/proc/<pid>/exe`, or `"unknown:<pid>"` as a
    /// fallback when we can't read the exe (e.g. permission denied, process
    /// exited between scan steps).
    pub local_exe: String,
    pub remote_ip: IpAddr,
    pub remote_port: u16,
}

/// Per-key statistics computed from the inter-arrival times of samples
/// in the current window. Returned by `BeaconHistory::analyze()` and
/// used by the detector to decide whether to emit a beacon event.
#[derive(Debug, Clone)]
pub struct BeaconStats {
    pub sample_count: usize,
    pub window_secs: f64,
    pub mean_interval_secs: f64,
    pub stddev_interval_secs: f64,
    /// Coefficient of variation: `stddev / mean`. Low values indicate
    /// periodic behavior.
    pub cov: f64,
}

impl BeaconStats {
    /// Is this a beacon match given the thresholds? Returns true if:
    /// - We have enough samples to be statistically meaningful
    /// - The CoV is below the threshold (= timing is periodic-ish)
    /// - The mean interval is in the beacon range (not too fast, not too slow)
    pub fn is_beacon(
        &self,
        cov_threshold: f64,
        min_samples: usize,
        min_interval_secs: f64,
        max_interval_secs: f64,
    ) -> bool {
        self.sample_count >= min_samples
            && self.cov < cov_threshold
            && self.mean_interval_secs >= min_interval_secs
            && self.mean_interval_secs <= max_interval_secs
    }
}

/// Time-series state for beacon detection. Tracks per-BeaconKey samples.
/// Cheap to clone (all fields are owned) for snapshotting.
///
/// Note: does NOT derive Serialize/Deserialize directly. serde_json can't
/// serialize maps with struct keys (BeaconKey is a struct) out of the box.
/// Instead, save() and load_or_default() convert to/from the private
/// `BeaconHistoryOnDisk` representation below, which uses Vec-of-tuples.
#[derive(Debug, Clone)]
pub struct BeaconHistory {
    /// Map from BeaconKey to deque of first-seen timestamps. Deque because
    /// we always push to the back and trim from the front.
    pub entries: HashMap<BeaconKey, VecDeque<DateTime<Utc>>>,
    /// Cap on total keys tracked.
    pub max_keys: usize,
    /// Cap on samples per key.
    pub max_samples_per_key: usize,
    /// Lookback window for CoV computation.
    pub window_secs: u64,
}

/// On-disk representation of BeaconHistory. Uses Vec-of-tuples instead of
/// HashMap so serde_json can serialize it cleanly (HashMap with struct keys
/// requires stringified keys, which is worse UX for hand-inspection).
#[derive(Debug, Serialize, Deserialize)]
struct BeaconHistoryOnDisk {
    entries: Vec<(BeaconKey, VecDeque<DateTime<Utc>>)>,
    max_keys: usize,
    max_samples_per_key: usize,
    window_secs: u64,
}

impl From<&BeaconHistory> for BeaconHistoryOnDisk {
    fn from(h: &BeaconHistory) -> Self {
        Self {
            entries: h
                .entries
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            max_keys: h.max_keys,
            max_samples_per_key: h.max_samples_per_key,
            window_secs: h.window_secs,
        }
    }
}

impl From<BeaconHistoryOnDisk> for BeaconHistory {
    fn from(d: BeaconHistoryOnDisk) -> Self {
        Self {
            entries: d.entries.into_iter().collect(),
            max_keys: d.max_keys,
            max_samples_per_key: d.max_samples_per_key,
            window_secs: d.window_secs,
        }
    }
}

impl BeaconHistory {
    pub fn new(max_keys: usize, max_samples_per_key: usize, window_secs: u64) -> Self {
        Self {
            entries: HashMap::new(),
            max_keys,
            max_samples_per_key,
            window_secs,
        }
    }

    /// Load from disk, or create a fresh empty history if the file doesn't
    /// exist or fails to parse. Never fails — a corrupted history is treated
    /// as "start fresh" because losing beacon state is better than crashing.
    pub fn load_or_default(
        path: &Path,
        max_keys: usize,
        max_samples_per_key: usize,
        window_secs: u64,
    ) -> Self {
        if !path.exists() {
            return Self::new(max_keys, max_samples_per_key, window_secs);
        }
        // nosemgrep: rust.actix.path-traversal.tainted-path.tainted-path
        match std::fs::read_to_string(path) {
            Ok(s) => match serde_json::from_str::<BeaconHistoryOnDisk>(&s) {
                Ok(on_disk) => {
                    let mut h: BeaconHistory = on_disk.into();
                    // Honor current config values even if on-disk had different
                    // caps (config may have changed between runs).
                    h.max_keys = max_keys;
                    h.max_samples_per_key = max_samples_per_key;
                    h.window_secs = window_secs;
                    info!(
                        path = %path.display(),
                        entries = h.entries.len(),
                        "Loaded beacon history from disk"
                    );
                    h
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        path = %path.display(),
                        "Beacon history file is corrupt; starting fresh"
                    );
                    Self::new(max_keys, max_samples_per_key, window_secs)
                }
            },
            Err(e) => {
                warn!(error = %e, "Failed to read beacon history, starting fresh");
                Self::new(max_keys, max_samples_per_key, window_secs)
            }
        }
    }

    /// Persist to disk via atomic temp+rename. Best-effort — failure is
    /// logged but does not propagate.
    pub fn save(&self, path: &Path) {
        let on_disk = BeaconHistoryOnDisk::from(self);
        let json = match serde_json::to_string(&on_disk) {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "Failed to serialize beacon history");
                return;
            }
        };
        if let Some(parent) = path.parent() {
            // nosemgrep: rust.actix.path-traversal.tainted-path.tainted-path
            let _ = std::fs::create_dir_all(parent);
        }
        let tmp = path.with_extension("json.tmp");
        // nosemgrep: rust.actix.path-traversal.tainted-path.tainted-path
        if let Err(e) = std::fs::write(&tmp, json) {
            warn!(error = %e, "Failed to write beacon history temp file");
            return;
        }
        // nosemgrep: rust.actix.path-traversal.tainted-path.tainted-path
        if let Err(e) = std::fs::rename(&tmp, path) {
            warn!(error = %e, "Failed to rename beacon history temp file");
            // nosemgrep: rust.actix.path-traversal.tainted-path.tainted-path
            let _ = std::fs::remove_file(&tmp);
        }
    }

    /// Record a "new connection seen" event for the given key at the
    /// current time. Trims old samples outside the window and enforces the
    /// memory caps.
    pub fn record_sample(&mut self, key: BeaconKey) {
        let now = Utc::now();
        let window = chrono::Duration::seconds(self.window_secs as i64);
        let cutoff = now - window;

        // Evict keys if we're at the cap (LRU by last sample).
        if self.entries.len() >= self.max_keys && !self.entries.contains_key(&key) {
            self.evict_oldest();
        }

        let deque = self.entries.entry(key).or_default();
        deque.push_back(now);
        // Trim old samples outside the window.
        while deque.front().is_some_and(|ts| *ts < cutoff) {
            deque.pop_front();
        }
        // Enforce per-key sample cap (drop oldest).
        while deque.len() > self.max_samples_per_key {
            deque.pop_front();
        }
    }

    /// Remove entries whose samples are all outside the current window.
    /// Called from the scan path to keep memory bounded between scans.
    pub fn prune_stale(&mut self) {
        let now = Utc::now();
        let window = chrono::Duration::seconds(self.window_secs as i64);
        let cutoff = now - window;
        self.entries.retain(|_k, deque| {
            while deque.front().is_some_and(|ts| *ts < cutoff) {
                deque.pop_front();
            }
            !deque.is_empty()
        });
    }

    /// Evict the single key with the oldest max-sample timestamp. Used
    /// when we hit max_keys and need to insert a new key.
    fn evict_oldest(&mut self) {
        let oldest_key = self
            .entries
            .iter()
            .min_by_key(|(_k, deque)| deque.back().copied().unwrap_or(DateTime::<Utc>::MIN_UTC))
            .map(|(k, _)| k.clone());
        if let Some(k) = oldest_key {
            self.entries.remove(&k);
        }
    }

    /// Compute stats for a key. Returns None if there are fewer than 2
    /// samples (inter-arrival requires at least 2 points).
    pub fn analyze(&self, key: &BeaconKey) -> Option<BeaconStats> {
        let deque = self.entries.get(key)?;
        let samples: Vec<DateTime<Utc>> = deque.iter().copied().collect();
        analyze_samples(&samples)
    }

    /// Iterate over all keys for scanning.
    pub fn keys(&self) -> impl Iterator<Item = &BeaconKey> {
        self.entries.keys()
    }

    /// Total distinct keys currently tracked. Exposed for metrics /
    /// debugging even though the scan loop doesn't call it directly.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the history has zero tracked keys. Exposed for tests and
    /// future metrics.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Compute CoV statistics from a sorted list of timestamps. Returns None
/// if fewer than 2 samples (we need at least 1 inter-arrival interval).
pub fn analyze_samples(samples: &[DateTime<Utc>]) -> Option<BeaconStats> {
    if samples.len() < 2 {
        return None;
    }

    // Compute inter-arrival intervals in seconds.
    let mut intervals: Vec<f64> = Vec::with_capacity(samples.len() - 1);
    for pair in samples.windows(2) {
        let delta = pair[1] - pair[0];
        intervals.push(delta.num_milliseconds() as f64 / 1000.0);
    }

    let n = intervals.len() as f64;
    let mean: f64 = intervals.iter().sum::<f64>() / n;

    // Standard deviation (population, not sample — we treat the observed
    // intervals as the full dataset).
    let variance: f64 = intervals.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n;
    let stddev = variance.sqrt();

    // Coefficient of variation. Guard against divide-by-zero (all intervals
    // identical and zero would mean all samples at the exact same time,
    // which is impossible in practice but defensive).
    let cov = if mean.abs() < 1e-9 {
        0.0
    } else {
        stddev / mean
    };

    let first = *samples.first().unwrap();
    let last = *samples.last().unwrap();
    let window_secs = (last - first).num_milliseconds() as f64 / 1000.0;

    Some(BeaconStats {
        sample_count: samples.len(),
        window_secs,
        mean_interval_secs: mean,
        stddev_interval_secs: stddev,
        cov,
    })
}

/// Build the beacon history file path from a data directory.
pub fn history_file_path(data_dir: &Path) -> PathBuf {
    data_dir.join("beacon_history.json")
}

/// Lookup a process's exe path via `/proc/<pid>/exe`. Returns a fallback
/// string on any failure so we don't lose the sample.
pub fn exe_path_for_pid(pid: u32) -> String {
    let proc_exe = format!("/proc/{}/exe", pid);
    // nosemgrep: rust.actix.path-traversal.tainted-path.tainted-path
    std::fs::read_link(&proc_exe)
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| format!("unknown:{}", pid))
}

/// Returns the default scan-tick duration used for "new connection" detection.
/// Currently hardcoded to 60s to match the daemon's scan interval. Exposed
/// as a function (rather than a const) in case future configs make it
/// dynamic.
#[allow(dead_code)]
pub fn default_tick_duration() -> Duration {
    Duration::from_secs(60)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tempfile::tempdir;

    fn make_key(ip: &str, port: u16) -> BeaconKey {
        BeaconKey {
            local_exe: "/usr/bin/test".into(),
            remote_ip: IpAddr::V4(ip.parse::<Ipv4Addr>().unwrap()),
            remote_port: port,
        }
    }

    fn timestamps_at_intervals(base: DateTime<Utc>, intervals_secs: &[i64]) -> Vec<DateTime<Utc>> {
        let mut out = vec![base];
        let mut cursor = base;
        for s in intervals_secs {
            cursor += chrono::Duration::seconds(*s);
            out.push(cursor);
        }
        out
    }

    #[test]
    fn test_analyze_samples_requires_two_points() {
        let now = Utc::now();
        assert!(analyze_samples(&[]).is_none());
        assert!(analyze_samples(&[now]).is_none());
    }

    #[test]
    fn test_analyze_samples_strict_periodic_has_zero_cov() {
        // 10 samples at exactly 60s intervals → CoV == 0.0
        let base = Utc::now();
        let samples = timestamps_at_intervals(base, &[60, 60, 60, 60, 60, 60, 60, 60, 60]);
        let stats = analyze_samples(&samples).unwrap();
        assert_eq!(stats.sample_count, 10);
        assert!((stats.mean_interval_secs - 60.0).abs() < 0.1);
        assert!(
            stats.cov < 0.01,
            "CoV should be ~0 for strict periodic, got {}",
            stats.cov
        );
    }

    #[test]
    fn test_analyze_samples_jittered_beacon_has_low_cov() {
        // 10 samples at ~120s intervals with +/- 5% jitter
        let base = Utc::now();
        // jitter pattern: 120, 125, 118, 122, 117, 124, 119, 123, 116
        let samples = timestamps_at_intervals(base, &[120, 125, 118, 122, 117, 124, 119, 123, 116]);
        let stats = analyze_samples(&samples).unwrap();
        assert!(
            stats.cov < 0.1,
            "Jittered beacon CoV should be < 0.1, got {}",
            stats.cov
        );
        assert!(
            stats.is_beacon(0.3, 4, 30.0, 900.0),
            "Jittered beacon should be classified as a beacon"
        );
    }

    #[test]
    fn test_analyze_samples_random_bursty_traffic_has_high_cov() {
        // Random intervals: 5s, 300s, 10s, 1s, 500s, 2s, 180s, 8s, 400s
        let base = Utc::now();
        let samples = timestamps_at_intervals(base, &[5, 300, 10, 1, 500, 2, 180, 8, 400]);
        let stats = analyze_samples(&samples).unwrap();
        assert!(
            stats.cov > 0.5,
            "Random traffic CoV should be > 0.5, got {}",
            stats.cov
        );
        assert!(
            !stats.is_beacon(0.3, 4, 30.0, 900.0),
            "Random traffic should NOT be classified as a beacon"
        );
    }

    #[test]
    fn test_is_beacon_requires_minimum_samples() {
        // 3 samples, perfect periodicity, but below min_samples=4
        let base = Utc::now();
        let samples = timestamps_at_intervals(base, &[60, 60]); // 3 total
        let stats = analyze_samples(&samples).unwrap();
        assert_eq!(stats.sample_count, 3);
        assert!(stats.cov < 0.01);
        assert!(
            !stats.is_beacon(0.3, 4, 30.0, 900.0),
            "Should fail min_samples check"
        );
    }

    #[test]
    fn test_is_beacon_rejects_too_fast_intervals() {
        // 1-second intervals → mean_interval = 1.0, below min_interval=30.0
        let base = Utc::now();
        let samples = timestamps_at_intervals(base, &[1, 1, 1, 1, 1]);
        let stats = analyze_samples(&samples).unwrap();
        assert!(!stats.is_beacon(0.3, 4, 30.0, 900.0));
    }

    #[test]
    fn test_is_beacon_rejects_too_slow_intervals() {
        // 2000-second intervals → above max_interval=900
        let base = Utc::now();
        let samples = timestamps_at_intervals(base, &[2000, 2000, 2000, 2000, 2000]);
        let stats = analyze_samples(&samples).unwrap();
        assert!(!stats.is_beacon(0.3, 4, 30.0, 900.0));
    }

    #[test]
    fn test_history_record_sample_basic() {
        let mut history = BeaconHistory::new(100, 20, 600);
        let key = make_key("1.2.3.4", 443);
        history.record_sample(key.clone());
        history.record_sample(key.clone());
        history.record_sample(key.clone());

        let deque = history.entries.get(&key).unwrap();
        assert_eq!(deque.len(), 3);
    }

    #[test]
    fn test_history_enforces_max_samples_per_key() {
        let mut history = BeaconHistory::new(100, 5, 3600);
        let key = make_key("1.2.3.4", 443);
        for _ in 0..10 {
            history.record_sample(key.clone());
        }
        let deque = history.entries.get(&key).unwrap();
        // Cap at 5 samples per key (oldest dropped)
        assert_eq!(deque.len(), 5);
    }

    #[test]
    fn test_history_enforces_max_keys() {
        let mut history = BeaconHistory::new(3, 20, 3600);
        for i in 0..5u8 {
            let key = make_key(&format!("1.2.3.{}", i), 443);
            history.record_sample(key);
        }
        // Cap at 3 keys
        assert!(history.len() <= 3);
    }

    #[test]
    fn test_history_prune_stale_removes_old_entries() {
        let mut history = BeaconHistory::new(100, 20, 10); // 10s window
        let key = make_key("1.2.3.4", 443);
        // Manually insert an old timestamp
        let old = Utc::now() - chrono::Duration::seconds(100);
        history
            .entries
            .insert(key.clone(), [old].into_iter().collect());

        history.prune_stale();
        assert!(history.entries.is_empty(), "Stale entry should be pruned");
    }

    #[test]
    fn test_history_persist_roundtrip() {
        let dir = tempdir().unwrap();
        let path = history_file_path(dir.path());

        let mut history = BeaconHistory::new(100, 20, 600);
        let key = make_key("1.2.3.4", 443);
        history.record_sample(key.clone());
        history.save(&path);

        let loaded = BeaconHistory::load_or_default(&path, 100, 20, 600);
        assert_eq!(loaded.len(), 1);
        assert!(loaded.entries.contains_key(&key));
    }

    #[test]
    fn test_history_load_missing_file_is_ok() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("does_not_exist.json");
        let history = BeaconHistory::load_or_default(&path, 100, 20, 600);
        assert!(history.is_empty());
    }

    #[test]
    fn test_history_load_corrupt_file_is_ok() {
        let dir = tempdir().unwrap();
        let path = history_file_path(dir.path());
        // nosemgrep: rust.actix.path-traversal.tainted-path.tainted-path
        std::fs::write(&path, "not valid json {").unwrap();
        let history = BeaconHistory::load_or_default(&path, 100, 20, 600);
        assert!(history.is_empty(), "Corrupt file should fall back to empty");
    }

    #[test]
    fn test_analyze_via_history() {
        let mut history = BeaconHistory::new(100, 20, 3600);
        let key = make_key("1.2.3.4", 443);
        // Record 10 samples at ~60s intervals in the past
        let base = Utc::now() - chrono::Duration::seconds(600);
        let deque: VecDeque<DateTime<Utc>> = (0..10)
            .map(|i| base + chrono::Duration::seconds(60 * i))
            .collect();
        history.entries.insert(key.clone(), deque);

        let stats = history.analyze(&key).unwrap();
        assert_eq!(stats.sample_count, 10);
        assert!((stats.mean_interval_secs - 60.0).abs() < 0.1);
        assert!(stats.cov < 0.01);
    }

    #[test]
    fn test_default_tick_duration_is_60s() {
        assert_eq!(default_tick_duration(), Duration::from_secs(60));
    }
}
