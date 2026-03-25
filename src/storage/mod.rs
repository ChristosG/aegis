use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write as IoWrite;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::core::state::{AppState, BlockEntry, FileBaseline, StrikeHistory};
use crate::core::threat::ThreatEvent;

// ---------------------------------------------------------------------------
// Seen-threats deduplication
// ---------------------------------------------------------------------------

/// A record of a previously seen threat fingerprint, used for cross-run dedup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeenEntry {
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub count: u64,
    pub responded: bool,
}

/// Map from threat fingerprint string to its seen-entry metadata.
pub type SeenThreats = HashMap<String, SeenEntry>;

/// Persistence layer for Aegis state (baselines, threat history, blocked IPs).
pub struct Storage {
    data_dir: PathBuf,
}

impl Storage {
    pub fn new(data_dir: impl Into<PathBuf>) -> Self {
        Self {
            data_dir: data_dir.into(),
        }
    }

    /// Ensure the data directory and subdirectories exist.
    pub fn init(&self) -> Result<()> {
        fs::create_dir_all(&self.data_dir)
            .with_context(|| format!("Failed to create data dir: {}", self.data_dir.display()))?;
        fs::create_dir_all(self.data_dir.join("feeds"))?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Full state persistence (JSON)
    // -----------------------------------------------------------------------

    /// Save AppState to a JSON file in the data directory.
    pub fn save_state(&self, state: &AppState) -> Result<()> {
        let path = self.data_dir.join("state.json");
        let json = serde_json::to_string_pretty(state)?;
        fs::write(&path, json)
            .with_context(|| format!("Failed to write state: {}", path.display()))?;
        set_permissions_0600(&path);
        Ok(())
    }

    /// Load AppState from the data directory, returning default if not found.
    pub fn load_state(&self) -> Result<AppState> {
        let path = self.data_dir.join("state.json");
        if path.exists() {
            let json = fs::read_to_string(&path)?;
            let state: AppState = serde_json::from_str(&json)?;
            Ok(state)
        } else {
            Ok(AppState::new())
        }
    }

    /// Return the path to the data directory.
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    // -----------------------------------------------------------------------
    // Threat log (append-only JSONL)
    // -----------------------------------------------------------------------

    /// Maximum size of threats.jsonl before rotation (10 MB).
    const MAX_LOG_SIZE: u64 = 10 * 1024 * 1024;
    /// Number of rotated log files to keep.
    const MAX_LOG_FILES: usize = 3;

    /// Append a single threat event as a JSON line to `threats.jsonl`.
    /// Automatically rotates the file when it exceeds 10 MB.
    pub fn append_threat(&self, event: &ThreatEvent) -> Result<()> {
        let path = self.data_dir.join("threats.jsonl");

        // Create parent dirs if needed (should already exist from init, but be
        // defensive).
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Rotate if the file exceeds the size limit.
        self.rotate_log_if_needed(&path)?;

        let json_line = serde_json::to_string(event).context("Failed to serialize threat event")?;

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("Failed to open threats log: {}", path.display()))?;

        set_permissions_0600(&path);

        writeln!(file, "{}", json_line)
            .with_context(|| format!("Failed to write to threats log: {}", path.display()))?;

        // Flush to disk so a crash/kill doesn't lose buffered events.
        file.sync_data()
            .with_context(|| format!("Failed to sync threats log: {}", path.display()))?;

        debug!(event_id = %event.id, "Threat event appended to JSONL log");
        Ok(())
    }

    /// Append multiple threat events at once, using a single file open and sync.
    pub fn append_threats(&self, events: &[ThreatEvent]) -> Result<()> {
        if events.is_empty() {
            return Ok(());
        }

        let path = self.data_dir.join("threats.jsonl");
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        self.rotate_log_if_needed(&path)?;

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("Failed to open threats log: {}", path.display()))?;

        set_permissions_0600(&path);

        for event in events {
            let json_line =
                serde_json::to_string(event).context("Failed to serialize threat event")?;
            writeln!(file, "{}", json_line)
                .with_context(|| format!("Failed to write to threats log: {}", path.display()))?;
        }

        // Single sync for the entire batch.
        file.sync_data()
            .with_context(|| format!("Failed to sync threats log: {}", path.display()))?;

        debug!(
            count = events.len(),
            "Batch-appended threat events to JSONL log"
        );
        Ok(())
    }

    /// Read threat events from the JSONL threat log, keeping only the most
    /// recent entries (bounded by MAX_LOAD_THREATS) to avoid loading a
    /// multi-megabyte file entirely into memory.
    const MAX_LOAD_THREATS: usize = 1000;

    pub fn load_threats(&self) -> Result<Vec<ThreatEvent>> {
        use std::collections::VecDeque;
        use std::io::{BufRead, BufReader};

        let path = self.data_dir.join("threats.jsonl");
        if !path.exists() {
            return Ok(Vec::new());
        }

        let file = fs::File::open(&path)
            .with_context(|| format!("Failed to open threats log: {}", path.display()))?;
        let reader = BufReader::new(file);

        // Ring buffer: only keep the last MAX_LOAD_THREATS events so we never
        // hold the entire (potentially 10 MB) file in memory.
        let mut ring = VecDeque::with_capacity(Self::MAX_LOAD_THREATS + 1);
        for (line_num, line_result) in reader.lines().enumerate() {
            let line = match line_result {
                Ok(l) => l,
                Err(e) => {
                    warn!(line = line_num + 1, error = %e, "IO error reading threats log line");
                    continue;
                }
            };
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            match serde_json::from_str::<ThreatEvent>(trimmed) {
                Ok(event) => {
                    if ring.len() == Self::MAX_LOAD_THREATS {
                        ring.pop_front();
                    }
                    ring.push_back(event);
                }
                Err(e) => {
                    warn!(
                        line = line_num + 1,
                        error = %e,
                        "Skipping malformed line in threats log"
                    );
                }
            }
        }

        Ok(ring.into())
    }

    // -----------------------------------------------------------------------
    // Log rotation
    // -----------------------------------------------------------------------

    /// Rotate threats.jsonl if it exceeds MAX_LOG_SIZE.
    /// Keeps up to MAX_LOG_FILES old files: threats.jsonl.1, .2, .3
    fn rotate_log_if_needed(&self, path: &Path) -> Result<()> {
        if !path.exists() {
            return Ok(());
        }

        let size = path.metadata().map(|m| m.len()).unwrap_or(0);
        if size < Self::MAX_LOG_SIZE {
            return Ok(());
        }

        info!(
            size_mb = size / (1024 * 1024),
            "Rotating threats log (exceeded {}MB limit)",
            Self::MAX_LOG_SIZE / (1024 * 1024)
        );

        // Shift existing rotated files: .3 -> delete, .2 -> .3, .1 -> .2
        for i in (1..Self::MAX_LOG_FILES).rev() {
            let from = path.with_extension(format!("jsonl.{}", i));
            let to = path.with_extension(format!("jsonl.{}", i + 1));
            if from.exists() {
                let _ = fs::rename(&from, &to);
            }
        }

        // Delete the oldest if it exceeds our keep count
        let oldest = path.with_extension(format!("jsonl.{}", Self::MAX_LOG_FILES + 1));
        if oldest.exists() {
            let _ = fs::remove_file(&oldest);
        }

        // Move current -> .1
        let rotated = path.with_extension("jsonl.1");
        fs::rename(path, &rotated)
            .with_context(|| format!("Failed to rotate {}", path.display()))?;

        info!("Threats log rotated successfully");
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Block list persistence (JSON)
    // -----------------------------------------------------------------------

    /// Path to the block list file.
    fn block_list_path(&self) -> PathBuf {
        self.data_dir.join("block_list.json")
    }

    /// Save the current set of blocked IPs to disk.
    pub fn save_block_list(&self, blocked_ips: &HashMap<IpAddr, BlockEntry>) -> Result<()> {
        let path = self.block_list_path();
        let entries: Vec<&BlockEntry> = blocked_ips.values().collect();
        let json =
            serde_json::to_string_pretty(&entries).context("Failed to serialize block list")?;

        fs::write(&path, json)
            .with_context(|| format!("Failed to write block list: {}", path.display()))?;

        set_permissions_0600(&path);
        debug!(count = entries.len(), "Block list saved");
        Ok(())
    }

    /// Load the block list from disk. Returns an empty map if the file does
    /// not exist.
    pub fn load_block_list(&self) -> Result<HashMap<IpAddr, BlockEntry>> {
        let path = self.block_list_path();
        if !path.exists() {
            return Ok(HashMap::new());
        }

        let json = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read block list: {}", path.display()))?;

        let entries: Vec<BlockEntry> = serde_json::from_str(&json)
            .with_context(|| format!("Failed to parse block list: {}", path.display()))?;

        let mut map = HashMap::new();
        for entry in entries {
            map.insert(entry.ip, entry);
        }

        info!(count = map.len(), "Block list loaded from disk");
        Ok(map)
    }

    /// Remove expired entries from the persisted block list. Returns the
    /// number of entries pruned.
    pub fn prune_expired_blocks(&self) -> Result<usize> {
        let mut blocks = self.load_block_list()?;
        let now = Utc::now();
        let before = blocks.len();

        blocks.retain(|_ip, entry| entry.expires_at.is_none_or(|exp| now <= exp));

        let pruned = before - blocks.len();
        if pruned > 0 {
            self.save_block_list(&blocks)?;
            info!(
                pruned = pruned,
                remaining = blocks.len(),
                "Pruned expired block entries"
            );
        }

        Ok(pruned)
    }

    // -----------------------------------------------------------------------
    // Seen-threats deduplication persistence
    // -----------------------------------------------------------------------

    /// Path to the seen-fingerprints file.
    fn seen_threats_path(&self) -> PathBuf {
        self.data_dir.join("seen_fingerprints.json")
    }

    /// Save the seen-threats map to disk.
    pub fn save_seen_threats(&self, seen: &SeenThreats) -> Result<()> {
        let path = self.seen_threats_path();
        let json =
            serde_json::to_string_pretty(seen).context("Failed to serialize seen threats")?;

        fs::write(&path, json)
            .with_context(|| format!("Failed to write seen threats: {}", path.display()))?;

        set_permissions_0600(&path);
        debug!(count = seen.len(), "Seen threats saved");
        Ok(())
    }

    /// Load the seen-threats map from disk. Returns an empty map if the file
    /// does not exist.
    pub fn load_seen_threats(&self) -> Result<SeenThreats> {
        let path = self.seen_threats_path();
        if !path.exists() {
            return Ok(HashMap::new());
        }

        let json = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read seen threats: {}", path.display()))?;

        let seen: SeenThreats = serde_json::from_str(&json)
            .with_context(|| format!("Failed to parse seen threats: {}", path.display()))?;

        debug!(count = seen.len(), "Seen threats loaded from disk");
        Ok(seen)
    }

    /// Remove entries older than `max_age` from the seen-threats map.
    pub fn prune_seen_threats(seen: &mut SeenThreats, max_age: Duration) {
        let cutoff =
            Utc::now() - chrono::Duration::from_std(max_age).unwrap_or(chrono::Duration::hours(24));
        let before = seen.len();
        seen.retain(|_, entry| entry.last_seen >= cutoff);
        let pruned = before - seen.len();
        if pruned > 0 {
            debug!(
                pruned = pruned,
                remaining = seen.len(),
                "Pruned expired seen-threat entries"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Strike history persistence
    // -----------------------------------------------------------------------

    /// Path to the strike history file.
    fn strike_history_path(&self) -> PathBuf {
        self.data_dir.join("strike_history.json")
    }

    /// Save the strike history to disk.
    pub fn save_strike_history(&self, history: &StrikeHistory) -> Result<()> {
        let path = self.strike_history_path();
        let json =
            serde_json::to_string_pretty(history).context("Failed to serialize strike history")?;

        fs::write(&path, json)
            .with_context(|| format!("Failed to write strike history: {}", path.display()))?;

        set_permissions_0600(&path);
        debug!(count = history.len(), "Strike history saved");
        Ok(())
    }

    /// Load the strike history from disk. Returns an empty map if the file
    /// does not exist.
    pub fn load_strike_history(&self) -> Result<StrikeHistory> {
        let path = self.strike_history_path();
        if !path.exists() {
            return Ok(HashMap::new());
        }

        let json = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read strike history: {}", path.display()))?;

        let history: StrikeHistory = serde_json::from_str(&json)
            .with_context(|| format!("Failed to parse strike history: {}", path.display()))?;

        info!(count = history.len(), "Strike history loaded from disk");
        Ok(history)
    }

    // -----------------------------------------------------------------------
    // Baseline storage
    // -----------------------------------------------------------------------

    /// Default path for the file integrity baseline.
    fn baseline_path(&self) -> PathBuf {
        self.data_dir.join("baseline.json")
    }

    /// Save a file integrity baseline to the data directory.
    pub fn save_baseline(&self, baseline: &FileBaseline) -> Result<()> {
        let path = self.baseline_path();

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let json =
            serde_json::to_string_pretty(baseline).context("Failed to serialize baseline")?;

        fs::write(&path, &json)
            .with_context(|| format!("Failed to write baseline: {}", path.display()))?;

        set_permissions_0600(&path);
        info!(
            files = baseline.len(),
            path = %path.display(),
            "Baseline saved"
        );
        Ok(())
    }

    /// Load a file integrity baseline from the data directory. Returns `None`
    /// if no baseline file exists.
    pub fn load_baseline(&self) -> Result<Option<FileBaseline>> {
        let path = self.baseline_path();
        if !path.exists() {
            return Ok(None);
        }

        let json = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read baseline: {}", path.display()))?;

        let baseline: FileBaseline = serde_json::from_str(&json)
            .with_context(|| format!("Failed to parse baseline: {}", path.display()))?;

        info!(
            files = baseline.len(),
            path = %path.display(),
            "Baseline loaded"
        );
        Ok(Some(baseline))
    }

    /// Load a baseline from a specific file path (used when the config
    /// specifies a custom baseline path).
    pub fn load_baseline_from(&self, path: &Path) -> Result<Option<FileBaseline>> {
        if !path.exists() {
            return Ok(None);
        }

        let json = fs::read_to_string(path)
            .with_context(|| format!("Failed to read baseline: {}", path.display()))?;

        let baseline: FileBaseline = serde_json::from_str(&json)
            .with_context(|| format!("Failed to parse baseline: {}", path.display()))?;

        Ok(Some(baseline))
    }

    // -----------------------------------------------------------------------
    // Storage metrics and cleanup
    // -----------------------------------------------------------------------

    /// Collect storage metrics for all data files.
    pub fn storage_metrics(&self) -> StorageMetrics {
        let threats_path = self.data_dir.join("threats.jsonl");

        // Active threat log
        let active_log = file_info(&threats_path);

        // Rotated log files
        let mut rotated_logs = Vec::new();
        for i in 1..=Self::MAX_LOG_FILES {
            let path = threats_path.with_extension(format!("jsonl.{}", i));
            if path.exists() {
                rotated_logs.push(file_info(&path));
            }
        }

        let total_log_bytes = active_log.size + rotated_logs.iter().map(|f| f.size).sum::<u64>();

        // Other data files
        let block_list = file_info(&self.block_list_path());
        let seen_threats = file_info(&self.seen_threats_path());
        let baseline = file_info(&self.baseline_path());
        let state_file = file_info(&self.data_dir.join("state.json"));

        // Feeds directory total size
        let feeds_dir = self.data_dir.join("feeds");
        let feeds_size = dir_size(&feeds_dir);

        // Quarantine directory total size
        let quarantine_dir = self.data_dir.join("quarantine");
        let quarantine_size = dir_size(&quarantine_dir);

        let total_bytes = total_log_bytes
            + block_list.size
            + seen_threats.size
            + baseline.size
            + state_file.size
            + feeds_size
            + quarantine_size;

        // Oldest threat timestamp (read first line of oldest rotated log or active)
        let oldest_path = if let Some(last) = rotated_logs.last() {
            PathBuf::from(&last.path)
        } else {
            threats_path.clone()
        };
        let oldest_threat_age_days = oldest_event_age_days(&oldest_path);

        StorageMetrics {
            data_dir: self.data_dir.display().to_string(),
            active_log,
            rotated_logs,
            total_log_bytes,
            block_list,
            seen_threats,
            baseline,
            state_file,
            feeds_size,
            quarantine_size,
            total_bytes,
            oldest_threat_age_days,
            max_log_size: Self::MAX_LOG_SIZE,
            max_log_files: Self::MAX_LOG_FILES,
        }
    }

    /// Purge rotated threat logs and clear the dedup cache.
    /// Returns the number of bytes freed.
    pub fn cleanup_storage(&self) -> Result<u64> {
        let threats_path = self.data_dir.join("threats.jsonl");
        let mut freed = 0u64;

        // Remove rotated log files
        for i in 1..=Self::MAX_LOG_FILES + 1 {
            let path = threats_path.with_extension(format!("jsonl.{}", i));
            if path.exists() {
                let size = path.metadata().map(|m| m.len()).unwrap_or(0);
                if let Err(e) = fs::remove_file(&path) {
                    warn!(path = %path.display(), error = %e, "Failed to remove rotated log");
                } else {
                    freed += size;
                    info!(path = %path.display(), "Removed rotated threat log");
                }
            }
        }

        // Clear seen-fingerprints (dedup cache — safe to clear, just resets dedup)
        let seen_path = self.seen_threats_path();
        if seen_path.exists() {
            let size = seen_path.metadata().map(|m| m.len()).unwrap_or(0);
            if let Err(e) = fs::remove_file(&seen_path) {
                warn!(error = %e, "Failed to remove seen-fingerprints");
            } else {
                freed += size;
                info!("Cleared seen-fingerprints dedup cache");
            }
        }

        info!(freed_bytes = freed, "Storage cleanup complete");
        Ok(freed)
    }
}

/// Metrics about Aegis data stored on disk.
#[derive(Debug, Clone, Serialize)]
pub struct StorageMetrics {
    pub data_dir: String,
    pub active_log: FileInfo,
    pub rotated_logs: Vec<FileInfo>,
    pub total_log_bytes: u64,
    pub block_list: FileInfo,
    pub seen_threats: FileInfo,
    pub baseline: FileInfo,
    pub state_file: FileInfo,
    pub feeds_size: u64,
    pub quarantine_size: u64,
    pub total_bytes: u64,
    pub oldest_threat_age_days: Option<u64>,
    pub max_log_size: u64,
    pub max_log_files: usize,
}

/// Info about a single data file.
#[derive(Debug, Clone, Serialize)]
pub struct FileInfo {
    pub path: String,
    pub size: u64,
    pub exists: bool,
}

/// Get size and existence info for a file.
fn file_info(path: &Path) -> FileInfo {
    let (size, exists) = if path.exists() {
        (path.metadata().map(|m| m.len()).unwrap_or(0), true)
    } else {
        (0, false)
    };
    FileInfo {
        path: path.display().to_string(),
        size,
        exists,
    }
}

/// Recursively sum file sizes in a directory.
fn dir_size(path: &Path) -> u64 {
    if !path.is_dir() {
        return 0;
    }
    let mut total = 0u64;
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_file() {
                total += p.metadata().map(|m| m.len()).unwrap_or(0);
            } else if p.is_dir() {
                total += dir_size(&p);
            }
        }
    }
    total
}

/// Read the first line of a JSONL file to find the oldest threat timestamp.
/// Returns the age in days from now, or None if the file is empty/unreadable.
fn oldest_event_age_days(path: &Path) -> Option<u64> {
    use std::io::{BufRead, BufReader};

    let file = fs::File::open(path).ok()?;
    let reader = BufReader::new(file);
    for line in reader.lines() {
        let line = line.ok()?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(event) = serde_json::from_str::<ThreatEvent>(trimmed) {
            let age = Utc::now() - event.timestamp;
            return Some(age.num_days().max(0) as u64);
        }
        break;
    }
    None
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Best-effort attempt to set file permissions to 0600 on Unix systems.
fn set_permissions_0600(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        if let Err(e) = fs::set_permissions(path, perms) {
            warn!(
                path = %path.display(),
                error = %e,
                "Failed to set file permissions to 0600"
            );
        }
    }
}
