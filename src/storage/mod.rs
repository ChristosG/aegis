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

use crate::core::state::{AppState, BlockEntry, FileBaseline};
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

        debug!(event_id = %event.id, "Threat event appended to JSONL log");
        Ok(())
    }

    /// Append multiple threat events at once.
    pub fn append_threats(&self, events: &[ThreatEvent]) -> Result<()> {
        for event in events {
            self.append_threat(event)?;
        }
        Ok(())
    }

    /// Read all threat events from the JSONL threat log.
    pub fn load_threats(&self) -> Result<Vec<ThreatEvent>> {
        let path = self.data_dir.join("threats.jsonl");
        if !path.exists() {
            return Ok(Vec::new());
        }

        let contents = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read threats log: {}", path.display()))?;

        let mut events = Vec::new();
        for (line_num, line) in contents.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match serde_json::from_str::<ThreatEvent>(line) {
                Ok(event) => events.push(event),
                Err(e) => {
                    warn!(
                        line = line_num + 1,
                        error = %e,
                        "Skipping malformed line in threats log"
                    );
                }
            }
        }

        Ok(events)
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

        blocks.retain(|_ip, entry| entry.expires_at.map_or(true, |exp| now <= exp));

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
