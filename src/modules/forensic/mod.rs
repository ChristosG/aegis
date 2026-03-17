pub mod bundle;
pub mod capture;

use std::fs;
use std::path::PathBuf;

use anyhow::Result;
use tracing::{info, warn};

use crate::config::defaults::resolve_path;
use crate::config::schema::ForensicConfig;
use crate::core::threat::{ThreatEvent, ThreatSeverity, ThreatType};

/// Forensic snapshot service. Subscribes to the event bus and captures
/// system state when matching threats are detected.
pub struct ForensicService {
    config: ForensicConfig,
    snapshot_dir: PathBuf,
}

impl ForensicService {
    pub fn new(config: ForensicConfig) -> Self {
        let snapshot_dir = resolve_path(&config.snapshot_dir);
        Self {
            config,
            snapshot_dir,
        }
    }

    /// Check if a threat event should trigger a forensic snapshot.
    pub fn should_snapshot(&self, threat: &ThreatEvent) -> bool {
        if !self.config.enabled {
            return false;
        }

        // Check severity threshold
        let min_severity = ThreatSeverity::from_str_loose(&self.config.trigger_severity)
            .unwrap_or(ThreatSeverity::Critical);
        if threat.severity < min_severity {
            return false;
        }

        // Check threat type match
        let threat_key = format!("{:?}", threat.threat_type).to_lowercase();
        // Convert from CamelCase to snake_case for matching
        let snake_key = camel_to_snake(&format!("{:?}", threat.threat_type));
        self.config
            .trigger_types
            .iter()
            .any(|t| t == &threat_key || t == &snake_key)
    }

    /// Capture a forensic snapshot for the given threat event.
    pub async fn capture_snapshot(&self, threat: &ThreatEvent) -> Result<ThreatEvent> {
        let timestamp = chrono::Utc::now().format("%Y%m%d%H%M%S");
        let threat_key = format!("{:?}", threat.threat_type).to_lowercase();
        let pid = threat.details.get("pid").cloned().unwrap_or_default();
        let dir_name = format!("{}-{}-{}", timestamp, threat_key, pid);
        let snapshot_path = self.snapshot_dir.join(&dir_name);

        fs::create_dir_all(&snapshot_path)?;

        info!(
            path = %snapshot_path.display(),
            threat_id = %threat.id,
            "Capturing forensic snapshot"
        );

        // Capture process info if PID is available
        if let Ok(pid_num) = pid.parse::<u32>() {
            capture::capture_process_info(pid_num, &snapshot_path)?;
        }

        // Capture network state
        capture::capture_network_state(&snapshot_path)?;

        // Capture process tree
        capture::capture_process_tree(&snapshot_path)?;

        // Bundle metadata
        bundle::write_metadata(&snapshot_path, threat)?;

        // Enforce snapshot limit
        self.enforce_retention()?;

        Ok(ThreatEvent::new(
            ThreatType::ForensicSnapshot,
            "forensic",
            format!("Forensic snapshot captured: {}", dir_name),
        )
        .with_detail("snapshot_path", snapshot_path.to_string_lossy().to_string())
        .with_detail("trigger_threat_id", &threat.id)
        .with_detail("trigger_type", threat_key))
    }

    fn enforce_retention(&self) -> Result<()> {
        if !self.snapshot_dir.exists() {
            return Ok(());
        }

        let mut snapshots: Vec<_> = fs::read_dir(&self.snapshot_dir)?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_dir())
            .collect();

        if snapshots.len() as u32 > self.config.max_snapshots {
            // Sort by creation time (oldest first)
            snapshots.sort_by_key(|e| {
                e.metadata()
                    .and_then(|m| m.created())
                    .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
            });

            let to_remove = snapshots.len() as u32 - self.config.max_snapshots;
            for entry in snapshots.iter().take(to_remove as usize) {
                if let Err(e) = fs::remove_dir_all(entry.path()) {
                    warn!(
                        path = %entry.path().display(),
                        error = %e,
                        "Failed to remove old forensic snapshot"
                    );
                }
            }
        }

        Ok(())
    }
}

fn camel_to_snake(s: &str) -> String {
    let mut result = String::new();
    for (i, c) in s.chars().enumerate() {
        if c.is_uppercase() && i > 0 {
            result.push('_');
        }
        result.push(c.to_lowercase().next().unwrap_or(c));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_camel_to_snake() {
        assert_eq!(camel_to_snake("ReverseShell"), "reverse_shell");
        assert_eq!(camel_to_snake("RootkitDetected"), "rootkit_detected");
        assert_eq!(camel_to_snake("C2Beacon"), "c2_beacon");
    }
}
