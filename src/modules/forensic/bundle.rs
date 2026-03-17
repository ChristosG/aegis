use std::fs;
use std::path::Path;

use anyhow::Result;
use serde_json::json;

use crate::core::threat::ThreatEvent;

/// Write metadata about the triggering threat event to the snapshot directory.
pub fn write_metadata(snapshot_dir: &Path, trigger: &ThreatEvent) -> Result<()> {
    let metadata = json!({
        "trigger": {
            "id": trigger.id,
            "threat_type": trigger.threat_type,
            "severity": trigger.severity,
            "description": trigger.description,
            "source_ip": trigger.source_ip,
            "target": trigger.target,
            "details": trigger.details,
            "timestamp": trigger.timestamp.to_rfc3339(),
        },
        "snapshot": {
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "hostname": hostname(),
            "kernel": kernel_version(),
        }
    });

    fs::write(
        snapshot_dir.join("metadata.json"),
        serde_json::to_string_pretty(&metadata)?,
    )?;

    Ok(())
}

fn hostname() -> String {
    fs::read_to_string("/etc/hostname")
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn kernel_version() -> String {
    fs::read_to_string("/proc/version")
        .unwrap_or_default()
        .trim()
        .to_string()
}
