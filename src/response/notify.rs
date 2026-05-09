//! v2.6.2 desktop notification surface.
//!
//! When the response engine takes a destructive action (kill or block) with
//! `auto_responded=true`, Aegis surfaces a desktop notification via
//! `notify-send` (libnotify). The notification body lists the threat type,
//! target (pid+name or ip), action taken, and the threat ID — the latter is
//! the canonical correlation handle the user can grep `journalctl` /
//! `threats.jsonl` against.
//!
//! Background: incident `20260509004453373-1434` killed a benign Python
//! loopback test from Claude Code and the only signal the user got was
//! their shell silently dying. They had to dig through journalctl to find
//! the cause. A best-effort desktop notification closes that UX gap
//! without affecting headless deployments — failure to deliver is silently
//! swallowed.
//!
//! Implementation note: we shell out to `notify-send` instead of linking
//! `notify-rust` to avoid a transitive dbus/zbus dependency on a binary
//! that runs as root. The cost is one fork+exec per notification, paid
//! only on kill/block (typically <1/min). If `notify-send` is missing the
//! call returns Err and the caller logs a debug line — never an error.

use std::process::{Command, Stdio};
use std::time::Duration;

use crate::core::threat::ThreatEvent;

use super::ResponseAction;

/// Best-effort notification dispatch. Never panics, never returns Err
/// to the caller of `respond()` — at most logs at debug.
///
/// Returns `true` if the notification was successfully spawned. Returns
/// `false` if `notify-send` is unavailable, the spawn timed out, or the
/// underlying command returned a non-zero exit code.
pub fn notify_action_taken(event: &ThreatEvent, action: &ResponseAction) -> bool {
    // We only notify on the "loud" actions. Alerts/logs are already
    // surfaced through stdout / threats.jsonl.
    let notable = matches!(
        action,
        ResponseAction::Kill | ResponseAction::Block | ResponseAction::BlockAndKill
    );
    if !notable {
        return false;
    }

    let summary = format!("Aegis: {} {}", action, event.threat_type);
    let body = build_body(event, action);
    let urgency = match event.severity {
        crate::core::threat::ThreatSeverity::Critical => "critical",
        crate::core::threat::ThreatSeverity::High => "normal",
        _ => "low",
    };

    // notify-send is best-effort. We bound the spawn with a wall-clock
    // timeout via `wait_timeout`-style polling so a hung dbus session
    // can't stall the response engine. (We use a manual poll because the
    // stdlib doesn't ship `wait_timeout`.)
    let spawn = Command::new("notify-send")
        .arg("--app-name=aegis")
        .arg(format!("--urgency={}", urgency))
        .arg("--icon=security-high")
        .arg(format!("--category={}", event.threat_type))
        .arg(&summary)
        .arg(&body)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();

    let mut child = match spawn {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!(
                error = %e,
                "notify-send not available; skipping desktop notification"
            );
            return false;
        }
    };

    // Poll for completion up to ~2 seconds. notify-send normally returns
    // in milliseconds; this only matters for pathological dbus stalls.
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    tracing::debug!("notify-send timed out; killed child");
                    return false;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(e) => {
                tracing::debug!(error = %e, "notify-send wait failed");
                return false;
            }
        }
    }
}

/// Build the notification body. Pulls (pid, name) and (source_ip) from
/// the event details so the user gets enough context to identify the
/// target without consulting journalctl. Always ends with the threat ID
/// for journalctl correlation.
fn build_body(event: &ThreatEvent, action: &ResponseAction) -> String {
    let mut parts: Vec<String> = Vec::new();
    parts.push(format!("action: {}", action));

    // Process target
    let pid = event.details.get("pid").map(String::as_str);
    let name = event
        .details
        .get("name")
        .map(String::as_str)
        .or(event.target.as_deref());
    if let (Some(pid), Some(name)) = (pid, name) {
        parts.push(format!("target: {} (pid {})", name, pid));
    } else if let Some(name) = name {
        parts.push(format!("target: {}", name));
    } else if let Some(ip) = event.source_ip {
        parts.push(format!("target: {}", ip));
    }

    // Parent (helps the user spot dev-tool false positives even when not
    // in the allowlist)
    if let Some(parent) = event.details.get("parent_name") {
        parts.push(format!("parent: {}", parent));
    }

    parts.push(format!("id: {}", event.id));
    parts.join("\n")
}
