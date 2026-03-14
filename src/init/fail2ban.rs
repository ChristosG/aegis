use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};
use colored::Colorize;

const FILTER_PATH: &str = "/etc/fail2ban/filter.d/aegis-threat.conf";
const JAIL_PATH: &str = "/etc/fail2ban/jail.d/aegis-threat.conf";

const FILTER_CONTENT: &str = r#"[Definition]
# Matches source_ip from Aegis JSONL threat log entries
failregex = "source_ip":"<HOST>"
ignoreregex =
"#;

/// Install the aegis-threat fail2ban filter and jail.
///
/// - Only creates files that don't already exist (preserves existing configs).
/// - Reloads fail2ban if changes were made.
/// - Skips entirely if fail2ban is not installed.
///
/// `threats_log_path` should be the resolved absolute path to threats.jsonl.
pub fn install_fail2ban(threats_log_path: &Path) -> Result<String> {
    println!("\n  {}", "Phase 6: fail2ban Integration".bold());
    println!("  {}", "-".repeat(40).dimmed());

    // Skip entirely if fail2ban is not installed.
    if !fail2ban_available() {
        println!(
            "    {} fail2ban not installed (skipping)",
            "SKIP".blue().bold()
        );
        return Ok("skipped (fail2ban not installed)".to_string());
    }

    let mut changed = false;

    // --- Filter file ---
    let filter_path = Path::new(FILTER_PATH);
    if filter_path.exists() {
        println!(
            "    {} {} (already exists)",
            "SKIP".blue().bold(),
            FILTER_PATH
        );
    } else {
        if let Some(parent) = filter_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(filter_path, FILTER_CONTENT)
            .with_context(|| format!("Failed to write {}", FILTER_PATH))?;
        println!("    {} Wrote {}", "OK".green().bold(), FILTER_PATH);
        changed = true;
    }

    // --- Jail file ---
    let jail_path = Path::new(JAIL_PATH);
    if jail_path.exists() {
        println!(
            "    {} {} (already exists)",
            "SKIP".blue().bold(),
            JAIL_PATH
        );
    } else {
        let jail_content = format!(
            r#"[aegis-threat]
enabled = true
filter = aegis-threat
logpath = {}
maxretry = 1
findtime = 24h
bantime = 24h
action = iptables-allports[name=aegis, chain=INPUT]
"#,
            threats_log_path.display()
        );

        if let Some(parent) = jail_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(jail_path, &jail_content)
            .with_context(|| format!("Failed to write {}", JAIL_PATH))?;
        println!("    {} Wrote {}", "OK".green().bold(), JAIL_PATH);
        changed = true;
    }

    // --- Reload fail2ban if we wrote anything ---
    if changed {
        let reload = Command::new("fail2ban-client")
            .arg("reload")
            .output()
            .context("Failed to run fail2ban-client reload")?;
        if reload.status.success() {
            println!("    {} fail2ban reloaded", "OK".green().bold());
        } else {
            let stderr = String::from_utf8_lossy(&reload.stderr);
            println!(
                "    {} fail2ban-client reload: {}",
                "WARN".yellow().bold(),
                stderr.trim()
            );
        }
    }

    Ok("aegis-threat jail installed".to_string())
}

/// Check whether fail2ban-client is available.
fn fail2ban_available() -> bool {
    Command::new("fail2ban-client")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
