use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};
use colored::Colorize;

const SYSCTL_CONF_PATH: &str = "/etc/sysctl.d/99-aegis-hardening.conf";

const SYSCTL_PARAMS: &str = "\
# Aegis kernel hardening parameters
# Managed by: aegis init

net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_synack_retries = 2
net.core.somaxconn = 4096
net.ipv4.conf.all.log_martians = 1
kernel.randomize_va_space = 2
";

/// Number of hardening parameters applied.
pub const PARAM_COUNT: usize = 15;

/// Write kernel hardening sysctl parameters and apply them.
///
/// Idempotent: skips if the file already exists with identical content.
/// Returns a status message for the summary.
pub fn apply_sysctl_hardening() -> Result<String> {
    println!("\n  {}", "Phase 3: Kernel Hardening".bold());
    println!("  {}", "-".repeat(40).dimmed());

    let path = Path::new(SYSCTL_CONF_PATH);

    // Idempotency: skip if file already has identical content.
    if path.exists() {
        let existing = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read {}", SYSCTL_CONF_PATH))?;
        if existing == SYSCTL_PARAMS {
            println!(
                "    {} {} (already up to date)",
                "SKIP".blue().bold(),
                SYSCTL_CONF_PATH
            );
            return Ok(format!("{} parameters (already applied)", PARAM_COUNT));
        }
    }

    // Ensure parent directory exists.
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(path, SYSCTL_PARAMS)
        .with_context(|| format!("Failed to write {}", SYSCTL_CONF_PATH))?;
    println!("    {} Wrote {}", "OK".green().bold(), SYSCTL_CONF_PATH);

    // Apply all sysctl settings.
    let output = Command::new("sysctl")
        .arg("--system")
        .output()
        .context("Failed to run sysctl --system")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!(
            "    {} sysctl --system: {}",
            "WARN".yellow().bold(),
            stderr.trim()
        );
    } else {
        println!(
            "    {} Applied {} parameters via sysctl --system",
            "OK".green().bold(),
            PARAM_COUNT
        );
    }

    Ok(format!("{} parameters hardened", PARAM_COUNT))
}
