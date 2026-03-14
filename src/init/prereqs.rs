use std::process::Command;

use anyhow::{bail, Result};
use colored::Colorize;

use crate::util::privileges::check_root;

/// Verify that Aegis is running as root and that required system tools are
/// present. Returns `Ok(())` on success; fatally bails if root or a required
/// tool is missing.
pub fn check_prerequisites() -> Result<()> {
    println!("\n  {}", "Phase 1: Prerequisites".bold());
    println!("  {}", "-".repeat(40).dimmed());

    // --- Root check (fatal) ---
    if !check_root() {
        bail!("aegis init must be run as root. Re-run with: sudo aegis init");
    }
    println!("    {} root privileges", "OK".green().bold());

    // --- Required tools ---
    for tool in &["iptables", "systemctl", "sysctl"] {
        if !tool_exists(tool) {
            bail!("{} is required but not found in PATH", tool);
        }
        println!("    {} {}", "OK".green().bold(), tool);
    }

    // --- Optional: fail2ban ---
    if tool_exists("fail2ban-client") {
        println!("    {} fail2ban-client", "OK".green().bold());
    } else {
        println!(
            "    {} fail2ban not found -- attempting install",
            "WARN".yellow().bold()
        );
        let install = Command::new("apt-get")
            .args(["install", "-y", "fail2ban"])
            .output();
        match install {
            Ok(output) if output.status.success() => {
                println!("    {} fail2ban installed", "INSTALLED".green().bold());
            }
            _ => {
                println!(
                    "    {} could not install fail2ban (skipping fail2ban phases)",
                    "WARN".yellow().bold()
                );
            }
        }
    }

    Ok(())
}

/// Returns `true` if the given tool can be found and executed with `--version`.
fn tool_exists(name: &str) -> bool {
    Command::new(name)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
