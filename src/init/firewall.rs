use std::collections::HashSet;
use std::process::Command;

use anyhow::{Context, Result};
use colored::Colorize;

/// Clean up duplicate rules in the AEGIS_BLOCK iptables chain and audit the
/// INPUT chain policy.
///
/// Returns the number of duplicate rules removed.
pub fn cleanup_firewall() -> Result<usize> {
    println!("\n  {}", "Phase 5: Firewall Cleanup".bold());
    println!("  {}", "-".repeat(40).dimmed());

    let removed = dedup_aegis_block()?;
    audit_input_policy();

    Ok(removed)
}

/// Remove duplicate DROP rules from the AEGIS_BLOCK chain.
fn dedup_aegis_block() -> Result<usize> {
    // List all rules in AEGIS_BLOCK.
    let output = Command::new("iptables")
        .args(["-S", "AEGIS_BLOCK"])
        .output()
        .context("Failed to run iptables -S AEGIS_BLOCK")?;

    if !output.status.success() {
        // Chain may not exist yet; that's fine.
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("No chain") || stderr.contains("does not exist") {
            println!(
                "    {} AEGIS_BLOCK chain does not exist (nothing to clean)",
                "SKIP".blue().bold()
            );
            return Ok(0);
        }
        println!(
            "    {} iptables -S AEGIS_BLOCK: {}",
            "WARN".yellow().bold(),
            stderr.trim()
        );
        return Ok(0);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut seen_ips: HashSet<String> = HashSet::new();
    let mut duplicates_removed = 0usize;

    // Each line looks like: -A AEGIS_BLOCK -s x.x.x.x/32 -j DROP
    for line in stdout.lines() {
        let line = line.trim();
        if !line.starts_with("-A AEGIS_BLOCK") {
            continue;
        }

        // Extract the IP from the -s flag.
        let ip = match extract_ip_from_rule(line) {
            Some(ip) => ip,
            None => continue,
        };

        if seen_ips.contains(&ip) {
            // Duplicate -- delete one occurrence.
            let del = Command::new("iptables")
                .args(["-D", "AEGIS_BLOCK", "-s", &ip, "-j", "DROP"])
                .output();
            match del {
                Ok(o) if o.status.success() => {
                    duplicates_removed += 1;
                }
                Ok(o) => {
                    let stderr = String::from_utf8_lossy(&o.stderr);
                    println!(
                        "    {} Failed to remove duplicate for {}: {}",
                        "WARN".yellow().bold(),
                        ip,
                        stderr.trim()
                    );
                }
                Err(e) => {
                    println!(
                        "    {} Failed to run iptables -D for {}: {}",
                        "WARN".yellow().bold(),
                        ip,
                        e
                    );
                }
            }
        } else {
            seen_ips.insert(ip);
        }
    }

    if duplicates_removed > 0 {
        println!(
            "    {} Removed {} duplicate rules from AEGIS_BLOCK",
            "OK".green().bold(),
            duplicates_removed
        );
    } else {
        println!(
            "    {} No duplicate rules found in AEGIS_BLOCK",
            "OK".green().bold()
        );
    }

    Ok(duplicates_removed)
}

/// Extract the IP/CIDR from an iptables -S rule line.
/// Expected format: `-A AEGIS_BLOCK -s x.x.x.x/32 -j DROP`
fn extract_ip_from_rule(line: &str) -> Option<String> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    for i in 0..parts.len() {
        if parts[i] == "-s" {
            if let Some(ip) = parts.get(i + 1) {
                return Some(ip.to_string());
            }
        }
    }
    None
}

/// Check the INPUT chain default policy and warn if it's ACCEPT.
fn audit_input_policy() {
    let output = Command::new("iptables").args(["-S", "INPUT"]).output();

    if let Ok(output) = output {
        let stdout = String::from_utf8_lossy(&output.stdout);
        // The first line should be: -P INPUT ACCEPT or -P INPUT DROP
        for line in stdout.lines() {
            if line.starts_with("-P INPUT ACCEPT") {
                println!(
                    "    {} INPUT chain policy is ACCEPT (consider changing to DROP with explicit ALLOW rules)",
                    "WARN".yellow().bold()
                );
                return;
            }
        }
    }
}
