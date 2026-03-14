use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};
use colored::Colorize;

use crate::util::hash::sha256_file;

const SERVICE_CONTENT: &str = include_str!("../../aegis.service");
const INSTALL_BIN_PATH: &str = "/usr/local/bin/aegis";
const SERVICE_PATH: &str = "/etc/systemd/system/aegis.service";

/// Install the aegis binary and systemd service unit.
///
/// - Copies the current binary to /usr/local/bin/aegis (skips if hashes match).
/// - Writes the service unit to /etc/systemd/system/.
/// - Runs daemon-reload and enables the service.
/// - Does NOT start the service.
pub fn install_service() -> Result<String> {
    println!("\n  {}", "Phase 7: Systemd Service".bold());
    println!("  {}", "-".repeat(40).dimmed());

    // --- Install binary ---
    let current_exe =
        std::env::current_exe().context("Failed to determine current executable path")?;

    let install_path = Path::new(INSTALL_BIN_PATH);
    let mut binary_status = "installed";

    if install_path.exists() {
        // Compare hashes to avoid unnecessary copy.
        let current_hash = sha256_file(&current_exe).context("Failed to hash current binary")?;
        let installed_hash =
            sha256_file(install_path).context("Failed to hash installed binary")?;

        if current_hash == installed_hash {
            println!(
                "    {} {} (already up to date)",
                "SKIP".blue().bold(),
                INSTALL_BIN_PATH
            );
            binary_status = "up to date";
        } else {
            std::fs::copy(&current_exe, install_path)
                .with_context(|| format!("Failed to copy binary to {}", INSTALL_BIN_PATH))?;
            println!("    {} Updated {}", "OK".green().bold(), INSTALL_BIN_PATH);
            binary_status = "updated";
        }
    } else {
        // Ensure parent directory exists.
        if let Some(parent) = install_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(&current_exe, install_path)
            .with_context(|| format!("Failed to copy binary to {}", INSTALL_BIN_PATH))?;
        println!(
            "    {} Installed binary to {}",
            "OK".green().bold(),
            INSTALL_BIN_PATH
        );
    }

    // Make binary executable.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o755);
        std::fs::set_permissions(install_path, perms)
            .context("Failed to set binary permissions")?;
    }

    // --- Write service file ---
    let service_path = Path::new(SERVICE_PATH);
    if service_path.exists() {
        let existing = std::fs::read_to_string(service_path)
            .with_context(|| format!("Failed to read {}", SERVICE_PATH))?;
        if existing == SERVICE_CONTENT {
            println!(
                "    {} {} (already up to date)",
                "SKIP".blue().bold(),
                SERVICE_PATH
            );
        } else {
            std::fs::write(service_path, SERVICE_CONTENT)
                .with_context(|| format!("Failed to write {}", SERVICE_PATH))?;
            println!("    {} Updated {}", "OK".green().bold(), SERVICE_PATH);
        }
    } else {
        std::fs::write(service_path, SERVICE_CONTENT)
            .with_context(|| format!("Failed to write {}", SERVICE_PATH))?;
        println!("    {} Wrote {}", "OK".green().bold(), SERVICE_PATH);
    }

    // --- daemon-reload ---
    let reload = Command::new("systemctl")
        .arg("daemon-reload")
        .output()
        .context("Failed to run systemctl daemon-reload")?;
    if !reload.status.success() {
        let stderr = String::from_utf8_lossy(&reload.stderr);
        println!(
            "    {} systemctl daemon-reload: {}",
            "WARN".yellow().bold(),
            stderr.trim()
        );
    }

    // --- Enable service ---
    let enable = Command::new("systemctl")
        .args(["enable", "aegis.service"])
        .output()
        .context("Failed to run systemctl enable")?;
    if enable.status.success() {
        println!("    {} aegis.service enabled", "OK".green().bold());
    } else {
        let stderr = String::from_utf8_lossy(&enable.stderr);
        println!(
            "    {} systemctl enable: {}",
            "WARN".yellow().bold(),
            stderr.trim()
        );
    }

    println!(
        "    {} Service not started -- review config first, then run:",
        "NOTE".blue().bold()
    );
    println!("         sudo systemctl start aegis");

    Ok(format!("aegis.service enabled (binary {})", binary_status))
}
