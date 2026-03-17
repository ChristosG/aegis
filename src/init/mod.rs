pub mod fail2ban;
pub mod firewall;
pub mod mail;
pub mod prereqs;
pub mod service;
pub mod sysctl;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use colored::Colorize;

use crate::config::defaults::{generate_default_toml, resolve_path};
use crate::config::schema::AegisConfig;
use crate::storage::Storage;

/// Skip flags passed from the CLI.
pub struct InitFlags {
    pub skip_sysctl: bool,
    pub skip_baseline: bool,
    pub skip_service: bool,
    pub skip_firewall_cleanup: bool,
    pub skip_fail2ban: bool,
    pub skip_dashboard: bool,
}

/// Summary of what each phase did, for the final report.
struct InitSummary {
    config_path: String,
    data_dir: String,
    sysctl: String,
    baseline: String,
    firewall: String,
    fail2ban: String,
    service: String,
    dashboard: String,
}

/// Run the full aegis init sequence.
pub fn run_init(config: &AegisConfig, flags: &InitFlags) -> Result<()> {
    println!(
        "\n{}",
        "============================================================".bold()
    );
    println!("{}", "  AEGIS SYSTEM HARDENING INIT".bold().cyan());
    println!(
        "{}",
        "============================================================".bold()
    );

    // Phase 1: Prerequisites
    prereqs::check_prerequisites()?;

    // Phase 2: Config & data directories
    let (config_path, data_dir) = setup_directories(config)?;

    // Track critical phase failures to gate the init marker.
    let mut critical_failed = false;

    // Phase 3: Kernel hardening
    let sysctl_status = if flags.skip_sysctl {
        println!(
            "\n  {} Phase 3: Kernel Hardening (--skip-sysctl)",
            "SKIP".blue().bold()
        );
        "skipped".to_string()
    } else {
        match sysctl::apply_sysctl_hardening() {
            Ok(s) => s,
            Err(e) => {
                println!(
                    "\n  {} Phase 3: Kernel Hardening failed: {}",
                    "FAIL".red().bold(),
                    e
                );
                critical_failed = true;
                format!("FAILED: {}", e)
            }
        }
    };

    // Phase 4: File integrity baseline
    let baseline_status = if flags.skip_baseline {
        println!(
            "\n  {} Phase 4: File Integrity Baseline (--skip-baseline)",
            "SKIP".blue().bold()
        );
        "skipped".to_string()
    } else if !config.file_integrity.enabled {
        // FI is disabled by default — ask the user if they want it
        println!("\n  {}", "Phase 4: File Integrity Baseline".bold());
        println!("  {}", "-".repeat(40).dimmed());
        println!(
            "    Enable file integrity monitoring? (scans /etc, /usr/bin, etc. for changes) [y/N] "
        );

        let mut answer = String::new();
        let enable_fi = if std::io::stdin().read_line(&mut answer).is_ok() {
            matches!(answer.trim(), "y" | "Y" | "yes" | "Yes" | "YES")
        } else {
            false
        };

        if enable_fi {
            // Update aegis.toml to enable FI
            if let Some(cfg_path) = crate::config::defaults::find_system_config_path() {
                if let Ok(content) = std::fs::read_to_string(&cfg_path) {
                    if let Ok(mut doc) = content.parse::<toml_edit::DocumentMut>() {
                        if !doc.contains_key("file_integrity") {
                            doc["file_integrity"] = toml_edit::Item::Table(toml_edit::Table::new());
                        }
                        doc["file_integrity"]["enabled"] = toml_edit::value(true);
                        let _ = std::fs::write(&cfg_path, doc.to_string());
                        println!(
                            "    {} File integrity enabled in {}",
                            "OK".green().bold(),
                            cfg_path.display()
                        );
                    }
                }
            }
            generate_baseline(config, &data_dir)?
        } else {
            println!(
                "    {} File integrity disabled. Enable later with: aegis fi --on",
                "SKIP".blue().bold()
            );
            "skipped (FI disabled)".to_string()
        }
    } else {
        generate_baseline(config, &data_dir)?
    };

    // Phase 5: Firewall cleanup
    let firewall_status = if flags.skip_firewall_cleanup {
        println!(
            "\n  {} Phase 5: Firewall Cleanup (--skip-firewall-cleanup)",
            "SKIP".blue().bold()
        );
        "skipped".to_string()
    } else {
        match firewall::cleanup_firewall() {
            Ok(removed) => {
                if removed > 0 {
                    format!("{} duplicate rules removed", removed)
                } else {
                    "clean (no duplicates)".to_string()
                }
            }
            Err(e) => {
                println!(
                    "\n  {} Phase 5: Firewall Cleanup failed: {}",
                    "FAIL".red().bold(),
                    e
                );
                critical_failed = true;
                format!("FAILED: {}", e)
            }
        }
    };

    // Phase 6: fail2ban
    let fail2ban_status = if flags.skip_fail2ban {
        println!(
            "\n  {} Phase 6: fail2ban (--skip-fail2ban)",
            "SKIP".blue().bold()
        );
        "skipped".to_string()
    } else {
        let threats_log = data_dir.join("threats.jsonl");
        fail2ban::install_fail2ban(&threats_log)?
    };

    // Phase 7: Systemd service
    let service_status = if flags.skip_service {
        println!(
            "\n  {} Phase 7: Systemd Service (--skip-service)",
            "SKIP".blue().bold()
        );
        "skipped".to_string()
    } else {
        match service::install_service() {
            Ok(s) => s,
            Err(e) => {
                println!(
                    "\n  {} Phase 7: Systemd Service failed: {}",
                    "FAIL".red().bold(),
                    e
                );
                critical_failed = true;
                format!("FAILED: {}", e)
            }
        }
    };

    // Phase 8: Dashboard setup
    let dashboard_status = if flags.skip_dashboard {
        println!(
            "\n  {} Phase 8: Web Dashboard (--skip-dashboard)",
            "SKIP".blue().bold()
        );
        "skipped".to_string()
    } else if config.dashboard.enabled {
        println!("\n  {}", "Phase 8: Web Dashboard".bold());
        println!("  {}", "-".repeat(40).dimmed());
        println!("    {} Already enabled in config", "OK".green().bold());
        "already enabled".to_string()
    } else {
        println!("\n  {}", "Phase 8: Web Dashboard".bold());
        println!("  {}", "-".repeat(40).dimmed());
        println!("    Enable the web dashboard? (accessible at http://127.0.0.1:9443) [y/N] ");

        let mut answer = String::new();
        let enable_dashboard = if std::io::stdin().read_line(&mut answer).is_ok() {
            matches!(answer.trim(), "y" | "Y" | "yes" | "Yes" | "YES")
        } else {
            false
        };

        if enable_dashboard {
            // Update aegis.toml to enable dashboard
            if let Some(cfg_path) = crate::config::defaults::find_system_config_path() {
                if let Ok(content) = std::fs::read_to_string(&cfg_path) {
                    if let Ok(mut doc) = content.parse::<toml_edit::DocumentMut>() {
                        if !doc.contains_key("dashboard") {
                            doc["dashboard"] = toml_edit::Item::Table(toml_edit::Table::new());
                        }
                        doc["dashboard"]["enabled"] = toml_edit::value(true);
                        let _ = std::fs::write(&cfg_path, doc.to_string());
                        println!(
                            "    {} Dashboard enabled in {}",
                            "OK".green().bold(),
                            cfg_path.display()
                        );
                    }
                }
            }

            // Generate API token now so the user can see it
            let token_file = &config.dashboard.token_file;
            let token_path = std::path::Path::new(token_file); // nosemgrep: rust.actix.path-traversal.tainted-path.tainted-path
            let token = if token_path.exists() {
                std::fs::read_to_string(token_path) // nosemgrep: rust.actix.path-traversal.tainted-path.tainted-path
                    .unwrap_or_default()
                    .trim()
                    .to_string()
            } else {
                // Generate a new token
                let mut bytes = [0u8; 32];
                use rand::RngCore;
                rand::thread_rng().fill_bytes(&mut bytes);
                let token = hex::encode(bytes);
                if let Some(parent) = token_path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let _ = std::fs::write(token_path, &token);
                // Set file permissions to 0600
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(
                        token_path,
                        std::fs::Permissions::from_mode(0o600),
                    );
                }
                println!(
                    "    {} Generated API token at {}",
                    "OK".green().bold(),
                    token_file
                );
                token
            };

            println!();
            println!(
                "    {}",
                "Dashboard will be available after starting the service:".dimmed()
            );
            let bind = &config.dashboard.bind;
            let is_localhost = matches!(bind.as_str(), "127.0.0.1" | "::1" | "localhost");
            println!("      URL:   http://{}:{}", bind, config.dashboard.port);
            if is_localhost {
                println!("    {}", "(no login needed for localhost)".dimmed());
            } else {
                println!("      Token: {}", token);
                println!(
                    "    {}",
                    "(token also stored in /etc/aegis/api.token)".dimmed()
                );
            }

            format!("enabled on port {}", config.dashboard.port)
        } else {
            println!(
                "    {} Dashboard disabled. Enable later in /etc/aegis/aegis.toml",
                "SKIP".blue().bold()
            );
            "skipped (disabled)".to_string()
        }
    };

    // Write init marker so dashboard/postinst can detect init has been run.
    // Only write if no critical phase (sysctl, firewall, service) failed.
    if critical_failed {
        println!(
            "\n    {} Init marker NOT written — one or more critical phases failed.",
            "WARN".yellow().bold()
        );
        println!(
            "    {}",
            "Re-run 'aegis init' after fixing the issues above.".dimmed()
        );
    } else {
        let marker = Path::new("/etc/aegis/.init_done");
        if let Err(e) = std::fs::write(marker, "1") {
            println!("    {} Could not write init marker: {}", "WARN".yellow(), e);
        }
    }

    // Summary
    let summary = InitSummary {
        config_path,
        data_dir: data_dir.display().to_string(),
        sysctl: sysctl_status,
        baseline: baseline_status,
        firewall: firewall_status,
        fail2ban: fail2ban_status,
        service: service_status,
        dashboard: dashboard_status,
    };

    print_summary(&summary);
    Ok(())
}

/// Phase 2: Create /etc/aegis/ config dir and data directory.
fn setup_directories(config: &AegisConfig) -> Result<(String, PathBuf)> {
    println!("\n  {}", "Phase 2: Config & Data Directories".bold());
    println!("  {}", "-".repeat(40).dimmed());

    // --- Config directory: /etc/aegis/aegis.toml ---
    let etc_dir = Path::new("/etc/aegis");
    std::fs::create_dir_all(etc_dir).context("Failed to create /etc/aegis/")?;

    let config_path = etc_dir.join("aegis.toml");
    if config_path.exists() {
        println!(
            "    {} {} (already exists, not overwriting)",
            "SKIP".blue().bold(),
            config_path.display()
        );
    } else {
        let toml_content = generate_default_toml();
        std::fs::write(&config_path, toml_content)
            .with_context(|| format!("Failed to write {}", config_path.display()))?;
        println!(
            "    {} Created {}",
            "OK".green().bold(),
            config_path.display()
        );
    }

    // --- Data directory ---
    let data_dir = resolve_path(&config.general.data_dir);
    let storage = Storage::new(&data_dir);
    storage
        .init()
        .context("Failed to initialise data directory")?;
    println!(
        "    {} Data directory: {}",
        "OK".green().bold(),
        data_dir.display()
    );

    // Quarantine subdirectory.
    let quarantine_dir = data_dir.join("quarantine");
    std::fs::create_dir_all(&quarantine_dir)
        .with_context(|| format!("Failed to create {}", quarantine_dir.display()))?;
    println!(
        "    {} Quarantine directory: {}",
        "OK".green().bold(),
        quarantine_dir.display()
    );

    Ok((config_path.display().to_string(), data_dir))
}

/// Phase 4: Generate a file integrity baseline.
///
/// This is the shared baseline generation logic used by both `aegis init` and
/// `aegis baseline`. The walk+hash loop that previously lived exclusively in
/// `cmd_baseline()` is factored out here so both call sites can reuse it.
///
/// If a baseline already exists in the data directory, this prints SKIP and
/// suggests running `aegis baseline` to regenerate.
fn generate_baseline(config: &AegisConfig, data_dir: &Path) -> Result<String> {
    println!("\n  {}", "Phase 4: File Integrity Baseline".bold());
    println!("  {}", "-".repeat(40).dimmed());

    let storage = Storage::new(data_dir);

    // Skip if baseline already exists.
    if let Ok(Some(_)) = storage.load_baseline() {
        println!(
            "    {} Baseline already exists (run `aegis baseline` to regenerate)",
            "SKIP".blue().bold()
        );
        return Ok("skipped (already exists)".to_string());
    }

    let watch_paths = &config.file_integrity.watch_paths;
    let exclude_paths = &config.file_integrity.exclude_paths;

    let (baseline, file_count, error_count) = build_baseline_map(watch_paths, exclude_paths)?;

    storage
        .save_baseline(&baseline)
        .context("Failed to save baseline")?;

    let status = format!("{} files hashed", file_count);
    if error_count > 0 {
        println!(
            "    {} {} ({} errors)",
            "OK".green().bold(),
            status,
            error_count
        );
    } else {
        println!("    {} {}", "OK".green().bold(), status);
    }

    Ok(status)
}

/// Walk configured paths and build a baseline hash map.
///
/// This is the public shared helper that both `aegis init` and `cmd_baseline()`
/// can use to generate a baseline.
pub fn build_baseline_map(
    watch_paths: &[String],
    exclude_paths: &[String],
) -> Result<(HashMap<PathBuf, String>, u64, u64)> {
    let mut baseline = HashMap::new();
    let mut file_count = 0u64;
    let mut error_count = 0u64;

    for watch_path in watch_paths {
        let path = Path::new(watch_path); // nosemgrep: rust.actix.path-traversal.tainted-path.tainted-path
        if !path.exists() {
            continue;
        }

        if path.is_file() {
            match crate::util::hash::sha256_file(path) {
                Ok(hash) => {
                    baseline.insert(path.to_path_buf(), hash);
                    file_count += 1;
                }
                Err(_) => {
                    error_count += 1;
                }
            }
        } else if path.is_dir() {
            for entry in walkdir(path, exclude_paths) {
                match crate::util::hash::sha256_file(&entry) {
                    Ok(hash) => {
                        baseline.insert(entry, hash);
                        file_count += 1;
                    }
                    Err(_) => {
                        error_count += 1;
                    }
                }
            }
        }
    }

    Ok((baseline, file_count, error_count))
}

/// Recursively walk a directory, yielding file paths not in the exclusion list.
/// Never follows symlinks.
pub fn walkdir(root: &Path, excludes: &[String]) -> Vec<PathBuf> {
    let mut files = Vec::new();

    fn walk_inner(dir: &Path, excludes: &[String], files: &mut Vec<PathBuf>) {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let path_str = path.to_string_lossy();

            if excludes.iter().any(|ex| path_str.starts_with(ex.as_str())) {
                continue;
            }

            if path.is_symlink() {
                continue;
            }

            if path.is_file() {
                files.push(path);
            } else if path.is_dir() {
                walk_inner(&path, excludes, files);
            }
        }
    }

    walk_inner(root, excludes, &mut files);
    files
}

/// Print the final summary report.
fn print_summary(summary: &InitSummary) {
    println!(
        "\n{}",
        "============================================================".bold()
    );
    println!("{}", "  AEGIS INIT COMPLETE".bold().green());
    println!(
        "{}",
        "============================================================".bold()
    );
    println!("    Config       : {}", summary.config_path);
    println!("    Data dir     : {}", summary.data_dir);
    println!("    Sysctl       : {}", summary.sysctl);
    println!("    Baseline     : {}", summary.baseline);
    println!("    Firewall     : {}", summary.firewall);
    println!("    fail2ban     : {}", summary.fail2ban);
    println!("    Service      : {}", summary.service);
    println!("    Dashboard    : {}", summary.dashboard);
    println!();
    println!("    Next steps:");
    println!("      1. Review /etc/aegis/aegis.toml");
    println!("      2. Start the daemon:  sudo systemctl start aegis");
    println!("      3. First scan:        sudo aegis scan --auto-respond");
    println!(
        "{}",
        "============================================================".bold()
    );
}
