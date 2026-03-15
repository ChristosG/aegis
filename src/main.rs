use std::net::IpAddr;

use anyhow::{Context, Result};
use chrono::Utc;
use clap::Parser;
use tokio_util::sync::CancellationToken;
use tracing::info;
use tracing_subscriber::EnvFilter;

use aegis::cli::args::{Cli, Commands, WhitelistAction};
use aegis::cli::{output, report};
use aegis::config::defaults::{load_or_default, resolve_path};
use aegis::config::validate;
use aegis::core::engine::Engine;
use aegis::core::state::BlockEntry;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // -----------------------------------------------------------------------
    // Load mail credentials from env file (before config, so env vars are
    // available when AlertManager reads AEGIS_SMTP_PASSWORD).
    // -----------------------------------------------------------------------
    load_mail_env();

    // -----------------------------------------------------------------------
    // Load configuration
    // -----------------------------------------------------------------------
    let config = load_or_default(cli.config.as_ref()).context("Failed to load configuration")?;

    // -----------------------------------------------------------------------
    // Set up tracing subscriber
    // -----------------------------------------------------------------------
    let log_level = if cli.verbose {
        "debug"
    } else {
        config.general.log_level.as_str()
    };

    let filter = EnvFilter::try_new(log_level).unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_thread_ids(false)
        .compact()
        .init();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        log_level = log_level,
        "Aegis starting"
    );

    // -----------------------------------------------------------------------
    // Ensure data directory exists
    // -----------------------------------------------------------------------
    let data_dir = resolve_path(&config.general.data_dir);
    std::fs::create_dir_all(&data_dir)
        .with_context(|| format!("Failed to create data directory: {}", data_dir.display()))?;

    // -----------------------------------------------------------------------
    // Dispatch to subcommand handler
    // -----------------------------------------------------------------------
    match cli.command {
        Commands::Scan {
            network,
            processes,
            files,
            auth,
            web,
            intel,
            auto_respond,
        } => {
            cmd_scan(
                config,
                network,
                processes,
                files,
                auth,
                web,
                intel,
                auto_respond,
            )
            .await
        }
        Commands::Watch { foreground } => cmd_watch(config, foreground).await,
        Commands::Status => cmd_status(config).await,
        Commands::Threats => cmd_threats(config).await,
        Commands::Block { ip, duration } => cmd_block(config, &ip, &duration).await,
        Commands::Unblock { ip } => cmd_unblock(config, &ip).await,
        Commands::Baseline => cmd_baseline(config).await,
        Commands::Report { format, output } => cmd_report(config, &format, output.as_deref()).await,
        Commands::Check => cmd_check(config),
        Commands::Whitelist { action } => cmd_whitelist(config, action).await,
        Commands::Fi { on, off } => cmd_fi(config, on, off).await,
        Commands::Update { check, force } => cmd_update(config, check, force).await,
        Commands::InitMail => cmd_init_mail(config),
        Commands::Init {
            skip_sysctl,
            skip_baseline,
            skip_service,
            skip_firewall_cleanup,
            skip_fail2ban,
        } => cmd_init(
            config,
            skip_sysctl,
            skip_baseline,
            skip_service,
            skip_firewall_cleanup,
            skip_fail2ban,
        ),
    }
}

/// Load AEGIS_SMTP_* credentials from /etc/aegis/mail.env or ~/.aegis/mail.env.
fn load_mail_env() {
    let candidates = [
        std::path::PathBuf::from("/etc/aegis/mail.env"),
        dirs::home_dir()
            .map(|h| h.join(".aegis/mail.env"))
            .unwrap_or_default(),
    ];

    for path in &candidates {
        if path.as_os_str().is_empty() || !path.exists() {
            continue;
        }
        if let Ok(content) = std::fs::read_to_string(path) {
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if let Some((key, value)) = line.split_once('=') {
                    let key = key.trim();
                    let value = value.trim();
                    if key.starts_with("AEGIS_") {
                        // SAFETY: only setting env vars before any multi-threaded work
                        unsafe {
                            std::env::set_var(key, value);
                        }
                    }
                }
            }
        }
        break; // use first found
    }
}

// ---------------------------------------------------------------------------
// Command handlers
// ---------------------------------------------------------------------------

/// Run a one-shot security scan.
#[allow(clippy::too_many_arguments)]
async fn cmd_scan(
    config: aegis::config::schema::AegisConfig,
    network: bool,
    processes: bool,
    files: bool,
    auth: bool,
    web: bool,
    intel: bool,
    auto_respond: bool,
) -> Result<()> {
    let engine = Engine::new(config);

    // Build module filter from CLI flags.
    let filter = {
        let any_set = network || processes || files || auth || web || intel;
        if any_set {
            let mut modules = Vec::new();
            if network {
                modules.push("network".to_string());
            }
            if processes {
                modules.push("process".to_string());
            }
            if files {
                modules.push("file_integrity".to_string());
            }
            if auth {
                modules.push("auth".to_string());
            }
            if web {
                modules.push("web".to_string());
            }
            if intel {
                modules.push("threat_intel".to_string());
            }
            Some(modules)
        } else {
            None // Run all enabled modules.
        }
    };

    let threats = engine.run_scan(filter, auto_respond).await?;

    if threats.is_empty() {
        println!(
            "\n  {}",
            colored::Colorize::green(colored::Colorize::bold(
                "No threats detected. System appears secure."
            ))
        );
    }

    Ok(())
}

/// Start the daemon in watch mode.
async fn cmd_watch(config: aegis::config::schema::AegisConfig, foreground: bool) -> Result<()> {
    if !foreground {
        eprintln!(
            "Note: Aegis daemon mode currently runs in the foreground. \
             Use --foreground or run in a systemd unit / tmux session."
        );
    }

    let engine = Engine::new(config.clone());
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();

    // Handle SIGINT / SIGTERM for graceful shutdown.
    tokio::spawn(async move {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to listen for ctrl-c");
        info!("Received shutdown signal");
        cancel_clone.cancel();
    });

    // Spawn web dashboard if feature is enabled and configured.
    #[cfg(feature = "web-dashboard")]
    {
        if config.dashboard.enabled {
            let web_cancel = cancel.clone();
            let state = engine.state();
            let config_arc = std::sync::Arc::new(config.clone());
            let response_engine = engine.response_engine();
            let alert_manager = engine.alert_manager();
            let storage = engine.storage();
            let event_bus = engine.event_bus_clone();
            let dashboard_config = config.dashboard.clone();

            tokio::spawn(async move {
                if let Err(e) = aegis::web::server::start_server(
                    dashboard_config,
                    state,
                    config_arc,
                    response_engine,
                    alert_manager,
                    storage,
                    event_bus,
                    web_cancel,
                )
                .await
                {
                    tracing::error!(error = %e, "Web dashboard server failed");
                }
            });
        }
    }

    engine.run_daemon(cancel).await?;
    Ok(())
}

/// Display the current security posture.
async fn cmd_status(config: aegis::config::schema::AegisConfig) -> Result<()> {
    let data_dir = resolve_path(&config.general.data_dir);
    let storage = aegis::storage::Storage::new(&data_dir);

    // Load persisted threats into state so status reflects history.
    let engine = Engine::new(config);
    let state = engine.state();
    {
        let mut state_guard = state.write().await;
        match storage.load_threats() {
            Ok(threats) if !threats.is_empty() => {
                state_guard.add_threats(threats);
            }
            _ => {}
        }
        // Check if the daemon is actually running via systemd.
        state_guard.daemon_running = is_daemon_running();
    }
    let state_guard = state.read().await;
    output::print_status(&state_guard);
    Ok(())
}

/// Check if the aegis systemd service is active.
fn is_daemon_running() -> bool {
    std::process::Command::new("systemctl")
        .args(["is-active", "--quiet", "aegis"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// List active threat events.
async fn cmd_threats(config: aegis::config::schema::AegisConfig) -> Result<()> {
    let data_dir = resolve_path(&config.general.data_dir);
    let storage = aegis::storage::Storage::new(&data_dir);
    let threats = storage.load_threats().unwrap_or_default();

    output::print_banner();
    if threats.is_empty() {
        println!(
            "\n  {}",
            colored::Colorize::green(colored::Colorize::bold("No active threats."))
        );
    } else {
        output::print_threats_table(&threats);
    }

    Ok(())
}

/// Block an IP address manually.
async fn cmd_block(
    config: aegis::config::schema::AegisConfig,
    ip_str: &str,
    duration_str: &str,
) -> Result<()> {
    let ip: IpAddr = ip_str
        .parse()
        .with_context(|| format!("Invalid IP address: '{}'", ip_str))?;

    let duration = aegis::core::scheduler::Scheduler::parse_duration(duration_str)
        .with_context(|| format!("Invalid duration: '{}'", duration_str))?;

    let expires_at = if duration_str == "forever" {
        None
    } else {
        Some(Utc::now() + chrono::Duration::from_std(duration)?)
    };

    let engine = Engine::new(config);
    engine
        .cli_block_ip(BlockEntry {
            ip,
            reason: format!("Manual block via CLI (duration: {})", duration_str),
            blocked_at: Utc::now(),
            expires_at,
            auto: false,
        })
        .await?;

    println!(
        "  {} Blocked {} for {}",
        colored::Colorize::green("OK"),
        ip,
        duration_str
    );

    info!(ip = %ip, duration = duration_str, "IP blocked via CLI");
    Ok(())
}

/// Unblock an IP address manually.
async fn cmd_unblock(config: aegis::config::schema::AegisConfig, ip_str: &str) -> Result<()> {
    let ip: IpAddr = ip_str
        .parse()
        .with_context(|| format!("Invalid IP address: '{}'", ip_str))?;

    let engine = Engine::new(config);
    let removed = engine.cli_unblock_ip(&ip).await?;

    if removed {
        println!("  {} Unblocked {}", colored::Colorize::green("OK"), ip);
        info!(ip = %ip, "IP unblocked via CLI");
    } else {
        println!(
            "  {} IP {} was not in the block list",
            colored::Colorize::yellow("WARN"),
            ip
        );
    }

    Ok(())
}

/// Create or update the file integrity baseline.
async fn cmd_baseline(config: aegis::config::schema::AegisConfig) -> Result<()> {
    output::print_banner();
    println!("\n  Creating file integrity baseline...\n");

    let watch_paths = &config.file_integrity.watch_paths;
    let exclude_paths = &config.file_integrity.exclude_paths;
    let baseline_path = resolve_path(&config.file_integrity.baseline_path);

    for wp in watch_paths {
        let path = std::path::Path::new(wp);
        if !path.exists() {
            eprintln!("  Skipping non-existent path: {}", wp);
        } else {
            println!("  Scanning: {}", wp);
        }
    }

    let (baseline, file_count, error_count) =
        aegis::init::build_baseline_map(watch_paths, exclude_paths)?;

    // Ensure parent directory exists.
    if let Some(parent) = baseline_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let json = serde_json::to_string_pretty(&baseline)?;
    std::fs::write(&baseline_path, &json)
        .with_context(|| format!("Failed to write baseline to {}", baseline_path.display()))?;

    println!(
        "\n  Baseline created: {} files hashed ({} errors)",
        file_count, error_count
    );
    println!("  Saved to: {}", baseline_path.display());

    Ok(())
}

/// Generate a security report.
async fn cmd_report(
    config: aegis::config::schema::AegisConfig,
    format: &str,
    output: Option<&str>,
) -> Result<()> {
    let data_dir = resolve_path(&config.general.data_dir);
    let storage = aegis::storage::Storage::new(&data_dir);

    let engine = Engine::new(config);
    let state = engine.state();
    {
        let mut state_guard = state.write().await;
        match storage.load_threats() {
            Ok(threats) if !threats.is_empty() => {
                state_guard.add_threats(threats);
            }
            _ => {}
        }
    }
    let state_guard = state.read().await;

    match format {
        "html" => {
            let html = aegis::cli::report::generate_html_report(&state_guard)?;
            if let Some(path) = output {
                std::fs::write(path, &html)?;
                println!("  HTML report written to {}", path);
            } else {
                println!("{}", html);
            }
        }
        "pdf" => {
            let path = output.unwrap_or("aegis-report.pdf");
            aegis::cli::report_pdf::generate_pdf_report(&state_guard, path)?;
            println!("  PDF report written to {}", path);
        }
        _ => {
            // text format (default)
            let report_text = report::generate_report(&state_guard)?;
            if let Some(path) = output {
                std::fs::write(path, &report_text)?;
                println!("  Text report written to {}", path);
            } else {
                println!("{}", report_text);
            }
        }
    }

    Ok(())
}

/// Validate the configuration file.
fn cmd_check(config: aegis::config::schema::AegisConfig) -> Result<()> {
    use colored::Colorize;

    println!("\n  Aegis Configuration Validator\n");

    let result = validate::validate_config(&config);

    if result.errors.is_empty() && result.warnings.is_empty() {
        println!(
            "  {} Configuration is valid. No issues found.\n",
            "OK".green().bold()
        );
        return Ok(());
    }

    if !result.errors.is_empty() {
        println!("  {} ({}):", "ERRORS".red().bold(), result.errors.len());
        for err in &result.errors {
            println!("    {} {}", "✗".red(), err);
        }
        println!();
    }

    if !result.warnings.is_empty() {
        println!(
            "  {} ({}):",
            "WARNINGS".yellow().bold(),
            result.warnings.len()
        );
        for warn in &result.warnings {
            println!("    {} {}", "!".yellow(), warn);
        }
        println!();
    }

    if result.is_ok() {
        println!(
            "  {} Configuration is valid ({} warning(s)).\n",
            "OK".green().bold(),
            result.warnings.len()
        );
    } else {
        println!(
            "  {} Configuration has {} error(s). Please fix them before running Aegis.\n",
            "FAIL".red().bold(),
            result.errors.len()
        );
    }

    Ok(())
}

/// Manage the response whitelist.
async fn cmd_whitelist(
    config: aegis::config::schema::AegisConfig,
    action: WhitelistAction,
) -> Result<()> {
    use colored::Colorize;

    match action {
        WhitelistAction::List => {
            println!("\n  Whitelisted CIDR ranges:\n");
            if config.response.whitelist.is_empty() {
                println!("    (none)");
            } else {
                for (i, cidr) in config.response.whitelist.iter().enumerate() {
                    println!("    {}. {}", i + 1, cidr);
                }
            }
            println!();
        }
        WhitelistAction::Add { cidr } => {
            // Validate CIDR
            if cidr.parse::<ipnet::IpNet>().is_err() && cidr.parse::<std::net::IpAddr>().is_err() {
                anyhow::bail!("Invalid CIDR or IP address: '{}'", cidr);
            }

            if config.response.whitelist.contains(&cidr) {
                println!(
                    "  {} '{}' is already in the whitelist",
                    "WARN".yellow(),
                    cidr
                );
                return Ok(());
            }

            // Use toml_edit to preserve comments/formatting
            let config_path = aegis::config::defaults::find_config_path(None)
                .ok_or_else(|| anyhow::anyhow!("No config file found. Run 'aegis init' first."))?;
            let content = std::fs::read_to_string(&config_path)?;
            let mut doc = content
                .parse::<toml_edit::DocumentMut>()
                .context("Failed to parse config file for editing")?;

            // Ensure [response] and whitelist exist
            if !doc.contains_key("response") {
                doc["response"] = toml_edit::Item::Table(toml_edit::Table::new());
            }
            let response = doc["response"].as_table_mut().unwrap();
            if !response.contains_key("whitelist") {
                response["whitelist"] = toml_edit::value(toml_edit::Array::new());
            }
            let whitelist = response["whitelist"]
                .as_array_mut()
                .ok_or_else(|| anyhow::anyhow!("whitelist is not an array in config"))?;
            whitelist.push(cidr.as_str());

            std::fs::write(&config_path, doc.to_string())?;
            println!(
                "  {} Added '{}' to whitelist in {}",
                "OK".green(),
                cidr,
                config_path.display()
            );
        }
        WhitelistAction::Remove { cidr } => {
            let config_path = aegis::config::defaults::find_config_path(None)
                .ok_or_else(|| anyhow::anyhow!("No config file found. Run 'aegis init' first."))?;
            let content = std::fs::read_to_string(&config_path)?;
            let mut doc = content
                .parse::<toml_edit::DocumentMut>()
                .context("Failed to parse config file for editing")?;

            if let Some(response) = doc.get_mut("response").and_then(|r| r.as_table_mut()) {
                if let Some(whitelist) =
                    response.get_mut("whitelist").and_then(|w| w.as_array_mut())
                {
                    let before_len = whitelist.len();
                    whitelist.retain(|v| v.as_str() != Some(cidr.as_str()));
                    if whitelist.len() == before_len {
                        println!("  {} '{}' was not in the whitelist", "WARN".yellow(), cidr);
                        return Ok(());
                    }
                }
            }

            std::fs::write(&config_path, doc.to_string())?;
            println!(
                "  {} Removed '{}' from whitelist in {}",
                "OK".green(),
                cidr,
                config_path.display()
            );
        }
    }

    Ok(())
}

/// Enable or disable file integrity monitoring.
async fn cmd_fi(config: aegis::config::schema::AegisConfig, on: bool, off: bool) -> Result<()> {
    use colored::Colorize;

    if !on && !off {
        // Just show current status
        println!(
            "\n  File integrity is currently: {}\n",
            if config.file_integrity.enabled {
                "enabled".green().bold()
            } else {
                "disabled".yellow().bold()
            }
        );
        println!("  Usage: aegis fi --on | --off");
        return Ok(());
    }

    let enable = on;
    let config_path = aegis::config::defaults::find_config_path(None)
        .ok_or_else(|| anyhow::anyhow!("No config file found. Run 'aegis init' first."))?;
    let content = std::fs::read_to_string(&config_path)?;
    let mut doc = content
        .parse::<toml_edit::DocumentMut>()
        .context("Failed to parse config file for editing")?;

    if !doc.contains_key("file_integrity") {
        doc["file_integrity"] = toml_edit::Item::Table(toml_edit::Table::new());
    }
    doc["file_integrity"]["enabled"] = toml_edit::value(enable);
    std::fs::write(&config_path, doc.to_string())?;

    if enable {
        println!(
            "  {} File integrity enabled in {}",
            "OK".green(),
            config_path.display()
        );

        // Generate baseline if one doesn't exist
        let baseline_path = resolve_path(&config.file_integrity.baseline_path);
        if !baseline_path.exists() {
            println!("  Generating baseline (no existing baseline found)...\n");
            cmd_baseline(config.clone()).await?;
        }
    } else {
        println!(
            "  {} File integrity disabled in {}",
            "OK".green(),
            config_path.display()
        );
    }

    // Check if dashboard is running and try to notify it
    let token_path = &config.dashboard.token_file;
    let action = if enable { "on" } else { "off" };
    if let Ok(token) = std::fs::read_to_string(token_path) {
        let url = format!(
            "http://{}:{}/api/file-integrity/toggle?action={}&token={}",
            config.dashboard.bind,
            config.dashboard.port,
            action,
            token.trim()
        );
        // Best-effort: if dashboard is running, notify it
        if let Ok(resp) = reqwest::Client::new().post(&url).send().await {
            if resp.status().is_success() {
                println!("  Dashboard notified of config change.");
                return Ok(());
            }
        }
    }

    println!("  Restart aegis for changes to take effect: sudo systemctl restart aegis");
    Ok(())
}

/// Check for or perform a self-update.
async fn cmd_update(
    _config: aegis::config::schema::AegisConfig,
    check_only: bool,
    force: bool,
) -> Result<()> {
    aegis::update::run_update(check_only, force).await
}

/// Interactive SMTP mail configuration.
fn cmd_init_mail(config: aegis::config::schema::AegisConfig) -> Result<()> {
    aegis::init::mail::run_init_mail(&config)
}

/// Full system hardening init.
fn cmd_init(
    config: aegis::config::schema::AegisConfig,
    skip_sysctl: bool,
    skip_baseline: bool,
    skip_service: bool,
    skip_firewall_cleanup: bool,
    skip_fail2ban: bool,
) -> Result<()> {
    let flags = aegis::init::InitFlags {
        skip_sysctl,
        skip_baseline,
        skip_service,
        skip_firewall_cleanup,
        skip_fail2ban,
    };
    aegis::init::run_init(&config, &flags)
}
