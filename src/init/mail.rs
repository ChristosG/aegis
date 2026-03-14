use std::io::{self, Write};
use std::path::Path;

use anyhow::{Context, Result};
use colored::Colorize;

use crate::config::schema::AegisConfig;

/// Prompt the user for input with an optional default value.
fn prompt(label: &str, default: &str) -> String {
    if default.is_empty() {
        print!("  {} ", label);
    } else {
        print!("  {} [{}]: ", label, default);
    }
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let input = input.trim().to_string();
    if input.is_empty() {
        default.to_string()
    } else {
        input
    }
}

/// Run the interactive SMTP mail configuration setup.
///
/// 1. Prompts for SMTP settings and credentials.
/// 2. Writes credentials to /etc/aegis/mail.env (mode 0600).
/// 3. Updates /etc/aegis/aegis.toml with the email alerting config.
pub fn run_init_mail(_config: &AegisConfig) -> Result<()> {
    println!(
        "\n{}",
        "============================================================".bold()
    );
    println!("{}", "  AEGIS EMAIL ALERT SETUP".bold().cyan());
    println!(
        "{}",
        "============================================================".bold()
    );

    let config_path = Path::new("/etc/aegis/aegis.toml");
    if !config_path.exists() {
        anyhow::bail!(
            "/etc/aegis/aegis.toml not found. Run `aegis init` first to create the config."
        );
    }

    println!("\n  Enter your SMTP settings below.\n");

    let smtp_host = prompt("SMTP host:", "smtp.gmail.com");
    let smtp_port_str = prompt("SMTP port:", "587");
    let smtp_port: u16 = smtp_port_str.parse().context("Invalid port number")?;
    let username = prompt("SMTP username (email):", "");
    let password = rpassword::prompt_password("  SMTP password (not echoed): ")
        .context("Failed to read password")?;
    let from = prompt("From address:", &username);
    let to_str = prompt("To address(es) (comma-separated):", "");
    let min_severity = prompt("Minimum severity for email alerts:", "high");

    let to_addrs: Vec<String> = to_str
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if to_addrs.is_empty() {
        anyhow::bail!("At least one recipient address is required.");
    }

    // --- Write credentials to /etc/aegis/mail.env ---
    let env_path = Path::new("/etc/aegis/mail.env");
    let env_content = format!(
        "AEGIS_SMTP_USERNAME={}\nAEGIS_SMTP_PASSWORD={}\n",
        username, password
    );

    std::fs::write(env_path, &env_content)
        .with_context(|| format!("Failed to write {}", env_path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(env_path, perms)
            .with_context(|| format!("Failed to set permissions on {}", env_path.display()))?;
    }

    println!(
        "\n    {} Credentials saved to {} (mode 0600)",
        "OK".green().bold(),
        env_path.display()
    );

    // --- Update aegis.toml with email settings ---
    let toml_str = std::fs::read_to_string(config_path)
        .with_context(|| format!("Failed to read {}", config_path.display()))?;

    let mut aegis_config: AegisConfig = toml::from_str(&toml_str)
        .with_context(|| format!("Failed to parse {}", config_path.display()))?;

    aegis_config.alerting.email.enabled = true;
    aegis_config.alerting.email.smtp_host = smtp_host;
    aegis_config.alerting.email.smtp_port = smtp_port;
    aegis_config.alerting.email.smtp_username = username.clone();
    // Do NOT store password in toml — it comes from env var via mail.env
    aegis_config.alerting.email.smtp_password = String::new();
    aegis_config.alerting.email.use_tls = true;
    aegis_config.alerting.email.from = from;
    aegis_config.alerting.email.to = to_addrs;
    aegis_config.alerting.email.min_severity = min_severity;

    let updated_toml =
        toml::to_string_pretty(&aegis_config).context("Failed to serialize updated config")?;
    std::fs::write(config_path, &updated_toml)
        .with_context(|| format!("Failed to write {}", config_path.display()))?;

    println!(
        "    {} Updated {}",
        "OK".green().bold(),
        config_path.display()
    );

    // --- Summary ---
    println!(
        "\n{}",
        "============================================================".bold()
    );
    println!("{}", "  EMAIL SETUP COMPLETE".bold().green());
    println!(
        "{}",
        "============================================================".bold()
    );
    println!(
        "    SMTP host      : {}:{}",
        aegis_config.alerting.email.smtp_host, aegis_config.alerting.email.smtp_port
    );
    println!(
        "    Username       : {}",
        aegis_config.alerting.email.smtp_username
    );
    println!("    From           : {}", aegis_config.alerting.email.from);
    println!(
        "    To             : {}",
        aegis_config.alerting.email.to.join(", ")
    );
    println!(
        "    Min severity   : {}",
        aegis_config.alerting.email.min_severity
    );
    println!("    Credentials    : {}", env_path.display());
    println!();
    println!("    To test, run:");
    println!("      sudo aegis scan --auto-respond");
    println!(
        "{}",
        "============================================================".bold()
    );

    Ok(())
}
