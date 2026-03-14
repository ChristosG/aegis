use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write as IoWrite;
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use colored::Colorize;
use tracing::{error, info, warn};

use crate::config::schema::AlertingConfig;
use crate::core::scheduler::Scheduler;
use crate::core::threat::{ThreatEvent, ThreatSeverity};

/// The alerting subsystem handles notification delivery for threat events
/// (terminal output, JSONL log file, email, webhooks).
pub struct AlertManager {
    config: AlertingConfig,
    /// Tracks the last email send time per threat-type key for cooldown
    /// enforcement.
    email_cooldown: Mutex<HashMap<String, DateTime<Utc>>>,
}

impl AlertManager {
    pub fn new(config: AlertingConfig) -> Self {
        Self {
            config,
            email_cooldown: Mutex::new(HashMap::new()),
        }
    }

    /// Send an alert for the given threat event through all configured channels.
    pub async fn alert(&self, event: &ThreatEvent) -> Result<()> {
        if self.config.terminal {
            self.alert_terminal(event);
        }

        if let Err(e) = self.alert_log_file(event) {
            error!(error = %e, "Failed to write threat to log file");
        }

        if self.config.email.enabled {
            if let Err(e) = self.alert_email(event).await {
                error!(error = %e, "Email alert failed (non-blocking)");
            }
        }

        if self.config.webhook.enabled {
            if let Err(e) = self.alert_webhook(event).await {
                error!(error = %e, "Webhook alert failed (non-blocking)");
            }
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Terminal alerting
    // -----------------------------------------------------------------------

    fn alert_terminal(&self, event: &ThreatEvent) {
        let ts = event.timestamp.format("%H:%M:%S");

        let severity_str = match event.severity {
            ThreatSeverity::Info => format!("{}", "INFO".cyan()),
            ThreatSeverity::Low => format!("{}", "LOW".blue()),
            ThreatSeverity::Medium => format!("{}", "MEDIUM".yellow()),
            ThreatSeverity::High => format!("{}", "HIGH".red()),
            ThreatSeverity::Critical => format!("{}", "CRITICAL".red().bold()),
        };

        let threat_str = match event.severity {
            ThreatSeverity::Critical => format!("{}", event.threat_type.to_string().red().bold()),
            ThreatSeverity::High => format!("{}", event.threat_type.to_string().red()),
            ThreatSeverity::Medium => format!("{}", event.threat_type.to_string().yellow()),
            _ => event.threat_type.to_string(),
        };

        let desc_str = match event.severity {
            ThreatSeverity::Critical | ThreatSeverity::High => {
                format!("{}", event.description.as_str().red())
            }
            _ => event.description.clone(),
        };

        // Print to stderr so it doesn't interfere with stdout output.
        eprintln!("[{}] [{}] {} - {}", ts, severity_str, threat_str, desc_str);

        if let Some(ip) = event.source_ip {
            eprintln!("         Source IP: {}", ip);
        }
        if let Some(ref target) = event.target {
            eprintln!("         Target:    {}", target);
        }
    }

    // -----------------------------------------------------------------------
    // JSON log file
    // -----------------------------------------------------------------------

    fn alert_log_file(&self, event: &ThreatEvent) -> Result<()> {
        let log_path_str = shellexpand_tilde(&self.config.log_file);
        let log_path = Path::new(&log_path_str);

        // Ensure parent directories exist.
        if let Some(parent) = log_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create log directory: {}", parent.display()))?;
        }

        // Serialize the event as a single JSON line.
        let json_line =
            serde_json::to_string(event).context("Failed to serialize threat event to JSON")?;

        // Open in append mode, creating the file if necessary.
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
            .with_context(|| format!("Failed to open log file: {}", log_path.display()))?;

        // Set file permissions to 0600 (owner read/write only).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o600);
            let _ = fs::set_permissions(log_path, perms);
        }

        writeln!(file, "{}", json_line)
            .with_context(|| format!("Failed to write to log file: {}", log_path.display()))?;

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Email alerting (via lettre)
    // -----------------------------------------------------------------------

    async fn alert_email(&self, event: &ThreatEvent) -> Result<()> {
        let email_cfg = &self.config.email;

        // Check minimum severity.
        let min_severity =
            ThreatSeverity::from_str_loose(&email_cfg.min_severity).unwrap_or(ThreatSeverity::High);
        if event.severity < min_severity {
            return Ok(());
        }

        // Check cooldown per threat type.
        let cooldown_duration = Scheduler::parse_duration(&email_cfg.cooldown)
            .unwrap_or_else(|_| Duration::from_secs(300));
        let cooldown_chrono = chrono::Duration::from_std(cooldown_duration)
            .unwrap_or_else(|_| chrono::Duration::minutes(5));

        {
            let mut cooldowns = self.email_cooldown.lock().unwrap();
            let threat_key = format!("{:?}", event.threat_type);
            if let Some(last_sent) = cooldowns.get(&threat_key) {
                if Utc::now() - *last_sent < cooldown_chrono {
                    info!(
                        threat_type = %event.threat_type,
                        "Email cooldown active, skipping"
                    );
                    return Ok(());
                }
            }
            cooldowns.insert(threat_key, Utc::now());
        }

        // Build the email.
        let subject = format!(
            "{} [{}] {} detected",
            email_cfg.subject_prefix, event.severity, event.threat_type
        );

        let body = format!(
            "<html><body>\
             <h2>Aegis Security Alert</h2>\
             <table border='1' cellpadding='5' cellspacing='0'>\
             <tr><td><b>Event ID</b></td><td>{}</td></tr>\
             <tr><td><b>Threat Type</b></td><td>{}</td></tr>\
             <tr><td><b>Severity</b></td><td>{}</td></tr>\
             <tr><td><b>Source Module</b></td><td>{}</td></tr>\
             <tr><td><b>Description</b></td><td>{}</td></tr>\
             <tr><td><b>Source IP</b></td><td>{}</td></tr>\
             <tr><td><b>Target</b></td><td>{}</td></tr>\
             <tr><td><b>Timestamp</b></td><td>{}</td></tr>\
             <tr><td><b>Auto Responded</b></td><td>{}</td></tr>\
             </table>\
             <h3>Details</h3><pre>{}</pre>\
             </body></html>",
            event.id,
            event.threat_type,
            event.severity,
            event.source_module,
            event.description,
            event
                .source_ip
                .map_or_else(|| "N/A".to_string(), |ip| ip.to_string()),
            event.target.as_deref().unwrap_or("N/A"),
            event.timestamp.to_rfc3339(),
            event.auto_responded,
            serde_json::to_string_pretty(&event.details).unwrap_or_default(),
        );

        // Support AEGIS_SMTP_PASSWORD / SMTP_PASSWORD env var override.
        let password = std::env::var("AEGIS_SMTP_PASSWORD")
            .or_else(|_| std::env::var("SMTP_PASSWORD"))
            .unwrap_or_else(|_| email_cfg.smtp_password.clone());

        // Support AEGIS_SMTP_USERNAME env var override.
        let username = std::env::var("AEGIS_SMTP_USERNAME")
            .unwrap_or_else(|_| email_cfg.smtp_username.clone());

        // Build recipients.
        if email_cfg.to.is_empty() {
            warn!("No email recipients configured");
            return Ok(());
        }

        // Build the lettre message.
        use lettre::message::header::ContentType;

        let from_addr = email_cfg
            .from
            .parse::<lettre::Address>()
            .with_context(|| format!("Invalid from address: {}", email_cfg.from))?;

        let mut message_builder = lettre::Message::builder()
            .from(lettre::message::Mailbox::new(
                Some("Aegis Security".to_string()),
                from_addr,
            ))
            .subject(&subject);

        for to_addr_str in &email_cfg.to {
            let addr = to_addr_str
                .parse::<lettre::Address>()
                .with_context(|| format!("Invalid to address: {}", to_addr_str))?;
            message_builder = message_builder.to(lettre::message::Mailbox::new(None, addr));
        }

        let email = message_builder
            .header(ContentType::TEXT_HTML)
            .body(body)
            .context("Failed to build email message")?;

        // Build SMTP transport.
        let creds = lettre::transport::smtp::authentication::Credentials::new(username, password);

        let transport = if email_cfg.use_tls {
            lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::starttls_relay(
                &email_cfg.smtp_host,
            )
            .with_context(|| {
                format!(
                    "Failed to create STARTTLS relay for {}",
                    email_cfg.smtp_host
                )
            })?
            .port(email_cfg.smtp_port)
            .credentials(creds)
            .build()
        } else {
            lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::builder_dangerous(
                &email_cfg.smtp_host,
            )
            .port(email_cfg.smtp_port)
            .credentials(creds)
            .build()
        };

        // Retry up to 3 times with exponential backoff (1s, 2s, 4s).
        use lettre::AsyncTransport;
        let mut last_err = None;
        for attempt in 0..3u32 {
            match transport.send(email.clone()).await {
                Ok(_response) => {
                    info!(
                        to = ?email_cfg.to,
                        subject = %subject,
                        "Email alert sent successfully"
                    );
                    return Ok(());
                }
                Err(e) => {
                    let delay = Duration::from_secs(1 << attempt);
                    warn!(
                        attempt = attempt + 1,
                        error = %e,
                        delay_secs = delay.as_secs(),
                        "Email send failed, retrying"
                    );
                    last_err = Some(e);
                    tokio::time::sleep(delay).await;
                }
            }
        }

        if let Some(e) = last_err {
            error!(error = %e, "Email alert failed after 3 attempts");
        }

        // Never let email failure block the response pipeline.
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Webhook alerting
    // -----------------------------------------------------------------------

    async fn alert_webhook(&self, event: &ThreatEvent) -> Result<()> {
        let webhook_cfg = &self.config.webhook;

        // Check minimum severity.
        let min_severity = ThreatSeverity::from_str_loose(&webhook_cfg.min_severity)
            .unwrap_or(ThreatSeverity::High);
        if event.severity < min_severity {
            return Ok(());
        }

        if webhook_cfg.url.is_empty() {
            warn!("Webhook enabled but no URL configured");
            return Ok(());
        }

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .context("Failed to build HTTP client")?;

        match client.post(&webhook_cfg.url).json(event).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    info!(url = %webhook_cfg.url, "Webhook alert sent successfully");
                } else {
                    warn!(
                        url = %webhook_cfg.url,
                        status = %response.status(),
                        "Webhook returned non-success status"
                    );
                }
            }
            Err(e) => {
                error!(url = %webhook_cfg.url, error = %e, "Webhook request failed");
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Expand a leading `~` to the user's home directory.
fn shellexpand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest).to_string_lossy().to_string();
        }
    }
    path.to_string()
}
