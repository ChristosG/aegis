use anyhow::{Context, Result};
use tracing::{info, warn};

use crate::config::schema::TelegramConfig;
use crate::core::threat::{ThreatEvent, ThreatSeverity};

/// Send a Telegram bot notification for a threat event.
pub async fn alert_telegram(config: &TelegramConfig, event: &ThreatEvent) -> Result<()> {
    let min_severity =
        ThreatSeverity::from_str_loose(&config.min_severity).unwrap_or(ThreatSeverity::High);
    if event.severity < min_severity {
        return Ok(());
    }

    // Support env var override for bot token.
    let bot_token =
        std::env::var("AEGIS_TELEGRAM_BOT_TOKEN").unwrap_or_else(|_| config.bot_token.clone());

    if bot_token.is_empty() {
        warn!("Telegram enabled but bot_token is empty");
        return Ok(());
    }

    if config.chat_id.is_empty() {
        warn!("Telegram enabled but chat_id is empty");
        return Ok(());
    }

    let severity_icon = match event.severity {
        ThreatSeverity::Critical => "\u{1f534}",
        ThreatSeverity::High => "\u{1f7e0}",
        ThreatSeverity::Medium => "\u{1f7e1}",
        ThreatSeverity::Low => "\u{1f535}",
        ThreatSeverity::Info => "\u{26aa}",
    };

    let source_ip = event
        .source_ip
        .map_or_else(|| "N/A".to_string(), |ip| ip.to_string());

    let text = format!(
        "{} <b>Aegis Alert</b>\n\n\
         <b>Threat:</b> {}\n\
         <b>Severity:</b> {}\n\
         <b>Module:</b> {}\n\
         <b>Source IP:</b> {}\n\
         <b>Description:</b> {}\n\
         <b>Time:</b> {}",
        severity_icon,
        event.threat_type,
        event.severity,
        event.source_module,
        source_ip,
        event.description,
        event.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
    );

    let url = format!("https://api.telegram.org/bot{}/sendMessage", bot_token);

    let payload = serde_json::json!({
        "chat_id": config.chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": true,
    });

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .context("Failed to build HTTP client")?;

    match client.post(&url).json(&payload).send().await {
        Ok(response) => {
            if response.status().is_success() {
                info!("Telegram alert sent successfully");
            } else {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                warn!(status = %status, body = %body, "Telegram API returned non-success status");
            }
        }
        Err(e) => {
            warn!(error = %e, "Telegram API request failed");
        }
    }

    Ok(())
}
