use anyhow::{Context, Result};
use tracing::{info, warn};

use crate::config::schema::SlackConfig;
use crate::core::threat::{ThreatEvent, ThreatSeverity};

/// Send a Slack webhook notification for a threat event.
pub async fn alert_slack(config: &SlackConfig, event: &ThreatEvent) -> Result<()> {
    let min_severity =
        ThreatSeverity::from_str_loose(&config.min_severity).unwrap_or(ThreatSeverity::High);
    if event.severity < min_severity {
        return Ok(());
    }

    if config.webhook_url.is_empty() {
        warn!("Slack enabled but webhook_url is empty");
        return Ok(());
    }

    let color = match event.severity {
        ThreatSeverity::Critical => "#FF0000",
        ThreatSeverity::High => "#FF4444",
        ThreatSeverity::Medium => "#FFA500",
        ThreatSeverity::Low => "#0088FF",
        ThreatSeverity::Info => "#888888",
    };

    let source_ip = event
        .source_ip
        .map_or_else(|| "N/A".to_string(), |ip| ip.to_string());

    let payload = serde_json::json!({
        "attachments": [{
            "color": color,
            "title": format!("Aegis Alert: {} [{}]", event.threat_type, event.severity),
            "text": event.description,
            "fields": [
                { "title": "Severity", "value": event.severity.to_string(), "short": true },
                { "title": "Module", "value": event.source_module, "short": true },
                { "title": "Source IP", "value": source_ip, "short": true },
                { "title": "Event ID", "value": event.id, "short": true },
            ],
            "ts": event.timestamp.timestamp()
        }]
    });

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .context("Failed to build HTTP client")?;

    match client.post(&config.webhook_url).json(&payload).send().await {
        Ok(response) => {
            if response.status().is_success() {
                info!("Slack alert sent successfully");
            } else {
                warn!(status = %response.status(), "Slack webhook returned non-success status");
            }
        }
        Err(e) => {
            warn!(error = %e, "Slack webhook request failed");
        }
    }

    Ok(())
}
