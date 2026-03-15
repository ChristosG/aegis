use axum::{extract::State, response::Json};

use crate::web::server::AppContext;

/// Return sanitized config (masks sensitive fields).
pub async fn api_config(State(ctx): State<AppContext>) -> Json<serde_json::Value> {
    let config = &*ctx.config;
    let mut config_json = serde_json::to_value(config).unwrap_or(serde_json::json!({}));

    // Sanitize sensitive fields
    if let Some(obj) = config_json.as_object_mut() {
        if let Some(alerting) = obj.get_mut("alerting").and_then(|a| a.as_object_mut()) {
            if let Some(email) = alerting.get_mut("email").and_then(|e| e.as_object_mut()) {
                if email.contains_key("smtp_password") {
                    email.insert("smtp_password".to_string(), serde_json::json!("***"));
                }
            }
            if let Some(telegram) = alerting.get_mut("telegram").and_then(|t| t.as_object_mut()) {
                if telegram.contains_key("bot_token") {
                    telegram.insert("bot_token".to_string(), serde_json::json!("***"));
                }
            }
            if let Some(slack) = alerting.get_mut("slack").and_then(|s| s.as_object_mut()) {
                if let Some(url) = slack.get("webhook_url").and_then(|u| u.as_str()) {
                    if !url.is_empty() {
                        slack.insert("webhook_url".to_string(), serde_json::json!("***"));
                    }
                }
            }
            if let Some(webhook) = alerting.get_mut("webhook").and_then(|w| w.as_object_mut()) {
                if let Some(url) = webhook.get("url").and_then(|u| u.as_str()) {
                    if !url.is_empty() {
                        webhook.insert("url".to_string(), serde_json::json!("***"));
                    }
                }
            }
        }
        // Mask dashboard token file path
        if let Some(dashboard) = obj.get_mut("dashboard").and_then(|d| d.as_object_mut()) {
            dashboard.remove("token_file");
        }
    }

    Json(config_json)
}
