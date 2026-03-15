use axum::{
    extract::State,
    response::{Html, Json},
};

use crate::web::server::AppContext;
use crate::web::templates;

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

/// Render config as a structured HTML page with collapsible sections.
pub async fn config_page(State(ctx): State<AppContext>) -> Html<String> {
    let config = &*ctx.config;
    let config_json = serde_json::to_value(config).unwrap_or(serde_json::json!({}));

    let mut sections = String::new();
    if let Some(obj) = config_json.as_object() {
        for (section_name, section_val) in obj {
            if section_name == "dashboard" {
                continue; // Don't show dashboard config (contains token path)
            }
            let label = section_name.replace('_', " ");
            let label = label
                .split(' ')
                .map(|w| {
                    let mut c = w.chars();
                    match c.next() {
                        None => String::new(),
                        Some(f) => f.to_uppercase().to_string() + c.as_str(),
                    }
                })
                .collect::<Vec<_>>()
                .join(" ");

            let mut rows = String::new();
            if let Some(section_obj) = section_val.as_object() {
                for (key, val) in section_obj {
                    let display_val = sanitize_config_value(section_name, key, val);
                    let escaped_key = templates::html_escape_pub(key);
                    let escaped_val = templates::html_escape_pub(&display_val);
                    rows.push_str(&format!(
                        r#"<div class="config-row"><span class="config-key">{escaped_key}</span><span class="config-value">{escaped_val}</span></div>"#,
                    ));
                }
            }

            let escaped_label = templates::html_escape_pub(&label);
            sections.push_str(&format!(
                r#"<div class="config-section">
                    <div class="config-section-header" onclick="toggleConfigSection(this)">
                        <span>{escaped_label}</span>
                        <span style="color:var(--text-muted)">&#9662;</span>
                    </div>
                    <div class="config-section-body">{rows}</div>
                </div>"#,
            ));
        }
    }

    let content = format!(
        r#"
        <div style="margin-bottom:16px">
            <button onclick="validateConfig()">Validate Config</button>
        </div>
        {sections}
        "#,
    );

    Html(templates::render_config_page(&content, &ctx.api_token))
}

/// Config validation API endpoint.
pub async fn api_check(State(ctx): State<AppContext>) -> Json<serde_json::Value> {
    let result = crate::config::validate::validate_config(&ctx.config);

    Json(serde_json::json!({
        "valid": result.is_ok(),
        "errors": result.errors,
        "warnings": result.warnings,
    }))
}

fn sanitize_config_value(section: &str, key: &str, val: &serde_json::Value) -> String {
    // Mask sensitive values
    if section == "alerting" {
        if key == "smtp_password" || key == "bot_token" {
            return "***".to_string();
        }
        if (key == "webhook_url" || key == "url") && val.as_str().is_some_and(|s| !s.is_empty()) {
            return "***".to_string();
        }
    }

    match val {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Array(arr) => {
            let items: Vec<String> = arr
                .iter()
                .map(|v| match v {
                    serde_json::Value::String(s) => s.clone(),
                    other => other.to_string(),
                })
                .collect();
            items.join(", ")
        }
        serde_json::Value::Object(_) => "[nested]".to_string(),
        serde_json::Value::Null => "null".to_string(),
    }
}
