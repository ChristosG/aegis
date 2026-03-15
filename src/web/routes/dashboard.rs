use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, Json},
};

use crate::core::threat::ThreatSeverity;
use crate::web::server::AppContext;
use crate::web::templates;

pub async fn dashboard_page(State(ctx): State<AppContext>) -> Result<Html<String>, StatusCode> {
    let state = ctx.state.read().await;
    let html = templates::render_dashboard(&state, &ctx.api_token);
    Ok(Html(html))
}

pub async fn health() -> &'static str {
    "ok"
}

/// Returns live dashboard stats for auto-refresh.
pub async fn api_stats(State(ctx): State<AppContext>) -> Json<serde_json::Value> {
    let state = ctx.state.read().await;
    let counts = state.threat_counts();

    Json(serde_json::json!({
        "posture": format!("{}", state.posture),
        "total_threats": state.threats.len(),
        "blocked_ips": state.blocked_ips.len(),
        "scans_run": state.stats.scans_run,
        "severity": {
            "critical": counts.get(&ThreatSeverity::Critical).copied().unwrap_or(0),
            "high": counts.get(&ThreatSeverity::High).copied().unwrap_or(0),
            "medium": counts.get(&ThreatSeverity::Medium).copied().unwrap_or(0),
            "low": counts.get(&ThreatSeverity::Low).copied().unwrap_or(0),
            "info": counts.get(&ThreatSeverity::Info).copied().unwrap_or(0),
        },
    }))
}
