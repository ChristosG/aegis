use axum::{extract::State, http::StatusCode, response::Json};
use serde::Deserialize;

use crate::core::state::BlockEntry;
use crate::web::server::AppContext;

pub async fn api_blocks(State(ctx): State<AppContext>) -> Json<serde_json::Value> {
    let state = ctx.state.read().await;
    let blocks: Vec<&BlockEntry> = state.blocked_ips.values().collect();
    Json(serde_json::json!({
        "blocked_ips": blocks,
        "count": blocks.len(),
    }))
}

#[derive(Deserialize)]
pub struct BlockRequest {
    pub ip: String,
    pub duration: Option<String>,
    pub reason: Option<String>,
}

pub async fn api_block(
    State(ctx): State<AppContext>,
    Json(req): Json<BlockRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let ip: std::net::IpAddr = req.ip.parse().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"status": "error", "message": "Invalid IP address"})),
        )
    })?;
    let duration_str = req.duration.as_deref().unwrap_or("24h");
    let duration =
        crate::core::scheduler::Scheduler::parse_duration(duration_str).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"status": "error", "message": "Invalid duration format"})),
            )
        })?;

    let expires_at = Some(
        chrono::Utc::now()
            + chrono::Duration::from_std(duration).unwrap_or(chrono::Duration::hours(24)),
    );

    let entry = BlockEntry {
        ip,
        reason: req
            .reason
            .unwrap_or_else(|| "Blocked via web dashboard".to_string()),
        blocked_at: chrono::Utc::now(),
        expires_at,
        auto: false,
    };

    // Block via firewall
    if let Err(e) = ctx.response_engine.block_ip_firewall(&ip) {
        tracing::warn!(error = %e, "Firewall block failed");
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "status": "error",
                "message": format!("Firewall block failed: {}", e),
            })),
        ));
    }

    let mut state = ctx.state.write().await;
    state.block_ip(entry);
    if let Err(e) = ctx.storage.save_block_list(&state.blocked_ips) {
        tracing::warn!(error = %e, "Failed to persist block list");
    }

    Ok(Json(
        serde_json::json!({ "status": "ok", "ip": ip.to_string() }),
    ))
}

pub async fn api_unblock(
    State(ctx): State<AppContext>,
    Json(req): Json<BlockRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let ip: std::net::IpAddr = req.ip.parse().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"status": "error", "message": "Invalid IP address"})),
        )
    })?;

    if let Err(e) = ctx.response_engine.unblock_ip_firewall(&ip) {
        tracing::warn!(error = %e, "Firewall unblock failed");
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "status": "error",
                "message": format!("Firewall unblock failed: {}", e),
            })),
        ));
    }

    let mut state = ctx.state.write().await;
    let removed = state.unblock_ip(&ip);
    if removed {
        if let Err(e) = ctx.storage.save_block_list(&state.blocked_ips) {
            tracing::warn!(error = %e, "Failed to persist block list");
        }
    }

    Ok(Json(
        serde_json::json!({ "status": "ok", "removed": removed }),
    ))
}
