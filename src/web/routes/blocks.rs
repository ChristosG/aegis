use axum::{extract::State, http::StatusCode, response::Json};
use serde::Deserialize;

use crate::core::state::BlockEntry;
use crate::web::server::AppContext;

pub async fn api_blocks(State(ctx): State<AppContext>) -> Json<serde_json::Value> {
    let state = ctx.state.read().await;
    let threshold = state.config.response.repeat_offender_threshold;
    let blocks: Vec<serde_json::Value> = state
        .blocked_ips
        .values()
        .map(|b| {
            let strike_info = state.strike_history.get(&b.ip);
            let strikes = strike_info.map_or(0, |r| r.strikes.len());
            let escalated = strike_info.is_some_and(|r| r.escalated);
            serde_json::json!({
                "ip": b.ip,
                "reason": b.reason,
                "blocked_at": b.blocked_at,
                "expires_at": b.expires_at,
                "auto": b.auto,
                "strikes": strikes,
                "escalated": escalated,
                "threshold": threshold,
            })
        })
        .collect();
    Json(serde_json::json!({
        "blocked_ips": blocks,
        "count": blocks.len(),
    }))
}

pub async fn api_strikes(State(ctx): State<AppContext>) -> Json<serde_json::Value> {
    let state = ctx.state.read().await;
    let records: Vec<serde_json::Value> = state
        .strike_history
        .iter()
        .map(|(ip, record)| {
            serde_json::json!({
                "ip": ip.to_string(),
                "strikes": record.strikes.len(),
                "last_reason": record.last_reason,
                "escalated": record.escalated,
                "timestamps": record.strikes,
            })
        })
        .collect();
    Json(serde_json::json!({
        "strike_records": records,
        "count": records.len(),
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
    let expires_at = if duration_str == "forever" {
        None
    } else {
        let duration =
            crate::core::scheduler::Scheduler::parse_duration(duration_str).map_err(|_| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(
                        serde_json::json!({"status": "error", "message": "Invalid duration format"}),
                    ),
                )
            })?;
        Some(
            chrono::Utc::now()
                + chrono::Duration::from_std(duration).unwrap_or(chrono::Duration::hours(24)),
        )
    };

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
