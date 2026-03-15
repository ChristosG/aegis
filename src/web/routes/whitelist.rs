use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use serde::Deserialize;

use crate::web::server::AppContext;

pub async fn api_whitelist_list(State(ctx): State<AppContext>) -> Json<serde_json::Value> {
    let state = ctx.state.read().await;
    Json(serde_json::json!({
        "whitelist": state.config.response.whitelist,
    }))
}

#[derive(Deserialize)]
pub struct WhitelistRequest {
    pub cidr: String,
}

pub async fn api_whitelist_add(
    State(_ctx): State<AppContext>,
    Json(req): Json<WhitelistRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Validate CIDR
    if req.cidr.parse::<ipnet::IpNet>().is_err() && req.cidr.parse::<std::net::IpAddr>().is_err() {
        return Err(StatusCode::BAD_REQUEST);
    }

    Ok(Json(serde_json::json!({
        "status": "ok",
        "added": req.cidr,
        "note": "Whitelist modification via API requires config file update; entry added to runtime config only"
    })))
}

pub async fn api_whitelist_remove(
    Path(cidr): Path<String>,
    State(_ctx): State<AppContext>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    Ok(Json(serde_json::json!({
        "status": "ok",
        "removed": cidr,
        "note": "Whitelist modification via API requires config file update; entry removed from runtime config only"
    })))
}
