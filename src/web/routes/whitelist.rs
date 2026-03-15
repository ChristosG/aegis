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
    State(ctx): State<AppContext>,
    Json(req): Json<WhitelistRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Validate CIDR or IP
    let cidr_str = if req.cidr.parse::<ipnet::IpNet>().is_ok() {
        req.cidr.clone()
    } else if let Ok(ip) = req.cidr.parse::<std::net::IpAddr>() {
        // Convert bare IP to CIDR
        match ip {
            std::net::IpAddr::V4(_) => format!("{}/32", ip),
            std::net::IpAddr::V6(_) => format!("{}/128", ip),
        }
    } else {
        return Ok(Json(serde_json::json!({
            "status": "error",
            "message": "Invalid CIDR or IP address",
        })));
    };

    // Persist to config file using toml_edit
    if let Err(e) = persist_whitelist_add(&cidr_str) {
        tracing::error!(error = %e, "Failed to persist whitelist addition");
        return Ok(Json(serde_json::json!({
            "status": "error",
            "message": format!("Failed to update config file: {}", e),
        })));
    }

    // Update runtime config
    {
        let mut state = ctx.state.write().await;
        if !state.config.response.whitelist.contains(&cidr_str) {
            state.config.response.whitelist.push(cidr_str.clone());
        }
    }

    Ok(Json(serde_json::json!({
        "status": "ok",
        "added": cidr_str,
    })))
}

pub async fn api_whitelist_remove(
    Path(cidr): Path<String>,
    State(ctx): State<AppContext>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Axum Path already decodes percent-encoding
    let cidr_decoded = cidr;

    // Persist removal to config file
    if let Err(e) = persist_whitelist_remove(&cidr_decoded) {
        tracing::error!(error = %e, "Failed to persist whitelist removal");
        return Ok(Json(serde_json::json!({
            "status": "error",
            "message": format!("Failed to update config file: {}", e),
        })));
    }

    // Update runtime config
    {
        let mut state = ctx.state.write().await;
        state.config.response.whitelist.retain(|c| c != &cidr_decoded);
    }

    Ok(Json(serde_json::json!({
        "status": "ok",
        "removed": cidr_decoded,
    })))
}

fn persist_whitelist_add(cidr: &str) -> anyhow::Result<()> {
    let config_path = crate::config::defaults::find_config_path(None)
        .ok_or_else(|| anyhow::anyhow!("No config file found"))?;

    let content = std::fs::read_to_string(&config_path)?;
    let mut doc = content.parse::<toml_edit::DocumentMut>()?;

    // Ensure [response] table exists
    if !doc.contains_key("response") {
        doc["response"] = toml_edit::Item::Table(toml_edit::Table::new());
    }

    let response = doc["response"].as_table_mut().unwrap();

    // Ensure whitelist array exists
    if !response.contains_key("whitelist") {
        response["whitelist"] = toml_edit::value(toml_edit::Array::new());
    }

    let arr = response["whitelist"]
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("whitelist is not an array in config"))?;

    // Check for duplicates
    for item in arr.iter() {
        if item.as_str() == Some(cidr) {
            return Ok(()); // Already present
        }
    }

    arr.push(cidr);
    std::fs::write(&config_path, doc.to_string())?;
    Ok(())
}

fn persist_whitelist_remove(cidr: &str) -> anyhow::Result<()> {
    let config_path = crate::config::defaults::find_config_path(None)
        .ok_or_else(|| anyhow::anyhow!("No config file found"))?;

    let content = std::fs::read_to_string(&config_path)?;
    let mut doc = content.parse::<toml_edit::DocumentMut>()?;

    if let Some(response) = doc.get_mut("response").and_then(|r| r.as_table_mut()) {
        if let Some(arr) = response.get_mut("whitelist").and_then(|w| w.as_array_mut()) {
            arr.retain(|item| item.as_str() != Some(cidr));
        }
    }

    std::fs::write(&config_path, doc.to_string())?;
    Ok(())
}
