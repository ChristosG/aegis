use axum::extract::{Query, State};
use axum::response::Json;
use tracing::{info, warn};

use crate::config::defaults::{find_system_config_path, resolve_path};
use crate::web::server::AppContext;

pub async fn api_baseline_reset(State(ctx): State<AppContext>) -> Json<serde_json::Value> {
    let config = &ctx.config.file_integrity;
    let baseline_path = resolve_path(&config.baseline_path);
    let pending_path = baseline_path
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .join("fi_pending.json");

    let mut errors = Vec::new();

    if baseline_path.exists() {
        if let Err(e) = std::fs::remove_file(&baseline_path) {
            warn!(error = %e, "Failed to delete baseline file");
            errors.push(format!("baseline: {}", e));
        } else {
            info!(path = %baseline_path.display(), "Baseline file deleted");
        }
    }

    if pending_path.exists() {
        if let Err(e) = std::fs::remove_file(&pending_path) {
            warn!(error = %e, "Failed to delete fi_pending.json");
            errors.push(format!("pending: {}", e));
        } else {
            info!("fi_pending.json deleted");
        }
    }

    if errors.is_empty() {
        Json(serde_json::json!({
            "status": "ok",
            "message": "Baseline reset. Next scan will establish new baseline."
        }))
    } else {
        Json(serde_json::json!({
            "status": "partial",
            "message": format!("Reset completed with errors: {}", errors.join("; "))
        }))
    }
}

pub async fn api_baseline_create(State(ctx): State<AppContext>) -> Json<serde_json::Value> {
    let config = &ctx.config.file_integrity;
    let baseline_path = resolve_path(&config.baseline_path);

    match crate::init::build_baseline_map(&config.watch_paths, &config.exclude_paths) {
        Ok((baseline, file_count, _error_count)) => {
            // Ensure parent directory exists
            if let Some(parent) = baseline_path.parent() {
                if let Err(e) = std::fs::create_dir_all(parent) {
                    warn!(error = %e, "Failed to create baseline directory");
                    return Json(serde_json::json!({
                        "status": "error",
                        "message": format!("Failed to create directory: {}", e)
                    }));
                }
            }

            match serde_json::to_string_pretty(&baseline) {
                Ok(json) => {
                    if let Err(e) = std::fs::write(&baseline_path, json) {
                        warn!(error = %e, "Failed to write baseline file");
                        return Json(serde_json::json!({
                            "status": "error",
                            "message": format!("Failed to write baseline: {}", e)
                        }));
                    }
                    info!(files = file_count, "Baseline created via API");
                    Json(serde_json::json!({
                        "status": "ok",
                        "files_hashed": file_count,
                    }))
                }
                Err(e) => Json(serde_json::json!({
                    "status": "error",
                    "message": format!("Failed to serialize baseline: {}", e)
                })),
            }
        }
        Err(e) => {
            warn!(error = %e, "Failed to build baseline");
            Json(serde_json::json!({
                "status": "error",
                "message": format!("Failed to build baseline: {}", e)
            }))
        }
    }
}

#[derive(serde::Deserialize)]
pub struct FiToggleParams {
    pub action: String,
}

pub async fn api_fi_toggle(
    State(_ctx): State<AppContext>,
    Query(params): Query<FiToggleParams>,
) -> Json<serde_json::Value> {
    let enable = match params.action.as_str() {
        "on" => true,
        "off" => false,
        other => {
            return Json(serde_json::json!({
                "status": "error",
                "message": format!("Invalid action '{}'. Use 'on' or 'off'.", other)
            }));
        }
    };

    let config_path = match find_system_config_path() {
        Some(p) => p,
        None => {
            return Json(serde_json::json!({
                "status": "error",
                "message": "No config file found."
            }));
        }
    };

    let content = match std::fs::read_to_string(&config_path) {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "Failed to read config file");
            return Json(serde_json::json!({
                "status": "error",
                "message": format!("Failed to read config: {}", e)
            }));
        }
    };

    let mut doc = match content.parse::<toml_edit::DocumentMut>() {
        Ok(d) => d,
        Err(e) => {
            warn!(error = %e, "Failed to parse config file");
            return Json(serde_json::json!({
                "status": "error",
                "message": format!("Failed to parse config: {}", e)
            }));
        }
    };

    if !doc.contains_key("file_integrity") {
        doc["file_integrity"] = toml_edit::Item::Table(toml_edit::Table::new());
    }
    doc["file_integrity"]["enabled"] = toml_edit::value(enable);

    if let Err(e) = std::fs::write(&config_path, doc.to_string()) {
        warn!(error = %e, "Failed to write config file");
        return Json(serde_json::json!({
            "status": "error",
            "message": format!("Failed to write config: {}", e)
        }));
    }

    let state_str = if enable { "enabled" } else { "disabled" };
    info!(fi_enabled = enable, "File integrity toggled via API");

    Json(serde_json::json!({
        "status": "ok",
        "fi_enabled": enable,
        "message": format!("File integrity {}. Restart aegis to apply.", state_str)
    }))
}
