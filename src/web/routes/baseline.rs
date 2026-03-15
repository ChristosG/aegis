use axum::{extract::State, response::Json};
use tracing::{info, warn};

use crate::config::defaults::resolve_path;
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
