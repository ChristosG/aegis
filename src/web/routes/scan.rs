use axum::{extract::State, http::StatusCode, response::Json};

use crate::web::server::AppContext;

/// Trigger a one-shot scan via the API.
pub async fn api_scan(
    State(ctx): State<AppContext>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Run all enabled modules
    let modules = crate::modules::create_modules(&ctx.config);
    let mut all_threats = Vec::new();

    for module in &modules {
        match module.scan().await {
            Ok(threats) => {
                all_threats.extend(threats);
            }
            Err(e) => {
                tracing::error!(module = module.name(), error = %e, "Scan module failed");
            }
        }
    }

    // Store threats
    {
        let mut state = ctx.state.write().await;
        state.add_threats(all_threats.clone());
    }

    // Persist
    if let Err(e) = ctx.storage.append_threats(&all_threats) {
        tracing::warn!(error = %e, "Failed to write threats to log");
    }

    Ok(Json(serde_json::json!({
        "status": "ok",
        "threats_found": all_threats.len(),
        "threats": all_threats,
    })))
}
