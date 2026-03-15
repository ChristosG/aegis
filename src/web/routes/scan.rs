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

/// Trigger auto-response for current unresponded threats.
pub async fn api_respond(
    State(ctx): State<AppContext>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let mut results = Vec::new();

    // Collect unresponded threats
    let threats: Vec<_> = {
        let state = ctx.state.read().await;
        state
            .threats
            .iter()
            .filter(|t| !t.auto_responded)
            .cloned()
            .collect()
    };

    for threat in &threats {
        let action = ctx.response_engine.determine_action(threat);
        let mut state = ctx.state.write().await;
        match ctx.response_engine.respond(threat, &mut state).await {
            Ok(msg) => {
                results.push(serde_json::json!({
                    "threat_id": threat.id,
                    "action": action.to_string(),
                    "result": msg,
                }));
            }
            Err(e) => {
                results.push(serde_json::json!({
                    "threat_id": threat.id,
                    "action": action.to_string(),
                    "error": e.to_string(),
                }));
            }
        }
    }

    // Persist updated block list
    {
        let state = ctx.state.read().await;
        if let Err(e) = ctx.storage.save_block_list(&state.blocked_ips) {
            tracing::warn!(error = %e, "Failed to persist block list after auto-respond");
        }
    }

    Ok(Json(serde_json::json!({
        "status": "ok",
        "responded": results.len(),
        "results": results,
    })))
}
