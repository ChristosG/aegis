use axum::{
    extract::{Path, State},
    response::Json,
};

use crate::modules::enrichment::EnrichmentService;
use crate::web::server::AppContext;

/// GET /api/enrich/{ip} — Enrich an IP address with threat intelligence.
pub async fn api_enrich(
    State(ctx): State<AppContext>,
    Path(ip): Path<String>,
) -> Json<serde_json::Value> {
    if !ctx.config.enrichment.enabled {
        return Json(serde_json::json!({
            "error": "Enrichment is not enabled. Configure API keys in [enrichment] section."
        }));
    }

    let service = EnrichmentService::new(ctx.config.enrichment.clone());

    match service.enrich(&ip).await {
        Ok(result) => Json(serde_json::to_value(&result).unwrap_or(serde_json::json!({}))),
        Err(e) => Json(serde_json::json!({
            "error": format!("Enrichment failed: {}", e),
        })),
    }
}
