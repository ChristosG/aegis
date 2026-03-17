use axum::{extract::State, response::Json};

use crate::modules::audit::AuditModule;
use crate::web::server::AppContext;

/// GET /api/audit — Run CIS benchmark audit and return results.
pub async fn api_audit(State(ctx): State<AppContext>) -> Json<serde_json::Value> {
    let audit_module = AuditModule::new(ctx.config.audit.clone());
    let profile = &ctx.config.audit.profile;

    match audit_module.run_audit(profile).await {
        Ok(results) => {
            let total = results.len();
            let passed = results.iter().filter(|r| r.pass).count();
            let score = if total > 0 {
                (passed as f64 / total as f64) * 100.0
            } else {
                100.0
            };

            Json(serde_json::json!({
                "profile": profile,
                "score": score,
                "total": total,
                "passed": passed,
                "failed": total - passed,
                "results": results,
            }))
        }
        Err(e) => Json(serde_json::json!({
            "error": format!("Audit failed: {}", e),
        })),
    }
}
