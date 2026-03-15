use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{IntoResponse, Json},
};

use crate::cli::report;
use crate::cli::report_pdf;
use crate::web::server::AppContext;

pub async fn api_report(State(ctx): State<AppContext>) -> Json<serde_json::Value> {
    let state = ctx.state.read().await;
    let text =
        report::generate_report(&state).unwrap_or_else(|_| "Report generation failed".to_string());
    Json(serde_json::json!({
        "report": text,
    }))
}

pub async fn download_pdf(State(ctx): State<AppContext>) -> Result<impl IntoResponse, StatusCode> {
    let state = ctx.state.read().await;

    // Generate actual PDF using the report_pdf module
    let tmp_path = std::env::temp_dir().join(format!("aegis-report-{}.pdf", std::process::id()));
    let tmp_str = tmp_path.to_string_lossy().to_string();

    report_pdf::generate_pdf_report(&state, &tmp_str).map_err(|e| {
        tracing::error!(error = %e, "PDF generation failed");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let bytes = std::fs::read(&tmp_path).map_err(|e| {
        tracing::error!(error = %e, "Failed to read generated PDF");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Clean up temp file
    let _ = std::fs::remove_file(&tmp_path);

    Ok((
        [
            (header::CONTENT_TYPE, "application/pdf"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"aegis-report.pdf\"",
            ),
        ],
        bytes,
    ))
}
