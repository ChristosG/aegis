use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{IntoResponse, Json},
};

use crate::cli::report;
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

    // Generate report text and write as simple PDF-like content
    let text =
        report::generate_report(&state).unwrap_or_else(|_| "Report generation failed".to_string());

    Ok((
        [
            (header::CONTENT_TYPE, "application/pdf"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"aegis-report.pdf\"",
            ),
        ],
        text.into_bytes(),
    ))
}
