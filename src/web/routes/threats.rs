use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, Json},
};

use crate::web::server::AppContext;
use crate::web::templates;

pub async fn threats_page(State(ctx): State<AppContext>) -> Result<Html<String>, StatusCode> {
    let state = ctx.state.read().await;
    let token = if ctx.auth_required {
        &ctx.api_token
    } else {
        ""
    };
    let html = templates::render_threats_page(&state, token);
    Ok(Html(html))
}

pub async fn api_threats(State(ctx): State<AppContext>) -> Json<serde_json::Value> {
    let state = ctx.state.read().await;
    Json(serde_json::json!({
        "threats": state.threats,
        "count": state.threats.len(),
    }))
}
