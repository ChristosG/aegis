use axum::{extract::State, http::StatusCode, response::Html};

use crate::web::server::AppContext;
use crate::web::templates;

pub async fn dashboard_page(State(ctx): State<AppContext>) -> Result<Html<String>, StatusCode> {
    let state = ctx.state.read().await;
    let html = templates::render_dashboard(&state, &ctx.api_token);
    Ok(Html(html))
}

pub async fn health() -> &'static str {
    "ok"
}
