use axum::{extract::State, http::StatusCode, response::Html};

use crate::web::server::AppContext;
use crate::web::templates;

pub async fn firewall_page(State(ctx): State<AppContext>) -> Result<Html<String>, StatusCode> {
    let state = ctx.state.read().await;
    let fi_enabled = ctx.config.file_integrity.enabled;
    let token = if ctx.auth_required {
        &ctx.api_token
    } else {
        ""
    };
    let html = templates::render_firewall_page(&state, token, fi_enabled);
    Ok(Html(html))
}
