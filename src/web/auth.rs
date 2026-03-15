use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};

use super::server::AppContext;

/// Middleware that validates the API token from either:
/// - `Authorization: Bearer <token>` header
/// - `?token=<token>` query parameter
pub async fn auth_middleware(
    State(ctx): State<AppContext>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Allow /health without auth
    if request.uri().path() == "/health" {
        return Ok(next.run(request).await);
    }

    let token_from_header = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_string());

    let token_from_query = request.uri().query().and_then(|q| {
        q.split('&').find_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            if key == "token" {
                Some(value.to_string())
            } else {
                None
            }
        })
    });

    let provided_token = token_from_header.or(token_from_query);

    match provided_token {
        Some(ref t) if constant_time_eq(t.as_bytes(), ctx.api_token.as_bytes()) => {
            Ok(next.run(request).await)
        }
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}

/// Constant-time comparison to prevent timing attacks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}
