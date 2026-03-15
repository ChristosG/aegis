use axum::{
    extract::{Request, State},
    http::{header::SET_COOKIE, StatusCode},
    middleware::Next,
    response::Response,
};

use super::server::AppContext;

/// Middleware that validates the API token from either:
/// - `Authorization: Bearer <token>` header
/// - `?token=<token>` query parameter
/// - `aegis_token=<token>` cookie
///
/// On successful auth via header or query param, sets a cookie so
/// subsequent page navigations work without re-specifying the token.
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

    let token_from_cookie = request
        .headers()
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';').find_map(|c| {
                let c = c.trim();
                c.strip_prefix("aegis_token=").map(|v| v.to_string())
            })
        });

    // Check in order: header > query > cookie
    let (provided_token, needs_cookie) = if let Some(t) = token_from_header {
        (Some(t), true)
    } else if let Some(t) = token_from_query {
        (Some(t), true)
    } else if let Some(t) = token_from_cookie {
        (Some(t), false)
    } else {
        (None, false)
    };

    match provided_token {
        Some(ref t) if constant_time_eq(t.as_bytes(), ctx.api_token.as_bytes()) => {
            let mut response = next.run(request).await;
            // Set cookie if auth came from header or query param
            if needs_cookie {
                let cookie = format!(
                    "aegis_token={}; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400",
                    t
                );
                if let Ok(val) = cookie.parse() {
                    response.headers_mut().insert(SET_COOKIE, val);
                }
            }
            Ok(response)
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
