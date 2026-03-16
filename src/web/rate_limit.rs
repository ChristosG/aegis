use axum::{
    body::Body,
    http::{Request, Response, StatusCode},
};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tower::{Layer, Service};

/// Per-IP token bucket entry.
struct Bucket {
    tokens: u32,
    last_refill: Instant,
}

/// Shared rate limit state.
struct RateLimitState {
    buckets: HashMap<IpAddr, Bucket>,
    last_prune: Instant,
}

/// Axum-compatible rate limiting layer.
/// 120 req/min for GET, 10 req/min for mutative (POST/DELETE).
#[derive(Clone)]
pub struct RateLimitLayer {
    state: Arc<Mutex<RateLimitState>>,
    /// When true (localhost bind), ignore X-Forwarded-For / X-Real-IP headers
    /// to prevent rate-limit bypass via header spoofing.
    is_localhost: bool,
}

impl Default for RateLimitLayer {
    fn default() -> Self {
        Self::new(false)
    }
}

impl RateLimitLayer {
    pub fn new(is_localhost: bool) -> Self {
        Self {
            state: Arc::new(Mutex::new(RateLimitState {
                buckets: HashMap::new(),
                last_prune: Instant::now(),
            })),
            is_localhost,
        }
    }
}

impl<S> Layer<S> for RateLimitLayer {
    type Service = RateLimitService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RateLimitService {
            inner,
            state: self.state.clone(),
            is_localhost: self.is_localhost,
        }
    }
}

#[derive(Clone)]
pub struct RateLimitService<S> {
    inner: S,
    state: Arc<Mutex<RateLimitState>>,
    is_localhost: bool,
}

impl<S> Service<Request<Body>> for RateLimitService<S>
where
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let ip = extract_client_ip(&req, self.is_localhost);
        let is_mutative =
            req.method() == axum::http::Method::POST || req.method() == axum::http::Method::DELETE;
        let max_tokens = if is_mutative { 10 } else { 120 };

        let allowed = if let Some(ip) = ip {
            let mut state = self.state.lock().unwrap();

            // Prune old entries every 5 minutes
            if state.last_prune.elapsed().as_secs() > 300 {
                let cutoff = Instant::now() - std::time::Duration::from_secs(120);
                state.buckets.retain(|_, b| b.last_refill > cutoff);
                state.last_prune = Instant::now();
            }

            let now = Instant::now();
            let bucket = state.buckets.entry(ip).or_insert(Bucket {
                tokens: max_tokens,
                last_refill: now,
            });

            // Refill tokens based on elapsed time
            let elapsed = now.duration_since(bucket.last_refill).as_secs();
            if elapsed > 0 {
                let refill = (elapsed as u32) * (max_tokens / 60).max(1);
                bucket.tokens = (bucket.tokens + refill).min(max_tokens);
                bucket.last_refill = now;
            }

            if bucket.tokens > 0 {
                bucket.tokens -= 1;
                true
            } else {
                false
            }
        } else {
            true // No IP detected, allow
        };

        if !allowed {
            return Box::pin(async {
                Ok(Response::builder()
                    .status(StatusCode::TOO_MANY_REQUESTS)
                    .header("Retry-After", "60")
                    .body(Body::from("Rate limit exceeded"))
                    .unwrap())
            });
        }

        let mut inner = self.inner.clone();
        Box::pin(async move { inner.call(req).await })
    }
}

fn extract_client_ip(req: &Request<Body>, is_localhost: bool) -> Option<IpAddr> {
    // Only trust forwarded headers when NOT bound to localhost.
    // On localhost there is no reverse proxy, so an attacker could spoof
    // X-Forwarded-For to bypass rate limits.
    if !is_localhost {
        if let Some(forwarded) = req.headers().get("x-forwarded-for") {
            if let Ok(val) = forwarded.to_str() {
                if let Some(first) = val.split(',').next() {
                    if let Ok(ip) = first.trim().parse() {
                        return Some(ip);
                    }
                }
            }
        }

        if let Some(real_ip) = req.headers().get("x-real-ip") {
            if let Ok(val) = real_ip.to_str() {
                if let Ok(ip) = val.trim().parse() {
                    return Some(ip);
                }
            }
        }
    }

    // Fall back to connection info from extensions
    req.extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip())
}
