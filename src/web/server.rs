use std::sync::Arc;

use anyhow::Result;
use axum::{
    middleware,
    routing::{delete, get, post},
    Router,
};
use tokio::sync::RwLock;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tracing::info;

use crate::alerting::AlertManager;
use crate::config::schema::{AegisConfig, DashboardConfig};
use crate::core::event_bus::EventBus;
use crate::core::state::AppState;
use crate::response::ResponseEngine;
use crate::storage::Storage;

use super::auth::auth_middleware;
use super::rate_limit::RateLimitLayer;
use super::routes;

/// Shared application context passed to all route handlers.
#[derive(Clone)]
pub struct AppContext {
    pub state: Arc<RwLock<AppState>>,
    pub config: Arc<AegisConfig>,
    pub response_engine: Arc<ResponseEngine>,
    pub alert_manager: Arc<AlertManager>,
    pub storage: Arc<Storage>,
    pub event_bus: EventBus,
    pub api_token: String,
    pub auth_required: bool,
}

/// Start the web dashboard server.
#[allow(clippy::too_many_arguments)]
pub async fn start_server(
    dashboard_config: DashboardConfig,
    state: Arc<RwLock<AppState>>,
    config: Arc<AegisConfig>,
    response_engine: Arc<ResponseEngine>,
    alert_manager: Arc<AlertManager>,
    storage: Arc<Storage>,
    event_bus: EventBus,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<()> {
    let api_token = super::token::ensure_token(&dashboard_config.token_file)?;

    let is_localhost = matches!(
        dashboard_config.bind.as_str(),
        "127.0.0.1" | "::1" | "localhost"
    );

    let ctx = AppContext {
        state,
        config,
        response_engine,
        alert_manager,
        storage,
        event_bus,
        api_token,
        auth_required: !is_localhost,
    };

    let origin = format!("http://{}:{}", dashboard_config.bind, dashboard_config.port);
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::exact(
            origin
                .parse()
                .unwrap_or_else(|_| "http://127.0.0.1:9443".parse().unwrap()),
        ))
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::DELETE,
        ])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::AUTHORIZATION,
        ]);

    let app = Router::new()
        // HTML pages
        .route("/", get(routes::dashboard::dashboard_page))
        .route("/threats", get(routes::threats::threats_page))
        .route("/firewall", get(routes::firewall::firewall_page))
        .route("/status", get(routes::status::status_page))
        .route("/config", get(routes::config::config_page))
        .route("/logs", get(routes::logs::logs_page))
        // Health check (no auth)
        .route("/health", get(routes::dashboard::health))
        // API routes
        .route("/api/threats", get(routes::threats::api_threats))
        .route("/api/blocks", get(routes::blocks::api_blocks))
        .route("/api/block", post(routes::blocks::api_block))
        .route("/api/unblock", post(routes::blocks::api_unblock))
        .route("/api/whitelist", get(routes::whitelist::api_whitelist_list))
        .route("/api/whitelist", post(routes::whitelist::api_whitelist_add))
        .route(
            "/api/whitelist/{cidr}",
            delete(routes::whitelist::api_whitelist_remove),
        )
        .route(
            "/api/config",
            get(routes::config::api_config).post(routes::config::api_config_update),
        )
        .route(
            "/api/module/toggle",
            post(routes::config::api_module_toggle),
        )
        .route(
            "/api/discover/ports",
            get(routes::config::api_discover_ports),
        )
        .route(
            "/api/discover/domains",
            get(routes::config::api_discover_domains),
        )
        .route("/api/restart", post(routes::config::api_restart))
        .route("/api/check", post(routes::config::api_check))
        .route("/api/scan", post(routes::scan::api_scan))
        .route("/api/respond", post(routes::scan::api_respond))
        .route("/api/stats", get(routes::dashboard::api_stats))
        .route("/api/status", get(routes::status::api_status))
        .route("/api/report", get(routes::report::api_report))
        .route("/report.pdf", get(routes::report::download_pdf))
        .route("/ws/threats", get(routes::ws::ws_threats))
        .route(
            "/api/baseline/reset",
            post(routes::baseline::api_baseline_reset),
        )
        .route(
            "/api/baseline/create",
            post(routes::baseline::api_baseline_create),
        )
        .route(
            "/api/file-integrity/toggle",
            post(routes::baseline::api_fi_toggle),
        )
        .route("/api/logs", get(routes::logs::api_logs))
        .layer(middleware::from_fn_with_state(ctx.clone(), auth_middleware))
        .layer(RateLimitLayer::new())
        .layer(cors)
        .with_state(ctx);

    let bind_addr = format!("{}:{}", dashboard_config.bind, dashboard_config.port);
    info!(addr = %bind_addr, "Starting web dashboard");

    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            cancel.cancelled().await;
        })
        .await?;

    Ok(())
}
