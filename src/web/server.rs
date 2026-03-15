use std::sync::Arc;

use anyhow::Result;
use axum::{
    middleware,
    routing::{delete, get, post},
    Router,
};
use tokio::sync::RwLock;
use tracing::info;

use crate::alerting::AlertManager;
use crate::config::schema::{AegisConfig, DashboardConfig};
use crate::core::event_bus::EventBus;
use crate::core::state::AppState;
use crate::response::ResponseEngine;
use crate::storage::Storage;

use super::auth::auth_middleware;
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

    let ctx = AppContext {
        state,
        config,
        response_engine,
        alert_manager,
        storage,
        event_bus,
        api_token,
    };

    let app = Router::new()
        // HTML pages
        .route("/", get(routes::dashboard::dashboard_page))
        .route("/threats", get(routes::threats::threats_page))
        .route("/firewall", get(routes::firewall::firewall_page))
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
        .route("/api/config", get(routes::config::api_config))
        .route("/api/scan", post(routes::scan::api_scan))
        .route("/api/respond", post(routes::scan::api_respond))
        .route("/api/stats", get(routes::dashboard::api_stats))
        .route("/api/report", get(routes::report::api_report))
        .route("/report.pdf", get(routes::report::download_pdf))
        .route("/ws/threats", get(routes::ws::ws_threats))
        .route(
            "/api/baseline/reset",
            post(routes::baseline::api_baseline_reset),
        )
        .route(
            "/api/file-integrity/toggle",
            post(routes::baseline::api_fi_toggle),
        )
        .layer(middleware::from_fn_with_state(ctx.clone(), auth_middleware))
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
