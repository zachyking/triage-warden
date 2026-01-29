//! Health check endpoints.

use axum::{extract::State, routing::get, Json, Router};
use std::time::Instant;

use crate::dto::{DatabaseHealth, HealthResponse};
use crate::state::AppState;

/// Start time for uptime calculation.
static START_TIME: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

/// Initialize the start time.
pub fn init_start_time() {
    START_TIME.get_or_init(Instant::now);
}

/// Creates health check routes.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/health", get(health_check))
        .route("/ready", get(readiness_check))
        .route("/live", get(liveness_check))
}

/// Health check endpoint.
///
/// Returns overall system health status.
#[utoipa::path(
    get,
    path = "/health",
    responses(
        (status = 200, description = "System is healthy", body = HealthResponse),
        (status = 503, description = "System is unhealthy")
    ),
    tag = "Health"
)]
async fn health_check(State(state): State<AppState>) -> Json<HealthResponse> {
    let db_healthy = state.db.is_healthy().await;
    let uptime = START_TIME.get().map(|t| t.elapsed().as_secs()).unwrap_or(0);

    let status = if db_healthy { "healthy" } else { "degraded" };

    Json(HealthResponse {
        status: status.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        database: DatabaseHealth {
            connected: db_healthy,
            pool_size: state.db.pool_size(),
            idle_connections: state.db.idle_connections(),
        },
        uptime_seconds: uptime,
    })
}

/// Kubernetes readiness probe.
///
/// Returns 200 if the service is ready to accept traffic.
#[utoipa::path(
    get,
    path = "/ready",
    responses(
        (status = 200, description = "Service is ready"),
        (status = 503, description = "Service is not ready")
    ),
    tag = "Health"
)]
async fn readiness_check(State(state): State<AppState>) -> axum::http::StatusCode {
    if state.db.is_healthy().await {
        axum::http::StatusCode::OK
    } else {
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    }
}

/// Kubernetes liveness probe.
///
/// Returns 200 if the service is alive.
#[utoipa::path(
    get,
    path = "/live",
    responses(
        (status = 200, description = "Service is alive")
    ),
    tag = "Health"
)]
async fn liveness_check() -> axum::http::StatusCode {
    axum::http::StatusCode::OK
}
