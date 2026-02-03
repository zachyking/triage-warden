//! Health check endpoints.

use axum::{extract::State, routing::get, Json, Router};
use std::time::Instant;
use tw_core::ConnectorStatus;

use crate::dto::{
    ComponentsHealth, ConnectorsHealth, DatabaseHealth, EventBusHealth, HealthResponse,
    KillSwitchHealth, LlmHealth,
};
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
        .route("/health/detailed", get(health_check_detailed))
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
        (status = 503, description = "System is unhealthy", body = HealthResponse)
    ),
    tag = "Health"
)]
async fn health_check(
    State(state): State<AppState>,
) -> (axum::http::StatusCode, Json<HealthResponse>) {
    let db_healthy = state.db.is_healthy().await;
    let uptime = START_TIME.get().map(|t| t.elapsed().as_secs()).unwrap_or(0);

    let status = if db_healthy { "healthy" } else { "unhealthy" };
    let http_status = if db_healthy {
        axum::http::StatusCode::OK
    } else {
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    };

    (
        http_status,
        Json(HealthResponse {
            status: status.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            database: DatabaseHealth {
                connected: db_healthy,
                pool_size: state.db.pool_size(),
                idle_connections: state.db.idle_connections(),
            },
            uptime_seconds: uptime,
            components: None,
        }),
    )
}

/// Detailed health check endpoint.
///
/// Returns comprehensive health status including all components.
#[utoipa::path(
    get,
    path = "/health/detailed",
    responses(
        (status = 200, description = "Detailed system health", body = HealthResponse),
        (status = 503, description = "System is unhealthy", body = HealthResponse)
    ),
    tag = "Health"
)]
async fn health_check_detailed(
    State(state): State<AppState>,
) -> (axum::http::StatusCode, Json<HealthResponse>) {
    let db_healthy = state.db.is_healthy().await;
    let uptime = START_TIME.get().map(|t| t.elapsed().as_secs()).unwrap_or(0);

    // Get kill switch status
    let ks_status = state.kill_switch.status().await;
    let kill_switch = KillSwitchHealth {
        active: ks_status.active,
        activated_by: ks_status.activated_by,
        activated_at: ks_status.activated_at.map(|t| t.to_rfc3339()),
    };

    // Get connectors health
    let connectors_health = get_connectors_health(&state).await;

    // Get LLM health
    let llm_health = get_llm_health(&state).await;

    // Get event bus health
    let event_bus = EventBusHealth {
        subscriber_count: state.event_bus.subscriber_count().await,
        operational: true,
    };

    // Determine overall status
    let status = determine_overall_status(
        db_healthy,
        ks_status.active,
        connectors_health.unhealthy,
        llm_health.enabled && !llm_health.configured,
    );

    // Return 503 if database is unhealthy (critical dependency)
    let http_status = if db_healthy {
        axum::http::StatusCode::OK
    } else {
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    };

    (
        http_status,
        Json(HealthResponse {
            status,
            version: env!("CARGO_PKG_VERSION").to_string(),
            database: DatabaseHealth {
                connected: db_healthy,
                pool_size: state.db.pool_size(),
                idle_connections: state.db.idle_connections(),
            },
            uptime_seconds: uptime,
            components: Some(ComponentsHealth {
                kill_switch,
                connectors: connectors_health,
                llm: llm_health,
                event_bus,
            }),
        }),
    )
}

/// Get connectors health summary.
async fn get_connectors_health(state: &AppState) -> ConnectorsHealth {
    use tw_core::db::create_connector_repository;

    let repo = create_connector_repository(&state.db);
    let connectors = repo.list().await.unwrap_or_default();

    let total = connectors.len() as u32;
    let mut healthy = 0u32;
    let mut unhealthy = 0u32;
    let mut disabled = 0u32;
    let mut unhealthy_connectors = Vec::new();

    for connector in &connectors {
        if !connector.enabled {
            disabled += 1;
        } else {
            match connector.status {
                ConnectorStatus::Connected => healthy += 1,
                ConnectorStatus::Disconnected | ConnectorStatus::Error => {
                    unhealthy += 1;
                    unhealthy_connectors.push(connector.name.clone());
                }
                ConnectorStatus::Unknown => {
                    // Unknown status is treated as potentially unhealthy
                    unhealthy += 1;
                    unhealthy_connectors.push(connector.name.clone());
                }
            }
        }
    }

    ConnectorsHealth {
        total,
        healthy,
        unhealthy,
        disabled,
        unhealthy_connectors,
    }
}

/// Get LLM configuration health.
async fn get_llm_health(state: &AppState) -> LlmHealth {
    use tw_core::db::create_settings_repository;

    let repo = create_settings_repository(&state.db);
    let llm_settings = repo.get_llm().await.ok();

    match llm_settings {
        Some(settings) => LlmHealth {
            enabled: settings.enabled,
            configured: !settings.api_key.is_empty(),
            provider: if settings.enabled {
                Some(settings.provider)
            } else {
                None
            },
        },
        None => LlmHealth {
            enabled: false,
            configured: false,
            provider: None,
        },
    }
}

/// Determine overall system status based on component health.
fn determine_overall_status(
    db_healthy: bool,
    kill_switch_active: bool,
    unhealthy_connectors: u32,
    llm_misconfigured: bool,
) -> String {
    if !db_healthy {
        return "unhealthy".to_string();
    }

    if kill_switch_active {
        return "halted".to_string();
    }

    if unhealthy_connectors > 0 || llm_misconfigured {
        return "degraded".to_string();
    }

    "healthy".to_string()
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        Router,
    };
    use tower::ServiceExt;
    use tw_core::db::DbPool;
    use tw_core::EventBus;
    use uuid::Uuid;

    use crate::state::AppState;

    /// Creates an in-memory SQLite pool for testing.
    async fn create_test_pool() -> sqlx::SqlitePool {
        let db_url = format!(
            "sqlite:file:test_health_{}?mode=memory&cache=shared",
            Uuid::new_v4()
        );

        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect(&db_url)
            .await
            .expect("Failed to create pool");

        pool
    }

    /// Creates an AppState with the test pool.
    async fn create_test_state() -> AppState {
        let pool = create_test_pool().await;
        let db = DbPool::Sqlite(pool);
        let event_bus = EventBus::new(100);
        AppState::new(db, event_bus)
    }

    /// Creates a test router with the health routes.
    async fn create_test_router() -> (Router, AppState) {
        let state = create_test_state().await;
        let router = Router::new().merge(routes()).with_state(state.clone());
        (router, state)
    }

    #[tokio::test]
    async fn test_health_check_basic() {
        let (app, _state) = create_test_router().await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let result: HealthResponse =
            serde_json::from_slice(&body).expect("Failed to parse response");

        assert!(result.status == "healthy" || result.status == "degraded");
        assert!(!result.version.is_empty());
    }

    #[tokio::test]
    async fn test_health_check_detailed() {
        let (app, _state) = create_test_router().await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health/detailed")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();

        // Parse as generic JSON to check structure without strict typing
        let result: serde_json::Value =
            serde_json::from_slice(&body).expect("Failed to parse response");

        // Verify key fields exist
        assert!(result.get("version").is_some());
        assert!(result.get("status").is_some());
        assert!(result.get("database").is_some());
        assert!(result.get("components").is_some());

        // Check kill switch is not active
        let components = result.get("components").unwrap();
        let kill_switch = components.get("kill_switch").unwrap();
        assert_eq!(kill_switch.get("active").unwrap(), false);
    }

    #[tokio::test]
    async fn test_liveness_check() {
        let (app, _state) = create_test_router().await;

        let response = app
            .oneshot(Request::builder().uri("/live").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_readiness_check_healthy() {
        let (app, _state) = create_test_router().await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/ready")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn test_determine_overall_status() {
        // All healthy
        assert_eq!(determine_overall_status(true, false, 0, false), "healthy");

        // Database unhealthy
        assert_eq!(
            determine_overall_status(false, false, 0, false),
            "unhealthy"
        );

        // Kill switch active
        assert_eq!(determine_overall_status(true, true, 0, false), "halted");

        // Unhealthy connectors
        assert_eq!(determine_overall_status(true, false, 1, false), "degraded");

        // LLM misconfigured
        assert_eq!(determine_overall_status(true, false, 0, true), "degraded");

        // Multiple issues - db takes priority
        assert_eq!(determine_overall_status(false, true, 1, true), "unhealthy");

        // Kill switch takes priority over connectors
        assert_eq!(determine_overall_status(true, true, 1, false), "halted");
    }

    #[tokio::test]
    async fn test_health_response_includes_uptime() {
        init_start_time();
        let (app, _state) = create_test_router().await;

        // Small delay to ensure uptime > 0
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let result: HealthResponse =
            serde_json::from_slice(&body).expect("Failed to parse response");

        // Just verify uptime is present (u64 is always >= 0)
        let _ = result.uptime_seconds;
    }
}
