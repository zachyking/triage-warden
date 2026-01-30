//! API server implementation.

use axum::{middleware, Router};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::signal;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;
use tracing::info;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

#[allow(unused_imports)]
use crate::dto::*;
use crate::error::ErrorResponse;
use crate::middleware::{cors_layer, request_id, request_logging, security_headers};
use crate::routes;
use crate::state::AppState;
use crate::web;

/// API server configuration.
#[derive(Debug, Clone)]
pub struct ApiServerConfig {
    /// Address to bind to.
    pub bind_address: SocketAddr,
    /// Request timeout.
    pub request_timeout: Duration,
    /// Enable Swagger UI.
    pub enable_swagger: bool,
    /// Shutdown timeout for graceful shutdown.
    pub shutdown_timeout: Duration,
}

impl Default for ApiServerConfig {
    fn default() -> Self {
        Self {
            bind_address: SocketAddr::from(([0, 0, 0, 0], 8080)),
            request_timeout: Duration::from_secs(30),
            enable_swagger: true,
            shutdown_timeout: Duration::from_secs(30),
        }
    }
}

/// OpenAPI documentation.
#[derive(OpenApi)]
#[openapi(
    paths(
        crate::routes::health::health_check,
        crate::routes::health::readiness_check,
        crate::routes::health::liveness_check,
        crate::routes::incidents::list_incidents,
        crate::routes::incidents::get_incident,
        crate::routes::incidents::execute_action,
        crate::routes::incidents::approve_action,
        crate::routes::webhooks::receive_alert,
        crate::routes::webhooks::receive_alert_from_source,
        crate::routes::metrics::prometheus_metrics,
        crate::routes::metrics::json_metrics,
    ),
    components(
        schemas(
            HealthResponse,
            DatabaseHealth,
            IncidentResponse,
            IncidentDetailResponse,
            EnrichmentResponse,
            AnalysisResponse,
            MitreTechniqueResponse,
            IoCResponse,
            ActionResponse,
            AuditEntryResponse,
            PaginationInfo,
            ExecuteActionRequest,
            ActionTargetDto,
            ApproveActionRequest,
            ActionExecutionResponse,
            WebhookAlertPayload,
            WebhookAcceptedResponse,
            MetricsResponse,
            IncidentMetrics,
            ActionMetrics,
            PerformanceMetrics,
            ErrorResponse,
        )
    ),
    tags(
        (name = "Health", description = "Health check endpoints"),
        (name = "Incidents", description = "Incident management"),
        (name = "Webhooks", description = "Alert ingestion via webhooks"),
        (name = "Metrics", description = "System metrics"),
    ),
    info(
        title = "Triage Warden API",
        version = "0.1.0",
        description = "AI-Augmented SOC API for incident triage and response",
        license(name = "MIT"),
    )
)]
pub struct ApiDoc;

/// API server.
pub struct ApiServer {
    config: ApiServerConfig,
    state: AppState,
}

impl ApiServer {
    /// Creates a new API server.
    pub fn new(state: AppState, config: ApiServerConfig) -> Self {
        Self { config, state }
    }

    /// Creates a new API server with default configuration.
    pub fn with_state(state: AppState) -> Self {
        Self::new(state, ApiServerConfig::default())
    }

    /// Builds the router.
    pub fn router(&self) -> Router {
        // Initialize start time for uptime calculation
        routes::health::init_start_time();

        // Build the main router with API routes
        let mut app = routes::create_router(self.state.clone());

        // Merge web dashboard routes
        app = app.merge(web::create_web_router(self.state.clone()));

        // Add Swagger UI if enabled
        if self.config.enable_swagger {
            app = app.merge(
                SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()),
            );
        }

        // Add static file serving
        let static_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("static");

        // Serve static files (CSS, JS, images)
        app = app.nest_service("/static", ServeDir::new(static_path));

        // Apply middleware (order matters: innermost first)
        app
            // Security headers
            .layer(middleware::from_fn(security_headers))
            // Request logging
            .layer(middleware::from_fn(request_logging))
            // Request ID
            .layer(middleware::from_fn(request_id))
            // Tracing
            .layer(TraceLayer::new_for_http())
            // CORS
            .layer(cors_layer())
            // Catch panics and return 500
            .layer(CatchPanicLayer::new())
    }

    /// Runs the server.
    pub async fn run(self) -> Result<(), std::io::Error> {
        let app = self.router();
        let addr = self.config.bind_address;

        info!("Starting API server on {}", addr);

        let listener = TcpListener::bind(addr).await?;

        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal())
            .await?;

        info!("API server shut down gracefully");
        Ok(())
    }

    /// Runs the server with a custom shutdown signal.
    pub async fn run_until<F>(self, shutdown: F) -> Result<(), std::io::Error>
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let app = self.router();
        let addr = self.config.bind_address;

        info!("Starting API server on {}", addr);

        let listener = TcpListener::bind(addr).await?;

        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown)
            .await?;

        info!("API server shut down gracefully");
        Ok(())
    }
}

/// Default shutdown signal handler.
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("Received Ctrl+C, initiating graceful shutdown");
        }
        _ = terminate => {
            info!("Received SIGTERM, initiating graceful shutdown");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tw_core::db::create_pool;
    use tw_core::EventBus;

    #[tokio::test]
    async fn test_router_creation() {
        // Create in-memory SQLite for testing
        let pool = create_pool("sqlite::memory:").await.unwrap();
        let event_bus = EventBus::new(100);
        let state = AppState::new(pool, event_bus);

        let server = ApiServer::with_state(state);
        let _router = server.router();

        // Just verify router builds without error
    }
}
