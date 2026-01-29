//! API routes.

pub mod health;
pub mod incidents;
pub mod metrics;
pub mod webhooks;

use axum::Router;
use crate::state::AppState;

/// Creates the main API router.
pub fn create_router(state: AppState) -> Router {
    Router::new()
        .nest("/api", api_routes())
        .merge(health::routes())
        .merge(metrics::routes())
        .with_state(state)
}

/// API routes under /api prefix.
fn api_routes() -> Router<AppState> {
    Router::new()
        .nest("/incidents", incidents::routes())
        .nest("/webhooks", webhooks::routes())
}
