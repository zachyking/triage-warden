//! API routes.

pub mod api_keys;
pub mod auth;
pub mod connectors;
pub mod health;
pub mod incidents;
pub mod kill_switch;
pub mod metrics;
pub mod notifications;
pub mod playbooks;
pub mod policies;
pub mod settings;
pub mod users;
pub mod webhooks;

use crate::state::AppState;
use axum::Router;

/// Creates the main API router.
pub fn create_router(state: AppState) -> Router {
    Router::new()
        .nest("/api", api_routes())
        .merge(health::routes())
        .merge(metrics::routes())
        .merge(auth::routes())
        .with_state(state)
}

/// API routes under /api prefix.
fn api_routes() -> Router<AppState> {
    Router::new()
        .nest("/admin/users", users::routes())
        .nest("/api-keys", api_keys::routes())
        .nest("/connectors", connectors::routes())
        .nest("/incidents", incidents::routes())
        .nest("/kill-switch", kill_switch::routes())
        .nest("/notifications", notifications::routes())
        .nest("/playbooks", playbooks::routes())
        .nest("/policies", policies::routes())
        .nest("/settings", settings::routes())
        .nest("/webhooks", webhooks::routes())
}
