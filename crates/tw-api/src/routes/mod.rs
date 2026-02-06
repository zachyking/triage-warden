//! API routes.

pub mod activity;
pub mod analytics;
pub mod api_keys;
pub mod assets;
pub mod auth;
pub mod autonomy;
pub mod comments;
pub mod connectors;
pub mod features;
pub mod feedback;
pub mod handoff;
pub mod health;
pub mod hunting;
pub mod identities;
pub mod incidents;
pub mod iocs;
pub mod kill_switch;
pub mod knowledge;
pub mod lessons;
pub mod metrics;
pub mod nl_query;
pub mod notifications;
pub mod packages;
pub mod playbooks;
pub mod policies;
pub mod reports;
pub mod risk;
pub mod settings;
pub mod training;
pub mod users;
pub mod webhooks;

use crate::state::AppState;
use axum::Router;

/// Creates the main API router.
pub fn create_router(state: AppState) -> Router {
    Router::new()
        // Versioned API endpoint
        .nest("/api/v1", api_routes())
        // Legacy unversioned endpoint (deprecated, will be removed in future versions)
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
        .nest("/admin/features", features::routes())
        .nest("/api-keys", api_keys::routes())
        .nest("/connectors", connectors::routes())
        .nest("/feedback", feedback::routes())
        .nest("/incidents", incidents::routes())
        .nest(
            "/incidents/:incident_id/feedback",
            feedback::incident_feedback_routes(),
        )
        .nest("/kill-switch", kill_switch::routes())
        .nest("/notifications", notifications::routes())
        .nest("/playbooks", playbooks::routes())
        .nest("/policies", policies::routes())
        .nest("/settings", settings::routes())
        .nest("/training", training::routes())
        .nest("/knowledge", knowledge::routes())
        .nest("/webhooks", webhooks::routes())
        .nest("/assets", assets::routes())
        .nest("/identities", identities::routes())
        .nest("/iocs", iocs::routes())
        .nest("/lessons", lessons::routes())
        .nest(
            "/incidents/:incident_id/lessons",
            lessons::incident_lessons_routes(),
        )
        .nest("/analytics", analytics::routes())
        .nest("/autonomy", autonomy::routes())
        .nest("/hunts", hunting::routes())
        .nest("/nl", nl_query::routes())
        .nest("/packages", packages::routes())
        .nest("/risk", risk::routes())
        .nest("/comments", comments::routes())
        .nest("/activity", activity::routes())
        .nest("/handoffs", handoff::routes())
}
