//! API routes.

pub mod activity;
pub mod analytics;
pub mod api_keys;
pub mod assets;
pub mod audit;
pub mod auth;
pub mod autonomy;
pub mod comments;
pub mod compliance;
pub mod connectors;
pub mod features;
pub mod feedback;
pub mod guardrails;
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
pub mod privacy;
pub mod reports;
pub mod risk;
pub mod roles;
pub mod settings;
pub mod training;
pub mod users;
pub mod webhooks;

use crate::auth::RequireAnalyst;
use crate::middleware::{AuthorizationState, PermissionRequirement};
use crate::state::AppState;
use axum::{
    extract::Request,
    middleware::{from_fn_with_state, Next},
    response::Response,
    Router,
};
use tw_core::rbac::{Action as RbacAction, Resource as RbacResource};

/// Creates the main API router.
pub fn create_router(state: AppState) -> Router {
    Router::new()
        // Versioned API endpoint
        .nest("/api/v1", api_routes(state.clone()))
        // Legacy unversioned endpoint (deprecated, will be removed in future versions)
        .nest("/api", api_routes(state.clone()))
        .merge(health::routes())
        .merge(metrics::routes())
        .merge(auth::routes())
        .with_state(state)
}

/// API routes under /api prefix.
fn api_routes(state: AppState) -> Router<AppState> {
    Router::new()
        .nest(
            "/admin/users",
            with_permission(
                users::routes(),
                state.clone(),
                RbacResource::User,
                RbacAction::Manage,
            ),
        )
        .nest(
            "/admin/features",
            with_permission(
                features::routes(),
                state.clone(),
                RbacResource::Settings,
                RbacAction::Manage,
            ),
        )
        .nest(
            "/api-keys",
            with_permission(
                api_keys::routes(),
                state.clone(),
                RbacResource::ApiKey,
                RbacAction::Manage,
            ),
        )
        .nest(
            "/roles",
            with_permission(
                roles::routes(),
                state.clone(),
                RbacResource::Role,
                RbacAction::Manage,
            ),
        )
        .nest(
            "/connectors",
            with_permission(
                connectors::routes(),
                state.clone(),
                RbacResource::Connector,
                RbacAction::Read,
            ),
        )
        .nest(
            "/audit",
            with_permission(
                audit::routes(),
                state.clone(),
                RbacResource::AuditLog,
                RbacAction::Read,
            ),
        )
        .nest(
            "/compliance",
            with_permission(
                compliance::routes(),
                state.clone(),
                RbacResource::Compliance,
                RbacAction::Read,
            ),
        )
        .nest(
            "/feedback",
            with_permission(
                feedback::routes(),
                state.clone(),
                RbacResource::Incident,
                RbacAction::Read,
            ),
        )
        .nest(
            "/incidents",
            with_permission(
                incidents::routes(),
                state.clone(),
                RbacResource::Incident,
                RbacAction::Read,
            ),
        )
        .nest(
            "/incidents/:incident_id/feedback",
            with_permission(
                feedback::incident_feedback_routes(),
                state.clone(),
                RbacResource::Incident,
                RbacAction::Read,
            ),
        )
        .nest(
            "/kill-switch",
            with_permission(
                kill_switch::routes(),
                state.clone(),
                RbacResource::Guardrail,
                RbacAction::Read,
            ),
        )
        .nest(
            "/guardrails",
            with_permission(
                guardrails::routes(),
                state.clone(),
                RbacResource::Guardrail,
                RbacAction::Read,
            ),
        )
        .nest(
            "/notifications",
            with_permission(
                notifications::routes().route_layer(from_fn_with_state(
                    state.clone(),
                    require_analyst_middleware,
                )),
                state.clone(),
                RbacResource::Incident,
                RbacAction::Read,
            ),
        )
        .nest(
            "/playbooks",
            with_permission(
                playbooks::routes(),
                state.clone(),
                RbacResource::Playbook,
                RbacAction::Read,
            ),
        )
        .nest(
            "/policies",
            with_permission(
                policies::routes().route_layer(from_fn_with_state(
                    state.clone(),
                    require_analyst_middleware,
                )),
                state.clone(),
                RbacResource::Policy,
                RbacAction::Read,
            ),
        )
        .nest(
            "/privacy",
            with_permission(
                privacy::routes(),
                state.clone(),
                RbacResource::Privacy,
                RbacAction::Read,
            ),
        )
        .nest(
            "/settings",
            with_permission(
                settings::routes(),
                state.clone(),
                RbacResource::Settings,
                RbacAction::Read,
            ),
        )
        .nest(
            "/training",
            with_permission(
                training::routes(),
                state.clone(),
                RbacResource::Incident,
                RbacAction::Read,
            ),
        )
        .nest(
            "/knowledge",
            with_permission(
                knowledge::routes(),
                state.clone(),
                RbacResource::KnowledgeBase,
                RbacAction::Read,
            ),
        )
        .nest("/webhooks", webhooks::routes())
        .nest(
            "/assets",
            with_permission(
                assets::routes(),
                state.clone(),
                RbacResource::Incident,
                RbacAction::Read,
            ),
        )
        .nest(
            "/identities",
            with_permission(
                identities::routes(),
                state.clone(),
                RbacResource::Incident,
                RbacAction::Read,
            ),
        )
        .nest(
            "/iocs",
            with_permission(
                iocs::routes(),
                state.clone(),
                RbacResource::Incident,
                RbacAction::Read,
            ),
        )
        .nest(
            "/lessons",
            with_permission(
                lessons::routes(),
                state.clone(),
                RbacResource::Incident,
                RbacAction::Read,
            ),
        )
        .nest(
            "/incidents/:incident_id/lessons",
            with_permission(
                lessons::incident_lessons_routes(),
                state.clone(),
                RbacResource::Incident,
                RbacAction::Read,
            ),
        )
        .nest(
            "/analytics",
            with_permission(
                analytics::routes(),
                state.clone(),
                RbacResource::Compliance,
                RbacAction::Read,
            ),
        )
        .nest(
            "/autonomy",
            with_permission(
                autonomy::routes(),
                state.clone(),
                RbacResource::Guardrail,
                RbacAction::Read,
            ),
        )
        .nest(
            "/hunts",
            with_permission(
                hunting::routes(),
                state.clone(),
                RbacResource::Hunt,
                RbacAction::Read,
            ),
        )
        .nest(
            "/nl",
            with_permission(
                nl_query::routes(),
                state.clone(),
                RbacResource::Incident,
                RbacAction::Read,
            ),
        )
        .nest(
            "/packages",
            with_permission(
                packages::routes(),
                state.clone(),
                RbacResource::Playbook,
                RbacAction::Read,
            ),
        )
        .nest(
            "/risk",
            with_permission(
                risk::routes(),
                state.clone(),
                RbacResource::Compliance,
                RbacAction::Read,
            ),
        )
        .nest(
            "/comments",
            with_permission(
                comments::routes(),
                state.clone(),
                RbacResource::Incident,
                RbacAction::Read,
            ),
        )
        .nest(
            "/activity",
            with_permission(
                activity::routes(),
                state.clone(),
                RbacResource::Incident,
                RbacAction::Read,
            ),
        )
        .nest(
            "/handoffs",
            with_permission(
                handoff::routes(),
                state,
                RbacResource::Incident,
                RbacAction::Read,
            ),
        )
}

fn with_permission(
    routes: Router<AppState>,
    state: AppState,
    resource: RbacResource,
    action: RbacAction,
) -> Router<AppState> {
    routes.route_layer(from_fn_with_state(
        AuthorizationState {
            app_state: state,
            requirement: PermissionRequirement::new(resource, action),
        },
        crate::middleware::require_permission_middleware,
    ))
}

async fn require_analyst_middleware(
    RequireAnalyst(_user): RequireAnalyst,
    request: Request,
    next: Next,
) -> Response {
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::create_test_state;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_kill_switch_status_requires_authentication() {
        let state = create_test_state().await;
        let app = create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/kill-switch")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
