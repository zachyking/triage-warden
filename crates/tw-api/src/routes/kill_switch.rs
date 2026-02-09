//! Kill switch API routes.
//!
//! These routes provide emergency control over the automation system,
//! allowing operators to immediately halt all automated actions.

use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::warn;

use crate::auth::AuthenticatedUser;
use crate::state::AppState;
use tw_core::auth::Role;
use tw_core::db::create_rbac_repository;
use tw_core::rbac::{
    builtin_roles, Action as RbacAction, AuthorizationRequest, Permission as RbacPermission,
    PermissionEvaluator, Resource as RbacResource,
};

/// Response for kill switch status.
#[derive(Debug, Serialize, Deserialize)]
pub struct KillSwitchStatusResponse {
    /// Whether the kill switch is currently active.
    pub active: bool,
    /// When the kill switch was activated (ISO 8601 format).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activated_at: Option<String>,
    /// Who activated the kill switch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activated_by: Option<String>,
}

/// Request to activate the kill switch.
#[derive(Debug, Deserialize)]
pub struct ActivateRequest {
    /// Optional reason for activating the kill switch.
    #[serde(default)]
    pub reason: Option<String>,
}

/// Request to deactivate the kill switch.
#[derive(Debug, Deserialize)]
pub struct DeactivateRequest {
    /// Optional reason for deactivating the kill switch.
    #[serde(default)]
    pub reason: Option<String>,
}

/// Response for kill switch operations.
#[derive(Debug, Serialize)]
pub struct KillSwitchOperationResponse {
    /// Whether the operation was successful.
    pub success: bool,
    /// Message describing the result.
    pub message: String,
    /// Current status after the operation.
    pub status: KillSwitchStatusResponse,
}

/// Creates the kill switch router.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(get_status))
        .route("/activate", post(activate))
        .route("/deactivate", post(deactivate))
}

/// Gets the current status of the kill switch.
#[axum::debug_handler]
async fn get_status(State(state): State<AppState>) -> Json<KillSwitchStatusResponse> {
    let status = state.kill_switch.status().await;

    Json(KillSwitchStatusResponse {
        active: status.active,
        activated_at: status.activated_at.map(|t| t.to_rfc3339()),
        activated_by: status.activated_by,
    })
}

/// Activates the kill switch, halting all automation.
#[axum::debug_handler]
async fn activate(
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
    Json(request): Json<ActivateRequest>,
) -> Result<Json<KillSwitchOperationResponse>, (StatusCode, Json<KillSwitchOperationResponse>)> {
    if let Err(reason) = authorize_kill_switch_operation(&state, &user).await {
        let status = state.kill_switch.status().await;
        return Err((
            StatusCode::FORBIDDEN,
            Json(KillSwitchOperationResponse {
                success: false,
                message: reason,
                status: KillSwitchStatusResponse {
                    active: status.active,
                    activated_at: status.activated_at.map(|t| t.to_rfc3339()),
                    activated_by: status.activated_by,
                },
            }),
        ));
    }

    let activated_by = if let Some(reason) = request.reason {
        format!("{} ({})", user.username, reason)
    } else {
        user.username.clone()
    };

    match state.kill_switch.activate(&activated_by).await {
        Ok(()) => {
            let status = state.kill_switch.status().await;
            Ok(Json(KillSwitchOperationResponse {
                success: true,
                message: "Kill switch activated. All automation has been halted.".to_string(),
                status: KillSwitchStatusResponse {
                    active: status.active,
                    activated_at: status.activated_at.map(|t| t.to_rfc3339()),
                    activated_by: status.activated_by,
                },
            }))
        }
        Err(e) => {
            let status = state.kill_switch.status().await;
            Err((
                StatusCode::CONFLICT,
                Json(KillSwitchOperationResponse {
                    success: false,
                    message: format!("Failed to activate: {}", e),
                    status: KillSwitchStatusResponse {
                        active: status.active,
                        activated_at: status.activated_at.map(|t| t.to_rfc3339()),
                        activated_by: status.activated_by,
                    },
                }),
            ))
        }
    }
}

/// Deactivates the kill switch, allowing automation to resume.
#[axum::debug_handler]
async fn deactivate(
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
    Json(request): Json<DeactivateRequest>,
) -> Result<Json<KillSwitchOperationResponse>, (StatusCode, Json<KillSwitchOperationResponse>)> {
    if let Err(reason) = authorize_kill_switch_operation(&state, &user).await {
        let status = state.kill_switch.status().await;
        return Err((
            StatusCode::FORBIDDEN,
            Json(KillSwitchOperationResponse {
                success: false,
                message: reason,
                status: KillSwitchStatusResponse {
                    active: status.active,
                    activated_at: status.activated_at.map(|t| t.to_rfc3339()),
                    activated_by: status.activated_by,
                },
            }),
        ));
    }

    let deactivated_by = if let Some(reason) = request.reason {
        format!("{} ({})", user.username, reason)
    } else {
        user.username.clone()
    };

    match state.kill_switch.deactivate(&deactivated_by).await {
        Ok(()) => {
            let status = state.kill_switch.status().await;
            Ok(Json(KillSwitchOperationResponse {
                success: true,
                message: "Kill switch deactivated. Automation may now resume.".to_string(),
                status: KillSwitchStatusResponse {
                    active: status.active,
                    activated_at: status.activated_at.map(|t| t.to_rfc3339()),
                    activated_by: status.activated_by,
                },
            }))
        }
        Err(e) => {
            let status = state.kill_switch.status().await;
            Err((
                StatusCode::CONFLICT,
                Json(KillSwitchOperationResponse {
                    success: false,
                    message: format!("Failed to deactivate: {}", e),
                    status: KillSwitchStatusResponse {
                        active: status.active,
                        activated_at: status.activated_at.map(|t| t.to_rfc3339()),
                        activated_by: status.activated_by,
                    },
                }),
            ))
        }
    }
}

async fn authorize_kill_switch_operation(
    state: &AppState,
    user: &tw_core::User,
) -> Result<(), String> {
    let mut effective_permissions = builtin_permissions_for_role(user.role, user.tenant_id);
    let rbac_repo = create_rbac_repository(&state.db);
    let custom_permissions = rbac_repo
        .get_user_permissions(user.tenant_id, user.id)
        .await
        .map_err(|e| format!("Failed to evaluate RBAC permissions: {e}"))?;
    effective_permissions.extend(custom_permissions);

    let request = AuthorizationRequest {
        user_id: user.id,
        tenant_id: user.tenant_id,
        resource: RbacResource::Guardrail,
        action: RbacAction::Manage,
        context: HashMap::new(),
    };
    let decision = PermissionEvaluator.evaluate(&effective_permissions, &request);
    if !decision.allowed {
        warn!(
            user_id = %user.id,
            tenant_id = %user.tenant_id,
            role = %user.role,
            reason = ?decision.reason,
            "Kill switch operation denied by RBAC"
        );
        return Err("Missing permission guardrail:manage".to_string());
    }

    Ok(())
}

fn builtin_permissions_for_role(role: Role, tenant_id: uuid::Uuid) -> Vec<RbacPermission> {
    let roles = builtin_roles(Some(tenant_id));
    let role_name = match role {
        Role::Admin => "tenant_admin",
        Role::Analyst => "analyst",
        Role::Viewer => "viewer",
    };
    roles
        .into_iter()
        .find(|candidate| candidate.name == role_name)
        .map(|matched| matched.permissions)
        .unwrap_or_default()
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

    async fn create_test_router() -> Router {
        let state = create_test_state().await;
        Router::new()
            .nest("/kill-switch", routes())
            .with_state(state)
    }

    #[tokio::test]
    async fn test_get_status_initially_inactive() {
        let app = create_test_router().await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/kill-switch")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let status: KillSwitchStatusResponse = serde_json::from_slice(&body).unwrap();

        assert!(!status.active);
        assert!(status.activated_at.is_none());
        assert!(status.activated_by.is_none());
    }
}
