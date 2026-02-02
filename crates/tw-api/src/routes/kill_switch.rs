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

use crate::auth::AuthenticatedUser;
use crate::state::AppState;

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
