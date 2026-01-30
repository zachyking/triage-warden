//! Policy management endpoints.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Form, Json, Router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;
use crate::state::AppState;
use tw_core::db::{create_policy_repository, PolicyRepository, PolicyUpdate};
use tw_core::policy::{ApprovalLevel, Policy, PolicyAction};

/// Creates policy routes.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(list_policies).post(create_policy))
        .route(
            "/{id}",
            get(get_policy).put(update_policy).delete(delete_policy),
        )
        .route("/{id}/toggle", post(toggle_policy))
}

/// Request to create a policy from the modal form.
#[derive(Debug, Deserialize)]
pub struct CreatePolicyRequest {
    /// Policy name.
    pub name: String,
    /// Optional description.
    pub description: Option<String>,
    /// Condition type (severity, action_type, target_pattern, asset_criticality).
    pub condition_type: Option<String>,
    /// Condition value.
    pub condition_value: Option<String>,
    /// Combined condition expression (alternative to condition_type + condition_value).
    pub condition: Option<String>,
    /// Approval type: "auto", "single", "dual", "manager".
    pub requires: Option<String>,
    /// Alternative field name for approval.
    pub approval: Option<String>,
    /// Priority (lower = higher priority).
    pub priority: Option<i32>,
    /// Whether the policy is enabled.
    pub enabled: Option<String>,
}

/// Request to update a policy.
#[derive(Debug, Deserialize)]
pub struct UpdatePolicyRequest {
    /// Policy name.
    pub name: Option<String>,
    /// Optional description.
    pub description: Option<String>,
    /// Condition expression.
    pub condition: Option<String>,
    /// Approval type: "auto", "single", "dual", "manager".
    pub approval: Option<String>,
    /// Priority (lower = higher priority).
    pub priority: Option<i32>,
    /// Whether the policy is enabled.
    pub enabled: Option<bool>,
}

/// Policy response for API.
#[derive(Debug, Serialize)]
pub struct PolicyResponse {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub condition: String,
    pub action: String,
    pub approval_level: Option<String>,
    pub priority: i32,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

impl From<Policy> for PolicyResponse {
    fn from(policy: Policy) -> Self {
        Self {
            id: policy.id,
            name: policy.name,
            description: policy.description,
            condition: policy.condition,
            action: policy.action.as_db_str().to_string(),
            approval_level: policy.approval_level.map(|l| l.as_db_str().to_string()),
            priority: policy.priority,
            enabled: policy.enabled,
            created_at: policy.created_at.to_rfc3339(),
            updated_at: policy.updated_at.to_rfc3339(),
        }
    }
}

/// Maps the approval field from the form to PolicyAction and ApprovalLevel.
fn map_approval_to_action(approval: &str) -> (PolicyAction, Option<ApprovalLevel>) {
    match approval.to_lowercase().as_str() {
        "auto" => (PolicyAction::AutoApprove, None),
        "single" => (PolicyAction::RequireApproval, Some(ApprovalLevel::Analyst)),
        "dual" => (PolicyAction::RequireApproval, Some(ApprovalLevel::Senior)),
        "manager" => (PolicyAction::RequireApproval, Some(ApprovalLevel::Manager)),
        _ => (PolicyAction::RequireApproval, Some(ApprovalLevel::Analyst)),
    }
}

/// Builds a condition string from type and value.
fn build_condition(condition_type: &str, condition_value: &str) -> String {
    match condition_type {
        "severity" => format!("severity == '{}'", condition_value),
        "action_type" => format!("action_type == '{}'", condition_value),
        "target_pattern" => format!("target MATCHES '{}'", condition_value),
        "asset_criticality" => format!("asset_criticality IN ({})", condition_value),
        _ => format!("{} == '{}'", condition_type, condition_value),
    }
}

/// Creates an HX-Trigger header value for toast notifications.
fn toast_trigger(toast_type: &str, title: &str, message: &str) -> String {
    serde_json::json!({
        "showToast": {
            "type": toast_type,
            "title": title,
            "message": message
        }
    })
    .to_string()
}

/// List all policies ordered by priority.
async fn list_policies(
    State(state): State<AppState>,
) -> Result<Json<Vec<PolicyResponse>>, ApiError> {
    let repo: Box<dyn PolicyRepository> = create_policy_repository(&state.db);

    let policies = repo.list().await?;
    let responses: Vec<PolicyResponse> = policies.into_iter().map(PolicyResponse::from).collect();

    Ok(Json(responses))
}

/// Get a single policy by ID.
async fn get_policy(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<PolicyResponse>, ApiError> {
    let repo: Box<dyn PolicyRepository> = create_policy_repository(&state.db);

    let policy = repo
        .get(id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Policy {} not found", id)))?;

    Ok(Json(PolicyResponse::from(policy)))
}

/// Create a new policy.
async fn create_policy(
    State(state): State<AppState>,
    Form(request): Form<CreatePolicyRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let repo: Box<dyn PolicyRepository> = create_policy_repository(&state.db);

    // Build condition from form fields
    let condition = if let Some(cond) = request.condition {
        cond
    } else {
        let cond_type = request.condition_type.as_deref().unwrap_or("severity");
        let cond_value = request.condition_value.as_deref().unwrap_or("critical");
        build_condition(cond_type, cond_value)
    };

    // Get approval type from either field
    let approval = request
        .requires
        .as_deref()
        .or(request.approval.as_deref())
        .unwrap_or("single");

    let (action, approval_level) = map_approval_to_action(approval);

    // Handle enabled checkbox - HTML form sends "on" if checked, nothing if unchecked
    let enabled = request
        .enabled
        .as_deref()
        .map(|v| v == "on")
        .unwrap_or(false);

    // Create the policy
    let mut policy = Policy::new(request.name, condition, action);
    policy.approval_level = approval_level;
    policy.enabled = enabled;

    if let Some(desc) = request.description {
        policy = policy.with_description(desc);
    }

    if let Some(priority) = request.priority {
        policy = policy.with_priority(priority);
    }

    let created = repo.create(&policy).await?;

    Ok((
        StatusCode::CREATED,
        [(
            axum::http::header::HeaderName::from_static("hx-trigger"),
            toast_trigger(
                "success",
                "Policy Created",
                "New approval policy has been created.",
            ),
        )],
        Json(PolicyResponse::from(created)),
    ))
}

/// Update an existing policy.
async fn update_policy(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Form(request): Form<UpdatePolicyRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let repo: Box<dyn PolicyRepository> = create_policy_repository(&state.db);

    // Verify policy exists
    repo.get(id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Policy {} not found", id)))?;

    // Build update struct
    let (action, approval_level) = if let Some(ref approval) = request.approval {
        let (a, l) = map_approval_to_action(approval);
        (Some(a), Some(l))
    } else {
        (None, None)
    };

    let update = PolicyUpdate {
        name: request.name,
        description: request.description.map(Some),
        condition: request.condition,
        action,
        approval_level,
        priority: request.priority,
        enabled: request.enabled,
    };

    let updated = repo.update(id, &update).await?;

    Ok((
        StatusCode::OK,
        [(
            axum::http::header::HeaderName::from_static("hx-trigger"),
            toast_trigger("success", "Policy Updated", "The policy has been updated."),
        )],
        Json(PolicyResponse::from(updated)),
    ))
}

/// Delete a policy.
async fn delete_policy(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    let repo: Box<dyn PolicyRepository> = create_policy_repository(&state.db);

    let deleted = repo.delete(id).await?;

    if !deleted {
        return Err(ApiError::NotFound(format!("Policy {} not found", id)));
    }

    Ok((
        StatusCode::OK,
        [(
            axum::http::header::HeaderName::from_static("hx-trigger"),
            toast_trigger("success", "Policy Deleted", "The policy has been deleted."),
        )],
        "",
    ))
}

/// Toggle the enabled status of a policy.
async fn toggle_policy(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    let repo: Box<dyn PolicyRepository> = create_policy_repository(&state.db);

    let policy = repo.toggle_enabled(id).await?;

    let status_text = if policy.enabled {
        "enabled"
    } else {
        "disabled"
    };
    let message = format!("Policy has been {}.", status_text);

    Ok((
        StatusCode::OK,
        [(
            axum::http::header::HeaderName::from_static("hx-trigger"),
            toast_trigger("success", "Policy Status Changed", &message),
        )],
        Json(PolicyResponse::from(policy)),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_map_approval_to_action() {
        let (action, level) = map_approval_to_action("auto");
        assert_eq!(action, PolicyAction::AutoApprove);
        assert!(level.is_none());

        let (action, level) = map_approval_to_action("single");
        assert_eq!(action, PolicyAction::RequireApproval);
        assert_eq!(level, Some(ApprovalLevel::Analyst));

        let (action, level) = map_approval_to_action("dual");
        assert_eq!(action, PolicyAction::RequireApproval);
        assert_eq!(level, Some(ApprovalLevel::Senior));

        let (action, level) = map_approval_to_action("manager");
        assert_eq!(action, PolicyAction::RequireApproval);
        assert_eq!(level, Some(ApprovalLevel::Manager));
    }

    #[test]
    fn test_build_condition() {
        assert_eq!(
            build_condition("severity", "critical"),
            "severity == 'critical'"
        );
        assert_eq!(
            build_condition("action_type", "isolate_host"),
            "action_type == 'isolate_host'"
        );
        assert_eq!(
            build_condition("target_pattern", ".*-prod-.*"),
            "target MATCHES '.*-prod-.*'"
        );
        assert_eq!(
            build_condition("asset_criticality", "critical, high"),
            "asset_criticality IN (critical, high)"
        );
    }
}
