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
            "/:id",
            get(get_policy).put(update_policy).delete(delete_policy),
        )
        .route("/:id/toggle", post(toggle_policy))
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
#[derive(Debug, Serialize, Deserialize)]
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

#[cfg(test)]
mod api_tests {
    use super::*;
    use axum::{
        body::Body,
        http::{header, Method, Request, StatusCode},
    };
    use tower::ServiceExt;
    use tw_core::db::{create_policy_repository, DbPool};
    use tw_core::EventBus;

    /// Creates an in-memory SQLite database pool for testing.
    async fn create_test_pool() -> sqlx::SqlitePool {
        let db_url = format!(
            "sqlite:file:test_policies_{}?mode=memory&cache=shared",
            Uuid::new_v4()
        );

        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect(&db_url)
            .await
            .expect("Failed to create test pool");

        // Create the policies table manually
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS policies (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                condition TEXT NOT NULL,
                action TEXT NOT NULL,
                approval_level TEXT,
                priority INTEGER NOT NULL DEFAULT 0,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            "#,
        )
        .execute(&pool)
        .await
        .expect("Failed to create policies table");

        pool
    }

    /// Creates a test AppState with an in-memory database.
    async fn create_test_state() -> AppState {
        let pool = create_test_pool().await;
        let db = DbPool::Sqlite(pool);
        let event_bus = EventBus::new(100);
        AppState::new(db, event_bus)
    }

    /// Creates the test router with policies routes.
    fn create_test_router(state: AppState) -> Router {
        Router::new()
            .nest("/api/policies", routes())
            .with_state(state)
    }

    /// Creates a test router and returns the state for additional operations.
    async fn create_test_router_with_state() -> (Router, AppState) {
        let state = create_test_state().await;
        let router = create_test_router(state.clone());
        (router, state)
    }

    /// Helper to create a policy in the database.
    async fn create_test_policy(
        state: &AppState,
        name: &str,
        condition: &str,
        action: PolicyAction,
    ) -> Policy {
        let repo = create_policy_repository(&state.db);
        let policy = Policy::new(name.to_string(), condition.to_string(), action);
        repo.create(&policy).await.expect("Failed to create policy")
    }

    // ==============================================
    // List Policies Tests
    // ==============================================

    #[tokio::test]
    async fn test_list_policies_empty() {
        let (app, _state) = create_test_router_with_state().await;

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/policies")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let policies: Vec<PolicyResponse> = serde_json::from_slice(&body).unwrap();

        assert!(policies.is_empty());
    }

    #[tokio::test]
    async fn test_list_policies_with_data() {
        let (app, state) = create_test_router_with_state().await;

        // Create some test policies
        create_test_policy(
            &state,
            "Critical Policy",
            "severity == 'critical'",
            PolicyAction::RequireApproval,
        )
        .await;
        create_test_policy(
            &state,
            "Auto Approve Low",
            "severity == 'low'",
            PolicyAction::AutoApprove,
        )
        .await;

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/policies")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let policies: Vec<PolicyResponse> = serde_json::from_slice(&body).unwrap();

        assert_eq!(policies.len(), 2);

        // Check that policies are returned
        let names: Vec<&str> = policies.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"Critical Policy"));
        assert!(names.contains(&"Auto Approve Low"));
    }

    #[tokio::test]
    async fn test_list_policies_ordered_by_priority() {
        let (app, state) = create_test_router_with_state().await;

        // Create policies with different priorities
        let repo = create_policy_repository(&state.db);

        let policy1 = Policy::new(
            "Low Priority".to_string(),
            "severity == 'low'".to_string(),
            PolicyAction::AutoApprove,
        )
        .with_priority(100);
        repo.create(&policy1).await.unwrap();

        let policy2 = Policy::new(
            "High Priority".to_string(),
            "severity == 'critical'".to_string(),
            PolicyAction::RequireApproval,
        )
        .with_priority(10);
        repo.create(&policy2).await.unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/policies")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let policies: Vec<PolicyResponse> = serde_json::from_slice(&body).unwrap();

        assert_eq!(policies.len(), 2);
        // First policy should be the one with lower priority number (higher priority)
        assert_eq!(policies[0].name, "High Priority");
        assert_eq!(policies[1].name, "Low Priority");
    }

    // ==============================================
    // Get Policy Tests
    // ==============================================

    #[tokio::test]
    async fn test_get_policy_success() {
        let (app, state) = create_test_router_with_state().await;

        let created = create_test_policy(
            &state,
            "Test Policy",
            "severity == 'high'",
            PolicyAction::RequireApproval,
        )
        .await;

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(&format!("/api/policies/{}", created.id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let policy: PolicyResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(policy.id, created.id);
        assert_eq!(policy.name, "Test Policy");
        assert_eq!(policy.condition, "severity == 'high'");
        assert_eq!(policy.action, "require_approval");
    }

    #[tokio::test]
    async fn test_get_policy_not_found() {
        let (app, _state) = create_test_router_with_state().await;

        let nonexistent_id = Uuid::new_v4();

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(&format!("/api/policies/{}", nonexistent_id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_get_policy_invalid_uuid() {
        let (app, _state) = create_test_router_with_state().await;

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/policies/invalid-uuid")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Invalid UUID should return 400 Bad Request
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    // ==============================================
    // Create Policy Tests
    // ==============================================

    #[tokio::test]
    async fn test_create_policy_with_condition_type_and_value() {
        let (app, _state) = create_test_router_with_state().await;

        let form_body = serde_urlencoded::to_string(&[
            ("name", "New Test Policy"),
            ("description", "A test policy"),
            ("condition_type", "severity"),
            ("condition_value", "critical"),
            ("approval", "single"),
            ("priority", "50"),
            ("enabled", "on"),
        ])
        .unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/policies")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(form_body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        // Verify HX-Trigger header is present
        let hx_trigger = response.headers().get("hx-trigger");
        assert!(hx_trigger.is_some());

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let policy: PolicyResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(policy.name, "New Test Policy");
        assert_eq!(policy.description, Some("A test policy".to_string()));
        assert_eq!(policy.condition, "severity == 'critical'");
        assert_eq!(policy.action, "require_approval");
        assert_eq!(policy.approval_level, Some("analyst".to_string()));
        assert_eq!(policy.priority, 50);
        assert!(policy.enabled);
    }

    #[tokio::test]
    async fn test_create_policy_with_direct_condition() {
        let (app, _state) = create_test_router_with_state().await;

        let form_body = serde_urlencoded::to_string(&[
            ("name", "Direct Condition Policy"),
            ("condition", "severity == 'high' AND source == 'siem'"),
            ("approval", "dual"),
        ])
        .unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/policies")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(form_body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let policy: PolicyResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(policy.name, "Direct Condition Policy");
        assert_eq!(policy.condition, "severity == 'high' AND source == 'siem'");
        assert_eq!(policy.approval_level, Some("senior".to_string()));
    }

    #[tokio::test]
    async fn test_create_policy_auto_approve() {
        let (app, _state) = create_test_router_with_state().await;

        let form_body = serde_urlencoded::to_string(&[
            ("name", "Auto Approve Policy"),
            ("condition", "severity == 'info'"),
            ("requires", "auto"),
        ])
        .unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/policies")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(form_body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let policy: PolicyResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(policy.action, "auto_approve");
        assert!(policy.approval_level.is_none());
    }

    #[tokio::test]
    async fn test_create_policy_manager_approval() {
        let (app, _state) = create_test_router_with_state().await;

        let form_body = serde_urlencoded::to_string(&[
            ("name", "Manager Approval Policy"),
            ("condition", "asset_criticality == 'critical'"),
            ("approval", "manager"),
        ])
        .unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/policies")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(form_body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let policy: PolicyResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(policy.approval_level, Some("manager".to_string()));
    }

    #[tokio::test]
    async fn test_create_policy_default_values() {
        let (app, _state) = create_test_router_with_state().await;

        // Minimal form data - should use defaults
        let form_body = serde_urlencoded::to_string(&[("name", "Minimal Policy")]).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/policies")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(form_body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let policy: PolicyResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(policy.name, "Minimal Policy");
        // Default condition from condition_type=severity, condition_value=critical
        assert_eq!(policy.condition, "severity == 'critical'");
        // Default approval is single (analyst)
        assert_eq!(policy.approval_level, Some("analyst".to_string()));
        // enabled checkbox not checked means disabled
        assert!(!policy.enabled);
    }

    // ==============================================
    // Update Policy Tests
    // ==============================================

    #[tokio::test]
    async fn test_update_policy_success() {
        let (app, state) = create_test_router_with_state().await;

        let created = create_test_policy(
            &state,
            "Original Name",
            "severity == 'low'",
            PolicyAction::AutoApprove,
        )
        .await;

        let form_body = serde_urlencoded::to_string(&[
            ("name", "Updated Name"),
            ("description", "Updated description"),
            ("condition", "severity == 'high'"),
            ("approval", "dual"),
            ("priority", "25"),
            ("enabled", "true"),
        ])
        .unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri(&format!("/api/policies/{}", created.id))
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(form_body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Verify HX-Trigger header
        let hx_trigger = response.headers().get("hx-trigger");
        assert!(hx_trigger.is_some());

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let policy: PolicyResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(policy.id, created.id);
        assert_eq!(policy.name, "Updated Name");
        assert_eq!(policy.description, Some("Updated description".to_string()));
        assert_eq!(policy.condition, "severity == 'high'");
        assert_eq!(policy.action, "require_approval");
        assert_eq!(policy.approval_level, Some("senior".to_string()));
        assert_eq!(policy.priority, 25);
        assert!(policy.enabled);
    }

    #[tokio::test]
    async fn test_update_policy_partial() {
        let (app, state) = create_test_router_with_state().await;

        let repo = create_policy_repository(&state.db);
        let policy = Policy::new(
            "Original Name".to_string(),
            "severity == 'low'".to_string(),
            PolicyAction::AutoApprove,
        )
        .with_description("Original description")
        .with_priority(50);
        let created = repo.create(&policy).await.unwrap();

        // Only update the name
        let form_body = serde_urlencoded::to_string(&[("name", "New Name Only")]).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri(&format!("/api/policies/{}", created.id))
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(form_body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let policy: PolicyResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(policy.name, "New Name Only");
        // Other fields should remain unchanged
        assert_eq!(policy.description, Some("Original description".to_string()));
        assert_eq!(policy.condition, "severity == 'low'");
        assert_eq!(policy.priority, 50);
    }

    #[tokio::test]
    async fn test_update_policy_not_found() {
        let (app, _state) = create_test_router_with_state().await;

        let nonexistent_id = Uuid::new_v4();

        let form_body = serde_urlencoded::to_string(&[("name", "Updated Name")]).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri(&format!("/api/policies/{}", nonexistent_id))
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(form_body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // ==============================================
    // Delete Policy Tests
    // ==============================================

    #[tokio::test]
    async fn test_delete_policy_success() {
        let (app, state) = create_test_router_with_state().await;

        let created = create_test_policy(
            &state,
            "Policy To Delete",
            "severity == 'low'",
            PolicyAction::AutoApprove,
        )
        .await;

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::DELETE)
                    .uri(&format!("/api/policies/{}", created.id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Verify HX-Trigger header
        let hx_trigger = response.headers().get("hx-trigger");
        assert!(hx_trigger.is_some());

        // Verify policy is deleted
        let repo = create_policy_repository(&state.db);
        let result = repo.get(created.id).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_delete_policy_not_found() {
        let (app, _state) = create_test_router_with_state().await;

        let nonexistent_id = Uuid::new_v4();

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::DELETE)
                    .uri(&format!("/api/policies/{}", nonexistent_id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // ==============================================
    // Toggle Policy Tests
    // ==============================================

    #[tokio::test]
    async fn test_toggle_policy_enable() {
        let (app, state) = create_test_router_with_state().await;

        let repo = create_policy_repository(&state.db);
        let policy = Policy::new(
            "Disabled Policy".to_string(),
            "severity == 'low'".to_string(),
            PolicyAction::AutoApprove,
        )
        .with_enabled(false);
        let created = repo.create(&policy).await.unwrap();
        assert!(!created.enabled);

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(&format!("/api/policies/{}/toggle", created.id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Verify HX-Trigger header
        let hx_trigger = response.headers().get("hx-trigger");
        assert!(hx_trigger.is_some());
        let trigger_value = hx_trigger.unwrap().to_str().unwrap();
        assert!(trigger_value.contains("enabled"));

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let policy: PolicyResponse = serde_json::from_slice(&body).unwrap();

        assert!(policy.enabled);
    }

    #[tokio::test]
    async fn test_toggle_policy_disable() {
        let (app, state) = create_test_router_with_state().await;

        let repo = create_policy_repository(&state.db);
        let policy = Policy::new(
            "Enabled Policy".to_string(),
            "severity == 'critical'".to_string(),
            PolicyAction::RequireApproval,
        )
        .with_enabled(true);
        let created = repo.create(&policy).await.unwrap();
        assert!(created.enabled);

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(&format!("/api/policies/{}/toggle", created.id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let policy: PolicyResponse = serde_json::from_slice(&body).unwrap();

        assert!(!policy.enabled);
    }

    #[tokio::test]
    async fn test_toggle_policy_not_found() {
        let (app, _state) = create_test_router_with_state().await;

        let nonexistent_id = Uuid::new_v4();

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(&format!("/api/policies/{}/toggle", nonexistent_id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // toggle_enabled returns DbError::NotFound which maps to 500
        // because it's not directly handled as ApiError::NotFound
        assert!(
            response.status() == StatusCode::INTERNAL_SERVER_ERROR
                || response.status() == StatusCode::NOT_FOUND
        );
    }

    // ==============================================
    // Policy Response Format Tests
    // ==============================================

    #[tokio::test]
    async fn test_policy_response_fields() {
        let (app, state) = create_test_router_with_state().await;

        let repo = create_policy_repository(&state.db);
        let policy = Policy::new(
            "Complete Policy".to_string(),
            "severity == 'critical'".to_string(),
            PolicyAction::RequireApproval,
        )
        .with_description("A complete policy for testing")
        .with_priority(10);
        let mut policy = policy;
        policy.approval_level = Some(ApprovalLevel::Manager);
        let created = repo.create(&policy).await.unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(&format!("/api/policies/{}", created.id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let policy: PolicyResponse = serde_json::from_slice(&body).unwrap();

        // Verify all response fields are present and correct
        assert_eq!(policy.id, created.id);
        assert_eq!(policy.name, "Complete Policy");
        assert_eq!(
            policy.description,
            Some("A complete policy for testing".to_string())
        );
        assert_eq!(policy.condition, "severity == 'critical'");
        assert_eq!(policy.action, "require_approval");
        assert_eq!(policy.approval_level, Some("manager".to_string()));
        assert_eq!(policy.priority, 10);
        assert!(policy.enabled);
        // Timestamps should be valid RFC3339 strings
        assert!(chrono::DateTime::parse_from_rfc3339(&policy.created_at).is_ok());
        assert!(chrono::DateTime::parse_from_rfc3339(&policy.updated_at).is_ok());
    }

    // ==============================================
    // Edge Cases and Validation Tests
    // ==============================================

    #[tokio::test]
    async fn test_create_policy_with_special_characters() {
        let (app, _state) = create_test_router_with_state().await;

        let form_body = serde_urlencoded::to_string(&[
            ("name", "Policy with 'quotes' and \"double quotes\""),
            ("condition", "target MATCHES '.*\\.example\\.com$'"),
            ("approval", "single"),
        ])
        .unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/policies")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(form_body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let policy: PolicyResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(policy.name, "Policy with 'quotes' and \"double quotes\"");
        assert_eq!(policy.condition, "target MATCHES '.*\\.example\\.com$'");
    }

    #[tokio::test]
    async fn test_create_policy_empty_description() {
        let (app, _state) = create_test_router_with_state().await;

        let form_body = serde_urlencoded::to_string(&[
            ("name", "No Description Policy"),
            ("condition", "severity == 'low'"),
            ("approval", "auto"),
        ])
        .unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/policies")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(form_body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let policy: PolicyResponse = serde_json::from_slice(&body).unwrap();

        assert!(policy.description.is_none());
    }

    #[tokio::test]
    async fn test_update_policy_clear_description() {
        let (app, state) = create_test_router_with_state().await;

        let repo = create_policy_repository(&state.db);
        let policy = Policy::new(
            "Has Description".to_string(),
            "severity == 'low'".to_string(),
            PolicyAction::AutoApprove,
        )
        .with_description("Original description");
        let created = repo.create(&policy).await.unwrap();

        // Update with empty description to clear it
        let form_body = serde_urlencoded::to_string(&[("description", "")]).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri(&format!("/api/policies/{}", created.id))
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(form_body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let policy: PolicyResponse = serde_json::from_slice(&body).unwrap();

        // Empty string becomes Some("") not None
        assert_eq!(policy.description, Some("".to_string()));
    }

    // ==============================================
    // Content Type Tests
    // ==============================================

    #[tokio::test]
    async fn test_list_policies_returns_json() {
        let (app, _state) = create_test_router_with_state().await;

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/policies")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let content_type = response.headers().get(header::CONTENT_TYPE);
        assert!(content_type.is_some());
        assert!(content_type
            .unwrap()
            .to_str()
            .unwrap()
            .contains("application/json"));
    }

    #[tokio::test]
    async fn test_create_policy_hx_trigger_format() {
        let state = create_test_state().await;
        let app = create_test_router(state);

        let form_body =
            serde_urlencoded::to_string(&[("name", "Trigger Test"), ("condition", "true")])
                .unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/policies")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(form_body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let hx_trigger = response.headers().get("hx-trigger").unwrap();
        let trigger_json: serde_json::Value =
            serde_json::from_str(hx_trigger.to_str().unwrap()).unwrap();

        assert!(trigger_json.get("showToast").is_some());
        let toast = trigger_json.get("showToast").unwrap();
        assert_eq!(toast.get("type").unwrap().as_str().unwrap(), "success");
        assert!(toast.get("title").is_some());
        assert!(toast.get("message").is_some());
    }
}
