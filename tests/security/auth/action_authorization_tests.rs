//! Tests for unauthorized action execution blocking.
//!
//! These tests verify that actions without proper authorization fail,
//! ensuring the security boundaries of the action execution system.

use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;

use tw_actions::registry::{
    Action, ActionContext, ActionError, ActionRegistry, ActionResult, ParameterDef, ParameterType,
};
use tw_core::auth::{AuthorizationContext, AuthorizationError, Permission, Role, User};
use uuid::Uuid;

/// A mock action for testing authorization controls.
struct MockAction {
    name: &'static str,
}

impl MockAction {
    fn new(name: &'static str) -> Self {
        Self { name }
    }
}

#[async_trait::async_trait]
impl Action for MockAction {
    fn name(&self) -> &str {
        self.name
    }

    fn description(&self) -> &str {
        "A mock action for testing"
    }

    fn required_parameters(&self) -> Vec<ParameterDef> {
        vec![ParameterDef::required(
            "target",
            "The target",
            ParameterType::String,
        )]
    }

    async fn execute(&self, context: ActionContext) -> Result<ActionResult, ActionError> {
        let target = context.require_string("target")?;
        Ok(ActionResult::success(
            self.name(),
            &format!("Executed on {}", target),
            chrono::Utc::now(),
            HashMap::new(),
        ))
    }
}

/// Helper to create a test user with a specific role.
fn create_test_user(role: Role) -> User {
    User::new(
        format!("{}@test.local", role.as_str()),
        format!("test_{}", role.as_str()),
        "hash",
        role,
    )
}

// ============================================================
// Test: Action execution requires authorization context
// ============================================================

#[tokio::test]
async fn test_action_execution_without_auth_context_fails() {
    let mut registry = ActionRegistry::new();
    registry.register(Arc::new(MockAction::new("test_action")));

    // Create context WITHOUT auth context
    let context =
        ActionContext::new(Uuid::new_v4()).with_param("target", serde_json::json!("test-host"));

    let result = registry.execute("test_action", context).await;

    // Should fail with Unauthorized error
    assert!(
        matches!(result, Err(ActionError::Unauthorized(_))),
        "Action execution without auth context should be unauthorized"
    );

    if let Err(ActionError::Unauthorized(msg)) = result {
        assert!(
            msg.contains("authorization context"),
            "Error message should mention authorization context"
        );
    }
}

#[tokio::test]
async fn test_action_execution_with_auth_context_succeeds() {
    let mut registry = ActionRegistry::new();
    registry.register(Arc::new(MockAction::new("test_action")));

    // Create context WITH auth context (using system context which has all permissions)
    let context = ActionContext::new(Uuid::new_v4())
        .with_param("target", serde_json::json!("test-host"))
        .with_auth_context(AuthorizationContext::system());

    let result = registry.execute("test_action", context).await;

    // Should succeed
    assert!(result.is_ok(), "Action with valid auth context should succeed");
    assert!(result.unwrap().success);
}

// ============================================================
// Test: Viewer role cannot execute actions
// ============================================================

#[tokio::test]
async fn test_viewer_cannot_execute_actions() {
    let mut registry = ActionRegistry::new();
    registry.register(Arc::new(MockAction::new("test_action")));

    let viewer = create_test_user(Role::Viewer);
    let auth_ctx = AuthorizationContext::from_user(&viewer);

    let context = ActionContext::new(Uuid::new_v4())
        .with_param("target", serde_json::json!("test-host"))
        .with_auth_context(auth_ctx);

    let result = registry.execute("test_action", context).await;

    // Viewer should not be able to execute actions
    assert!(
        matches!(result, Err(ActionError::Unauthorized(_))),
        "Viewer should not be able to execute actions"
    );

    if let Err(ActionError::Unauthorized(msg)) = result {
        assert!(
            msg.contains("execute_actions") || msg.contains("ExecuteActions"),
            "Error should mention execute_actions permission: {}",
            msg
        );
    }
}

#[tokio::test]
async fn test_analyst_can_execute_actions() {
    let mut registry = ActionRegistry::new();
    registry.register(Arc::new(MockAction::new("test_action")));

    let analyst = create_test_user(Role::Analyst);
    let auth_ctx = AuthorizationContext::from_user(&analyst);

    let context = ActionContext::new(Uuid::new_v4())
        .with_param("target", serde_json::json!("test-host"))
        .with_auth_context(auth_ctx);

    let result = registry.execute("test_action", context).await;

    // Analyst should be able to execute non-destructive actions
    assert!(
        result.is_ok(),
        "Analyst should be able to execute non-destructive actions"
    );
}

#[tokio::test]
async fn test_admin_can_execute_actions() {
    let mut registry = ActionRegistry::new();
    registry.register(Arc::new(MockAction::new("test_action")));

    let admin = create_test_user(Role::Admin);
    let auth_ctx = AuthorizationContext::from_user(&admin);

    let context = ActionContext::new(Uuid::new_v4())
        .with_param("target", serde_json::json!("test-host"))
        .with_auth_context(auth_ctx);

    let result = registry.execute("test_action", context).await;

    // Admin should be able to execute any action
    assert!(result.is_ok(), "Admin should be able to execute any action");
}

// ============================================================
// Test: Destructive actions require approval permission
// ============================================================

#[tokio::test]
async fn test_destructive_action_requires_approval_permission() {
    let mut registry = ActionRegistry::new();
    // "isolate_host" is defined as a destructive action
    registry.register(Arc::new(MockAction::new("isolate_host")));

    // Create a custom context with ExecuteActions but without ApproveActions
    let user = create_test_user(Role::Analyst);
    let mut permissions = HashSet::new();
    permissions.insert(Permission::ExecuteActions);
    // Note: NOT adding ApproveActions permission

    let auth_ctx = AuthorizationContext::with_permissions(
        user.id,
        user.username.clone(),
        user.role,
        permissions,
    );

    let context = ActionContext::new(Uuid::new_v4())
        .with_param("target", serde_json::json!("critical-host"))
        .with_auth_context(auth_ctx);

    let result = registry.execute("isolate_host", context).await;

    // Should fail because destructive actions require ApproveActions permission
    assert!(
        matches!(result, Err(ActionError::Unauthorized(_))),
        "Destructive action without approval permission should fail"
    );
}

#[tokio::test]
async fn test_destructive_action_with_approval_permission_succeeds() {
    let mut registry = ActionRegistry::new();
    registry.register(Arc::new(MockAction::new("isolate_host")));

    // Full analyst permissions include both ExecuteActions and ApproveActions
    let analyst = create_test_user(Role::Analyst);
    let auth_ctx = AuthorizationContext::from_user(&analyst);

    let context = ActionContext::new(Uuid::new_v4())
        .with_param("target", serde_json::json!("critical-host"))
        .with_auth_context(auth_ctx);

    let result = registry.execute("isolate_host", context).await;

    // Analyst with full permissions should succeed
    assert!(
        result.is_ok(),
        "Analyst with approval permission should execute destructive actions"
    );
}

// ============================================================
// Test: All destructive actions are properly protected
// ============================================================

#[tokio::test]
async fn test_all_destructive_actions_require_approval() {
    // These are the defined destructive actions from tw_core::auth
    let destructive_actions = vec![
        "isolate_host",
        "disable_user",
        "block_sender",
        "quarantine_email",
    ];

    for action_name in destructive_actions {
        let mut registry = ActionRegistry::new();
        registry.register(Arc::new(MockAction::new(Box::leak(
            action_name.to_string().into_boxed_str(),
        ))));

        // User with only ExecuteActions (no ApproveActions)
        let user = create_test_user(Role::Viewer);
        let mut permissions = HashSet::new();
        permissions.insert(Permission::ExecuteActions);

        let auth_ctx = AuthorizationContext::with_permissions(
            user.id,
            user.username.clone(),
            Role::Analyst, // Give Analyst role but limited permissions
            permissions,
        );

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("target", serde_json::json!("test-target"))
            .with_auth_context(auth_ctx);

        let result = registry.execute(action_name, context).await;

        assert!(
            matches!(result, Err(ActionError::Unauthorized(_))),
            "Destructive action '{}' should require approval permission",
            action_name
        );
    }
}

// ============================================================
// Test: Authorization context validation methods
// ============================================================

#[tokio::test]
async fn test_authorization_context_validate_execute_permission() {
    // Viewer does not have ExecuteActions permission
    let viewer = create_test_user(Role::Viewer);
    let ctx = AuthorizationContext::from_user(&viewer);

    let result = ctx.validate_execute_permission();
    assert!(
        result.is_err(),
        "Viewer should not have execute permission"
    );

    // Analyst has ExecuteActions permission
    let analyst = create_test_user(Role::Analyst);
    let ctx = AuthorizationContext::from_user(&analyst);

    let result = ctx.validate_execute_permission();
    assert!(result.is_ok(), "Analyst should have execute permission");
}

#[tokio::test]
async fn test_authorization_context_validate_destructive_permission() {
    // Custom context with ExecuteActions but not ApproveActions
    let mut permissions = HashSet::new();
    permissions.insert(Permission::ExecuteActions);

    let ctx = AuthorizationContext::with_permissions(
        Uuid::new_v4(),
        "limited_user",
        Role::Analyst,
        permissions,
    );

    let result = ctx.validate_destructive_permission();
    assert!(
        result.is_err(),
        "Should fail without ApproveActions permission"
    );

    // Full analyst context has both permissions
    let analyst = create_test_user(Role::Analyst);
    let ctx = AuthorizationContext::from_user(&analyst);

    let result = ctx.validate_destructive_permission();
    assert!(
        result.is_ok(),
        "Analyst should have destructive permission"
    );
}

// ============================================================
// Test: Audit logging captures authorization failures
// ============================================================

#[tokio::test]
async fn test_unauthorized_action_is_audited() {
    use tw_observability::ActionAuditLog;

    let audit_log = Arc::new(ActionAuditLog::without_tracing(100));
    let mut registry = ActionRegistry::new();
    registry.set_audit_log(Arc::clone(&audit_log));
    registry.register(Arc::new(MockAction::new("test_action")));

    // Attempt unauthorized action (no auth context)
    let context =
        ActionContext::new(Uuid::new_v4()).with_param("target", serde_json::json!("test-host"));

    let _ = registry.execute("test_action", context).await;

    // Wait for async audit log
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let entries = audit_log.get_entries().await;
    assert_eq!(entries.len(), 1, "Should have one audit entry");
    assert_eq!(
        entries[0].result,
        tw_observability::ActionAuditResult::Denied,
        "Audit should show denied result"
    );
}

#[tokio::test]
async fn test_viewer_action_denial_is_audited() {
    use tw_observability::ActionAuditLog;

    let audit_log = Arc::new(ActionAuditLog::without_tracing(100));
    let mut registry = ActionRegistry::new();
    registry.set_audit_log(Arc::clone(&audit_log));
    registry.register(Arc::new(MockAction::new("test_action")));

    let viewer = create_test_user(Role::Viewer);
    let auth_ctx = AuthorizationContext::from_user(&viewer);

    let context = ActionContext::new(Uuid::new_v4())
        .with_param("target", serde_json::json!("test-host"))
        .with_auth_context(auth_ctx);

    let _ = registry.execute("test_action", context).await;

    // Wait for async audit log
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let entries = audit_log.get_entries().await;
    assert_eq!(entries.len(), 1, "Should have one audit entry");
    assert_eq!(
        entries[0].result,
        tw_observability::ActionAuditResult::Denied,
        "Audit should show denied result for viewer"
    );
    assert_eq!(
        entries[0].actor_role, "viewer",
        "Audit should capture viewer role"
    );
}

// ============================================================
// Test: Permission hierarchy is enforced
// ============================================================

#[tokio::test]
async fn test_permission_hierarchy() {
    // Admin has all permissions
    let admin = create_test_user(Role::Admin);
    let admin_ctx = AuthorizationContext::from_user(&admin);
    assert!(admin_ctx.has_permission(Permission::ReadIncidents));
    assert!(admin_ctx.has_permission(Permission::WriteIncidents));
    assert!(admin_ctx.has_permission(Permission::ApproveActions));
    assert!(admin_ctx.has_permission(Permission::ExecuteActions));
    assert!(admin_ctx.has_permission(Permission::ManageUsers));
    assert!(admin_ctx.has_permission(Permission::ManageSettings));

    // Analyst has operational permissions but not management
    let analyst = create_test_user(Role::Analyst);
    let analyst_ctx = AuthorizationContext::from_user(&analyst);
    assert!(analyst_ctx.has_permission(Permission::ReadIncidents));
    assert!(analyst_ctx.has_permission(Permission::WriteIncidents));
    assert!(analyst_ctx.has_permission(Permission::ApproveActions));
    assert!(analyst_ctx.has_permission(Permission::ExecuteActions));
    assert!(!analyst_ctx.has_permission(Permission::ManageUsers));
    assert!(!analyst_ctx.has_permission(Permission::ManageSettings));

    // Viewer has only read permissions
    let viewer = create_test_user(Role::Viewer);
    let viewer_ctx = AuthorizationContext::from_user(&viewer);
    assert!(viewer_ctx.has_permission(Permission::ReadIncidents));
    assert!(!viewer_ctx.has_permission(Permission::WriteIncidents));
    assert!(!viewer_ctx.has_permission(Permission::ApproveActions));
    assert!(!viewer_ctx.has_permission(Permission::ExecuteActions));
    assert!(!viewer_ctx.has_permission(Permission::ManageUsers));
}

// ============================================================
// Test: System context has all permissions
// ============================================================

#[tokio::test]
async fn test_system_context_has_all_permissions() {
    let system_ctx = AuthorizationContext::system();

    for permission in Permission::all() {
        assert!(
            system_ctx.has_permission(permission),
            "System context should have {:?} permission",
            permission
        );
    }

    // System context should always pass validation
    assert!(system_ctx.validate_execute_permission().is_ok());
    assert!(system_ctx.validate_destructive_permission().is_ok());
}

// ============================================================
// Test: Authorization error messages are informative
// ============================================================

#[tokio::test]
async fn test_authorization_error_messages() {
    let viewer = create_test_user(Role::Viewer);
    let ctx = AuthorizationContext::from_user(&viewer);

    let err = ctx.validate_execute_permission().unwrap_err();

    // Error should contain useful information
    let error_msg = err.to_string();
    assert!(
        error_msg.contains(&viewer.username) || error_msg.contains("viewer"),
        "Error should mention user or role: {}",
        error_msg
    );
    assert!(
        error_msg.contains("execute") || error_msg.contains("ExecuteActions"),
        "Error should mention required permission: {}",
        error_msg
    );
}
