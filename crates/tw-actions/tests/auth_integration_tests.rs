//! Integration tests for authentication and authorization controls.
//!
//! These tests verify security controls including:
//! - Unauthorized action execution is blocked
//! - Workflow transition authorization
//! - Force flag removal verification
//! - Escalation privilege checks

use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;

use tw_actions::registry::{
    Action, ActionContext, ActionError, ActionRegistry, ActionResult, ParameterDef, ParameterType,
};
use tw_core::auth::{AuthorizationContext, Permission, Role, User};
use tw_observability::ActionAuditLog;
use uuid::Uuid;

// =============================================================================
// Mock Actions for Testing
// =============================================================================

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

/// A mock action that tests for force flag handling.
struct ForceAwareAction;

#[async_trait::async_trait]
impl Action for ForceAwareAction {
    fn name(&self) -> &str {
        "force_aware_action"
    }

    fn description(&self) -> &str {
        "An action that should reject force flags"
    }

    fn required_parameters(&self) -> Vec<ParameterDef> {
        vec![
            ParameterDef::required("target", "The target", ParameterType::String),
            ParameterDef::optional(
                "force",
                "Force the action (should be rejected)",
                ParameterType::Boolean,
                serde_json::json!(false),
            ),
        ]
    }

    async fn execute(&self, context: ActionContext) -> Result<ActionResult, ActionError> {
        let target = context.require_string("target")?;

        // Check if force flag is present and true
        if let Some(force) = context.get_param("force") {
            if force.as_bool().unwrap_or(false) {
                return Err(ActionError::InvalidParameters(
                    "Force flag is not permitted. All actions must follow standard authorization flow.".to_string()
                ));
            }
        }

        Ok(ActionResult::success(
            self.name(),
            &format!("Executed on {} without force", target),
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

// =============================================================================
// Unauthorized Action Execution Tests
// =============================================================================

#[tokio::test]
async fn test_action_execution_without_auth_context_fails() {
    let mut registry = ActionRegistry::new();
    registry.register(Arc::new(MockAction::new("test_action")));

    let context =
        ActionContext::new(Uuid::new_v4()).with_param("target", serde_json::json!("test-host"));

    let result = registry.execute("test_action", context).await;

    assert!(
        matches!(result, Err(ActionError::Unauthorized(_))),
        "Action execution without auth context should be unauthorized"
    );
}

#[tokio::test]
async fn test_action_execution_with_auth_context_succeeds() {
    let mut registry = ActionRegistry::new();
    registry.register(Arc::new(MockAction::new("test_action")));

    let context = ActionContext::new(Uuid::new_v4())
        .with_param("target", serde_json::json!("test-host"))
        .with_auth_context(AuthorizationContext::system());

    let result = registry.execute("test_action", context).await;

    assert!(
        result.is_ok(),
        "Action with valid auth context should succeed"
    );
    assert!(result.unwrap().success);
}

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

    assert!(
        matches!(result, Err(ActionError::Unauthorized(_))),
        "Viewer should not be able to execute actions"
    );
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

    assert!(
        result.is_ok(),
        "Analyst should be able to execute non-destructive actions"
    );
}

// =============================================================================
// Destructive Action Authorization Tests
// =============================================================================

#[tokio::test]
async fn test_destructive_action_requires_approval_permission() {
    let mut registry = ActionRegistry::new();
    registry.register(Arc::new(MockAction::new("isolate_host")));

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

    assert!(
        matches!(result, Err(ActionError::Unauthorized(_))),
        "Destructive action without approval permission should fail"
    );
}

#[tokio::test]
async fn test_destructive_action_with_full_permissions_succeeds() {
    let mut registry = ActionRegistry::new();
    registry.register(Arc::new(MockAction::new("isolate_host")));

    let analyst = create_test_user(Role::Analyst);
    let auth_ctx = AuthorizationContext::from_user(&analyst);

    let context = ActionContext::new(Uuid::new_v4())
        .with_param("target", serde_json::json!("critical-host"))
        .with_auth_context(auth_ctx);

    let result = registry.execute("isolate_host", context).await;

    assert!(
        result.is_ok(),
        "Analyst with full permissions should execute destructive actions"
    );
}

#[tokio::test]
async fn test_all_destructive_actions_require_approval() {
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

        let user = create_test_user(Role::Viewer);
        let mut permissions = HashSet::new();
        permissions.insert(Permission::ExecuteActions);

        let auth_ctx = AuthorizationContext::with_permissions(
            user.id,
            user.username.clone(),
            Role::Analyst,
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

// =============================================================================
// Force Flag Rejection Tests
// =============================================================================

#[tokio::test]
async fn test_force_flag_true_is_rejected() {
    let mut registry = ActionRegistry::new();
    registry.register(Arc::new(ForceAwareAction));

    let admin = create_test_user(Role::Admin);
    let auth_ctx = AuthorizationContext::from_user(&admin);

    let context = ActionContext::new(Uuid::new_v4())
        .with_param("target", serde_json::json!("test-host"))
        .with_param("force", serde_json::json!(true))
        .with_auth_context(auth_ctx);

    let result = registry.execute("force_aware_action", context).await;

    assert!(
        matches!(result, Err(ActionError::InvalidParameters(_))),
        "Force flag should be rejected"
    );
}

#[tokio::test]
async fn test_force_flag_false_is_allowed() {
    let mut registry = ActionRegistry::new();
    registry.register(Arc::new(ForceAwareAction));

    let admin = create_test_user(Role::Admin);
    let auth_ctx = AuthorizationContext::from_user(&admin);

    let context = ActionContext::new(Uuid::new_v4())
        .with_param("target", serde_json::json!("test-host"))
        .with_param("force", serde_json::json!(false))
        .with_auth_context(auth_ctx);

    let result = registry.execute("force_aware_action", context).await;

    assert!(result.is_ok(), "Force flag set to false should be allowed");
}

#[tokio::test]
async fn test_admin_cannot_use_force_flag() {
    let mut registry = ActionRegistry::new();
    registry.register(Arc::new(ForceAwareAction));

    let admin = create_test_user(Role::Admin);
    let auth_ctx = AuthorizationContext::from_user(&admin);

    let context = ActionContext::new(Uuid::new_v4())
        .with_param("target", serde_json::json!("critical-system"))
        .with_param("force", serde_json::json!(true))
        .with_auth_context(auth_ctx);

    let result = registry.execute("force_aware_action", context).await;

    assert!(
        matches!(result, Err(ActionError::InvalidParameters(_))),
        "Even admin should not be able to use force flag"
    );
}

// =============================================================================
// Audit Logging Tests
// =============================================================================

#[tokio::test]
async fn test_unauthorized_action_is_audited() {
    let audit_log = Arc::new(ActionAuditLog::without_tracing(100));
    let mut registry = ActionRegistry::new();
    registry.set_audit_log(Arc::clone(&audit_log));
    registry.register(Arc::new(MockAction::new("test_action")));

    let context =
        ActionContext::new(Uuid::new_v4()).with_param("target", serde_json::json!("test-host"));

    let _ = registry.execute("test_action", context).await;

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

// =============================================================================
// Permission Hierarchy Tests
// =============================================================================

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

    assert!(system_ctx.validate_execute_permission().is_ok());
    assert!(system_ctx.validate_destructive_permission().is_ok());
}

// =============================================================================
// Authorization Context Tests
// =============================================================================

#[tokio::test]
async fn test_authorization_context_tracks_session() {
    let analyst = create_test_user(Role::Analyst);
    let ctx = AuthorizationContext::from_user(&analyst)
        .with_session("session-12345")
        .with_ip_address("192.168.1.100");

    assert_eq!(ctx.session_id, Some("session-12345".to_string()));
    assert_eq!(ctx.ip_address, Some("192.168.1.100".to_string()));

    assert!(ctx.has_permission(Permission::WriteIncidents));
    assert!(ctx.has_permission(Permission::ExecuteActions));
}

#[tokio::test]
async fn test_audit_identity_includes_user_info() {
    let analyst = create_test_user(Role::Analyst);
    let ctx = AuthorizationContext::from_user(&analyst);

    let identity = ctx.audit_identity();

    assert!(
        identity.contains(&analyst.id.to_string()),
        "Audit identity should include user ID"
    );
    assert!(
        identity.contains(&analyst.username),
        "Audit identity should include username"
    );
}

// =============================================================================
// Kill Switch Permission Tests
// =============================================================================

#[tokio::test]
async fn test_kill_switch_requires_admin() {
    let admin = create_test_user(Role::Admin);
    let ctx = AuthorizationContext::from_user(&admin);
    assert!(
        ctx.has_permission(Permission::ManageKillSwitch),
        "Admin should have ManageKillSwitch permission"
    );

    let analyst = create_test_user(Role::Analyst);
    let ctx = AuthorizationContext::from_user(&analyst);
    assert!(
        !ctx.has_permission(Permission::ManageKillSwitch),
        "Analyst should not have ManageKillSwitch permission"
    );

    let viewer = create_test_user(Role::Viewer);
    let ctx = AuthorizationContext::from_user(&viewer);
    assert!(
        !ctx.has_permission(Permission::ManageKillSwitch),
        "Viewer should not have ManageKillSwitch permission"
    );
}

// =============================================================================
// Management Permission Tests
// =============================================================================

#[tokio::test]
async fn test_management_permissions_require_admin() {
    let admin = create_test_user(Role::Admin);
    let admin_ctx = AuthorizationContext::from_user(&admin);

    let analyst = create_test_user(Role::Analyst);
    let analyst_ctx = AuthorizationContext::from_user(&analyst);

    // ManagePlaybooks
    assert!(admin_ctx.has_permission(Permission::ManagePlaybooks));
    assert!(!analyst_ctx.has_permission(Permission::ManagePlaybooks));

    // ManagePolicies
    assert!(admin_ctx.has_permission(Permission::ManagePolicies));
    assert!(!analyst_ctx.has_permission(Permission::ManagePolicies));

    // ManageConnectors
    assert!(admin_ctx.has_permission(Permission::ManageConnectors));
    assert!(!analyst_ctx.has_permission(Permission::ManageConnectors));

    // ManageUsers
    assert!(admin_ctx.has_permission(Permission::ManageUsers));
    assert!(!analyst_ctx.has_permission(Permission::ManageUsers));

    // ManageSettings
    assert!(admin_ctx.has_permission(Permission::ManageSettings));
    assert!(!analyst_ctx.has_permission(Permission::ManageSettings));
}

// =============================================================================
// Role Permission Assignment Tests
// =============================================================================

#[test]
fn test_admin_role_permissions() {
    let permissions = AuthorizationContext::permissions_for_role(Role::Admin);
    assert_eq!(
        permissions,
        Permission::all(),
        "Admin should have all permissions"
    );
}

#[test]
fn test_analyst_role_permissions() {
    let permissions = AuthorizationContext::permissions_for_role(Role::Analyst);

    assert!(permissions.contains(&Permission::ReadIncidents));
    assert!(permissions.contains(&Permission::WriteIncidents));
    assert!(permissions.contains(&Permission::ApproveActions));
    assert!(permissions.contains(&Permission::ExecuteActions));

    assert!(!permissions.contains(&Permission::ManageUsers));
    assert!(!permissions.contains(&Permission::ManageSettings));
    assert!(!permissions.contains(&Permission::ManagePlaybooks));
    assert!(!permissions.contains(&Permission::ManagePolicies));
    assert!(!permissions.contains(&Permission::ManageConnectors));
    assert!(!permissions.contains(&Permission::ManageKillSwitch));
}

#[test]
fn test_viewer_role_permissions() {
    let permissions = AuthorizationContext::permissions_for_role(Role::Viewer);

    assert!(permissions.contains(&Permission::ReadIncidents));
    assert_eq!(
        permissions.len(),
        1,
        "Viewer should only have one permission"
    );
}
