//! Tests for workflow transition authorization.
//!
//! These tests verify that state transitions in workflows require proper
//! authorization, ensuring the security of workflow state changes.

use std::collections::HashSet;

use tw_core::auth::{AuthorizationContext, Permission, Role, User};
use uuid::Uuid;

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
// Test: WriteIncidents permission required for state changes
// ============================================================

#[tokio::test]
async fn test_viewer_cannot_modify_incident_state() {
    let viewer = create_test_user(Role::Viewer);
    let ctx = AuthorizationContext::from_user(&viewer);

    // Viewer should NOT have WriteIncidents permission
    assert!(
        !ctx.has_permission(Permission::WriteIncidents),
        "Viewer should not have WriteIncidents permission"
    );
}

#[tokio::test]
async fn test_analyst_can_modify_incident_state() {
    let analyst = create_test_user(Role::Analyst);
    let ctx = AuthorizationContext::from_user(&analyst);

    // Analyst SHOULD have WriteIncidents permission
    assert!(
        ctx.has_permission(Permission::WriteIncidents),
        "Analyst should have WriteIncidents permission"
    );
}

#[tokio::test]
async fn test_admin_can_modify_incident_state() {
    let admin = create_test_user(Role::Admin);
    let ctx = AuthorizationContext::from_user(&admin);

    // Admin SHOULD have WriteIncidents permission
    assert!(
        ctx.has_permission(Permission::WriteIncidents),
        "Admin should have WriteIncidents permission"
    );
}

// ============================================================
// Test: ApproveActions permission required for approval workflows
// ============================================================

#[tokio::test]
async fn test_viewer_cannot_approve_actions() {
    let viewer = create_test_user(Role::Viewer);
    let ctx = AuthorizationContext::from_user(&viewer);

    // Viewer should NOT have ApproveActions permission
    assert!(
        !ctx.has_permission(Permission::ApproveActions),
        "Viewer should not have ApproveActions permission"
    );
}

#[tokio::test]
async fn test_analyst_can_approve_actions() {
    let analyst = create_test_user(Role::Analyst);
    let ctx = AuthorizationContext::from_user(&analyst);

    // Analyst SHOULD have ApproveActions permission
    assert!(
        ctx.has_permission(Permission::ApproveActions),
        "Analyst should have ApproveActions permission"
    );
}

// ============================================================
// Test: Multi-permission workflow transitions
// ============================================================

#[tokio::test]
async fn test_destructive_workflow_requires_multiple_permissions() {
    // Destructive workflows require both ExecuteActions AND ApproveActions
    let analyst = create_test_user(Role::Analyst);
    let ctx = AuthorizationContext::from_user(&analyst);

    // Analyst should have both
    assert!(
        ctx.has_all_permissions(&[Permission::ExecuteActions, Permission::ApproveActions]),
        "Analyst should have both ExecuteActions and ApproveActions"
    );

    // Viewer should have neither
    let viewer = create_test_user(Role::Viewer);
    let ctx = AuthorizationContext::from_user(&viewer);

    assert!(
        !ctx.has_all_permissions(&[Permission::ExecuteActions, Permission::ApproveActions]),
        "Viewer should not have destructive workflow permissions"
    );
}

#[tokio::test]
async fn test_has_any_permission_for_workflow_access() {
    let viewer = create_test_user(Role::Viewer);
    let ctx = AuthorizationContext::from_user(&viewer);

    // Viewer can read but not write - should have ANY of read permissions
    assert!(
        ctx.has_any_permission(&[Permission::ReadIncidents, Permission::WriteIncidents]),
        "Viewer should have at least read permission"
    );

    // But viewer should NOT have ANY write permissions
    assert!(
        !ctx.has_any_permission(&[
            Permission::WriteIncidents,
            Permission::ApproveActions,
            Permission::ExecuteActions
        ]),
        "Viewer should not have any write permissions"
    );
}

// ============================================================
// Test: Custom permission sets for workflow-specific access
// ============================================================

#[tokio::test]
async fn test_custom_permission_set_for_read_only_operator() {
    // Create a read-only operator context
    let mut permissions = HashSet::new();
    permissions.insert(Permission::ReadIncidents);

    let ctx = AuthorizationContext::with_permissions(
        Uuid::new_v4(),
        "readonly_operator",
        Role::Viewer,
        permissions,
    );

    // Can read but not write
    assert!(ctx.has_permission(Permission::ReadIncidents));
    assert!(!ctx.has_permission(Permission::WriteIncidents));
    assert!(!ctx.has_permission(Permission::ExecuteActions));
}

#[tokio::test]
async fn test_custom_permission_set_for_limited_analyst() {
    // Create an analyst that can only read and write, but not execute
    let mut permissions = HashSet::new();
    permissions.insert(Permission::ReadIncidents);
    permissions.insert(Permission::WriteIncidents);
    // Explicitly NOT adding ExecuteActions

    let ctx = AuthorizationContext::with_permissions(
        Uuid::new_v4(),
        "limited_analyst",
        Role::Analyst,
        permissions,
    );

    // Can read and write
    assert!(ctx.has_permission(Permission::ReadIncidents));
    assert!(ctx.has_permission(Permission::WriteIncidents));

    // But cannot execute
    assert!(
        !ctx.has_permission(Permission::ExecuteActions),
        "Limited analyst should not have execute permission"
    );

    // validate_execute_permission should fail
    assert!(
        ctx.validate_execute_permission().is_err(),
        "Limited analyst should fail execute validation"
    );
}

// ============================================================
// Test: Workflow transition with session tracking
// ============================================================

#[tokio::test]
async fn test_authorization_context_tracks_session() {
    let analyst = create_test_user(Role::Analyst);
    let ctx = AuthorizationContext::from_user(&analyst)
        .with_session("session-12345")
        .with_ip_address("192.168.1.100");

    // Session and IP should be tracked
    assert_eq!(ctx.session_id, Some("session-12345".to_string()));
    assert_eq!(ctx.ip_address, Some("192.168.1.100".to_string()));

    // Should still have proper permissions
    assert!(ctx.has_permission(Permission::WriteIncidents));
    assert!(ctx.has_permission(Permission::ExecuteActions));
}

#[tokio::test]
async fn test_audit_identity_includes_user_info() {
    let analyst = create_test_user(Role::Analyst);
    let ctx = AuthorizationContext::from_user(&analyst);

    let identity = ctx.audit_identity();

    // Should include user ID and name for audit trail
    assert!(
        identity.contains(&analyst.id.to_string()),
        "Audit identity should include user ID"
    );
    assert!(
        identity.contains(&analyst.username),
        "Audit identity should include username"
    );
}

// ============================================================
// Test: Kill switch permission is restricted
// ============================================================

#[tokio::test]
async fn test_kill_switch_requires_admin_or_specific_permission() {
    // Only Admin should have ManageKillSwitch by default
    let admin = create_test_user(Role::Admin);
    let ctx = AuthorizationContext::from_user(&admin);
    assert!(
        ctx.has_permission(Permission::ManageKillSwitch),
        "Admin should have ManageKillSwitch permission"
    );

    // Analyst should NOT have it by default
    let analyst = create_test_user(Role::Analyst);
    let ctx = AuthorizationContext::from_user(&analyst);
    assert!(
        !ctx.has_permission(Permission::ManageKillSwitch),
        "Analyst should not have ManageKillSwitch permission"
    );

    // Viewer should NOT have it
    let viewer = create_test_user(Role::Viewer);
    let ctx = AuthorizationContext::from_user(&viewer);
    assert!(
        !ctx.has_permission(Permission::ManageKillSwitch),
        "Viewer should not have ManageKillSwitch permission"
    );
}

// ============================================================
// Test: Playbook and policy management permissions
// ============================================================

#[tokio::test]
async fn test_playbook_management_requires_admin() {
    // Only Admin should have ManagePlaybooks by default
    let admin = create_test_user(Role::Admin);
    let ctx = AuthorizationContext::from_user(&admin);
    assert!(
        ctx.has_permission(Permission::ManagePlaybooks),
        "Admin should have ManagePlaybooks permission"
    );

    let analyst = create_test_user(Role::Analyst);
    let ctx = AuthorizationContext::from_user(&analyst);
    assert!(
        !ctx.has_permission(Permission::ManagePlaybooks),
        "Analyst should not have ManagePlaybooks permission"
    );
}

#[tokio::test]
async fn test_policy_management_requires_admin() {
    // Only Admin should have ManagePolicies by default
    let admin = create_test_user(Role::Admin);
    let ctx = AuthorizationContext::from_user(&admin);
    assert!(
        ctx.has_permission(Permission::ManagePolicies),
        "Admin should have ManagePolicies permission"
    );

    let analyst = create_test_user(Role::Analyst);
    let ctx = AuthorizationContext::from_user(&analyst);
    assert!(
        !ctx.has_permission(Permission::ManagePolicies),
        "Analyst should not have ManagePolicies permission"
    );
}

// ============================================================
// Test: Connector management permissions
// ============================================================

#[tokio::test]
async fn test_connector_management_requires_admin() {
    // Only Admin should have ManageConnectors by default
    let admin = create_test_user(Role::Admin);
    let ctx = AuthorizationContext::from_user(&admin);
    assert!(
        ctx.has_permission(Permission::ManageConnectors),
        "Admin should have ManageConnectors permission"
    );

    let analyst = create_test_user(Role::Analyst);
    let ctx = AuthorizationContext::from_user(&analyst);
    assert!(
        !ctx.has_permission(Permission::ManageConnectors),
        "Analyst should not have ManageConnectors permission"
    );
}

// ============================================================
// Test: User management permissions
// ============================================================

#[tokio::test]
async fn test_user_management_requires_admin() {
    // Only Admin should have ManageUsers by default
    let admin = create_test_user(Role::Admin);
    let ctx = AuthorizationContext::from_user(&admin);
    assert!(
        ctx.has_permission(Permission::ManageUsers),
        "Admin should have ManageUsers permission"
    );

    let analyst = create_test_user(Role::Analyst);
    let ctx = AuthorizationContext::from_user(&analyst);
    assert!(
        !ctx.has_permission(Permission::ManageUsers),
        "Analyst should not have ManageUsers permission"
    );

    let viewer = create_test_user(Role::Viewer);
    let ctx = AuthorizationContext::from_user(&viewer);
    assert!(
        !ctx.has_permission(Permission::ManageUsers),
        "Viewer should not have ManageUsers permission"
    );
}

// ============================================================
// Test: Settings management permissions
// ============================================================

#[tokio::test]
async fn test_settings_management_requires_admin() {
    // Only Admin should have ManageSettings by default
    let admin = create_test_user(Role::Admin);
    let ctx = AuthorizationContext::from_user(&admin);
    assert!(
        ctx.has_permission(Permission::ManageSettings),
        "Admin should have ManageSettings permission"
    );

    let analyst = create_test_user(Role::Analyst);
    let ctx = AuthorizationContext::from_user(&analyst);
    assert!(
        !ctx.has_permission(Permission::ManageSettings),
        "Analyst should not have ManageSettings permission"
    );
}

// ============================================================
// Test: Role-based permission assignments are correct
// ============================================================

#[tokio::test]
async fn test_admin_role_permissions() {
    let permissions = AuthorizationContext::permissions_for_role(Role::Admin);

    // Admin should have ALL permissions
    assert_eq!(
        permissions,
        Permission::all(),
        "Admin should have all permissions"
    );
}

#[tokio::test]
async fn test_analyst_role_permissions() {
    let permissions = AuthorizationContext::permissions_for_role(Role::Analyst);

    // Analyst should have operational permissions
    assert!(permissions.contains(&Permission::ReadIncidents));
    assert!(permissions.contains(&Permission::WriteIncidents));
    assert!(permissions.contains(&Permission::ApproveActions));
    assert!(permissions.contains(&Permission::ExecuteActions));

    // But not management permissions
    assert!(!permissions.contains(&Permission::ManageUsers));
    assert!(!permissions.contains(&Permission::ManageSettings));
    assert!(!permissions.contains(&Permission::ManagePlaybooks));
    assert!(!permissions.contains(&Permission::ManagePolicies));
    assert!(!permissions.contains(&Permission::ManageConnectors));
    assert!(!permissions.contains(&Permission::ManageKillSwitch));
}

#[tokio::test]
async fn test_viewer_role_permissions() {
    let permissions = AuthorizationContext::permissions_for_role(Role::Viewer);

    // Viewer should only have read permission
    assert!(permissions.contains(&Permission::ReadIncidents));
    assert_eq!(permissions.len(), 1, "Viewer should only have one permission");
}
