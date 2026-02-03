//! Tests for session-based access controls.
//!
//! These tests verify that session-based authentication properly enforces
//! role-based scopes similar to API key scopes.

use tw_core::auth::{Role, SessionData, User};
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
// Test: SessionData creation and properties
// ============================================================

#[test]
fn test_session_data_creation() {
    let user = create_test_user(Role::Analyst);
    let session = SessionData::new(&user);

    assert_eq!(session.user_id, user.id);
    assert_eq!(session.username, user.username);
    assert_eq!(session.role, user.role);
}

#[test]
fn test_session_data_has_csrf_token() {
    let user = create_test_user(Role::Analyst);
    let session = SessionData::new(&user);

    // CSRF token should be present and non-empty
    assert!(
        !session.csrf_token.is_empty(),
        "Session should have CSRF token"
    );
    assert!(
        session.csrf_token.len() >= 32,
        "CSRF token should be at least 32 characters"
    );
}

#[test]
fn test_session_csrf_tokens_are_unique() {
    let user = create_test_user(Role::Analyst);

    let session1 = SessionData::new(&user);
    let session2 = SessionData::new(&user);

    assert_ne!(
        session1.csrf_token, session2.csrf_token,
        "Each session should have a unique CSRF token"
    );
}

// ============================================================
// Test: Session role preservation
// ============================================================

#[test]
fn test_session_preserves_admin_role() {
    let user = create_test_user(Role::Admin);
    let session = SessionData::new(&user);

    assert_eq!(session.role, Role::Admin);
}

#[test]
fn test_session_preserves_analyst_role() {
    let user = create_test_user(Role::Analyst);
    let session = SessionData::new(&user);

    assert_eq!(session.role, Role::Analyst);
}

#[test]
fn test_session_preserves_viewer_role() {
    let user = create_test_user(Role::Viewer);
    let session = SessionData::new(&user);

    assert_eq!(session.role, Role::Viewer);
}

// ============================================================
// Test: Role-based scope mapping (from extractors module)
// ============================================================

/// Maps a user role to its equivalent set of API scopes.
/// This mirrors the logic in tw_api::auth::extractors::scopes_for_role
fn scopes_for_role(role: &Role) -> &'static [&'static str] {
    match role {
        Role::Admin => &["*"],
        Role::Analyst => &["read", "write", "incidents", "connectors", "webhooks"],
        Role::Viewer => &["read"],
    }
}

/// Checks if a role has a specific scope.
fn role_has_scope(role: &Role, required_scope: &str) -> bool {
    let role_scopes = scopes_for_role(role);
    role_scopes.contains(&"*") || role_scopes.contains(&required_scope)
}

#[test]
fn test_admin_session_has_all_scopes() {
    let role = Role::Admin;

    assert!(role_has_scope(&role, "read"));
    assert!(role_has_scope(&role, "write"));
    assert!(role_has_scope(&role, "incidents"));
    assert!(role_has_scope(&role, "connectors"));
    assert!(role_has_scope(&role, "admin"));
    assert!(role_has_scope(&role, "webhooks"));
    assert!(role_has_scope(&role, "settings"));
    // Wildcard grants any scope
    assert!(role_has_scope(&role, "any_scope"));
}

#[test]
fn test_analyst_session_has_operational_scopes() {
    let role = Role::Analyst;

    assert!(role_has_scope(&role, "read"));
    assert!(role_has_scope(&role, "write"));
    assert!(role_has_scope(&role, "incidents"));
    assert!(role_has_scope(&role, "connectors"));
    assert!(role_has_scope(&role, "webhooks"));

    // Analyst should NOT have admin scope
    assert!(
        !role_has_scope(&role, "admin"),
        "Analyst should not have admin scope"
    );
    assert!(
        !role_has_scope(&role, "settings"),
        "Analyst should not have settings scope"
    );
}

#[test]
fn test_viewer_session_has_read_only_scope() {
    let role = Role::Viewer;

    assert!(role_has_scope(&role, "read"));

    // Viewer should NOT have any write scopes
    assert!(
        !role_has_scope(&role, "write"),
        "Viewer should not have write scope"
    );
    assert!(
        !role_has_scope(&role, "incidents"),
        "Viewer should not have incidents scope"
    );
    assert!(
        !role_has_scope(&role, "admin"),
        "Viewer should not have admin scope"
    );
    assert!(
        !role_has_scope(&role, "connectors"),
        "Viewer should not have connectors scope"
    );
}

// ============================================================
// Test: Session-based access control scenarios
// ============================================================

#[test]
fn test_viewer_session_cannot_access_write_endpoints() {
    let user = create_test_user(Role::Viewer);
    let session = SessionData::new(&user);

    // Viewer session should not have write scope
    assert!(
        !role_has_scope(&session.role, "write"),
        "Viewer session should not access write endpoints"
    );
}

#[test]
fn test_viewer_session_cannot_manage_incidents() {
    let user = create_test_user(Role::Viewer);
    let session = SessionData::new(&user);

    // Viewer session should not have incidents scope
    assert!(
        !role_has_scope(&session.role, "incidents"),
        "Viewer session should not manage incidents"
    );
}

#[test]
fn test_analyst_session_can_manage_incidents() {
    let user = create_test_user(Role::Analyst);
    let session = SessionData::new(&user);

    // Analyst session should have incidents scope
    assert!(
        role_has_scope(&session.role, "incidents"),
        "Analyst session should manage incidents"
    );
}

#[test]
fn test_analyst_session_cannot_access_admin_endpoints() {
    let user = create_test_user(Role::Analyst);
    let session = SessionData::new(&user);

    // Analyst session should not have admin scope
    assert!(
        !role_has_scope(&session.role, "admin"),
        "Analyst session should not access admin endpoints"
    );
}

// ============================================================
// Test: Session user ID consistency
// ============================================================

#[test]
fn test_session_user_id_matches_user() {
    let user = create_test_user(Role::Analyst);
    let session = SessionData::new(&user);

    assert_eq!(
        session.user_id, user.id,
        "Session user_id should match the user"
    );
}

#[test]
fn test_session_username_matches_user() {
    let user = create_test_user(Role::Analyst);
    let session = SessionData::new(&user);

    assert_eq!(
        session.username, user.username,
        "Session username should match the user"
    );
}

// ============================================================
// Test: Role comparison for permission checks
// ============================================================

#[test]
fn test_role_permission_hierarchy() {
    // Admin has all permissions
    assert!(Role::Admin.has_permission(Role::Admin));
    assert!(Role::Admin.has_permission(Role::Analyst));
    assert!(Role::Admin.has_permission(Role::Viewer));

    // Analyst has analyst and viewer permissions
    assert!(!Role::Analyst.has_permission(Role::Admin));
    assert!(Role::Analyst.has_permission(Role::Analyst));
    assert!(Role::Analyst.has_permission(Role::Viewer));

    // Viewer only has viewer permissions
    assert!(!Role::Viewer.has_permission(Role::Admin));
    assert!(!Role::Viewer.has_permission(Role::Analyst));
    assert!(Role::Viewer.has_permission(Role::Viewer));
}

// ============================================================
// Test: Session serialization/deserialization (for storage)
// ============================================================

#[test]
fn test_session_data_serialization() {
    let user = create_test_user(Role::Analyst);
    let session = SessionData::new(&user);

    // Should serialize to JSON
    let json = serde_json::to_string(&session).expect("Should serialize");
    assert!(!json.is_empty());

    // Should deserialize back
    let deserialized: SessionData =
        serde_json::from_str(&json).expect("Should deserialize");

    assert_eq!(deserialized.user_id, session.user_id);
    assert_eq!(deserialized.username, session.username);
    assert_eq!(deserialized.role, session.role);
    assert_eq!(deserialized.csrf_token, session.csrf_token);
}

#[test]
fn test_session_data_roundtrip() {
    for role in [Role::Admin, Role::Analyst, Role::Viewer] {
        let user = create_test_user(role);
        let session = SessionData::new(&user);

        let json = serde_json::to_string(&session).expect("Should serialize");
        let deserialized: SessionData =
            serde_json::from_str(&json).expect("Should deserialize");

        assert_eq!(deserialized.role, role, "Role should roundtrip for {:?}", role);
    }
}

// ============================================================
// Test: User state validation for sessions
// ============================================================

#[test]
fn test_user_enabled_state() {
    let mut user = create_test_user(Role::Analyst);
    assert!(user.enabled, "New user should be enabled by default");

    user.enabled = false;
    assert!(!user.enabled, "Disabled user should be disabled");
}

#[test]
fn test_user_has_permission_method() {
    let admin = create_test_user(Role::Admin);
    assert!(admin.has_permission(Role::Admin));
    assert!(admin.has_permission(Role::Analyst));
    assert!(admin.has_permission(Role::Viewer));

    let analyst = create_test_user(Role::Analyst);
    assert!(!analyst.has_permission(Role::Admin));
    assert!(analyst.has_permission(Role::Analyst));
    assert!(analyst.has_permission(Role::Viewer));

    let viewer = create_test_user(Role::Viewer);
    assert!(!viewer.has_permission(Role::Admin));
    assert!(!viewer.has_permission(Role::Analyst));
    assert!(viewer.has_permission(Role::Viewer));
}

#[test]
fn test_user_is_admin_method() {
    let admin = create_test_user(Role::Admin);
    assert!(admin.is_admin());

    let analyst = create_test_user(Role::Analyst);
    assert!(!analyst.is_admin());

    let viewer = create_test_user(Role::Viewer);
    assert!(!viewer.is_admin());
}

// ============================================================
// Test: Session scope enforcement with extractors
// ============================================================

#[test]
fn test_scope_enforcement_for_read_operations() {
    // All roles should be able to read
    assert!(role_has_scope(&Role::Admin, "read"));
    assert!(role_has_scope(&Role::Analyst, "read"));
    assert!(role_has_scope(&Role::Viewer, "read"));
}

#[test]
fn test_scope_enforcement_for_write_operations() {
    // Only Admin and Analyst should be able to write
    assert!(role_has_scope(&Role::Admin, "write"));
    assert!(role_has_scope(&Role::Analyst, "write"));
    assert!(!role_has_scope(&Role::Viewer, "write"));
}

#[test]
fn test_scope_enforcement_for_admin_operations() {
    // Only Admin should access admin operations
    assert!(role_has_scope(&Role::Admin, "admin"));
    assert!(!role_has_scope(&Role::Analyst, "admin"));
    assert!(!role_has_scope(&Role::Viewer, "admin"));
}

#[test]
fn test_scope_enforcement_for_webhook_operations() {
    // Admin (via wildcard) and Analyst should access webhooks
    assert!(role_has_scope(&Role::Admin, "webhooks"));
    assert!(role_has_scope(&Role::Analyst, "webhooks"));
    assert!(!role_has_scope(&Role::Viewer, "webhooks"));
}
