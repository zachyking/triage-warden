//! Tests for API key scope enforcement.
//!
//! These tests verify that API keys can only access their allowed scopes,
//! ensuring proper scope-based access control.

use chrono::{Duration, Utc};
use tw_core::auth::{ApiKey, Role};
use uuid::Uuid;

// ============================================================
// Test: API key scope checking
// ============================================================

#[test]
fn test_api_key_has_scope_exact_match() {
    let user_id = Uuid::new_v4();
    let (api_key, _) = ApiKey::new(
        user_id,
        "Test Key",
        vec!["read".to_string(), "incidents".to_string()],
    );

    assert!(api_key.has_scope("read"), "Should have 'read' scope");
    assert!(
        api_key.has_scope("incidents"),
        "Should have 'incidents' scope"
    );
    assert!(
        !api_key.has_scope("write"),
        "Should NOT have 'write' scope"
    );
    assert!(
        !api_key.has_scope("admin"),
        "Should NOT have 'admin' scope"
    );
}

#[test]
fn test_api_key_wildcard_scope_grants_all() {
    let user_id = Uuid::new_v4();
    let (api_key, _) = ApiKey::new(user_id, "Test Key", vec!["*".to_string()]);

    // Wildcard should grant access to any scope
    assert!(
        api_key.has_scope("read"),
        "Wildcard should grant 'read' scope"
    );
    assert!(
        api_key.has_scope("write"),
        "Wildcard should grant 'write' scope"
    );
    assert!(
        api_key.has_scope("incidents"),
        "Wildcard should grant 'incidents' scope"
    );
    assert!(
        api_key.has_scope("admin"),
        "Wildcard should grant 'admin' scope"
    );
    assert!(
        api_key.has_scope("any_scope"),
        "Wildcard should grant any scope"
    );
}

#[test]
fn test_api_key_empty_scopes_denies_all() {
    let user_id = Uuid::new_v4();
    let (api_key, _) = ApiKey::new(user_id, "Test Key", vec![]);

    // Empty scopes should deny everything
    assert!(
        !api_key.has_scope("read"),
        "Empty scopes should deny 'read'"
    );
    assert!(
        !api_key.has_scope("write"),
        "Empty scopes should deny 'write'"
    );
}

#[test]
fn test_api_key_scope_is_case_sensitive() {
    let user_id = Uuid::new_v4();
    let (api_key, _) = ApiKey::new(user_id, "Test Key", vec!["Read".to_string()]);

    // Scope matching is case-sensitive
    assert!(api_key.has_scope("Read"), "Should have 'Read' scope");
    assert!(
        !api_key.has_scope("read"),
        "Should NOT have 'read' (lowercase)"
    );
    assert!(
        !api_key.has_scope("READ"),
        "Should NOT have 'READ' (uppercase)"
    );
}

// ============================================================
// Test: API key expiration
// ============================================================

#[test]
fn test_api_key_not_expired_when_no_expiration() {
    let user_id = Uuid::new_v4();
    let (api_key, _) = ApiKey::new(user_id, "Test Key", vec!["read".to_string()]);

    // Key without expiration should never be expired
    assert!(
        !api_key.is_expired(),
        "Key without expiration should not be expired"
    );
}

#[test]
fn test_api_key_expired_when_past_expiration() {
    let user_id = Uuid::new_v4();
    let (mut api_key, _) = ApiKey::new(user_id, "Test Key", vec!["read".to_string()]);

    // Set expiration to 1 hour ago
    api_key.expires_at = Some(Utc::now() - Duration::hours(1));

    assert!(api_key.is_expired(), "Key should be expired");
}

#[test]
fn test_api_key_not_expired_when_future_expiration() {
    let user_id = Uuid::new_v4();
    let (mut api_key, _) = ApiKey::new(user_id, "Test Key", vec!["read".to_string()]);

    // Set expiration to 1 hour from now
    api_key.expires_at = Some(Utc::now() + Duration::hours(1));

    assert!(!api_key.is_expired(), "Key should not be expired yet");
}

// ============================================================
// Test: API key verification
// ============================================================

#[test]
fn test_api_key_verify_correct_key() {
    let user_id = Uuid::new_v4();
    let (api_key, raw_key) = ApiKey::new(user_id, "Test Key", vec!["read".to_string()]);

    assert!(
        api_key.verify(&raw_key),
        "Should verify with correct raw key"
    );
}

#[test]
fn test_api_key_verify_wrong_key() {
    let user_id = Uuid::new_v4();
    let (api_key, _) = ApiKey::new(user_id, "Test Key", vec!["read".to_string()]);

    assert!(
        !api_key.verify("wrong_key"),
        "Should NOT verify with wrong key"
    );
    assert!(
        !api_key.verify("tw_wrong_prefix_wrong_secret"),
        "Should NOT verify with wrong formatted key"
    );
}

#[test]
fn test_api_key_verify_similar_key() {
    let user_id = Uuid::new_v4();
    let (api_key, raw_key) = ApiKey::new(user_id, "Test Key", vec!["read".to_string()]);

    // Modify one character of the raw key
    let mut modified_key = raw_key.clone();
    if let Some(last_char) = modified_key.pop() {
        let new_char = if last_char == 'a' { 'b' } else { 'a' };
        modified_key.push(new_char);
    }

    assert!(
        !api_key.verify(&modified_key),
        "Should NOT verify with slightly modified key"
    );
}

// ============================================================
// Test: API key prefix format
// ============================================================

#[test]
fn test_api_key_prefix_format() {
    let user_id = Uuid::new_v4();
    let (api_key, raw_key) = ApiKey::new(user_id, "Test Key", vec!["read".to_string()]);

    // Raw key should start with "tw_"
    assert!(
        raw_key.starts_with("tw_"),
        "Raw key should start with 'tw_'"
    );

    // Key prefix should also start with "tw_"
    assert!(
        api_key.key_prefix.starts_with("tw_"),
        "Key prefix should start with 'tw_'"
    );

    // Raw key should contain the prefix
    assert!(
        raw_key.starts_with(&api_key.key_prefix),
        "Raw key should start with the prefix"
    );
}

#[test]
fn test_api_key_format_has_three_parts() {
    let user_id = Uuid::new_v4();
    let (_, raw_key) = ApiKey::new(user_id, "Test Key", vec!["read".to_string()]);

    // Raw key format: tw_<prefix>_<secret>
    let parts: Vec<&str> = raw_key.splitn(3, '_').collect();
    assert_eq!(parts.len(), 3, "Raw key should have 3 parts separated by '_'");
    assert_eq!(parts[0], "tw", "First part should be 'tw'");
    assert_eq!(parts[1].len(), 6, "Prefix should be 6 characters");
    assert_eq!(parts[2].len(), 32, "Secret should be 32 characters");
}

// ============================================================
// Test: Scope-based access control scenarios
// ============================================================

#[test]
fn test_read_only_api_key_cannot_write() {
    let user_id = Uuid::new_v4();
    let (api_key, _) = ApiKey::new(user_id, "Read Only Key", vec!["read".to_string()]);

    assert!(api_key.has_scope("read"), "Should have read scope");
    assert!(
        !api_key.has_scope("write"),
        "Should NOT have write scope"
    );
    assert!(
        !api_key.has_scope("incidents"),
        "Should NOT have incidents scope"
    );
}

#[test]
fn test_incidents_api_key_limited_to_incidents() {
    let user_id = Uuid::new_v4();
    let (api_key, _) = ApiKey::new(user_id, "Incidents Key", vec!["incidents".to_string()]);

    assert!(api_key.has_scope("incidents"), "Should have incidents scope");
    assert!(
        !api_key.has_scope("connectors"),
        "Should NOT have connectors scope"
    );
    assert!(
        !api_key.has_scope("admin"),
        "Should NOT have admin scope"
    );
}

#[test]
fn test_multi_scope_api_key() {
    let user_id = Uuid::new_v4();
    let (api_key, _) = ApiKey::new(
        user_id,
        "Multi-Scope Key",
        vec![
            "read".to_string(),
            "write".to_string(),
            "incidents".to_string(),
        ],
    );

    assert!(api_key.has_scope("read"), "Should have read scope");
    assert!(api_key.has_scope("write"), "Should have write scope");
    assert!(api_key.has_scope("incidents"), "Should have incidents scope");
    assert!(
        !api_key.has_scope("admin"),
        "Should NOT have admin scope"
    );
    assert!(
        !api_key.has_scope("connectors"),
        "Should NOT have connectors scope"
    );
}

// ============================================================
// Test: Standard API key scopes
// ============================================================

#[test]
fn test_standard_scopes() {
    // Verify the standard scopes are well-defined
    let valid_scopes = vec![
        "read",
        "write",
        "incidents",
        "connectors",
        "playbooks",
        "settings",
        "admin",
        "webhooks",
        "*",
    ];

    for scope in &valid_scopes {
        let user_id = Uuid::new_v4();
        let (api_key, _) = ApiKey::new(user_id, "Test Key", vec![scope.to_string()]);
        assert!(
            api_key.has_scope(scope),
            "Should have {} scope",
            scope
        );
    }
}

// ============================================================
// Test: API key creation with user association
// ============================================================

#[test]
fn test_api_key_associated_with_user() {
    let user_id = Uuid::new_v4();
    let (api_key, _) = ApiKey::new(user_id, "Test Key", vec!["read".to_string()]);

    assert_eq!(
        api_key.user_id, user_id,
        "API key should be associated with the correct user"
    );
}

#[test]
fn test_api_key_has_unique_id() {
    let user_id = Uuid::new_v4();
    let (api_key1, _) = ApiKey::new(user_id, "Key 1", vec!["read".to_string()]);
    let (api_key2, _) = ApiKey::new(user_id, "Key 2", vec!["read".to_string()]);

    assert_ne!(
        api_key1.id, api_key2.id,
        "Each API key should have a unique ID"
    );
}

#[test]
fn test_api_key_has_creation_timestamp() {
    let before = Utc::now();
    let user_id = Uuid::new_v4();
    let (api_key, _) = ApiKey::new(user_id, "Test Key", vec!["read".to_string()]);
    let after = Utc::now();

    assert!(
        api_key.created_at >= before && api_key.created_at <= after,
        "API key should have a valid creation timestamp"
    );
}

// ============================================================
// Test: API key security properties
// ============================================================

#[test]
fn test_api_key_hash_is_not_raw_key() {
    let user_id = Uuid::new_v4();
    let (api_key, raw_key) = ApiKey::new(user_id, "Test Key", vec!["read".to_string()]);

    assert_ne!(
        api_key.key_hash, raw_key,
        "Key hash should not be the raw key"
    );
    assert!(
        !api_key.key_hash.contains(&raw_key),
        "Key hash should not contain the raw key"
    );
}

#[test]
fn test_api_key_raw_keys_are_unique() {
    let user_id = Uuid::new_v4();
    let (_, raw_key1) = ApiKey::new(user_id, "Key 1", vec!["read".to_string()]);
    let (_, raw_key2) = ApiKey::new(user_id, "Key 2", vec!["read".to_string()]);

    assert_ne!(raw_key1, raw_key2, "Each raw key should be unique");
}

#[test]
fn test_api_key_verification_is_timing_safe() {
    // This is a design verification - the verify function should use constant-time comparison
    // We can't truly test this in a unit test, but we verify the function works correctly
    let user_id = Uuid::new_v4();
    let (api_key, raw_key) = ApiKey::new(user_id, "Test Key", vec!["read".to_string()]);

    // Multiple verifications should give consistent results
    for _ in 0..100 {
        assert!(api_key.verify(&raw_key), "Verification should be consistent");
    }

    // Wrong keys should also be consistent
    for _ in 0..100 {
        assert!(
            !api_key.verify("wrong_key"),
            "Rejection should be consistent"
        );
    }
}

// ============================================================
// Test: Role-to-scope mapping
// ============================================================

#[test]
fn test_admin_role_maps_to_wildcard_scope() {
    // Admin users should effectively have wildcard access
    // This is tested via the extractors, but we document the expected behavior here
    let admin_scopes = vec!["*".to_string()];
    let user_id = Uuid::new_v4();
    let (api_key, _) = ApiKey::new(user_id, "Admin Key", admin_scopes);

    // Admin key with wildcard should access everything
    assert!(api_key.has_scope("read"));
    assert!(api_key.has_scope("write"));
    assert!(api_key.has_scope("incidents"));
    assert!(api_key.has_scope("admin"));
    assert!(api_key.has_scope("connectors"));
    assert!(api_key.has_scope("settings"));
}

#[test]
fn test_analyst_role_scopes() {
    // Analyst should have operational scopes
    let analyst_scopes = vec![
        "read".to_string(),
        "write".to_string(),
        "incidents".to_string(),
        "connectors".to_string(),
        "webhooks".to_string(),
    ];
    let user_id = Uuid::new_v4();
    let (api_key, _) = ApiKey::new(user_id, "Analyst Key", analyst_scopes);

    assert!(api_key.has_scope("read"));
    assert!(api_key.has_scope("write"));
    assert!(api_key.has_scope("incidents"));
    assert!(api_key.has_scope("connectors"));
    assert!(api_key.has_scope("webhooks"));

    // But NOT admin scope
    assert!(!api_key.has_scope("admin"));
}

#[test]
fn test_viewer_role_scopes() {
    // Viewer should only have read scope
    let viewer_scopes = vec!["read".to_string()];
    let user_id = Uuid::new_v4();
    let (api_key, _) = ApiKey::new(user_id, "Viewer Key", viewer_scopes);

    assert!(api_key.has_scope("read"));
    assert!(!api_key.has_scope("write"));
    assert!(!api_key.has_scope("incidents"));
    assert!(!api_key.has_scope("admin"));
}
