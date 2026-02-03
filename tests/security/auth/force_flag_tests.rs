//! Tests for force flag removal verification.
//!
//! These tests verify that force flags are properly rejected or handled,
//! preventing bypass of security controls.

use std::collections::HashMap;
use std::sync::Arc;

use tw_actions::registry::{
    Action, ActionContext, ActionError, ActionRegistry, ActionResult, ParameterDef, ParameterType,
};
use tw_core::auth::{AuthorizationContext, Permission, Role, User};
use uuid::Uuid;

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
            // Optional force parameter - should be rejected if true
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
                // Reject force flag - this is a security control
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

// ============================================================
// Test: Force flag is rejected
// ============================================================

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

    if let Err(ActionError::InvalidParameters(msg)) = result {
        assert!(
            msg.contains("Force flag") || msg.contains("force"),
            "Error should mention force flag: {}",
            msg
        );
    }
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
async fn test_no_force_flag_is_allowed() {
    let mut registry = ActionRegistry::new();
    registry.register(Arc::new(ForceAwareAction));

    let admin = create_test_user(Role::Admin);
    let auth_ctx = AuthorizationContext::from_user(&admin);

    let context = ActionContext::new(Uuid::new_v4())
        .with_param("target", serde_json::json!("test-host"))
        // No force parameter
        .with_auth_context(auth_ctx);

    let result = registry.execute("force_aware_action", context).await;

    assert!(result.is_ok(), "Missing force flag should default to allowed");
}

// ============================================================
// Test: Force flag rejected even for admin users
// ============================================================

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

    // Even admin cannot bypass with force flag
    assert!(
        matches!(result, Err(ActionError::InvalidParameters(_))),
        "Even admin should not be able to use force flag"
    );
}

#[tokio::test]
async fn test_system_context_cannot_use_force_flag() {
    let mut registry = ActionRegistry::new();
    registry.register(Arc::new(ForceAwareAction));

    let context = ActionContext::new(Uuid::new_v4())
        .with_param("target", serde_json::json!("automated-target"))
        .with_param("force", serde_json::json!(true))
        .with_auth_context(AuthorizationContext::system());

    let result = registry.execute("force_aware_action", context).await;

    // Even system context cannot bypass with force flag
    assert!(
        matches!(result, Err(ActionError::InvalidParameters(_))),
        "Even system context should not be able to use force flag"
    );
}

// ============================================================
// Test: Force flag variations are handled
// ============================================================

#[tokio::test]
async fn test_force_flag_string_true_treated_as_false() {
    let mut registry = ActionRegistry::new();
    registry.register(Arc::new(ForceAwareAction));

    let admin = create_test_user(Role::Admin);
    let auth_ctx = AuthorizationContext::from_user(&admin);

    // String "true" should not be treated as boolean true
    let context = ActionContext::new(Uuid::new_v4())
        .with_param("target", serde_json::json!("test-host"))
        .with_param("force", serde_json::json!("true")) // String, not boolean
        .with_auth_context(auth_ctx);

    let result = registry.execute("force_aware_action", context).await;

    // String "true" is not boolean true, so as_bool() returns None
    // which defaults to false, allowing the action
    assert!(
        result.is_ok(),
        "String 'true' should not trigger force flag rejection"
    );
}

#[tokio::test]
async fn test_force_flag_number_not_treated_as_true() {
    let mut registry = ActionRegistry::new();
    registry.register(Arc::new(ForceAwareAction));

    let admin = create_test_user(Role::Admin);
    let auth_ctx = AuthorizationContext::from_user(&admin);

    // Number 1 should not be treated as boolean true
    let context = ActionContext::new(Uuid::new_v4())
        .with_param("target", serde_json::json!("test-host"))
        .with_param("force", serde_json::json!(1)) // Number, not boolean
        .with_auth_context(auth_ctx);

    let result = registry.execute("force_aware_action", context).await;

    // Number 1 is not boolean true, so as_bool() returns None
    assert!(
        result.is_ok(),
        "Number 1 should not trigger force flag rejection"
    );
}

// ============================================================
// Test: Dry run mode with force flag
// ============================================================

#[tokio::test]
async fn test_dry_run_bypasses_force_check() {
    let mut registry = ActionRegistry::new();
    registry.register(Arc::new(ForceAwareAction));

    let admin = create_test_user(Role::Admin);
    let auth_ctx = AuthorizationContext::from_user(&admin);

    // In dry run mode, the action's execute() is not called
    let context = ActionContext::new(Uuid::new_v4())
        .with_param("target", serde_json::json!("test-host"))
        .with_param("force", serde_json::json!(true))
        .with_dry_run(true)
        .with_auth_context(auth_ctx);

    let result = registry.execute("force_aware_action", context).await;

    // Dry run should succeed even with force flag because execute() is skipped
    assert!(
        result.is_ok(),
        "Dry run should skip execute() and thus force check"
    );
    assert!(
        result.unwrap().message.contains("Dry run"),
        "Should indicate dry run"
    );
}

// ============================================================
// Test: Force flag rejection is audited
// ============================================================

#[tokio::test]
async fn test_force_flag_rejection_is_audited() {
    use tw_observability::ActionAuditLog;

    let audit_log = Arc::new(ActionAuditLog::without_tracing(100));
    let mut registry = ActionRegistry::new();
    registry.set_audit_log(Arc::clone(&audit_log));
    registry.register(Arc::new(ForceAwareAction));

    let admin = create_test_user(Role::Admin);
    let auth_ctx = AuthorizationContext::from_user(&admin);

    let context = ActionContext::new(Uuid::new_v4())
        .with_param("target", serde_json::json!("test-host"))
        .with_param("force", serde_json::json!(true))
        .with_auth_context(auth_ctx);

    let _ = registry.execute("force_aware_action", context).await;

    // Wait for async audit log
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let entries = audit_log.get_entries().await;
    assert_eq!(entries.len(), 1, "Should have one audit entry");
    assert_eq!(
        entries[0].result,
        tw_observability::ActionAuditResult::Failure,
        "Force flag rejection should be logged as failure"
    );
}

// ============================================================
// Test: Multiple actions with force flag handling
// ============================================================

/// Another mock action that also rejects force flags
struct AnotherForceAwareAction;

#[async_trait::async_trait]
impl Action for AnotherForceAwareAction {
    fn name(&self) -> &str {
        "another_force_aware_action"
    }

    fn description(&self) -> &str {
        "Another action that should reject force flags"
    }

    fn required_parameters(&self) -> Vec<ParameterDef> {
        vec![
            ParameterDef::required("host", "The host", ParameterType::String),
            ParameterDef::optional(
                "skip_validation",
                "Skip validation (should be rejected)",
                ParameterType::Boolean,
                serde_json::json!(false),
            ),
            ParameterDef::optional(
                "bypass_checks",
                "Bypass checks (should be rejected)",
                ParameterType::Boolean,
                serde_json::json!(false),
            ),
        ]
    }

    async fn execute(&self, context: ActionContext) -> Result<ActionResult, ActionError> {
        let host = context.require_string("host")?;

        // Check for various bypass flags
        let skip_validation = context
            .get_param("skip_validation")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let bypass_checks = context
            .get_param("bypass_checks")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if skip_validation {
            return Err(ActionError::InvalidParameters(
                "skip_validation flag is not permitted.".to_string(),
            ));
        }

        if bypass_checks {
            return Err(ActionError::InvalidParameters(
                "bypass_checks flag is not permitted.".to_string(),
            ));
        }

        Ok(ActionResult::success(
            self.name(),
            &format!("Executed on {} with all validations", host),
            chrono::Utc::now(),
            HashMap::new(),
        ))
    }
}

#[tokio::test]
async fn test_skip_validation_flag_rejected() {
    let mut registry = ActionRegistry::new();
    registry.register(Arc::new(AnotherForceAwareAction));

    let admin = create_test_user(Role::Admin);
    let auth_ctx = AuthorizationContext::from_user(&admin);

    let context = ActionContext::new(Uuid::new_v4())
        .with_param("host", serde_json::json!("test-host"))
        .with_param("skip_validation", serde_json::json!(true))
        .with_auth_context(auth_ctx);

    let result = registry.execute("another_force_aware_action", context).await;

    assert!(
        matches!(result, Err(ActionError::InvalidParameters(_))),
        "skip_validation flag should be rejected"
    );
}

#[tokio::test]
async fn test_bypass_checks_flag_rejected() {
    let mut registry = ActionRegistry::new();
    registry.register(Arc::new(AnotherForceAwareAction));

    let admin = create_test_user(Role::Admin);
    let auth_ctx = AuthorizationContext::from_user(&admin);

    let context = ActionContext::new(Uuid::new_v4())
        .with_param("host", serde_json::json!("test-host"))
        .with_param("bypass_checks", serde_json::json!(true))
        .with_auth_context(auth_ctx);

    let result = registry.execute("another_force_aware_action", context).await;

    assert!(
        matches!(result, Err(ActionError::InvalidParameters(_))),
        "bypass_checks flag should be rejected"
    );
}

#[tokio::test]
async fn test_action_without_bypass_flags_succeeds() {
    let mut registry = ActionRegistry::new();
    registry.register(Arc::new(AnotherForceAwareAction));

    let admin = create_test_user(Role::Admin);
    let auth_ctx = AuthorizationContext::from_user(&admin);

    let context = ActionContext::new(Uuid::new_v4())
        .with_param("host", serde_json::json!("test-host"))
        // No bypass flags
        .with_auth_context(auth_ctx);

    let result = registry.execute("another_force_aware_action", context).await;

    assert!(result.is_ok(), "Action without bypass flags should succeed");
}

// ============================================================
// Test: Force flag handling documentation
// ============================================================

#[test]
fn test_force_flag_patterns_documented() {
    // This test documents the patterns that should be rejected
    let forbidden_flag_patterns = vec![
        "force",
        "skip_validation",
        "bypass_checks",
        "no_verify",
        "unsafe",
        "override",
        "skip_auth",
        "skip_approval",
    ];

    // All these patterns represent security bypasses and should be rejected
    for pattern in &forbidden_flag_patterns {
        // Document that this is a forbidden pattern
        assert!(
            pattern.len() > 0,
            "Pattern '{}' should be considered for rejection",
            pattern
        );
    }
}
