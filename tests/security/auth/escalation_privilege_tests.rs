//! Tests for escalation privilege checks.
//!
//! These tests verify that escalation requires proper privileges and
//! follows the correct authorization flow.

use std::collections::HashSet;

use tw_policy::escalation::{
    EscalationAction, EscalationCondition, EscalationManager, EscalationRule, IncidentContext,
};
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
// Test: Escalation manager rule evaluation
// ============================================================

#[tokio::test]
async fn test_escalation_manager_checks_rules() {
    let manager = EscalationManager::default();

    // Critical severity should trigger escalation to manager
    let incident = IncidentContext::new("test_alert".to_string(), "critical".to_string());
    let action = manager.check_escalation(&incident).await;

    assert_eq!(
        action,
        Some(EscalationAction::EscalateToManager),
        "Critical severity should escalate to manager"
    );
}

#[tokio::test]
async fn test_non_critical_incident_not_escalated() {
    let manager = EscalationManager::default();

    // Low severity should not trigger escalation (unless other conditions met)
    let incident = IncidentContext::new("benign_alert".to_string(), "low".to_string());
    let action = manager.check_escalation(&incident).await;

    assert!(
        action.is_none(),
        "Low severity incident should not escalate"
    );
}

// ============================================================
// Test: Escalation levels and permissions
// ============================================================

#[tokio::test]
async fn test_analyst_can_handle_analyst_escalation() {
    let analyst = create_test_user(Role::Analyst);
    let ctx = AuthorizationContext::from_user(&analyst);

    // Analyst should have permissions to handle analyst-level escalations
    assert!(
        ctx.has_permission(Permission::WriteIncidents),
        "Analyst should be able to handle incidents"
    );
    assert!(
        ctx.has_permission(Permission::ApproveActions),
        "Analyst should be able to approve actions"
    );
}

#[tokio::test]
async fn test_viewer_cannot_handle_escalations() {
    let viewer = create_test_user(Role::Viewer);
    let ctx = AuthorizationContext::from_user(&viewer);

    // Viewer should NOT have permissions to handle escalations
    assert!(
        !ctx.has_permission(Permission::WriteIncidents),
        "Viewer should not be able to handle incidents"
    );
    assert!(
        !ctx.has_permission(Permission::ApproveActions),
        "Viewer should not be able to approve actions"
    );
}

#[tokio::test]
async fn test_admin_can_handle_all_escalation_levels() {
    let admin = create_test_user(Role::Admin);
    let ctx = AuthorizationContext::from_user(&admin);

    // Admin should have all permissions
    assert!(ctx.has_permission(Permission::WriteIncidents));
    assert!(ctx.has_permission(Permission::ApproveActions));
    assert!(ctx.has_permission(Permission::ExecuteActions));
    assert!(ctx.has_permission(Permission::ManageKillSwitch));
}

// ============================================================
// Test: False positive rate escalation
// ============================================================

#[tokio::test]
async fn test_high_false_positive_rate_triggers_escalation() {
    let manager = EscalationManager::default();

    // Record high false positive rate (>50% with at least 10 samples)
    for _ in 0..6 {
        manager.record_false_positive("suspicious_login").await;
    }
    for _ in 0..4 {
        manager.record_true_positive("suspicious_login").await;
    }

    let incident = IncidentContext::new("suspicious_login".to_string(), "medium".to_string());
    let action = manager.check_escalation(&incident).await;

    assert_eq!(
        action,
        Some(EscalationAction::EscalateToAnalyst),
        "High FP rate should trigger analyst escalation"
    );
}

#[tokio::test]
async fn test_low_false_positive_rate_does_not_escalate() {
    let manager = EscalationManager::default();

    // Record low false positive rate (30%)
    for _ in 0..3 {
        manager.record_false_positive("legitimate_alert").await;
    }
    for _ in 0..7 {
        manager.record_true_positive("legitimate_alert").await;
    }

    let incident = IncidentContext::new("legitimate_alert".to_string(), "medium".to_string());
    let action = manager.check_escalation(&incident).await;

    // Should not escalate to analyst (might escalate for other reasons)
    assert!(
        action.is_none() || action != Some(EscalationAction::EscalateToAnalyst),
        "Low FP rate should not trigger FP-based escalation"
    );
}

#[tokio::test]
async fn test_insufficient_samples_does_not_trigger_fp_escalation() {
    let manager = EscalationManager::default();

    // Record only 5 false positives (need 10 samples minimum)
    for _ in 0..5 {
        manager.record_false_positive("new_alert").await;
    }

    let incident = IncidentContext::new("new_alert".to_string(), "medium".to_string());
    let action = manager.check_escalation(&incident).await;

    // Should not escalate due to insufficient samples
    assert!(
        action.is_none() || action != Some(EscalationAction::EscalateToAnalyst),
        "Insufficient samples should not trigger FP-based escalation"
    );
}

// ============================================================
// Test: Related incidents escalation
// ============================================================

#[tokio::test]
async fn test_related_incidents_trigger_senior_escalation() {
    let manager = EscalationManager::default();

    // Record multiple related incidents (>3 within time window)
    let correlation_key = "campaign_12345";
    for _ in 0..4 {
        manager.record_incident(correlation_key).await;
    }

    let incident = IncidentContext::new("phishing".to_string(), "medium".to_string())
        .with_correlation_key(correlation_key.to_string());
    let action = manager.check_escalation(&incident).await;

    assert_eq!(
        action,
        Some(EscalationAction::EscalateToSenior),
        "Related incidents should escalate to senior"
    );
}

#[tokio::test]
async fn test_few_related_incidents_does_not_escalate() {
    let manager = EscalationManager::default();

    // Record only 2 related incidents (need >3)
    let correlation_key = "small_campaign";
    for _ in 0..2 {
        manager.record_incident(correlation_key).await;
    }

    let incident = IncidentContext::new("phishing".to_string(), "medium".to_string())
        .with_correlation_key(correlation_key.to_string());
    let action = manager.check_escalation(&incident).await;

    // Should not escalate to senior
    assert!(
        action.is_none() || action != Some(EscalationAction::EscalateToSenior),
        "Few related incidents should not trigger senior escalation"
    );
}

// ============================================================
// Test: Custom escalation rules
// ============================================================

#[tokio::test]
async fn test_custom_severity_rule() {
    let rules = vec![EscalationRule::new(
        "high_severity".to_string(),
        "Escalate high severity to senior".to_string(),
        EscalationCondition::Severity {
            level: "high".to_string(),
        },
        EscalationAction::EscalateToSenior,
    )];

    let manager = EscalationManager::new(rules);
    let incident = IncidentContext::new("any_alert".to_string(), "high".to_string());
    let action = manager.check_escalation(&incident).await;

    assert_eq!(
        action,
        Some(EscalationAction::EscalateToSenior),
        "High severity should escalate to senior per custom rule"
    );
}

#[tokio::test]
async fn test_custom_alert_type_rule() {
    let rules = vec![EscalationRule::new(
        "apt_detection".to_string(),
        "Escalate APT alerts to manager".to_string(),
        EscalationCondition::Custom {
            field: "alert_type".to_string(),
            operator: "contains".to_string(),
            value: "apt".to_string(),
        },
        EscalationAction::EscalateToManager,
    )];

    let manager = EscalationManager::new(rules);
    let incident = IncidentContext::new("apt_activity_detected".to_string(), "high".to_string());
    let action = manager.check_escalation(&incident).await;

    assert_eq!(
        action,
        Some(EscalationAction::EscalateToManager),
        "APT alert should escalate to manager"
    );
}

// ============================================================
// Test: Rule priority (first match wins)
// ============================================================

#[tokio::test]
async fn test_first_matching_rule_wins() {
    let rules = vec![
        // First rule - matches critical
        EscalationRule::new(
            "critical_to_analyst".to_string(),
            "First rule".to_string(),
            EscalationCondition::Severity {
                level: "critical".to_string(),
            },
            EscalationAction::EscalateToAnalyst,
        ),
        // Second rule - also matches critical
        EscalationRule::new(
            "critical_to_manager".to_string(),
            "Second rule".to_string(),
            EscalationCondition::Severity {
                level: "critical".to_string(),
            },
            EscalationAction::EscalateToManager,
        ),
    ];

    let manager = EscalationManager::new(rules);
    let incident = IncidentContext::new("test".to_string(), "critical".to_string());
    let action = manager.check_escalation(&incident).await;

    // First rule should win
    assert_eq!(
        action,
        Some(EscalationAction::EscalateToAnalyst),
        "First matching rule should win"
    );
}

// ============================================================
// Test: Authorization context for escalation actions
// ============================================================

#[tokio::test]
async fn test_escalation_requires_execute_permission() {
    // To execute escalation actions, user needs ExecuteActions permission
    let viewer = create_test_user(Role::Viewer);
    let viewer_ctx = AuthorizationContext::from_user(&viewer);

    assert!(
        viewer_ctx.validate_execute_permission().is_err(),
        "Viewer should not be able to execute escalation"
    );

    let analyst = create_test_user(Role::Analyst);
    let analyst_ctx = AuthorizationContext::from_user(&analyst);

    assert!(
        analyst_ctx.validate_execute_permission().is_ok(),
        "Analyst should be able to execute escalation"
    );
}

#[tokio::test]
async fn test_manager_escalation_level_permissions() {
    // Manager-level escalations may require elevated permissions
    // This is enforced by the authorization context checks

    let analyst = create_test_user(Role::Analyst);
    let ctx = AuthorizationContext::from_user(&analyst);

    // Analyst cannot manage kill switch (manager-level privilege)
    assert!(
        !ctx.has_permission(Permission::ManageKillSwitch),
        "Analyst should not have kill switch permission"
    );

    let admin = create_test_user(Role::Admin);
    let ctx = AuthorizationContext::from_user(&admin);

    // Admin can manage kill switch
    assert!(
        ctx.has_permission(Permission::ManageKillSwitch),
        "Admin should have kill switch permission"
    );
}

// ============================================================
// Test: Escalation tracking and cleanup
// ============================================================

#[tokio::test]
async fn test_escalation_manager_cleanup() {
    let manager = EscalationManager::default();

    // Record some incidents
    manager.record_incident("old_campaign").await;
    manager.record_incident("recent_campaign").await;

    // Cleanup with 0 hour max age (should remove all)
    manager.cleanup(0).await;

    let counts = manager.get_incident_counts().await;
    assert!(counts.is_empty(), "Cleanup should remove all incidents");
}

#[tokio::test]
async fn test_get_fp_stats() {
    let manager = EscalationManager::default();

    manager.record_false_positive("test_alert").await;
    manager.record_true_positive("test_alert").await;
    manager.record_false_positive("other_alert").await;

    let stats = manager.get_all_fp_stats().await;
    assert_eq!(stats.len(), 2, "Should track two alert types");

    let test_stats = stats.get("test_alert").expect("Should have test_alert stats");
    assert_eq!(test_stats.fp_count, 1);
    assert_eq!(test_stats.tp_count, 1);
}

// ============================================================
// Test: Escalation action display
// ============================================================

#[test]
fn test_escalation_action_display() {
    assert_eq!(
        format!("{}", EscalationAction::EscalateToAnalyst),
        "Escalate to Analyst"
    );
    assert_eq!(
        format!("{}", EscalationAction::EscalateToSenior),
        "Escalate to Senior Analyst"
    );
    assert_eq!(
        format!("{}", EscalationAction::EscalateToManager),
        "Escalate to Manager"
    );
    assert_eq!(
        format!("{}", EscalationAction::Custom("notify_oncall".to_string())),
        "Custom: notify_oncall"
    );
}

// ============================================================
// Test: Authorization for different escalation levels
// ============================================================

#[tokio::test]
async fn test_analyst_level_escalation_authorization() {
    // Analyst-level escalations require at least analyst permissions
    let analyst = create_test_user(Role::Analyst);
    let ctx = AuthorizationContext::from_user(&analyst);

    assert!(
        ctx.has_permission(Permission::WriteIncidents),
        "Should be able to update incident status"
    );
    assert!(
        ctx.has_permission(Permission::ApproveActions),
        "Should be able to approve actions"
    );
}

#[tokio::test]
async fn test_senior_level_escalation_authorization() {
    // Senior-level escalations also require analyst permissions (no separate senior role)
    let analyst = create_test_user(Role::Analyst);
    let ctx = AuthorizationContext::from_user(&analyst);

    // Analyst can handle senior escalations
    assert!(ctx.validate_execute_permission().is_ok());
    assert!(ctx.validate_destructive_permission().is_ok());
}

#[tokio::test]
async fn test_manager_level_escalation_authorization() {
    // Manager-level escalations may require additional permissions
    let admin = create_test_user(Role::Admin);
    let ctx = AuthorizationContext::from_user(&admin);

    // Admin should have all permissions for manager-level escalations
    assert!(ctx.has_permission(Permission::ManageUsers));
    assert!(ctx.has_permission(Permission::ManageSettings));
    assert!(ctx.has_permission(Permission::ManageKillSwitch));
}

// ============================================================
// Test: Incident context builder
// ============================================================

#[test]
fn test_incident_context_builder() {
    let context = IncidentContext::new("test_alert".to_string(), "high".to_string())
        .with_correlation_key("campaign_123".to_string());

    assert_eq!(context.alert_type, "test_alert");
    assert_eq!(context.severity, "high");
    assert_eq!(context.correlation_key, Some("campaign_123".to_string()));
}

#[test]
fn test_incident_context_without_correlation() {
    let context = IncidentContext::new("standalone_alert".to_string(), "medium".to_string());

    assert_eq!(context.alert_type, "standalone_alert");
    assert_eq!(context.severity, "medium");
    assert!(context.correlation_key.is_none());
}

// ============================================================
// Test: Escalation rule management
// ============================================================

#[tokio::test]
async fn test_add_and_remove_escalation_rules() {
    let mut manager = EscalationManager::new(vec![]);
    assert_eq!(manager.rules().len(), 0);

    let rule = EscalationRule::new(
        "test_rule".to_string(),
        "Test description".to_string(),
        EscalationCondition::Severity {
            level: "high".to_string(),
        },
        EscalationAction::EscalateToAnalyst,
    );

    manager.add_rule(rule);
    assert_eq!(manager.rules().len(), 1);

    let removed = manager.remove_rule("test_rule");
    assert!(removed, "Should successfully remove rule");
    assert_eq!(manager.rules().len(), 0);

    let removed_again = manager.remove_rule("test_rule");
    assert!(!removed_again, "Should not find rule to remove");
}

// ============================================================
// Test: Severity case insensitivity
// ============================================================

#[tokio::test]
async fn test_severity_case_insensitive() {
    let manager = EscalationManager::default();

    // Test various cases
    let incident1 = IncidentContext::new("test".to_string(), "CRITICAL".to_string());
    let incident2 = IncidentContext::new("test".to_string(), "Critical".to_string());
    let incident3 = IncidentContext::new("test".to_string(), "critical".to_string());

    let action1 = manager.check_escalation(&incident1).await;
    let action2 = manager.check_escalation(&incident2).await;
    let action3 = manager.check_escalation(&incident3).await;

    // All should escalate to manager
    assert_eq!(action1, Some(EscalationAction::EscalateToManager));
    assert_eq!(action2, Some(EscalationAction::EscalateToManager));
    assert_eq!(action3, Some(EscalationAction::EscalateToManager));
}
