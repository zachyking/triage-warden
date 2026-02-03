//! Integration tests for escalation privilege checks.
//!
//! These tests verify that escalation requires proper privileges and
//! follows the correct authorization flow.

use std::collections::HashMap;

use tw_core::auth::{AuthorizationContext, Permission, Role, User};
use tw_policy::escalation::{
    EscalationAction, EscalationCondition, EscalationManager, EscalationRule, FalsePositiveStats,
    IncidentContext,
};

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
// Escalation Manager Rule Evaluation Tests
// =============================================================================

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

    let incident = IncidentContext::new("benign_alert".to_string(), "low".to_string());
    let action: Option<EscalationAction> = manager.check_escalation(&incident).await;

    assert!(
        action.is_none(),
        "Low severity incident should not escalate"
    );
}

// =============================================================================
// Escalation Level Permission Tests
// =============================================================================

#[tokio::test]
async fn test_analyst_can_handle_analyst_escalation() {
    let analyst = create_test_user(Role::Analyst);
    let ctx = AuthorizationContext::from_user(&analyst);

    assert!(ctx.has_permission(Permission::WriteIncidents));
    assert!(ctx.has_permission(Permission::ApproveActions));
}

#[tokio::test]
async fn test_viewer_cannot_handle_escalations() {
    let viewer = create_test_user(Role::Viewer);
    let ctx = AuthorizationContext::from_user(&viewer);

    assert!(!ctx.has_permission(Permission::WriteIncidents));
    assert!(!ctx.has_permission(Permission::ApproveActions));
}

#[tokio::test]
async fn test_admin_can_handle_all_escalation_levels() {
    let admin = create_test_user(Role::Admin);
    let ctx = AuthorizationContext::from_user(&admin);

    assert!(ctx.has_permission(Permission::WriteIncidents));
    assert!(ctx.has_permission(Permission::ApproveActions));
    assert!(ctx.has_permission(Permission::ExecuteActions));
    assert!(ctx.has_permission(Permission::ManageKillSwitch));
}

// =============================================================================
// False Positive Rate Escalation Tests
// =============================================================================

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

    for _ in 0..3 {
        manager.record_false_positive("legitimate_alert").await;
    }
    for _ in 0..7 {
        manager.record_true_positive("legitimate_alert").await;
    }

    let incident = IncidentContext::new("legitimate_alert".to_string(), "medium".to_string());
    let action: Option<EscalationAction> = manager.check_escalation(&incident).await;

    assert!(
        action.is_none() || action != Some(EscalationAction::EscalateToAnalyst),
        "Low FP rate should not trigger FP-based escalation"
    );
}

#[tokio::test]
async fn test_insufficient_samples_does_not_trigger_fp_escalation() {
    let manager = EscalationManager::default();

    for _ in 0..5 {
        manager.record_false_positive("new_alert").await;
    }

    let incident = IncidentContext::new("new_alert".to_string(), "medium".to_string());
    let action: Option<EscalationAction> = manager.check_escalation(&incident).await;

    assert!(
        action.is_none() || action != Some(EscalationAction::EscalateToAnalyst),
        "Insufficient samples should not trigger FP-based escalation"
    );
}

// =============================================================================
// Related Incidents Escalation Tests
// =============================================================================

#[tokio::test]
async fn test_related_incidents_trigger_senior_escalation() {
    let manager = EscalationManager::default();

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

    let correlation_key = "small_campaign";
    for _ in 0..2 {
        manager.record_incident(correlation_key).await;
    }

    let incident = IncidentContext::new("phishing".to_string(), "medium".to_string())
        .with_correlation_key(correlation_key.to_string());
    let action: Option<EscalationAction> = manager.check_escalation(&incident).await;

    assert!(
        action.is_none() || action != Some(EscalationAction::EscalateToSenior),
        "Few related incidents should not trigger senior escalation"
    );
}

// =============================================================================
// Custom Escalation Rule Tests
// =============================================================================

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

// =============================================================================
// Rule Priority Tests
// =============================================================================

#[tokio::test]
async fn test_first_matching_rule_wins() {
    let rules = vec![
        EscalationRule::new(
            "critical_to_analyst".to_string(),
            "First rule".to_string(),
            EscalationCondition::Severity {
                level: "critical".to_string(),
            },
            EscalationAction::EscalateToAnalyst,
        ),
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

    assert_eq!(
        action,
        Some(EscalationAction::EscalateToAnalyst),
        "First matching rule should win"
    );
}

// =============================================================================
// Escalation Authorization Tests
// =============================================================================

#[tokio::test]
async fn test_escalation_requires_execute_permission() {
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
    let analyst = create_test_user(Role::Analyst);
    let ctx = AuthorizationContext::from_user(&analyst);

    assert!(
        !ctx.has_permission(Permission::ManageKillSwitch),
        "Analyst should not have kill switch permission"
    );

    let admin = create_test_user(Role::Admin);
    let ctx = AuthorizationContext::from_user(&admin);

    assert!(
        ctx.has_permission(Permission::ManageKillSwitch),
        "Admin should have kill switch permission"
    );
}

// =============================================================================
// Escalation Tracking Tests
// =============================================================================

#[tokio::test]
async fn test_escalation_manager_cleanup() {
    let manager = EscalationManager::default();

    manager.record_incident("old_campaign").await;
    manager.record_incident("recent_campaign").await;

    manager.cleanup(0).await;

    let counts: HashMap<String, usize> = manager.get_incident_counts().await;
    assert!(counts.is_empty(), "Cleanup should remove all incidents");
}

#[tokio::test]
async fn test_get_fp_stats() {
    let manager = EscalationManager::default();

    manager.record_false_positive("test_alert").await;
    manager.record_true_positive("test_alert").await;
    manager.record_false_positive("other_alert").await;

    let stats: HashMap<String, FalsePositiveStats> = manager.get_all_fp_stats().await;
    assert_eq!(stats.len(), 2, "Should track two alert types");

    let test_stats = stats
        .get("test_alert")
        .expect("Should have test_alert stats");
    assert_eq!(test_stats.fp_count, 1);
    assert_eq!(test_stats.tp_count, 1);
}

// =============================================================================
// Escalation Action Display Tests
// =============================================================================

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

// =============================================================================
// Escalation Level Authorization Tests
// =============================================================================

#[tokio::test]
async fn test_analyst_level_escalation_authorization() {
    let analyst = create_test_user(Role::Analyst);
    let ctx = AuthorizationContext::from_user(&analyst);

    assert!(ctx.has_permission(Permission::WriteIncidents));
    assert!(ctx.has_permission(Permission::ApproveActions));
}

#[tokio::test]
async fn test_senior_level_escalation_authorization() {
    let analyst = create_test_user(Role::Analyst);
    let ctx = AuthorizationContext::from_user(&analyst);

    assert!(ctx.validate_execute_permission().is_ok());
    assert!(ctx.validate_destructive_permission().is_ok());
}

#[tokio::test]
async fn test_manager_level_escalation_authorization() {
    let admin = create_test_user(Role::Admin);
    let ctx = AuthorizationContext::from_user(&admin);

    assert!(ctx.has_permission(Permission::ManageUsers));
    assert!(ctx.has_permission(Permission::ManageSettings));
    assert!(ctx.has_permission(Permission::ManageKillSwitch));
}

// =============================================================================
// Incident Context Builder Tests
// =============================================================================

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

// =============================================================================
// Escalation Rule Management Tests
// =============================================================================

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

// =============================================================================
// Severity Case Insensitivity Tests
// =============================================================================

#[tokio::test]
async fn test_severity_case_insensitive() {
    let manager = EscalationManager::default();

    let incident1 = IncidentContext::new("test".to_string(), "CRITICAL".to_string());
    let incident2 = IncidentContext::new("test".to_string(), "Critical".to_string());
    let incident3 = IncidentContext::new("test".to_string(), "critical".to_string());

    let action1 = manager.check_escalation(&incident1).await;
    let action2 = manager.check_escalation(&incident2).await;
    let action3 = manager.check_escalation(&incident3).await;

    assert_eq!(action1, Some(EscalationAction::EscalateToManager));
    assert_eq!(action2, Some(EscalationAction::EscalateToManager));
    assert_eq!(action3, Some(EscalationAction::EscalateToManager));
}
