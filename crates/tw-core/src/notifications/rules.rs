//! Notification rules engine with condition matching and throttling.
//!
//! Rules are evaluated against incoming TriageEvents. When a rule matches,
//! notifications are dispatched to the configured channels.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::debug;
use uuid::Uuid;

use crate::events::TriageEvent;

/// Trigger types for notification rules.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NotificationTrigger {
    /// A new incident has been created.
    IncidentCreated,
    /// An incident's severity has changed.
    SeverityChanged,
    /// An action is pending approval.
    ActionPendingApproval,
    /// AI analysis has been completed.
    AnalysisCompleted,
    /// A playbook has completed execution.
    PlaybookCompleted,
    /// An incident has been resolved.
    IncidentResolved,
    /// An action has been executed.
    ActionExecuted,
    /// An incident has been escalated.
    IncidentEscalated,
    /// Kill switch activated.
    KillSwitchActivated,
    /// System error occurred.
    SystemError,
    /// Analyst feedback received.
    FeedbackReceived,
    /// Custom trigger type.
    Custom(String),
}

impl NotificationTrigger {
    /// Returns the string representation of the trigger.
    pub fn as_str(&self) -> &str {
        match self {
            NotificationTrigger::IncidentCreated => "incident_created",
            NotificationTrigger::SeverityChanged => "severity_changed",
            NotificationTrigger::ActionPendingApproval => "action_pending_approval",
            NotificationTrigger::AnalysisCompleted => "analysis_completed",
            NotificationTrigger::PlaybookCompleted => "playbook_completed",
            NotificationTrigger::IncidentResolved => "incident_resolved",
            NotificationTrigger::ActionExecuted => "action_executed",
            NotificationTrigger::IncidentEscalated => "incident_escalated",
            NotificationTrigger::KillSwitchActivated => "kill_switch_activated",
            NotificationTrigger::SystemError => "system_error",
            NotificationTrigger::FeedbackReceived => "feedback_received",
            NotificationTrigger::Custom(_) => "custom",
        }
    }

    /// Checks whether this trigger matches a given TriageEvent.
    pub fn matches_event(&self, event: &TriageEvent) -> bool {
        matches!(
            (self, event),
            (
                NotificationTrigger::IncidentCreated,
                TriageEvent::IncidentCreated { .. }
            ) | (
                NotificationTrigger::SeverityChanged,
                TriageEvent::StatusChanged { .. }
            ) | (
                NotificationTrigger::ActionPendingApproval,
                TriageEvent::ActionsProposed { .. }
            ) | (
                NotificationTrigger::AnalysisCompleted,
                TriageEvent::AnalysisComplete { .. }
            ) | (
                NotificationTrigger::IncidentResolved,
                TriageEvent::IncidentResolved { .. }
            ) | (
                NotificationTrigger::ActionExecuted,
                TriageEvent::ActionExecuted { .. }
            ) | (
                NotificationTrigger::IncidentEscalated,
                TriageEvent::IncidentEscalated { .. }
            ) | (
                NotificationTrigger::KillSwitchActivated,
                TriageEvent::KillSwitchActivated { .. }
            ) | (
                NotificationTrigger::SystemError,
                TriageEvent::SystemError { .. }
            ) | (
                NotificationTrigger::FeedbackReceived,
                TriageEvent::FeedbackReceived { .. }
            )
        )
    }
}

/// Condition that must be met for a notification rule to fire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationCondition {
    /// The field to evaluate (supports dot notation for nested fields).
    pub field: String,
    /// The comparison operator.
    pub operator: ConditionOperator,
    /// The value to compare against.
    pub value: serde_json::Value,
}

/// Comparison operators for notification conditions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConditionOperator {
    /// Equals comparison.
    Equals,
    /// Not equals comparison.
    NotEquals,
    /// Greater than (numeric).
    GreaterThan,
    /// Less than (numeric).
    LessThan,
    /// String contains.
    Contains,
    /// Value is in a list.
    In,
}

/// Channel-specific configuration for where to send notifications.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ChannelConfig {
    /// Send to a Slack channel.
    Slack {
        channel_id: String,
        #[serde(default)]
        mention_users: Vec<String>,
    },
    /// Send to a Teams webhook.
    Teams { webhook_url: String },
    /// Send via email.
    Email {
        recipients: Vec<String>,
        #[serde(default)]
        template: Option<String>,
    },
    /// Send to a generic webhook.
    Webhook {
        url: String,
        #[serde(default)]
        headers: HashMap<String, String>,
    },
}

/// Throttle configuration to prevent notification flooding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThrottleConfig {
    /// Maximum notifications per hour for this rule.
    pub max_per_hour: u32,
    /// Cooldown period in seconds between notifications.
    pub cooldown_secs: u64,
}

/// A notification rule that defines when and where to send notifications.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationRule {
    /// Unique identifier for this rule.
    pub id: Uuid,
    /// Tenant this rule belongs to.
    pub tenant_id: Uuid,
    /// Human-readable name for the rule.
    pub name: String,
    /// Optional description.
    pub description: Option<String>,
    /// The trigger event type.
    pub trigger: NotificationTrigger,
    /// Additional conditions that must be met.
    pub conditions: Vec<NotificationCondition>,
    /// Channels to send notifications to.
    pub channels: Vec<ChannelConfig>,
    /// Optional throttle configuration.
    pub throttle: Option<ThrottleConfig>,
    /// Whether this rule is currently enabled.
    pub enabled: bool,
    /// When this rule was created.
    pub created_at: DateTime<Utc>,
    /// When this rule was last updated.
    pub updated_at: DateTime<Utc>,
}

impl NotificationRule {
    /// Creates a new notification rule.
    pub fn new(
        tenant_id: Uuid,
        name: String,
        trigger: NotificationTrigger,
        channels: Vec<ChannelConfig>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            tenant_id,
            name,
            description: None,
            trigger,
            conditions: Vec::new(),
            channels,
            throttle: None,
            enabled: true,
            created_at: now,
            updated_at: now,
        }
    }
}

/// A record of a notification that was sent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationHistory {
    /// Unique identifier for this delivery record.
    pub id: Uuid,
    /// The rule that triggered this notification.
    pub rule_id: Uuid,
    /// The event that triggered the notification.
    pub trigger: String,
    /// Channel type that was notified.
    pub channel_type: String,
    /// Whether the delivery was successful.
    pub success: bool,
    /// Error message if delivery failed.
    pub error: Option<String>,
    /// When the notification was sent.
    pub sent_at: DateTime<Utc>,
}

/// Notification engine that evaluates rules and dispatches notifications.
pub struct NotificationEngine {
    /// The notification rules to evaluate.
    rules: Arc<RwLock<Vec<NotificationRule>>>,
    /// Throttle state: rule_id -> last notification timestamps.
    throttle_state: Arc<RwLock<HashMap<Uuid, Vec<DateTime<Utc>>>>>,
    /// Delivery history.
    history: Arc<RwLock<Vec<NotificationHistory>>>,
}

impl NotificationEngine {
    /// Creates a new notification engine.
    pub fn new() -> Self {
        Self {
            rules: Arc::new(RwLock::new(Vec::new())),
            throttle_state: Arc::new(RwLock::new(HashMap::new())),
            history: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Adds a rule to the engine.
    pub async fn add_rule(&self, rule: NotificationRule) {
        let mut rules = self.rules.write().await;
        rules.push(rule);
    }

    /// Removes a rule by ID.
    pub async fn remove_rule(&self, rule_id: Uuid) -> bool {
        let mut rules = self.rules.write().await;
        let len_before = rules.len();
        rules.retain(|r| r.id != rule_id);
        rules.len() < len_before
    }

    /// Updates an existing rule.
    pub async fn update_rule(&self, rule: NotificationRule) -> bool {
        let mut rules = self.rules.write().await;
        if let Some(existing) = rules.iter_mut().find(|r| r.id == rule.id) {
            *existing = rule;
            true
        } else {
            false
        }
    }

    /// Gets all rules.
    pub async fn get_rules(&self) -> Vec<NotificationRule> {
        let rules = self.rules.read().await;
        rules.clone()
    }

    /// Gets a rule by ID.
    pub async fn get_rule(&self, rule_id: Uuid) -> Option<NotificationRule> {
        let rules = self.rules.read().await;
        rules.iter().find(|r| r.id == rule_id).cloned()
    }

    /// Evaluates all rules against an event and returns matching rules.
    pub async fn evaluate_event(&self, event: &TriageEvent) -> Vec<NotificationRule> {
        let rules = self.rules.read().await;
        let event_json = serde_json::to_value(event).unwrap_or_default();
        let now = Utc::now();

        let mut matching = Vec::new();

        for rule in rules.iter() {
            if !rule.enabled {
                continue;
            }

            // Check trigger match
            if !rule.trigger.matches_event(event) {
                continue;
            }

            // Check conditions
            if !evaluate_conditions(&rule.conditions, &event_json) {
                debug!(rule_id = %rule.id, "Rule conditions not met");
                continue;
            }

            // Check throttle
            if !self.check_throttle(rule, now).await {
                debug!(rule_id = %rule.id, "Rule throttled");
                continue;
            }

            matching.push(rule.clone());
        }

        // Update throttle state for matching rules
        if !matching.is_empty() {
            let mut throttle_state = self.throttle_state.write().await;
            for rule in &matching {
                throttle_state.entry(rule.id).or_default().push(now);
            }
        }

        matching
    }

    /// Records a notification delivery in the history.
    pub async fn record_delivery(
        &self,
        rule_id: Uuid,
        trigger: &str,
        channel_type: &str,
        success: bool,
        error: Option<String>,
    ) {
        let record = NotificationHistory {
            id: Uuid::new_v4(),
            rule_id,
            trigger: trigger.to_string(),
            channel_type: channel_type.to_string(),
            success,
            error,
            sent_at: Utc::now(),
        };

        let mut history = self.history.write().await;
        history.push(record);

        // Keep history bounded
        if history.len() > 10_000 {
            history.drain(..1_000);
        }
    }

    /// Gets the notification delivery history.
    pub async fn get_history(&self, limit: Option<usize>) -> Vec<NotificationHistory> {
        let history = self.history.read().await;
        match limit {
            Some(n) => history.iter().rev().take(n).cloned().collect(),
            None => history.clone(),
        }
    }

    /// Checks whether a rule is throttled.
    async fn check_throttle(&self, rule: &NotificationRule, now: DateTime<Utc>) -> bool {
        let throttle = match &rule.throttle {
            Some(t) => t,
            None => return true, // No throttle configured
        };

        let throttle_state = self.throttle_state.read().await;
        let timestamps = match throttle_state.get(&rule.id) {
            Some(ts) => ts,
            None => return true, // No previous notifications
        };

        // Check cooldown
        if let Some(last) = timestamps.last() {
            let cooldown = Duration::seconds(throttle.cooldown_secs as i64);
            if now - *last < cooldown {
                return false;
            }
        }

        // Check max per hour
        let one_hour_ago = now - Duration::hours(1);
        let count_last_hour = timestamps.iter().filter(|t| **t > one_hour_ago).count();
        if count_last_hour >= throttle.max_per_hour as usize {
            return false;
        }

        true
    }
}

impl Default for NotificationEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Evaluates a set of conditions against an event JSON value.
pub fn evaluate_conditions(
    conditions: &[NotificationCondition],
    event_json: &serde_json::Value,
) -> bool {
    // All conditions must match (AND logic)
    conditions.iter().all(|c| evaluate_condition(c, event_json))
}

/// Evaluates a single condition against an event JSON value.
pub fn evaluate_condition(
    condition: &NotificationCondition,
    event_json: &serde_json::Value,
) -> bool {
    let field_value = get_nested_field(event_json, &condition.field);
    let field_value = match field_value {
        Some(v) => v,
        None => return false,
    };

    match condition.operator {
        ConditionOperator::Equals => field_value == &condition.value,
        ConditionOperator::NotEquals => field_value != &condition.value,
        ConditionOperator::GreaterThan => {
            compare_numeric(field_value, &condition.value, |a, b| a > b)
        }
        ConditionOperator::LessThan => compare_numeric(field_value, &condition.value, |a, b| a < b),
        ConditionOperator::Contains => {
            if let (Some(haystack), Some(needle)) = (field_value.as_str(), condition.value.as_str())
            {
                haystack.contains(needle)
            } else {
                false
            }
        }
        ConditionOperator::In => {
            if let Some(arr) = condition.value.as_array() {
                arr.contains(field_value)
            } else {
                false
            }
        }
    }
}

/// Gets a nested field from a JSON value using dot notation.
fn get_nested_field<'a>(value: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let mut current = value;
    for part in path.split('.') {
        current = match current {
            serde_json::Value::Object(map) => map.get(part)?,
            _ => return None,
        };
    }
    Some(current)
}

/// Compares two JSON values as numbers.
fn compare_numeric(
    a: &serde_json::Value,
    b: &serde_json::Value,
    cmp: fn(f64, f64) -> bool,
) -> bool {
    let a_num = a.as_f64();
    let b_num = b.as_f64();
    match (a_num, b_num) {
        (Some(a), Some(b)) => cmp(a, b),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_rule(trigger: NotificationTrigger) -> NotificationRule {
        NotificationRule::new(
            Uuid::new_v4(),
            "Test Rule".to_string(),
            trigger,
            vec![ChannelConfig::Slack {
                channel_id: "#security".to_string(),
                mention_users: vec![],
            }],
        )
    }

    // ==========================================================================
    // Trigger matching tests
    // ==========================================================================

    #[test]
    fn test_trigger_matches_incident_created() {
        let trigger = NotificationTrigger::IncidentCreated;
        let event = TriageEvent::IncidentCreated {
            incident_id: Uuid::new_v4(),
            alert_id: "alert-001".to_string(),
        };
        assert!(trigger.matches_event(&event));
    }

    #[test]
    fn test_trigger_matches_incident_resolved() {
        let trigger = NotificationTrigger::IncidentResolved;
        let event = TriageEvent::IncidentResolved {
            incident_id: Uuid::new_v4(),
            resolution: crate::events::Resolution {
                resolution_type: crate::events::ResolutionType::Remediated,
                summary: "Fixed".to_string(),
                actions_taken: vec![],
                lessons_learned: None,
            },
        };
        assert!(trigger.matches_event(&event));
    }

    #[test]
    fn test_trigger_matches_kill_switch() {
        let trigger = NotificationTrigger::KillSwitchActivated;
        let event = TriageEvent::KillSwitchActivated {
            reason: "emergency".to_string(),
            activated_by: "admin".to_string(),
        };
        assert!(trigger.matches_event(&event));
    }

    #[test]
    fn test_trigger_no_match() {
        let trigger = NotificationTrigger::IncidentCreated;
        let event = TriageEvent::KillSwitchActivated {
            reason: "test".to_string(),
            activated_by: "admin".to_string(),
        };
        assert!(!trigger.matches_event(&event));
    }

    #[test]
    fn test_trigger_as_str() {
        assert_eq!(
            NotificationTrigger::IncidentCreated.as_str(),
            "incident_created"
        );
        assert_eq!(
            NotificationTrigger::KillSwitchActivated.as_str(),
            "kill_switch_activated"
        );
        assert_eq!(
            NotificationTrigger::Custom("test".to_string()).as_str(),
            "custom"
        );
    }

    // ==========================================================================
    // Condition evaluation tests
    // ==========================================================================

    #[test]
    fn test_condition_equals() {
        let condition = NotificationCondition {
            field: "severity".to_string(),
            operator: ConditionOperator::Equals,
            value: serde_json::json!("critical"),
        };
        let event = serde_json::json!({"severity": "critical"});
        assert!(evaluate_condition(&condition, &event));

        let event = serde_json::json!({"severity": "low"});
        assert!(!evaluate_condition(&condition, &event));
    }

    #[test]
    fn test_condition_not_equals() {
        let condition = NotificationCondition {
            field: "status".to_string(),
            operator: ConditionOperator::NotEquals,
            value: serde_json::json!("resolved"),
        };
        let event = serde_json::json!({"status": "open"});
        assert!(evaluate_condition(&condition, &event));

        let event = serde_json::json!({"status": "resolved"});
        assert!(!evaluate_condition(&condition, &event));
    }

    #[test]
    fn test_condition_greater_than() {
        let condition = NotificationCondition {
            field: "risk_score".to_string(),
            operator: ConditionOperator::GreaterThan,
            value: serde_json::json!(80),
        };
        let event = serde_json::json!({"risk_score": 90});
        assert!(evaluate_condition(&condition, &event));

        let event = serde_json::json!({"risk_score": 50});
        assert!(!evaluate_condition(&condition, &event));
    }

    #[test]
    fn test_condition_less_than() {
        let condition = NotificationCondition {
            field: "confidence".to_string(),
            operator: ConditionOperator::LessThan,
            value: serde_json::json!(0.5),
        };
        let event = serde_json::json!({"confidence": 0.3});
        assert!(evaluate_condition(&condition, &event));

        let event = serde_json::json!({"confidence": 0.8});
        assert!(!evaluate_condition(&condition, &event));
    }

    #[test]
    fn test_condition_contains() {
        let condition = NotificationCondition {
            field: "title".to_string(),
            operator: ConditionOperator::Contains,
            value: serde_json::json!("ransomware"),
        };
        let event = serde_json::json!({"title": "Potential ransomware detected"});
        assert!(evaluate_condition(&condition, &event));

        let event = serde_json::json!({"title": "Port scan detected"});
        assert!(!evaluate_condition(&condition, &event));
    }

    #[test]
    fn test_condition_in() {
        let condition = NotificationCondition {
            field: "severity".to_string(),
            operator: ConditionOperator::In,
            value: serde_json::json!(["critical", "high"]),
        };
        let event = serde_json::json!({"severity": "critical"});
        assert!(evaluate_condition(&condition, &event));

        let event = serde_json::json!({"severity": "low"});
        assert!(!evaluate_condition(&condition, &event));
    }

    #[test]
    fn test_condition_nested_field() {
        let condition = NotificationCondition {
            field: "analysis.verdict".to_string(),
            operator: ConditionOperator::Equals,
            value: serde_json::json!("malicious"),
        };
        let event = serde_json::json!({"analysis": {"verdict": "malicious"}});
        assert!(evaluate_condition(&condition, &event));
    }

    #[test]
    fn test_condition_missing_field() {
        let condition = NotificationCondition {
            field: "nonexistent".to_string(),
            operator: ConditionOperator::Equals,
            value: serde_json::json!("value"),
        };
        let event = serde_json::json!({"other": "field"});
        assert!(!evaluate_condition(&condition, &event));
    }

    #[test]
    fn test_multiple_conditions_all_match() {
        let conditions = vec![
            NotificationCondition {
                field: "severity".to_string(),
                operator: ConditionOperator::Equals,
                value: serde_json::json!("critical"),
            },
            NotificationCondition {
                field: "risk_score".to_string(),
                operator: ConditionOperator::GreaterThan,
                value: serde_json::json!(80),
            },
        ];
        let event = serde_json::json!({"severity": "critical", "risk_score": 95});
        assert!(evaluate_conditions(&conditions, &event));
    }

    #[test]
    fn test_multiple_conditions_one_fails() {
        let conditions = vec![
            NotificationCondition {
                field: "severity".to_string(),
                operator: ConditionOperator::Equals,
                value: serde_json::json!("critical"),
            },
            NotificationCondition {
                field: "risk_score".to_string(),
                operator: ConditionOperator::GreaterThan,
                value: serde_json::json!(80),
            },
        ];
        let event = serde_json::json!({"severity": "critical", "risk_score": 50});
        assert!(!evaluate_conditions(&conditions, &event));
    }

    #[test]
    fn test_empty_conditions_always_match() {
        let conditions: Vec<NotificationCondition> = vec![];
        let event = serde_json::json!({"anything": "value"});
        assert!(evaluate_conditions(&conditions, &event));
    }

    // ==========================================================================
    // Engine tests
    // ==========================================================================

    #[tokio::test]
    async fn test_engine_evaluate_matching_rule() {
        let engine = NotificationEngine::new();

        let rule = test_rule(NotificationTrigger::IncidentCreated);
        engine.add_rule(rule).await;

        let event = TriageEvent::IncidentCreated {
            incident_id: Uuid::new_v4(),
            alert_id: "alert-001".to_string(),
        };

        let matches = engine.evaluate_event(&event).await;
        assert_eq!(matches.len(), 1);
    }

    #[tokio::test]
    async fn test_engine_no_matching_rules() {
        let engine = NotificationEngine::new();

        let rule = test_rule(NotificationTrigger::IncidentResolved);
        engine.add_rule(rule).await;

        let event = TriageEvent::IncidentCreated {
            incident_id: Uuid::new_v4(),
            alert_id: "alert-001".to_string(),
        };

        let matches = engine.evaluate_event(&event).await;
        assert!(matches.is_empty());
    }

    #[tokio::test]
    async fn test_engine_disabled_rule_not_matched() {
        let engine = NotificationEngine::new();

        let mut rule = test_rule(NotificationTrigger::IncidentCreated);
        rule.enabled = false;
        engine.add_rule(rule).await;

        let event = TriageEvent::IncidentCreated {
            incident_id: Uuid::new_v4(),
            alert_id: "alert-001".to_string(),
        };

        let matches = engine.evaluate_event(&event).await;
        assert!(matches.is_empty());
    }

    #[tokio::test]
    async fn test_engine_throttling() {
        let engine = NotificationEngine::new();

        let mut rule = test_rule(NotificationTrigger::IncidentCreated);
        rule.throttle = Some(ThrottleConfig {
            max_per_hour: 2,
            cooldown_secs: 0,
        });
        engine.add_rule(rule).await;

        let event = TriageEvent::IncidentCreated {
            incident_id: Uuid::new_v4(),
            alert_id: "alert-001".to_string(),
        };

        // First two should match
        let matches = engine.evaluate_event(&event).await;
        assert_eq!(matches.len(), 1);

        let matches = engine.evaluate_event(&event).await;
        assert_eq!(matches.len(), 1);

        // Third should be throttled
        let matches = engine.evaluate_event(&event).await;
        assert!(matches.is_empty());
    }

    #[tokio::test]
    async fn test_engine_add_remove_rule() {
        let engine = NotificationEngine::new();

        let rule = test_rule(NotificationTrigger::IncidentCreated);
        let rule_id = rule.id;
        engine.add_rule(rule).await;

        let rules = engine.get_rules().await;
        assert_eq!(rules.len(), 1);

        let removed = engine.remove_rule(rule_id).await;
        assert!(removed);

        let rules = engine.get_rules().await;
        assert!(rules.is_empty());
    }

    #[tokio::test]
    async fn test_engine_update_rule() {
        let engine = NotificationEngine::new();

        let rule = test_rule(NotificationTrigger::IncidentCreated);
        let rule_id = rule.id;
        engine.add_rule(rule).await;

        let mut updated = engine.get_rule(rule_id).await.unwrap();
        updated.name = "Updated Name".to_string();
        updated.enabled = false;

        let result = engine.update_rule(updated).await;
        assert!(result);

        let rule = engine.get_rule(rule_id).await.unwrap();
        assert_eq!(rule.name, "Updated Name");
        assert!(!rule.enabled);
    }

    #[tokio::test]
    async fn test_engine_record_delivery() {
        let engine = NotificationEngine::new();
        let rule_id = Uuid::new_v4();

        engine
            .record_delivery(rule_id, "incident_created", "slack", true, None)
            .await;

        engine
            .record_delivery(
                rule_id,
                "incident_created",
                "email",
                false,
                Some("SMTP error".to_string()),
            )
            .await;

        let history = engine.get_history(None).await;
        assert_eq!(history.len(), 2);
        assert!(history[0].success);
        assert!(!history[1].success);
        assert_eq!(history[1].error.as_deref(), Some("SMTP error"));
    }

    #[tokio::test]
    async fn test_engine_get_history_limited() {
        let engine = NotificationEngine::new();
        let rule_id = Uuid::new_v4();

        for i in 0..5 {
            engine
                .record_delivery(rule_id, &format!("event_{}", i), "slack", true, None)
                .await;
        }

        let history = engine.get_history(Some(3)).await;
        assert_eq!(history.len(), 3);
    }

    #[tokio::test]
    async fn test_engine_with_conditions() {
        let engine = NotificationEngine::new();

        let mut rule = test_rule(NotificationTrigger::KillSwitchActivated);
        rule.conditions = vec![NotificationCondition {
            field: "KillSwitchActivated.reason".to_string(),
            operator: ConditionOperator::Contains,
            value: serde_json::json!("emergency"),
        }];
        engine.add_rule(rule).await;

        let event = TriageEvent::KillSwitchActivated {
            reason: "emergency shutdown".to_string(),
            activated_by: "admin".to_string(),
        };

        let matches = engine.evaluate_event(&event).await;
        assert_eq!(matches.len(), 1);
    }

    // ==========================================================================
    // Serialization tests
    // ==========================================================================

    #[test]
    fn test_notification_rule_serialization() {
        let rule = test_rule(NotificationTrigger::IncidentCreated);
        let json = serde_json::to_string(&rule).unwrap();
        let deserialized: NotificationRule = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, rule.id);
        assert_eq!(deserialized.name, rule.name);
    }

    #[test]
    fn test_channel_config_serialization() {
        let slack = ChannelConfig::Slack {
            channel_id: "#security".to_string(),
            mention_users: vec!["@oncall".to_string()],
        };
        let json = serde_json::to_string(&slack).unwrap();
        assert!(json.contains("slack"));
        assert!(json.contains("#security"));

        let teams = ChannelConfig::Teams {
            webhook_url: "https://outlook.office.com/webhook/test".to_string(),
        };
        let json = serde_json::to_string(&teams).unwrap();
        assert!(json.contains("teams"));

        let email = ChannelConfig::Email {
            recipients: vec!["admin@example.com".to_string()],
            template: Some("alert_template".to_string()),
        };
        let json = serde_json::to_string(&email).unwrap();
        assert!(json.contains("email"));

        let webhook = ChannelConfig::Webhook {
            url: "https://example.com/hook".to_string(),
            headers: HashMap::new(),
        };
        let json = serde_json::to_string(&webhook).unwrap();
        assert!(json.contains("webhook"));
    }

    #[test]
    fn test_throttle_config_serialization() {
        let config = ThrottleConfig {
            max_per_hour: 10,
            cooldown_secs: 300,
        };
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: ThrottleConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.max_per_hour, 10);
        assert_eq!(deserialized.cooldown_secs, 300);
    }

    #[test]
    fn test_notification_history_serialization() {
        let history = NotificationHistory {
            id: Uuid::new_v4(),
            rule_id: Uuid::new_v4(),
            trigger: "incident_created".to_string(),
            channel_type: "slack".to_string(),
            success: true,
            error: None,
            sent_at: Utc::now(),
        };
        let json = serde_json::to_string(&history).unwrap();
        let deserialized: NotificationHistory = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, history.id);
        assert!(deserialized.success);
    }

    // ==========================================================================
    // Helper function tests
    // ==========================================================================

    #[test]
    fn test_get_nested_field() {
        let json = serde_json::json!({
            "a": {
                "b": {
                    "c": "value"
                }
            }
        });

        assert_eq!(
            get_nested_field(&json, "a.b.c"),
            Some(&serde_json::json!("value"))
        );
        assert!(get_nested_field(&json, "a.b.d").is_none());
        assert!(get_nested_field(&json, "x.y.z").is_none());
    }

    #[test]
    fn test_compare_numeric() {
        let a = serde_json::json!(10);
        let b = serde_json::json!(5);
        assert!(compare_numeric(&a, &b, |x, y| x > y));
        assert!(!compare_numeric(&a, &b, |x, y| x < y));
    }

    #[test]
    fn test_compare_numeric_non_numeric() {
        let a = serde_json::json!("not a number");
        let b = serde_json::json!(5);
        assert!(!compare_numeric(&a, &b, |x, y| x > y));
    }
}
