//! Escalation rules engine for Triage Warden.
//!
//! This module implements the escalation manager that determines when
//! incidents should be escalated to human analysts based on configurable rules.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, instrument, warn};

/// Statistics for tracking false positives for a specific alert type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FalsePositiveStats {
    /// Number of false positives recorded.
    pub fp_count: usize,
    /// Number of true positives recorded.
    pub tp_count: usize,
    /// When statistics were last updated.
    pub last_updated: DateTime<Utc>,
}

impl FalsePositiveStats {
    /// Creates new stats with zero counts.
    pub fn new() -> Self {
        Self {
            fp_count: 0,
            tp_count: 0,
            last_updated: Utc::now(),
        }
    }

    /// Gets the total sample count.
    pub fn total_samples(&self) -> usize {
        self.fp_count + self.tp_count
    }

    /// Calculates the false positive rate.
    /// Returns None if there are no samples.
    pub fn fp_rate(&self) -> Option<f64> {
        let total = self.total_samples();
        if total == 0 {
            None
        } else {
            Some(self.fp_count as f64 / total as f64)
        }
    }
}

impl Default for FalsePositiveStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Context for an incident being evaluated for escalation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentContext {
    /// Type of alert that generated this incident.
    pub alert_type: String,
    /// Severity level of the incident.
    pub severity: String,
    /// Optional correlation key for grouping related incidents.
    pub correlation_key: Option<String>,
}

impl IncidentContext {
    /// Creates a new incident context.
    pub fn new(alert_type: String, severity: String) -> Self {
        Self {
            alert_type,
            severity,
            correlation_key: None,
        }
    }

    /// Creates an incident context with a correlation key.
    pub fn with_correlation_key(mut self, key: String) -> Self {
        self.correlation_key = Some(key);
        self
    }
}

/// Conditions that trigger escalation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationCondition {
    /// Escalate when false positive rate exceeds threshold with minimum samples.
    FalsePositiveRate {
        /// Threshold above which to escalate (e.g., 0.5 = 50% FP rate).
        threshold: f64,
        /// Minimum number of samples required before evaluating.
        min_samples: usize,
    },
    /// Escalate when multiple related incidents occur within a time window.
    RelatedIncidents {
        /// Number of incidents that trigger escalation.
        count: usize,
        /// Time window in hours to count incidents.
        time_window_hours: u64,
    },
    /// Escalate based on incident severity.
    Severity {
        /// Severity level that triggers escalation.
        level: String,
    },
    /// Custom condition for extensibility.
    Custom {
        /// Field to evaluate.
        field: String,
        /// Comparison operator (eq, ne, gt, lt, contains, matches).
        operator: String,
        /// Value to compare against.
        value: String,
    },
}

/// Actions to take when escalation is triggered.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EscalationAction {
    /// Escalate to an analyst for review.
    EscalateToAnalyst,
    /// Escalate to a senior analyst for review.
    EscalateToSenior,
    /// Escalate to SOC manager for review.
    EscalateToManager,
    /// Custom escalation action.
    Custom(String),
}

impl std::fmt::Display for EscalationAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EscalationAction::EscalateToAnalyst => write!(f, "Escalate to Analyst"),
            EscalationAction::EscalateToSenior => write!(f, "Escalate to Senior Analyst"),
            EscalationAction::EscalateToManager => write!(f, "Escalate to Manager"),
            EscalationAction::Custom(action) => write!(f, "Custom: {}", action),
        }
    }
}

/// An escalation rule that defines when and how to escalate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationRule {
    /// Unique name for this rule.
    pub name: String,
    /// Description of what this rule does.
    pub description: String,
    /// Condition that triggers this rule.
    pub condition: EscalationCondition,
    /// Action to take when triggered.
    pub action: EscalationAction,
}

impl EscalationRule {
    /// Creates a new escalation rule.
    pub fn new(
        name: String,
        description: String,
        condition: EscalationCondition,
        action: EscalationAction,
    ) -> Self {
        Self {
            name,
            description,
            condition,
            action,
        }
    }
}

/// Internal state for the escalation manager.
#[derive(Debug, Default)]
struct EscalationState {
    /// False positive statistics by alert type.
    fp_tracker: HashMap<String, FalsePositiveStats>,
    /// Incident timestamps by correlation key.
    incident_tracker: HashMap<String, Vec<DateTime<Utc>>>,
}

/// Manager for evaluating escalation rules.
pub struct EscalationManager {
    /// Configured escalation rules.
    rules: Vec<EscalationRule>,
    /// Internal state (protected by RwLock for thread safety).
    state: Arc<RwLock<EscalationState>>,
}

impl EscalationManager {
    /// Creates a new escalation manager with the given rules.
    pub fn new(rules: Vec<EscalationRule>) -> Self {
        Self {
            rules,
            state: Arc::new(RwLock::new(EscalationState::default())),
        }
    }

    /// Checks if an incident should be escalated based on configured rules.
    /// Returns the first matching escalation action, if any.
    #[instrument(skip(self))]
    pub async fn check_escalation(&self, incident: &IncidentContext) -> Option<EscalationAction> {
        let state = self.state.read().await;

        for rule in &self.rules {
            if self.evaluate_condition(&rule.condition, incident, &state).await {
                info!(
                    "Escalation rule '{}' triggered for incident type '{}'",
                    rule.name, incident.alert_type
                );
                return Some(rule.action.clone());
            }
        }

        debug!(
            "No escalation rules matched for incident type '{}'",
            incident.alert_type
        );
        None
    }

    /// Evaluates a single escalation condition.
    async fn evaluate_condition(
        &self,
        condition: &EscalationCondition,
        incident: &IncidentContext,
        state: &EscalationState,
    ) -> bool {
        match condition {
            EscalationCondition::FalsePositiveRate {
                threshold,
                min_samples,
            } => {
                if let Some(stats) = state.fp_tracker.get(&incident.alert_type) {
                    if stats.total_samples() >= *min_samples {
                        if let Some(rate) = stats.fp_rate() {
                            return rate > *threshold;
                        }
                    }
                }
                false
            }

            EscalationCondition::RelatedIncidents {
                count,
                time_window_hours,
            } => {
                if let Some(correlation_key) = &incident.correlation_key {
                    if let Some(timestamps) = state.incident_tracker.get(correlation_key) {
                        let cutoff = Utc::now() - Duration::hours(*time_window_hours as i64);
                        let recent_count = timestamps.iter().filter(|t| **t > cutoff).count();
                        return recent_count > *count;
                    }
                }
                false
            }

            EscalationCondition::Severity { level } => {
                incident.severity.eq_ignore_ascii_case(level)
            }

            EscalationCondition::Custom {
                field,
                operator,
                value,
            } => {
                let field_value = match field.as_str() {
                    "alert_type" => &incident.alert_type,
                    "severity" => &incident.severity,
                    _ => return false,
                };

                match operator.as_str() {
                    "eq" => field_value.eq_ignore_ascii_case(value),
                    "ne" => !field_value.eq_ignore_ascii_case(value),
                    "contains" => field_value.to_lowercase().contains(&value.to_lowercase()),
                    "matches" => {
                        if let Ok(re) = regex::Regex::new(value) {
                            re.is_match(field_value)
                        } else {
                            warn!("Invalid regex pattern in custom escalation condition: {}", value);
                            false
                        }
                    }
                    _ => {
                        warn!("Unknown operator in custom escalation condition: {}", operator);
                        false
                    }
                }
            }
        }
    }

    /// Records a false positive for a specific alert type.
    #[instrument(skip(self))]
    pub async fn record_false_positive(&self, alert_type: &str) {
        let mut state = self.state.write().await;
        let stats = state
            .fp_tracker
            .entry(alert_type.to_string())
            .or_insert_with(FalsePositiveStats::new);
        stats.fp_count += 1;
        stats.last_updated = Utc::now();
        debug!(
            "Recorded false positive for '{}': total FP={}, TP={}",
            alert_type, stats.fp_count, stats.tp_count
        );
    }

    /// Records a true positive for a specific alert type.
    #[instrument(skip(self))]
    pub async fn record_true_positive(&self, alert_type: &str) {
        let mut state = self.state.write().await;
        let stats = state
            .fp_tracker
            .entry(alert_type.to_string())
            .or_insert_with(FalsePositiveStats::new);
        stats.tp_count += 1;
        stats.last_updated = Utc::now();
        debug!(
            "Recorded true positive for '{}': total FP={}, TP={}",
            alert_type, stats.fp_count, stats.tp_count
        );
    }

    /// Records an incident for correlation tracking.
    #[instrument(skip(self))]
    pub async fn record_incident(&self, correlation_key: &str) {
        let mut state = self.state.write().await;
        let timestamps = state
            .incident_tracker
            .entry(correlation_key.to_string())
            .or_insert_with(Vec::new);
        timestamps.push(Utc::now());
        debug!(
            "Recorded incident for correlation key '{}': total={}",
            correlation_key,
            timestamps.len()
        );
    }

    /// Gets the false positive rate for a specific alert type.
    /// Returns None if the alert type is not tracked or has no samples.
    pub async fn get_fp_rate(&self, alert_type: &str) -> Option<f64> {
        let state = self.state.read().await;
        state.fp_tracker.get(alert_type).and_then(|s| s.fp_rate())
    }

    /// Gets the current rules.
    pub fn rules(&self) -> &[EscalationRule] {
        &self.rules
    }

    /// Adds a new rule.
    pub fn add_rule(&mut self, rule: EscalationRule) {
        self.rules.push(rule);
    }

    /// Removes a rule by name.
    pub fn remove_rule(&mut self, name: &str) -> bool {
        let initial_len = self.rules.len();
        self.rules.retain(|r| r.name != name);
        self.rules.len() < initial_len
    }

    /// Cleans up old incident tracking data.
    /// Removes incidents older than the specified number of hours.
    pub async fn cleanup(&self, max_age_hours: i64) {
        let cutoff = Utc::now() - Duration::hours(max_age_hours);
        let mut state = self.state.write().await;

        for timestamps in state.incident_tracker.values_mut() {
            timestamps.retain(|t| *t > cutoff);
        }

        // Remove empty entries
        state.incident_tracker.retain(|_, v| !v.is_empty());

        debug!("Cleaned up incident tracker, max age {} hours", max_age_hours);
    }

    /// Gets false positive stats for all tracked alert types.
    pub async fn get_all_fp_stats(&self) -> HashMap<String, FalsePositiveStats> {
        let state = self.state.read().await;
        state.fp_tracker.clone()
    }

    /// Gets incident counts by correlation key.
    pub async fn get_incident_counts(&self) -> HashMap<String, usize> {
        let state = self.state.read().await;
        state
            .incident_tracker
            .iter()
            .map(|(k, v)| (k.clone(), v.len()))
            .collect()
    }
}

impl Default for EscalationManager {
    fn default() -> Self {
        // Default rules based on guardrails.yaml
        let rules = vec![
            EscalationRule::new(
                "repeated_false_positives".to_string(),
                "Escalate if same alert type has high FP rate".to_string(),
                EscalationCondition::FalsePositiveRate {
                    threshold: 0.5,
                    min_samples: 10,
                },
                EscalationAction::EscalateToAnalyst,
            ),
            EscalationRule::new(
                "incident_correlation".to_string(),
                "Escalate if multiple related incidents detected".to_string(),
                EscalationCondition::RelatedIncidents {
                    count: 3,
                    time_window_hours: 1,
                },
                EscalationAction::EscalateToSenior,
            ),
            EscalationRule::new(
                "critical_severity".to_string(),
                "Always escalate critical severity incidents".to_string(),
                EscalationCondition::Severity {
                    level: "critical".to_string(),
                },
                EscalationAction::EscalateToManager,
            ),
        ];

        Self::new(rules)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_default_manager() -> EscalationManager {
        EscalationManager::default()
    }

    #[tokio::test]
    async fn test_false_positive_rate_escalation() {
        let manager = create_default_manager();

        // Record 6 false positives and 4 true positives (60% FP rate)
        for _ in 0..6 {
            manager.record_false_positive("suspicious_login").await;
        }
        for _ in 0..4 {
            manager.record_true_positive("suspicious_login").await;
        }

        let incident = IncidentContext::new("suspicious_login".to_string(), "high".to_string());
        let action = manager.check_escalation(&incident).await;

        assert_eq!(action, Some(EscalationAction::EscalateToAnalyst));
    }

    #[tokio::test]
    async fn test_false_positive_rate_no_escalation_below_threshold() {
        let manager = create_default_manager();

        // Record 3 false positives and 7 true positives (30% FP rate)
        for _ in 0..3 {
            manager.record_false_positive("suspicious_login").await;
        }
        for _ in 0..7 {
            manager.record_true_positive("suspicious_login").await;
        }

        let incident = IncidentContext::new("suspicious_login".to_string(), "high".to_string());
        let action = manager.check_escalation(&incident).await;

        // Should not escalate because FP rate is below threshold
        // But will match critical_severity if severity is critical
        assert!(action.is_none() || action != Some(EscalationAction::EscalateToAnalyst));
    }

    #[tokio::test]
    async fn test_false_positive_rate_no_escalation_insufficient_samples() {
        let manager = create_default_manager();

        // Record only 5 false positives (not enough samples, needs 10)
        for _ in 0..5 {
            manager.record_false_positive("suspicious_login").await;
        }

        let incident = IncidentContext::new("suspicious_login".to_string(), "high".to_string());
        let action = manager.check_escalation(&incident).await;

        // Should not escalate due to FP rate because insufficient samples
        assert!(action.is_none() || action != Some(EscalationAction::EscalateToAnalyst));
    }

    #[tokio::test]
    async fn test_related_incidents_escalation() {
        let manager = create_default_manager();
        let correlation_key = "campaign_12345";

        // Record 4 incidents with the same correlation key
        for _ in 0..4 {
            manager.record_incident(correlation_key).await;
        }

        let incident = IncidentContext::new("phishing".to_string(), "medium".to_string())
            .with_correlation_key(correlation_key.to_string());
        let action = manager.check_escalation(&incident).await;

        assert_eq!(action, Some(EscalationAction::EscalateToSenior));
    }

    #[tokio::test]
    async fn test_related_incidents_no_escalation_below_count() {
        let manager = create_default_manager();
        let correlation_key = "campaign_12345";

        // Record only 2 incidents (need >3 to trigger)
        for _ in 0..2 {
            manager.record_incident(correlation_key).await;
        }

        let incident = IncidentContext::new("phishing".to_string(), "medium".to_string())
            .with_correlation_key(correlation_key.to_string());
        let action = manager.check_escalation(&incident).await;

        // Should not escalate to senior because count is below threshold
        assert!(action.is_none() || action != Some(EscalationAction::EscalateToSenior));
    }

    #[tokio::test]
    async fn test_severity_escalation() {
        let manager = create_default_manager();

        let incident = IncidentContext::new("ransomware".to_string(), "critical".to_string());
        let action = manager.check_escalation(&incident).await;

        assert_eq!(action, Some(EscalationAction::EscalateToManager));
    }

    #[tokio::test]
    async fn test_severity_case_insensitive() {
        let manager = create_default_manager();

        let incident = IncidentContext::new("ransomware".to_string(), "CRITICAL".to_string());
        let action = manager.check_escalation(&incident).await;

        assert_eq!(action, Some(EscalationAction::EscalateToManager));
    }

    #[tokio::test]
    async fn test_no_escalation_non_critical() {
        let manager = create_default_manager();

        let incident = IncidentContext::new("port_scan".to_string(), "low".to_string());
        let action = manager.check_escalation(&incident).await;

        assert!(action.is_none());
    }

    #[tokio::test]
    async fn test_custom_condition_eq() {
        let rules = vec![EscalationRule::new(
            "custom_alert_type".to_string(),
            "Escalate specific alert type".to_string(),
            EscalationCondition::Custom {
                field: "alert_type".to_string(),
                operator: "eq".to_string(),
                value: "apt_activity".to_string(),
            },
            EscalationAction::EscalateToManager,
        )];

        let manager = EscalationManager::new(rules);
        let incident = IncidentContext::new("apt_activity".to_string(), "high".to_string());
        let action = manager.check_escalation(&incident).await;

        assert_eq!(action, Some(EscalationAction::EscalateToManager));
    }

    #[tokio::test]
    async fn test_custom_condition_contains() {
        let rules = vec![EscalationRule::new(
            "custom_contains".to_string(),
            "Escalate alerts containing 'malware'".to_string(),
            EscalationCondition::Custom {
                field: "alert_type".to_string(),
                operator: "contains".to_string(),
                value: "malware".to_string(),
            },
            EscalationAction::EscalateToSenior,
        )];

        let manager = EscalationManager::new(rules);
        let incident = IncidentContext::new("ransomware_malware_detected".to_string(), "high".to_string());
        let action = manager.check_escalation(&incident).await;

        assert_eq!(action, Some(EscalationAction::EscalateToSenior));
    }

    #[tokio::test]
    async fn test_custom_condition_matches_regex() {
        let rules = vec![EscalationRule::new(
            "custom_regex".to_string(),
            "Escalate alerts matching pattern".to_string(),
            EscalationCondition::Custom {
                field: "alert_type".to_string(),
                operator: "matches".to_string(),
                value: r"^apt_.*_detected$".to_string(),
            },
            EscalationAction::EscalateToManager,
        )];

        let manager = EscalationManager::new(rules);

        let incident1 = IncidentContext::new("apt_campaign_detected".to_string(), "high".to_string());
        assert_eq!(
            manager.check_escalation(&incident1).await,
            Some(EscalationAction::EscalateToManager)
        );

        let incident2 = IncidentContext::new("regular_alert".to_string(), "high".to_string());
        assert_eq!(manager.check_escalation(&incident2).await, None);
    }

    #[tokio::test]
    async fn test_get_fp_rate() {
        let manager = create_default_manager();

        // No data yet
        assert_eq!(manager.get_fp_rate("unknown").await, None);

        // Add some data
        manager.record_false_positive("test_alert").await;
        manager.record_true_positive("test_alert").await;

        let rate = manager.get_fp_rate("test_alert").await;
        assert!(rate.is_some());
        assert!((rate.unwrap() - 0.5).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_false_positive_stats() {
        let stats = FalsePositiveStats::new();
        assert_eq!(stats.fp_count, 0);
        assert_eq!(stats.tp_count, 0);
        assert_eq!(stats.total_samples(), 0);
        assert!(stats.fp_rate().is_none());
    }

    #[tokio::test]
    async fn test_escalation_action_display() {
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

    #[tokio::test]
    async fn test_add_and_remove_rule() {
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
        assert!(removed);
        assert_eq!(manager.rules().len(), 0);

        let removed_again = manager.remove_rule("test_rule");
        assert!(!removed_again);
    }

    #[tokio::test]
    async fn test_cleanup() {
        let manager = create_default_manager();

        // Record some incidents
        manager.record_incident("old_campaign").await;
        manager.record_incident("recent_campaign").await;

        // Cleanup with 0 hour max age (should remove all)
        manager.cleanup(0).await;

        let counts = manager.get_incident_counts().await;
        assert!(counts.is_empty());
    }

    #[tokio::test]
    async fn test_get_all_fp_stats() {
        let manager = create_default_manager();

        manager.record_false_positive("alert_a").await;
        manager.record_true_positive("alert_a").await;
        manager.record_false_positive("alert_b").await;

        let stats = manager.get_all_fp_stats().await;
        assert_eq!(stats.len(), 2);
        assert!(stats.contains_key("alert_a"));
        assert!(stats.contains_key("alert_b"));
    }

    #[tokio::test]
    async fn test_incident_context_builder() {
        let context = IncidentContext::new("phishing".to_string(), "high".to_string())
            .with_correlation_key("campaign_123".to_string());

        assert_eq!(context.alert_type, "phishing");
        assert_eq!(context.severity, "high");
        assert_eq!(context.correlation_key, Some("campaign_123".to_string()));
    }

    #[tokio::test]
    async fn test_rule_priority_first_match_wins() {
        // First matching rule wins
        let rules = vec![
            EscalationRule::new(
                "first_rule".to_string(),
                "First rule".to_string(),
                EscalationCondition::Severity {
                    level: "critical".to_string(),
                },
                EscalationAction::EscalateToAnalyst, // This should win
            ),
            EscalationRule::new(
                "second_rule".to_string(),
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

        assert_eq!(action, Some(EscalationAction::EscalateToAnalyst));
    }

    #[tokio::test]
    async fn test_no_correlation_key_no_related_incidents_match() {
        let manager = create_default_manager();

        // Record incidents with a correlation key
        for _ in 0..5 {
            manager.record_incident("some_campaign").await;
        }

        // Incident without correlation key should not match related incidents rule
        let incident = IncidentContext::new("phishing".to_string(), "medium".to_string());
        let action = manager.check_escalation(&incident).await;

        // Should not match the related incidents rule
        assert!(action.is_none() || action != Some(EscalationAction::EscalateToSenior));
    }
}
