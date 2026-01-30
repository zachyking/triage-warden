//! Policy evaluation engine for Triage Warden.
//!
//! This module implements the core policy engine that evaluates proposed
//! actions against configured rules and guardrails.

use crate::approval::ApprovalLevel;
use crate::rules::{PolicyRule, RuleCondition, RuleEffect};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, info, instrument, warn};

/// Errors that can occur in policy evaluation.
#[derive(Error, Debug)]
pub enum PolicyError {
    #[error("Policy configuration error: {0}")]
    ConfigError(String),

    #[error("Rate limit exceeded: {0}")]
    RateLimitExceeded(String),

    #[error("Denied by policy: {0}")]
    Denied(String),

    #[error("Invalid target: {0}")]
    InvalidTarget(String),
}

/// Result of policy evaluation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PolicyDecision {
    /// Action is allowed to proceed automatically.
    Allowed,
    /// Action is denied by policy.
    Denied(DenyReason),
    /// Action requires approval before proceeding.
    RequiresApproval(ApprovalLevel),
}

/// Reason for denying an action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DenyReason {
    /// The rule that caused the denial.
    pub rule_name: String,
    /// Human-readable explanation.
    pub message: String,
    /// Whether this denial can be overridden.
    pub can_override: bool,
}

/// Context for evaluating a proposed action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionContext {
    /// Type of action being proposed.
    pub action_type: String,
    /// Target of the action.
    pub target: ActionTarget,
    /// Severity of the incident.
    pub incident_severity: String,
    /// Confidence score from analysis.
    pub confidence: f64,
    /// Source of the proposal (AI, playbook, analyst).
    pub proposer: String,
    /// Additional context data.
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Target of an action for policy evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionTarget {
    /// Type of target (host, user, ip, etc.).
    pub target_type: String,
    /// Target identifier.
    pub identifier: String,
    /// Criticality level of the target.
    pub criticality: Option<Criticality>,
    /// Tags/labels on the target.
    pub tags: Vec<String>,
}

/// Criticality level for assets.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Criticality {
    Low,
    Medium,
    High,
    Critical,
}

/// Deny list configuration for blocking specific actions or targets.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DenyList {
    /// Actions that are never allowed.
    pub actions: Vec<String>,
    /// Target patterns that are protected.
    pub target_patterns: Vec<String>,
    /// Specific IPs that are protected.
    pub protected_ips: Vec<String>,
    /// Specific users that are protected.
    pub protected_users: Vec<String>,
}

impl DenyList {
    /// Checks if an action is in the deny list.
    pub fn is_action_denied(&self, action: &str) -> bool {
        self.actions.iter().any(|a| a == action)
    }

    /// Checks if a target matches any protected pattern.
    pub fn is_target_protected(&self, target: &str) -> bool {
        for pattern in &self.target_patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                if re.is_match(target) {
                    return true;
                }
            }
        }
        false
    }

    /// Checks if an IP is protected.
    pub fn is_ip_protected(&self, ip: &str) -> bool {
        self.protected_ips.contains(&ip.to_string())
    }

    /// Checks if a user is protected.
    pub fn is_user_protected(&self, user: &str) -> bool {
        self.protected_users.contains(&user.to_string())
    }
}

/// Rate limit configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum executions per hour.
    pub max_per_hour: u32,
    /// Maximum executions per day.
    pub max_per_day: u32,
    /// Maximum concurrent executions.
    pub max_concurrent: Option<u32>,
}

/// Rate limiter state.
#[derive(Debug, Default)]
struct RateLimiterState {
    /// Actions executed in the current hour window.
    hourly_counts: HashMap<String, Vec<DateTime<Utc>>>,
    /// Actions executed in the current day window.
    daily_counts: HashMap<String, Vec<DateTime<Utc>>>,
    /// Currently executing actions.
    concurrent: HashMap<String, u32>,
}

/// Rate limiter for action execution.
pub struct RateLimiter {
    /// Rate limit configurations by action type.
    configs: HashMap<String, RateLimitConfig>,
    /// Current state.
    state: Arc<RwLock<RateLimiterState>>,
}

impl RateLimiter {
    /// Creates a new rate limiter with the given configurations.
    pub fn new(configs: HashMap<String, RateLimitConfig>) -> Self {
        Self {
            configs,
            state: Arc::new(RwLock::new(RateLimiterState::default())),
        }
    }

    /// Checks if an action is within rate limits.
    #[instrument(skip(self))]
    pub async fn check(&self, action_type: &str) -> Result<(), PolicyError> {
        let config = match self.configs.get(action_type) {
            Some(c) => c,
            None => return Ok(()), // No limit configured
        };

        let now = Utc::now();
        let hour_ago = now - Duration::hours(1);
        let day_ago = now - Duration::days(1);

        let state = self.state.read().await;

        // Check hourly limit
        if let Some(times) = state.hourly_counts.get(action_type) {
            let count = times.iter().filter(|t| **t > hour_ago).count() as u32;
            if count >= config.max_per_hour {
                return Err(PolicyError::RateLimitExceeded(format!(
                    "{} hourly limit ({}) exceeded",
                    action_type, config.max_per_hour
                )));
            }
        }

        // Check daily limit
        if let Some(times) = state.daily_counts.get(action_type) {
            let count = times.iter().filter(|t| **t > day_ago).count() as u32;
            if count >= config.max_per_day {
                return Err(PolicyError::RateLimitExceeded(format!(
                    "{} daily limit ({}) exceeded",
                    action_type, config.max_per_day
                )));
            }
        }

        // Check concurrent limit
        if let Some(max_concurrent) = config.max_concurrent {
            if let Some(current) = state.concurrent.get(action_type) {
                if *current >= max_concurrent {
                    return Err(PolicyError::RateLimitExceeded(format!(
                        "{} concurrent limit ({}) exceeded",
                        action_type, max_concurrent
                    )));
                }
            }
        }

        Ok(())
    }

    /// Records an action execution.
    pub async fn record(&self, action_type: &str) {
        let now = Utc::now();
        let mut state = self.state.write().await;

        state
            .hourly_counts
            .entry(action_type.to_string())
            .or_default()
            .push(now);

        state
            .daily_counts
            .entry(action_type.to_string())
            .or_default()
            .push(now);
    }

    /// Increments the concurrent count for an action.
    pub async fn start_concurrent(&self, action_type: &str) {
        let mut state = self.state.write().await;
        *state.concurrent.entry(action_type.to_string()).or_insert(0) += 1;
    }

    /// Decrements the concurrent count for an action.
    pub async fn end_concurrent(&self, action_type: &str) {
        let mut state = self.state.write().await;
        if let Some(count) = state.concurrent.get_mut(action_type) {
            *count = count.saturating_sub(1);
        }
    }

    /// Cleans up old entries to prevent memory growth.
    pub async fn cleanup(&self) {
        let now = Utc::now();
        let hour_ago = now - Duration::hours(1);
        let day_ago = now - Duration::days(1);

        let mut state = self.state.write().await;

        for times in state.hourly_counts.values_mut() {
            times.retain(|t| *t > hour_ago);
        }

        for times in state.daily_counts.values_mut() {
            times.retain(|t| *t > day_ago);
        }
    }
}

/// The policy engine evaluates proposed actions against configured rules.
pub struct PolicyEngine {
    /// Policy rules.
    rules: Vec<PolicyRule>,
    /// Deny list for blocked actions/targets.
    deny_list: DenyList,
    /// Rate limiter.
    rate_limiter: RateLimiter,
    /// Default decision when no rules match.
    default_decision: PolicyDecision,
}

impl PolicyEngine {
    /// Creates a new policy engine.
    pub fn new(
        rules: Vec<PolicyRule>,
        deny_list: DenyList,
        rate_limits: HashMap<String, RateLimitConfig>,
    ) -> Self {
        Self {
            rules,
            deny_list,
            rate_limiter: RateLimiter::new(rate_limits),
            default_decision: PolicyDecision::RequiresApproval(ApprovalLevel::Analyst),
        }
    }

    /// Creates a policy engine with default configuration.
    pub fn default_config() -> Self {
        let rules = vec![
            // Critical assets require senior approval (highest priority)
            PolicyRule::new(
                "critical_assets_senior_approval".to_string(),
                vec![RuleCondition::TargetCriticalityIn(vec![
                    Criticality::Critical,
                ])],
                RuleEffect::RequireApproval(ApprovalLevel::Senior),
            ),
            // Low-risk actions for high-confidence verdicts
            PolicyRule::new(
                "auto_approve_low_risk_high_confidence".to_string(),
                vec![
                    RuleCondition::ActionTypeIn(vec![
                        "create_ticket".to_string(),
                        "add_ticket_comment".to_string(),
                        "send_notification".to_string(),
                    ]),
                    RuleCondition::ConfidenceAbove(0.9),
                ],
                RuleEffect::Allow,
            ),
            // Require approval for host isolation
            PolicyRule::new(
                "host_isolation_requires_approval".to_string(),
                vec![RuleCondition::ActionTypeIn(
                    vec!["isolate_host".to_string()],
                )],
                RuleEffect::RequireApproval(ApprovalLevel::Analyst),
            ),
        ];

        let deny_list = DenyList {
            actions: vec!["delete_user".to_string(), "wipe_host".to_string()],
            target_patterns: vec![r".*-prod-.*".to_string(), r"dc\d+\..*".to_string()],
            protected_ips: vec![],
            protected_users: vec!["admin".to_string(), "root".to_string()],
        };

        let mut rate_limits = HashMap::new();
        rate_limits.insert(
            "isolate_host".to_string(),
            RateLimitConfig {
                max_per_hour: 5,
                max_per_day: 20,
                max_concurrent: Some(2),
            },
        );
        rate_limits.insert(
            "disable_user".to_string(),
            RateLimitConfig {
                max_per_hour: 10,
                max_per_day: 50,
                max_concurrent: Some(5),
            },
        );

        Self::new(rules, deny_list, rate_limits)
    }

    /// Evaluates a proposed action against all policies.
    #[instrument(skip(self, context), fields(action = %context.action_type))]
    pub async fn evaluate(&self, context: &ActionContext) -> Result<PolicyDecision, PolicyError> {
        debug!("Evaluating policy for action: {}", context.action_type);

        // 1. Check deny list
        if self.deny_list.is_action_denied(&context.action_type) {
            info!("Action {} denied by deny list", context.action_type);
            return Ok(PolicyDecision::Denied(DenyReason {
                rule_name: "deny_list".to_string(),
                message: format!("Action '{}' is not allowed", context.action_type),
                can_override: false,
            }));
        }

        // Check target protection
        if self
            .deny_list
            .is_target_protected(&context.target.identifier)
        {
            info!(
                "Target {} is protected by deny list",
                context.target.identifier
            );
            return Ok(PolicyDecision::Denied(DenyReason {
                rule_name: "target_protection".to_string(),
                message: format!("Target '{}' is protected", context.target.identifier),
                can_override: false,
            }));
        }

        // Check user protection
        if context.target.target_type == "user"
            && self.deny_list.is_user_protected(&context.target.identifier)
        {
            return Ok(PolicyDecision::Denied(DenyReason {
                rule_name: "user_protection".to_string(),
                message: format!("User '{}' is protected", context.target.identifier),
                can_override: false,
            }));
        }

        // 2. Check rate limits
        if let Err(e) = self.rate_limiter.check(&context.action_type).await {
            warn!("Rate limit check failed: {}", e);
            return Ok(PolicyDecision::Denied(DenyReason {
                rule_name: "rate_limit".to_string(),
                message: e.to_string(),
                can_override: true,
            }));
        }

        // 3. Evaluate rules in order
        for rule in &self.rules {
            if rule.matches(context) {
                debug!("Rule '{}' matched", rule.name);
                match &rule.effect {
                    RuleEffect::Allow => return Ok(PolicyDecision::Allowed),
                    RuleEffect::Deny(reason) => {
                        return Ok(PolicyDecision::Denied(DenyReason {
                            rule_name: rule.name.clone(),
                            message: reason.clone(),
                            can_override: rule.can_override,
                        }))
                    }
                    RuleEffect::RequireApproval(level) => {
                        return Ok(PolicyDecision::RequiresApproval(*level))
                    }
                }
            }
        }

        // 4. Return default decision
        debug!("No rules matched, returning default decision");
        Ok(self.default_decision.clone())
    }

    /// Records an action execution for rate limiting.
    pub async fn record_execution(&self, action_type: &str) {
        self.rate_limiter.record(action_type).await;
    }

    /// Starts tracking a concurrent action.
    pub async fn start_action(&self, action_type: &str) {
        self.rate_limiter.start_concurrent(action_type).await;
    }

    /// Ends tracking a concurrent action.
    pub async fn end_action(&self, action_type: &str) {
        self.rate_limiter.end_concurrent(action_type).await;
    }

    /// Gets the current rules.
    pub fn rules(&self) -> &[PolicyRule] {
        &self.rules
    }

    /// Adds a new rule.
    pub fn add_rule(&mut self, rule: PolicyRule) {
        self.rules.push(rule);
    }

    /// Removes a rule by name.
    pub fn remove_rule(&mut self, name: &str) -> bool {
        let initial_len = self.rules.len();
        self.rules.retain(|r| r.name != name);
        self.rules.len() < initial_len
    }

    /// Updates the deny list.
    pub fn update_deny_list(&mut self, deny_list: DenyList) {
        self.deny_list = deny_list;
    }

    /// Sets the default decision.
    pub fn set_default_decision(&mut self, decision: PolicyDecision) {
        self.default_decision = decision;
    }

    /// Cleans up rate limiter state.
    pub async fn cleanup(&self) {
        self.rate_limiter.cleanup().await;
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::default_config()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_context(action_type: &str, confidence: f64) -> ActionContext {
        ActionContext {
            action_type: action_type.to_string(),
            target: ActionTarget {
                target_type: "host".to_string(),
                identifier: "workstation-001".to_string(),
                criticality: Some(Criticality::Medium),
                tags: vec![],
            },
            incident_severity: "high".to_string(),
            confidence,
            proposer: "ai".to_string(),
            metadata: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn test_allow_low_risk_action() {
        let engine = PolicyEngine::default_config();
        let context = create_test_context("create_ticket", 0.95);

        let decision = engine.evaluate(&context).await.unwrap();
        assert_eq!(decision, PolicyDecision::Allowed);
    }

    #[tokio::test]
    async fn test_deny_dangerous_action() {
        let engine = PolicyEngine::default_config();
        let context = create_test_context("delete_user", 0.99);

        let decision = engine.evaluate(&context).await.unwrap();
        assert!(matches!(decision, PolicyDecision::Denied(_)));
    }

    #[tokio::test]
    async fn test_require_approval_for_isolation() {
        let engine = PolicyEngine::default_config();
        let context = create_test_context("isolate_host", 0.95);

        let decision = engine.evaluate(&context).await.unwrap();
        assert!(matches!(
            decision,
            PolicyDecision::RequiresApproval(ApprovalLevel::Analyst)
        ));
    }

    #[tokio::test]
    async fn test_critical_asset_protection() {
        let engine = PolicyEngine::default_config();
        let mut context = create_test_context("isolate_host", 0.95);
        context.target.criticality = Some(Criticality::Critical);

        let decision = engine.evaluate(&context).await.unwrap();
        assert!(matches!(
            decision,
            PolicyDecision::RequiresApproval(ApprovalLevel::Senior)
        ));
    }

    #[tokio::test]
    async fn test_protected_target() {
        let engine = PolicyEngine::default_config();
        let mut context = create_test_context("isolate_host", 0.95);
        context.target.identifier = "dc01.corp.local".to_string();

        let decision = engine.evaluate(&context).await.unwrap();
        assert!(matches!(decision, PolicyDecision::Denied(_)));
    }

    #[tokio::test]
    async fn test_rate_limiting() {
        let mut rate_limits = HashMap::new();
        rate_limits.insert(
            "test_action".to_string(),
            RateLimitConfig {
                max_per_hour: 2,
                max_per_day: 10,
                max_concurrent: None,
            },
        );

        let engine = PolicyEngine::new(vec![], DenyList::default(), rate_limits);
        let context = create_test_context("test_action", 0.95);

        // First two should succeed
        engine.record_execution("test_action").await;
        engine.record_execution("test_action").await;

        // Third should be rate limited
        let decision = engine.evaluate(&context).await.unwrap();
        assert!(matches!(decision, PolicyDecision::Denied(_)));
    }

    #[tokio::test]
    async fn test_deny_list_patterns() {
        let deny_list = DenyList {
            actions: vec![],
            target_patterns: vec![r".*-prod-.*".to_string()],
            protected_ips: vec![],
            protected_users: vec![],
        };

        assert!(deny_list.is_target_protected("web-prod-01"));
        assert!(deny_list.is_target_protected("db-prod-cluster"));
        assert!(!deny_list.is_target_protected("web-dev-01"));
    }
}
