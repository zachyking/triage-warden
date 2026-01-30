//! Policy rule definitions for Triage Warden.
//!
//! This module defines the structure and evaluation logic for policy rules
//! that control automated actions.

use crate::approval::ApprovalLevel;
use crate::engine::{ActionContext, Criticality};
use serde::{Deserialize, Serialize};

/// A policy rule that can be evaluated against an action context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Unique name for this rule.
    pub name: String,
    /// Description of what this rule does.
    pub description: Option<String>,
    /// Conditions that must all be true for this rule to match.
    pub conditions: Vec<RuleCondition>,
    /// Effect when the rule matches.
    pub effect: RuleEffect,
    /// Whether this rule's effect can be overridden.
    pub can_override: bool,
    /// Priority (lower = higher priority, evaluated first).
    pub priority: u32,
    /// Whether this rule is enabled.
    pub enabled: bool,
}

impl PolicyRule {
    /// Creates a new policy rule.
    pub fn new(name: String, conditions: Vec<RuleCondition>, effect: RuleEffect) -> Self {
        Self {
            name,
            description: None,
            conditions,
            effect,
            can_override: false,
            priority: 100,
            enabled: true,
        }
    }

    /// Creates a new rule with description.
    pub fn with_description(mut self, description: &str) -> Self {
        self.description = Some(description.to_string());
        self
    }

    /// Sets whether the rule can be overridden.
    pub fn with_override(mut self, can_override: bool) -> Self {
        self.can_override = can_override;
        self
    }

    /// Sets the rule priority.
    pub fn with_priority(mut self, priority: u32) -> Self {
        self.priority = priority;
        self
    }

    /// Checks if this rule matches the given context.
    pub fn matches(&self, context: &ActionContext) -> bool {
        if !self.enabled {
            return false;
        }
        self.conditions.iter().all(|c| c.evaluate(context))
    }
}

/// Conditions that can be used in policy rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleCondition {
    /// Action type must be in the given list.
    ActionTypeIn(Vec<String>),
    /// Action type must NOT be in the given list.
    ActionTypeNotIn(Vec<String>),
    /// Confidence score must be above threshold.
    ConfidenceAbove(f64),
    /// Confidence score must be below threshold.
    ConfidenceBelow(f64),
    /// Target criticality must be in the given list.
    TargetCriticalityIn(Vec<Criticality>),
    /// Target type must match.
    TargetTypeIs(String),
    /// Target must have all specified tags.
    TargetHasTags(Vec<String>),
    /// Target identifier must match pattern.
    TargetMatchesPattern(String),
    /// Incident severity must be in the given list.
    IncidentSeverityIn(Vec<String>),
    /// Proposer must be in the given list.
    ProposerIn(Vec<String>),
    /// Custom metadata field must equal value.
    MetadataEquals {
        key: String,
        value: serde_json::Value,
    },
    /// All sub-conditions must match.
    And(Vec<RuleCondition>),
    /// Any sub-condition must match.
    Or(Vec<RuleCondition>),
    /// Sub-condition must NOT match.
    Not(Box<RuleCondition>),
    /// Always true.
    Always,
    /// Always false.
    Never,
}

impl RuleCondition {
    /// Evaluates this condition against the given context.
    pub fn evaluate(&self, context: &ActionContext) -> bool {
        match self {
            RuleCondition::ActionTypeIn(types) => types.contains(&context.action_type),

            RuleCondition::ActionTypeNotIn(types) => !types.contains(&context.action_type),

            RuleCondition::ConfidenceAbove(threshold) => context.confidence > *threshold,

            RuleCondition::ConfidenceBelow(threshold) => context.confidence < *threshold,

            RuleCondition::TargetCriticalityIn(levels) => {
                if let Some(criticality) = &context.target.criticality {
                    levels.contains(criticality)
                } else {
                    false
                }
            }

            RuleCondition::TargetTypeIs(expected) => context.target.target_type == *expected,

            RuleCondition::TargetHasTags(required_tags) => required_tags
                .iter()
                .all(|t| context.target.tags.contains(t)),

            RuleCondition::TargetMatchesPattern(pattern) => {
                if let Ok(re) = regex::Regex::new(pattern) {
                    re.is_match(&context.target.identifier)
                } else {
                    false
                }
            }

            RuleCondition::IncidentSeverityIn(severities) => {
                severities.contains(&context.incident_severity)
            }

            RuleCondition::ProposerIn(proposers) => proposers.contains(&context.proposer),

            RuleCondition::MetadataEquals { key, value } => {
                context.metadata.get(key) == Some(value)
            }

            RuleCondition::And(conditions) => conditions.iter().all(|c| c.evaluate(context)),

            RuleCondition::Or(conditions) => conditions.iter().any(|c| c.evaluate(context)),

            RuleCondition::Not(condition) => !condition.evaluate(context),

            RuleCondition::Always => true,

            RuleCondition::Never => false,
        }
    }
}

/// Effect to apply when a rule matches.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleEffect {
    /// Allow the action to proceed automatically.
    Allow,
    /// Deny the action with a reason.
    Deny(String),
    /// Require approval at the specified level.
    RequireApproval(ApprovalLevel),
}

/// Builder for creating policy rules.
pub struct PolicyRuleBuilder {
    name: String,
    description: Option<String>,
    conditions: Vec<RuleCondition>,
    effect: Option<RuleEffect>,
    can_override: bool,
    priority: u32,
    enabled: bool,
}

impl PolicyRuleBuilder {
    /// Creates a new rule builder with the given name.
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            description: None,
            conditions: vec![],
            effect: None,
            can_override: false,
            priority: 100,
            enabled: true,
        }
    }

    /// Sets the rule description.
    pub fn description(mut self, desc: &str) -> Self {
        self.description = Some(desc.to_string());
        self
    }

    /// Adds a condition.
    pub fn when(mut self, condition: RuleCondition) -> Self {
        self.conditions.push(condition);
        self
    }

    /// Adds multiple conditions (all must match).
    pub fn when_all(mut self, conditions: Vec<RuleCondition>) -> Self {
        self.conditions.extend(conditions);
        self
    }

    /// Sets the effect to allow.
    pub fn then_allow(mut self) -> Self {
        self.effect = Some(RuleEffect::Allow);
        self
    }

    /// Sets the effect to deny.
    pub fn then_deny(mut self, reason: &str) -> Self {
        self.effect = Some(RuleEffect::Deny(reason.to_string()));
        self
    }

    /// Sets the effect to require approval.
    pub fn then_require_approval(mut self, level: ApprovalLevel) -> Self {
        self.effect = Some(RuleEffect::RequireApproval(level));
        self
    }

    /// Sets whether the rule can be overridden.
    pub fn override_allowed(mut self, allowed: bool) -> Self {
        self.can_override = allowed;
        self
    }

    /// Sets the rule priority.
    pub fn priority(mut self, priority: u32) -> Self {
        self.priority = priority;
        self
    }

    /// Sets whether the rule is enabled.
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Builds the policy rule.
    pub fn build(self) -> Result<PolicyRule, &'static str> {
        let effect = self.effect.ok_or("Effect must be specified")?;

        Ok(PolicyRule {
            name: self.name,
            description: self.description,
            conditions: self.conditions,
            effect,
            can_override: self.can_override,
            priority: self.priority,
            enabled: self.enabled,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::ActionTarget;
    use std::collections::HashMap;

    fn create_context(action: &str, confidence: f64) -> ActionContext {
        ActionContext {
            action_type: action.to_string(),
            target: ActionTarget {
                target_type: "host".to_string(),
                identifier: "test-host".to_string(),
                criticality: Some(Criticality::Medium),
                tags: vec!["windows".to_string(), "workstation".to_string()],
            },
            incident_severity: "high".to_string(),
            confidence,
            proposer: "ai".to_string(),
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_action_type_condition() {
        let context = create_context("isolate_host", 0.9);

        let condition = RuleCondition::ActionTypeIn(vec!["isolate_host".to_string()]);
        assert!(condition.evaluate(&context));

        let condition = RuleCondition::ActionTypeIn(vec!["disable_user".to_string()]);
        assert!(!condition.evaluate(&context));
    }

    #[test]
    fn test_confidence_conditions() {
        let context = create_context("isolate_host", 0.85);

        let condition = RuleCondition::ConfidenceAbove(0.8);
        assert!(condition.evaluate(&context));

        let condition = RuleCondition::ConfidenceAbove(0.9);
        assert!(!condition.evaluate(&context));

        let condition = RuleCondition::ConfidenceBelow(0.9);
        assert!(condition.evaluate(&context));
    }

    #[test]
    fn test_criticality_condition() {
        let context = create_context("isolate_host", 0.9);

        let condition =
            RuleCondition::TargetCriticalityIn(vec![Criticality::Medium, Criticality::High]);
        assert!(condition.evaluate(&context));

        let condition = RuleCondition::TargetCriticalityIn(vec![Criticality::Critical]);
        assert!(!condition.evaluate(&context));
    }

    #[test]
    fn test_tag_condition() {
        let context = create_context("isolate_host", 0.9);

        let condition = RuleCondition::TargetHasTags(vec!["windows".to_string()]);
        assert!(condition.evaluate(&context));

        let condition =
            RuleCondition::TargetHasTags(vec!["windows".to_string(), "workstation".to_string()]);
        assert!(condition.evaluate(&context));

        let condition = RuleCondition::TargetHasTags(vec!["linux".to_string()]);
        assert!(!condition.evaluate(&context));
    }

    #[test]
    fn test_pattern_condition() {
        let mut context = create_context("isolate_host", 0.9);
        context.target.identifier = "prod-web-01".to_string();

        let condition = RuleCondition::TargetMatchesPattern(r"prod-.*".to_string());
        assert!(condition.evaluate(&context));

        let condition = RuleCondition::TargetMatchesPattern(r"dev-.*".to_string());
        assert!(!condition.evaluate(&context));
    }

    #[test]
    fn test_composite_conditions() {
        let context = create_context("isolate_host", 0.9);

        // AND condition
        let condition = RuleCondition::And(vec![
            RuleCondition::ActionTypeIn(vec!["isolate_host".to_string()]),
            RuleCondition::ConfidenceAbove(0.8),
        ]);
        assert!(condition.evaluate(&context));

        // OR condition
        let condition = RuleCondition::Or(vec![
            RuleCondition::ActionTypeIn(vec!["disable_user".to_string()]),
            RuleCondition::ConfidenceAbove(0.8),
        ]);
        assert!(condition.evaluate(&context));

        // NOT condition
        let condition = RuleCondition::Not(Box::new(RuleCondition::ActionTypeIn(vec![
            "disable_user".to_string(),
        ])));
        assert!(condition.evaluate(&context));
    }

    #[test]
    fn test_rule_builder() {
        let rule = PolicyRuleBuilder::new("test_rule")
            .description("Test rule for unit tests")
            .when(RuleCondition::ActionTypeIn(
                vec!["isolate_host".to_string()],
            ))
            .when(RuleCondition::ConfidenceAbove(0.9))
            .then_require_approval(ApprovalLevel::Senior)
            .priority(50)
            .override_allowed(true)
            .build()
            .unwrap();

        assert_eq!(rule.name, "test_rule");
        assert_eq!(rule.priority, 50);
        assert!(rule.can_override);
        assert_eq!(rule.conditions.len(), 2);
    }

    #[test]
    fn test_rule_matching() {
        let rule = PolicyRule::new(
            "test".to_string(),
            vec![
                RuleCondition::ActionTypeIn(vec!["isolate_host".to_string()]),
                RuleCondition::ConfidenceAbove(0.8),
            ],
            RuleEffect::Allow,
        );

        let context = create_context("isolate_host", 0.9);
        assert!(rule.matches(&context));

        let context = create_context("isolate_host", 0.7);
        assert!(!rule.matches(&context));

        let context = create_context("disable_user", 0.9);
        assert!(!rule.matches(&context));
    }

    #[test]
    fn test_disabled_rule() {
        let mut rule = PolicyRule::new(
            "test".to_string(),
            vec![RuleCondition::Always],
            RuleEffect::Allow,
        );
        rule.enabled = false;

        let context = create_context("anything", 0.9);
        assert!(!rule.matches(&context));
    }
}
