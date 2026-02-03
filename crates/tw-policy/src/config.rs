//! YAML configuration loader for Triage Warden policy engine.
//!
//! This module handles loading and parsing the guardrails.yaml configuration
//! file into structured configuration types.

use crate::approval::ApprovalLevel;
use crate::engine::{
    validate_regex_safe, Criticality, DenyList, PolicyEngine, RateLimitConfig,
    RegexValidationError, ValidatedDenyList,
};
use crate::rules::{PolicyRule, RuleCondition, RuleEffect};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::path::Path;
use thiserror::Error;

/// Errors that can occur during configuration loading.
#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Failed to read configuration file: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Failed to parse YAML configuration: {0}")]
    ParseError(#[from] serde_yaml::Error),

    #[error("Invalid regex pattern '{pattern}': {message}")]
    InvalidRegex { pattern: String, message: String },

    #[error("Unsafe regex pattern (potential ReDoS): {0}")]
    UnsafeRegex(#[from] RegexValidationError),

    #[error("Missing required field: {0}")]
    MissingField(String),

    #[error("Invalid configuration value: {0}")]
    InvalidValue(String),

    #[error("Environment variable not found: {0}")]
    EnvVarNotFound(String),
}

/// Top-level guardrails configuration matching the YAML schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardrailsConfig {
    /// Deny list configuration.
    pub deny_list: DenyListConfig,
    /// Rate limits by action type.
    pub rate_limits: HashMap<String, RateLimitConfigYaml>,
    /// Approval policies.
    pub approval_policies: Vec<ApprovalPolicyConfig>,
    /// Auto-approve rules.
    pub auto_approve_rules: Vec<AutoApproveRuleConfig>,
    /// Data handling policies.
    pub data_policies: DataPoliciesConfig,
    /// Escalation rules.
    pub escalation_rules: Vec<EscalationRuleConfig>,
}

/// Deny list configuration from YAML.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DenyListConfig {
    /// Actions that are never allowed.
    #[serde(default)]
    pub actions: Vec<String>,
    /// Target patterns that are protected (regex).
    #[serde(default)]
    pub target_patterns: Vec<String>,
    /// Protected IP addresses.
    #[serde(default)]
    pub protected_ips: Vec<String>,
    /// Protected user accounts.
    #[serde(default)]
    pub protected_users: Vec<String>,
}

/// Rate limit configuration from YAML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfigYaml {
    /// Maximum executions per hour.
    pub max_per_hour: u32,
    /// Maximum executions per day.
    pub max_per_day: u32,
    /// Maximum concurrent executions.
    #[serde(default)]
    pub max_concurrent: Option<u32>,
}

impl From<RateLimitConfigYaml> for RateLimitConfig {
    fn from(yaml: RateLimitConfigYaml) -> Self {
        RateLimitConfig {
            max_per_hour: yaml.max_per_hour,
            max_per_day: yaml.max_per_day,
            max_concurrent: yaml.max_concurrent,
        }
    }
}

/// Approval policy configuration from YAML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalPolicyConfig {
    /// Policy name.
    pub name: String,
    /// Policy description.
    pub description: String,
    /// Conditions that trigger this policy.
    pub condition: ApprovalConditionConfig,
    /// Required approval level.
    pub requires: ApprovalLevelConfig,
    /// Whether this requirement can be overridden.
    #[serde(default)]
    pub can_override: bool,
}

/// Condition configuration for approval policies.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ApprovalConditionConfig {
    /// Target criticality levels that trigger this policy.
    #[serde(default)]
    pub target_criticality: Vec<String>,
    /// Action types that trigger this policy.
    #[serde(default)]
    pub action_type: Vec<String>,
    /// Confidence threshold (trigger if below this value).
    #[serde(default)]
    pub confidence_below: Option<f64>,
}

/// Approval level configuration (maps string to ApprovalLevel).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalLevelConfig {
    Analyst,
    Senior,
    Manager,
    Executive,
}

impl From<ApprovalLevelConfig> for ApprovalLevel {
    fn from(config: ApprovalLevelConfig) -> Self {
        match config {
            ApprovalLevelConfig::Analyst => ApprovalLevel::Analyst,
            ApprovalLevelConfig::Senior => ApprovalLevel::Senior,
            ApprovalLevelConfig::Manager => ApprovalLevel::Manager,
            ApprovalLevelConfig::Executive => ApprovalLevel::Executive,
        }
    }
}

/// Auto-approve rule configuration from YAML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoApproveRuleConfig {
    /// Rule name.
    pub name: String,
    /// Rule description.
    pub description: String,
    /// Action types this rule applies to.
    pub action_types: Vec<String>,
    /// Conditions that must be met for auto-approval.
    #[serde(default)]
    pub conditions: Vec<AutoApproveCondition>,
}

/// Condition for auto-approval.
///
/// In YAML, conditions are expressed as single-key maps:
/// ```yaml
/// conditions:
///   - confidence_above: 0.5
///   - verdict: true_positive
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AutoApproveCondition {
    /// Confidence must be above this threshold.
    #[serde(default)]
    pub confidence_above: Option<f64>,
    /// Verdict must match.
    #[serde(default)]
    pub verdict: Option<String>,
}

/// Data policies configuration from YAML.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DataPoliciesConfig {
    /// Whether to filter PII from logs and prompts.
    #[serde(default)]
    pub pii_filter: bool,
    /// Patterns to detect PII.
    #[serde(default)]
    pub pii_patterns: Vec<String>,
    /// Whether to redact secrets from logs.
    #[serde(default)]
    pub secrets_redaction: bool,
    /// Patterns to detect secrets.
    #[serde(default)]
    pub secret_patterns: Vec<String>,
    /// Whether to audit all data access.
    #[serde(default)]
    pub audit_data_access: bool,
}

/// Escalation rule configuration from YAML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationRuleConfig {
    /// Rule name.
    pub name: String,
    /// Rule description.
    pub description: String,
    /// Conditions that trigger escalation.
    pub condition: EscalationConditionConfig,
    /// Action to take when escalating.
    pub action: String,
}

/// Condition configuration for escalation rules.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EscalationConditionConfig {
    /// False positive rate threshold.
    #[serde(default)]
    pub false_positive_rate_above: Option<f64>,
    /// Minimum sample size for rate calculations.
    #[serde(default)]
    pub sample_size_min: Option<u32>,
    /// Number of related incidents threshold.
    #[serde(default)]
    pub related_incidents_above: Option<u32>,
    /// Time window for related incidents (hours).
    #[serde(default)]
    pub time_window_hours: Option<u32>,
    /// Severity level that triggers escalation.
    #[serde(default)]
    pub severity: Option<String>,
}

/// Substitutes environment variables in a string.
///
/// Replaces patterns like `${VAR_NAME}` with the corresponding environment variable value.
fn substitute_env_vars(input: &str) -> Result<String, ConfigError> {
    let re = Regex::new(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}").expect("Invalid regex for env vars");
    let mut result = input.to_string();
    let mut errors = Vec::new();

    for cap in re.captures_iter(input) {
        let full_match = cap.get(0).unwrap().as_str();
        let var_name = cap.get(1).unwrap().as_str();

        match env::var(var_name) {
            Ok(value) => {
                result = result.replace(full_match, &value);
            }
            Err(_) => {
                errors.push(var_name.to_string());
            }
        }
    }

    if !errors.is_empty() {
        return Err(ConfigError::EnvVarNotFound(errors.join(", ")));
    }

    Ok(result)
}

/// Validates that a regex pattern compiles successfully and is safe against ReDoS.
///
/// This function performs two validation steps:
/// 1. Checks that the pattern is syntactically valid
/// 2. Checks that the pattern doesn't contain constructs prone to catastrophic backtracking
fn validate_regex(pattern: &str) -> Result<(), ConfigError> {
    // First check basic syntax
    Regex::new(pattern).map_err(|e| ConfigError::InvalidRegex {
        pattern: pattern.to_string(),
        message: e.to_string(),
    })?;

    // Then check for ReDoS patterns
    validate_regex_safe(pattern)?;

    Ok(())
}

/// Loads and parses the guardrails configuration from a YAML file.
///
/// # Arguments
/// * `path` - Path to the guardrails.yaml file
///
/// # Returns
/// * `Ok(GuardrailsConfig)` - Parsed configuration
/// * `Err(ConfigError)` - If file cannot be read, parsed, or validated
///
/// # Example
/// ```no_run
/// use std::path::Path;
/// use tw_policy::config::load_guardrails;
///
/// let config = load_guardrails(Path::new("config/guardrails.yaml")).unwrap();
/// ```
pub fn load_guardrails(path: &Path) -> Result<GuardrailsConfig, ConfigError> {
    // Read the file content
    let content = std::fs::read_to_string(path)?;

    // Substitute environment variables
    let content = substitute_env_vars(&content)?;

    // Parse YAML
    let config: GuardrailsConfig = serde_yaml::from_str(&content)?;

    // Validate the configuration
    validate_config(&config)?;

    Ok(config)
}

/// Validates the loaded configuration.
fn validate_config(config: &GuardrailsConfig) -> Result<(), ConfigError> {
    // Validate deny list regex patterns
    for pattern in &config.deny_list.target_patterns {
        validate_regex(pattern)?;
    }

    // Validate data policy PII patterns
    for pattern in &config.data_policies.pii_patterns {
        validate_regex(pattern)?;
    }

    // Validate data policy secret patterns
    for pattern in &config.data_policies.secret_patterns {
        validate_regex(pattern)?;
    }

    // Validate approval policies have names
    for policy in &config.approval_policies {
        if policy.name.is_empty() {
            return Err(ConfigError::MissingField(
                "approval_policies[].name".to_string(),
            ));
        }
    }

    // Validate auto-approve rules have names and action types
    for rule in &config.auto_approve_rules {
        if rule.name.is_empty() {
            return Err(ConfigError::MissingField(
                "auto_approve_rules[].name".to_string(),
            ));
        }
        if rule.action_types.is_empty() {
            return Err(ConfigError::MissingField(format!(
                "auto_approve_rules[{}].action_types",
                rule.name
            )));
        }
    }

    // Validate escalation rules have names
    for rule in &config.escalation_rules {
        if rule.name.is_empty() {
            return Err(ConfigError::MissingField(
                "escalation_rules[].name".to_string(),
            ));
        }
    }

    Ok(())
}

impl DenyListConfig {
    /// Converts to the engine's DenyList type.
    ///
    /// **Note**: This returns a raw `DenyList` with uncompiled patterns.
    /// For production use with ReDoS protection, use `to_validated_deny_list()` instead.
    pub fn to_deny_list(&self) -> DenyList {
        DenyList {
            actions: self.actions.clone(),
            target_patterns: self.target_patterns.clone(),
            protected_ips: self.protected_ips.clone(),
            protected_users: self.protected_users.clone(),
        }
    }

    /// Converts to a ValidatedDenyList with pre-compiled and validated regex patterns.
    ///
    /// This method:
    /// 1. Validates all patterns for potential ReDoS vulnerabilities
    /// 2. Compiles patterns once and caches them as `Arc<Regex>`
    /// 3. Returns a `ValidatedDenyList` that is safe and efficient for repeated use
    ///
    /// # Errors
    ///
    /// Returns an error if any pattern is invalid or potentially unsafe.
    ///
    /// # Example
    ///
    /// ```
    /// use tw_policy::config::DenyListConfig;
    ///
    /// let config = DenyListConfig {
    ///     actions: vec!["delete_user".to_string()],
    ///     target_patterns: vec![r".*-prod-.*".to_string()],
    ///     protected_ips: vec![],
    ///     protected_users: vec![],
    /// };
    ///
    /// let validated = config.to_validated_deny_list().expect("Safe patterns");
    /// assert!(validated.is_target_protected("web-prod-01"));
    /// ```
    pub fn to_validated_deny_list(&self) -> Result<ValidatedDenyList, ConfigError> {
        let deny_list = self.to_deny_list();
        ValidatedDenyList::try_from_deny_list(&deny_list).map_err(ConfigError::from)
    }
}

impl GuardrailsConfig {
    /// Converts rate limits to the engine's format.
    pub fn to_rate_limits(&self) -> HashMap<String, RateLimitConfig> {
        self.rate_limits
            .iter()
            .map(|(k, v)| (k.clone(), v.clone().into()))
            .collect()
    }

    /// Converts approval policies and auto-approve rules to PolicyRules.
    pub fn to_policy_rules(&self) -> Vec<PolicyRule> {
        let mut rules = Vec::new();
        let mut priority = 0u32;

        // Convert approval policies (evaluated first, require approval)
        for policy in &self.approval_policies {
            let conditions = self.build_approval_conditions(&policy.condition);
            if conditions.is_empty() {
                continue;
            }

            let rule = PolicyRule {
                name: policy.name.clone(),
                description: Some(policy.description.clone()),
                conditions,
                effect: RuleEffect::RequireApproval(policy.requires.clone().into()),
                can_override: policy.can_override,
                priority,
                enabled: true,
            };
            rules.push(rule);
            priority += 1;
        }

        // Convert auto-approve rules (allow actions that match)
        for auto_rule in &self.auto_approve_rules {
            let mut conditions = vec![RuleCondition::ActionTypeIn(auto_rule.action_types.clone())];

            // Add auto-approve conditions
            for condition in &auto_rule.conditions {
                if let Some(threshold) = condition.confidence_above {
                    conditions.push(RuleCondition::ConfidenceAbove(threshold));
                }
                if let Some(verdict) = &condition.verdict {
                    conditions.push(RuleCondition::MetadataEquals {
                        key: "verdict".to_string(),
                        value: serde_json::Value::String(verdict.clone()),
                    });
                }
            }

            let rule = PolicyRule {
                name: auto_rule.name.clone(),
                description: Some(auto_rule.description.clone()),
                conditions,
                effect: RuleEffect::Allow,
                can_override: true,
                priority,
                enabled: true,
            };
            rules.push(rule);
            priority += 1;
        }

        rules
    }

    /// Builds rule conditions from approval condition config.
    fn build_approval_conditions(&self, condition: &ApprovalConditionConfig) -> Vec<RuleCondition> {
        let mut conditions = Vec::new();

        // Target criticality condition
        if !condition.target_criticality.is_empty() {
            let criticalities: Vec<Criticality> = condition
                .target_criticality
                .iter()
                .filter_map(|c| match c.to_lowercase().as_str() {
                    "low" => Some(Criticality::Low),
                    "medium" => Some(Criticality::Medium),
                    "high" => Some(Criticality::High),
                    "critical" => Some(Criticality::Critical),
                    _ => None,
                })
                .collect();

            if !criticalities.is_empty() {
                conditions.push(RuleCondition::TargetCriticalityIn(criticalities));
            }
        }

        // Action type condition
        if !condition.action_type.is_empty() {
            conditions.push(RuleCondition::ActionTypeIn(condition.action_type.clone()));
        }

        // Confidence threshold condition
        if let Some(threshold) = condition.confidence_below {
            conditions.push(RuleCondition::ConfidenceBelow(threshold));
        }

        conditions
    }
}

impl PolicyEngine {
    /// Creates a PolicyEngine from a GuardrailsConfig.
    ///
    /// # Arguments
    /// * `config` - The loaded guardrails configuration
    ///
    /// # Returns
    /// A new PolicyEngine configured according to the provided configuration.
    ///
    /// # Example
    /// ```no_run
    /// use std::path::Path;
    /// use tw_policy::config::load_guardrails;
    /// use tw_policy::PolicyEngine;
    ///
    /// let config = load_guardrails(Path::new("config/guardrails.yaml")).unwrap();
    /// let engine = PolicyEngine::from_config(config);
    /// ```
    pub fn from_config(config: GuardrailsConfig) -> Self {
        let deny_list = config.deny_list.to_deny_list();
        let rate_limits = config.to_rate_limits();
        let rules = config.to_policy_rules();

        PolicyEngine::new(rules, deny_list, rate_limits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn create_valid_yaml() -> &'static str {
        r#"
deny_list:
  actions:
    - delete_user
    - wipe_host
  target_patterns:
    - ".*-prod-.*"
    - "dc\\d+\\..*"
  protected_ips:
    - "10.0.0.1"
  protected_users:
    - "admin"
    - "root"

rate_limits:
  isolate_host:
    max_per_hour: 5
    max_per_day: 20
    max_concurrent: 2
  disable_user:
    max_per_hour: 10
    max_per_day: 50

approval_policies:
  - name: critical_asset_protection
    description: "Require senior approval for actions on critical assets"
    condition:
      target_criticality:
        - critical
        - high
    requires: senior
    can_override: false

auto_approve_rules:
  - name: ticket_operations
    description: "Auto-approve ticket creation and updates"
    action_types:
      - create_ticket
      - update_ticket
    conditions:
      - confidence_above: 0.5

data_policies:
  pii_filter: true
  pii_patterns:
    - "\\b\\d{3}-\\d{2}-\\d{4}\\b"
  secrets_redaction: true
  secret_patterns:
    - "(?i)api[_-]?key"
  audit_data_access: true

escalation_rules:
  - name: critical_severity
    description: "Always escalate critical severity incidents"
    condition:
      severity: critical
    action: escalate_to_manager
"#
    }

    #[test]
    fn test_load_valid_config() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(create_valid_yaml().as_bytes()).unwrap();

        let config = load_guardrails(file.path()).unwrap();

        // Verify deny list
        assert_eq!(config.deny_list.actions.len(), 2);
        assert!(config
            .deny_list
            .actions
            .contains(&"delete_user".to_string()));
        assert_eq!(config.deny_list.target_patterns.len(), 2);
        assert_eq!(config.deny_list.protected_ips.len(), 1);
        assert_eq!(config.deny_list.protected_users.len(), 2);

        // Verify rate limits
        assert_eq!(config.rate_limits.len(), 2);
        assert!(config.rate_limits.contains_key("isolate_host"));
        let isolate_limit = &config.rate_limits["isolate_host"];
        assert_eq!(isolate_limit.max_per_hour, 5);
        assert_eq!(isolate_limit.max_per_day, 20);
        assert_eq!(isolate_limit.max_concurrent, Some(2));

        // Verify approval policies
        assert_eq!(config.approval_policies.len(), 1);
        assert_eq!(
            config.approval_policies[0].name,
            "critical_asset_protection"
        );

        // Verify auto-approve rules
        assert_eq!(config.auto_approve_rules.len(), 1);
        assert_eq!(config.auto_approve_rules[0].name, "ticket_operations");

        // Verify data policies
        assert!(config.data_policies.pii_filter);
        assert_eq!(config.data_policies.pii_patterns.len(), 1);
        assert!(config.data_policies.secrets_redaction);
        assert!(config.data_policies.audit_data_access);

        // Verify escalation rules
        assert_eq!(config.escalation_rules.len(), 1);
        assert_eq!(config.escalation_rules[0].name, "critical_severity");
    }

    #[test]
    fn test_missing_file() {
        let result = load_guardrails(Path::new("/nonexistent/path/guardrails.yaml"));
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ConfigError::IoError(_)));
    }

    #[test]
    fn test_invalid_yaml() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"invalid: yaml: content: [").unwrap();

        let result = load_guardrails(file.path());
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ConfigError::ParseError(_)));
    }

    #[test]
    fn test_invalid_regex_pattern() {
        let yaml = r#"
deny_list:
  actions: []
  target_patterns:
    - "[invalid(regex"
  protected_ips: []
  protected_users: []
rate_limits: {}
approval_policies: []
auto_approve_rules: []
data_policies:
  pii_filter: false
  pii_patterns: []
  secrets_redaction: false
  secret_patterns: []
  audit_data_access: false
escalation_rules: []
"#;

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(yaml.as_bytes()).unwrap();

        let result = load_guardrails(file.path());
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ConfigError::InvalidRegex { .. }
        ));
    }

    #[test]
    fn test_env_var_substitution() {
        env::set_var("TEST_IP", "192.168.1.1");

        let yaml = r#"
deny_list:
  actions: []
  target_patterns: []
  protected_ips:
    - "${TEST_IP}"
  protected_users: []
rate_limits: {}
approval_policies: []
auto_approve_rules: []
data_policies:
  pii_filter: false
  pii_patterns: []
  secrets_redaction: false
  secret_patterns: []
  audit_data_access: false
escalation_rules: []
"#;

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(yaml.as_bytes()).unwrap();

        let config = load_guardrails(file.path()).unwrap();
        assert_eq!(config.deny_list.protected_ips[0], "192.168.1.1");

        env::remove_var("TEST_IP");
    }

    #[test]
    fn test_missing_env_var() {
        let yaml = r#"
deny_list:
  actions: []
  target_patterns: []
  protected_ips:
    - "${NONEXISTENT_VAR}"
  protected_users: []
rate_limits: {}
approval_policies: []
auto_approve_rules: []
data_policies:
  pii_filter: false
  pii_patterns: []
  secrets_redaction: false
  secret_patterns: []
  audit_data_access: false
escalation_rules: []
"#;

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(yaml.as_bytes()).unwrap();

        let result = load_guardrails(file.path());
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ConfigError::EnvVarNotFound(_)
        ));
    }

    #[test]
    fn test_policy_engine_from_config() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(create_valid_yaml().as_bytes()).unwrap();

        let config = load_guardrails(file.path()).unwrap();
        let engine = PolicyEngine::from_config(config);

        // Verify the engine was created with the correct rules
        let rules = engine.rules();
        assert!(!rules.is_empty());

        // Check that we have both approval and auto-approve rules
        let has_approval_rule = rules.iter().any(|r| r.name == "critical_asset_protection");
        let has_auto_approve_rule = rules.iter().any(|r| r.name == "ticket_operations");
        assert!(has_approval_rule);
        assert!(has_auto_approve_rule);
    }

    #[test]
    fn test_deny_list_conversion() {
        let config = DenyListConfig {
            actions: vec!["delete_user".to_string()],
            target_patterns: vec![".*-prod-.*".to_string()],
            protected_ips: vec!["10.0.0.1".to_string()],
            protected_users: vec!["admin".to_string()],
        };

        let deny_list = config.to_deny_list();
        assert!(deny_list.is_action_denied("delete_user"));
        assert!(deny_list.is_target_protected("web-prod-01"));
        assert!(deny_list.is_ip_protected("10.0.0.1"));
        assert!(deny_list.is_user_protected("admin"));
    }

    #[test]
    fn test_rate_limit_conversion() {
        let yaml_config = RateLimitConfigYaml {
            max_per_hour: 5,
            max_per_day: 20,
            max_concurrent: Some(2),
        };

        let config: RateLimitConfig = yaml_config.into();
        assert_eq!(config.max_per_hour, 5);
        assert_eq!(config.max_per_day, 20);
        assert_eq!(config.max_concurrent, Some(2));
    }

    #[test]
    fn test_approval_level_conversion() {
        assert_eq!(
            ApprovalLevel::from(ApprovalLevelConfig::Analyst),
            ApprovalLevel::Analyst
        );
        assert_eq!(
            ApprovalLevel::from(ApprovalLevelConfig::Senior),
            ApprovalLevel::Senior
        );
        assert_eq!(
            ApprovalLevel::from(ApprovalLevelConfig::Manager),
            ApprovalLevel::Manager
        );
        assert_eq!(
            ApprovalLevel::from(ApprovalLevelConfig::Executive),
            ApprovalLevel::Executive
        );
    }

    #[test]
    fn test_auto_approve_rule_without_action_types() {
        let yaml = r#"
deny_list:
  actions: []
  target_patterns: []
  protected_ips: []
  protected_users: []
rate_limits: {}
approval_policies: []
auto_approve_rules:
  - name: invalid_rule
    description: "Missing action types"
    action_types: []
    conditions: []
data_policies:
  pii_filter: false
  pii_patterns: []
  secrets_redaction: false
  secret_patterns: []
  audit_data_access: false
escalation_rules: []
"#;

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(yaml.as_bytes()).unwrap();

        let result = load_guardrails(file.path());
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ConfigError::MissingField(_)));
    }

    #[test]
    fn test_policy_rules_generation() {
        let config = GuardrailsConfig {
            deny_list: DenyListConfig::default(),
            rate_limits: HashMap::new(),
            approval_policies: vec![ApprovalPolicyConfig {
                name: "test_policy".to_string(),
                description: "Test policy".to_string(),
                condition: ApprovalConditionConfig {
                    target_criticality: vec!["critical".to_string()],
                    action_type: vec![],
                    confidence_below: None,
                },
                requires: ApprovalLevelConfig::Senior,
                can_override: false,
            }],
            auto_approve_rules: vec![AutoApproveRuleConfig {
                name: "test_auto".to_string(),
                description: "Test auto-approve".to_string(),
                action_types: vec!["create_ticket".to_string()],
                conditions: vec![AutoApproveCondition {
                    confidence_above: Some(0.9),
                    verdict: None,
                }],
            }],
            data_policies: DataPoliciesConfig::default(),
            escalation_rules: vec![],
        };

        let rules = config.to_policy_rules();
        assert_eq!(rules.len(), 2);

        // Check approval policy rule
        let approval_rule = &rules[0];
        assert_eq!(approval_rule.name, "test_policy");
        assert!(matches!(
            approval_rule.effect,
            RuleEffect::RequireApproval(ApprovalLevel::Senior)
        ));

        // Check auto-approve rule
        let auto_rule = &rules[1];
        assert_eq!(auto_rule.name, "test_auto");
        assert!(matches!(auto_rule.effect, RuleEffect::Allow));
    }

    #[test]
    fn test_substitute_env_vars() {
        env::set_var("TEST_VAR1", "value1");
        env::set_var("TEST_VAR2", "value2");

        let input = "prefix_${TEST_VAR1}_middle_${TEST_VAR2}_suffix";
        let result = substitute_env_vars(input).unwrap();
        assert_eq!(result, "prefix_value1_middle_value2_suffix");

        env::remove_var("TEST_VAR1");
        env::remove_var("TEST_VAR2");
    }

    #[test]
    fn test_validate_regex() {
        assert!(validate_regex(r".*-prod-.*").is_ok());
        assert!(validate_regex(r"\d{3}-\d{2}-\d{4}").is_ok());
        assert!(validate_regex(r"[invalid(regex").is_err());
    }

    #[test]
    fn test_load_actual_guardrails_yaml() {
        // Test loading the actual config/guardrails.yaml from the project
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let config_path = Path::new(manifest_dir)
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("config")
            .join("guardrails.yaml");

        if config_path.exists() {
            let config = load_guardrails(&config_path).expect("Failed to load guardrails.yaml");

            // Verify key components are loaded
            assert!(
                !config.deny_list.actions.is_empty(),
                "deny_list.actions should not be empty"
            );
            assert!(
                !config.rate_limits.is_empty(),
                "rate_limits should not be empty"
            );
            assert!(
                !config.approval_policies.is_empty(),
                "approval_policies should not be empty"
            );
            assert!(
                !config.auto_approve_rules.is_empty(),
                "auto_approve_rules should not be empty"
            );
            assert!(config.data_policies.pii_filter, "pii_filter should be true");
            assert!(
                !config.escalation_rules.is_empty(),
                "escalation_rules should not be empty"
            );

            // Verify we can create a PolicyEngine from the config
            let engine = PolicyEngine::from_config(config);
            assert!(!engine.rules().is_empty(), "PolicyEngine should have rules");
        }
    }
}
