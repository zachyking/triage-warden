//! Configuration loading for Triage Warden CLI.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Application configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    /// Operation mode (assisted, supervised, autonomous).
    #[serde(default = "default_operation_mode")]
    pub operation_mode: String,

    /// Maximum concurrent incidents.
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent_incidents: usize,

    /// Configured connectors.
    #[serde(default)]
    pub connectors: HashMap<String, ConnectorConfig>,

    /// LLM configuration.
    #[serde(default)]
    pub llm: LLMConfig,

    /// Policy configuration.
    #[serde(default)]
    pub policy: PolicyConfig,

    /// Logging configuration.
    #[serde(default)]
    pub logging: LoggingConfig,
}

fn default_operation_mode() -> String {
    "supervised".to_string()
}

fn default_max_concurrent() -> usize {
    50
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            operation_mode: default_operation_mode(),
            max_concurrent_incidents: default_max_concurrent(),
            connectors: HashMap::new(),
            llm: LLMConfig::default(),
            policy: PolicyConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}

impl AppConfig {
    /// Loads configuration from a file.
    pub fn load(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;

        let config: Self = serde_yaml::from_str(&contents)
            .with_context(|| format!("Failed to parse config file: {}", path.display()))?;

        Ok(config)
    }

    /// Saves configuration to a file.
    pub fn save(&self, path: &Path) -> Result<()> {
        let contents = serde_yaml::to_string(self)?;
        std::fs::write(path, contents)?;
        Ok(())
    }

    /// Creates a copy with secrets redacted.
    pub fn redact_secrets(&self) -> Self {
        let mut config = self.clone();

        // Redact connector secrets
        for connector in config.connectors.values_mut() {
            if !connector.api_key.is_empty() {
                connector.api_key = "***REDACTED***".to_string();
            }
            if !connector.api_secret.is_empty() {
                connector.api_secret = "***REDACTED***".to_string();
            }
        }

        // Redact LLM API key
        if !config.llm.api_key.is_empty() {
            config.llm.api_key = "***REDACTED***".to_string();
        }

        config
    }
}

/// Connector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorConfig {
    /// Connector type (jira, virustotal, splunk, etc.).
    pub connector_type: String,

    /// Base URL for the API.
    #[serde(default)]
    pub base_url: String,

    /// Whether this connector is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// API key (if applicable).
    #[serde(default)]
    pub api_key: String,

    /// API secret (if applicable).
    #[serde(default)]
    pub api_secret: String,

    /// Request timeout in seconds.
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,

    /// Additional connector-specific settings.
    #[serde(default)]
    pub settings: HashMap<String, serde_json::Value>,
}

fn default_true() -> bool {
    true
}

fn default_timeout() -> u64 {
    30
}

/// LLM configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LLMConfig {
    /// LLM provider (openai, anthropic, local).
    #[serde(default = "default_llm_provider")]
    pub provider: String,

    /// Model name.
    #[serde(default = "default_llm_model")]
    pub model: String,

    /// API key.
    #[serde(default)]
    pub api_key: String,

    /// API base URL (for local/custom providers).
    #[serde(default)]
    pub base_url: String,

    /// Maximum tokens for responses.
    #[serde(default = "default_max_tokens")]
    pub max_tokens: usize,

    /// Temperature for generation.
    #[serde(default = "default_temperature")]
    pub temperature: f32,
}

fn default_llm_provider() -> String {
    "openai".to_string()
}

fn default_llm_model() -> String {
    "gpt-4-turbo".to_string()
}

fn default_max_tokens() -> usize {
    4096
}

fn default_temperature() -> f32 {
    0.1
}

impl Default for LLMConfig {
    fn default() -> Self {
        Self {
            provider: default_llm_provider(),
            model: default_llm_model(),
            api_key: String::new(),
            base_url: String::new(),
            max_tokens: default_max_tokens(),
            temperature: default_temperature(),
        }
    }
}

/// Policy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Path to guardrails configuration.
    #[serde(default = "default_guardrails_path")]
    pub guardrails_path: String,

    /// Default approval level for unknown actions.
    #[serde(default = "default_approval_level")]
    pub default_approval_level: String,

    /// Whether to auto-approve low-risk actions.
    #[serde(default)]
    pub auto_approve_low_risk: bool,

    /// Confidence threshold for auto-approval.
    #[serde(default = "default_confidence_threshold")]
    pub confidence_threshold: f64,
}

fn default_guardrails_path() -> String {
    "config/guardrails.yaml".to_string()
}

fn default_approval_level() -> String {
    "analyst".to_string()
}

fn default_confidence_threshold() -> f64 {
    0.9
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            guardrails_path: default_guardrails_path(),
            default_approval_level: default_approval_level(),
            auto_approve_low_risk: false,
            confidence_threshold: default_confidence_threshold(),
        }
    }
}

/// Logging configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level.
    #[serde(default = "default_log_level")]
    pub level: String,

    /// Whether to use JSON format.
    #[serde(default)]
    pub json_format: bool,

    /// Log file path (if not stdout).
    #[serde(default)]
    pub file_path: Option<String>,
}

fn default_log_level() -> String {
    "info".to_string()
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            json_format: false,
            file_path: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AppConfig::default();
        assert_eq!(config.operation_mode, "supervised");
        assert_eq!(config.max_concurrent_incidents, 50);
    }

    #[test]
    fn test_redact_secrets() {
        let mut config = AppConfig::default();
        config.llm.api_key = "secret-key".to_string();
        config.connectors.insert(
            "test".to_string(),
            ConnectorConfig {
                connector_type: "test".to_string(),
                base_url: "https://api.example.com".to_string(),
                enabled: true,
                api_key: "connector-secret".to_string(),
                api_secret: String::new(),
                timeout_secs: 30,
                settings: HashMap::new(),
            },
        );

        let redacted = config.redact_secrets();
        assert_eq!(redacted.llm.api_key, "***REDACTED***");
        assert_eq!(
            redacted.connectors.get("test").unwrap().api_key,
            "***REDACTED***"
        );
    }

    #[test]
    fn test_parse_yaml() {
        let yaml = r#"
operation_mode: autonomous
max_concurrent_incidents: 100

connectors:
  jira:
    connector_type: jira
    base_url: https://company.atlassian.net
    api_key: ${JIRA_API_KEY}
    settings:
      project_key: SEC

llm:
  provider: anthropic
  model: claude-3-sonnet
  api_key: ${ANTHROPIC_API_KEY}
"#;

        let config: AppConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.operation_mode, "autonomous");
        assert_eq!(config.max_concurrent_incidents, 100);
        assert!(config.connectors.contains_key("jira"));
        assert_eq!(config.llm.provider, "anthropic");
    }
}
