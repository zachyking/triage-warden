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

    /// Database configuration.
    #[serde(default)]
    pub database: DatabaseConfig,

    /// API server configuration.
    #[serde(default)]
    pub api: ApiConfig,
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
            database: DatabaseConfig::default(),
            api: ApiConfig::default(),
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

/// Database configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// Database URL (sqlite:// or postgres://).
    #[serde(default = "default_database_url")]
    pub url: String,

    /// Maximum connections in pool.
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,

    /// Run migrations on startup.
    #[serde(default = "default_true")]
    pub run_migrations: bool,
}

fn default_database_url() -> String {
    "sqlite://triage-warden.db?mode=rwc".to_string()
}

fn default_max_connections() -> u32 {
    10
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: default_database_url(),
            max_connections: default_max_connections(),
            run_migrations: true,
        }
    }
}

/// API server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    /// Port to listen on.
    #[serde(default = "default_port")]
    pub port: u16,

    /// Host to bind to.
    #[serde(default = "default_host")]
    pub host: String,

    /// Enable Swagger UI.
    #[serde(default = "default_true")]
    pub enable_swagger: bool,

    /// Request timeout in seconds.
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_port() -> u16 {
    8080
}

fn default_host() -> String {
    "0.0.0.0".to_string()
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            port: default_port(),
            host: default_host(),
            enable_swagger: true,
            timeout_secs: default_timeout(),
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

    #[test]
    fn test_default_config_all_fields() {
        let config = AppConfig::default();
        assert_eq!(config.operation_mode, "supervised");
        assert_eq!(config.max_concurrent_incidents, 50);
        assert!(config.connectors.is_empty());
        assert_eq!(config.llm.provider, "openai");
        assert_eq!(config.llm.model, "gpt-4-turbo");
        assert!(config.llm.api_key.is_empty());
        assert_eq!(config.llm.max_tokens, 4096);
        assert!((config.llm.temperature - 0.1).abs() < f32::EPSILON);
        assert_eq!(config.policy.guardrails_path, "config/guardrails.yaml");
        assert_eq!(config.policy.default_approval_level, "analyst");
        assert!(!config.policy.auto_approve_low_risk);
        assert!((config.policy.confidence_threshold - 0.9).abs() < f64::EPSILON);
        assert_eq!(config.logging.level, "info");
        assert!(!config.logging.json_format);
        assert!(config.logging.file_path.is_none());
        assert_eq!(config.database.url, "sqlite://triage-warden.db?mode=rwc");
        assert_eq!(config.database.max_connections, 10);
        assert!(config.database.run_migrations);
        assert_eq!(config.api.port, 8080);
        assert_eq!(config.api.host, "0.0.0.0");
        assert!(config.api.enable_swagger);
        assert_eq!(config.api.timeout_secs, 30);
    }

    #[test]
    fn test_load_nonexistent_file() {
        let result = AppConfig::load(std::path::Path::new("/nonexistent/config.yaml"));
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Failed to read config file"));
    }

    #[test]
    fn test_load_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test-config.yaml");
        std::fs::write(
            &file_path,
            "operation_mode: autonomous\nmax_concurrent_incidents: 200\n",
        )
        .unwrap();

        let config = AppConfig::load(&file_path).unwrap();
        assert_eq!(config.operation_mode, "autonomous");
        assert_eq!(config.max_concurrent_incidents, 200);
    }

    #[test]
    fn test_load_invalid_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("bad.yaml");
        std::fs::write(&file_path, "{{{{not valid yaml").unwrap();

        let result = AppConfig::load(&file_path);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Failed to parse config file"));
    }

    #[test]
    fn test_redact_secrets_empty_keys_not_redacted() {
        let mut config = AppConfig::default();
        config.llm.api_key = String::new();
        config.connectors.insert(
            "vt".to_string(),
            ConnectorConfig {
                connector_type: "virustotal".to_string(),
                base_url: "https://api.virustotal.com".to_string(),
                enabled: true,
                api_key: String::new(),
                api_secret: String::new(),
                timeout_secs: 30,
                settings: HashMap::new(),
            },
        );

        let redacted = config.redact_secrets();
        // Empty keys should stay empty, not be replaced with REDACTED
        assert!(redacted.llm.api_key.is_empty());
        assert!(redacted.connectors.get("vt").unwrap().api_key.is_empty());
        assert!(redacted.connectors.get("vt").unwrap().api_secret.is_empty());
    }

    #[test]
    fn test_redact_secrets_both_api_key_and_secret() {
        let mut config = AppConfig::default();
        config.connectors.insert(
            "cs".to_string(),
            ConnectorConfig {
                connector_type: "crowdstrike".to_string(),
                base_url: "https://api.crowdstrike.com".to_string(),
                enabled: true,
                api_key: "client-id".to_string(),
                api_secret: "client-secret".to_string(),
                timeout_secs: 30,
                settings: HashMap::new(),
            },
        );

        let redacted = config.redact_secrets();
        let cs = redacted.connectors.get("cs").unwrap();
        assert_eq!(cs.api_key, "***REDACTED***");
        assert_eq!(cs.api_secret, "***REDACTED***");
        // Base URL should NOT be redacted
        assert_eq!(cs.base_url, "https://api.crowdstrike.com");
    }

    #[test]
    fn test_parse_yaml_with_all_sections() {
        let yaml = r#"
operation_mode: assisted
max_concurrent_incidents: 10

llm:
  provider: local
  model: llama2
  base_url: http://localhost:11434
  max_tokens: 2048
  temperature: 0.3

policy:
  guardrails_path: /etc/tw/guardrails.yaml
  default_approval_level: manager
  auto_approve_low_risk: true
  confidence_threshold: 0.8

logging:
  level: debug
  json_format: true
  file_path: /var/log/tw/app.log

database:
  url: postgres://localhost/triage
  max_connections: 20
  run_migrations: false

api:
  port: 9090
  host: 127.0.0.1
  enable_swagger: false
  timeout_secs: 60
"#;

        let config: AppConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.operation_mode, "assisted");
        assert_eq!(config.max_concurrent_incidents, 10);
        assert_eq!(config.llm.provider, "local");
        assert_eq!(config.llm.model, "llama2");
        assert_eq!(config.llm.base_url, "http://localhost:11434");
        assert_eq!(config.llm.max_tokens, 2048);
        assert!((config.llm.temperature - 0.3).abs() < f32::EPSILON);
        assert_eq!(config.policy.guardrails_path, "/etc/tw/guardrails.yaml");
        assert_eq!(config.policy.default_approval_level, "manager");
        assert!(config.policy.auto_approve_low_risk);
        assert!((config.policy.confidence_threshold - 0.8).abs() < f64::EPSILON);
        assert_eq!(config.logging.level, "debug");
        assert!(config.logging.json_format);
        assert_eq!(
            config.logging.file_path.as_deref(),
            Some("/var/log/tw/app.log")
        );
        assert_eq!(config.database.url, "postgres://localhost/triage");
        assert_eq!(config.database.max_connections, 20);
        assert!(!config.database.run_migrations);
        assert_eq!(config.api.port, 9090);
        assert_eq!(config.api.host, "127.0.0.1");
        assert!(!config.api.enable_swagger);
        assert_eq!(config.api.timeout_secs, 60);
    }

    #[test]
    fn test_connector_config_defaults() {
        let yaml = r#"
connectors:
  test:
    connector_type: generic
"#;
        let config: AppConfig = serde_yaml::from_str(yaml).unwrap();
        let test_conn = config.connectors.get("test").unwrap();
        assert!(test_conn.enabled); // default_true
        assert!(test_conn.base_url.is_empty());
        assert!(test_conn.api_key.is_empty());
        assert!(test_conn.api_secret.is_empty());
        assert_eq!(test_conn.timeout_secs, 30); // default_timeout
        assert!(test_conn.settings.is_empty());
    }
}
