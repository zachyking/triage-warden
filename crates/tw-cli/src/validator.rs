//! Configuration validation for Triage Warden.
//!
//! This module provides comprehensive startup validation to ensure all required
//! configuration is present and valid before the server starts.

use crate::config::AppConfig;
use colored::Colorize;
use std::path::Path;
use tw_core::is_production_environment;

/// Result of configuration validation.
#[derive(Debug, Default)]
pub struct ValidationResult {
    /// Critical errors that prevent startup.
    pub errors: Vec<String>,
    /// Warnings that should be addressed but don't prevent startup.
    pub warnings: Vec<String>,
}

impl ValidationResult {
    /// Creates a new empty validation result.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an error to the result.
    pub fn add_error(&mut self, message: impl Into<String>) {
        self.errors.push(message.into());
    }

    /// Adds a warning to the result.
    pub fn add_warning(&mut self, message: impl Into<String>) {
        self.warnings.push(message.into());
    }

    /// Returns true if there are any errors.
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    /// Returns true if there are any warnings.
    pub fn has_warnings(&self) -> bool {
        !self.warnings.is_empty()
    }

    /// Prints the validation result to the console.
    pub fn print(&self) {
        if !self.warnings.is_empty() {
            println!();
            println!("{}", "Configuration Warnings:".yellow().bold());
            for warning in &self.warnings {
                println!("  {} {}", "⚠".yellow(), warning);
            }
        }

        if !self.errors.is_empty() {
            println!();
            println!("{}", "Configuration Errors:".red().bold());
            for error in &self.errors {
                println!("  {} {}", "✗".red(), error);
            }
        }

        if self.errors.is_empty() && self.warnings.is_empty() {
            println!("  {} Configuration OK", "✓".green());
        }
    }
}

/// Validates application configuration before startup.
pub struct ConfigValidator;

impl ConfigValidator {
    /// Validates the application configuration.
    ///
    /// Returns a ValidationResult containing any errors and warnings found.
    pub fn validate(config: &AppConfig) -> ValidationResult {
        let mut result = ValidationResult::new();

        // Validate guardrails file
        Self::validate_guardrails(config, &mut result);

        // Validate encryption key
        Self::validate_encryption_key(&mut result);

        // Validate LLM configuration
        Self::validate_llm_config(config, &mut result);

        // Validate connectors
        Self::validate_connectors(config, &mut result);

        // Validate operation mode
        Self::validate_operation_mode(config, &mut result);

        // Validate database URL
        Self::validate_database_url(config, &mut result);

        result
    }

    /// Validates the guardrails configuration file exists and is valid.
    fn validate_guardrails(config: &AppConfig, result: &mut ValidationResult) {
        let guardrails_path = Path::new(&config.policy.guardrails_path);

        if !guardrails_path.exists() {
            result.add_warning(format!(
                "Guardrails file not found: {}. Using default policy rules. \
                 Create this file to customize approval policies and rate limits.",
                config.policy.guardrails_path
            ));
            return;
        }

        // Try to read and parse the file
        match std::fs::read_to_string(guardrails_path) {
            Ok(contents) => {
                // Try to parse as YAML
                if let Err(e) = serde_yaml::from_str::<serde_yaml::Value>(&contents) {
                    result.add_error(format!(
                        "Failed to parse guardrails file '{}': {}",
                        config.policy.guardrails_path, e
                    ));
                }
            }
            Err(e) => {
                result.add_error(format!(
                    "Failed to read guardrails file '{}': {}",
                    config.policy.guardrails_path, e
                ));
            }
        }
    }

    /// Validates the encryption key environment variable.
    fn validate_encryption_key(result: &mut ValidationResult) {
        match std::env::var("TW_ENCRYPTION_KEY") {
            Ok(key) => {
                // Validate it's valid base64 and correct length
                match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &key) {
                    Ok(bytes) => {
                        if bytes.len() != 32 {
                            result.add_error(format!(
                                "TW_ENCRYPTION_KEY must be 32 bytes (256 bits), got {} bytes. \
                                 Generate a valid key with: openssl rand -base64 32",
                                bytes.len()
                            ));
                        }
                    }
                    Err(_) => {
                        result.add_error(
                            "TW_ENCRYPTION_KEY is not valid base64. \
                             Generate a valid key with: openssl rand -base64 32"
                                .to_string(),
                        );
                    }
                }
            }
            Err(_) => {
                // Check if we're in production mode
                if is_production_environment() {
                    result.add_error(
                        "Missing required config: TW_ENCRYPTION_KEY. \
                         Set this environment variable with a 32-byte base64-encoded key \
                         for encrypting sensitive data. Generate with: openssl rand -base64 32"
                            .to_string(),
                    );
                } else {
                    result.add_warning(
                        "TW_ENCRYPTION_KEY not set. Credentials will be stored in PLAINTEXT. \
                         This is acceptable for development but MUST be set for production. \
                         Generate a key with: openssl rand -base64 32"
                            .to_string(),
                    );
                }
            }
        }
    }

    /// Validates LLM configuration.
    fn validate_llm_config(config: &AppConfig, result: &mut ValidationResult) {
        let llm = &config.llm;

        // Check if provider requires an API key
        let requires_api_key = matches!(
            llm.provider.to_lowercase().as_str(),
            "openai" | "anthropic" | "azure"
        );

        if requires_api_key && llm.api_key.is_empty() {
            // Check for provider-specific env vars
            let env_var = match llm.provider.to_lowercase().as_str() {
                "openai" => "OPENAI_API_KEY",
                "anthropic" => "ANTHROPIC_API_KEY",
                "azure" => "AZURE_OPENAI_API_KEY",
                _ => "LLM_API_KEY",
            };

            if std::env::var(env_var).is_err() {
                result.add_warning(format!(
                    "LLM API key not configured. Set llm.api_key in config or {} env var. \
                     AI-powered triage features will not work without this.",
                    env_var
                ));
            }
        }

        // Validate local provider has base_url
        if llm.provider.to_lowercase() == "local" && llm.base_url.is_empty() {
            result.add_error(
                "Local LLM provider requires base_url to be set (e.g., http://localhost:11434)"
                    .to_string(),
            );
        }

        // Validate temperature range
        if !(0.0..=2.0).contains(&llm.temperature) {
            result.add_warning(format!(
                "LLM temperature {} is outside typical range (0.0 - 2.0). \
                 Lower values (0.1-0.3) are recommended for consistent triage decisions.",
                llm.temperature
            ));
        }
    }

    /// Validates connector configurations.
    fn validate_connectors(config: &AppConfig, result: &mut ValidationResult) {
        for (name, connector) in &config.connectors {
            if !connector.enabled {
                continue;
            }

            // Validate required fields based on connector type
            match connector.connector_type.to_lowercase().as_str() {
                "virustotal" => {
                    if connector.api_key.is_empty() && std::env::var("VIRUSTOTAL_API_KEY").is_err()
                    {
                        result.add_warning(format!(
                            "Connector '{}': VirusTotal requires an API key. \
                             Set api_key in config or VIRUSTOTAL_API_KEY env var.",
                            name
                        ));
                    }
                }
                "jira" => {
                    if connector.base_url.is_empty() {
                        result.add_error(format!(
                            "Connector '{}': Jira requires base_url (e.g., https://company.atlassian.net)",
                            name
                        ));
                    }
                    if connector.api_key.is_empty() && connector.api_secret.is_empty() {
                        result.add_warning(format!(
                            "Connector '{}': Jira requires API credentials. \
                             Set api_key (email) and api_secret (API token).",
                            name
                        ));
                    }
                }
                "splunk" => {
                    if connector.base_url.is_empty() {
                        result.add_error(format!("Connector '{}': Splunk requires base_url", name));
                    }
                    if connector.api_key.is_empty() {
                        result.add_warning(format!(
                            "Connector '{}': Splunk requires an API token (api_key)",
                            name
                        ));
                    }
                }
                "crowdstrike" => {
                    if connector.api_key.is_empty() || connector.api_secret.is_empty() {
                        result.add_warning(format!(
                            "Connector '{}': CrowdStrike requires client_id (api_key) and client_secret (api_secret)",
                            name
                        ));
                    }
                }
                _ => {
                    // Generic connector - just check base_url
                    if connector.base_url.is_empty() {
                        result.add_warning(format!("Connector '{}': No base_url configured", name));
                    }
                }
            }
        }
    }

    /// Validates operation mode.
    fn validate_operation_mode(config: &AppConfig, result: &mut ValidationResult) {
        let valid_modes = ["assisted", "supervised", "autonomous"];
        if !valid_modes.contains(&config.operation_mode.to_lowercase().as_str()) {
            result.add_error(format!(
                "Invalid operation_mode '{}'. Must be one of: {}",
                config.operation_mode,
                valid_modes.join(", ")
            ));
        }

        if config.operation_mode.to_lowercase() == "autonomous" {
            result.add_warning(
                "Operating in AUTONOMOUS mode. The system will execute actions automatically \
                 without human approval. Ensure guardrails are properly configured."
                    .to_string(),
            );
        }
    }

    /// Validates database URL format.
    fn validate_database_url(config: &AppConfig, result: &mut ValidationResult) {
        let url = &config.database.url;

        if !url.starts_with("sqlite://")
            && !url.starts_with("postgres://")
            && !url.starts_with("postgresql://")
        {
            result.add_error(format!(
                "Invalid database URL '{}'. Must start with sqlite:// or postgres://",
                url
            ));
        }

        // Warn about SQLite in production
        if url.starts_with("sqlite://") && is_production_environment() {
            result.add_warning(
                "Using SQLite database in production is not recommended. \
                 Consider using PostgreSQL for better performance and reliability."
                    .to_string(),
            );
        }
    }
}

// Note: is_production_environment() is imported from tw_core

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ConnectorConfig;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// Mutex to serialize tests that modify environment variables.
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    fn default_config() -> AppConfig {
        AppConfig::default()
    }

    #[test]
    fn test_validation_result_operations() {
        let mut result = ValidationResult::new();
        assert!(!result.has_errors());
        assert!(!result.has_warnings());

        result.add_error("Test error");
        assert!(result.has_errors());

        result.add_warning("Test warning");
        assert!(result.has_warnings());

        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.warnings.len(), 1);
    }

    #[test]
    fn test_valid_operation_modes() {
        for mode in &["assisted", "supervised", "autonomous"] {
            let mut config = default_config();
            config.operation_mode = mode.to_string();

            let mut result = ValidationResult::new();
            ConfigValidator::validate_operation_mode(&config, &mut result);

            assert!(!result.has_errors(), "Mode '{}' should be valid", mode);
        }
    }

    #[test]
    fn test_invalid_operation_mode() {
        let mut config = default_config();
        config.operation_mode = "invalid".to_string();

        let mut result = ValidationResult::new();
        ConfigValidator::validate_operation_mode(&config, &mut result);

        assert!(result.has_errors());
    }

    #[test]
    fn test_autonomous_mode_warning() {
        let mut config = default_config();
        config.operation_mode = "autonomous".to_string();

        let mut result = ValidationResult::new();
        ConfigValidator::validate_operation_mode(&config, &mut result);

        assert!(result.has_warnings());
        assert!(result.warnings[0].contains("AUTONOMOUS"));
    }

    #[test]
    fn test_invalid_database_url() {
        let mut config = default_config();
        config.database.url = "mysql://localhost/db".to_string();

        let mut result = ValidationResult::new();
        ConfigValidator::validate_database_url(&config, &mut result);

        assert!(result.has_errors());
    }

    #[test]
    fn test_valid_database_urls() {
        for url in &[
            "sqlite://test.db",
            "postgres://localhost/db",
            "postgresql://localhost/db",
        ] {
            let mut config = default_config();
            config.database.url = url.to_string();

            let mut result = ValidationResult::new();
            ConfigValidator::validate_database_url(&config, &mut result);

            assert!(!result.has_errors(), "URL '{}' should be valid", url);
        }
    }

    #[test]
    fn test_local_llm_requires_base_url() {
        let mut config = default_config();
        config.llm.provider = "local".to_string();
        config.llm.base_url = String::new();

        let mut result = ValidationResult::new();
        ConfigValidator::validate_llm_config(&config, &mut result);

        assert!(result.has_errors());
    }

    #[test]
    fn test_jira_connector_requires_base_url() {
        let mut config = default_config();
        config.connectors.insert(
            "jira".to_string(),
            ConnectorConfig {
                connector_type: "jira".to_string(),
                base_url: String::new(),
                enabled: true,
                api_key: "test".to_string(),
                api_secret: "test".to_string(),
                timeout_secs: 30,
                settings: HashMap::new(),
            },
        );

        let mut result = ValidationResult::new();
        ConfigValidator::validate_connectors(&config, &mut result);

        assert!(result.has_errors());
    }

    #[test]
    fn test_disabled_connector_not_validated() {
        let mut config = default_config();
        config.connectors.insert(
            "jira".to_string(),
            ConnectorConfig {
                connector_type: "jira".to_string(),
                base_url: String::new(), // Invalid but disabled
                enabled: false,
                api_key: String::new(),
                api_secret: String::new(),
                timeout_secs: 30,
                settings: HashMap::new(),
            },
        );

        let mut result = ValidationResult::new();
        ConfigValidator::validate_connectors(&config, &mut result);

        assert!(!result.has_errors());
    }

    #[test]
    fn test_temperature_warning() {
        let mut config = default_config();
        config.llm.temperature = 3.0; // Out of range

        let mut result = ValidationResult::new();
        ConfigValidator::validate_llm_config(&config, &mut result);

        assert!(result.has_warnings());
    }

    #[test]
    fn test_valid_temperature_no_warning() {
        let mut config = default_config();
        config.llm.temperature = 0.1;

        let mut result = ValidationResult::new();
        ConfigValidator::validate_llm_config(&config, &mut result);

        // Should not have temperature-related warnings (may have API key warnings)
        let temp_warnings: Vec<_> = result
            .warnings
            .iter()
            .filter(|w| w.contains("temperature"))
            .collect();
        assert!(temp_warnings.is_empty());
    }

    #[test]
    fn test_splunk_connector_requires_base_url() {
        let mut config = default_config();
        config.connectors.insert(
            "splunk".to_string(),
            ConnectorConfig {
                connector_type: "splunk".to_string(),
                base_url: String::new(),
                enabled: true,
                api_key: "token".to_string(),
                api_secret: String::new(),
                timeout_secs: 30,
                settings: HashMap::new(),
            },
        );

        let mut result = ValidationResult::new();
        ConfigValidator::validate_connectors(&config, &mut result);

        assert!(result.has_errors());
        assert!(result.errors[0].contains("Splunk requires base_url"));
    }

    #[test]
    fn test_crowdstrike_connector_missing_credentials() {
        let mut config = default_config();
        config.connectors.insert(
            "cs".to_string(),
            ConnectorConfig {
                connector_type: "crowdstrike".to_string(),
                base_url: "https://api.crowdstrike.com".to_string(),
                enabled: true,
                api_key: String::new(),
                api_secret: String::new(),
                timeout_secs: 30,
                settings: HashMap::new(),
            },
        );

        let mut result = ValidationResult::new();
        ConfigValidator::validate_connectors(&config, &mut result);

        assert!(result.has_warnings());
        assert!(result.warnings[0].contains("CrowdStrike"));
    }

    #[test]
    fn test_generic_connector_missing_base_url() {
        let mut config = default_config();
        config.connectors.insert(
            "custom".to_string(),
            ConnectorConfig {
                connector_type: "custom_tool".to_string(),
                base_url: String::new(),
                enabled: true,
                api_key: String::new(),
                api_secret: String::new(),
                timeout_secs: 30,
                settings: HashMap::new(),
            },
        );

        let mut result = ValidationResult::new();
        ConfigValidator::validate_connectors(&config, &mut result);

        assert!(result.has_warnings());
        assert!(result.warnings[0].contains("No base_url configured"));
    }

    #[test]
    fn test_local_llm_with_base_url_no_error() {
        let mut config = default_config();
        config.llm.provider = "local".to_string();
        config.llm.base_url = "http://localhost:11434".to_string();

        let mut result = ValidationResult::new();
        ConfigValidator::validate_llm_config(&config, &mut result);

        assert!(!result.has_errors());
    }

    #[test]
    fn test_validation_result_print_does_not_panic() {
        let mut result = ValidationResult::new();
        result.add_error("test error");
        result.add_warning("test warning");
        // Should not panic
        result.print();
    }

    #[test]
    fn test_validation_result_empty_print_does_not_panic() {
        let result = ValidationResult::new();
        result.print();
    }

    #[test]
    fn test_full_validate_with_default_config() {
        let _lock = ENV_MUTEX.lock().unwrap();
        // Set TW_ENV to non-production so encryption key is not required
        std::env::set_var("TW_ENV", "development");
        let config = default_config();
        let result = ConfigValidator::validate(&config);
        std::env::remove_var("TW_ENV");
        // Default config should produce no errors in dev mode (may produce warnings)
        assert!(!result.has_errors());
    }

    #[test]
    fn test_validate_multiple_connectors() {
        let mut config = default_config();
        config.connectors.insert(
            "jira".to_string(),
            ConnectorConfig {
                connector_type: "jira".to_string(),
                base_url: "https://company.atlassian.net".to_string(),
                enabled: true,
                api_key: "email@company.com".to_string(),
                api_secret: "api-token".to_string(),
                timeout_secs: 30,
                settings: HashMap::new(),
            },
        );
        config.connectors.insert(
            "vt".to_string(),
            ConnectorConfig {
                connector_type: "virustotal".to_string(),
                base_url: "https://www.virustotal.com".to_string(),
                enabled: true,
                api_key: "vt-key".to_string(),
                api_secret: String::new(),
                timeout_secs: 30,
                settings: HashMap::new(),
            },
        );

        let mut result = ValidationResult::new();
        ConfigValidator::validate_connectors(&config, &mut result);

        // Both have credentials, should have no errors/warnings about them
        assert!(!result.has_errors());
    }

    #[test]
    fn test_negative_temperature_warning() {
        let mut config = default_config();
        config.llm.temperature = -0.5;

        let mut result = ValidationResult::new();
        ConfigValidator::validate_llm_config(&config, &mut result);

        let temp_warnings: Vec<_> = result
            .warnings
            .iter()
            .filter(|w| w.contains("temperature"))
            .collect();
        assert!(!temp_warnings.is_empty());
    }
}
