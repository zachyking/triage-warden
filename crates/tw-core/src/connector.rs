//! Connector configuration data models for Triage Warden.
//!
//! This module defines the data structures used to store and manage
//! connector configurations for external integrations (VirusTotal, Jira, etc.).
//!
//! # Credential Encryption
//!
//! Sensitive fields in connector configurations (api_key, password, client_secret, token)
//! are encrypted before storage using AES-256-GCM. The encryption key must be configured
//! via the `TW_ENCRYPTION_KEY` environment variable.

use crate::crypto::{CredentialEncryptor, CryptoError};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

/// Fields in connector configs that contain sensitive credentials and should be encrypted.
const SENSITIVE_FIELDS: &[&str] = &[
    "api_key",
    "password",
    "client_secret",
    "token",
    "secret",
    "private_key",
    "access_token",
    "refresh_token",
    "bearer_token",
    "auth_token",
    "credentials",
];

/// Types of connectors supported by Triage Warden.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorType {
    /// VirusTotal threat intelligence integration.
    VirusTotal,
    /// Jira ticketing system integration.
    Jira,
    /// Splunk SIEM integration.
    Splunk,
    /// CrowdStrike EDR integration.
    CrowdStrike,
    /// Microsoft Defender integration.
    Defender,
    /// Microsoft 365 integration.
    M365,
    /// Google Workspace integration.
    GoogleWorkspace,
    /// Generic/custom connector.
    Generic,
}

impl ConnectorType {
    /// Returns the database-compatible string representation (snake_case).
    pub fn as_db_str(&self) -> &'static str {
        match self {
            ConnectorType::VirusTotal => "virus_total",
            ConnectorType::Jira => "jira",
            ConnectorType::Splunk => "splunk",
            ConnectorType::CrowdStrike => "crowd_strike",
            ConnectorType::Defender => "defender",
            ConnectorType::M365 => "m365",
            ConnectorType::GoogleWorkspace => "google_workspace",
            ConnectorType::Generic => "generic",
        }
    }

    /// Parses a connector type from a database string.
    pub fn from_db_str(s: &str) -> Option<Self> {
        match s {
            "virus_total" => Some(ConnectorType::VirusTotal),
            "jira" => Some(ConnectorType::Jira),
            "splunk" => Some(ConnectorType::Splunk),
            "crowd_strike" => Some(ConnectorType::CrowdStrike),
            "defender" => Some(ConnectorType::Defender),
            "m365" => Some(ConnectorType::M365),
            "google_workspace" => Some(ConnectorType::GoogleWorkspace),
            "generic" => Some(ConnectorType::Generic),
            _ => None,
        }
    }
}

impl std::fmt::Display for ConnectorType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectorType::VirusTotal => write!(f, "VirusTotal"),
            ConnectorType::Jira => write!(f, "Jira"),
            ConnectorType::Splunk => write!(f, "Splunk"),
            ConnectorType::CrowdStrike => write!(f, "CrowdStrike"),
            ConnectorType::Defender => write!(f, "Defender"),
            ConnectorType::M365 => write!(f, "M365"),
            ConnectorType::GoogleWorkspace => write!(f, "Google Workspace"),
            ConnectorType::Generic => write!(f, "Generic"),
        }
    }
}

/// Status of a connector's connection state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorStatus {
    /// Connector is connected and operational.
    Connected,
    /// Connector is disconnected.
    Disconnected,
    /// Connector encountered an error.
    Error,
    /// Connector status is unknown.
    Unknown,
}

impl ConnectorStatus {
    /// Returns the database-compatible string representation (snake_case).
    pub fn as_db_str(&self) -> &'static str {
        match self {
            ConnectorStatus::Connected => "connected",
            ConnectorStatus::Disconnected => "disconnected",
            ConnectorStatus::Error => "error",
            ConnectorStatus::Unknown => "unknown",
        }
    }

    /// Parses a connector status from a database string.
    pub fn from_db_str(s: &str) -> Option<Self> {
        match s {
            "connected" => Some(ConnectorStatus::Connected),
            "disconnected" => Some(ConnectorStatus::Disconnected),
            "error" => Some(ConnectorStatus::Error),
            "unknown" => Some(ConnectorStatus::Unknown),
            _ => None,
        }
    }
}

impl std::fmt::Display for ConnectorStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectorStatus::Connected => write!(f, "Connected"),
            ConnectorStatus::Disconnected => write!(f, "Disconnected"),
            ConnectorStatus::Error => write!(f, "Error"),
            ConnectorStatus::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Configuration for a connector integration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorConfig {
    /// Unique identifier for this connector configuration.
    pub id: Uuid,
    /// Human-readable name for this connector.
    pub name: String,
    /// Type of connector.
    pub connector_type: ConnectorType,
    /// Connector-specific configuration (api_key, base_url, etc.).
    pub config: serde_json::Value,
    /// Current connection status.
    pub status: ConnectorStatus,
    /// Whether the connector is enabled.
    pub enabled: bool,
    /// Timestamp of the last health check.
    pub last_health_check: Option<DateTime<Utc>>,
    /// Timestamp when the connector was created.
    pub created_at: DateTime<Utc>,
    /// Timestamp of the last update.
    pub updated_at: DateTime<Utc>,
}

impl ConnectorConfig {
    /// Creates a new connector configuration.
    pub fn new(name: String, connector_type: ConnectorType, config: serde_json::Value) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            name,
            connector_type,
            config,
            status: ConnectorStatus::Unknown,
            enabled: true,
            last_health_check: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Updates the connector status.
    pub fn set_status(&mut self, status: ConnectorStatus) {
        self.status = status;
        self.updated_at = Utc::now();
    }

    /// Updates the last health check timestamp.
    pub fn record_health_check(&mut self) {
        self.last_health_check = Some(Utc::now());
        self.updated_at = Utc::now();
    }

    /// Enables or disables the connector.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        self.updated_at = Utc::now();
    }

    /// Encrypts sensitive fields in the config before storage.
    ///
    /// This method traverses the config JSON object and encrypts any fields
    /// whose names match the SENSITIVE_FIELDS list. Encrypted values are
    /// prefixed with "encrypted:" to distinguish them from plaintext values.
    ///
    /// # Arguments
    ///
    /// * `encryptor` - The credential encryptor to use for encryption
    ///
    /// # Returns
    ///
    /// A new ConnectorConfig with encrypted sensitive fields, or an error if encryption fails.
    pub fn encrypt_credentials(
        &self,
        encryptor: &Arc<dyn CredentialEncryptor>,
    ) -> Result<Self, CryptoError> {
        let encrypted_config = encrypt_sensitive_fields(&self.config, encryptor)?;
        Ok(Self {
            config: encrypted_config,
            ..self.clone()
        })
    }

    /// Decrypts sensitive fields in the config after retrieval from storage.
    ///
    /// This method traverses the config JSON object and decrypts any fields
    /// that have the "encrypted:" prefix.
    ///
    /// # Arguments
    ///
    /// * `encryptor` - The credential encryptor to use for decryption
    ///
    /// # Returns
    ///
    /// A new ConnectorConfig with decrypted sensitive fields, or an error if decryption fails.
    pub fn decrypt_credentials(
        &self,
        encryptor: &Arc<dyn CredentialEncryptor>,
    ) -> Result<Self, CryptoError> {
        let decrypted_config = decrypt_sensitive_fields(&self.config, encryptor)?;
        Ok(Self {
            config: decrypted_config,
            ..self.clone()
        })
    }

    /// Returns true if the config contains any encrypted fields.
    pub fn has_encrypted_fields(&self) -> bool {
        has_encrypted_prefix(&self.config)
    }

    /// Returns a redacted version of the config suitable for logging/display.
    ///
    /// Sensitive fields are replaced with "[REDACTED]" to prevent accidental
    /// exposure of credentials in logs or API responses.
    pub fn redacted_config(&self) -> serde_json::Value {
        redact_sensitive_fields(&self.config)
    }
}

/// Prefix used to identify encrypted values in the config.
const ENCRYPTED_PREFIX: &str = "encrypted:";

/// Encrypts sensitive fields in a JSON value recursively.
fn encrypt_sensitive_fields(
    value: &serde_json::Value,
    encryptor: &Arc<dyn CredentialEncryptor>,
) -> Result<serde_json::Value, CryptoError> {
    match value {
        serde_json::Value::Object(map) => {
            let mut new_map = serde_json::Map::new();
            for (key, val) in map {
                let new_val = if is_sensitive_field(key) {
                    // Encrypt string values of sensitive fields
                    if let Some(s) = val.as_str() {
                        // Don't double-encrypt already encrypted values
                        if s.starts_with(ENCRYPTED_PREFIX) {
                            val.clone()
                        } else {
                            let encrypted = encryptor.encrypt(s)?;
                            serde_json::Value::String(format!("{}{}", ENCRYPTED_PREFIX, encrypted))
                        }
                    } else {
                        // Non-string values in sensitive fields - recursively process
                        encrypt_sensitive_fields(val, encryptor)?
                    }
                } else {
                    // Recursively process nested objects
                    encrypt_sensitive_fields(val, encryptor)?
                };
                new_map.insert(key.clone(), new_val);
            }
            Ok(serde_json::Value::Object(new_map))
        }
        serde_json::Value::Array(arr) => {
            let new_arr: Result<Vec<_>, _> = arr
                .iter()
                .map(|v| encrypt_sensitive_fields(v, encryptor))
                .collect();
            Ok(serde_json::Value::Array(new_arr?))
        }
        // Other value types pass through unchanged
        _ => Ok(value.clone()),
    }
}

/// Decrypts sensitive fields in a JSON value recursively.
fn decrypt_sensitive_fields(
    value: &serde_json::Value,
    encryptor: &Arc<dyn CredentialEncryptor>,
) -> Result<serde_json::Value, CryptoError> {
    match value {
        serde_json::Value::Object(map) => {
            let mut new_map = serde_json::Map::new();
            for (key, val) in map {
                let new_val = if let Some(s) = val.as_str() {
                    // Decrypt values with encrypted prefix
                    if let Some(encrypted) = s.strip_prefix(ENCRYPTED_PREFIX) {
                        let decrypted = encryptor.decrypt(encrypted)?;
                        serde_json::Value::String(decrypted)
                    } else {
                        val.clone()
                    }
                } else {
                    // Recursively process nested objects/arrays
                    decrypt_sensitive_fields(val, encryptor)?
                };
                new_map.insert(key.clone(), new_val);
            }
            Ok(serde_json::Value::Object(new_map))
        }
        serde_json::Value::Array(arr) => {
            let new_arr: Result<Vec<_>, _> = arr
                .iter()
                .map(|v| decrypt_sensitive_fields(v, encryptor))
                .collect();
            Ok(serde_json::Value::Array(new_arr?))
        }
        // Other value types pass through unchanged
        _ => Ok(value.clone()),
    }
}

/// Checks if a field name is in the sensitive fields list.
fn is_sensitive_field(name: &str) -> bool {
    let name_lower = name.to_lowercase();
    SENSITIVE_FIELDS.iter().any(|&s| name_lower.contains(s))
}

/// Checks if a JSON value contains any encrypted fields.
fn has_encrypted_prefix(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(s) => s.starts_with(ENCRYPTED_PREFIX),
        serde_json::Value::Object(map) => map.values().any(has_encrypted_prefix),
        serde_json::Value::Array(arr) => arr.iter().any(has_encrypted_prefix),
        _ => false,
    }
}

/// Redacts sensitive fields in a JSON value for safe logging/display.
fn redact_sensitive_fields(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut new_map = serde_json::Map::new();
            for (key, val) in map {
                let new_val = if is_sensitive_field(key) {
                    serde_json::Value::String("[REDACTED]".to_string())
                } else {
                    redact_sensitive_fields(val)
                };
                new_map.insert(key.clone(), new_val);
            }
            serde_json::Value::Object(new_map)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(redact_sensitive_fields).collect())
        }
        // Check if string value looks like it might be a credential (has encrypted prefix)
        serde_json::Value::String(s) if s.starts_with(ENCRYPTED_PREFIX) => {
            serde_json::Value::String("[ENCRYPTED]".to_string())
        }
        _ => value.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Aes256GcmEncryptor, PlaintextEncryptor};

    #[test]
    fn test_connector_type_db_str() {
        assert_eq!(ConnectorType::VirusTotal.as_db_str(), "virus_total");
        assert_eq!(ConnectorType::Jira.as_db_str(), "jira");
        assert_eq!(ConnectorType::CrowdStrike.as_db_str(), "crowd_strike");
        assert_eq!(ConnectorType::M365.as_db_str(), "m365");
    }

    #[test]
    fn test_connector_type_from_db_str() {
        assert_eq!(
            ConnectorType::from_db_str("virus_total"),
            Some(ConnectorType::VirusTotal)
        );
        assert_eq!(
            ConnectorType::from_db_str("jira"),
            Some(ConnectorType::Jira)
        );
        assert_eq!(ConnectorType::from_db_str("invalid"), None);
    }

    #[test]
    fn test_connector_status_db_str() {
        assert_eq!(ConnectorStatus::Connected.as_db_str(), "connected");
        assert_eq!(ConnectorStatus::Error.as_db_str(), "error");
    }

    #[test]
    fn test_connector_status_from_db_str() {
        assert_eq!(
            ConnectorStatus::from_db_str("connected"),
            Some(ConnectorStatus::Connected)
        );
        assert_eq!(
            ConnectorStatus::from_db_str("unknown"),
            Some(ConnectorStatus::Unknown)
        );
        assert_eq!(ConnectorStatus::from_db_str("invalid"), None);
    }

    #[test]
    fn test_connector_config_new() {
        let config = ConnectorConfig::new(
            "My VirusTotal".to_string(),
            ConnectorType::VirusTotal,
            serde_json::json!({"api_key": "test-key"}),
        );

        assert_eq!(config.name, "My VirusTotal");
        assert_eq!(config.connector_type, ConnectorType::VirusTotal);
        assert_eq!(config.status, ConnectorStatus::Unknown);
        assert!(config.enabled);
        assert!(config.last_health_check.is_none());
    }

    #[test]
    fn test_connector_config_set_status() {
        let mut config = ConnectorConfig::new(
            "Test".to_string(),
            ConnectorType::Jira,
            serde_json::json!({}),
        );
        let original_updated = config.updated_at;

        std::thread::sleep(std::time::Duration::from_millis(1));
        config.set_status(ConnectorStatus::Connected);

        assert_eq!(config.status, ConnectorStatus::Connected);
        assert!(config.updated_at > original_updated);
    }

    #[test]
    fn test_encrypt_decrypt_credentials() {
        let encryptor: Arc<dyn CredentialEncryptor> = Arc::new(Aes256GcmEncryptor::new([42u8; 32]));

        let config = ConnectorConfig::new(
            "Test Connector".to_string(),
            ConnectorType::VirusTotal,
            serde_json::json!({
                "api_key": "my-secret-key",
                "base_url": "https://api.virustotal.com",
                "password": "super-secret",
            }),
        );

        // Encrypt
        let encrypted = config.encrypt_credentials(&encryptor).unwrap();

        // Verify sensitive fields are encrypted
        let api_key = encrypted.config["api_key"].as_str().unwrap();
        assert!(api_key.starts_with("encrypted:"));
        assert!(!api_key.contains("my-secret-key"));

        let password = encrypted.config["password"].as_str().unwrap();
        assert!(password.starts_with("encrypted:"));
        assert!(!password.contains("super-secret"));

        // Verify non-sensitive fields are unchanged
        assert_eq!(encrypted.config["base_url"], "https://api.virustotal.com");

        // Decrypt
        let decrypted = encrypted.decrypt_credentials(&encryptor).unwrap();

        // Verify original values restored
        assert_eq!(decrypted.config["api_key"], "my-secret-key");
        assert_eq!(decrypted.config["password"], "super-secret");
        assert_eq!(decrypted.config["base_url"], "https://api.virustotal.com");
    }

    #[test]
    fn test_encrypt_nested_credentials() {
        let encryptor: Arc<dyn CredentialEncryptor> = Arc::new(Aes256GcmEncryptor::new([42u8; 32]));

        let config = ConnectorConfig::new(
            "Test OAuth".to_string(),
            ConnectorType::M365,
            serde_json::json!({
                "oauth": {
                    "client_id": "public-id",
                    "client_secret": "secret-value",
                    "token_url": "https://login.microsoft.com/token"
                },
                "api_key": "another-secret"
            }),
        );

        let encrypted = config.encrypt_credentials(&encryptor).unwrap();

        // client_secret should be encrypted
        let client_secret = encrypted.config["oauth"]["client_secret"].as_str().unwrap();
        assert!(client_secret.starts_with("encrypted:"));

        // client_id should NOT be encrypted (not in sensitive fields)
        assert_eq!(encrypted.config["oauth"]["client_id"], "public-id");

        // api_key should be encrypted
        let api_key = encrypted.config["api_key"].as_str().unwrap();
        assert!(api_key.starts_with("encrypted:"));

        // Decrypt and verify
        let decrypted = encrypted.decrypt_credentials(&encryptor).unwrap();
        assert_eq!(decrypted.config["oauth"]["client_secret"], "secret-value");
        assert_eq!(decrypted.config["api_key"], "another-secret");
    }

    #[test]
    fn test_has_encrypted_fields() {
        let config = ConnectorConfig::new(
            "Test".to_string(),
            ConnectorType::Generic,
            serde_json::json!({
                "api_key": "encrypted:abc123",
                "name": "test"
            }),
        );
        assert!(config.has_encrypted_fields());

        let config2 = ConnectorConfig::new(
            "Test".to_string(),
            ConnectorType::Generic,
            serde_json::json!({
                "api_key": "plaintext-key",
                "name": "test"
            }),
        );
        assert!(!config2.has_encrypted_fields());
    }

    #[test]
    fn test_redacted_config() {
        let config = ConnectorConfig::new(
            "Test".to_string(),
            ConnectorType::Splunk,
            serde_json::json!({
                "api_key": "my-secret-api-key",
                "password": "my-password",
                "base_url": "https://splunk.example.com",
                "oauth": {
                    "client_id": "public-id",
                    "client_secret": "secret-value"
                }
            }),
        );

        let redacted = config.redacted_config();

        // Sensitive fields should be redacted
        assert_eq!(redacted["api_key"], "[REDACTED]");
        assert_eq!(redacted["password"], "[REDACTED]");
        assert_eq!(redacted["oauth"]["client_secret"], "[REDACTED]");

        // Non-sensitive fields should be preserved
        assert_eq!(redacted["base_url"], "https://splunk.example.com");
        assert_eq!(redacted["oauth"]["client_id"], "public-id");
    }

    #[test]
    fn test_no_double_encryption() {
        let encryptor: Arc<dyn CredentialEncryptor> = Arc::new(Aes256GcmEncryptor::new([42u8; 32]));

        let config = ConnectorConfig::new(
            "Test".to_string(),
            ConnectorType::VirusTotal,
            serde_json::json!({
                "api_key": "secret"
            }),
        );

        // Encrypt twice
        let encrypted1 = config.encrypt_credentials(&encryptor).unwrap();
        let encrypted2 = encrypted1.encrypt_credentials(&encryptor).unwrap();

        // Should be the same (no double encryption)
        assert_eq!(encrypted1.config["api_key"], encrypted2.config["api_key"]);

        // Should still decrypt correctly
        let decrypted = encrypted2.decrypt_credentials(&encryptor).unwrap();
        assert_eq!(decrypted.config["api_key"], "secret");
    }

    #[test]
    fn test_plaintext_encryptor_passthrough() {
        let encryptor: Arc<dyn CredentialEncryptor> = Arc::new(PlaintextEncryptor);

        let config = ConnectorConfig::new(
            "Test".to_string(),
            ConnectorType::Generic,
            serde_json::json!({
                "api_key": "my-key"
            }),
        );

        let encrypted = config.encrypt_credentials(&encryptor).unwrap();
        // With PlaintextEncryptor, value is "encrypted:" + plaintext
        assert!(encrypted.config["api_key"]
            .as_str()
            .unwrap()
            .starts_with("encrypted:"));

        let decrypted = encrypted.decrypt_credentials(&encryptor).unwrap();
        assert_eq!(decrypted.config["api_key"], "my-key");
    }

    #[test]
    fn test_is_sensitive_field() {
        assert!(is_sensitive_field("api_key"));
        assert!(is_sensitive_field("API_KEY"));
        assert!(is_sensitive_field("my_api_key_value"));
        assert!(is_sensitive_field("password"));
        assert!(is_sensitive_field("client_secret"));
        assert!(is_sensitive_field("bearer_token"));
        assert!(is_sensitive_field("access_token"));

        assert!(!is_sensitive_field("name"));
        assert!(!is_sensitive_field("base_url"));
        assert!(!is_sensitive_field("enabled"));
        assert!(!is_sensitive_field("timeout"));
    }
}
