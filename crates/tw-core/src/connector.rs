//! Connector configuration data models for Triage Warden.
//!
//! This module defines the data structures used to store and manage
//! connector configurations for external integrations (VirusTotal, Jira, etc.).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
