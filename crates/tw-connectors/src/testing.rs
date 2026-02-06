//! Testing harness for connector implementations.
//!
//! Provides helper functions and utilities to simplify testing connectors.

use crate::traits::{AuthConfig, ConnectorConfig, ConnectorHealth, ConnectorResult, RawAlert};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

/// Creates a test connector config with sensible defaults.
pub fn test_connector_config(name: &str, base_url: &str) -> ConnectorConfig {
    ConnectorConfig {
        name: name.to_string(),
        base_url: base_url.to_string(),
        auth: AuthConfig::None,
        timeout_secs: 30,
        max_retries: 0,
        verify_tls: true,
        headers: HashMap::new(),
    }
}

/// Creates a test connector config with bearer token auth.
pub fn test_connector_config_with_bearer(
    name: &str,
    base_url: &str,
    token: &str,
) -> ConnectorConfig {
    ConnectorConfig {
        name: name.to_string(),
        base_url: base_url.to_string(),
        auth: AuthConfig::BearerToken {
            token: crate::SecureString::new(token.to_string()),
        },
        timeout_secs: 30,
        max_retries: 0,
        verify_tls: true,
        headers: HashMap::new(),
    }
}

/// Creates a sample raw alert for testing.
pub fn sample_raw_alert(id: &str, severity: &str) -> RawAlert {
    RawAlert {
        id: id.to_string(),
        title: format!("Test Alert {}", id),
        description: format!("Test alert description for {}", id),
        severity: severity.to_string(),
        timestamp: Utc::now(),
        source: "test".to_string(),
        raw_data: HashMap::new(),
    }
}

/// Creates a sample raw alert with a specific timestamp.
pub fn sample_raw_alert_at(id: &str, severity: &str, timestamp: DateTime<Utc>) -> RawAlert {
    RawAlert {
        id: id.to_string(),
        title: format!("Test Alert {}", id),
        description: format!("Test alert description for {}", id),
        severity: severity.to_string(),
        timestamp,
        source: "test".to_string(),
        raw_data: HashMap::new(),
    }
}

/// Asserts that a connector health check returns healthy.
pub fn assert_healthy(result: &ConnectorResult<ConnectorHealth>) {
    match result {
        Ok(ConnectorHealth::Healthy) => {}
        other => panic!("Expected Healthy, got {:?}", other),
    }
}

/// Asserts that a connector health check returns unhealthy.
pub fn assert_unhealthy(result: &ConnectorResult<ConnectorHealth>) {
    match result {
        Ok(ConnectorHealth::Unhealthy(_)) => {}
        other => panic!("Expected Unhealthy, got {:?}", other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_test_connector_config() {
        let config = test_connector_config("test", "https://api.example.com");
        assert_eq!(config.name, "test");
        assert_eq!(config.base_url, "https://api.example.com");
        assert!(matches!(config.auth, AuthConfig::None));
    }

    #[test]
    fn test_test_connector_config_with_bearer() {
        let config =
            test_connector_config_with_bearer("test", "https://api.example.com", "token123");
        assert_eq!(config.name, "test");
        assert!(matches!(config.auth, AuthConfig::BearerToken { .. }));
    }

    #[test]
    fn test_sample_raw_alert() {
        let alert = sample_raw_alert("alert-1", "high");
        assert_eq!(alert.id, "alert-1");
        assert_eq!(alert.severity, "high");
    }

    #[test]
    fn test_assert_healthy() {
        let result: ConnectorResult<ConnectorHealth> = Ok(ConnectorHealth::Healthy);
        assert_healthy(&result);
    }

    #[test]
    fn test_assert_unhealthy() {
        let result: ConnectorResult<ConnectorHealth> =
            Ok(ConnectorHealth::Unhealthy("down".to_string()));
        assert_unhealthy(&result);
    }
}
