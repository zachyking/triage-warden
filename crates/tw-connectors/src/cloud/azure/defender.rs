//! Microsoft Defender for Cloud connector.
//!
//! Provides integration with Microsoft Defender for Cloud for security alerts
//! and recommendations.

use crate::http::HttpClient;
use crate::traits::{
    AlertSource, ConnectorCategory, ConnectorError, ConnectorHealth, ConnectorResult, RawAlert,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, instrument};

/// Defender for Cloud connector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefenderConfig {
    /// Base connector configuration.
    #[serde(flatten)]
    pub connector: crate::traits::ConnectorConfig,
    /// Azure subscription ID.
    pub subscription_id: String,
}

/// Microsoft Defender for Cloud connector.
pub struct DefenderConnector {
    config: DefenderConfig,
    client: HttpClient,
}

impl DefenderConnector {
    /// Creates a new Defender for Cloud connector.
    pub fn new(config: DefenderConfig) -> ConnectorResult<Self> {
        let client = HttpClient::new(config.connector.clone())?;
        info!(
            "Defender for Cloud connector initialized for subscription '{}'",
            config.subscription_id
        );
        Ok(Self { config, client })
    }

    /// Builds the base API path.
    fn base_path(&self) -> String {
        format!(
            "/subscriptions/{}/providers/Microsoft.Security",
            self.config.subscription_id
        )
    }

    /// Parses a Defender alert into a RawAlert.
    fn parse_alert(alert: &DefenderAlert) -> RawAlert {
        let severity = match alert.properties.severity.as_deref() {
            Some("High") => "high",
            Some("Medium") => "medium",
            Some("Low") => "low",
            Some("Informational") => "info",
            _ => "medium",
        };

        let mut raw_data = HashMap::new();
        raw_data.insert(
            "alert_type".to_string(),
            serde_json::json!(alert.properties.alert_type),
        );
        raw_data.insert(
            "status".to_string(),
            serde_json::json!(alert.properties.status),
        );
        raw_data.insert(
            "compromised_entity".to_string(),
            serde_json::json!(alert.properties.compromised_entity),
        );
        if let Some(ref intent) = alert.properties.intent {
            raw_data.insert("intent".to_string(), serde_json::json!(intent));
        }
        if let Some(ref techniques) = alert.properties.techniques {
            raw_data.insert(
                "mitre_techniques".to_string(),
                serde_json::json!(techniques),
            );
        }

        RawAlert {
            id: alert.name.clone(),
            title: alert.properties.alert_display_name.clone(),
            description: alert.properties.description.clone().unwrap_or_default(),
            severity: severity.to_string(),
            timestamp: alert
                .properties
                .time_generated_utc
                .as_ref()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(Utc::now),
            source: "azure_defender".to_string(),
            raw_data,
        }
    }
}

#[async_trait]
impl crate::traits::Connector for DefenderConnector {
    fn name(&self) -> &str {
        &self.config.connector.name
    }

    fn connector_type(&self) -> &str {
        "cloud"
    }

    fn category(&self) -> ConnectorCategory {
        ConnectorCategory::Cloud
    }

    fn capabilities(&self) -> Vec<String> {
        vec![
            "health_check".to_string(),
            "test_connection".to_string(),
            "fetch_alerts".to_string(),
            "acknowledge_alert".to_string(),
        ]
    }

    async fn health_check(&self) -> ConnectorResult<ConnectorHealth> {
        let path = format!("{}/alerts?api-version=2022-01-01&$top=1", self.base_path());
        match self.client.get(&path).await {
            Ok(response) if response.status().is_success() => Ok(ConnectorHealth::Healthy),
            Ok(response) if response.status().as_u16() == 401 => Ok(ConnectorHealth::Unhealthy(
                "Authentication failed".to_string(),
            )),
            Ok(_) => Ok(ConnectorHealth::Degraded("Unexpected response".to_string())),
            Err(ConnectorError::ConnectionFailed(e)) => Ok(ConnectorHealth::Unhealthy(format!(
                "Connection failed: {}",
                e
            ))),
            Err(e) => Ok(ConnectorHealth::Unhealthy(e.to_string())),
        }
    }

    async fn test_connection(&self) -> ConnectorResult<bool> {
        let path = format!("{}/alerts?api-version=2022-01-01&$top=1", self.base_path());
        let response = self.client.get(&path).await?;
        Ok(response.status().is_success())
    }
}

#[async_trait]
impl AlertSource for DefenderConnector {
    #[instrument(skip(self))]
    async fn fetch_alerts(
        &self,
        since: DateTime<Utc>,
        limit: Option<usize>,
    ) -> ConnectorResult<Vec<RawAlert>> {
        let top = limit.unwrap_or(100).min(200);
        let filter = format!(
            "properties/timeGeneratedUtc ge {}",
            since.format("%Y-%m-%dT%H:%M:%SZ")
        );
        let path = format!(
            "{}/alerts?api-version=2022-01-01&$top={}&$filter={}",
            self.base_path(),
            top,
            urlencoding::encode(&filter)
        );

        let response = self.client.get(&path).await?;

        if !response.status().is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ConnectorError::RequestFailed(format!(
                "Failed to list alerts: {}",
                body
            )));
        }

        let result: DefenderAlertListResponse = response.json().await.map_err(|e| {
            ConnectorError::InvalidResponse(format!("Failed to parse alerts: {}", e))
        })?;

        Ok(result.value.iter().map(Self::parse_alert).collect())
    }

    async fn acknowledge_alert(&self, alert_id: &str) -> ConnectorResult<()> {
        let path = format!(
            "{}/alerts/{}/activate?api-version=2022-01-01",
            self.base_path(),
            alert_id
        );

        let response = self.client.post(&path, &serde_json::json!({})).await?;

        if !response.status().is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ConnectorError::RequestFailed(format!(
                "Failed to acknowledge alert: {}",
                body
            )));
        }

        Ok(())
    }
}

// Defender API response types

#[derive(Debug, Deserialize)]
struct DefenderAlertListResponse {
    #[serde(default)]
    value: Vec<DefenderAlert>,
}

#[derive(Debug, Deserialize)]
struct DefenderAlert {
    name: String,
    properties: DefenderAlertProperties,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DefenderAlertProperties {
    alert_display_name: String,
    description: Option<String>,
    severity: Option<String>,
    status: Option<String>,
    alert_type: Option<String>,
    compromised_entity: Option<String>,
    intent: Option<String>,
    techniques: Option<Vec<String>>,
    time_generated_utc: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::test_connector_config;
    use crate::traits::Connector;

    fn create_test_config() -> DefenderConfig {
        DefenderConfig {
            connector: test_connector_config("defender-test", "https://management.azure.com"),
            subscription_id: "sub-12345".to_string(),
        }
    }

    #[test]
    fn test_connector_creation() {
        let config = create_test_config();
        let connector = DefenderConnector::new(config);
        assert!(connector.is_ok());
    }

    #[test]
    fn test_connector_name_and_type() {
        let config = create_test_config();
        let connector = DefenderConnector::new(config).unwrap();
        assert_eq!(connector.name(), "defender-test");
        assert_eq!(connector.connector_type(), "cloud");
        assert_eq!(connector.category(), ConnectorCategory::Cloud);
    }

    #[test]
    fn test_parse_alert() {
        let alert = DefenderAlert {
            name: "alert-001".to_string(),
            properties: DefenderAlertProperties {
                alert_display_name: "Suspicious VM Activity".to_string(),
                description: Some("Unusual activity detected on VM".to_string()),
                severity: Some("High".to_string()),
                status: Some("Active".to_string()),
                alert_type: Some("VM_SuspiciousActivity".to_string()),
                compromised_entity: Some("my-vm".to_string()),
                intent: Some("Execution".to_string()),
                techniques: Some(vec!["T1059".to_string()]),
                time_generated_utc: Some("2024-01-15T10:30:00Z".to_string()),
            },
        };

        let raw = DefenderConnector::parse_alert(&alert);
        assert_eq!(raw.id, "alert-001");
        assert_eq!(raw.severity, "high");
        assert_eq!(raw.source, "azure_defender");
    }

    #[test]
    fn test_base_path() {
        let config = create_test_config();
        let connector = DefenderConnector::new(config).unwrap();
        let path = connector.base_path();
        assert!(path.contains("sub-12345"));
        assert!(path.contains("Microsoft.Security"));
    }

    #[test]
    fn test_capabilities() {
        let config = create_test_config();
        let connector = DefenderConnector::new(config).unwrap();
        let caps = connector.capabilities();
        assert!(caps.contains(&"fetch_alerts".to_string()));
    }
}
