//! Microsoft Sentinel connector.
//!
//! Provides integration with Microsoft Sentinel (Azure SIEM) for security incident
//! and alert management.

use crate::http::HttpClient;
use crate::traits::{
    AlertSource, ConnectorCategory, ConnectorError, ConnectorHealth, ConnectorResult, RawAlert,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, instrument};

/// Sentinel connector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentinelConfig {
    /// Base connector configuration.
    #[serde(flatten)]
    pub connector: crate::traits::ConnectorConfig,
    /// Azure subscription ID.
    pub subscription_id: String,
    /// Resource group name.
    pub resource_group: String,
    /// Log Analytics workspace name.
    pub workspace_name: String,
}

/// Microsoft Sentinel connector.
pub struct SentinelConnector {
    config: SentinelConfig,
    client: HttpClient,
}

impl SentinelConnector {
    /// Creates a new Sentinel connector.
    pub fn new(config: SentinelConfig) -> ConnectorResult<Self> {
        let client = HttpClient::new(config.connector.clone())?;
        info!(
            "Sentinel connector initialized for workspace '{}'",
            config.workspace_name
        );
        Ok(Self { config, client })
    }

    /// Builds the base API path for Sentinel operations.
    fn base_path(&self) -> String {
        format!(
            "/subscriptions/{}/resourceGroups/{}/providers/Microsoft.OperationalInsights/workspaces/{}/providers/Microsoft.SecurityInsights",
            self.config.subscription_id, self.config.resource_group, self.config.workspace_name
        )
    }

    /// Parses a Sentinel incident into a RawAlert.
    fn parse_incident(incident: &SentinelIncident) -> RawAlert {
        let severity = match incident.properties.severity.as_deref() {
            Some("High") => "high",
            Some("Medium") => "medium",
            Some("Low") => "low",
            Some("Informational") => "info",
            _ => "medium",
        };

        let mut raw_data = HashMap::new();
        raw_data.insert(
            "incident_number".to_string(),
            serde_json::json!(incident.properties.incident_number),
        );
        raw_data.insert(
            "status".to_string(),
            serde_json::json!(incident.properties.status),
        );
        if let Some(ref owner) = incident.properties.owner {
            raw_data.insert("owner".to_string(), serde_json::json!(owner));
        }
        if let Some(ref labels) = incident.properties.labels {
            raw_data.insert("labels".to_string(), serde_json::json!(labels));
        }
        raw_data.insert(
            "alert_count".to_string(),
            serde_json::json!(incident
                .properties
                .additional_data
                .as_ref()
                .map(|a| a.alerts_count)),
        );

        RawAlert {
            id: incident.name.clone(),
            title: incident.properties.title.clone(),
            description: incident.properties.description.clone().unwrap_or_default(),
            severity: severity.to_string(),
            timestamp: incident
                .properties
                .created_time_utc
                .as_ref()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(Utc::now),
            source: "azure_sentinel".to_string(),
            raw_data,
        }
    }
}

#[async_trait]
impl crate::traits::Connector for SentinelConnector {
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
        let path = format!(
            "{}/incidents?api-version=2023-11-01&$top=1",
            self.base_path()
        );
        match self.client.get(&path).await {
            Ok(response) if response.status().is_success() => Ok(ConnectorHealth::Healthy),
            Ok(response) if response.status().as_u16() == 401 => Ok(ConnectorHealth::Unhealthy(
                "Authentication failed".to_string(),
            )),
            Ok(response) if response.status().as_u16() == 403 => Ok(ConnectorHealth::Unhealthy(
                "Authorization denied".to_string(),
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
        let path = format!(
            "{}/incidents?api-version=2023-11-01&$top=1",
            self.base_path()
        );
        let response = self.client.get(&path).await?;
        Ok(response.status().is_success())
    }
}

#[async_trait]
impl AlertSource for SentinelConnector {
    #[instrument(skip(self))]
    async fn fetch_alerts(
        &self,
        since: DateTime<Utc>,
        limit: Option<usize>,
    ) -> ConnectorResult<Vec<RawAlert>> {
        let top = limit.unwrap_or(100).min(200);
        let filter = format!(
            "properties/createdTimeUtc ge {}",
            since.format("%Y-%m-%dT%H:%M:%SZ")
        );
        let path = format!(
            "{}/incidents?api-version=2023-11-01&$top={}&$filter={}&$orderby=properties/createdTimeUtc desc",
            self.base_path(),
            top,
            urlencoding::encode(&filter)
        );

        let response = self.client.get(&path).await?;

        if !response.status().is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ConnectorError::RequestFailed(format!(
                "Failed to list incidents: {}",
                body
            )));
        }

        let result: SentinelIncidentListResponse = response.json().await.map_err(|e| {
            ConnectorError::InvalidResponse(format!("Failed to parse incidents: {}", e))
        })?;

        Ok(result.value.iter().map(Self::parse_incident).collect())
    }

    async fn acknowledge_alert(&self, alert_id: &str) -> ConnectorResult<()> {
        let path = format!(
            "{}/incidents/{}?api-version=2023-11-01",
            self.base_path(),
            alert_id
        );

        // First get the current incident to preserve etag
        let response = self.client.get(&path).await?;
        if !response.status().is_success() {
            return Err(ConnectorError::NotFound(format!(
                "Incident not found: {}",
                alert_id
            )));
        }

        let incident: SentinelIncident = response.json().await.map_err(|e| {
            ConnectorError::InvalidResponse(format!("Failed to parse incident: {}", e))
        })?;

        // Update status to Active (acknowledged)
        let body = serde_json::json!({
            "properties": {
                "title": incident.properties.title,
                "severity": incident.properties.severity,
                "status": "Active"
            }
        });

        let response = self.client.put(&path, &body).await?;
        if !response.status().is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ConnectorError::RequestFailed(format!(
                "Failed to acknowledge incident: {}",
                body
            )));
        }

        Ok(())
    }
}

// Sentinel API response types

#[derive(Debug, Deserialize)]
struct SentinelIncidentListResponse {
    #[serde(default)]
    value: Vec<SentinelIncident>,
}

#[derive(Debug, Deserialize)]
struct SentinelIncident {
    name: String,
    properties: SentinelIncidentProperties,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SentinelIncidentProperties {
    title: String,
    description: Option<String>,
    severity: Option<String>,
    status: Option<String>,
    incident_number: Option<u64>,
    created_time_utc: Option<String>,
    owner: Option<serde_json::Value>,
    labels: Option<Vec<serde_json::Value>>,
    additional_data: Option<SentinelAdditionalData>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SentinelAdditionalData {
    alerts_count: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::test_connector_config;
    use crate::traits::Connector;

    fn create_test_config() -> SentinelConfig {
        SentinelConfig {
            connector: test_connector_config("sentinel-test", "https://management.azure.com"),
            subscription_id: "sub-12345".to_string(),
            resource_group: "rg-security".to_string(),
            workspace_name: "ws-sentinel".to_string(),
        }
    }

    #[test]
    fn test_connector_creation() {
        let config = create_test_config();
        let connector = SentinelConnector::new(config);
        assert!(connector.is_ok());
    }

    #[test]
    fn test_connector_name_and_type() {
        let config = create_test_config();
        let connector = SentinelConnector::new(config).unwrap();
        assert_eq!(connector.name(), "sentinel-test");
        assert_eq!(connector.connector_type(), "cloud");
        assert_eq!(connector.category(), ConnectorCategory::Cloud);
    }

    #[test]
    fn test_base_path() {
        let config = create_test_config();
        let connector = SentinelConnector::new(config).unwrap();
        let path = connector.base_path();
        assert!(path.contains("sub-12345"));
        assert!(path.contains("rg-security"));
        assert!(path.contains("ws-sentinel"));
    }

    #[test]
    fn test_parse_incident() {
        let incident = SentinelIncident {
            name: "incident-001".to_string(),
            properties: SentinelIncidentProperties {
                title: "Suspicious Activity".to_string(),
                description: Some("Detected suspicious login".to_string()),
                severity: Some("High".to_string()),
                status: Some("New".to_string()),
                incident_number: Some(42),
                created_time_utc: Some("2024-01-15T10:30:00Z".to_string()),
                owner: None,
                labels: None,
                additional_data: Some(SentinelAdditionalData {
                    alerts_count: Some(3),
                }),
            },
        };

        let alert = SentinelConnector::parse_incident(&incident);
        assert_eq!(alert.id, "incident-001");
        assert_eq!(alert.severity, "high");
        assert_eq!(alert.source, "azure_sentinel");
    }

    #[test]
    fn test_capabilities() {
        let config = create_test_config();
        let connector = SentinelConnector::new(config).unwrap();
        let caps = connector.capabilities();
        assert!(caps.contains(&"fetch_alerts".to_string()));
        assert!(caps.contains(&"acknowledge_alert".to_string()));
    }
}
