//! Google Cloud Security Command Center (SCC) connector.
//!
//! Provides integration with GCP Security Command Center for security findings.

use crate::http::HttpClient;
use crate::traits::{
    AlertSource, ConnectorCategory, ConnectorError, ConnectorHealth, ConnectorResult, RawAlert,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, instrument};

/// SCC connector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SCCConfig {
    /// Base connector configuration.
    #[serde(flatten)]
    pub connector: crate::traits::ConnectorConfig,
    /// GCP organization ID.
    pub organization_id: String,
    /// SCC source ID filter (optional).
    pub source_id: Option<String>,
}

/// Google Cloud Security Command Center connector.
pub struct SCCConnector {
    config: SCCConfig,
    client: HttpClient,
}

impl SCCConnector {
    /// Creates a new SCC connector.
    pub fn new(config: SCCConfig) -> ConnectorResult<Self> {
        let client = HttpClient::new(config.connector.clone())?;
        info!(
            "SCC connector initialized for organization '{}'",
            config.organization_id
        );
        Ok(Self { config, client })
    }

    /// Builds the parent resource path.
    fn parent_path(&self) -> String {
        match &self.config.source_id {
            Some(source_id) => format!(
                "organizations/{}/sources/{}",
                self.config.organization_id, source_id
            ),
            None => format!("organizations/{}/sources/-", self.config.organization_id),
        }
    }

    /// Parses an SCC finding into a RawAlert.
    fn parse_finding(finding: &SCCFinding) -> RawAlert {
        let severity = match finding.severity.as_deref() {
            Some("CRITICAL") => "critical",
            Some("HIGH") => "high",
            Some("MEDIUM") => "medium",
            Some("LOW") => "low",
            _ => "info",
        };

        let mut raw_data = HashMap::new();
        raw_data.insert("category".to_string(), serde_json::json!(finding.category));
        raw_data.insert("state".to_string(), serde_json::json!(finding.state));
        raw_data.insert(
            "resource_name".to_string(),
            serde_json::json!(finding.resource_name),
        );
        if let Some(ref indicator) = finding.indicator {
            raw_data.insert("indicator".to_string(), indicator.clone());
        }
        if let Some(ref mitre) = finding.mitre_attack {
            raw_data.insert("mitre_attack".to_string(), mitre.clone());
        }

        RawAlert {
            id: finding.name.clone(),
            title: finding
                .category
                .clone()
                .unwrap_or_else(|| "SCC Finding".to_string()),
            description: finding.description.clone().unwrap_or_default(),
            severity: severity.to_string(),
            timestamp: finding
                .event_time
                .as_ref()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(Utc::now),
            source: "gcp_scc".to_string(),
            raw_data,
        }
    }
}

#[async_trait]
impl crate::traits::Connector for SCCConnector {
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
            "/v1/organizations/{}/sources?pageSize=1",
            self.config.organization_id
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
            "/v1/organizations/{}/sources?pageSize=1",
            self.config.organization_id
        );
        let response = self.client.get(&path).await?;
        Ok(response.status().is_success())
    }
}

#[async_trait]
impl AlertSource for SCCConnector {
    #[instrument(skip(self))]
    async fn fetch_alerts(
        &self,
        since: DateTime<Utc>,
        limit: Option<usize>,
    ) -> ConnectorResult<Vec<RawAlert>> {
        let page_size = limit.unwrap_or(100).min(1000);
        let filter = format!(
            "state=\"ACTIVE\" AND eventTime >= \"{}\"",
            since.format("%Y-%m-%dT%H:%M:%SZ")
        );
        let path = format!(
            "/v1/{}/findings?filter={}&pageSize={}&orderBy=eventTime desc",
            self.parent_path(),
            urlencoding::encode(&filter),
            page_size
        );

        let response = self.client.get(&path).await?;

        if !response.status().is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ConnectorError::RequestFailed(format!(
                "Failed to list findings: {}",
                body
            )));
        }

        let result: SCCListFindingsResponse = response.json().await.map_err(|e| {
            ConnectorError::InvalidResponse(format!("Failed to parse findings: {}", e))
        })?;

        Ok(result
            .list_findings_results
            .iter()
            .map(|r| Self::parse_finding(&r.finding))
            .collect())
    }

    async fn acknowledge_alert(&self, alert_id: &str) -> ConnectorResult<()> {
        let path = format!("/v1/{}:setMute", alert_id);
        let body = serde_json::json!({
            "mute": "MUTED"
        });

        let response = self.client.post(&path, &body).await?;

        if !response.status().is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ConnectorError::RequestFailed(format!(
                "Failed to mute finding: {}",
                body
            )));
        }

        Ok(())
    }
}

// SCC API response types

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SCCListFindingsResponse {
    #[serde(default)]
    list_findings_results: Vec<SCCFindingResult>,
}

#[derive(Debug, Deserialize)]
struct SCCFindingResult {
    finding: SCCFinding,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SCCFinding {
    name: String,
    category: Option<String>,
    description: Option<String>,
    severity: Option<String>,
    state: Option<String>,
    resource_name: Option<String>,
    event_time: Option<String>,
    indicator: Option<serde_json::Value>,
    mitre_attack: Option<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::test_connector_config;
    use crate::traits::Connector;

    fn create_test_config() -> SCCConfig {
        SCCConfig {
            connector: test_connector_config("scc-test", "https://securitycenter.googleapis.com"),
            organization_id: "org-12345".to_string(),
            source_id: None,
        }
    }

    #[test]
    fn test_connector_creation() {
        let config = create_test_config();
        let connector = SCCConnector::new(config);
        assert!(connector.is_ok());
    }

    #[test]
    fn test_connector_name_and_type() {
        let config = create_test_config();
        let connector = SCCConnector::new(config).unwrap();
        assert_eq!(connector.name(), "scc-test");
        assert_eq!(connector.connector_type(), "cloud");
        assert_eq!(connector.category(), ConnectorCategory::Cloud);
    }

    #[test]
    fn test_parent_path_all_sources() {
        let config = create_test_config();
        let connector = SCCConnector::new(config).unwrap();
        let path = connector.parent_path();
        assert_eq!(path, "organizations/org-12345/sources/-");
    }

    #[test]
    fn test_parent_path_specific_source() {
        let mut config = create_test_config();
        config.source_id = Some("source-001".to_string());
        let connector = SCCConnector::new(config).unwrap();
        let path = connector.parent_path();
        assert_eq!(path, "organizations/org-12345/sources/source-001");
    }

    #[test]
    fn test_parse_finding() {
        let finding = SCCFinding {
            name: "organizations/123/sources/456/findings/789".to_string(),
            category: Some("MALWARE".to_string()),
            description: Some("Malware detected on instance".to_string()),
            severity: Some("HIGH".to_string()),
            state: Some("ACTIVE".to_string()),
            resource_name: Some("//compute.googleapis.com/projects/my-project/zones/us-central1-a/instances/my-instance".to_string()),
            event_time: Some("2024-01-15T10:30:00Z".to_string()),
            indicator: None,
            mitre_attack: None,
        };

        let alert = SCCConnector::parse_finding(&finding);
        assert_eq!(alert.severity, "high");
        assert_eq!(alert.source, "gcp_scc");
        assert_eq!(alert.title, "MALWARE");
    }
}
