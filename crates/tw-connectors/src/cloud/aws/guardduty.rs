//! AWS GuardDuty connector.
//!
//! Provides integration with AWS GuardDuty for threat detection findings.

use crate::http::HttpClient;
use crate::traits::{
    AlertSource, ConnectorCategory, ConnectorError, ConnectorHealth, ConnectorResult, RawAlert,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, instrument};

/// GuardDuty connector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardDutyConfig {
    /// Base connector configuration.
    #[serde(flatten)]
    pub connector: crate::traits::ConnectorConfig,
    /// AWS region (e.g., "us-east-1").
    pub region: String,
    /// GuardDuty detector ID.
    pub detector_id: String,
}

/// AWS GuardDuty connector for threat detection findings.
pub struct GuardDutyConnector {
    config: GuardDutyConfig,
    client: HttpClient,
}

impl GuardDutyConnector {
    /// Creates a new GuardDuty connector.
    pub fn new(config: GuardDutyConfig) -> ConnectorResult<Self> {
        let client = HttpClient::new(config.connector.clone())?;
        info!(
            "GuardDuty connector initialized for region '{}', detector '{}'",
            config.region, config.detector_id
        );
        Ok(Self { config, client })
    }

    /// Parses a GuardDuty finding into a RawAlert.
    fn parse_finding(finding: &GDFinding) -> RawAlert {
        let severity = match finding.severity {
            s if s >= 7.0 => "critical",
            s if s >= 4.0 => "high",
            s if s >= 2.0 => "medium",
            _ => "low",
        };

        let mut raw_data = HashMap::new();
        raw_data.insert(
            "account_id".to_string(),
            serde_json::json!(finding.account_id),
        );
        raw_data.insert("region".to_string(), serde_json::json!(finding.region));
        raw_data.insert(
            "finding_type".to_string(),
            serde_json::json!(finding.finding_type),
        );
        raw_data.insert(
            "severity_numeric".to_string(),
            serde_json::json!(finding.severity),
        );
        if let Some(ref resource) = finding.resource {
            raw_data.insert("resource".to_string(), resource.clone());
        }

        RawAlert {
            id: finding.id.clone(),
            title: finding.title.clone(),
            description: finding.description.clone(),
            severity: severity.to_string(),
            timestamp: finding
                .created_at
                .as_ref()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(Utc::now),
            source: "aws_guardduty".to_string(),
            raw_data,
        }
    }
}

#[async_trait]
impl crate::traits::Connector for GuardDutyConnector {
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
        let path = format!("/detector/{}", self.config.detector_id);
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
        let path = format!("/detector/{}", self.config.detector_id);
        let response = self.client.get(&path).await?;
        Ok(response.status().is_success())
    }
}

#[async_trait]
impl AlertSource for GuardDutyConnector {
    #[instrument(skip(self))]
    async fn fetch_alerts(
        &self,
        since: DateTime<Utc>,
        limit: Option<usize>,
    ) -> ConnectorResult<Vec<RawAlert>> {
        let criterion = serde_json::json!({
            "criterion": {
                "updatedAt": {
                    "greaterThanOrEqual": since.timestamp_millis()
                }
            },
            "maxResults": limit.unwrap_or(50).min(50)
        });

        let path = format!("/detector/{}/findings", self.config.detector_id);
        let response = self.client.post(&path, &criterion).await?;

        if !response.status().is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ConnectorError::RequestFailed(format!(
                "Failed to list findings: {}",
                body
            )));
        }

        let list_result: GDListFindingsResponse = response.json().await.map_err(|e| {
            ConnectorError::InvalidResponse(format!("Failed to parse findings list: {}", e))
        })?;

        if list_result.finding_ids.is_empty() {
            return Ok(Vec::new());
        }

        // Get finding details
        let body = serde_json::json!({
            "findingIds": list_result.finding_ids
        });
        let detail_path = format!("/detector/{}/findings/get", self.config.detector_id);
        let response = self.client.post(&detail_path, &body).await?;

        if !response.status().is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ConnectorError::RequestFailed(format!(
                "Failed to get finding details: {}",
                body
            )));
        }

        let detail_result: GDGetFindingsResponse = response.json().await.map_err(|e| {
            ConnectorError::InvalidResponse(format!("Failed to parse finding details: {}", e))
        })?;

        Ok(detail_result
            .findings
            .iter()
            .map(Self::parse_finding)
            .collect())
    }

    async fn acknowledge_alert(&self, alert_id: &str) -> ConnectorResult<()> {
        let body = serde_json::json!({
            "findingIds": [alert_id],
            "feedback": "USEFUL"
        });

        let path = format!("/detector/{}/findings/feedback", self.config.detector_id);
        let response = self.client.post(&path, &body).await?;

        if !response.status().is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ConnectorError::RequestFailed(format!(
                "Failed to acknowledge finding: {}",
                body
            )));
        }

        Ok(())
    }
}

// GuardDuty API response types

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GDListFindingsResponse {
    #[serde(default)]
    finding_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GDGetFindingsResponse {
    #[serde(default)]
    findings: Vec<GDFinding>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GDFinding {
    id: String,
    title: String,
    description: String,
    severity: f64,
    account_id: String,
    region: String,
    #[serde(default)]
    finding_type: String,
    created_at: Option<String>,
    resource: Option<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::test_connector_config;
    use crate::traits::Connector;

    fn create_test_config() -> GuardDutyConfig {
        GuardDutyConfig {
            connector: test_connector_config(
                "guardduty-test",
                "https://guardduty.us-east-1.amazonaws.com",
            ),
            region: "us-east-1".to_string(),
            detector_id: "detector-12345".to_string(),
        }
    }

    #[test]
    fn test_connector_creation() {
        let config = create_test_config();
        let connector = GuardDutyConnector::new(config);
        assert!(connector.is_ok());
    }

    #[test]
    fn test_connector_name_and_type() {
        let config = create_test_config();
        let connector = GuardDutyConnector::new(config).unwrap();
        assert_eq!(connector.name(), "guardduty-test");
        assert_eq!(connector.connector_type(), "cloud");
        assert_eq!(connector.category(), ConnectorCategory::Cloud);
    }

    #[test]
    fn test_parse_finding_high_severity() {
        let finding = GDFinding {
            id: "finding-001".to_string(),
            title: "Unauthorized API Call".to_string(),
            description: "An API was called from an unauthorized IP".to_string(),
            severity: 8.0,
            account_id: "123456789012".to_string(),
            region: "us-east-1".to_string(),
            finding_type: "Recon:EC2/PortProbeUnprotectedPort".to_string(),
            created_at: Some("2024-01-15T10:30:00Z".to_string()),
            resource: None,
        };

        let alert = GuardDutyConnector::parse_finding(&finding);
        assert_eq!(alert.id, "finding-001");
        assert_eq!(alert.severity, "critical");
        assert_eq!(alert.source, "aws_guardduty");
    }

    #[test]
    fn test_parse_finding_low_severity() {
        let finding = GDFinding {
            id: "finding-002".to_string(),
            title: "Low severity finding".to_string(),
            description: "Minor issue".to_string(),
            severity: 1.5,
            account_id: "123456789012".to_string(),
            region: "us-east-1".to_string(),
            finding_type: "UnauthorizedAccess".to_string(),
            created_at: None,
            resource: None,
        };

        let alert = GuardDutyConnector::parse_finding(&finding);
        assert_eq!(alert.severity, "low");
    }

    #[test]
    fn test_capabilities() {
        let config = create_test_config();
        let connector = GuardDutyConnector::new(config).unwrap();
        let caps = connector.capabilities();
        assert!(caps.contains(&"fetch_alerts".to_string()));
        assert!(caps.contains(&"acknowledge_alert".to_string()));
    }
}
