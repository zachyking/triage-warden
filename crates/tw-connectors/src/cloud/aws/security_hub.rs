//! AWS Security Hub connector.
//!
//! Provides integration with AWS Security Hub for aggregated security findings.

use crate::http::HttpClient;
use crate::traits::{
    AlertSource, ConnectorCategory, ConnectorError, ConnectorHealth, ConnectorResult, RawAlert,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, instrument};

/// Security Hub connector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityHubConfig {
    /// Base connector configuration.
    #[serde(flatten)]
    pub connector: crate::traits::ConnectorConfig,
    /// AWS region.
    pub region: String,
    /// Product ARN filter (optional).
    pub product_arn_filter: Option<String>,
}

/// AWS Security Hub connector for aggregated findings.
pub struct SecurityHubConnector {
    config: SecurityHubConfig,
    client: HttpClient,
}

impl SecurityHubConnector {
    /// Creates a new Security Hub connector.
    pub fn new(config: SecurityHubConfig) -> ConnectorResult<Self> {
        let client = HttpClient::new(config.connector.clone())?;
        info!(
            "Security Hub connector initialized for region '{}'",
            config.region
        );
        Ok(Self { config, client })
    }

    /// Parses a Security Hub finding into a RawAlert.
    fn parse_finding(finding: &SHFinding) -> RawAlert {
        let severity = finding
            .severity
            .as_ref()
            .map(|s| match s.label.as_deref() {
                Some("CRITICAL") => "critical",
                Some("HIGH") => "high",
                Some("MEDIUM") => "medium",
                Some("LOW") => "low",
                _ => "info",
            })
            .unwrap_or("info");

        let mut raw_data = HashMap::new();
        raw_data.insert(
            "aws_account_id".to_string(),
            serde_json::json!(finding.aws_account_id),
        );
        raw_data.insert(
            "product_arn".to_string(),
            serde_json::json!(finding.product_arn),
        );
        raw_data.insert(
            "generator_id".to_string(),
            serde_json::json!(finding.generator_id),
        );
        raw_data.insert(
            "workflow_status".to_string(),
            serde_json::json!(finding.workflow.as_ref().map(|w| &w.status)),
        );
        if let Some(ref compliance) = finding.compliance {
            raw_data.insert("compliance".to_string(), serde_json::json!(compliance));
        }

        RawAlert {
            id: finding.id.clone(),
            title: finding.title.clone(),
            description: finding.description.clone().unwrap_or_default(),
            severity: severity.to_string(),
            timestamp: finding
                .created_at
                .as_ref()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(Utc::now),
            source: "aws_security_hub".to_string(),
            raw_data,
        }
    }
}

#[async_trait]
impl crate::traits::Connector for SecurityHubConnector {
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
        match self.client.get("/hub").await {
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
        let response = self.client.get("/hub").await?;
        Ok(response.status().is_success())
    }
}

#[async_trait]
impl AlertSource for SecurityHubConnector {
    #[instrument(skip(self))]
    async fn fetch_alerts(
        &self,
        since: DateTime<Utc>,
        limit: Option<usize>,
    ) -> ConnectorResult<Vec<RawAlert>> {
        let mut filters = serde_json::json!({
            "UpdatedAt": [{
                "DateRange": {
                    "Value": 1,
                    "Unit": "DAYS"
                }
            }],
            "RecordState": [{
                "Value": "ACTIVE",
                "Comparison": "EQUALS"
            }]
        });

        if let Some(ref product_arn) = self.config.product_arn_filter {
            filters["ProductArn"] = serde_json::json!([{
                "Value": product_arn,
                "Comparison": "EQUALS"
            }]);
        }

        let body = serde_json::json!({
            "Filters": filters,
            "MaxResults": limit.unwrap_or(100).min(100)
        });

        let response = self.client.post("/findings", &body).await?;

        if !response.status().is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ConnectorError::RequestFailed(format!(
                "Failed to get findings: {}",
                body
            )));
        }

        let result: SHGetFindingsResponse = response.json().await.map_err(|e| {
            ConnectorError::InvalidResponse(format!("Failed to parse findings: {}", e))
        })?;

        let alerts: Vec<RawAlert> = result
            .findings
            .iter()
            .filter(|f| {
                f.created_at
                    .as_ref()
                    .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                    .map(|dt| dt.with_timezone(&Utc) >= since)
                    .unwrap_or(true)
            })
            .map(Self::parse_finding)
            .collect();

        Ok(alerts)
    }

    async fn acknowledge_alert(&self, alert_id: &str) -> ConnectorResult<()> {
        let body = serde_json::json!({
            "FindingIdentifiers": [{
                "Id": alert_id,
                "ProductArn": self.config.product_arn_filter.as_deref().unwrap_or("*")
            }],
            "Workflow": {
                "Status": "NOTIFIED"
            }
        });

        let response = self.client.post("/findings/batchUpdate", &body).await?;

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

// Security Hub API response types

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct SHGetFindingsResponse {
    #[serde(default)]
    findings: Vec<SHFinding>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct SHFinding {
    id: String,
    title: String,
    description: Option<String>,
    aws_account_id: String,
    product_arn: String,
    generator_id: String,
    severity: Option<SHSeverity>,
    created_at: Option<String>,
    workflow: Option<SHWorkflow>,
    compliance: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct SHSeverity {
    label: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct SHWorkflow {
    status: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::test_connector_config;
    use crate::traits::Connector;

    fn create_test_config() -> SecurityHubConfig {
        SecurityHubConfig {
            connector: test_connector_config(
                "securityhub-test",
                "https://securityhub.us-east-1.amazonaws.com",
            ),
            region: "us-east-1".to_string(),
            product_arn_filter: None,
        }
    }

    #[test]
    fn test_connector_creation() {
        let config = create_test_config();
        let connector = SecurityHubConnector::new(config);
        assert!(connector.is_ok());
    }

    #[test]
    fn test_connector_name_and_type() {
        let config = create_test_config();
        let connector = SecurityHubConnector::new(config).unwrap();
        assert_eq!(connector.name(), "securityhub-test");
        assert_eq!(connector.connector_type(), "cloud");
        assert_eq!(connector.category(), ConnectorCategory::Cloud);
    }

    #[test]
    fn test_parse_finding_critical() {
        let finding = SHFinding {
            id: "arn:aws:securityhub:finding-001".to_string(),
            title: "Critical finding".to_string(),
            description: Some("A critical security issue".to_string()),
            aws_account_id: "123456789012".to_string(),
            product_arn: "arn:aws:securityhub:product".to_string(),
            generator_id: "generator-1".to_string(),
            severity: Some(SHSeverity {
                label: Some("CRITICAL".to_string()),
            }),
            created_at: Some("2024-01-15T10:30:00Z".to_string()),
            workflow: Some(SHWorkflow {
                status: "NEW".to_string(),
            }),
            compliance: None,
        };

        let alert = SecurityHubConnector::parse_finding(&finding);
        assert_eq!(alert.severity, "critical");
        assert_eq!(alert.source, "aws_security_hub");
    }

    #[test]
    fn test_parse_finding_no_severity() {
        let finding = SHFinding {
            id: "finding-002".to_string(),
            title: "Info finding".to_string(),
            description: None,
            aws_account_id: "123456789012".to_string(),
            product_arn: "arn:product".to_string(),
            generator_id: "gen-1".to_string(),
            severity: None,
            created_at: None,
            workflow: None,
            compliance: None,
        };

        let alert = SecurityHubConnector::parse_finding(&finding);
        assert_eq!(alert.severity, "info");
    }

    #[test]
    fn test_capabilities() {
        let config = create_test_config();
        let connector = SecurityHubConnector::new(config).unwrap();
        let caps = connector.capabilities();
        assert!(caps.contains(&"fetch_alerts".to_string()));
    }
}
