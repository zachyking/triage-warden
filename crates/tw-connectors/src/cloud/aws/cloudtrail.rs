//! AWS CloudTrail connector.
//!
//! Provides integration with AWS CloudTrail for audit log retrieval and analysis.

use crate::http::HttpClient;
use crate::traits::{
    ConnectorCategory, ConnectorError, ConnectorHealth, ConnectorResult, Enricher,
    EnrichmentResult, Ioc, IocType,
};
use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, instrument};

/// CloudTrail connector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudTrailConfig {
    /// Base connector configuration.
    #[serde(flatten)]
    pub connector: crate::traits::ConnectorConfig,
    /// AWS region.
    pub region: String,
    /// Trail ARN (optional, queries all trails if not specified).
    pub trail_arn: Option<String>,
}

/// AWS CloudTrail connector for audit log enrichment.
pub struct CloudTrailConnector {
    config: CloudTrailConfig,
    client: HttpClient,
}

impl CloudTrailConnector {
    /// Creates a new CloudTrail connector.
    pub fn new(config: CloudTrailConfig) -> ConnectorResult<Self> {
        let client = HttpClient::new(config.connector.clone())?;
        info!(
            "CloudTrail connector initialized for region '{}'",
            config.region
        );
        Ok(Self { config, client })
    }
}

#[async_trait]
impl crate::traits::Connector for CloudTrailConnector {
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
            "enrich".to_string(),
        ]
    }

    async fn health_check(&self) -> ConnectorResult<ConnectorHealth> {
        match self.client.get("/2013-11-01/trails").await {
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
        let response = self.client.get("/2013-11-01/trails").await?;
        Ok(response.status().is_success())
    }
}

#[async_trait]
impl Enricher for CloudTrailConnector {
    fn supported_ioc_types(&self) -> Vec<IocType> {
        vec![IocType::IpAddress]
    }

    #[instrument(skip(self))]
    async fn enrich(&self, ioc: &Ioc) -> ConnectorResult<EnrichmentResult> {
        if ioc.ioc_type != IocType::IpAddress {
            return Ok(EnrichmentResult {
                ioc: ioc.clone(),
                found: false,
                risk_score: None,
                data: HashMap::new(),
                source: "aws_cloudtrail".to_string(),
                enriched_at: Utc::now(),
            });
        }

        // Look up events from this IP address
        let body = serde_json::json!({
            "LookupAttributes": [{
                "AttributeKey": "SourceIPAddress",
                "AttributeValue": ioc.value
            }],
            "MaxResults": 50
        });

        let response = self.client.post("/2013-11-01/events/lookup", &body).await?;

        if !response.status().is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ConnectorError::RequestFailed(format!(
                "Failed to look up events: {}",
                body
            )));
        }

        let result: CTLookupResponse = response.json().await.map_err(|e| {
            ConnectorError::InvalidResponse(format!("Failed to parse lookup response: {}", e))
        })?;

        let event_count = result.events.len();
        let mut data = HashMap::new();
        data.insert("event_count".to_string(), serde_json::json!(event_count));

        // Extract unique event names
        let event_names: Vec<&str> = result
            .events
            .iter()
            .map(|e| e.event_name.as_str())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        data.insert("event_names".to_string(), serde_json::json!(event_names));

        // Extract unique usernames
        let users: Vec<&str> = result
            .events
            .iter()
            .filter_map(|e| e.username.as_deref())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        data.insert("users".to_string(), serde_json::json!(users));

        let risk_score = if event_count > 20 {
            Some(70)
        } else if event_count > 5 {
            Some(40)
        } else if event_count > 0 {
            Some(20)
        } else {
            None
        };

        Ok(EnrichmentResult {
            ioc: ioc.clone(),
            found: event_count > 0,
            risk_score,
            data,
            source: "aws_cloudtrail".to_string(),
            enriched_at: Utc::now(),
        })
    }
}

// CloudTrail API response types

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CTLookupResponse {
    #[serde(default)]
    events: Vec<CTEvent>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CTEvent {
    event_name: String,
    username: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::test_connector_config;
    use crate::traits::Connector;

    fn create_test_config() -> CloudTrailConfig {
        CloudTrailConfig {
            connector: test_connector_config(
                "cloudtrail-test",
                "https://cloudtrail.us-east-1.amazonaws.com",
            ),
            region: "us-east-1".to_string(),
            trail_arn: None,
        }
    }

    #[test]
    fn test_connector_creation() {
        let config = create_test_config();
        let connector = CloudTrailConnector::new(config);
        assert!(connector.is_ok());
    }

    #[test]
    fn test_connector_name_and_type() {
        let config = create_test_config();
        let connector = CloudTrailConnector::new(config).unwrap();
        assert_eq!(connector.name(), "cloudtrail-test");
        assert_eq!(connector.connector_type(), "cloud");
        assert_eq!(connector.category(), ConnectorCategory::Cloud);
    }

    #[test]
    fn test_supported_ioc_types() {
        let config = create_test_config();
        let connector = CloudTrailConnector::new(config).unwrap();
        let types = connector.supported_ioc_types();
        assert_eq!(types, vec![IocType::IpAddress]);
    }

    #[test]
    fn test_capabilities() {
        let config = create_test_config();
        let connector = CloudTrailConnector::new(config).unwrap();
        let caps = connector.capabilities();
        assert!(caps.contains(&"enrich".to_string()));
    }
}
