//! Google Chronicle SIEM connector.
//!
//! Provides integration with Google Chronicle (now part of Google Security Operations)
//! for UDM searches, alert retrieval, and detection rules.

use crate::http::HttpClient;
use crate::traits::{
    ConnectorCategory, ConnectorError, ConnectorHealth, ConnectorResult, SIEMAlert, SIEMConnector,
    SIEMEvent, SavedSearch, SearchResults, TimeRange,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, instrument};

/// Google Chronicle connector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChronicleConfig {
    /// Base connector configuration.
    #[serde(flatten)]
    pub connector: crate::traits::ConnectorConfig,
    /// Chronicle instance/customer ID.
    pub customer_id: String,
    /// Chronicle region (e.g., "us", "europe", "asia-southeast1").
    pub region: String,
}

/// Google Chronicle SIEM connector.
pub struct ChronicleConnector {
    config: ChronicleConfig,
    client: HttpClient,
}

impl ChronicleConnector {
    /// Creates a new Chronicle connector.
    pub fn new(config: ChronicleConfig) -> ConnectorResult<Self> {
        let client = HttpClient::new(config.connector.clone())?;
        info!(
            "Chronicle connector initialized for customer '{}' in region '{}'",
            config.customer_id, config.region
        );
        Ok(Self { config, client })
    }

    fn parse_udm_event(event: &ChronicleUdmEvent) -> SIEMEvent {
        let timestamp = event
            .metadata
            .as_ref()
            .and_then(|m| m.event_timestamp.as_ref())
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);

        let mut fields = HashMap::new();
        if let Some(ref metadata) = event.metadata {
            if let Some(ref event_type) = metadata.event_type {
                fields.insert("event_type".to_string(), serde_json::json!(event_type));
            }
        }
        if let Some(ref principal) = event.principal {
            fields.insert(
                "principal".to_string(),
                serde_json::to_value(principal).unwrap_or_default(),
            );
        }
        if let Some(ref target) = event.target {
            fields.insert(
                "target".to_string(),
                serde_json::to_value(target).unwrap_or_default(),
            );
        }

        SIEMEvent {
            timestamp,
            raw: serde_json::to_string(event).unwrap_or_default(),
            fields,
            source: "chronicle".to_string(),
        }
    }

    fn parse_detection(detection: &ChronicleDetection) -> SIEMAlert {
        let timestamp = detection
            .detection_time
            .as_ref()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);

        SIEMAlert {
            id: detection.id.clone().unwrap_or_default(),
            name: detection
                .rule_name
                .clone()
                .unwrap_or_else(|| "Unknown Detection".to_string()),
            severity: detection
                .severity
                .clone()
                .unwrap_or_else(|| "medium".to_string()),
            timestamp,
            details: {
                let mut d = HashMap::new();
                if let Some(ref rule_id) = detection.rule_id {
                    d.insert("rule_id".to_string(), serde_json::json!(rule_id));
                }
                if let Some(ref description) = detection.description {
                    d.insert("description".to_string(), serde_json::json!(description));
                }
                d
            },
        }
    }
}

#[async_trait]
impl crate::traits::Connector for ChronicleConnector {
    fn name(&self) -> &str {
        &self.config.connector.name
    }

    fn connector_type(&self) -> &str {
        "siem"
    }

    fn category(&self) -> ConnectorCategory {
        ConnectorCategory::Siem
    }

    fn capabilities(&self) -> Vec<String> {
        vec![
            "health_check".to_string(),
            "test_connection".to_string(),
            "search".to_string(),
            "get_recent_alerts".to_string(),
            "get_saved_searches".to_string(),
        ]
    }

    async fn health_check(&self) -> ConnectorResult<ConnectorHealth> {
        match self.client.get("/v2/health").await {
            Ok(r) if r.status().is_success() => Ok(ConnectorHealth::Healthy),
            Ok(r) if r.status().as_u16() == 401 => Ok(ConnectorHealth::Unhealthy(
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
        let response = self.client.get("/v2/health").await?;
        Ok(response.status().is_success())
    }
}

#[async_trait]
impl SIEMConnector for ChronicleConnector {
    #[instrument(skip(self))]
    async fn search(&self, query: &str, timerange: TimeRange) -> ConnectorResult<SearchResults> {
        let body = serde_json::json!({
            "query": query,
            "time_range": {
                "start_time": timerange.start.to_rfc3339(),
                "end_time": timerange.end.to_rfc3339()
            },
            "limit": 100
        });

        let response = self.client.post("/v2/detect/rules:search", &body).await?;
        if !response.status().is_success() {
            let err = response.text().await.unwrap_or_default();
            return Err(ConnectorError::RequestFailed(format!(
                "Search failed: {}",
                err
            )));
        }

        let result: ChronicleSearchResponse = response
            .json()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(format!("Parse error: {}", e)))?;

        let events: Vec<SIEMEvent> = result
            .udm_events
            .iter()
            .map(Self::parse_udm_event)
            .collect();

        Ok(SearchResults {
            search_id: uuid::Uuid::new_v4().to_string(),
            total_count: events.len() as u64,
            events,
            stats: None,
        })
    }

    #[instrument(skip(self))]
    async fn get_saved_searches(&self) -> ConnectorResult<Vec<SavedSearch>> {
        let response = self.client.get("/v2/detect/rules").await?;
        if !response.status().is_success() {
            return Ok(Vec::new());
        }

        let result: ChronicleRulesResponse = response
            .json()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(format!("Parse error: {}", e)))?;

        Ok(result
            .rules
            .into_iter()
            .map(|r| SavedSearch {
                id: r.rule_id.unwrap_or_default(),
                name: r.rule_name.unwrap_or_else(|| "Unnamed Rule".to_string()),
                query: r.rule_text.unwrap_or_default(),
                alerts_enabled: r.alerting.unwrap_or(false),
            })
            .collect())
    }

    #[instrument(skip(self))]
    async fn get_recent_alerts(&self, limit: usize) -> ConnectorResult<Vec<SIEMAlert>> {
        let path = format!("/v2/detect/detections?page_size={}", limit);
        let response = self.client.get(&path).await?;

        if !response.status().is_success() {
            return Ok(Vec::new());
        }

        let result: ChronicleDetectionsResponse = response
            .json()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(format!("Parse error: {}", e)))?;

        Ok(result
            .detections
            .iter()
            .map(Self::parse_detection)
            .collect())
    }

    #[instrument(skip(self))]
    async fn get_field_values(
        &self,
        field: &str,
        timerange: TimeRange,
        limit: usize,
    ) -> ConnectorResult<Vec<String>> {
        let body = serde_json::json!({
            "field": field,
            "time_range": {
                "start_time": timerange.start.to_rfc3339(),
                "end_time": timerange.end.to_rfc3339()
            },
            "limit": limit
        });

        let response = self.client.post("/v2/udm/fieldValues", &body).await?;

        if !response.status().is_success() {
            return Ok(Vec::new());
        }

        let result: serde_json::Value = response
            .json()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(format!("Parse error: {}", e)))?;

        let values = result
            .get("values")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        Ok(values
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect())
    }
}

// Chronicle API response types

#[derive(Debug, Default, Deserialize, Serialize)]
struct ChronicleSearchResponse {
    #[serde(default, rename = "udmEvents")]
    udm_events: Vec<ChronicleUdmEvent>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ChronicleUdmEvent {
    metadata: Option<ChronicleMetadata>,
    principal: Option<serde_json::Value>,
    target: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ChronicleMetadata {
    event_timestamp: Option<String>,
    event_type: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct ChronicleDetectionsResponse {
    #[serde(default)]
    detections: Vec<ChronicleDetection>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChronicleDetection {
    id: Option<String>,
    rule_name: Option<String>,
    rule_id: Option<String>,
    severity: Option<String>,
    description: Option<String>,
    detection_time: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct ChronicleRulesResponse {
    #[serde(default)]
    rules: Vec<ChronicleRule>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChronicleRule {
    rule_id: Option<String>,
    rule_name: Option<String>,
    rule_text: Option<String>,
    alerting: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::test_connector_config;
    use crate::traits::Connector;

    fn create_test_config() -> ChronicleConfig {
        ChronicleConfig {
            connector: test_connector_config("chronicle-test", "https://backstory.googleapis.com"),
            customer_id: "customer-12345".to_string(),
            region: "us".to_string(),
        }
    }

    #[test]
    fn test_connector_creation() {
        assert!(ChronicleConnector::new(create_test_config()).is_ok());
    }

    #[test]
    fn test_connector_name_and_category() {
        let c = ChronicleConnector::new(create_test_config()).unwrap();
        assert_eq!(c.name(), "chronicle-test");
        assert_eq!(c.connector_type(), "siem");
        assert_eq!(c.category(), ConnectorCategory::Siem);
    }

    #[test]
    fn test_parse_detection() {
        let detection = ChronicleDetection {
            id: Some("det-001".to_string()),
            rule_name: Some("Suspicious Login".to_string()),
            rule_id: Some("rule-001".to_string()),
            severity: Some("high".to_string()),
            description: Some("Multiple failed logins".to_string()),
            detection_time: Some("2024-01-15T10:30:00Z".to_string()),
        };

        let alert = ChronicleConnector::parse_detection(&detection);
        assert_eq!(alert.id, "det-001");
        assert_eq!(alert.name, "Suspicious Login");
        assert_eq!(alert.severity, "high");
    }

    #[test]
    fn test_capabilities() {
        let c = ChronicleConnector::new(create_test_config()).unwrap();
        let caps = c.capabilities();
        assert!(caps.contains(&"search".to_string()));
    }
}
