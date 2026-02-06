//! Elastic Security connector.
//!
//! Provides integration with Elastic Security / Elasticsearch for SIEM operations
//! including search, alerts, and saved searches.

use crate::http::HttpClient;
use crate::traits::{
    ConnectorCategory, ConnectorError, ConnectorHealth, ConnectorResult, SIEMAlert, SIEMConnector,
    SIEMEvent, SavedSearch, SearchResults, SearchStats, TimeRange,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, instrument};

/// Elastic Security connector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElasticConfig {
    /// Base connector configuration.
    #[serde(flatten)]
    pub connector: crate::traits::ConnectorConfig,
    /// Default index pattern for searches.
    pub index_pattern: String,
    /// Kibana space ID (optional).
    pub space_id: Option<String>,
}

/// Elastic Security connector.
pub struct ElasticConnector {
    config: ElasticConfig,
    client: HttpClient,
}

impl ElasticConnector {
    /// Creates a new Elastic Security connector.
    pub fn new(config: ElasticConfig) -> ConnectorResult<Self> {
        let client = HttpClient::new(config.connector.clone())?;
        info!(
            "Elastic connector initialized with index pattern '{}'",
            config.index_pattern
        );
        Ok(Self { config, client })
    }

    fn parse_hit(hit: &ElasticHit) -> SIEMEvent {
        let source = &hit.source;
        let timestamp = source
            .get("@timestamp")
            .and_then(|v| v.as_str())
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);

        SIEMEvent {
            timestamp,
            raw: serde_json::to_string(source).unwrap_or_default(),
            fields: source.clone(),
            source: hit.index.clone().unwrap_or_default(),
        }
    }

    fn parse_alert(hit: &ElasticHit) -> SIEMAlert {
        let source = &hit.source;
        let timestamp = source
            .get("@timestamp")
            .and_then(|v| v.as_str())
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);

        SIEMAlert {
            id: hit.id.clone().unwrap_or_default(),
            name: source
                .get("signal")
                .and_then(|s| s.get("rule"))
                .and_then(|r| r.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or("Unknown Alert")
                .to_string(),
            severity: source
                .get("signal")
                .and_then(|s| s.get("rule"))
                .and_then(|r| r.get("severity"))
                .and_then(|s| s.as_str())
                .unwrap_or("medium")
                .to_string(),
            timestamp,
            details: source.clone(),
        }
    }
}

#[async_trait]
impl crate::traits::Connector for ElasticConnector {
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
        match self.client.get("/_cluster/health").await {
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
        let response = self.client.get("/_cluster/health").await?;
        Ok(response.status().is_success())
    }
}

#[async_trait]
impl SIEMConnector for ElasticConnector {
    #[instrument(skip(self))]
    async fn search(&self, query: &str, timerange: TimeRange) -> ConnectorResult<SearchResults> {
        let body = serde_json::json!({
            "query": {
                "bool": {
                    "must": [
                        { "query_string": { "query": query } },
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": timerange.start.to_rfc3339(),
                                    "lte": timerange.end.to_rfc3339()
                                }
                            }
                        }
                    ]
                }
            },
            "size": 100,
            "sort": [{ "@timestamp": "desc" }]
        });

        let path = format!("/{}/_search", self.config.index_pattern);
        let response = self.client.post(&path, &body).await?;

        if !response.status().is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ConnectorError::RequestFailed(format!(
                "Search failed: {}",
                body
            )));
        }

        let result: ElasticSearchResponse = response
            .json()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(format!("Parse error: {}", e)))?;

        let events: Vec<SIEMEvent> = result.hits.hits.iter().map(Self::parse_hit).collect();

        Ok(SearchResults {
            search_id: uuid::Uuid::new_v4().to_string(),
            total_count: result.hits.total.value,
            events,
            stats: Some(SearchStats {
                execution_time_ms: result.took,
                events_scanned: result.hits.total.value,
                bytes_scanned: 0,
            }),
        })
    }

    #[instrument(skip(self))]
    async fn get_saved_searches(&self) -> ConnectorResult<Vec<SavedSearch>> {
        let space_prefix = self
            .config
            .space_id
            .as_ref()
            .map(|s| format!("/s/{}", s))
            .unwrap_or_default();
        let path = format!(
            "{}/api/saved_objects/_find?type=search&per_page=100",
            space_prefix
        );

        let response = self.client.get(&path).await?;
        if !response.status().is_success() {
            return Ok(Vec::new());
        }

        let result: ElasticSavedObjectResponse = response
            .json()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(format!("Parse error: {}", e)))?;

        Ok(result
            .saved_objects
            .into_iter()
            .map(|so| SavedSearch {
                id: so.id,
                name: so
                    .attributes
                    .get("title")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Untitled")
                    .to_string(),
                query: so
                    .attributes
                    .get("kibanaSavedObjectMeta")
                    .and_then(|m| m.get("searchSourceJSON"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                alerts_enabled: false,
            })
            .collect())
    }

    #[instrument(skip(self))]
    async fn get_recent_alerts(&self, limit: usize) -> ConnectorResult<Vec<SIEMAlert>> {
        let space_prefix = self
            .config
            .space_id
            .as_ref()
            .map(|s| format!("/s/{}", s))
            .unwrap_or_default();
        let body = serde_json::json!({
            "query": { "match_all": {} },
            "size": limit,
            "sort": [{ "@timestamp": "desc" }]
        });

        let path = format!("{}/.siem-signals-*/_search", space_prefix);
        let response = self.client.post(&path, &body).await?;

        if !response.status().is_success() {
            return Ok(Vec::new());
        }

        let result: ElasticSearchResponse = response
            .json()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(format!("Parse error: {}", e)))?;

        Ok(result.hits.hits.iter().map(Self::parse_alert).collect())
    }

    #[instrument(skip(self))]
    async fn get_field_values(
        &self,
        field: &str,
        timerange: TimeRange,
        limit: usize,
    ) -> ConnectorResult<Vec<String>> {
        let body = serde_json::json!({
            "size": 0,
            "query": {
                "range": {
                    "@timestamp": {
                        "gte": timerange.start.to_rfc3339(),
                        "lte": timerange.end.to_rfc3339()
                    }
                }
            },
            "aggs": {
                "field_values": {
                    "terms": { "field": field, "size": limit }
                }
            }
        });

        let path = format!("/{}/_search", self.config.index_pattern);
        let response = self.client.post(&path, &body).await?;

        if !response.status().is_success() {
            return Ok(Vec::new());
        }

        let result: serde_json::Value = response
            .json()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(format!("Parse error: {}", e)))?;

        let buckets = result
            .get("aggregations")
            .and_then(|a| a.get("field_values"))
            .and_then(|f| f.get("buckets"))
            .and_then(|b| b.as_array())
            .cloned()
            .unwrap_or_default();

        Ok(buckets
            .iter()
            .filter_map(|b| b.get("key").and_then(|k| k.as_str()).map(String::from))
            .collect())
    }
}

// Elastic API response types

#[derive(Debug, Deserialize)]
struct ElasticSearchResponse {
    took: u64,
    hits: ElasticHits,
}

#[derive(Debug, Deserialize)]
struct ElasticHits {
    total: ElasticTotal,
    #[serde(default)]
    hits: Vec<ElasticHit>,
}

#[derive(Debug, Deserialize)]
struct ElasticTotal {
    value: u64,
}

#[derive(Debug, Deserialize)]
struct ElasticHit {
    #[serde(rename = "_id")]
    id: Option<String>,
    #[serde(rename = "_index")]
    index: Option<String>,
    #[serde(rename = "_source", default)]
    source: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct ElasticSavedObjectResponse {
    #[serde(default)]
    saved_objects: Vec<ElasticSavedObject>,
}

#[derive(Debug, Deserialize)]
struct ElasticSavedObject {
    id: String,
    #[serde(default)]
    attributes: HashMap<String, serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::test_connector_config;
    use crate::traits::Connector;

    fn create_test_config() -> ElasticConfig {
        ElasticConfig {
            connector: test_connector_config("elastic-test", "https://es.company.com:9200"),
            index_pattern: "security-*".to_string(),
            space_id: None,
        }
    }

    #[test]
    fn test_connector_creation() {
        assert!(ElasticConnector::new(create_test_config()).is_ok());
    }

    #[test]
    fn test_connector_name_and_category() {
        let c = ElasticConnector::new(create_test_config()).unwrap();
        assert_eq!(c.name(), "elastic-test");
        assert_eq!(c.connector_type(), "siem");
        assert_eq!(c.category(), ConnectorCategory::Siem);
    }

    #[test]
    fn test_parse_hit() {
        let hit = ElasticHit {
            id: Some("hit-001".to_string()),
            index: Some("security-2024.01.15".to_string()),
            source: {
                let mut m = HashMap::new();
                m.insert(
                    "@timestamp".to_string(),
                    serde_json::json!("2024-01-15T10:30:00Z"),
                );
                m.insert("message".to_string(), serde_json::json!("Test event"));
                m
            },
        };

        let event = ElasticConnector::parse_hit(&hit);
        assert_eq!(event.source, "security-2024.01.15");
        assert!(event.raw.contains("Test event"));
    }

    #[test]
    fn test_capabilities() {
        let c = ElasticConnector::new(create_test_config()).unwrap();
        let caps = c.capabilities();
        assert!(caps.contains(&"search".to_string()));
        assert!(caps.contains(&"get_recent_alerts".to_string()));
    }
}
