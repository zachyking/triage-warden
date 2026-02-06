//! IBM QRadar SIEM connector.
//!
//! Provides integration with IBM QRadar for AQL searches, offense/alert retrieval,
//! and saved search management.

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

/// QRadar connector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QRadarConfig {
    /// Base connector configuration.
    #[serde(flatten)]
    pub connector: crate::traits::ConnectorConfig,
    /// QRadar console hostname.
    pub console_hostname: String,
}

/// IBM QRadar SIEM connector.
pub struct QRadarConnector {
    config: QRadarConfig,
    client: HttpClient,
}

impl QRadarConnector {
    /// Creates a new QRadar connector.
    pub fn new(config: QRadarConfig) -> ConnectorResult<Self> {
        let client = HttpClient::new(config.connector.clone())?;
        info!(
            "QRadar connector initialized for '{}'",
            config.console_hostname
        );
        Ok(Self { config, client })
    }

    fn parse_event(event: &QRadarEvent) -> SIEMEvent {
        let timestamp = event
            .start_time
            .and_then(DateTime::from_timestamp_millis)
            .unwrap_or_else(Utc::now);

        let mut fields = HashMap::new();
        if let Some(ref src) = event.source_ip {
            fields.insert("source_ip".to_string(), serde_json::json!(src));
        }
        if let Some(ref dst) = event.destination_ip {
            fields.insert("destination_ip".to_string(), serde_json::json!(dst));
        }
        if let Some(cat) = event.category {
            fields.insert("category".to_string(), serde_json::json!(cat));
        }
        if let Some(mag) = event.magnitude {
            fields.insert("magnitude".to_string(), serde_json::json!(mag));
        }

        SIEMEvent {
            timestamp,
            raw: serde_json::to_string(&fields).unwrap_or_default(),
            fields,
            source: "qradar".to_string(),
        }
    }

    fn parse_offense(offense: &QRadarOffense) -> SIEMAlert {
        let timestamp = offense
            .start_time
            .and_then(DateTime::from_timestamp_millis)
            .unwrap_or_else(Utc::now);

        let severity = match offense.severity {
            Some(s) if s >= 8 => "critical",
            Some(s) if s >= 6 => "high",
            Some(s) if s >= 4 => "medium",
            _ => "low",
        };

        SIEMAlert {
            id: offense.id.map(|i| i.to_string()).unwrap_or_default(),
            name: offense
                .description
                .clone()
                .unwrap_or_else(|| "Unknown Offense".to_string()),
            severity: severity.to_string(),
            timestamp,
            details: {
                let mut d = HashMap::new();
                if let Some(ref cats) = offense.categories {
                    d.insert("categories".to_string(), serde_json::json!(cats));
                }
                if let Some(count) = offense.event_count {
                    d.insert("event_count".to_string(), serde_json::json!(count));
                }
                if let Some(ref status) = offense.status {
                    d.insert("status".to_string(), serde_json::json!(status));
                }
                d
            },
        }
    }
}

#[async_trait]
impl crate::traits::Connector for QRadarConnector {
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
        match self.client.get("/api/system/about").await {
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
        let response = self.client.get("/api/system/about").await?;
        Ok(response.status().is_success())
    }
}

#[async_trait]
impl SIEMConnector for QRadarConnector {
    #[instrument(skip(self))]
    async fn search(&self, query: &str, timerange: TimeRange) -> ConnectorResult<SearchResults> {
        let aql = format!(
            "{} START '{}' STOP '{}'",
            query,
            timerange.start.format("%Y-%m-%d %H:%M"),
            timerange.end.format("%Y-%m-%d %H:%M")
        );

        let body = serde_json::json!({
            "query_expression": aql
        });

        let response = self.client.post("/api/ariel/searches", &body).await?;
        if !response.status().is_success() {
            let err = response.text().await.unwrap_or_default();
            return Err(ConnectorError::RequestFailed(format!(
                "AQL search failed: {}",
                err
            )));
        }

        let search_resp: QRadarSearchResponse = response
            .json()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(format!("Parse error: {}", e)))?;

        let search_id = search_resp.search_id;

        // Get results
        let result_path = format!("/api/ariel/searches/{}/results", search_id);
        let response = self.client.get(&result_path).await?;

        if !response.status().is_success() {
            return Ok(SearchResults {
                search_id,
                total_count: 0,
                events: Vec::new(),
                stats: None,
            });
        }

        let result: QRadarSearchResults = response
            .json()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(format!("Parse error: {}", e)))?;

        let events: Vec<SIEMEvent> = result.events.iter().map(Self::parse_event).collect();

        Ok(SearchResults {
            search_id,
            total_count: events.len() as u64,
            events,
            stats: None,
        })
    }

    #[instrument(skip(self))]
    async fn get_saved_searches(&self) -> ConnectorResult<Vec<SavedSearch>> {
        let response = self
            .client
            .get("/api/ariel/saved_searches?fields=id,name,aql")
            .await?;

        if !response.status().is_success() {
            return Ok(Vec::new());
        }

        let searches: Vec<QRadarSavedSearch> = response
            .json()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(format!("Parse error: {}", e)))?;

        Ok(searches
            .into_iter()
            .map(|s| SavedSearch {
                id: s.id.to_string(),
                name: s.name,
                query: s.aql.unwrap_or_default(),
                alerts_enabled: false,
            })
            .collect())
    }

    #[instrument(skip(self))]
    async fn get_recent_alerts(&self, limit: usize) -> ConnectorResult<Vec<SIEMAlert>> {
        let path = format!(
            "/api/siem/offenses?filter=status=OPEN&Range=items=0-{}&sort=-start_time",
            limit.saturating_sub(1)
        );

        let response = self.client.get(&path).await?;
        if !response.status().is_success() {
            return Ok(Vec::new());
        }

        let offenses: Vec<QRadarOffense> = response
            .json()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(format!("Parse error: {}", e)))?;

        Ok(offenses.iter().map(Self::parse_offense).collect())
    }

    #[instrument(skip(self))]
    async fn get_field_values(
        &self,
        field: &str,
        timerange: TimeRange,
        limit: usize,
    ) -> ConnectorResult<Vec<String>> {
        let aql = format!(
            "SELECT DISTINCT({}) as val FROM events START '{}' STOP '{}' LIMIT {}",
            field,
            timerange.start.format("%Y-%m-%d %H:%M"),
            timerange.end.format("%Y-%m-%d %H:%M"),
            limit
        );

        let body = serde_json::json!({ "query_expression": aql });
        let response = self.client.post("/api/ariel/searches", &body).await?;

        if !response.status().is_success() {
            return Ok(Vec::new());
        }

        let search_resp: QRadarSearchResponse = response
            .json()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(format!("Parse error: {}", e)))?;

        let result_path = format!("/api/ariel/searches/{}/results", search_resp.search_id);
        let response = self.client.get(&result_path).await?;

        if !response.status().is_success() {
            return Ok(Vec::new());
        }

        let result: serde_json::Value = response
            .json()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(format!("Parse error: {}", e)))?;

        let values = result
            .get("events")
            .and_then(|e| e.as_array())
            .cloned()
            .unwrap_or_default();

        Ok(values
            .iter()
            .filter_map(|v| v.get("val").and_then(|v| v.as_str()).map(String::from))
            .collect())
    }
}

// QRadar API response types

#[derive(Debug, Deserialize)]
struct QRadarSearchResponse {
    search_id: String,
}

#[derive(Debug, Default, Deserialize)]
struct QRadarSearchResults {
    #[serde(default)]
    events: Vec<QRadarEvent>,
}

#[derive(Debug, Deserialize)]
struct QRadarEvent {
    #[serde(rename = "starttime")]
    start_time: Option<i64>,
    #[serde(rename = "sourceip")]
    source_ip: Option<String>,
    #[serde(rename = "destinationip")]
    destination_ip: Option<String>,
    category: Option<i64>,
    magnitude: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct QRadarOffense {
    id: Option<i64>,
    description: Option<String>,
    severity: Option<i64>,
    start_time: Option<i64>,
    categories: Option<Vec<String>>,
    event_count: Option<i64>,
    status: Option<String>,
}

#[derive(Debug, Deserialize)]
struct QRadarSavedSearch {
    id: i64,
    name: String,
    aql: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::test_connector_config;
    use crate::traits::Connector;

    fn create_test_config() -> QRadarConfig {
        QRadarConfig {
            connector: test_connector_config("qradar-test", "https://qradar.company.com"),
            console_hostname: "qradar.company.com".to_string(),
        }
    }

    #[test]
    fn test_connector_creation() {
        assert!(QRadarConnector::new(create_test_config()).is_ok());
    }

    #[test]
    fn test_connector_name_and_category() {
        let c = QRadarConnector::new(create_test_config()).unwrap();
        assert_eq!(c.name(), "qradar-test");
        assert_eq!(c.connector_type(), "siem");
        assert_eq!(c.category(), ConnectorCategory::Siem);
    }

    #[test]
    fn test_parse_offense_high_severity() {
        let offense = QRadarOffense {
            id: Some(1001),
            description: Some("Possible data exfiltration".to_string()),
            severity: Some(9),
            start_time: Some(1705312200000),
            categories: Some(vec!["Data Exfiltration".to_string()]),
            event_count: Some(150),
            status: Some("OPEN".to_string()),
        };

        let alert = QRadarConnector::parse_offense(&offense);
        assert_eq!(alert.id, "1001");
        assert_eq!(alert.severity, "critical");
    }

    #[test]
    fn test_parse_offense_low_severity() {
        let offense = QRadarOffense {
            id: Some(1002),
            description: Some("Port scan detected".to_string()),
            severity: Some(3),
            start_time: None,
            categories: None,
            event_count: Some(10),
            status: Some("OPEN".to_string()),
        };

        let alert = QRadarConnector::parse_offense(&offense);
        assert_eq!(alert.severity, "low");
    }

    #[test]
    fn test_capabilities() {
        let c = QRadarConnector::new(create_test_config()).unwrap();
        let caps = c.capabilities();
        assert!(caps.contains(&"search".to_string()));
    }
}
