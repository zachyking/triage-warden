//! Mock SIEM connector for testing.
//!
//! Provides a configurable mock connector for testing SIEM searches and alert
//! handling without making real API calls. Supports failure injection and
//! scenario-based testing.

use crate::traits::{
    ConnectorError, ConnectorHealth, ConnectorResult, SIEMAlert, SIEMConnector, SIEMEvent,
    SavedSearch, SearchResults, SearchStats, TimeRange,
};
use async_trait::async_trait;
use chrono::{Duration, Utc};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Behavior configuration for failure injection.
#[derive(Debug, Clone)]
pub enum MockBehavior {
    /// Normal operation.
    Normal,
    /// Fail after N calls.
    FailAfter { calls: u64, error: ConnectorError },
    /// Simulate slow searches.
    SlowSearch(std::time::Duration),
    /// Always fail.
    AlwaysFail(ConnectorError),
    /// Unhealthy status.
    Unhealthy(String),
}

impl Default for MockBehavior {
    fn default() -> Self {
        Self::Normal
    }
}

/// Mock SIEM connector for testing.
pub struct MockSIEMConnector {
    name: String,
    events: Arc<RwLock<Vec<SIEMEvent>>>,
    alerts: Arc<RwLock<Vec<SIEMAlert>>>,
    saved_searches: Arc<RwLock<Vec<SavedSearch>>>,
    behavior: Arc<RwLock<MockBehavior>>,
    call_count: AtomicU64,
    search_history: Arc<RwLock<Vec<SearchRecord>>>,
}

/// Record of a search for test verification.
#[derive(Debug, Clone)]
pub struct SearchRecord {
    pub query: String,
    pub timerange: TimeRange,
    pub timestamp: chrono::DateTime<Utc>,
    pub result_count: u64,
}

impl MockSIEMConnector {
    /// Creates a new mock SIEM connector.
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            events: Arc::new(RwLock::new(Vec::new())),
            alerts: Arc::new(RwLock::new(Vec::new())),
            saved_searches: Arc::new(RwLock::new(Self::default_saved_searches())),
            behavior: Arc::new(RwLock::new(MockBehavior::Normal)),
            call_count: AtomicU64::new(0),
            search_history: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Creates a mock SIEM connector with sample security data.
    pub fn with_sample_data(name: &str) -> Self {
        Self {
            name: name.to_string(),
            events: Arc::new(RwLock::new(Self::generate_sample_events())),
            alerts: Arc::new(RwLock::new(Self::generate_sample_alerts())),
            saved_searches: Arc::new(RwLock::new(Self::default_saved_searches())),
            behavior: Arc::new(RwLock::new(MockBehavior::Normal)),
            call_count: AtomicU64::new(0),
            search_history: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Creates sample events with lazy initialization (async version).
    pub async fn with_sample_data_async(name: &str) -> Self {
        Self::with_sample_data(name)
    }

    fn generate_sample_events() -> Vec<SIEMEvent> {
        let now = Utc::now();
        vec![
            SIEMEvent {
                timestamp: now - Duration::minutes(30),
                raw: r#"{"event": "login_failure", "user": "admin", "src_ip": "192.168.1.100", "reason": "invalid_password"}"#.to_string(),
                fields: {
                    let mut m = HashMap::new();
                    m.insert("event".to_string(), serde_json::json!("login_failure"));
                    m.insert("user".to_string(), serde_json::json!("admin"));
                    m.insert("src_ip".to_string(), serde_json::json!("192.168.1.100"));
                    m.insert("reason".to_string(), serde_json::json!("invalid_password"));
                    m
                },
                source: "auth_logs".to_string(),
            },
            SIEMEvent {
                timestamp: now - Duration::minutes(25),
                raw: r#"{"event": "login_failure", "user": "admin", "src_ip": "192.168.1.100", "reason": "invalid_password"}"#.to_string(),
                fields: {
                    let mut m = HashMap::new();
                    m.insert("event".to_string(), serde_json::json!("login_failure"));
                    m.insert("user".to_string(), serde_json::json!("admin"));
                    m.insert("src_ip".to_string(), serde_json::json!("192.168.1.100"));
                    m.insert("reason".to_string(), serde_json::json!("invalid_password"));
                    m
                },
                source: "auth_logs".to_string(),
            },
            SIEMEvent {
                timestamp: now - Duration::minutes(20),
                raw: r#"{"event": "login_success", "user": "admin", "src_ip": "192.168.1.100"}"#.to_string(),
                fields: {
                    let mut m = HashMap::new();
                    m.insert("event".to_string(), serde_json::json!("login_success"));
                    m.insert("user".to_string(), serde_json::json!("admin"));
                    m.insert("src_ip".to_string(), serde_json::json!("192.168.1.100"));
                    m
                },
                source: "auth_logs".to_string(),
            },
            SIEMEvent {
                timestamp: now - Duration::minutes(15),
                raw: r#"{"event": "file_access", "user": "jsmith", "file": "/etc/passwd", "action": "read"}"#.to_string(),
                fields: {
                    let mut m = HashMap::new();
                    m.insert("event".to_string(), serde_json::json!("file_access"));
                    m.insert("user".to_string(), serde_json::json!("jsmith"));
                    m.insert("file".to_string(), serde_json::json!("/etc/passwd"));
                    m.insert("action".to_string(), serde_json::json!("read"));
                    m
                },
                source: "file_logs".to_string(),
            },
            SIEMEvent {
                timestamp: now - Duration::minutes(10),
                raw: r#"{"event": "process_execution", "host": "workstation-001", "process": "powershell.exe", "command": "-enc SGVsbG8gV29ybGQ="}"#.to_string(),
                fields: {
                    let mut m = HashMap::new();
                    m.insert("event".to_string(), serde_json::json!("process_execution"));
                    m.insert("host".to_string(), serde_json::json!("workstation-001"));
                    m.insert("process".to_string(), serde_json::json!("powershell.exe"));
                    m.insert("command".to_string(), serde_json::json!("-enc SGVsbG8gV29ybGQ="));
                    m
                },
                source: "edr_logs".to_string(),
            },
            SIEMEvent {
                timestamp: now - Duration::minutes(5),
                raw: r#"{"event": "network_connection", "host": "workstation-001", "dest_ip": "203.0.113.100", "dest_port": 443}"#.to_string(),
                fields: {
                    let mut m = HashMap::new();
                    m.insert("event".to_string(), serde_json::json!("network_connection"));
                    m.insert("host".to_string(), serde_json::json!("workstation-001"));
                    m.insert("dest_ip".to_string(), serde_json::json!("203.0.113.100"));
                    m.insert("dest_port".to_string(), serde_json::json!(443));
                    m
                },
                source: "network_logs".to_string(),
            },
        ]
    }

    fn generate_sample_alerts() -> Vec<SIEMAlert> {
        let now = Utc::now();
        vec![
            SIEMAlert {
                id: "alert-001".to_string(),
                name: "Multiple Login Failures".to_string(),
                severity: "high".to_string(),
                timestamp: now - Duration::minutes(20),
                details: {
                    let mut m = HashMap::new();
                    m.insert("user".to_string(), serde_json::json!("admin"));
                    m.insert("count".to_string(), serde_json::json!(10));
                    m.insert("src_ip".to_string(), serde_json::json!("192.168.1.100"));
                    m
                },
            },
            SIEMAlert {
                id: "alert-002".to_string(),
                name: "Suspicious File Access".to_string(),
                severity: "medium".to_string(),
                timestamp: now - Duration::minutes(15),
                details: {
                    let mut m = HashMap::new();
                    m.insert("user".to_string(), serde_json::json!("jsmith"));
                    m.insert("file".to_string(), serde_json::json!("/etc/passwd"));
                    m
                },
            },
            SIEMAlert {
                id: "alert-003".to_string(),
                name: "Encoded PowerShell Command".to_string(),
                severity: "high".to_string(),
                timestamp: now - Duration::minutes(10),
                details: {
                    let mut m = HashMap::new();
                    m.insert("host".to_string(), serde_json::json!("workstation-001"));
                    m.insert("process".to_string(), serde_json::json!("powershell.exe"));
                    m.insert("technique".to_string(), serde_json::json!("T1059.001"));
                    m
                },
            },
            SIEMAlert {
                id: "alert-004".to_string(),
                name: "Connection to Known Malicious IP".to_string(),
                severity: "critical".to_string(),
                timestamp: now - Duration::minutes(5),
                details: {
                    let mut m = HashMap::new();
                    m.insert("host".to_string(), serde_json::json!("workstation-001"));
                    m.insert("dest_ip".to_string(), serde_json::json!("203.0.113.100"));
                    m.insert("threat_intel".to_string(), serde_json::json!("botnet_c2"));
                    m
                },
            },
        ]
    }

    fn default_saved_searches() -> Vec<SavedSearch> {
        vec![
            SavedSearch {
                id: "ss-001".to_string(),
                name: "Failed Logins".to_string(),
                query: "event=login_failure".to_string(),
                alerts_enabled: true,
            },
            SavedSearch {
                id: "ss-002".to_string(),
                name: "Suspicious File Access".to_string(),
                query: "event=file_access file=/etc/*".to_string(),
                alerts_enabled: true,
            },
            SavedSearch {
                id: "ss-003".to_string(),
                name: "Encoded Commands".to_string(),
                query: "process=powershell.exe command=*-enc*".to_string(),
                alerts_enabled: true,
            },
            SavedSearch {
                id: "ss-004".to_string(),
                name: "Outbound Connections".to_string(),
                query: "event=network_connection".to_string(),
                alerts_enabled: false,
            },
        ]
    }

    /// Adds an event to the mock.
    pub async fn add_event(&self, event: SIEMEvent) {
        let mut events = self.events.write().await;
        events.push(event);
    }

    /// Adds multiple events.
    pub async fn add_events(&self, new_events: Vec<SIEMEvent>) {
        let mut events = self.events.write().await;
        events.extend(new_events);
    }

    /// Adds an alert to the mock.
    pub async fn add_alert(&self, alert: SIEMAlert) {
        let mut alerts = self.alerts.write().await;
        alerts.push(alert);
    }

    /// Sets the behavior for failure injection.
    pub async fn set_behavior(&self, behavior: MockBehavior) {
        let mut b = self.behavior.write().await;
        *b = behavior;
    }

    /// Gets the search history for test verification.
    pub async fn get_search_history(&self) -> Vec<SearchRecord> {
        let history = self.search_history.read().await;
        history.clone()
    }

    /// Clears all data.
    pub async fn clear(&self) {
        self.events.write().await.clear();
        self.alerts.write().await.clear();
        self.search_history.write().await.clear();
        self.call_count.store(0, Ordering::SeqCst);
    }

    /// Check behavior and apply any configured effects.
    async fn check_behavior(&self) -> ConnectorResult<()> {
        let count = self.call_count.fetch_add(1, Ordering::SeqCst) + 1;
        let behavior = self.behavior.read().await;

        match &*behavior {
            MockBehavior::Normal => Ok(()),
            MockBehavior::FailAfter { calls, error } => {
                if count > *calls {
                    Err(error.clone())
                } else {
                    Ok(())
                }
            }
            MockBehavior::SlowSearch(duration) => {
                tokio::time::sleep(*duration).await;
                Ok(())
            }
            MockBehavior::AlwaysFail(error) => Err(error.clone()),
            MockBehavior::Unhealthy(_) => Ok(()),
        }
    }
}

#[async_trait]
impl crate::traits::Connector for MockSIEMConnector {
    fn name(&self) -> &str {
        &self.name
    }

    fn connector_type(&self) -> &str {
        "siem"
    }

    async fn health_check(&self) -> ConnectorResult<ConnectorHealth> {
        let behavior = self.behavior.read().await;
        match &*behavior {
            MockBehavior::Unhealthy(reason) => Ok(ConnectorHealth::Unhealthy(reason.clone())),
            MockBehavior::AlwaysFail(_) => {
                Ok(ConnectorHealth::Unhealthy("Always failing".to_string()))
            }
            _ => Ok(ConnectorHealth::Healthy),
        }
    }

    async fn test_connection(&self) -> ConnectorResult<bool> {
        let behavior = self.behavior.read().await;
        match &*behavior {
            MockBehavior::AlwaysFail(e) => Err(e.clone()),
            MockBehavior::Unhealthy(_) => Ok(false),
            _ => Ok(true),
        }
    }
}

#[async_trait]
impl SIEMConnector for MockSIEMConnector {
    async fn search(&self, query: &str, timerange: TimeRange) -> ConnectorResult<SearchResults> {
        self.check_behavior().await?;

        let events = self.events.read().await;
        let start_time = std::time::Instant::now();

        // Simple filtering based on whether the query appears in the raw event
        let filtered: Vec<SIEMEvent> = events
            .iter()
            .filter(|e| {
                e.timestamp >= timerange.start
                    && e.timestamp <= timerange.end
                    && (query.is_empty() || e.raw.to_lowercase().contains(&query.to_lowercase()))
            })
            .cloned()
            .collect();

        let result_count = filtered.len() as u64;

        // Record the search
        {
            let mut history = self.search_history.write().await;
            history.push(SearchRecord {
                query: query.to_string(),
                timerange: timerange.clone(),
                timestamp: Utc::now(),
                result_count,
            });
        }

        Ok(SearchResults {
            search_id: format!("search-{}", uuid::Uuid::new_v4()),
            total_count: result_count,
            events: filtered,
            stats: Some(SearchStats {
                execution_time_ms: start_time.elapsed().as_millis() as u64,
                events_scanned: events.len() as u64,
                bytes_scanned: events.iter().map(|e| e.raw.len() as u64).sum(),
            }),
        })
    }

    async fn get_saved_searches(&self) -> ConnectorResult<Vec<SavedSearch>> {
        self.check_behavior().await?;
        let searches = self.saved_searches.read().await;
        Ok(searches.clone())
    }

    async fn get_recent_alerts(&self, limit: usize) -> ConnectorResult<Vec<SIEMAlert>> {
        self.check_behavior().await?;
        let alerts = self.alerts.read().await;

        // Return most recent first
        let mut sorted: Vec<SIEMAlert> = alerts.clone();
        sorted.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        sorted.truncate(limit);

        Ok(sorted)
    }

    async fn get_field_values(
        &self,
        field: &str,
        timerange: TimeRange,
        limit: usize,
    ) -> ConnectorResult<Vec<String>> {
        self.check_behavior().await?;

        let events = self.events.read().await;
        let mut values: Vec<String> = events
            .iter()
            .filter(|e| e.timestamp >= timerange.start && e.timestamp <= timerange.end)
            .filter_map(|e| {
                e.fields.get(field).and_then(|v| match v {
                    serde_json::Value::String(s) => Some(s.clone()),
                    serde_json::Value::Number(n) => Some(n.to_string()),
                    serde_json::Value::Bool(b) => Some(b.to_string()),
                    _ => None,
                })
            })
            .collect();

        values.sort();
        values.dedup();
        values.truncate(limit);

        Ok(values)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_search() {
        let connector = MockSIEMConnector::with_sample_data_async("test").await;
        let results = connector
            .search("login_failure", TimeRange::last_hours(24))
            .await
            .unwrap();

        assert!(results.total_count >= 1);
    }

    #[tokio::test]
    async fn test_search_empty_query() {
        let connector = MockSIEMConnector::with_sample_data_async("test").await;
        let results = connector
            .search("", TimeRange::last_hours(24))
            .await
            .unwrap();

        // Should return all events in the time range
        assert!(results.total_count > 0);
    }

    #[tokio::test]
    async fn test_get_alerts() {
        let connector = MockSIEMConnector::with_sample_data_async("test").await;
        let alerts = connector.get_recent_alerts(10).await.unwrap();

        assert!(!alerts.is_empty());
        // Should be sorted by timestamp descending
        for i in 1..alerts.len() {
            assert!(alerts[i - 1].timestamp >= alerts[i].timestamp);
        }
    }

    #[tokio::test]
    async fn test_get_field_values() {
        let connector = MockSIEMConnector::with_sample_data_async("test").await;
        let values = connector
            .get_field_values("user", TimeRange::last_hours(24), 10)
            .await
            .unwrap();

        assert!(values.contains(&"admin".to_string()));
    }

    #[tokio::test]
    async fn test_failure_injection() {
        let connector = MockSIEMConnector::new("test");
        connector
            .set_behavior(MockBehavior::AlwaysFail(ConnectorError::ConnectionFailed(
                "Test failure".to_string(),
            )))
            .await;

        let result = connector.search("test", TimeRange::last_hours(1)).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_search_history() {
        let connector = MockSIEMConnector::new("test");

        connector
            .search("query1", TimeRange::last_hours(1))
            .await
            .ok();
        connector
            .search("query2", TimeRange::last_hours(2))
            .await
            .ok();

        let history = connector.get_search_history().await;
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].query, "query1");
        assert_eq!(history[1].query, "query2");
    }
}
