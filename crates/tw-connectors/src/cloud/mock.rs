//! Mock cloud connector for testing.
//!
//! Provides a configurable mock connector for testing cloud security operations
//! including alert fetching, enrichment, and response actions.

use crate::traits::{
    Action, ActionExecutor, ActionResult, ActionType, AlertSource, ConnectorCategory,
    ConnectorError, ConnectorHealth, ConnectorResult, Enricher, EnrichmentResult, Ioc, IocType,
    RawAlert,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Mock cloud connector for testing.
pub struct MockCloudConnector {
    name: String,
    alerts: Arc<RwLock<Vec<RawAlert>>>,
    acknowledged: Arc<RwLock<Vec<String>>>,
    healthy: Arc<RwLock<bool>>,
}

impl MockCloudConnector {
    /// Creates a new mock cloud connector.
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            alerts: Arc::new(RwLock::new(Vec::new())),
            acknowledged: Arc::new(RwLock::new(Vec::new())),
            healthy: Arc::new(RwLock::new(true)),
        }
    }

    /// Creates a mock cloud connector with sample alerts.
    pub fn with_sample_data(name: &str) -> Self {
        let now = Utc::now();
        let alerts = vec![
            RawAlert {
                id: "cloud-alert-001".to_string(),
                title: "Unauthorized API Call Detected".to_string(),
                description: "An API call from an unauthorized source IP was detected".to_string(),
                severity: "high".to_string(),
                timestamp: now - chrono::Duration::minutes(30),
                source: "mock_cloud".to_string(),
                raw_data: {
                    let mut m = HashMap::new();
                    m.insert("source_ip".to_string(), serde_json::json!("203.0.113.50"));
                    m.insert("api_call".to_string(), serde_json::json!("RunInstances"));
                    m
                },
            },
            RawAlert {
                id: "cloud-alert-002".to_string(),
                title: "Publicly Exposed Storage Bucket".to_string(),
                description: "A storage bucket was configured with public read access".to_string(),
                severity: "critical".to_string(),
                timestamp: now - chrono::Duration::minutes(15),
                source: "mock_cloud".to_string(),
                raw_data: {
                    let mut m = HashMap::new();
                    m.insert(
                        "bucket_name".to_string(),
                        serde_json::json!("sensitive-data-bucket"),
                    );
                    m.insert("access_level".to_string(), serde_json::json!("public-read"));
                    m
                },
            },
            RawAlert {
                id: "cloud-alert-003".to_string(),
                title: "Suspicious IAM Policy Change".to_string(),
                description: "Admin policy was attached to a new role".to_string(),
                severity: "medium".to_string(),
                timestamp: now - chrono::Duration::minutes(5),
                source: "mock_cloud".to_string(),
                raw_data: HashMap::new(),
            },
        ];

        Self {
            name: name.to_string(),
            alerts: Arc::new(RwLock::new(alerts)),
            acknowledged: Arc::new(RwLock::new(Vec::new())),
            healthy: Arc::new(RwLock::new(true)),
        }
    }

    /// Adds an alert to the mock.
    pub async fn add_alert(&self, alert: RawAlert) {
        self.alerts.write().await.push(alert);
    }

    /// Sets the health status of the mock.
    pub async fn set_healthy(&self, healthy: bool) {
        *self.healthy.write().await = healthy;
    }

    /// Gets acknowledged alert IDs for test verification.
    pub async fn get_acknowledged(&self) -> Vec<String> {
        self.acknowledged.read().await.clone()
    }
}

#[async_trait]
impl crate::traits::Connector for MockCloudConnector {
    fn name(&self) -> &str {
        &self.name
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
            "enrich".to_string(),
            "execute_action".to_string(),
        ]
    }

    async fn health_check(&self) -> ConnectorResult<ConnectorHealth> {
        if *self.healthy.read().await {
            Ok(ConnectorHealth::Healthy)
        } else {
            Ok(ConnectorHealth::Unhealthy("Mock unhealthy".to_string()))
        }
    }

    async fn test_connection(&self) -> ConnectorResult<bool> {
        Ok(*self.healthy.read().await)
    }
}

#[async_trait]
impl AlertSource for MockCloudConnector {
    async fn fetch_alerts(
        &self,
        since: DateTime<Utc>,
        limit: Option<usize>,
    ) -> ConnectorResult<Vec<RawAlert>> {
        let alerts = self.alerts.read().await;
        let filtered: Vec<RawAlert> = alerts
            .iter()
            .filter(|a| a.timestamp >= since)
            .take(limit.unwrap_or(usize::MAX))
            .cloned()
            .collect();
        Ok(filtered)
    }

    async fn acknowledge_alert(&self, alert_id: &str) -> ConnectorResult<()> {
        let alerts = self.alerts.read().await;
        if !alerts.iter().any(|a| a.id == alert_id) {
            return Err(ConnectorError::NotFound(format!(
                "Alert not found: {}",
                alert_id
            )));
        }
        self.acknowledged.write().await.push(alert_id.to_string());
        Ok(())
    }
}

#[async_trait]
impl Enricher for MockCloudConnector {
    fn supported_ioc_types(&self) -> Vec<IocType> {
        vec![IocType::IpAddress, IocType::Domain]
    }

    async fn enrich(&self, ioc: &Ioc) -> ConnectorResult<EnrichmentResult> {
        let mut data = HashMap::new();
        data.insert(
            "source".to_string(),
            serde_json::json!("mock_cloud_enrichment"),
        );

        Ok(EnrichmentResult {
            ioc: ioc.clone(),
            found: true,
            risk_score: Some(50),
            data,
            source: "mock_cloud".to_string(),
            enriched_at: Utc::now(),
        })
    }
}

#[async_trait]
impl ActionExecutor for MockCloudConnector {
    fn supported_actions(&self) -> Vec<ActionType> {
        vec![ActionType::BlockIp, ActionType::IsolateHost]
    }

    async fn execute_action(&self, action: &Action) -> ConnectorResult<ActionResult> {
        Ok(ActionResult {
            success: true,
            action_id: format!("mock-action-{}", uuid::Uuid::new_v4()),
            message: format!(
                "Mock action {:?} executed on {}",
                action.action_type, action.target
            ),
            timestamp: Utc::now(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::Connector;

    #[test]
    fn test_mock_creation() {
        let connector = MockCloudConnector::new("test-cloud");
        assert_eq!(connector.name(), "test-cloud");
        assert_eq!(connector.connector_type(), "cloud");
        assert_eq!(connector.category(), ConnectorCategory::Cloud);
    }

    #[tokio::test]
    async fn test_mock_health_check() {
        let connector = MockCloudConnector::new("test-cloud");

        let health = connector.health_check().await.unwrap();
        assert!(matches!(health, ConnectorHealth::Healthy));

        connector.set_healthy(false).await;
        let health = connector.health_check().await.unwrap();
        assert!(matches!(health, ConnectorHealth::Unhealthy(_)));
    }

    #[tokio::test]
    async fn test_mock_fetch_alerts() {
        let connector = MockCloudConnector::with_sample_data("test-cloud");
        let since = Utc::now() - chrono::Duration::hours(1);

        let alerts = connector.fetch_alerts(since, None).await.unwrap();
        assert_eq!(alerts.len(), 3);
        assert_eq!(alerts[0].id, "cloud-alert-001");
    }

    #[tokio::test]
    async fn test_mock_fetch_alerts_with_limit() {
        let connector = MockCloudConnector::with_sample_data("test-cloud");
        let since = Utc::now() - chrono::Duration::hours(1);

        let alerts = connector.fetch_alerts(since, Some(1)).await.unwrap();
        assert_eq!(alerts.len(), 1);
    }

    #[tokio::test]
    async fn test_mock_acknowledge_alert() {
        let connector = MockCloudConnector::with_sample_data("test-cloud");

        connector
            .acknowledge_alert("cloud-alert-001")
            .await
            .unwrap();

        let acknowledged = connector.get_acknowledged().await;
        assert_eq!(acknowledged, vec!["cloud-alert-001"]);
    }

    #[tokio::test]
    async fn test_mock_acknowledge_nonexistent() {
        let connector = MockCloudConnector::with_sample_data("test-cloud");
        let result = connector.acknowledge_alert("nonexistent").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_mock_enrich() {
        let connector = MockCloudConnector::new("test-cloud");
        let ioc = Ioc {
            ioc_type: IocType::IpAddress,
            value: "10.0.0.1".to_string(),
        };

        let result = connector.enrich(&ioc).await.unwrap();
        assert!(result.found);
        assert_eq!(result.risk_score, Some(50));
    }

    #[tokio::test]
    async fn test_mock_execute_action() {
        let connector = MockCloudConnector::new("test-cloud");
        let action = Action {
            action_type: ActionType::BlockIp,
            target: "203.0.113.50".to_string(),
            reason: "Malicious activity".to_string(),
            parameters: HashMap::new(),
        };

        let result = connector.execute_action(&action).await.unwrap();
        assert!(result.success);
    }

    #[test]
    fn test_mock_supported_actions() {
        let connector = MockCloudConnector::new("test-cloud");
        let actions = connector.supported_actions();
        assert!(actions.contains(&ActionType::BlockIp));
        assert!(actions.contains(&ActionType::IsolateHost));
    }
}
