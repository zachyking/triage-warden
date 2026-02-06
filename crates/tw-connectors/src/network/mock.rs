//! Mock network security connector for testing.

use crate::traits::{
    ActionResult, ConnectorHealth, ConnectorResult, NetworkEvent, NetworkSecurityConnector,
    TimeRange,
};
use async_trait::async_trait;
use chrono::{Duration, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Mock network security connector for testing.
pub struct MockNetworkConnector {
    name: String,
    events: Arc<RwLock<Vec<NetworkEvent>>>,
    blocked_ips: Arc<RwLock<Vec<String>>>,
    blocked_domains: Arc<RwLock<Vec<String>>>,
}

impl MockNetworkConnector {
    /// Creates a new mock network connector.
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            events: Arc::new(RwLock::new(Vec::new())),
            blocked_ips: Arc::new(RwLock::new(Vec::new())),
            blocked_domains: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Creates a mock with sample data.
    pub fn with_sample_data(name: &str) -> Self {
        let now = Utc::now();
        let events = vec![
            NetworkEvent {
                id: "evt-001".to_string(),
                timestamp: now - Duration::minutes(10),
                event_type: "threat".to_string(),
                severity: "high".to_string(),
                source_ip: Some("192.168.1.100".to_string()),
                destination_ip: Some("203.0.113.50".to_string()),
                source_port: Some(54321),
                destination_port: Some(443),
                protocol: Some("TCP".to_string()),
                action: "deny".to_string(),
                rule: Some("block-malicious-ips".to_string()),
                details: HashMap::new(),
            },
            NetworkEvent {
                id: "evt-002".to_string(),
                timestamp: now - Duration::minutes(5),
                event_type: "dns".to_string(),
                severity: "medium".to_string(),
                source_ip: Some("192.168.1.101".to_string()),
                destination_ip: None,
                source_port: None,
                destination_port: Some(53),
                protocol: Some("UDP".to_string()),
                action: "blocked".to_string(),
                rule: Some("dns-blacklist".to_string()),
                details: {
                    let mut d = HashMap::new();
                    d.insert(
                        "domain".to_string(),
                        serde_json::json!("malware.example.com"),
                    );
                    d
                },
            },
        ];

        Self {
            name: name.to_string(),
            events: Arc::new(RwLock::new(events)),
            blocked_ips: Arc::new(RwLock::new(Vec::new())),
            blocked_domains: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Gets the list of blocked IPs.
    pub async fn get_blocked_ips(&self) -> Vec<String> {
        self.blocked_ips.read().await.clone()
    }

    /// Gets the list of blocked domains.
    pub async fn get_blocked_domains(&self) -> Vec<String> {
        self.blocked_domains.read().await.clone()
    }
}

#[async_trait]
impl crate::traits::Connector for MockNetworkConnector {
    fn name(&self) -> &str {
        &self.name
    }

    fn connector_type(&self) -> &str {
        "network"
    }

    async fn health_check(&self) -> ConnectorResult<ConnectorHealth> {
        Ok(ConnectorHealth::Healthy)
    }

    async fn test_connection(&self) -> ConnectorResult<bool> {
        Ok(true)
    }
}

#[async_trait]
impl NetworkSecurityConnector for MockNetworkConnector {
    async fn get_events(
        &self,
        timerange: TimeRange,
        limit: usize,
    ) -> ConnectorResult<Vec<NetworkEvent>> {
        let events = self.events.read().await;
        Ok(events
            .iter()
            .filter(|e| e.timestamp >= timerange.start && e.timestamp <= timerange.end)
            .take(limit)
            .cloned()
            .collect())
    }

    async fn block_ip(&self, ip: &str, _reason: &str) -> ConnectorResult<ActionResult> {
        self.blocked_ips.write().await.push(ip.to_string());
        Ok(ActionResult {
            success: true,
            action_id: format!("mock-block-ip-{}", ip),
            message: format!("IP {} blocked", ip),
            timestamp: Utc::now(),
        })
    }

    async fn block_domain(&self, domain: &str, _reason: &str) -> ConnectorResult<ActionResult> {
        self.blocked_domains.write().await.push(domain.to_string());
        Ok(ActionResult {
            success: true,
            action_id: format!("mock-block-domain-{}", domain),
            message: format!("Domain {} blocked", domain),
            timestamp: Utc::now(),
        })
    }

    async fn get_traffic_logs(
        &self,
        target: &str,
        timerange: TimeRange,
        limit: usize,
    ) -> ConnectorResult<Vec<NetworkEvent>> {
        let events = self.events.read().await;
        Ok(events
            .iter()
            .filter(|e| {
                e.timestamp >= timerange.start
                    && e.timestamp <= timerange.end
                    && (e.source_ip.as_deref() == Some(target)
                        || e.destination_ip.as_deref() == Some(target))
            })
            .take(limit)
            .cloned()
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::Connector;

    #[tokio::test]
    async fn test_get_events() {
        let c = MockNetworkConnector::with_sample_data("test");
        let events = c.get_events(TimeRange::last_hours(1), 100).await.unwrap();
        assert_eq!(events.len(), 2);
    }

    #[tokio::test]
    async fn test_block_ip() {
        let c = MockNetworkConnector::new("test");
        let result = c.block_ip("203.0.113.50", "malicious").await.unwrap();
        assert!(result.success);
        assert_eq!(c.get_blocked_ips().await, vec!["203.0.113.50"]);
    }

    #[tokio::test]
    async fn test_block_domain() {
        let c = MockNetworkConnector::new("test");
        let result = c
            .block_domain("malware.example.com", "malware C2")
            .await
            .unwrap();
        assert!(result.success);
        assert_eq!(c.get_blocked_domains().await, vec!["malware.example.com"]);
    }

    #[test]
    fn test_name_and_type() {
        let c = MockNetworkConnector::new("test");
        assert_eq!(c.name(), "test");
        assert_eq!(c.connector_type(), "network");
    }
}
