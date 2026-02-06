//! Cisco Umbrella connector.
//!
//! Provides integration with Cisco Umbrella (OpenDNS) for DNS security events,
//! domain blocking, and traffic analysis.

use crate::http::HttpClient;
use crate::traits::{
    ActionResult, ConnectorCategory, ConnectorError, ConnectorHealth, ConnectorResult,
    NetworkEvent, NetworkSecurityConnector, TimeRange,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, instrument};

/// Cisco Umbrella connector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UmbrellaConfig {
    /// Base connector configuration.
    #[serde(flatten)]
    pub connector: crate::traits::ConnectorConfig,
    /// Organization ID in Umbrella.
    pub org_id: String,
}

/// Cisco Umbrella connector.
pub struct UmbrellaConnector {
    config: UmbrellaConfig,
    client: HttpClient,
}

impl UmbrellaConnector {
    /// Creates a new Cisco Umbrella connector.
    pub fn new(config: UmbrellaConfig) -> ConnectorResult<Self> {
        let client = HttpClient::new(config.connector.clone())?;
        info!("Umbrella connector initialized for org '{}'", config.org_id);
        Ok(Self { config, client })
    }

    fn parse_event(event: &UmbrellaEvent) -> NetworkEvent {
        let timestamp = event
            .datetime
            .as_ref()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);

        NetworkEvent {
            id: event.id.clone().unwrap_or_default(),
            timestamp,
            event_type: "dns".to_string(),
            severity: event
                .categories
                .as_ref()
                .map(|c| {
                    if c.iter()
                        .any(|cat| cat.contains("Malware") || cat.contains("Phishing"))
                    {
                        "high".to_string()
                    } else {
                        "medium".to_string()
                    }
                })
                .unwrap_or_else(|| "low".to_string()),
            source_ip: event.internal_ip.clone(),
            destination_ip: event.external_ip.clone(),
            source_port: None,
            destination_port: Some(53),
            protocol: Some("DNS".to_string()),
            action: event
                .action
                .clone()
                .unwrap_or_else(|| "Allowed".to_string()),
            rule: event.policy_identity.clone(),
            details: {
                let mut d = HashMap::new();
                if let Some(ref domain) = event.domain {
                    d.insert("domain".to_string(), serde_json::json!(domain));
                }
                if let Some(ref cats) = event.categories {
                    d.insert("categories".to_string(), serde_json::json!(cats));
                }
                d
            },
        }
    }
}

#[async_trait]
impl crate::traits::Connector for UmbrellaConnector {
    fn name(&self) -> &str {
        &self.config.connector.name
    }

    fn connector_type(&self) -> &str {
        "network"
    }

    fn category(&self) -> ConnectorCategory {
        ConnectorCategory::Network
    }

    fn capabilities(&self) -> Vec<String> {
        vec![
            "health_check".to_string(),
            "test_connection".to_string(),
            "get_events".to_string(),
            "block_domain".to_string(),
            "get_traffic_logs".to_string(),
        ]
    }

    async fn health_check(&self) -> ConnectorResult<ConnectorHealth> {
        let path = format!("/organizations/{}", self.config.org_id);
        match self.client.get(&path).await {
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
        let path = format!("/organizations/{}", self.config.org_id);
        let response = self.client.get(&path).await?;
        Ok(response.status().is_success())
    }
}

#[async_trait]
impl NetworkSecurityConnector for UmbrellaConnector {
    #[instrument(skip(self))]
    async fn get_events(
        &self,
        timerange: TimeRange,
        limit: usize,
    ) -> ConnectorResult<Vec<NetworkEvent>> {
        let path = format!(
            "/organizations/{}/security-events?start={}&stop={}&limit={}",
            self.config.org_id,
            timerange.start.timestamp_millis(),
            timerange.end.timestamp_millis(),
            limit
        );

        let response = self.client.get(&path).await?;
        if !response.status().is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ConnectorError::RequestFailed(format!(
                "Failed to get events: {}",
                body
            )));
        }

        let events: Vec<UmbrellaEvent> = response
            .json()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(format!("Parse error: {}", e)))?;

        Ok(events.iter().map(Self::parse_event).collect())
    }

    #[instrument(skip(self))]
    async fn block_ip(&self, ip: &str, reason: &str) -> ConnectorResult<ActionResult> {
        let body = serde_json::json!({
            "name": format!("blocked-{}", ip),
            "domains": [],
            "urls": [],
            "ipv4s": [ip],
            "description": reason
        });

        let path = format!("/organizations/{}/destinationlists", self.config.org_id);
        let response = self.client.post(&path, &body).await?;

        info!("Blocked IP {} on Umbrella: {}", ip, reason);
        Ok(ActionResult {
            success: response.status().is_success(),
            action_id: format!("umbrella-block-ip-{}", ip),
            message: format!("IP {} added to block list: {}", ip, reason),
            timestamp: Utc::now(),
        })
    }

    #[instrument(skip(self))]
    async fn block_domain(&self, domain: &str, reason: &str) -> ConnectorResult<ActionResult> {
        let body = serde_json::json!([{
            "destination": domain,
        }]);

        let path = format!(
            "/organizations/{}/destinationlists/destinations",
            self.config.org_id
        );
        let response = self.client.post(&path, &body).await?;

        info!("Blocked domain {} on Umbrella: {}", domain, reason);
        Ok(ActionResult {
            success: response.status().is_success(),
            action_id: format!("umbrella-block-domain-{}", domain),
            message: format!("Domain {} blocked: {}", domain, reason),
            timestamp: Utc::now(),
        })
    }

    #[instrument(skip(self))]
    async fn get_traffic_logs(
        &self,
        target: &str,
        timerange: TimeRange,
        limit: usize,
    ) -> ConnectorResult<Vec<NetworkEvent>> {
        let path = format!(
            "/organizations/{}/activity?start={}&stop={}&ip={}&limit={}",
            self.config.org_id,
            timerange.start.timestamp_millis(),
            timerange.end.timestamp_millis(),
            urlencoding::encode(target),
            limit
        );

        let response = self.client.get(&path).await?;
        if !response.status().is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ConnectorError::RequestFailed(format!(
                "Failed to get traffic logs: {}",
                body
            )));
        }

        let events: Vec<UmbrellaEvent> = response
            .json()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(format!("Parse error: {}", e)))?;

        Ok(events.iter().map(Self::parse_event).collect())
    }
}

// Umbrella API response types

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UmbrellaEvent {
    id: Option<String>,
    datetime: Option<String>,
    internal_ip: Option<String>,
    external_ip: Option<String>,
    domain: Option<String>,
    action: Option<String>,
    categories: Option<Vec<String>>,
    policy_identity: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::test_connector_config;
    use crate::traits::Connector;

    fn create_test_config() -> UmbrellaConfig {
        UmbrellaConfig {
            connector: test_connector_config("umbrella-test", "https://api.umbrella.com/v1"),
            org_id: "org-12345".to_string(),
        }
    }

    #[test]
    fn test_connector_creation() {
        assert!(UmbrellaConnector::new(create_test_config()).is_ok());
    }

    #[test]
    fn test_connector_name_and_category() {
        let c = UmbrellaConnector::new(create_test_config()).unwrap();
        assert_eq!(c.name(), "umbrella-test");
        assert_eq!(c.connector_type(), "network");
        assert_eq!(c.category(), ConnectorCategory::Network);
    }

    #[test]
    fn test_parse_event() {
        let event = UmbrellaEvent {
            id: Some("evt-001".to_string()),
            datetime: Some("2024-01-15T10:30:00Z".to_string()),
            internal_ip: Some("192.168.1.100".to_string()),
            external_ip: Some("203.0.113.50".to_string()),
            domain: Some("malware.example.com".to_string()),
            action: Some("Blocked".to_string()),
            categories: Some(vec!["Malware".to_string()]),
            policy_identity: Some("default-policy".to_string()),
        };

        let parsed = UmbrellaConnector::parse_event(&event);
        assert_eq!(parsed.id, "evt-001");
        assert_eq!(parsed.event_type, "dns");
        assert_eq!(parsed.severity, "high");
        assert_eq!(parsed.action, "Blocked");
    }

    #[test]
    fn test_capabilities() {
        let c = UmbrellaConnector::new(create_test_config()).unwrap();
        let caps = c.capabilities();
        assert!(caps.contains(&"block_domain".to_string()));
    }
}
