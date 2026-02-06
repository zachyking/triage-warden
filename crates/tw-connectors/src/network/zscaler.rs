//! Zscaler connector.
//!
//! Provides integration with Zscaler Internet Access (ZIA) for security events,
//! URL/IP blocking, and web traffic logs.

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

/// Zscaler connector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZscalerConfig {
    /// Base connector configuration.
    #[serde(flatten)]
    pub connector: crate::traits::ConnectorConfig,
    /// Zscaler cloud name (e.g., "zscaler", "zscalerone", "zscalertwo").
    pub cloud: String,
}

/// Zscaler connector.
pub struct ZscalerConnector {
    config: ZscalerConfig,
    client: HttpClient,
}

impl ZscalerConnector {
    /// Creates a new Zscaler connector.
    pub fn new(config: ZscalerConfig) -> ConnectorResult<Self> {
        let client = HttpClient::new(config.connector.clone())?;
        info!("Zscaler connector initialized for cloud '{}'", config.cloud);
        Ok(Self { config, client })
    }

    fn parse_event(event: &ZscalerEvent) -> NetworkEvent {
        let timestamp = event
            .datetime
            .as_ref()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);

        NetworkEvent {
            id: event.event_id.clone().unwrap_or_default(),
            timestamp,
            event_type: event
                .event_type
                .clone()
                .unwrap_or_else(|| "web".to_string()),
            severity: event.severity.clone().unwrap_or_else(|| "info".to_string()),
            source_ip: event.client_ip.clone(),
            destination_ip: event.server_ip.clone(),
            source_port: event.client_source_port,
            destination_port: event.server_port,
            protocol: event.proto.clone(),
            action: event
                .action
                .clone()
                .unwrap_or_else(|| "Allowed".to_string()),
            rule: event.policy_name.clone(),
            details: {
                let mut d = HashMap::new();
                if let Some(ref url) = event.url {
                    d.insert("url".to_string(), serde_json::json!(url));
                }
                if let Some(ref hostname) = event.hostname {
                    d.insert("hostname".to_string(), serde_json::json!(hostname));
                }
                d
            },
        }
    }
}

#[async_trait]
impl crate::traits::Connector for ZscalerConnector {
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
            "block_ip".to_string(),
            "block_domain".to_string(),
            "get_traffic_logs".to_string(),
        ]
    }

    async fn health_check(&self) -> ConnectorResult<ConnectorHealth> {
        match self.client.get("/api/v1/status").await {
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
        let response = self.client.get("/api/v1/status").await?;
        Ok(response.status().is_success())
    }
}

#[async_trait]
impl NetworkSecurityConnector for ZscalerConnector {
    #[instrument(skip(self))]
    async fn get_events(
        &self,
        timerange: TimeRange,
        limit: usize,
    ) -> ConnectorResult<Vec<NetworkEvent>> {
        let body = serde_json::json!({
            "startTime": timerange.start.timestamp(),
            "endTime": timerange.end.timestamp(),
            "size": limit,
            "category": "security"
        });

        let response = self
            .client
            .post("/api/v1/webApplicationRules/securityEvents", &body)
            .await?;

        if !response.status().is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ConnectorError::RequestFailed(format!(
                "Failed to get events: {}",
                body
            )));
        }

        let result: ZscalerEventResponse = response
            .json()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(format!("Parse error: {}", e)))?;

        Ok(result.events.iter().map(Self::parse_event).collect())
    }

    #[instrument(skip(self))]
    async fn block_ip(&self, ip: &str, reason: &str) -> ConnectorResult<ActionResult> {
        let body = serde_json::json!({
            "urls": [ip],
            "dbCategorizedUrls": [],
            "customCategory": "CUSTOM_BLOCK",
            "description": reason
        });

        let response = self
            .client
            .post("/api/v1/security/advanced/blacklistUrls", &body)
            .await?;

        info!("Blocked IP {} on Zscaler: {}", ip, reason);
        Ok(ActionResult {
            success: response.status().is_success(),
            action_id: format!("zscaler-block-ip-{}", ip),
            message: format!("IP {} added to blacklist: {}", ip, reason),
            timestamp: Utc::now(),
        })
    }

    #[instrument(skip(self))]
    async fn block_domain(&self, domain: &str, reason: &str) -> ConnectorResult<ActionResult> {
        let body = serde_json::json!({
            "urls": [domain],
            "dbCategorizedUrls": [],
            "customCategory": "CUSTOM_BLOCK",
            "description": reason
        });

        let response = self
            .client
            .post("/api/v1/security/advanced/blacklistUrls", &body)
            .await?;

        info!("Blocked domain {} on Zscaler: {}", domain, reason);
        Ok(ActionResult {
            success: response.status().is_success(),
            action_id: format!("zscaler-block-domain-{}", domain),
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
        let body = serde_json::json!({
            "startTime": timerange.start.timestamp(),
            "endTime": timerange.end.timestamp(),
            "size": limit,
            "filter": target
        });

        let response = self
            .client
            .post("/api/v1/webTransactionLogs", &body)
            .await?;

        if !response.status().is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ConnectorError::RequestFailed(format!(
                "Failed to get traffic logs: {}",
                body
            )));
        }

        let result: ZscalerEventResponse = response
            .json()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(format!("Parse error: {}", e)))?;

        Ok(result.events.iter().map(Self::parse_event).collect())
    }
}

// Zscaler API response types

#[derive(Debug, Default, Deserialize)]
struct ZscalerEventResponse {
    #[serde(default)]
    events: Vec<ZscalerEvent>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ZscalerEvent {
    event_id: Option<String>,
    datetime: Option<String>,
    event_type: Option<String>,
    severity: Option<String>,
    client_ip: Option<String>,
    server_ip: Option<String>,
    client_source_port: Option<u16>,
    server_port: Option<u16>,
    proto: Option<String>,
    action: Option<String>,
    policy_name: Option<String>,
    url: Option<String>,
    hostname: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::test_connector_config;
    use crate::traits::Connector;

    fn create_test_config() -> ZscalerConfig {
        ZscalerConfig {
            connector: test_connector_config("zscaler-test", "https://zsapi.zscaler.net"),
            cloud: "zscaler".to_string(),
        }
    }

    #[test]
    fn test_connector_creation() {
        assert!(ZscalerConnector::new(create_test_config()).is_ok());
    }

    #[test]
    fn test_connector_name_and_category() {
        let c = ZscalerConnector::new(create_test_config()).unwrap();
        assert_eq!(c.name(), "zscaler-test");
        assert_eq!(c.connector_type(), "network");
        assert_eq!(c.category(), ConnectorCategory::Network);
    }

    #[test]
    fn test_parse_event() {
        let event = ZscalerEvent {
            event_id: Some("evt-001".to_string()),
            datetime: Some("2024-01-15T10:30:00Z".to_string()),
            event_type: Some("web".to_string()),
            severity: Some("high".to_string()),
            client_ip: Some("192.168.1.100".to_string()),
            server_ip: Some("203.0.113.50".to_string()),
            client_source_port: Some(54321),
            server_port: Some(443),
            proto: Some("HTTPS".to_string()),
            action: Some("Blocked".to_string()),
            policy_name: Some("malware-block".to_string()),
            url: Some("https://evil.example.com/payload".to_string()),
            hostname: Some("evil.example.com".to_string()),
        };

        let parsed = ZscalerConnector::parse_event(&event);
        assert_eq!(parsed.id, "evt-001");
        assert_eq!(parsed.severity, "high");
        assert_eq!(parsed.action, "Blocked");
    }

    #[test]
    fn test_capabilities() {
        let c = ZscalerConnector::new(create_test_config()).unwrap();
        let caps = c.capabilities();
        assert!(caps.contains(&"block_ip".to_string()));
        assert!(caps.contains(&"block_domain".to_string()));
    }
}
