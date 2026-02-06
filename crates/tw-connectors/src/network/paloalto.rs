//! Palo Alto Networks connector.
//!
//! Provides integration with Palo Alto Networks firewalls and Panorama for
//! security event retrieval, IP/domain blocking, and traffic log analysis.

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

/// Palo Alto Networks connector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaloAltoConfig {
    /// Base connector configuration.
    #[serde(flatten)]
    pub connector: crate::traits::ConnectorConfig,
    /// Panorama or firewall hostname.
    pub hostname: String,
    /// Virtual system (vsys) name if applicable.
    pub vsys: Option<String>,
}

/// Palo Alto Networks connector.
pub struct PaloAltoConnector {
    config: PaloAltoConfig,
    client: HttpClient,
}

impl PaloAltoConnector {
    /// Creates a new Palo Alto Networks connector.
    pub fn new(config: PaloAltoConfig) -> ConnectorResult<Self> {
        let client = HttpClient::new(config.connector.clone())?;
        info!("Palo Alto connector initialized for '{}'", config.hostname);
        Ok(Self { config, client })
    }

    fn parse_log_entry(entry: &PALogEntry) -> NetworkEvent {
        let timestamp = entry
            .receive_time
            .as_ref()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);

        NetworkEvent {
            id: entry.log_id.clone().unwrap_or_default(),
            timestamp,
            event_type: entry
                .log_type
                .clone()
                .unwrap_or_else(|| "traffic".to_string()),
            severity: entry
                .severity
                .clone()
                .unwrap_or_else(|| "informational".to_string()),
            source_ip: entry.src.clone(),
            destination_ip: entry.dst.clone(),
            source_port: entry.sport,
            destination_port: entry.dport,
            protocol: entry.proto.clone(),
            action: entry.action.clone().unwrap_or_else(|| "allow".to_string()),
            rule: entry.rule.clone(),
            details: HashMap::new(),
        }
    }
}

#[async_trait]
impl crate::traits::Connector for PaloAltoConnector {
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
        match self
            .client
            .get("/api/?type=op&cmd=<show><system><info></info></system></show>")
            .await
        {
            Ok(r) if r.status().is_success() => Ok(ConnectorHealth::Healthy),
            Ok(r) if r.status().as_u16() == 401 || r.status().as_u16() == 403 => Ok(
                ConnectorHealth::Unhealthy("Authentication failed".to_string()),
            ),
            Ok(_) => Ok(ConnectorHealth::Degraded("Unexpected response".to_string())),
            Err(ConnectorError::ConnectionFailed(e)) => Ok(ConnectorHealth::Unhealthy(format!(
                "Connection failed: {}",
                e
            ))),
            Err(e) => Ok(ConnectorHealth::Unhealthy(e.to_string())),
        }
    }

    async fn test_connection(&self) -> ConnectorResult<bool> {
        let response = self
            .client
            .get("/api/?type=op&cmd=<show><system><info></info></system></show>")
            .await?;
        Ok(response.status().is_success())
    }
}

#[async_trait]
impl NetworkSecurityConnector for PaloAltoConnector {
    #[instrument(skip(self))]
    async fn get_events(
        &self,
        timerange: TimeRange,
        limit: usize,
    ) -> ConnectorResult<Vec<NetworkEvent>> {
        let query = format!(
            "(receive_time geq '{}') and (receive_time leq '{}')",
            timerange.start.format("%Y/%m/%d %H:%M:%S"),
            timerange.end.format("%Y/%m/%d %H:%M:%S")
        );
        let path = format!(
            "/api/?type=log&log-type=threat&query={}&nlogs={}",
            urlencoding::encode(&query),
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

        let result: PALogResponse = response
            .json()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(format!("Parse error: {}", e)))?;

        Ok(result.logs.iter().map(Self::parse_log_entry).collect())
    }

    #[instrument(skip(self))]
    async fn block_ip(&self, ip: &str, reason: &str) -> ConnectorResult<ActionResult> {
        let vsys = self.config.vsys.as_deref().unwrap_or("vsys1");
        let body = serde_json::json!({
            "entry": {
                "@name": ip,
                "ip-netmask": ip,
                "description": reason
            }
        });

        let path = format!(
            "/restapi/v10.2/Objects/Addresses?location=vsys&vsys={}&name=blocked-{}",
            urlencoding::encode(vsys),
            urlencoding::encode(ip)
        );
        let response = self.client.post(&path, &body).await?;

        info!("Blocked IP {} on Palo Alto: {}", ip, reason);
        Ok(ActionResult {
            success: response.status().is_success(),
            action_id: format!("pa-block-ip-{}", ip),
            message: format!("IP {} blocked: {}", ip, reason),
            timestamp: Utc::now(),
        })
    }

    #[instrument(skip(self))]
    async fn block_domain(&self, domain: &str, reason: &str) -> ConnectorResult<ActionResult> {
        let body = serde_json::json!({
            "entry": [{
                "@name": domain,
                "description": reason
            }]
        });

        let path = "/restapi/v10.2/Objects/CustomURLCategories";
        let response = self.client.post(path, &body).await?;

        info!("Blocked domain {} on Palo Alto: {}", domain, reason);
        Ok(ActionResult {
            success: response.status().is_success(),
            action_id: format!("pa-block-domain-{}", domain),
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
        let query = format!(
            "(addr.src in '{}' or addr.dst in '{}') and (receive_time geq '{}') and (receive_time leq '{}')",
            target,
            target,
            timerange.start.format("%Y/%m/%d %H:%M:%S"),
            timerange.end.format("%Y/%m/%d %H:%M:%S")
        );
        let path = format!(
            "/api/?type=log&log-type=traffic&query={}&nlogs={}",
            urlencoding::encode(&query),
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

        let result: PALogResponse = response
            .json()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(format!("Parse error: {}", e)))?;

        Ok(result.logs.iter().map(Self::parse_log_entry).collect())
    }
}

// Palo Alto API response types

#[derive(Debug, Default, Deserialize)]
struct PALogResponse {
    #[serde(default)]
    logs: Vec<PALogEntry>,
}

#[derive(Debug, Deserialize)]
struct PALogEntry {
    #[serde(rename = "logid")]
    log_id: Option<String>,
    #[serde(rename = "type")]
    log_type: Option<String>,
    severity: Option<String>,
    src: Option<String>,
    dst: Option<String>,
    sport: Option<u16>,
    dport: Option<u16>,
    proto: Option<String>,
    action: Option<String>,
    rule: Option<String>,
    receive_time: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::test_connector_config;
    use crate::traits::Connector;

    fn create_test_config() -> PaloAltoConfig {
        PaloAltoConfig {
            connector: test_connector_config("pa-test", "https://panorama.company.com"),
            hostname: "panorama.company.com".to_string(),
            vsys: Some("vsys1".to_string()),
        }
    }

    #[test]
    fn test_connector_creation() {
        assert!(PaloAltoConnector::new(create_test_config()).is_ok());
    }

    #[test]
    fn test_connector_name_and_category() {
        let c = PaloAltoConnector::new(create_test_config()).unwrap();
        assert_eq!(c.name(), "pa-test");
        assert_eq!(c.connector_type(), "network");
        assert_eq!(c.category(), ConnectorCategory::Network);
    }

    #[test]
    fn test_parse_log_entry() {
        let entry = PALogEntry {
            log_id: Some("log-001".to_string()),
            log_type: Some("threat".to_string()),
            severity: Some("high".to_string()),
            src: Some("192.168.1.100".to_string()),
            dst: Some("10.0.0.50".to_string()),
            sport: Some(54321),
            dport: Some(443),
            proto: Some("tcp".to_string()),
            action: Some("deny".to_string()),
            rule: Some("block-malicious".to_string()),
            receive_time: Some("2024-01-15T10:30:00Z".to_string()),
        };

        let event = PaloAltoConnector::parse_log_entry(&entry);
        assert_eq!(event.id, "log-001");
        assert_eq!(event.event_type, "threat");
        assert_eq!(event.severity, "high");
        assert_eq!(event.source_ip, Some("192.168.1.100".to_string()));
        assert_eq!(event.action, "deny");
    }

    #[test]
    fn test_capabilities() {
        let c = PaloAltoConnector::new(create_test_config()).unwrap();
        let caps = c.capabilities();
        assert!(caps.contains(&"block_ip".to_string()));
        assert!(caps.contains(&"get_traffic_logs".to_string()));
    }
}
