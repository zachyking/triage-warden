//! VMware Carbon Black EDR connector.
//!
//! Provides integration with Carbon Black Cloud for endpoint detection
//! and response including device management and alert retrieval.

use crate::http::HttpClient;
use crate::traits::{
    ActionResult, ConnectorCategory, ConnectorError, ConnectorHealth, ConnectorResult, Detection,
    EDRConnector, HostInfo, HostStatus, NetworkConnection, ProcessInfo, TimeRange,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, instrument};

/// Carbon Black Cloud configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarbonBlackConfig {
    #[serde(flatten)]
    pub connector: crate::traits::ConnectorConfig,
    /// Organization key.
    pub org_key: String,
}

/// VMware Carbon Black Cloud connector.
pub struct CarbonBlackConnector {
    config: CarbonBlackConfig,
    client: HttpClient,
}

impl CarbonBlackConnector {
    pub fn new(config: CarbonBlackConfig) -> ConnectorResult<Self> {
        let client = HttpClient::new(config.connector.clone())?;
        info!(
            "Carbon Black connector initialized for org '{}'",
            config.org_key
        );
        Ok(Self { config, client })
    }

    fn parse_device(device: &CbDevice) -> HostInfo {
        let status = match device.status.as_deref() {
            Some("REGISTERED") => HostStatus::Online,
            Some("DEREGISTERED") | Some("BYPASS") => HostStatus::Offline,
            _ => HostStatus::Unknown,
        };

        let last_seen = device
            .last_contact_time
            .as_ref()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);

        HostInfo {
            hostname: device.name.clone().unwrap_or_default(),
            host_id: device.id.map(|id| id.to_string()).unwrap_or_default(),
            ip_addresses: device
                .last_internal_ip_address
                .clone()
                .into_iter()
                .collect(),
            mac_addresses: Vec::new(),
            os: device.os.clone().unwrap_or_default(),
            os_version: device.os_version.clone().unwrap_or_default(),
            agent_version: device.sensor_version.clone().unwrap_or_default(),
            last_seen,
            isolated: device.quarantined.unwrap_or(false),
            status,
            tags: Vec::new(),
        }
    }

    fn parse_alert(alert: &CbAlert) -> Detection {
        let timestamp = alert
            .create_time
            .as_ref()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);

        let severity = match alert.severity {
            Some(1..=3) => "low",
            Some(4..=6) => "medium",
            Some(7..=8) => "high",
            Some(9..=10) => "critical",
            _ => "medium",
        }
        .to_string();

        Detection {
            id: alert.id.clone().unwrap_or_default(),
            name: alert
                .reason
                .clone()
                .unwrap_or_else(|| "Unknown Alert".into()),
            severity,
            timestamp,
            description: alert.reason.clone().unwrap_or_default(),
            tactic: alert.attack_tactic.clone(),
            technique: alert.attack_technique.clone(),
            file_hash: None,
            process_name: alert.process_name.clone(),
            details: {
                let mut d = HashMap::new();
                if let Some(ref cat) = alert.category {
                    d.insert("category".to_string(), serde_json::json!(cat));
                }
                d
            },
        }
    }
}

#[async_trait]
impl crate::traits::Connector for CarbonBlackConnector {
    fn name(&self) -> &str {
        &self.config.connector.name
    }

    fn connector_type(&self) -> &str {
        "edr"
    }

    fn category(&self) -> ConnectorCategory {
        ConnectorCategory::Edr
    }

    async fn health_check(&self) -> ConnectorResult<ConnectorHealth> {
        let path = format!(
            "/appservices/v6/orgs/{}/devices/_search",
            self.config.org_key
        );
        let body = serde_json::json!({"rows": 1});
        match self.client.post(&path, &body).await {
            Ok(r) if r.status().is_success() => Ok(ConnectorHealth::Healthy),
            Ok(r) if r.status().as_u16() == 401 || r.status().as_u16() == 403 => {
                Ok(ConnectorHealth::Unhealthy("Auth failed".into()))
            }
            Ok(_) => Ok(ConnectorHealth::Degraded("Unexpected response".into())),
            Err(ConnectorError::ConnectionFailed(e)) => Ok(ConnectorHealth::Unhealthy(format!(
                "Connection failed: {}",
                e
            ))),
            Err(e) => Ok(ConnectorHealth::Unhealthy(e.to_string())),
        }
    }

    async fn test_connection(&self) -> ConnectorResult<bool> {
        let path = format!(
            "/appservices/v6/orgs/{}/devices/_search",
            self.config.org_key
        );
        let body = serde_json::json!({"rows": 1});
        let r = self.client.post(&path, &body).await?;
        Ok(r.status().is_success())
    }
}

#[async_trait]
impl EDRConnector for CarbonBlackConnector {
    #[instrument(skip(self))]
    async fn get_host_info(&self, hostname: &str) -> ConnectorResult<HostInfo> {
        let path = format!(
            "/appservices/v6/orgs/{}/devices/_search",
            self.config.org_key
        );
        let body = serde_json::json!({
            "query": format!("name:{}", hostname),
            "rows": 1
        });

        let response = self.client.post(&path, &body).await?;

        if !response.status().is_success() {
            return Err(ConnectorError::NotFound(format!(
                "Host not found: {}",
                hostname
            )));
        }

        let result: CbSearchResponse<CbDevice> = response
            .json()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(format!("Parse error: {}", e)))?;

        result
            .results
            .into_iter()
            .next()
            .map(|d| Self::parse_device(&d))
            .ok_or_else(|| ConnectorError::NotFound(format!("Host not found: {}", hostname)))
    }

    #[instrument(skip(self))]
    async fn search_hosts(&self, query: &str, limit: usize) -> ConnectorResult<Vec<HostInfo>> {
        let path = format!(
            "/appservices/v6/orgs/{}/devices/_search",
            self.config.org_key
        );
        let body = serde_json::json!({
            "query": format!("name:*{}*", query),
            "rows": limit
        });

        let response = self.client.post(&path, &body).await?;

        if !response.status().is_success() {
            return Ok(Vec::new());
        }

        let result: CbSearchResponse<CbDevice> = response.json().await.unwrap_or_default();
        Ok(result.results.iter().map(Self::parse_device).collect())
    }

    #[instrument(skip(self))]
    async fn isolate_host(&self, hostname: &str) -> ConnectorResult<ActionResult> {
        let host = self.get_host_info(hostname).await?;
        let path = format!(
            "/appservices/v6/orgs/{}/device_actions",
            self.config.org_key
        );
        let body = serde_json::json!({
            "action_type": "QUARANTINE",
            "device_id": [host.host_id.parse::<i64>().unwrap_or(0)],
            "options": { "toggle": "ON" }
        });

        let response = self.client.post(&path, &body).await?;

        info!("Isolated host: {}", hostname);
        Ok(ActionResult {
            success: response.status().is_success(),
            action_id: format!("cb-quarantine-{}", host.host_id),
            message: format!("Host {} quarantine enabled", hostname),
            timestamp: Utc::now(),
        })
    }

    #[instrument(skip(self))]
    async fn unisolate_host(&self, hostname: &str) -> ConnectorResult<ActionResult> {
        let host = self.get_host_info(hostname).await?;
        let path = format!(
            "/appservices/v6/orgs/{}/device_actions",
            self.config.org_key
        );
        let body = serde_json::json!({
            "action_type": "QUARANTINE",
            "device_id": [host.host_id.parse::<i64>().unwrap_or(0)],
            "options": { "toggle": "OFF" }
        });

        let response = self.client.post(&path, &body).await?;

        info!("Removed isolation from host: {}", hostname);
        Ok(ActionResult {
            success: response.status().is_success(),
            action_id: format!("cb-unquarantine-{}", host.host_id),
            message: format!("Host {} quarantine lifted", hostname),
            timestamp: Utc::now(),
        })
    }

    #[instrument(skip(self))]
    async fn get_host_detections(&self, hostname: &str) -> ConnectorResult<Vec<Detection>> {
        let path = format!(
            "/appservices/v6/orgs/{}/alerts/_search",
            self.config.org_key
        );
        let body = serde_json::json!({
            "query": format!("device_name:{}", hostname),
            "rows": 50
        });

        let response = self.client.post(&path, &body).await?;

        if !response.status().is_success() {
            return Ok(Vec::new());
        }

        let result: CbSearchResponse<CbAlert> = response.json().await.unwrap_or_default();
        Ok(result.results.iter().map(Self::parse_alert).collect())
    }

    async fn get_processes(
        &self,
        _hostname: &str,
        _timerange: TimeRange,
    ) -> ConnectorResult<Vec<ProcessInfo>> {
        Ok(Vec::new())
    }

    async fn get_network_connections(
        &self,
        _hostname: &str,
        _timerange: TimeRange,
    ) -> ConnectorResult<Vec<NetworkConnection>> {
        Ok(Vec::new())
    }
}

// Carbon Black API response types

#[derive(Debug, Default, Deserialize)]
struct CbSearchResponse<T: Default> {
    #[serde(default)]
    results: Vec<T>,
}

#[derive(Debug, Default, Deserialize)]
struct CbDevice {
    id: Option<i64>,
    name: Option<String>,
    last_internal_ip_address: Option<String>,
    os: Option<String>,
    os_version: Option<String>,
    sensor_version: Option<String>,
    status: Option<String>,
    last_contact_time: Option<String>,
    quarantined: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
struct CbAlert {
    id: Option<String>,
    reason: Option<String>,
    severity: Option<u8>,
    category: Option<String>,
    create_time: Option<String>,
    process_name: Option<String>,
    attack_tactic: Option<String>,
    attack_technique: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::test_connector_config;
    use crate::traits::Connector;

    fn create_test_config() -> CarbonBlackConfig {
        CarbonBlackConfig {
            connector: test_connector_config("cb-test", "https://defense.conferdeploy.net"),
            org_key: "ORGKEY123".to_string(),
        }
    }

    #[test]
    fn test_connector_creation() {
        assert!(CarbonBlackConnector::new(create_test_config()).is_ok());
    }

    #[test]
    fn test_connector_name_and_category() {
        let c = CarbonBlackConnector::new(create_test_config()).unwrap();
        assert_eq!(c.name(), "cb-test");
        assert_eq!(c.connector_type(), "edr");
        assert_eq!(c.category(), ConnectorCategory::Edr);
    }

    #[test]
    fn test_parse_device() {
        let device = CbDevice {
            id: Some(12345),
            name: Some("workstation-001".to_string()),
            last_internal_ip_address: Some("192.168.1.100".to_string()),
            os: Some("WINDOWS".to_string()),
            os_version: Some("Windows 10 x64".to_string()),
            sensor_version: Some("3.9.0.1234".to_string()),
            status: Some("REGISTERED".to_string()),
            last_contact_time: Some("2024-01-15T10:30:00Z".to_string()),
            quarantined: Some(false),
        };

        let host = CarbonBlackConnector::parse_device(&device);
        assert_eq!(host.hostname, "workstation-001");
        assert_eq!(host.status, HostStatus::Online);
        assert!(!host.isolated);
    }

    #[test]
    fn test_parse_alert() {
        let alert = CbAlert {
            id: Some("alert-001".to_string()),
            reason: Some("Suspicious script execution".to_string()),
            severity: Some(8),
            category: Some("THREAT".to_string()),
            create_time: Some("2024-01-15T10:30:00Z".to_string()),
            process_name: Some("powershell.exe".to_string()),
            attack_tactic: Some("Execution".to_string()),
            attack_technique: Some("T1059".to_string()),
        };

        let detection = CarbonBlackConnector::parse_alert(&alert);
        assert_eq!(detection.id, "alert-001");
        assert_eq!(detection.severity, "high");
        assert_eq!(detection.process_name, Some("powershell.exe".to_string()));
    }
}
