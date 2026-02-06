//! Microsoft Defender for Endpoint EDR connector.
//!
//! Provides integration with Microsoft Defender for Endpoint (MDE) for
//! machine management, alert retrieval, and response actions.

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

/// Defender for Endpoint configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefenderEndpointConfig {
    #[serde(flatten)]
    pub connector: crate::traits::ConnectorConfig,
    /// Azure AD tenant ID.
    pub tenant_id: String,
}

/// Microsoft Defender for Endpoint connector.
pub struct DefenderEndpointConnector {
    config: DefenderEndpointConfig,
    client: HttpClient,
}

impl DefenderEndpointConnector {
    pub fn new(config: DefenderEndpointConfig) -> ConnectorResult<Self> {
        let client = HttpClient::new(config.connector.clone())?;
        info!(
            "Defender for Endpoint connector initialized for tenant '{}'",
            config.tenant_id
        );
        Ok(Self { config, client })
    }

    fn parse_machine(machine: &MdeMachine) -> HostInfo {
        let status = match machine.health_status.as_deref() {
            Some("Active") => HostStatus::Online,
            Some("Inactive") => HostStatus::Offline,
            _ => HostStatus::Unknown,
        };

        let last_seen = machine
            .last_seen
            .as_ref()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);

        HostInfo {
            hostname: machine.computer_dns_name.clone().unwrap_or_default(),
            host_id: machine.id.clone().unwrap_or_default(),
            ip_addresses: machine.last_ip_address.clone().into_iter().collect(),
            mac_addresses: Vec::new(),
            os: machine.os_platform.clone().unwrap_or_default(),
            os_version: machine.os_build.map(|b| b.to_string()).unwrap_or_default(),
            agent_version: machine.agent_version.clone().unwrap_or_default(),
            last_seen,
            isolated: machine.machine_isolation_type.as_deref() != Some("None")
                && machine.machine_isolation_type.is_some(),
            status,
            tags: machine.machine_tags.clone().unwrap_or_default(),
        }
    }

    fn parse_alert(alert: &MdeAlert) -> Detection {
        let timestamp = alert
            .alert_creation_time
            .as_ref()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);

        let severity = alert
            .severity
            .clone()
            .unwrap_or_else(|| "Medium".into())
            .to_lowercase();

        Detection {
            id: alert.id.clone().unwrap_or_default(),
            name: alert
                .title
                .clone()
                .unwrap_or_else(|| "Unknown Alert".into()),
            severity,
            timestamp,
            description: alert.description.clone().unwrap_or_default(),
            tactic: alert
                .mitre_techniques
                .as_ref()
                .and_then(|t| t.first().cloned()),
            technique: alert
                .mitre_techniques
                .as_ref()
                .and_then(|t| t.get(1).cloned()),
            file_hash: None,
            process_name: None,
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
impl crate::traits::Connector for DefenderEndpointConnector {
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
        match self.client.get("/api/machines?$top=1").await {
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
        let r = self.client.get("/api/machines?$top=1").await?;
        Ok(r.status().is_success())
    }
}

#[async_trait]
impl EDRConnector for DefenderEndpointConnector {
    #[instrument(skip(self))]
    async fn get_host_info(&self, hostname: &str) -> ConnectorResult<HostInfo> {
        let path = format!("/api/machines?$filter=computerDnsName eq '{}'", hostname);
        let response = self.client.get(&path).await?;

        if !response.status().is_success() {
            return Err(ConnectorError::NotFound(format!(
                "Host not found: {}",
                hostname
            )));
        }

        let result: MdeResponse<Vec<MdeMachine>> = response
            .json()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(format!("Parse error: {}", e)))?;

        result
            .value
            .into_iter()
            .next()
            .map(|m| Self::parse_machine(&m))
            .ok_or_else(|| ConnectorError::NotFound(format!("Host not found: {}", hostname)))
    }

    #[instrument(skip(self))]
    async fn search_hosts(&self, query: &str, limit: usize) -> ConnectorResult<Vec<HostInfo>> {
        let path = format!(
            "/api/machines?$filter=contains(computerDnsName,'{}')&$top={}",
            query, limit
        );
        let response = self.client.get(&path).await?;

        if !response.status().is_success() {
            return Ok(Vec::new());
        }

        let result: MdeResponse<Vec<MdeMachine>> = response.json().await.unwrap_or_default();
        Ok(result.value.iter().map(Self::parse_machine).collect())
    }

    #[instrument(skip(self))]
    async fn isolate_host(&self, hostname: &str) -> ConnectorResult<ActionResult> {
        let host = self.get_host_info(hostname).await?;
        let body = serde_json::json!({
            "Comment": "Isolated by Triage Warden",
            "IsolationType": "Full"
        });

        let path = format!("/api/machines/{}/isolate", host.host_id);
        let response = self.client.post(&path, &body).await?;

        info!("Isolated host: {}", hostname);
        Ok(ActionResult {
            success: response.status().is_success(),
            action_id: format!("mde-isolate-{}", host.host_id),
            message: format!("Host {} isolation initiated", hostname),
            timestamp: Utc::now(),
        })
    }

    #[instrument(skip(self))]
    async fn unisolate_host(&self, hostname: &str) -> ConnectorResult<ActionResult> {
        let host = self.get_host_info(hostname).await?;
        let body = serde_json::json!({
            "Comment": "Unisolated by Triage Warden"
        });

        let path = format!("/api/machines/{}/unisolate", host.host_id);
        let response = self.client.post(&path, &body).await?;

        info!("Removed isolation from host: {}", hostname);
        Ok(ActionResult {
            success: response.status().is_success(),
            action_id: format!("mde-unisolate-{}", host.host_id),
            message: format!("Host {} isolation lifted", hostname),
            timestamp: Utc::now(),
        })
    }

    #[instrument(skip(self))]
    async fn get_host_detections(&self, hostname: &str) -> ConnectorResult<Vec<Detection>> {
        let host = self.get_host_info(hostname).await?;
        let path = format!("/api/machines/{}/alerts", host.host_id);
        let response = self.client.get(&path).await?;

        if !response.status().is_success() {
            return Ok(Vec::new());
        }

        let result: MdeResponse<Vec<MdeAlert>> = response.json().await.unwrap_or_default();
        Ok(result.value.iter().map(Self::parse_alert).collect())
    }

    async fn get_processes(
        &self,
        _hostname: &str,
        _timerange: TimeRange,
    ) -> ConnectorResult<Vec<ProcessInfo>> {
        // MDE Advanced Hunting would be used for process enumeration
        Ok(Vec::new())
    }

    async fn get_network_connections(
        &self,
        _hostname: &str,
        _timerange: TimeRange,
    ) -> ConnectorResult<Vec<NetworkConnection>> {
        // MDE Advanced Hunting would be used for network connections
        Ok(Vec::new())
    }
}

// MDE API response types

#[derive(Debug, Default, Deserialize)]
struct MdeResponse<T: Default> {
    #[serde(default)]
    value: T,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MdeMachine {
    id: Option<String>,
    computer_dns_name: Option<String>,
    last_ip_address: Option<String>,
    os_platform: Option<String>,
    os_build: Option<i64>,
    agent_version: Option<String>,
    health_status: Option<String>,
    last_seen: Option<String>,
    machine_isolation_type: Option<String>,
    machine_tags: Option<Vec<String>>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MdeAlert {
    id: Option<String>,
    title: Option<String>,
    description: Option<String>,
    severity: Option<String>,
    category: Option<String>,
    alert_creation_time: Option<String>,
    mitre_techniques: Option<Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::test_connector_config;
    use crate::traits::Connector;

    fn create_test_config() -> DefenderEndpointConfig {
        DefenderEndpointConfig {
            connector: test_connector_config(
                "mde-test",
                "https://api.securitycenter.microsoft.com",
            ),
            tenant_id: "tenant-abc-123".to_string(),
        }
    }

    #[test]
    fn test_connector_creation() {
        assert!(DefenderEndpointConnector::new(create_test_config()).is_ok());
    }

    #[test]
    fn test_connector_name_and_category() {
        let c = DefenderEndpointConnector::new(create_test_config()).unwrap();
        assert_eq!(c.name(), "mde-test");
        assert_eq!(c.connector_type(), "edr");
        assert_eq!(c.category(), ConnectorCategory::Edr);
    }

    #[test]
    fn test_parse_machine() {
        let machine = MdeMachine {
            id: Some("machine-001".to_string()),
            computer_dns_name: Some("workstation-001.corp.com".to_string()),
            last_ip_address: Some("10.0.0.50".to_string()),
            os_platform: Some("Windows10".to_string()),
            os_build: Some(19045),
            agent_version: Some("10.8790.19041.2364".to_string()),
            health_status: Some("Active".to_string()),
            last_seen: Some("2024-01-15T10:30:00Z".to_string()),
            machine_isolation_type: Some("None".to_string()),
            machine_tags: Some(vec!["VIP".to_string()]),
        };

        let host = DefenderEndpointConnector::parse_machine(&machine);
        assert_eq!(host.hostname, "workstation-001.corp.com");
        assert_eq!(host.status, HostStatus::Online);
        assert!(!host.isolated);
    }

    #[test]
    fn test_parse_alert() {
        let alert = MdeAlert {
            id: Some("alert-001".to_string()),
            title: Some("Suspicious PowerShell".to_string()),
            description: Some("PowerShell execution detected".to_string()),
            severity: Some("High".to_string()),
            category: Some("Execution".to_string()),
            alert_creation_time: Some("2024-01-15T10:30:00Z".to_string()),
            mitre_techniques: Some(vec!["T1059.001".to_string()]),
        };

        let detection = DefenderEndpointConnector::parse_alert(&alert);
        assert_eq!(detection.id, "alert-001");
        assert_eq!(detection.severity, "high");
    }
}
