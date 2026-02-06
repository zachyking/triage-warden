//! SentinelOne EDR connector.
//!
//! Provides integration with SentinelOne for endpoint detection and response
//! including host management, threat detection, and isolation actions.

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

/// SentinelOne connector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentinelOneConfig {
    #[serde(flatten)]
    pub connector: crate::traits::ConnectorConfig,
    /// SentinelOne site ID (optional, for multi-site deployments).
    pub site_id: Option<String>,
    /// Account ID.
    pub account_id: Option<String>,
}

/// SentinelOne EDR connector.
pub struct SentinelOneConnector {
    config: SentinelOneConfig,
    client: HttpClient,
}

impl SentinelOneConnector {
    pub fn new(config: SentinelOneConfig) -> ConnectorResult<Self> {
        let client = HttpClient::new(config.connector.clone())?;
        info!("SentinelOne connector initialized");
        Ok(Self { config, client })
    }

    fn parse_agent(agent: &S1Agent) -> HostInfo {
        let status = match agent.network_status.as_deref() {
            Some("connected") => HostStatus::Online,
            Some("disconnected") => HostStatus::Offline,
            _ => HostStatus::Unknown,
        };

        let last_seen = agent
            .last_active_date
            .as_ref()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);

        HostInfo {
            hostname: agent.computer_name.clone().unwrap_or_default(),
            host_id: agent.id.clone().unwrap_or_default(),
            ip_addresses: agent.last_ip_to_mgmt.clone().into_iter().collect(),
            mac_addresses: Vec::new(),
            os: agent.os_name.clone().unwrap_or_default(),
            os_version: agent.os_revision.clone().unwrap_or_default(),
            agent_version: agent.agent_version.clone().unwrap_or_default(),
            last_seen,
            isolated: agent.network_quarantine_enabled.unwrap_or(false),
            status,
            tags: agent.tags.clone().unwrap_or_default(),
        }
    }

    fn parse_threat(threat: &S1Threat) -> Detection {
        let timestamp = threat
            .created_at
            .as_ref()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);

        let severity = match threat.confidence_level.as_deref() {
            Some("malicious") => "critical",
            Some("suspicious") => "high",
            _ => "medium",
        }
        .to_string();

        Detection {
            id: threat.id.clone().unwrap_or_default(),
            name: threat
                .classification
                .clone()
                .unwrap_or_else(|| "Unknown Threat".into()),
            severity,
            timestamp,
            description: threat.threat_name.clone().unwrap_or_default(),
            tactic: threat.mitre_tactic.clone(),
            technique: threat.mitre_technique.clone(),
            file_hash: threat.file_content_hash.clone(),
            process_name: threat.originator_process.clone(),
            details: HashMap::new(),
        }
    }
}

#[async_trait]
impl crate::traits::Connector for SentinelOneConnector {
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
        match self.client.get("/web/api/v2.1/system/status").await {
            Ok(r) if r.status().is_success() => Ok(ConnectorHealth::Healthy),
            Ok(r) if r.status().as_u16() == 401 => {
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
        let r = self.client.get("/web/api/v2.1/system/status").await?;
        Ok(r.status().is_success())
    }
}

#[async_trait]
impl EDRConnector for SentinelOneConnector {
    #[instrument(skip(self))]
    async fn get_host_info(&self, hostname: &str) -> ConnectorResult<HostInfo> {
        let path = format!(
            "/web/api/v2.1/agents?computerName={}",
            urlencoding::encode(hostname)
        );
        let response = self.client.get(&path).await?;

        if !response.status().is_success() {
            return Err(ConnectorError::NotFound(format!(
                "Host not found: {}",
                hostname
            )));
        }

        let result: S1Response<Vec<S1Agent>> = response
            .json()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(format!("Parse error: {}", e)))?;

        result
            .data
            .into_iter()
            .next()
            .map(|a| Self::parse_agent(&a))
            .ok_or_else(|| ConnectorError::NotFound(format!("Host not found: {}", hostname)))
    }

    #[instrument(skip(self))]
    async fn search_hosts(&self, query: &str, limit: usize) -> ConnectorResult<Vec<HostInfo>> {
        let path = format!(
            "/web/api/v2.1/agents?computerName__contains={}&limit={}",
            urlencoding::encode(query),
            limit
        );
        let response = self.client.get(&path).await?;

        if !response.status().is_success() {
            return Ok(Vec::new());
        }

        let result: S1Response<Vec<S1Agent>> = response.json().await.unwrap_or_default();
        Ok(result.data.iter().map(Self::parse_agent).collect())
    }

    #[instrument(skip(self))]
    async fn isolate_host(&self, hostname: &str) -> ConnectorResult<ActionResult> {
        let host = self.get_host_info(hostname).await?;
        let body = serde_json::json!({
            "filter": { "ids": [host.host_id] }
        });

        let response = self
            .client
            .post("/web/api/v2.1/agents/actions/disconnect", &body)
            .await?;

        info!("Isolated host: {}", hostname);
        Ok(ActionResult {
            success: response.status().is_success(),
            action_id: format!("s1-isolate-{}", host.host_id),
            message: format!("Host {} network quarantine enabled", hostname),
            timestamp: Utc::now(),
        })
    }

    #[instrument(skip(self))]
    async fn unisolate_host(&self, hostname: &str) -> ConnectorResult<ActionResult> {
        let host = self.get_host_info(hostname).await?;
        let body = serde_json::json!({
            "filter": { "ids": [host.host_id] }
        });

        let response = self
            .client
            .post("/web/api/v2.1/agents/actions/connect", &body)
            .await?;

        info!("Removed isolation from host: {}", hostname);
        Ok(ActionResult {
            success: response.status().is_success(),
            action_id: format!("s1-unisolate-{}", host.host_id),
            message: format!("Host {} network quarantine lifted", hostname),
            timestamp: Utc::now(),
        })
    }

    #[instrument(skip(self))]
    async fn get_host_detections(&self, hostname: &str) -> ConnectorResult<Vec<Detection>> {
        let path = format!(
            "/web/api/v2.1/threats?computerName__contains={}",
            urlencoding::encode(hostname)
        );
        let response = self.client.get(&path).await?;

        if !response.status().is_success() {
            return Ok(Vec::new());
        }

        let result: S1Response<Vec<S1Threat>> = response.json().await.unwrap_or_default();
        Ok(result.data.iter().map(Self::parse_threat).collect())
    }

    async fn get_processes(
        &self,
        _hostname: &str,
        _timerange: TimeRange,
    ) -> ConnectorResult<Vec<ProcessInfo>> {
        // SentinelOne Deep Visibility would be used here
        Ok(Vec::new())
    }

    async fn get_network_connections(
        &self,
        _hostname: &str,
        _timerange: TimeRange,
    ) -> ConnectorResult<Vec<NetworkConnection>> {
        // SentinelOne Deep Visibility would be used here
        Ok(Vec::new())
    }
}

// SentinelOne API response types

#[derive(Debug, Default, Deserialize)]
struct S1Response<T: Default> {
    #[serde(default)]
    data: T,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct S1Agent {
    id: Option<String>,
    computer_name: Option<String>,
    last_ip_to_mgmt: Option<String>,
    os_name: Option<String>,
    os_revision: Option<String>,
    agent_version: Option<String>,
    network_status: Option<String>,
    last_active_date: Option<String>,
    network_quarantine_enabled: Option<bool>,
    tags: Option<Vec<String>>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct S1Threat {
    id: Option<String>,
    classification: Option<String>,
    threat_name: Option<String>,
    confidence_level: Option<String>,
    created_at: Option<String>,
    file_content_hash: Option<String>,
    originator_process: Option<String>,
    mitre_tactic: Option<String>,
    mitre_technique: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::test_connector_config;
    use crate::traits::Connector;

    fn create_test_config() -> SentinelOneConfig {
        SentinelOneConfig {
            connector: test_connector_config("s1-test", "https://usea1.sentinelone.net"),
            site_id: Some("site-001".to_string()),
            account_id: None,
        }
    }

    #[test]
    fn test_connector_creation() {
        assert!(SentinelOneConnector::new(create_test_config()).is_ok());
    }

    #[test]
    fn test_connector_name_and_category() {
        let c = SentinelOneConnector::new(create_test_config()).unwrap();
        assert_eq!(c.name(), "s1-test");
        assert_eq!(c.connector_type(), "edr");
        assert_eq!(c.category(), ConnectorCategory::Edr);
    }

    #[test]
    fn test_parse_agent() {
        let agent = S1Agent {
            id: Some("agent-001".to_string()),
            computer_name: Some("workstation-001".to_string()),
            last_ip_to_mgmt: Some("192.168.1.100".to_string()),
            os_name: Some("Windows 10".to_string()),
            os_revision: Some("19045".to_string()),
            agent_version: Some("23.1.0".to_string()),
            network_status: Some("connected".to_string()),
            last_active_date: Some("2024-01-15T10:30:00Z".to_string()),
            network_quarantine_enabled: Some(false),
            tags: Some(vec!["production".to_string()]),
        };

        let host = SentinelOneConnector::parse_agent(&agent);
        assert_eq!(host.hostname, "workstation-001");
        assert_eq!(host.status, HostStatus::Online);
        assert!(!host.isolated);
    }

    #[test]
    fn test_parse_threat() {
        let threat = S1Threat {
            id: Some("threat-001".to_string()),
            classification: Some("Malware".to_string()),
            threat_name: Some("Trojan.Gen".to_string()),
            confidence_level: Some("malicious".to_string()),
            created_at: Some("2024-01-15T10:30:00Z".to_string()),
            file_content_hash: Some("abc123".to_string()),
            originator_process: Some("malware.exe".to_string()),
            mitre_tactic: Some("Execution".to_string()),
            mitre_technique: Some("T1059".to_string()),
        };

        let detection = SentinelOneConnector::parse_threat(&threat);
        assert_eq!(detection.id, "threat-001");
        assert_eq!(detection.severity, "critical");
        assert_eq!(detection.tactic, Some("Execution".to_string()));
    }
}
