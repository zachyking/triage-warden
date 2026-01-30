//! CrowdStrike Falcon EDR connector.
//!
//! This module provides integration with CrowdStrike Falcon platform for
//! host management, detection retrieval, and response actions.

use crate::http::{HttpClient, RateLimitConfig};
use crate::traits::{
    ActionResult, ConnectorConfig, ConnectorError, ConnectorHealth, ConnectorResult, Detection,
    EDRConnector, HostInfo, HostStatus, NetworkConnection, ProcessInfo, TimeRange,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use tracing::{info, instrument, warn};

/// CrowdStrike-specific configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrowdStrikeConfig {
    /// Base connector configuration.
    #[serde(flatten)]
    pub connector: ConnectorConfig,
    /// API region: us-1, us-2, eu-1, us-gov-1.
    #[serde(default = "default_region")]
    pub region: String,
    /// Member CID for MSSP deployments.
    pub member_cid: Option<String>,
}

fn default_region() -> String {
    "us-1".to_string()
}

/// Get base URL for CrowdStrike region.
fn get_region_url(region: &str) -> &'static str {
    match region {
        "us-1" => "https://api.crowdstrike.com",
        "us-2" => "https://api.us-2.crowdstrike.com",
        "eu-1" => "https://api.eu-1.crowdstrike.com",
        "us-gov-1" => "https://api.laggar.gcw.crowdstrike.com",
        _ => "https://api.crowdstrike.com",
    }
}

/// CrowdStrike Falcon EDR connector.
pub struct CrowdStrikeConnector {
    config: CrowdStrikeConfig,
    client: HttpClient,
}

impl CrowdStrikeConnector {
    /// Creates a new CrowdStrike connector.
    pub fn new(config: CrowdStrikeConfig) -> ConnectorResult<Self> {
        // CrowdStrike API rate limits: ~5000 req/hour for most endpoints
        let rate_limit = RateLimitConfig {
            max_requests: 100,
            period: Duration::from_secs(60),
            burst_size: 20,
        };

        // Update base URL based on region if not explicitly set
        let mut connector_config = config.connector.clone();
        if connector_config.base_url.is_empty()
            || connector_config.base_url == "https://api.crowdstrike.com"
        {
            connector_config.base_url = get_region_url(&config.region).to_string();
        }

        let client = HttpClient::with_rate_limit(connector_config, Some(rate_limit))?;

        info!(
            "CrowdStrike connector initialized for region '{}'",
            config.region
        );

        Ok(Self { config, client })
    }

    /// Builds a FQL filter for host search.
    pub fn build_host_filter(query: &str) -> String {
        let escaped = query.replace('\'', "\\'");
        format!("hostname:*'{}*'+status:'normal'", escaped)
    }

    /// Builds a FQL filter for detection search.
    pub fn build_detection_filter(hostname: &str) -> String {
        let escaped = hostname.replace('\'', "\\'");
        format!("device.hostname:'{}'", escaped)
    }

    /// Looks up hosts by hostname pattern.
    #[instrument(skip(self))]
    async fn find_host_id(&self, hostname: &str) -> ConnectorResult<String> {
        let filter = format!("hostname:'{}'", hostname.replace('\'', "\\'"));
        let path = format!(
            "/devices/queries/devices/v1?filter={}",
            urlencoding::encode(&filter)
        );

        let response = self.client.get(&path).await?;

        if !response.status().is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ConnectorError::RequestFailed(format!(
                "Failed to find host: {}",
                body
            )));
        }

        let result: CSQueryResponse = response.json().await.map_err(|e| {
            ConnectorError::InvalidResponse(format!("Failed to parse response: {}", e))
        })?;

        result
            .resources
            .first()
            .cloned()
            .ok_or_else(|| ConnectorError::NotFound(format!("Host not found: {}", hostname)))
    }

    /// Gets host details by agent ID (AID).
    #[instrument(skip(self))]
    async fn get_host_by_id(&self, aid: &str) -> ConnectorResult<HostInfo> {
        let path = format!("/devices/entities/devices/v2?ids={}", aid);

        let response = self.client.get(&path).await?;

        if !response.status().is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ConnectorError::RequestFailed(format!(
                "Failed to get host: {}",
                body
            )));
        }

        let result: CSDevicesResponse = response.json().await.map_err(|e| {
            ConnectorError::InvalidResponse(format!("Failed to parse response: {}", e))
        })?;

        result
            .resources
            .into_iter()
            .next()
            .map(|d| self.parse_device(&d))
            .ok_or_else(|| ConnectorError::NotFound(format!("Host not found: {}", aid)))
    }

    /// Parses a CrowdStrike device into HostInfo.
    fn parse_device(&self, device: &CSDevice) -> HostInfo {
        let status = match device.status.as_deref() {
            Some("normal") | Some("online") => HostStatus::Online,
            Some("offline") => HostStatus::Offline,
            _ => HostStatus::Unknown,
        };

        let last_seen = device
            .last_seen
            .as_ref()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);

        HostInfo {
            hostname: device.hostname.clone().unwrap_or_default(),
            host_id: device.device_id.clone(),
            ip_addresses: device
                .local_ip
                .clone()
                .map(|ip| vec![ip])
                .unwrap_or_default(),
            mac_addresses: device
                .mac_address
                .clone()
                .map(|mac| vec![mac])
                .unwrap_or_default(),
            os: device.platform_name.clone().unwrap_or_default(),
            os_version: device.os_version.clone().unwrap_or_default(),
            agent_version: device.agent_version.clone().unwrap_or_default(),
            last_seen,
            isolated: device
                .device_policies
                .as_ref()
                .and_then(|p| p.containment.as_ref())
                .map(|c| c.applied.unwrap_or(false))
                .unwrap_or(false),
            status,
            tags: device.tags.clone().unwrap_or_default(),
        }
    }

    /// Parses a CrowdStrike detection into Detection.
    fn parse_detection(&self, det: &CSDetection) -> Detection {
        let timestamp = det
            .first_behavior
            .as_ref()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);

        let severity = match det.max_severity.unwrap_or(0) {
            0..=20 => "info",
            21..=40 => "low",
            41..=60 => "medium",
            61..=80 => "high",
            _ => "critical",
        }
        .to_string();

        Detection {
            id: det.detection_id.clone(),
            name: det
                .behaviors
                .as_ref()
                .and_then(|b| b.first())
                .and_then(|b| b.display_name.clone())
                .unwrap_or_else(|| "Unknown Detection".to_string()),
            severity,
            timestamp,
            description: det
                .behaviors
                .as_ref()
                .and_then(|b| b.first())
                .and_then(|b| b.description.clone())
                .unwrap_or_default(),
            tactic: det
                .behaviors
                .as_ref()
                .and_then(|b| b.first())
                .and_then(|b| b.tactic.clone()),
            technique: det
                .behaviors
                .as_ref()
                .and_then(|b| b.first())
                .and_then(|b| b.technique.clone()),
            file_hash: det
                .behaviors
                .as_ref()
                .and_then(|b| b.first())
                .and_then(|b| b.sha256.clone()),
            process_name: det
                .behaviors
                .as_ref()
                .and_then(|b| b.first())
                .and_then(|b| b.filename.clone()),
            details: {
                let mut m = HashMap::new();
                if let Some(behaviors) = &det.behaviors {
                    m.insert(
                        "behaviors".to_string(),
                        serde_json::to_value(behaviors).unwrap_or_default(),
                    );
                }
                if let Some(cid) = &det.cid {
                    m.insert("cid".to_string(), serde_json::json!(cid));
                }
                m
            },
        }
    }
}

#[async_trait]
impl crate::traits::Connector for CrowdStrikeConnector {
    fn name(&self) -> &str {
        &self.config.connector.name
    }

    fn connector_type(&self) -> &str {
        "edr"
    }

    async fn health_check(&self) -> ConnectorResult<ConnectorHealth> {
        // Check sensor installer details as a lightweight health check
        let path = "/policy/combined/reveal-uninstall-token/v1?device_id=health_check";
        match self.client.get(path).await {
            Ok(response) if response.status().is_success() => Ok(ConnectorHealth::Healthy),
            Ok(response) if response.status().as_u16() == 401 => Ok(ConnectorHealth::Unhealthy(
                "Authentication failed".to_string(),
            )),
            Ok(response) if response.status().as_u16() == 403 => Ok(ConnectorHealth::Unhealthy(
                "Authorization denied".to_string(),
            )),
            Ok(response) if response.status().as_u16() == 429 => {
                Ok(ConnectorHealth::Degraded("Rate limited".to_string()))
            }
            Ok(_) => Ok(ConnectorHealth::Healthy), // 404 is fine for health check
            Err(ConnectorError::ConnectionFailed(e)) => Ok(ConnectorHealth::Unhealthy(format!(
                "Connection failed: {}",
                e
            ))),
            Err(e) => Ok(ConnectorHealth::Unhealthy(e.to_string())),
        }
    }

    async fn test_connection(&self) -> ConnectorResult<bool> {
        // Try to list a single device as connection test
        let path = "/devices/queries/devices/v1?limit=1";
        let response = self.client.get(path).await?;
        Ok(response.status().is_success())
    }
}

#[async_trait]
impl EDRConnector for CrowdStrikeConnector {
    #[instrument(skip(self), fields(hostname = %hostname))]
    async fn get_host_info(&self, hostname: &str) -> ConnectorResult<HostInfo> {
        let aid = self.find_host_id(hostname).await?;
        self.get_host_by_id(&aid).await
    }

    #[instrument(skip(self))]
    async fn search_hosts(&self, query: &str, limit: usize) -> ConnectorResult<Vec<HostInfo>> {
        let filter = Self::build_host_filter(query);
        let path = format!(
            "/devices/queries/devices/v1?filter={}&limit={}",
            urlencoding::encode(&filter),
            limit
        );

        let response = self.client.get(&path).await?;

        if !response.status().is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ConnectorError::RequestFailed(format!(
                "Failed to search hosts: {}",
                body
            )));
        }

        let query_result: CSQueryResponse = response.json().await.map_err(|e| {
            ConnectorError::InvalidResponse(format!("Failed to parse response: {}", e))
        })?;

        if query_result.resources.is_empty() {
            return Ok(Vec::new());
        }

        // Get details for all found hosts
        let ids = query_result.resources.join("&ids=");
        let path = format!("/devices/entities/devices/v2?ids={}", ids);

        let response = self.client.get(&path).await?;

        if !response.status().is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ConnectorError::RequestFailed(format!(
                "Failed to get host details: {}",
                body
            )));
        }

        let devices_result: CSDevicesResponse = response.json().await.map_err(|e| {
            ConnectorError::InvalidResponse(format!("Failed to parse response: {}", e))
        })?;

        Ok(devices_result
            .resources
            .iter()
            .map(|d| self.parse_device(d))
            .collect())
    }

    #[instrument(skip(self), fields(hostname = %hostname))]
    async fn isolate_host(&self, hostname: &str) -> ConnectorResult<ActionResult> {
        let aid = self.find_host_id(hostname).await?;

        let body = serde_json::json!({
            "ids": [aid]
        });

        let path = "/devices/entities/devices-actions/v2?action_name=contain";
        let response = self.client.post(&path, &body).await?;

        if !response.status().is_success() {
            let error = response.text().await.unwrap_or_default();
            return Err(ConnectorError::RequestFailed(format!(
                "Failed to isolate host: {}",
                error
            )));
        }

        info!("Isolated host: {} (AID: {})", hostname, aid);

        Ok(ActionResult {
            success: true,
            action_id: format!("contain-{}", aid),
            message: format!("Host {} isolation initiated", hostname),
            timestamp: Utc::now(),
        })
    }

    #[instrument(skip(self), fields(hostname = %hostname))]
    async fn unisolate_host(&self, hostname: &str) -> ConnectorResult<ActionResult> {
        let aid = self.find_host_id(hostname).await?;

        let body = serde_json::json!({
            "ids": [aid]
        });

        let path = "/devices/entities/devices-actions/v2?action_name=lift_containment";
        let response = self.client.post(&path, &body).await?;

        if !response.status().is_success() {
            let error = response.text().await.unwrap_or_default();
            return Err(ConnectorError::RequestFailed(format!(
                "Failed to unisolate host: {}",
                error
            )));
        }

        info!("Removed isolation from host: {} (AID: {})", hostname, aid);

        Ok(ActionResult {
            success: true,
            action_id: format!("lift_containment-{}", aid),
            message: format!("Host {} isolation lifted", hostname),
            timestamp: Utc::now(),
        })
    }

    #[instrument(skip(self), fields(hostname = %hostname))]
    async fn get_host_detections(&self, hostname: &str) -> ConnectorResult<Vec<Detection>> {
        let filter = Self::build_detection_filter(hostname);
        let path = format!(
            "/detects/queries/detects/v1?filter={}",
            urlencoding::encode(&filter)
        );

        let response = self.client.get(&path).await?;

        if !response.status().is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ConnectorError::RequestFailed(format!(
                "Failed to query detections: {}",
                body
            )));
        }

        let query_result: CSQueryResponse = response.json().await.map_err(|e| {
            ConnectorError::InvalidResponse(format!("Failed to parse response: {}", e))
        })?;

        if query_result.resources.is_empty() {
            return Ok(Vec::new());
        }

        // Get detection details
        let body = serde_json::json!({
            "ids": query_result.resources
        });

        let response = self
            .client
            .post("/detects/entities/summaries/GET/v1", &body)
            .await?;

        if !response.status().is_success() {
            let error = response.text().await.unwrap_or_default();
            return Err(ConnectorError::RequestFailed(format!(
                "Failed to get detection details: {}",
                error
            )));
        }

        let detections_result: CSDetectionsResponse = response.json().await.map_err(|e| {
            ConnectorError::InvalidResponse(format!("Failed to parse detections: {}", e))
        })?;

        Ok(detections_result
            .resources
            .iter()
            .map(|d| self.parse_detection(d))
            .collect())
    }

    #[instrument(skip(self), fields(hostname = %hostname))]
    async fn get_processes(
        &self,
        hostname: &str,
        _timerange: TimeRange,
    ) -> ConnectorResult<Vec<ProcessInfo>> {
        // Note: Full process listing requires Real Time Response (RTR) API
        // which involves session management. For now, we return an empty list
        // and log a warning.
        warn!(
            "Process listing for {} requires RTR session (not implemented)",
            hostname
        );

        Ok(Vec::new())
    }

    #[instrument(skip(self), fields(hostname = %hostname))]
    async fn get_network_connections(
        &self,
        hostname: &str,
        _timerange: TimeRange,
    ) -> ConnectorResult<Vec<NetworkConnection>> {
        // Note: Network connection listing requires Real Time Response (RTR) API
        // which involves session management. For now, we return an empty list
        // and log a warning.
        warn!(
            "Network connection listing for {} requires RTR session (not implemented)",
            hostname
        );

        Ok(Vec::new())
    }
}

// CrowdStrike API response types

#[derive(Debug, Deserialize)]
struct CSQueryResponse {
    #[serde(default)]
    resources: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct CSDevicesResponse {
    #[serde(default)]
    resources: Vec<CSDevice>,
}

#[derive(Debug, Deserialize)]
struct CSDevice {
    device_id: String,
    hostname: Option<String>,
    local_ip: Option<String>,
    mac_address: Option<String>,
    platform_name: Option<String>,
    os_version: Option<String>,
    agent_version: Option<String>,
    last_seen: Option<String>,
    status: Option<String>,
    tags: Option<Vec<String>>,
    device_policies: Option<CSDevicePolicies>,
}

#[derive(Debug, Deserialize)]
struct CSDevicePolicies {
    containment: Option<CSContainmentPolicy>,
}

#[derive(Debug, Deserialize)]
struct CSContainmentPolicy {
    applied: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct CSDetectionsResponse {
    #[serde(default)]
    resources: Vec<CSDetection>,
}

#[derive(Debug, Deserialize, Serialize)]
struct CSDetection {
    detection_id: String,
    cid: Option<String>,
    first_behavior: Option<String>,
    max_severity: Option<u8>,
    behaviors: Option<Vec<CSBehavior>>,
}

#[derive(Debug, Deserialize, Serialize)]
struct CSBehavior {
    display_name: Option<String>,
    description: Option<String>,
    tactic: Option<String>,
    technique: Option<String>,
    filename: Option<String>,
    sha256: Option<String>,
    cmdline: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::AuthConfig;

    fn create_test_config() -> CrowdStrikeConfig {
        CrowdStrikeConfig {
            connector: ConnectorConfig {
                name: "crowdstrike-test".to_string(),
                base_url: "https://api.crowdstrike.com".to_string(),
                auth: AuthConfig::OAuth2 {
                    client_id: "test-client-id".to_string(),
                    client_secret: "test-client-secret".to_string(),
                    token_url: "https://api.crowdstrike.com/oauth2/token".to_string(),
                    scopes: vec!["hosts:read".to_string(), "hosts:write".to_string()],
                },
                timeout_secs: 30,
                max_retries: 3,
                verify_tls: true,
                headers: HashMap::new(),
            },
            region: "us-1".to_string(),
            member_cid: None,
        }
    }

    #[test]
    fn test_build_host_filter() {
        let filter = CrowdStrikeConnector::build_host_filter("workstation");
        assert!(filter.contains("hostname:*'workstation*'"));
        assert!(filter.contains("status:'normal'"));
    }

    #[test]
    fn test_build_host_filter_escaping() {
        let filter = CrowdStrikeConnector::build_host_filter("test'host");
        assert!(filter.contains("test\\'host"));
    }

    #[test]
    fn test_build_detection_filter() {
        let filter = CrowdStrikeConnector::build_detection_filter("workstation-001");
        assert_eq!(filter, "device.hostname:'workstation-001'");
    }

    #[test]
    fn test_region_urls() {
        assert_eq!(get_region_url("us-1"), "https://api.crowdstrike.com");
        assert_eq!(get_region_url("us-2"), "https://api.us-2.crowdstrike.com");
        assert_eq!(get_region_url("eu-1"), "https://api.eu-1.crowdstrike.com");
        assert_eq!(
            get_region_url("us-gov-1"),
            "https://api.laggar.gcw.crowdstrike.com"
        );
        assert_eq!(get_region_url("unknown"), "https://api.crowdstrike.com");
    }

    #[test]
    fn test_connector_creation() {
        let config = create_test_config();
        let connector = CrowdStrikeConnector::new(config);
        assert!(connector.is_ok());
    }
}
