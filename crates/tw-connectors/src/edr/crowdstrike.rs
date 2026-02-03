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
use tracing::{debug, info, instrument, warn};

/// Default timeout for RTR command polling (30 seconds).
const RTR_COMMAND_TIMEOUT_SECS: u64 = 30;

/// Poll interval for RTR command results (500ms).
const RTR_POLL_INTERVAL_MS: u64 = 500;

/// Represents an active RTR (Real Time Response) session.
#[derive(Debug, Clone)]
pub struct RTRSession {
    /// The session ID returned by CrowdStrike.
    pub session_id: String,
    /// The device ID (AID) this session is connected to.
    pub device_id: String,
}

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

    /// FQL special characters that need escaping.
    /// Reference: CrowdStrike Falcon Query Language documentation
    /// Note: Hyphens in hostnames don't need escaping when used in quoted values.
    const FQL_SPECIAL_CHARS: &'static [char] =
        &['\'', '"', '\\', '*', '?', '[', ']', '+', ':', '/', '(', ')'];

    /// Escapes a value for safe use in FQL filters.
    /// This prevents FQL injection attacks by escaping all special characters.
    fn escape_fql(value: &str) -> String {
        let mut result = String::with_capacity(value.len() * 2);
        for c in value.chars() {
            if Self::FQL_SPECIAL_CHARS.contains(&c) {
                result.push('\\');
            }
            result.push(c);
        }
        result
    }

    /// Validates that a hostname only contains safe ASCII characters.
    ///
    /// This function enforces strict hostname validation to prevent:
    /// - Unicode lookalike character attacks (e.g., Cyrillic 'а' vs ASCII 'a')
    /// - FQL injection via specially crafted hostnames
    /// - Overly long hostnames that could cause issues
    ///
    /// Returns the normalized (lowercase) hostname on success.
    fn validate_hostname(hostname: &str) -> ConnectorResult<String> {
        // Check for empty hostname first
        if hostname.is_empty() {
            return Err(ConnectorError::ConfigError(
                "Hostname cannot be empty".to_string(),
            ));
        }

        // Enforce maximum hostname length per RFC 1035
        if hostname.len() > 253 {
            return Err(ConnectorError::ConfigError(
                "Hostname must not exceed 253 characters".to_string(),
            ));
        }

        // Normalize to lowercase for consistent validation and querying
        let normalized = hostname.to_lowercase();

        // Validate each character is ASCII and allowed in hostnames
        // Only allow: a-z, 0-9, hyphen, underscore, and dot
        for c in normalized.chars() {
            // First, reject ANY non-ASCII character to prevent Unicode lookalike attacks
            if !c.is_ascii() {
                return Err(ConnectorError::ConfigError(format!(
                    "Non-ASCII character in hostname (possible Unicode lookalike attack): '{}'",
                    c
                )));
            }

            // Then validate against allowed ASCII characters
            if !c.is_ascii_alphanumeric() && c != '-' && c != '_' && c != '.' {
                return Err(ConnectorError::ConfigError(format!(
                    "Invalid character '{}' in hostname",
                    c
                )));
            }
        }

        // Additional hostname format validation
        // Cannot start or end with hyphen or dot
        if normalized.starts_with('-')
            || normalized.ends_with('-')
            || normalized.starts_with('.')
            || normalized.ends_with('.')
        {
            return Err(ConnectorError::ConfigError(
                "Hostname cannot start or end with hyphen or dot".to_string(),
            ));
        }

        // Cannot have consecutive dots
        if normalized.contains("..") {
            return Err(ConnectorError::ConfigError(
                "Hostname cannot contain consecutive dots".to_string(),
            ));
        }

        Ok(normalized)
    }

    /// Builds a FQL filter for host search.
    pub fn build_host_filter(query: &str) -> String {
        let escaped = Self::escape_fql(query);
        format!("hostname:*'{}*'+status:'normal'", escaped)
    }

    /// Builds a FQL filter for detection search.
    pub fn build_detection_filter(hostname: &str) -> String {
        let escaped = Self::escape_fql(hostname);
        format!("device.hostname:'{}'", escaped)
    }

    /// Looks up hosts by hostname pattern.
    #[instrument(skip(self))]
    async fn find_host_id(&self, hostname: &str) -> ConnectorResult<String> {
        // Validate hostname and get normalized (lowercase) version
        // This prevents Unicode lookalike attacks before FQL escaping
        let normalized_hostname = Self::validate_hostname(hostname)?;
        // Apply FQL escaping AFTER validation to ensure safe query construction
        let filter = format!("hostname:'{}'", Self::escape_fql(&normalized_hostname));
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

    // ========================================================================
    // RTR (Real Time Response) Session Management
    // ========================================================================

    /// Initializes an RTR session with a device.
    ///
    /// # Arguments
    /// * `device_id` - The CrowdStrike Agent ID (AID) of the target device.
    ///
    /// # Returns
    /// An `RTRSession` containing the session ID and device ID.
    #[instrument(skip(self), fields(device_id = %device_id))]
    async fn init_rtr_session(&self, device_id: &str) -> ConnectorResult<RTRSession> {
        let body = serde_json::json!({
            "device_id": device_id,
            "queue_offline": false
        });

        let response = self
            .client
            .post("/real-time-response/entities/sessions/v1", &body)
            .await?;

        if !response.status().is_success() {
            let error = response.text().await.unwrap_or_default();
            return Err(ConnectorError::RequestFailed(format!(
                "Failed to init RTR session: {}",
                error
            )));
        }

        let result: RTRSessionResponse = response.json().await.map_err(|e| {
            ConnectorError::InvalidResponse(format!("Failed to parse RTR session response: {}", e))
        })?;

        let session =
            result.resources.into_iter().next().ok_or_else(|| {
                ConnectorError::InvalidResponse("No session returned".to_string())
            })?;

        info!(
            "RTR session initialized: {} for device {}",
            session.session_id, device_id
        );

        Ok(RTRSession {
            session_id: session.session_id,
            device_id: device_id.to_string(),
        })
    }

    /// Closes an RTR session.
    ///
    /// # Arguments
    /// * `session` - The RTR session to close.
    #[instrument(skip(self), fields(session_id = %session.session_id))]
    async fn close_rtr_session(&self, session: &RTRSession) -> ConnectorResult<()> {
        let path = format!(
            "/real-time-response/entities/sessions/v1?session_id={}",
            urlencoding::encode(&session.session_id)
        );

        let response = self.client.delete(&path).await?;

        if !response.status().is_success() {
            let error = response.text().await.unwrap_or_default();
            warn!(
                "Failed to close RTR session {}: {}",
                session.session_id, error
            );
            // Don't return error - session cleanup is best effort
        } else {
            info!("RTR session closed: {}", session.session_id);
        }

        Ok(())
    }

    /// Runs an RTR admin command and waits for the result.
    ///
    /// # Arguments
    /// * `session` - The active RTR session.
    /// * `base_command` - The base command (e.g., "ps", "netstat").
    /// * `command_string` - The full command string.
    ///
    /// # Returns
    /// The stdout output from the command.
    #[instrument(skip(self), fields(session_id = %session.session_id, command = %base_command))]
    async fn run_rtr_command(
        &self,
        session: &RTRSession,
        base_command: &str,
        command_string: &str,
    ) -> ConnectorResult<String> {
        // Execute the command
        let body = serde_json::json!({
            "device_id": session.device_id,
            "session_id": session.session_id,
            "base_command": base_command,
            "command_string": command_string
        });

        let response = self
            .client
            .post("/real-time-response/entities/admin-command/v1", &body)
            .await?;

        if !response.status().is_success() {
            let error = response.text().await.unwrap_or_default();
            return Err(ConnectorError::RequestFailed(format!(
                "Failed to execute RTR command: {}",
                error
            )));
        }

        let result: RTRCommandResponse = response.json().await.map_err(|e| {
            ConnectorError::InvalidResponse(format!("Failed to parse RTR command response: {}", e))
        })?;

        let command_result = result.resources.into_iter().next().ok_or_else(|| {
            ConnectorError::InvalidResponse("No command result returned".to_string())
        })?;

        let cloud_request_id = command_result.cloud_request_id;
        debug!(
            "RTR command submitted, cloud_request_id: {}",
            cloud_request_id
        );

        // Poll for command completion
        self.poll_rtr_command_result(&cloud_request_id).await
    }

    /// Polls for RTR command result until complete or timeout.
    #[instrument(skip(self), fields(cloud_request_id = %cloud_request_id))]
    async fn poll_rtr_command_result(&self, cloud_request_id: &str) -> ConnectorResult<String> {
        let start = std::time::Instant::now();
        let timeout = Duration::from_secs(RTR_COMMAND_TIMEOUT_SECS);
        let poll_interval = Duration::from_millis(RTR_POLL_INTERVAL_MS);

        loop {
            if start.elapsed() > timeout {
                return Err(ConnectorError::Timeout(format!(
                    "RTR command timed out after {} seconds",
                    RTR_COMMAND_TIMEOUT_SECS
                )));
            }

            let path = format!(
                "/real-time-response/entities/admin-command/v1?cloud_request_id={}&sequence_id=0",
                urlencoding::encode(cloud_request_id)
            );

            let response = self.client.get(&path).await?;

            if !response.status().is_success() {
                let error = response.text().await.unwrap_or_default();
                return Err(ConnectorError::RequestFailed(format!(
                    "Failed to get RTR command result: {}",
                    error
                )));
            }

            let result: RTRCommandResultResponse = response.json().await.map_err(|e| {
                ConnectorError::InvalidResponse(format!(
                    "Failed to parse RTR command result response: {}",
                    e
                ))
            })?;

            if let Some(resource) = result.resources.into_iter().next() {
                if resource.complete {
                    debug!("RTR command completed successfully");

                    // Check for errors in the command output
                    if let Some(stderr) = &resource.stderr {
                        if !stderr.is_empty() {
                            warn!("RTR command stderr: {}", stderr);
                        }
                    }

                    return Ok(resource.stdout.unwrap_or_default());
                }
            }

            tokio::time::sleep(poll_interval).await;
        }
    }

    /// Executes an RTR command with automatic session management.
    /// Ensures the session is always closed even on error.
    #[instrument(skip(self), fields(hostname = %hostname, command = %base_command))]
    async fn execute_rtr_command(
        &self,
        hostname: &str,
        base_command: &str,
        command_string: &str,
    ) -> ConnectorResult<String> {
        let aid = self.find_host_id(hostname).await?;
        let session = self.init_rtr_session(&aid).await?;

        // Use scopeguard pattern to ensure session cleanup
        let result = self
            .run_rtr_command(&session, base_command, command_string)
            .await;

        // Always close the session, even if the command failed
        if let Err(e) = self.close_rtr_session(&session).await {
            warn!("Error closing RTR session: {}", e);
        }

        result
    }

    // ========================================================================
    // Output Parsing
    // ========================================================================

    /// Parses the output of the RTR `ps` command into ProcessInfo structs.
    fn parse_ps_output(&self, output: &str) -> Vec<ProcessInfo> {
        let mut processes = Vec::new();

        for line in output.lines().skip(1) {
            // Skip header line
            if line.trim().is_empty() {
                continue;
            }

            if let Some(proc) = self.parse_ps_line(line) {
                processes.push(proc);
            }
        }

        processes
    }

    /// Parses a single line from `ps` output.
    /// CrowdStrike RTR ps output format is typically:
    /// PID PPID Name CommandLine User StartTime FilePath
    fn parse_ps_line(&self, line: &str) -> Option<ProcessInfo> {
        // Use regex to parse the ps output line
        // Format: PID | PPID | Name | User | StartTime | CommandLine/FilePath
        let parts: Vec<&str> = line.split_whitespace().collect();

        if parts.len() < 5 {
            return None;
        }

        let pid: u32 = parts.first()?.parse().ok()?;
        let parent_pid: Option<u32> = parts.get(1).and_then(|s| s.parse().ok());
        let name = parts.get(2)?.to_string();
        let user = parts.get(3).unwrap_or(&"").to_string();

        // Try to parse start time - it may be in various formats
        let start_time = parts
            .get(4)
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);

        // Command line and file path are typically the rest
        let command_line = if parts.len() > 5 {
            parts[5..].join(" ")
        } else {
            name.clone()
        };

        Some(ProcessInfo {
            pid,
            name,
            command_line: command_line.clone(),
            parent_pid,
            user,
            start_time,
            file_hash: None,
            file_path: Some(command_line),
        })
    }

    /// Parses the output of the RTR `netstat` command into NetworkConnection structs.
    fn parse_netstat_output(&self, output: &str) -> Vec<NetworkConnection> {
        let mut connections = Vec::new();

        for line in output.lines().skip(1) {
            // Skip header line
            if line.trim().is_empty() {
                continue;
            }

            if let Some(conn) = self.parse_netstat_line(line) {
                connections.push(conn);
            }
        }

        connections
    }

    /// Parses a single line from `netstat` output.
    /// CrowdStrike RTR netstat output format is typically:
    /// Protocol LocalAddress LocalPort RemoteAddress RemotePort State PID ProcessName
    fn parse_netstat_line(&self, line: &str) -> Option<NetworkConnection> {
        let parts: Vec<&str> = line.split_whitespace().collect();

        if parts.len() < 7 {
            return None;
        }

        let protocol = parts.first()?.to_string();
        let local_address = parts.get(1)?.to_string();
        let local_port: u16 = parts.get(2)?.parse().ok()?;
        let remote_address = parts.get(3)?.to_string();
        let remote_port: u16 = parts.get(4)?.parse().ok()?;
        let state = parts.get(5)?.to_string();
        let pid: u32 = parts.get(6)?.parse().ok()?;
        let process_name = parts.get(7).unwrap_or(&"").to_string();

        Some(NetworkConnection {
            pid,
            process_name,
            local_address,
            local_port,
            remote_address,
            remote_port,
            protocol,
            state,
            timestamp: Utc::now(),
        })
    }

    // ========================================================================
    // Detection Parsing
    // ========================================================================

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
        let response = self.client.post(path, &body).await?;

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
        let response = self.client.post(path, &body).await?;

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
        info!("Getting processes for host {} via RTR", hostname);

        let output = self.execute_rtr_command(hostname, "ps", "ps").await?;
        let processes = self.parse_ps_output(&output);

        info!("Retrieved {} processes from {}", processes.len(), hostname);
        Ok(processes)
    }

    #[instrument(skip(self), fields(hostname = %hostname))]
    async fn get_network_connections(
        &self,
        hostname: &str,
        _timerange: TimeRange,
    ) -> ConnectorResult<Vec<NetworkConnection>> {
        info!("Getting network connections for host {} via RTR", hostname);

        let output = self
            .execute_rtr_command(hostname, "netstat", "netstat")
            .await?;
        let connections = self.parse_netstat_output(&output);

        info!(
            "Retrieved {} network connections from {}",
            connections.len(),
            hostname
        );
        Ok(connections)
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

// RTR (Real Time Response) API response types

/// Response from RTR session initialization.
#[derive(Debug, Deserialize)]
struct RTRSessionResponse {
    #[serde(default)]
    resources: Vec<RTRSessionResource>,
}

/// A single RTR session resource.
#[derive(Debug, Deserialize)]
#[allow(dead_code)] // Fields are populated via deserialization
struct RTRSessionResource {
    session_id: String,
    #[serde(default)]
    scripts: Vec<serde_json::Value>,
}

/// Response from RTR command execution.
#[derive(Debug, Deserialize)]
struct RTRCommandResponse {
    #[serde(default)]
    resources: Vec<RTRCommandResource>,
}

/// A single RTR command resource.
#[derive(Debug, Deserialize)]
#[allow(dead_code)] // Fields are populated via deserialization
struct RTRCommandResource {
    cloud_request_id: String,
    session_id: String,
    #[serde(default)]
    complete: bool,
    stdout: Option<String>,
    stderr: Option<String>,
}

/// Response from RTR command result polling.
#[derive(Debug, Deserialize)]
struct RTRCommandResultResponse {
    #[serde(default)]
    resources: Vec<RTRCommandResultResource>,
}

/// A single RTR command result resource.
#[derive(Debug, Deserialize)]
#[allow(dead_code)] // Fields are populated via deserialization
struct RTRCommandResultResource {
    session_id: String,
    cloud_request_id: String,
    #[serde(default)]
    complete: bool,
    stdout: Option<String>,
    stderr: Option<String>,
    #[serde(default)]
    sequence_id: i32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_string::SecureString;
    use crate::traits::AuthConfig;

    fn create_test_config() -> CrowdStrikeConfig {
        CrowdStrikeConfig {
            connector: ConnectorConfig {
                name: "crowdstrike-test".to_string(),
                base_url: "https://api.crowdstrike.com".to_string(),
                auth: AuthConfig::OAuth2 {
                    client_id: "test-client-id".to_string(),
                    client_secret: SecureString::new("test-client-secret".to_string()),
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

    // RTR Output Parsing Tests

    #[test]
    fn test_parse_ps_output() {
        let config = create_test_config();
        let connector = CrowdStrikeConnector::new(config).unwrap();

        let ps_output = r#"PID PPID Name User StartTime CommandLine
1234 1 chrome.exe DOMAIN\user 2024-01-15T10:30:00Z C:\Program Files\Chrome\chrome.exe --flag
5678 1234 notepad.exe DOMAIN\user 2024-01-15T10:31:00Z C:\Windows\System32\notepad.exe
9012 0 System SYSTEM 2024-01-15T08:00:00Z System"#;

        let processes = connector.parse_ps_output(ps_output);

        assert_eq!(processes.len(), 3);

        let chrome = &processes[0];
        assert_eq!(chrome.pid, 1234);
        assert_eq!(chrome.parent_pid, Some(1));
        assert_eq!(chrome.name, "chrome.exe");
        assert_eq!(chrome.user, "DOMAIN\\user");

        let notepad = &processes[1];
        assert_eq!(notepad.pid, 5678);
        assert_eq!(notepad.parent_pid, Some(1234));
        assert_eq!(notepad.name, "notepad.exe");

        let system = &processes[2];
        assert_eq!(system.pid, 9012);
        assert_eq!(system.parent_pid, Some(0));
        assert_eq!(system.name, "System");
    }

    #[test]
    fn test_parse_ps_output_empty() {
        let config = create_test_config();
        let connector = CrowdStrikeConnector::new(config).unwrap();

        let ps_output = "PID PPID Name User StartTime CommandLine\n";
        let processes = connector.parse_ps_output(ps_output);
        assert!(processes.is_empty());
    }

    #[test]
    fn test_parse_ps_output_malformed_lines() {
        let config = create_test_config();
        let connector = CrowdStrikeConnector::new(config).unwrap();

        let ps_output = r#"PID PPID Name User StartTime CommandLine
1234 1 chrome.exe DOMAIN\user 2024-01-15T10:30:00Z C:\Chrome\chrome.exe
invalid line
5678 abc notepad.exe"#;

        let processes = connector.parse_ps_output(ps_output);
        // Should skip invalid lines but parse valid ones
        assert_eq!(processes.len(), 1);
        assert_eq!(processes[0].pid, 1234);
    }

    #[test]
    fn test_parse_netstat_output() {
        let config = create_test_config();
        let connector = CrowdStrikeConnector::new(config).unwrap();

        let netstat_output = r#"Protocol LocalAddress LocalPort RemoteAddress RemotePort State PID ProcessName
TCP 192.168.1.100 52341 142.250.190.78 443 ESTABLISHED 1234 chrome.exe
TCP 0.0.0.0 80 0.0.0.0 0 LISTENING 4 System
UDP 192.168.1.100 53 8.8.8.8 53 ESTABLISHED 5678 dns.exe"#;

        let connections = connector.parse_netstat_output(netstat_output);

        assert_eq!(connections.len(), 3);

        let chrome_conn = &connections[0];
        assert_eq!(chrome_conn.protocol, "TCP");
        assert_eq!(chrome_conn.local_address, "192.168.1.100");
        assert_eq!(chrome_conn.local_port, 52341);
        assert_eq!(chrome_conn.remote_address, "142.250.190.78");
        assert_eq!(chrome_conn.remote_port, 443);
        assert_eq!(chrome_conn.state, "ESTABLISHED");
        assert_eq!(chrome_conn.pid, 1234);
        assert_eq!(chrome_conn.process_name, "chrome.exe");

        let system_conn = &connections[1];
        assert_eq!(system_conn.protocol, "TCP");
        assert_eq!(system_conn.local_port, 80);
        assert_eq!(system_conn.state, "LISTENING");
        assert_eq!(system_conn.pid, 4);
    }

    #[test]
    fn test_parse_netstat_output_empty() {
        let config = create_test_config();
        let connector = CrowdStrikeConnector::new(config).unwrap();

        let netstat_output =
            "Protocol LocalAddress LocalPort RemoteAddress RemotePort State PID ProcessName\n";
        let connections = connector.parse_netstat_output(netstat_output);
        assert!(connections.is_empty());
    }

    #[test]
    fn test_parse_netstat_output_malformed_lines() {
        let config = create_test_config();
        let connector = CrowdStrikeConnector::new(config).unwrap();

        let netstat_output = r#"Protocol LocalAddress LocalPort RemoteAddress RemotePort State PID ProcessName
TCP 192.168.1.100 52341 142.250.190.78 443 ESTABLISHED 1234 chrome.exe
invalid
TCP short"#;

        let connections = connector.parse_netstat_output(netstat_output);
        // Should skip invalid lines but parse valid ones
        assert_eq!(connections.len(), 1);
        assert_eq!(connections[0].pid, 1234);
    }

    #[test]
    fn test_parse_ps_line_minimal() {
        let config = create_test_config();
        let connector = CrowdStrikeConnector::new(config).unwrap();

        // Test with minimal valid data (5 fields)
        let line = "100 0 init root 2024-01-15T00:00:00Z";
        let proc = connector.parse_ps_line(line);
        assert!(proc.is_some());

        let proc = proc.unwrap();
        assert_eq!(proc.pid, 100);
        assert_eq!(proc.parent_pid, Some(0));
        assert_eq!(proc.name, "init");
        assert_eq!(proc.user, "root");
    }

    #[test]
    fn test_parse_netstat_line_minimal() {
        let config = create_test_config();
        let connector = CrowdStrikeConnector::new(config).unwrap();

        // Test with minimal valid data (7 fields - no process name)
        let line = "TCP 127.0.0.1 8080 0.0.0.0 0 LISTENING 1000";
        let conn = connector.parse_netstat_line(line);
        assert!(conn.is_some());

        let conn = conn.unwrap();
        assert_eq!(conn.protocol, "TCP");
        assert_eq!(conn.local_address, "127.0.0.1");
        assert_eq!(conn.local_port, 8080);
        assert_eq!(conn.remote_address, "0.0.0.0");
        assert_eq!(conn.remote_port, 0);
        assert_eq!(conn.state, "LISTENING");
        assert_eq!(conn.pid, 1000);
        assert_eq!(conn.process_name, ""); // No process name provided
    }

    // RTR Response Parsing Tests

    #[test]
    fn test_rtr_session_response_deserialization() {
        let json = r#"{
            "resources": [{
                "session_id": "abc-123-def-456",
                "scripts": []
            }]
        }"#;

        let response: RTRSessionResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.resources.len(), 1);
        assert_eq!(response.resources[0].session_id, "abc-123-def-456");
    }

    #[test]
    fn test_rtr_command_response_deserialization() {
        let json = r#"{
            "resources": [{
                "cloud_request_id": "cloud-req-123",
                "session_id": "session-456",
                "complete": false,
                "stdout": null,
                "stderr": null
            }]
        }"#;

        let response: RTRCommandResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.resources.len(), 1);
        assert_eq!(response.resources[0].cloud_request_id, "cloud-req-123");
        assert!(!response.resources[0].complete);
    }

    #[test]
    fn test_rtr_command_result_response_deserialization() {
        let json = r#"{
            "resources": [{
                "session_id": "session-456",
                "cloud_request_id": "cloud-req-123",
                "complete": true,
                "stdout": "PID PPID Name\n1234 1 test.exe",
                "stderr": "",
                "sequence_id": 0
            }]
        }"#;

        let response: RTRCommandResultResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.resources.len(), 1);
        assert!(response.resources[0].complete);
        assert!(response.resources[0].stdout.is_some());
        assert!(response.resources[0]
            .stdout
            .as_ref()
            .unwrap()
            .contains("test.exe"));
    }

    #[test]
    fn test_rtr_session_response_empty_resources() {
        let json = r#"{"resources": []}"#;
        let response: RTRSessionResponse = serde_json::from_str(json).unwrap();
        assert!(response.resources.is_empty());
    }

    // ========================================================================
    // Hostname Validation Tests - Unicode Bypass Prevention
    // ========================================================================

    #[test]
    fn test_validate_hostname_valid() {
        // Valid hostnames should pass and be normalized to lowercase
        let result = CrowdStrikeConnector::validate_hostname("workstation-001");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "workstation-001");

        let result = CrowdStrikeConnector::validate_hostname("SERVER.DOMAIN.COM");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "server.domain.com");

        let result = CrowdStrikeConnector::validate_hostname("host_name_123");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "host_name_123");
    }

    #[test]
    fn test_validate_hostname_lowercase_normalization() {
        // Verify uppercase is normalized to lowercase
        let result = CrowdStrikeConnector::validate_hostname("WORKSTATION-001");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "workstation-001");

        let result = CrowdStrikeConnector::validate_hostname("MixedCase.Host");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "mixedcase.host");
    }

    #[test]
    fn test_validate_hostname_empty() {
        let result = CrowdStrikeConnector::validate_hostname("");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ConnectorError::ConfigError(_)));
    }

    #[test]
    fn test_validate_hostname_too_long() {
        // 254 characters should fail
        let long_hostname = "a".repeat(254);
        let result = CrowdStrikeConnector::validate_hostname(&long_hostname);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ConnectorError::ConfigError(_)));

        // 253 characters should pass
        let max_hostname = "a".repeat(253);
        let result = CrowdStrikeConnector::validate_hostname(&max_hostname);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_hostname_unicode_cyrillic_lookalike() {
        // Cyrillic 'а' (U+0430) looks like ASCII 'a'
        // This is a common homoglyph attack
        let hostname_with_cyrillic_a = "workst\u{0430}tion"; // Contains Cyrillic 'а'
        let result = CrowdStrikeConnector::validate_hostname(hostname_with_cyrillic_a);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ConnectorError::ConfigError(_)));
        if let ConnectorError::ConfigError(msg) = err {
            assert!(msg.contains("Non-ASCII") || msg.contains("Unicode lookalike"));
        }
    }

    #[test]
    fn test_validate_hostname_unicode_greek_lookalike() {
        // Greek 'ο' (U+03BF) looks like ASCII 'o'
        let hostname_with_greek_o = "workstati\u{03BF}n"; // Contains Greek 'ο'
        let result = CrowdStrikeConnector::validate_hostname(hostname_with_greek_o);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_hostname_unicode_fullwidth_chars() {
        // Fullwidth Latin 'A' (U+FF21) could bypass filters
        let hostname_with_fullwidth = "\u{FF21}dmin-workstation"; // Fullwidth 'A'
        let result = CrowdStrikeConnector::validate_hostname(hostname_with_fullwidth);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_hostname_unicode_invisible_chars() {
        // Zero-width space (U+200B) is invisible
        let hostname_with_zwsp = "work\u{200B}station"; // Contains zero-width space
        let result = CrowdStrikeConnector::validate_hostname(hostname_with_zwsp);
        assert!(result.is_err());

        // Zero-width joiner (U+200D)
        let hostname_with_zwj = "work\u{200D}station";
        let result = CrowdStrikeConnector::validate_hostname(hostname_with_zwj);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_hostname_unicode_combining_chars() {
        // Combining acute accent (U+0301) could alter appearance
        let hostname_with_combining = "workstation\u{0301}";
        let result = CrowdStrikeConnector::validate_hostname(hostname_with_combining);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_hostname_unicode_rtl_override() {
        // Right-to-left override (U+202E) could confuse display
        let hostname_with_rtl = "work\u{202E}station";
        let result = CrowdStrikeConnector::validate_hostname(hostname_with_rtl);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_hostname_unicode_mathematical_lookalikes() {
        // Mathematical italic 'h' (U+210E) looks similar to ASCII 'h'
        let hostname_with_math = "\u{210E}ostname";
        let result = CrowdStrikeConnector::validate_hostname(hostname_with_math);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_hostname_fql_injection_attempts() {
        // FQL special characters should be rejected even though they'd be escaped
        // These test that the character validation happens
        let injection_attempts = vec![
            "host'name",        // Single quote
            "host\"name",       // Double quote
            "host\\name",       // Backslash
            "host*name",        // Asterisk
            "host?name",        // Question mark
            "host[0]",          // Square brackets
            "host+name",        // Plus
            "host:name",        // Colon
            "host/name",        // Slash
            "host(name)",       // Parentheses
            "hostname'+OR+1=1", // SQL/FQL injection pattern
        ];

        for hostname in injection_attempts {
            let result = CrowdStrikeConnector::validate_hostname(hostname);
            assert!(
                result.is_err(),
                "Should reject hostname with FQL chars: {}",
                hostname
            );
        }
    }

    #[test]
    fn test_validate_hostname_format_invalid_start_end() {
        // Cannot start with hyphen
        let result = CrowdStrikeConnector::validate_hostname("-hostname");
        assert!(result.is_err());

        // Cannot end with hyphen
        let result = CrowdStrikeConnector::validate_hostname("hostname-");
        assert!(result.is_err());

        // Cannot start with dot
        let result = CrowdStrikeConnector::validate_hostname(".hostname");
        assert!(result.is_err());

        // Cannot end with dot
        let result = CrowdStrikeConnector::validate_hostname("hostname.");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_hostname_consecutive_dots() {
        let result = CrowdStrikeConnector::validate_hostname("host..name");
        assert!(result.is_err());

        let result = CrowdStrikeConnector::validate_hostname("sub...domain.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_hostname_all_unicode_categories() {
        // Test various Unicode categories that could be used for bypasses
        let unicode_tests = vec![
            ("\u{00E0}", "Latin small letter a with grave"),
            ("\u{0101}", "Latin small letter a with macron"),
            ("\u{0430}", "Cyrillic small letter a"),
            ("\u{0435}", "Cyrillic small letter ie"),
            ("\u{043E}", "Cyrillic small letter o"),
            ("\u{0440}", "Cyrillic small letter er"),
            ("\u{0441}", "Cyrillic small letter es"),
            ("\u{0445}", "Cyrillic small letter ha"),
            ("\u{03B1}", "Greek small letter alpha"),
            ("\u{03BF}", "Greek small letter omicron"),
            ("\u{2010}", "Hyphen"),
            ("\u{2011}", "Non-breaking hyphen"),
            ("\u{2012}", "Figure dash"),
            ("\u{2013}", "En dash"),
            ("\u{2014}", "Em dash"),
            ("\u{FF0D}", "Fullwidth hyphen-minus"),
            ("\u{2024}", "One dot leader"),
            ("\u{2027}", "Hyphenation point"),
            ("\u{FF0E}", "Fullwidth full stop"),
        ];

        for (char_str, description) in unicode_tests {
            let hostname = format!("host{}name", char_str);
            let result = CrowdStrikeConnector::validate_hostname(&hostname);
            assert!(
                result.is_err(),
                "Should reject hostname containing {} ({})",
                description,
                char_str
            );
        }
    }

    #[test]
    fn test_validate_hostname_preserves_valid_after_lowercase() {
        // Ensure valid characters are preserved after lowercase conversion
        let result = CrowdStrikeConnector::validate_hostname("ABC123-DEF_GHI.JKL");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "abc123-def_ghi.jkl");
    }
}
