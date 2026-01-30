//! Mock EDR connector for testing.
//!
//! Provides a configurable mock connector for testing EDR operations including
//! host management, detections, and response actions. Supports failure injection
//! and scenario-based testing.

use crate::traits::{
    ActionResult, ConnectorError, ConnectorHealth, ConnectorResult, Detection, EDRConnector,
    HostInfo, HostStatus, NetworkConnection, ProcessInfo, TimeRange,
};
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Behavior configuration for failure injection.
#[derive(Debug, Clone)]
pub enum MockBehavior {
    /// Normal operation.
    Normal,
    /// Fail isolation operations.
    FailIsolation(ConnectorError),
    /// Fail after N calls.
    FailAfter { calls: u64, error: ConnectorError },
    /// Always fail.
    AlwaysFail(ConnectorError),
    /// Unhealthy status.
    Unhealthy(String),
}

impl Default for MockBehavior {
    fn default() -> Self {
        Self::Normal
    }
}

/// Record of an action for test verification.
#[derive(Debug, Clone)]
pub struct ActionRecord {
    pub action_type: String,
    pub hostname: String,
    pub timestamp: chrono::DateTime<Utc>,
    pub success: bool,
}

/// Mock EDR connector for testing.
pub struct MockEDRConnector {
    name: String,
    hosts: Arc<RwLock<HashMap<String, HostInfo>>>,
    detections: Arc<RwLock<HashMap<String, Vec<Detection>>>>,
    processes: Arc<RwLock<HashMap<String, Vec<ProcessInfo>>>>,
    connections: Arc<RwLock<HashMap<String, Vec<NetworkConnection>>>>,
    behavior: Arc<RwLock<MockBehavior>>,
    call_count: AtomicU64,
    action_history: Arc<RwLock<Vec<ActionRecord>>>,
}

impl MockEDRConnector {
    /// Creates a new mock EDR connector.
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            hosts: Arc::new(RwLock::new(HashMap::new())),
            detections: Arc::new(RwLock::new(HashMap::new())),
            processes: Arc::new(RwLock::new(HashMap::new())),
            connections: Arc::new(RwLock::new(HashMap::new())),
            behavior: Arc::new(RwLock::new(MockBehavior::Normal)),
            call_count: AtomicU64::new(0),
            action_history: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Creates a mock EDR connector with sample data (synchronous version).
    pub fn with_sample_data(name: &str) -> Self {
        let now = Utc::now();
        Self {
            name: name.to_string(),
            hosts: Arc::new(RwLock::new(Self::create_sample_hosts(now))),
            detections: Arc::new(RwLock::new(Self::create_sample_detections(now))),
            processes: Arc::new(RwLock::new(Self::create_sample_processes(now))),
            connections: Arc::new(RwLock::new(Self::create_sample_connections(now))),
            behavior: Arc::new(RwLock::new(MockBehavior::Normal)),
            call_count: AtomicU64::new(0),
            action_history: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Creates with sample data (async version).
    pub async fn with_sample_data_async(name: &str) -> Self {
        Self::with_sample_data(name)
    }

    fn create_sample_hosts(now: DateTime<Utc>) -> HashMap<String, HostInfo> {
        let hosts_list = vec![
            HostInfo {
                hostname: "workstation-001".to_string(),
                host_id: "host-12345".to_string(),
                ip_addresses: vec!["192.168.1.100".to_string()],
                mac_addresses: vec!["00:11:22:33:44:55".to_string()],
                os: "Windows".to_string(),
                os_version: "Windows 10 Enterprise 21H2".to_string(),
                agent_version: "6.42.0".to_string(),
                last_seen: now,
                isolated: false,
                status: HostStatus::Online,
                tags: vec!["workstation".to_string(), "finance".to_string()],
            },
            HostInfo {
                hostname: "workstation-002".to_string(),
                host_id: "host-12346".to_string(),
                ip_addresses: vec!["192.168.1.101".to_string()],
                mac_addresses: vec!["00:11:22:33:44:56".to_string()],
                os: "Windows".to_string(),
                os_version: "Windows 11 Enterprise".to_string(),
                agent_version: "6.42.0".to_string(),
                last_seen: now,
                isolated: false,
                status: HostStatus::Online,
                tags: vec!["workstation".to_string(), "engineering".to_string()],
            },
            HostInfo {
                hostname: "server-001".to_string(),
                host_id: "host-67890".to_string(),
                ip_addresses: vec!["10.0.0.50".to_string()],
                mac_addresses: vec!["AA:BB:CC:DD:EE:FF".to_string()],
                os: "Linux".to_string(),
                os_version: "Ubuntu 22.04 LTS".to_string(),
                agent_version: "6.42.0".to_string(),
                last_seen: now,
                isolated: false,
                status: HostStatus::Online,
                tags: vec![
                    "server".to_string(),
                    "production".to_string(),
                    "critical".to_string(),
                ],
            },
            HostInfo {
                hostname: "dc01".to_string(),
                host_id: "host-99999".to_string(),
                ip_addresses: vec!["10.0.0.10".to_string()],
                mac_addresses: vec!["AA:BB:CC:DD:EE:00".to_string()],
                os: "Windows".to_string(),
                os_version: "Windows Server 2019".to_string(),
                agent_version: "6.42.0".to_string(),
                last_seen: now,
                isolated: false,
                status: HostStatus::Online,
                tags: vec![
                    "server".to_string(),
                    "domain-controller".to_string(),
                    "critical".to_string(),
                ],
            },
        ];

        let mut hosts = HashMap::new();
        for host in hosts_list {
            hosts.insert(host.hostname.clone(), host);
        }
        hosts
    }

    fn create_sample_detections(now: DateTime<Utc>) -> HashMap<String, Vec<Detection>> {
        let mut detections = HashMap::new();

        detections.insert(
            "workstation-001".to_string(),
            vec![
                Detection {
                    id: "detection-001".to_string(),
                    name: "Suspicious PowerShell Execution".to_string(),
                    severity: "high".to_string(),
                    timestamp: now - Duration::minutes(10),
                    description: "PowerShell executed encoded command with suspicious parameters"
                        .to_string(),
                    tactic: Some("Execution".to_string()),
                    technique: Some("T1059.001".to_string()),
                    file_hash: Some("abc123def456".to_string()),
                    process_name: Some("powershell.exe".to_string()),
                    details: {
                        let mut m = HashMap::new();
                        m.insert(
                            "command_line".to_string(),
                            serde_json::json!("-enc SGVsbG8gV29ybGQ="),
                        );
                        m.insert("parent_process".to_string(), serde_json::json!("cmd.exe"));
                        m
                    },
                },
                Detection {
                    id: "detection-002".to_string(),
                    name: "Connection to Known Malicious IP".to_string(),
                    severity: "critical".to_string(),
                    timestamp: now - Duration::minutes(5),
                    description: "Process established connection to IP associated with botnet C2"
                        .to_string(),
                    tactic: Some("Command and Control".to_string()),
                    technique: Some("T1071.001".to_string()),
                    file_hash: None,
                    process_name: Some("rundll32.exe".to_string()),
                    details: {
                        let mut m = HashMap::new();
                        m.insert("dest_ip".to_string(), serde_json::json!("203.0.113.100"));
                        m.insert("dest_port".to_string(), serde_json::json!(443));
                        m
                    },
                },
            ],
        );

        detections.insert(
            "workstation-002".to_string(),
            vec![Detection {
                id: "detection-003".to_string(),
                name: "Credential Dumping Attempt".to_string(),
                severity: "critical".to_string(),
                timestamp: now - Duration::minutes(2),
                description: "Process attempted to access LSASS memory".to_string(),
                tactic: Some("Credential Access".to_string()),
                technique: Some("T1003.001".to_string()),
                file_hash: Some("malware123".to_string()),
                process_name: Some("mimikatz.exe".to_string()),
                details: HashMap::new(),
            }],
        );

        detections
    }

    fn create_sample_processes(now: DateTime<Utc>) -> HashMap<String, Vec<ProcessInfo>> {
        let mut processes = HashMap::new();

        processes.insert(
            "workstation-001".to_string(),
            vec![
                ProcessInfo {
                    pid: 4,
                    name: "System".to_string(),
                    command_line: "".to_string(),
                    parent_pid: None,
                    user: "NT AUTHORITY\\SYSTEM".to_string(),
                    start_time: now - Duration::hours(24),
                    file_hash: None,
                    file_path: None,
                },
                ProcessInfo {
                    pid: 1234,
                    name: "explorer.exe".to_string(),
                    command_line: "C:\\Windows\\explorer.exe".to_string(),
                    parent_pid: Some(4),
                    user: "DOMAIN\\user".to_string(),
                    start_time: now - Duration::hours(8),
                    file_hash: Some("explorer_hash".to_string()),
                    file_path: Some("C:\\Windows\\explorer.exe".to_string()),
                },
                ProcessInfo {
                    pid: 5678,
                    name: "chrome.exe".to_string(),
                    command_line: "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\""
                        .to_string(),
                    parent_pid: Some(1234),
                    user: "DOMAIN\\user".to_string(),
                    start_time: now - Duration::hours(2),
                    file_hash: Some("chrome_hash".to_string()),
                    file_path: Some(
                        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe".to_string(),
                    ),
                },
                ProcessInfo {
                    pid: 9999,
                    name: "powershell.exe".to_string(),
                    command_line: "powershell.exe -enc SGVsbG8gV29ybGQ=".to_string(),
                    parent_pid: Some(1234),
                    user: "DOMAIN\\user".to_string(),
                    start_time: now - Duration::minutes(10),
                    file_hash: Some("powershell_hash".to_string()),
                    file_path: Some(
                        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
                            .to_string(),
                    ),
                },
            ],
        );

        processes
    }

    fn create_sample_connections(now: DateTime<Utc>) -> HashMap<String, Vec<NetworkConnection>> {
        let mut connections = HashMap::new();

        connections.insert(
            "workstation-001".to_string(),
            vec![
                NetworkConnection {
                    pid: 5678,
                    process_name: "chrome.exe".to_string(),
                    local_address: "192.168.1.100".to_string(),
                    local_port: 54321,
                    remote_address: "142.250.80.68".to_string(),
                    remote_port: 443,
                    protocol: "TCP".to_string(),
                    state: "ESTABLISHED".to_string(),
                    timestamp: now,
                },
                NetworkConnection {
                    pid: 9999,
                    process_name: "powershell.exe".to_string(),
                    local_address: "192.168.1.100".to_string(),
                    local_port: 54322,
                    remote_address: "203.0.113.100".to_string(),
                    remote_port: 443,
                    protocol: "TCP".to_string(),
                    state: "ESTABLISHED".to_string(),
                    timestamp: now - Duration::minutes(5),
                },
            ],
        );

        connections
    }

    /// Adds a host to the mock.
    pub async fn add_host(&self, host: HostInfo) {
        self.hosts.write().await.insert(host.hostname.clone(), host);
    }

    /// Adds a detection to the mock.
    pub async fn add_detection(&self, hostname: &str, detection: Detection) {
        self.detections
            .write()
            .await
            .entry(hostname.to_string())
            .or_default()
            .push(detection);
    }

    /// Sets the behavior for failure injection.
    pub async fn set_behavior(&self, behavior: MockBehavior) {
        *self.behavior.write().await = behavior;
    }

    /// Gets the action history for test verification.
    pub async fn get_action_history(&self) -> Vec<ActionRecord> {
        self.action_history.read().await.clone()
    }

    /// Clears all data.
    pub async fn clear(&self) {
        self.hosts.write().await.clear();
        self.detections.write().await.clear();
        self.processes.write().await.clear();
        self.connections.write().await.clear();
        self.action_history.write().await.clear();
        self.call_count.store(0, Ordering::SeqCst);
    }

    /// Check behavior and apply any configured effects.
    async fn check_behavior(&self) -> ConnectorResult<()> {
        let count = self.call_count.fetch_add(1, Ordering::SeqCst) + 1;
        let behavior = self.behavior.read().await;

        match &*behavior {
            MockBehavior::Normal => Ok(()),
            MockBehavior::FailIsolation(_) => Ok(()), // Only affects isolation
            MockBehavior::FailAfter { calls, error } => {
                if count > *calls {
                    Err(error.clone())
                } else {
                    Ok(())
                }
            }
            MockBehavior::AlwaysFail(error) => Err(error.clone()),
            MockBehavior::Unhealthy(_) => Ok(()),
        }
    }

    /// Record an action.
    async fn record_action(&self, action_type: &str, hostname: &str, success: bool) {
        self.action_history.write().await.push(ActionRecord {
            action_type: action_type.to_string(),
            hostname: hostname.to_string(),
            timestamp: Utc::now(),
            success,
        });
    }
}

#[async_trait]
impl crate::traits::Connector for MockEDRConnector {
    fn name(&self) -> &str {
        &self.name
    }

    fn connector_type(&self) -> &str {
        "edr"
    }

    async fn health_check(&self) -> ConnectorResult<ConnectorHealth> {
        let behavior = self.behavior.read().await;
        match &*behavior {
            MockBehavior::Unhealthy(reason) => Ok(ConnectorHealth::Unhealthy(reason.clone())),
            MockBehavior::AlwaysFail(_) => {
                Ok(ConnectorHealth::Unhealthy("Always failing".to_string()))
            }
            _ => Ok(ConnectorHealth::Healthy),
        }
    }

    async fn test_connection(&self) -> ConnectorResult<bool> {
        let behavior = self.behavior.read().await;
        match &*behavior {
            MockBehavior::AlwaysFail(e) => Err(e.clone()),
            MockBehavior::Unhealthy(_) => Ok(false),
            _ => Ok(true),
        }
    }
}

#[async_trait]
impl EDRConnector for MockEDRConnector {
    async fn get_host_info(&self, hostname: &str) -> ConnectorResult<HostInfo> {
        self.check_behavior().await?;

        let hosts = self.hosts.read().await;
        hosts
            .get(hostname)
            .cloned()
            .ok_or_else(|| ConnectorError::NotFound(format!("Host not found: {}", hostname)))
    }

    async fn search_hosts(&self, query: &str, limit: usize) -> ConnectorResult<Vec<HostInfo>> {
        self.check_behavior().await?;

        let hosts = self.hosts.read().await;
        let query_lower = query.to_lowercase();

        let results: Vec<HostInfo> = hosts
            .values()
            .filter(|h| {
                h.hostname.to_lowercase().contains(&query_lower)
                    || h.ip_addresses.iter().any(|ip| ip.contains(&query_lower))
                    || h.tags
                        .iter()
                        .any(|t| t.to_lowercase().contains(&query_lower))
                    || h.host_id.to_lowercase().contains(&query_lower)
            })
            .take(limit)
            .cloned()
            .collect();

        Ok(results)
    }

    async fn isolate_host(&self, hostname: &str) -> ConnectorResult<ActionResult> {
        // Check for isolation-specific failure
        {
            let behavior = self.behavior.read().await;
            if let MockBehavior::FailIsolation(error) = &*behavior {
                self.record_action("isolate", hostname, false).await;
                return Err(error.clone());
            }
        }

        self.check_behavior().await?;

        let mut hosts = self.hosts.write().await;
        if let Some(host) = hosts.get_mut(hostname) {
            if host.isolated {
                self.record_action("isolate", hostname, false).await;
                return Err(ConnectorError::RequestFailed(format!(
                    "Host {} is already isolated",
                    hostname
                )));
            }

            host.isolated = true;
            self.record_action("isolate", hostname, true).await;

            Ok(ActionResult {
                success: true,
                action_id: format!("isolate-{}", uuid::Uuid::new_v4()),
                message: format!("Host {} isolated successfully", hostname),
                timestamp: Utc::now(),
            })
        } else {
            self.record_action("isolate", hostname, false).await;
            Err(ConnectorError::NotFound(format!(
                "Host not found: {}",
                hostname
            )))
        }
    }

    async fn unisolate_host(&self, hostname: &str) -> ConnectorResult<ActionResult> {
        self.check_behavior().await?;

        let mut hosts = self.hosts.write().await;
        if let Some(host) = hosts.get_mut(hostname) {
            if !host.isolated {
                self.record_action("unisolate", hostname, false).await;
                return Err(ConnectorError::RequestFailed(format!(
                    "Host {} is not isolated",
                    hostname
                )));
            }

            host.isolated = false;
            self.record_action("unisolate", hostname, true).await;

            Ok(ActionResult {
                success: true,
                action_id: format!("unisolate-{}", uuid::Uuid::new_v4()),
                message: format!("Host {} isolation removed", hostname),
                timestamp: Utc::now(),
            })
        } else {
            self.record_action("unisolate", hostname, false).await;
            Err(ConnectorError::NotFound(format!(
                "Host not found: {}",
                hostname
            )))
        }
    }

    async fn get_host_detections(&self, hostname: &str) -> ConnectorResult<Vec<Detection>> {
        self.check_behavior().await?;

        // Verify host exists
        {
            let hosts = self.hosts.read().await;
            if !hosts.contains_key(hostname) {
                return Err(ConnectorError::NotFound(format!(
                    "Host not found: {}",
                    hostname
                )));
            }
        }

        let detections = self.detections.read().await;
        Ok(detections.get(hostname).cloned().unwrap_or_default())
    }

    async fn get_processes(
        &self,
        hostname: &str,
        timerange: TimeRange,
    ) -> ConnectorResult<Vec<ProcessInfo>> {
        self.check_behavior().await?;

        // Verify host exists
        {
            let hosts = self.hosts.read().await;
            if !hosts.contains_key(hostname) {
                return Err(ConnectorError::NotFound(format!(
                    "Host not found: {}",
                    hostname
                )));
            }
        }

        let processes = self.processes.read().await;
        let host_processes = processes.get(hostname).cloned().unwrap_or_default();

        // Filter by timerange
        let filtered: Vec<ProcessInfo> = host_processes
            .into_iter()
            .filter(|p| p.start_time >= timerange.start && p.start_time <= timerange.end)
            .collect();

        Ok(filtered)
    }

    async fn get_network_connections(
        &self,
        hostname: &str,
        timerange: TimeRange,
    ) -> ConnectorResult<Vec<NetworkConnection>> {
        self.check_behavior().await?;

        // Verify host exists
        {
            let hosts = self.hosts.read().await;
            if !hosts.contains_key(hostname) {
                return Err(ConnectorError::NotFound(format!(
                    "Host not found: {}",
                    hostname
                )));
            }
        }

        let connections = self.connections.read().await;
        let host_connections = connections.get(hostname).cloned().unwrap_or_default();

        // Filter by timerange
        let filtered: Vec<NetworkConnection> = host_connections
            .into_iter()
            .filter(|c| c.timestamp >= timerange.start && c.timestamp <= timerange.end)
            .collect();

        Ok(filtered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_get_host_info() {
        let connector = MockEDRConnector::with_sample_data("test");
        let host = connector.get_host_info("workstation-001").await.unwrap();

        assert_eq!(host.hostname, "workstation-001");
        assert!(!host.isolated);
        assert!(host.tags.contains(&"finance".to_string()));
    }

    #[tokio::test]
    async fn test_host_not_found() {
        let connector = MockEDRConnector::with_sample_data("test");
        let result = connector.get_host_info("nonexistent").await;

        assert!(matches!(result, Err(ConnectorError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_isolate_host() {
        let connector = MockEDRConnector::with_sample_data("test");

        let result = connector.isolate_host("workstation-001").await.unwrap();
        assert!(result.success);

        let host = connector.get_host_info("workstation-001").await.unwrap();
        assert!(host.isolated);

        // Should fail if already isolated
        let result = connector.isolate_host("workstation-001").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_unisolate_host() {
        let connector = MockEDRConnector::with_sample_data("test");

        // First isolate
        connector.isolate_host("workstation-001").await.unwrap();

        // Then unisolate
        let result = connector.unisolate_host("workstation-001").await.unwrap();
        assert!(result.success);

        let host = connector.get_host_info("workstation-001").await.unwrap();
        assert!(!host.isolated);
    }

    #[tokio::test]
    async fn test_search_hosts() {
        let connector = MockEDRConnector::with_sample_data("test");

        let results = connector.search_hosts("finance", 10).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].hostname, "workstation-001");

        let results = connector.search_hosts("critical", 10).await.unwrap();
        assert_eq!(results.len(), 2); // server-001 and dc01
    }

    #[tokio::test]
    async fn test_get_detections() {
        let connector = MockEDRConnector::with_sample_data("test");
        let detections = connector
            .get_host_detections("workstation-001")
            .await
            .unwrap();

        assert_eq!(detections.len(), 2);
        assert!(detections
            .iter()
            .any(|d| d.name == "Suspicious PowerShell Execution"));
    }

    #[tokio::test]
    async fn test_failure_injection() {
        let connector = MockEDRConnector::with_sample_data("test");
        connector
            .set_behavior(MockBehavior::FailIsolation(ConnectorError::RequestFailed(
                "Network isolation not available".to_string(),
            )))
            .await;

        let result = connector.isolate_host("workstation-001").await;
        assert!(result.is_err());

        // But other operations should still work
        let host = connector.get_host_info("workstation-001").await.unwrap();
        assert!(!host.isolated);
    }

    #[tokio::test]
    async fn test_action_history() {
        let connector = MockEDRConnector::with_sample_data("test");

        connector.isolate_host("workstation-001").await.ok();
        connector.unisolate_host("workstation-001").await.ok();

        let history = connector.get_action_history().await;
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].action_type, "isolate");
        assert_eq!(history[1].action_type, "unisolate");
    }
}
