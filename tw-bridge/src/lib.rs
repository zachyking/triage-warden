//! # tw-bridge
//!
//! Rust-Python bridge using PyO3 for Triage Warden.
//!
//! This crate provides Python bindings for the core Triage Warden functionality,
//! allowing the Python AI components to interact with Rust connectors and the orchestrator.
//!
//! ## Usage
//!
//! ```python
//! from tw_bridge import ThreatIntelBridge, SIEMBridge, EDRBridge
//!
//! # Threat Intelligence lookups
//! ti = ThreatIntelBridge("mock")
//! result = ti.lookup_hash("abc123")  # Returns dict
//! result = ti.lookup_ip("192.168.1.1")
//! result = ti.lookup_domain("evil.example.com")
//!
//! # SIEM search
//! siem = SIEMBridge("mock")
//! results = siem.search("login_failure", 24)  # Search last 24 hours
//! alerts = siem.get_recent_alerts(10)  # Get 10 most recent alerts
//!
//! # EDR operations
//! edr = EDRBridge("mock")
//! host = edr.get_host_info("workstation-001")
//! result = edr.isolate_host("workstation-001")
//! detections = edr.get_detections("workstation-001")
//! ```

use once_cell::sync::OnceCell;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::runtime::Runtime;
use uuid::Uuid;

use tw_connectors::edr::mock::MockEDRConnector;
use tw_connectors::siem::mock::MockSIEMConnector;
use tw_connectors::threat_intel::mock::MockThreatIntelConnector;
use tw_connectors::traits::{EDRConnector, SIEMConnector, ThreatIntelConnector, TimeRange};
use tw_policy::{
    ApprovalLevel, ApprovalManager, KillSwitch, ModeManager, OperationMode, PolicyDecision,
    PolicyEngine,
};

/// Global Tokio runtime for blocking async operations.
static TOKIO_RUNTIME: OnceCell<Runtime> = OnceCell::new();

/// Gets or initializes the shared Tokio runtime.
fn get_runtime() -> &'static Runtime {
    TOKIO_RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(4)
            .thread_name("tw-bridge-worker")
            .build()
            .expect("Failed to create Tokio runtime")
    })
}

/// Converts a ConnectorError to a Python exception.
fn connector_error_to_py(err: tw_connectors::ConnectorError) -> PyErr {
    PyRuntimeError::new_err(format!("Connector error: {}", err))
}

/// Python-compatible triage request.
#[pyclass]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PyTriageRequest {
    #[pyo3(get, set)]
    pub incident_id: String,
    #[pyo3(get, set)]
    pub alert_data: String, // JSON string
    #[pyo3(get, set)]
    pub enrichments: String, // JSON string
}

#[pymethods]
impl PyTriageRequest {
    #[new]
    pub fn new(incident_id: String, alert_data: String, enrichments: String) -> Self {
        Self {
            incident_id,
            alert_data,
            enrichments,
        }
    }
}

/// Python-compatible triage result.
#[pyclass]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PyTriageResult {
    #[pyo3(get)]
    pub success: bool,
    #[pyo3(get)]
    pub verdict: String,
    #[pyo3(get)]
    pub confidence: f64,
    #[pyo3(get)]
    pub summary: String,
    #[pyo3(get)]
    pub reasoning: String,
    #[pyo3(get)]
    pub recommended_actions: String, // JSON array
    #[pyo3(get)]
    pub mitre_techniques: String, // JSON array
    #[pyo3(get)]
    pub error: Option<String>,
}

#[pymethods]
impl PyTriageResult {
    #[new]
    pub fn new(
        success: bool,
        verdict: String,
        confidence: f64,
        summary: String,
        reasoning: String,
        recommended_actions: String,
        mitre_techniques: String,
        error: Option<String>,
    ) -> Self {
        Self {
            success,
            verdict,
            confidence,
            summary,
            reasoning,
            recommended_actions,
            mitre_techniques,
            error,
        }
    }

    /// Create a failure result.
    #[staticmethod]
    pub fn failure(error: String) -> Self {
        Self {
            success: false,
            verdict: "error".to_string(),
            confidence: 0.0,
            summary: String::new(),
            reasoning: String::new(),
            recommended_actions: "[]".to_string(),
            mitre_techniques: "[]".to_string(),
            error: Some(error),
        }
    }
}

/// Python-compatible threat intel result.
#[pyclass]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PyThreatIntelResult {
    #[pyo3(get)]
    pub indicator_type: String,
    #[pyo3(get)]
    pub indicator: String,
    #[pyo3(get)]
    pub verdict: String,
    #[pyo3(get)]
    pub malicious_score: u8,
    #[pyo3(get)]
    pub malicious_count: u32,
    #[pyo3(get)]
    pub total_engines: u32,
    #[pyo3(get)]
    pub categories: String, // JSON array
    #[pyo3(get)]
    pub source: String,
}

#[pymethods]
impl PyThreatIntelResult {
    #[new]
    pub fn new(
        indicator_type: String,
        indicator: String,
        verdict: String,
        malicious_score: u8,
        malicious_count: u32,
        total_engines: u32,
        categories: String,
        source: String,
    ) -> Self {
        Self {
            indicator_type,
            indicator,
            verdict,
            malicious_score,
            malicious_count,
            total_engines,
            categories,
            source,
        }
    }

    /// Create an unknown result.
    #[staticmethod]
    pub fn unknown(indicator_type: String, indicator: String) -> Self {
        Self {
            indicator_type,
            indicator,
            verdict: "unknown".to_string(),
            malicious_score: 0,
            malicious_count: 0,
            total_engines: 0,
            categories: "[]".to_string(),
            source: "none".to_string(),
        }
    }
}

/// Python-compatible host info.
#[pyclass]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PyHostInfo {
    #[pyo3(get)]
    pub hostname: String,
    #[pyo3(get)]
    pub host_id: String,
    #[pyo3(get)]
    pub ip_addresses: String, // JSON array
    #[pyo3(get)]
    pub os: String,
    #[pyo3(get)]
    pub os_version: String,
    #[pyo3(get)]
    pub isolated: bool,
    #[pyo3(get)]
    pub status: String,
}

/// Bridge configuration.
#[pyclass]
#[derive(Clone, Debug)]
pub struct BridgeConfig {
    #[pyo3(get, set)]
    pub config_path: String,
}

#[pymethods]
impl BridgeConfig {
    #[new]
    pub fn new(config_path: String) -> Self {
        Self { config_path }
    }
}

// ============================================================================
// ThreatIntelBridge - Threat Intelligence Connector Bridge
// ============================================================================

/// Bridge for threat intelligence lookups.
///
/// Provides Python access to threat intel connectors for looking up
/// indicators of compromise (IOCs) including hashes, IPs, domains, and URLs.
///
/// Example:
///     ti = ThreatIntelBridge("mock")
///     result = ti.lookup_hash("44d88612fea8a8f36de82e1278abb02f")
///     print(result)  # Returns dict with verdict, score, etc.
#[pyclass]
pub struct ThreatIntelBridge {
    connector: Arc<MockThreatIntelConnector>,
    connector_type: String,
}

#[pymethods]
impl ThreatIntelBridge {
    /// Creates a new ThreatIntelBridge.
    ///
    /// Args:
    ///     connector_type: Type of connector to use (currently only "mock" supported)
    ///
    /// Returns:
    ///     ThreatIntelBridge instance
    ///
    /// Raises:
    ///     ValueError: If connector_type is not supported
    #[new]
    pub fn new(connector_type: &str) -> PyResult<Self> {
        match connector_type {
            "mock" => Ok(Self {
                connector: Arc::new(MockThreatIntelConnector::new("mock")),
                connector_type: connector_type.to_string(),
            }),
            _ => Err(PyValueError::new_err(format!(
                "Unsupported connector type: {}. Supported: mock",
                connector_type
            ))),
        }
    }

    /// Returns the connector type.
    pub fn get_connector_type(&self) -> String {
        self.connector_type.clone()
    }

    /// Look up a file hash in threat intelligence.
    ///
    /// Args:
    ///     hash: File hash (MD5, SHA1, or SHA256)
    ///
    /// Returns:
    ///     dict with threat intelligence results including:
    ///         - indicator_type: Type of hash (md5, sha1, sha256)
    ///         - indicator: The hash value
    ///         - verdict: malicious, suspicious, clean, or unknown
    ///         - malicious_score: Score from 0-100
    ///         - malicious_count: Number of engines flagging as malicious
    ///         - total_engines: Total engines that analyzed
    ///         - categories: List of threat categories
    ///         - malware_families: List of identified malware families
    ///         - source: Intelligence source
    ///
    /// Raises:
    ///     RuntimeError: If the lookup fails
    pub fn lookup_hash(&self, py: Python<'_>, hash: &str) -> PyResult<PyObject> {
        let connector = Arc::clone(&self.connector);
        let hash = hash.to_string();

        let result = get_runtime()
            .block_on(async move { connector.lookup_hash(&hash).await })
            .map_err(connector_error_to_py)?;

        pythonize::pythonize(py, &result)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))
    }

    /// Look up an IP address in threat intelligence.
    ///
    /// Args:
    ///     ip: IP address (IPv4 or IPv6)
    ///
    /// Returns:
    ///     dict with threat intelligence results
    ///
    /// Raises:
    ///     ValueError: If IP address is invalid
    ///     RuntimeError: If the lookup fails
    pub fn lookup_ip(&self, py: Python<'_>, ip: &str) -> PyResult<PyObject> {
        let ip_addr: IpAddr = ip
            .parse()
            .map_err(|e| PyValueError::new_err(format!("Invalid IP address: {}", e)))?;

        let connector = Arc::clone(&self.connector);

        let result = get_runtime()
            .block_on(async move { connector.lookup_ip(&ip_addr).await })
            .map_err(connector_error_to_py)?;

        pythonize::pythonize(py, &result)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))
    }

    /// Look up a domain in threat intelligence.
    ///
    /// Args:
    ///     domain: Domain name to look up
    ///
    /// Returns:
    ///     dict with threat intelligence results
    ///
    /// Raises:
    ///     RuntimeError: If the lookup fails
    pub fn lookup_domain(&self, py: Python<'_>, domain: &str) -> PyResult<PyObject> {
        let connector = Arc::clone(&self.connector);
        let domain = domain.to_string();

        let result = get_runtime()
            .block_on(async move { connector.lookup_domain(&domain).await })
            .map_err(connector_error_to_py)?;

        pythonize::pythonize(py, &result)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))
    }

    /// Look up a URL in threat intelligence.
    ///
    /// Args:
    ///     url: URL to look up
    ///
    /// Returns:
    ///     dict with threat intelligence results
    ///
    /// Raises:
    ///     RuntimeError: If the lookup fails
    pub fn lookup_url(&self, py: Python<'_>, url: &str) -> PyResult<PyObject> {
        let connector = Arc::clone(&self.connector);
        let url = url.to_string();

        let result = get_runtime()
            .block_on(async move { connector.lookup_url(&url).await })
            .map_err(connector_error_to_py)?;

        pythonize::pythonize(py, &result)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))
    }

    /// Check the health of the connector.
    ///
    /// Returns:
    ///     dict with health status
    pub fn health_check(&self, py: Python<'_>) -> PyResult<PyObject> {
        let connector = Arc::clone(&self.connector);

        let result = get_runtime()
            .block_on(async move {
                use tw_connectors::traits::Connector;
                connector.health_check().await
            })
            .map_err(connector_error_to_py)?;

        pythonize::pythonize(py, &result)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))
    }
}

// ============================================================================
// SIEMBridge - SIEM Connector Bridge
// ============================================================================

/// Bridge for SIEM operations.
///
/// Provides Python access to SIEM connectors for searching logs
/// and retrieving alerts.
///
/// Example:
///     siem = SIEMBridge("mock")
///     results = siem.search("login_failure", 24)  # Search last 24 hours
///     alerts = siem.get_recent_alerts(10)
#[pyclass]
pub struct SIEMBridge {
    connector: Arc<MockSIEMConnector>,
    connector_type: String,
}

#[pymethods]
impl SIEMBridge {
    /// Creates a new SIEMBridge.
    ///
    /// Args:
    ///     connector_type: Type of connector (currently only "mock" supported)
    ///     with_sample_data: If True, initializes with sample security events
    ///
    /// Returns:
    ///     SIEMBridge instance
    ///
    /// Raises:
    ///     ValueError: If connector_type is not supported
    #[new]
    #[pyo3(signature = (connector_type, with_sample_data=true))]
    pub fn new(connector_type: &str, with_sample_data: bool) -> PyResult<Self> {
        match connector_type {
            "mock" => {
                let connector = if with_sample_data {
                    MockSIEMConnector::with_sample_data("mock")
                } else {
                    MockSIEMConnector::new("mock")
                };
                Ok(Self {
                    connector: Arc::new(connector),
                    connector_type: connector_type.to_string(),
                })
            }
            _ => Err(PyValueError::new_err(format!(
                "Unsupported connector type: {}. Supported: mock",
                connector_type
            ))),
        }
    }

    /// Returns the connector type.
    pub fn get_connector_type(&self) -> String {
        self.connector_type.clone()
    }

    /// Search SIEM logs.
    ///
    /// Args:
    ///     query: Search query string
    ///     hours: Number of hours to search back (default: 24)
    ///
    /// Returns:
    ///     dict with search results including:
    ///         - search_id: Unique search identifier
    ///         - total_count: Total number of matching events
    ///         - events: List of matching events
    ///         - stats: Search statistics (execution time, etc.)
    ///
    /// Raises:
    ///     RuntimeError: If the search fails
    #[pyo3(signature = (query, hours=24))]
    pub fn search(&self, py: Python<'_>, query: &str, hours: i64) -> PyResult<PyObject> {
        let connector = Arc::clone(&self.connector);
        let query = query.to_string();
        let timerange = TimeRange::last_hours(hours);

        let result = get_runtime()
            .block_on(async move { connector.search(&query, timerange).await })
            .map_err(connector_error_to_py)?;

        pythonize::pythonize(py, &result)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))
    }

    /// Get recent alerts from the SIEM.
    ///
    /// Args:
    ///     limit: Maximum number of alerts to return (default: 100)
    ///
    /// Returns:
    ///     list of alert dicts, each containing:
    ///         - id: Alert ID
    ///         - name: Alert name
    ///         - severity: Alert severity (critical, high, medium, low)
    ///         - timestamp: When the alert was triggered
    ///         - details: Additional alert details
    ///
    /// Raises:
    ///     RuntimeError: If retrieval fails
    #[pyo3(signature = (limit=100))]
    pub fn get_recent_alerts(&self, py: Python<'_>, limit: usize) -> PyResult<PyObject> {
        let connector = Arc::clone(&self.connector);

        let result = get_runtime()
            .block_on(async move { connector.get_recent_alerts(limit).await })
            .map_err(connector_error_to_py)?;

        pythonize::pythonize(py, &result)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))
    }

    /// Get saved searches/alerts configured in the SIEM.
    ///
    /// Returns:
    ///     list of saved search dicts
    ///
    /// Raises:
    ///     RuntimeError: If retrieval fails
    pub fn get_saved_searches(&self, py: Python<'_>) -> PyResult<PyObject> {
        let connector = Arc::clone(&self.connector);

        let result = get_runtime()
            .block_on(async move { connector.get_saved_searches().await })
            .map_err(connector_error_to_py)?;

        pythonize::pythonize(py, &result)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))
    }

    /// Get unique values for a field within a time range.
    ///
    /// Args:
    ///     field: Field name to get values for
    ///     hours: Number of hours to search back (default: 24)
    ///     limit: Maximum number of values to return (default: 100)
    ///
    /// Returns:
    ///     list of unique field values
    ///
    /// Raises:
    ///     RuntimeError: If retrieval fails
    #[pyo3(signature = (field, hours=24, limit=100))]
    pub fn get_field_values(
        &self,
        py: Python<'_>,
        field: &str,
        hours: i64,
        limit: usize,
    ) -> PyResult<PyObject> {
        let connector = Arc::clone(&self.connector);
        let field = field.to_string();
        let timerange = TimeRange::last_hours(hours);

        let result = get_runtime()
            .block_on(async move { connector.get_field_values(&field, timerange, limit).await })
            .map_err(connector_error_to_py)?;

        pythonize::pythonize(py, &result)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))
    }

    /// Check the health of the connector.
    ///
    /// Returns:
    ///     dict with health status
    pub fn health_check(&self, py: Python<'_>) -> PyResult<PyObject> {
        let connector = Arc::clone(&self.connector);

        let result = get_runtime()
            .block_on(async move {
                use tw_connectors::traits::Connector;
                connector.health_check().await
            })
            .map_err(connector_error_to_py)?;

        pythonize::pythonize(py, &result)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))
    }
}

// ============================================================================
// EDRBridge - EDR Connector Bridge
// ============================================================================

/// Bridge for EDR (Endpoint Detection and Response) operations.
///
/// Provides Python access to EDR connectors for host management,
/// threat detection, and response actions.
///
/// Example:
///     edr = EDRBridge("mock")
///     host = edr.get_host_info("workstation-001")
///     detections = edr.get_detections("workstation-001")
///     result = edr.isolate_host("workstation-001")
#[pyclass]
pub struct EDRBridge {
    connector: Arc<MockEDRConnector>,
    connector_type: String,
}

#[pymethods]
impl EDRBridge {
    /// Creates a new EDRBridge.
    ///
    /// Args:
    ///     connector_type: Type of connector (currently only "mock" supported)
    ///     with_sample_data: If True, initializes with sample hosts and detections
    ///
    /// Returns:
    ///     EDRBridge instance
    ///
    /// Raises:
    ///     ValueError: If connector_type is not supported
    #[new]
    #[pyo3(signature = (connector_type, with_sample_data=true))]
    pub fn new(connector_type: &str, with_sample_data: bool) -> PyResult<Self> {
        match connector_type {
            "mock" => {
                let connector = if with_sample_data {
                    MockEDRConnector::with_sample_data("mock")
                } else {
                    MockEDRConnector::new("mock")
                };
                Ok(Self {
                    connector: Arc::new(connector),
                    connector_type: connector_type.to_string(),
                })
            }
            _ => Err(PyValueError::new_err(format!(
                "Unsupported connector type: {}. Supported: mock",
                connector_type
            ))),
        }
    }

    /// Returns the connector type.
    pub fn get_connector_type(&self) -> String {
        self.connector_type.clone()
    }

    /// Get information about a host.
    ///
    /// Args:
    ///     hostname: Hostname to look up
    ///
    /// Returns:
    ///     dict with host information including:
    ///         - hostname: Host name
    ///         - host_id: EDR host identifier
    ///         - ip_addresses: List of IP addresses
    ///         - mac_addresses: List of MAC addresses
    ///         - os: Operating system
    ///         - os_version: OS version
    ///         - agent_version: EDR agent version
    ///         - last_seen: Last communication timestamp
    ///         - isolated: Whether host is network isolated
    ///         - status: Host status (online, offline, unknown)
    ///         - tags: Host tags
    ///
    /// Raises:
    ///     RuntimeError: If host not found or lookup fails
    pub fn get_host_info(&self, py: Python<'_>, hostname: &str) -> PyResult<PyObject> {
        let connector = Arc::clone(&self.connector);
        let hostname = hostname.to_string();

        let result = get_runtime()
            .block_on(async move { connector.get_host_info(&hostname).await })
            .map_err(connector_error_to_py)?;

        pythonize::pythonize(py, &result)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))
    }

    /// Search for hosts matching a query.
    ///
    /// Args:
    ///     query: Search query (matches hostname, IP, tags, host_id)
    ///     limit: Maximum number of results (default: 100)
    ///
    /// Returns:
    ///     list of host dicts
    ///
    /// Raises:
    ///     RuntimeError: If search fails
    #[pyo3(signature = (query, limit=100))]
    pub fn search_hosts(&self, py: Python<'_>, query: &str, limit: usize) -> PyResult<PyObject> {
        let connector = Arc::clone(&self.connector);
        let query = query.to_string();

        let result = get_runtime()
            .block_on(async move { connector.search_hosts(&query, limit).await })
            .map_err(connector_error_to_py)?;

        pythonize::pythonize(py, &result)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))
    }

    /// Isolate a host from the network.
    ///
    /// This is a containment action that prevents the host from
    /// communicating with other systems while maintaining EDR connectivity.
    ///
    /// Args:
    ///     hostname: Hostname to isolate
    ///
    /// Returns:
    ///     dict with action result including:
    ///         - success: Whether isolation succeeded
    ///         - action_id: Unique action identifier
    ///         - message: Status message
    ///         - timestamp: When action was executed
    ///
    /// Raises:
    ///     RuntimeError: If isolation fails or host not found
    pub fn isolate_host(&self, py: Python<'_>, hostname: &str) -> PyResult<PyObject> {
        let connector = Arc::clone(&self.connector);
        let hostname = hostname.to_string();

        let result = get_runtime()
            .block_on(async move { connector.isolate_host(&hostname).await })
            .map_err(connector_error_to_py)?;

        pythonize::pythonize(py, &result)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))
    }

    /// Remove network isolation from a host.
    ///
    /// Args:
    ///     hostname: Hostname to unisolate
    ///
    /// Returns:
    ///     dict with action result
    ///
    /// Raises:
    ///     RuntimeError: If operation fails or host not found/not isolated
    pub fn unisolate_host(&self, py: Python<'_>, hostname: &str) -> PyResult<PyObject> {
        let connector = Arc::clone(&self.connector);
        let hostname = hostname.to_string();

        let result = get_runtime()
            .block_on(async move { connector.unisolate_host(&hostname).await })
            .map_err(connector_error_to_py)?;

        pythonize::pythonize(py, &result)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))
    }

    /// Get detections/alerts for a host.
    ///
    /// Args:
    ///     hostname: Hostname to get detections for
    ///
    /// Returns:
    ///     list of detection dicts, each containing:
    ///         - id: Detection ID
    ///         - name: Detection name/type
    ///         - severity: Severity level
    ///         - timestamp: When detected
    ///         - description: Detection description
    ///         - tactic: MITRE ATT&CK tactic
    ///         - technique: MITRE ATT&CK technique ID
    ///         - file_hash: Associated file hash (if any)
    ///         - process_name: Associated process (if any)
    ///         - details: Additional detection details
    ///
    /// Raises:
    ///     RuntimeError: If host not found or retrieval fails
    pub fn get_detections(&self, py: Python<'_>, hostname: &str) -> PyResult<PyObject> {
        let connector = Arc::clone(&self.connector);
        let hostname = hostname.to_string();

        let result = get_runtime()
            .block_on(async move { connector.get_host_detections(&hostname).await })
            .map_err(connector_error_to_py)?;

        pythonize::pythonize(py, &result)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))
    }

    /// Get process information for a host.
    ///
    /// Args:
    ///     hostname: Hostname to get processes for
    ///     hours: Number of hours to look back (default: 24)
    ///
    /// Returns:
    ///     list of process dicts
    ///
    /// Raises:
    ///     RuntimeError: If host not found or retrieval fails
    #[pyo3(signature = (hostname, hours=24))]
    pub fn get_processes(&self, py: Python<'_>, hostname: &str, hours: i64) -> PyResult<PyObject> {
        let connector = Arc::clone(&self.connector);
        let hostname = hostname.to_string();
        let timerange = TimeRange::last_hours(hours);

        let result = get_runtime()
            .block_on(async move { connector.get_processes(&hostname, timerange).await })
            .map_err(connector_error_to_py)?;

        pythonize::pythonize(py, &result)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))
    }

    /// Get network connections for a host.
    ///
    /// Args:
    ///     hostname: Hostname to get connections for
    ///     hours: Number of hours to look back (default: 24)
    ///
    /// Returns:
    ///     list of connection dicts
    ///
    /// Raises:
    ///     RuntimeError: If host not found or retrieval fails
    #[pyo3(signature = (hostname, hours=24))]
    pub fn get_network_connections(
        &self,
        py: Python<'_>,
        hostname: &str,
        hours: i64,
    ) -> PyResult<PyObject> {
        let connector = Arc::clone(&self.connector);
        let hostname = hostname.to_string();
        let timerange = TimeRange::last_hours(hours);

        let result = get_runtime()
            .block_on(async move {
                connector
                    .get_network_connections(&hostname, timerange)
                    .await
            })
            .map_err(connector_error_to_py)?;

        pythonize::pythonize(py, &result)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))
    }

    /// Check the health of the connector.
    ///
    /// Returns:
    ///     dict with health status
    pub fn health_check(&self, py: Python<'_>) -> PyResult<PyObject> {
        let connector = Arc::clone(&self.connector);

        let result = get_runtime()
            .block_on(async move {
                use tw_connectors::traits::Connector;
                connector.health_check().await
            })
            .map_err(connector_error_to_py)?;

        pythonize::pythonize(py, &result)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))
    }
}

// ============================================================================
// PolicyBridge - Policy Engine Bridge for Python
// ============================================================================

/// Bridge for policy engine operations.
///
/// Provides Python access to the policy engine, mode manager, kill switch,
/// and approval workflows for the ReAct agent integration.
///
/// Example:
///     policy = PolicyBridge()
///     result = policy.check_action("isolate_host", "workstation-001", 0.95)
///     mode = policy.get_operation_mode()
///     active = policy.is_kill_switch_active()
#[pyclass]
pub struct PolicyBridge {
    policy_engine: Arc<tokio::sync::RwLock<PolicyEngine>>,
    mode_manager: ModeManager,
    kill_switch: Arc<KillSwitch>,
    approval_manager: ApprovalManager,
}

#[pymethods]
impl PolicyBridge {
    /// Creates a new PolicyBridge with default/mock implementations.
    ///
    /// Returns:
    ///     PolicyBridge instance with default configurations
    #[new]
    pub fn new() -> PyResult<Self> {
        Ok(Self {
            policy_engine: Arc::new(tokio::sync::RwLock::new(PolicyEngine::default())),
            mode_manager: ModeManager::new(),
            kill_switch: Arc::new(KillSwitch::new()),
            approval_manager: ApprovalManager::default(),
        })
    }

    /// Check if an action is allowed by the policy engine.
    ///
    /// Args:
    ///     action_type: Type of action (e.g., "isolate_host", "create_ticket")
    ///     target: Target of the action (e.g., hostname, IP address)
    ///     confidence: Confidence score from the AI analysis (0.0 to 1.0)
    ///
    /// Returns:
    ///     dict with:
    ///         - decision: "allowed", "denied", or "requires_approval"
    ///         - reason: Explanation for the decision (for denied/requires_approval)
    ///         - approval_level: Required approval level (for requires_approval)
    ///
    /// Example:
    ///     result = policy.check_action("isolate_host", "workstation-001", 0.95)
    ///     if result["decision"] == "allowed":
    ///         # Proceed with action
    ///     elif result["decision"] == "requires_approval":
    ///         # Submit approval request
    pub fn check_action(
        &self,
        py: Python<'_>,
        action_type: &str,
        target: &str,
        confidence: f64,
    ) -> PyResult<PyObject> {
        // First check kill switch
        if self.kill_switch.is_active() {
            let result = serde_json::json!({
                "decision": "denied",
                "reason": "Kill switch is active - all automation halted",
                "approval_level": null
            });
            return pythonize::pythonize(py, &result)
                .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)));
        }

        // Build action context for policy evaluation
        let context = tw_policy::engine::ActionContext {
            action_type: action_type.to_string(),
            target: tw_policy::engine::ActionTarget {
                target_type: "host".to_string(),
                identifier: target.to_string(),
                criticality: None,
                tags: vec![],
            },
            incident_severity: "high".to_string(),
            confidence,
            proposer: "ai".to_string(),
            metadata: std::collections::HashMap::new(),
        };

        let policy_engine = Arc::clone(&self.policy_engine);

        let decision = get_runtime().block_on(async move {
            let engine = policy_engine.read().await;
            engine.evaluate(&context).await
        });

        let result = match decision {
            Ok(PolicyDecision::Allowed) => serde_json::json!({
                "decision": "allowed",
                "reason": null,
                "approval_level": null
            }),
            Ok(PolicyDecision::Denied(deny_reason)) => serde_json::json!({
                "decision": "denied",
                "reason": deny_reason.message,
                "approval_level": null
            }),
            Ok(PolicyDecision::RequiresApproval(level)) => {
                let level_str = match level {
                    ApprovalLevel::Analyst => "analyst",
                    ApprovalLevel::Senior => "senior",
                    ApprovalLevel::Manager => "manager",
                    ApprovalLevel::Executive => "executive",
                };
                serde_json::json!({
                    "decision": "requires_approval",
                    "reason": format!("Action requires {} approval", level_str),
                    "approval_level": level_str
                })
            }
            Err(e) => serde_json::json!({
                "decision": "denied",
                "reason": format!("Policy evaluation error: {}", e),
                "approval_level": null
            }),
        };

        pythonize::pythonize(py, &result)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))
    }

    /// Get the current operation mode.
    ///
    /// Returns:
    ///     str: "assisted", "supervised", or "autonomous"
    ///
    /// Example:
    ///     mode = policy.get_operation_mode()
    ///     if mode == "autonomous":
    ///         # Full automation enabled
    pub fn get_operation_mode(&self) -> PyResult<String> {
        let mode = get_runtime().block_on(async { self.mode_manager.get_mode().await });
        Ok(match mode {
            OperationMode::Assisted => "assisted".to_string(),
            OperationMode::Supervised => "supervised".to_string(),
            OperationMode::Autonomous => "autonomous".to_string(),
        })
    }

    /// Check if the kill switch is active.
    ///
    /// Returns:
    ///     bool: True if kill switch is active (all automation halted)
    ///
    /// Example:
    ///     if policy.is_kill_switch_active():
    ///         print("Automation halted by kill switch")
    pub fn is_kill_switch_active(&self) -> bool {
        self.kill_switch.is_active()
    }

    /// Submit an approval request for an action.
    ///
    /// Args:
    ///     action_type: Type of action requiring approval
    ///     target: Target of the action
    ///     level: Required approval level ("analyst", "senior", "manager", "executive")
    ///
    /// Returns:
    ///     str: The unique request_id for tracking the approval
    ///
    /// Raises:
    ///     ValueError: If the approval level is invalid
    ///
    /// Example:
    ///     request_id = policy.submit_approval_request("isolate_host", "server-001", "senior")
    ///     # Later check status with check_approval_status(request_id)
    pub fn submit_approval_request(
        &self,
        action_type: &str,
        target: &str,
        level: &str,
    ) -> PyResult<String> {
        let approval_level = match level.to_lowercase().as_str() {
            "analyst" => ApprovalLevel::Analyst,
            "senior" => ApprovalLevel::Senior,
            "manager" => ApprovalLevel::Manager,
            "executive" => ApprovalLevel::Executive,
            _ => {
                return Err(PyValueError::new_err(format!(
                "Invalid approval level: {}. Must be one of: analyst, senior, manager, executive",
                level
            )))
            }
        };

        let request = get_runtime().block_on(async {
            self.approval_manager
                .submit_request(action_type, target, approval_level, "ai-agent")
                .await
        });

        Ok(request.id.to_string())
    }

    /// Check the status of an approval request.
    ///
    /// Args:
    ///     request_id: The unique request ID returned from submit_approval_request
    ///
    /// Returns:
    ///     dict with:
    ///         - status: "pending", "approved", "denied", or "expired"
    ///         - decided_by: Who made the decision (None if still pending)
    ///
    /// Raises:
    ///     ValueError: If request_id is not a valid UUID
    ///
    /// Example:
    ///     status = policy.check_approval_status(request_id)
    ///     if status["status"] == "approved":
    ///         # Proceed with action
    ///     elif status["status"] == "pending":
    ///         # Wait for approval
    pub fn check_approval_status(&self, py: Python<'_>, request_id: &str) -> PyResult<PyObject> {
        let uuid = request_id
            .parse::<Uuid>()
            .map_err(|e| PyValueError::new_err(format!("Invalid request_id: {}", e)))?;

        let request =
            get_runtime().block_on(async { self.approval_manager.get_request(uuid).await });

        let result = match request {
            Some(req) => {
                use tw_policy::ManagedApprovalStatus;
                let status_str = match req.status {
                    ManagedApprovalStatus::Pending => "pending",
                    ManagedApprovalStatus::Approved => "approved",
                    ManagedApprovalStatus::Denied => "denied",
                    ManagedApprovalStatus::Expired => "expired",
                    ManagedApprovalStatus::Cancelled => "denied", // Map cancelled to denied
                };
                serde_json::json!({
                    "status": status_str,
                    "decided_by": req.decision_by
                })
            }
            None => serde_json::json!({
                "status": "expired",
                "decided_by": null
            }),
        };

        pythonize::pythonize(py, &result)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))
    }
}

impl Default for PolicyBridge {
    fn default() -> Self {
        Self {
            policy_engine: Arc::new(tokio::sync::RwLock::new(PolicyEngine::default())),
            mode_manager: ModeManager::new(),
            kill_switch: Arc::new(KillSwitch::new()),
            approval_manager: ApprovalManager::default(),
        }
    }
}

// ============================================================================
// Legacy TriageWardenBridge (kept for backward compatibility)
// ============================================================================

/// Main bridge class for Python interop (legacy).
///
/// This class is maintained for backward compatibility.
/// For new code, prefer using the specialized bridges:
/// - ThreatIntelBridge for threat intelligence
/// - SIEMBridge for SIEM operations
/// - EDRBridge for EDR operations
#[pyclass]
pub struct TriageWardenBridge {
    config: BridgeConfig,
    threat_intel: Option<Arc<MockThreatIntelConnector>>,
    siem: Option<Arc<MockSIEMConnector>>,
    edr: Option<Arc<MockEDRConnector>>,
}

#[pymethods]
impl TriageWardenBridge {
    #[new]
    pub fn new(config: BridgeConfig) -> PyResult<Self> {
        Ok(Self {
            config,
            threat_intel: None,
            siem: None,
            edr: None,
        })
    }

    /// Initialize the bridge and connect to all configured services.
    pub fn initialize(&mut self) -> PyResult<bool> {
        // Initialize mock connectors
        self.threat_intel = Some(Arc::new(MockThreatIntelConnector::new("mock")));
        self.siem = Some(Arc::new(MockSIEMConnector::with_sample_data("mock")));
        self.edr = Some(Arc::new(MockEDRConnector::with_sample_data("mock")));

        tracing::info!(
            "TriageWardenBridge initialized with config: {}",
            self.config.config_path
        );
        Ok(true)
    }

    /// Look up a hash in threat intelligence.
    pub fn lookup_hash(&self, py: Python<'_>, hash: &str) -> PyResult<PyObject> {
        let connector = self
            .threat_intel
            .as_ref()
            .ok_or_else(|| PyRuntimeError::new_err("Bridge not initialized"))?;

        let connector = Arc::clone(connector);
        let hash = hash.to_string();

        let result = get_runtime()
            .block_on(async move { connector.lookup_hash(&hash).await })
            .map_err(connector_error_to_py)?;

        pythonize::pythonize(py, &result)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))
    }

    /// Look up an IP in threat intelligence.
    pub fn lookup_ip(&self, py: Python<'_>, ip: &str) -> PyResult<PyObject> {
        let connector = self
            .threat_intel
            .as_ref()
            .ok_or_else(|| PyRuntimeError::new_err("Bridge not initialized"))?;

        let ip_addr: IpAddr = ip
            .parse()
            .map_err(|e| PyValueError::new_err(format!("Invalid IP address: {}", e)))?;

        let connector = Arc::clone(connector);

        let result = get_runtime()
            .block_on(async move { connector.lookup_ip(&ip_addr).await })
            .map_err(connector_error_to_py)?;

        pythonize::pythonize(py, &result)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))
    }

    /// Look up a domain in threat intelligence.
    pub fn lookup_domain(&self, py: Python<'_>, domain: &str) -> PyResult<PyObject> {
        let connector = self
            .threat_intel
            .as_ref()
            .ok_or_else(|| PyRuntimeError::new_err("Bridge not initialized"))?;

        let connector = Arc::clone(connector);
        let domain = domain.to_string();

        let result = get_runtime()
            .block_on(async move { connector.lookup_domain(&domain).await })
            .map_err(connector_error_to_py)?;

        pythonize::pythonize(py, &result)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))
    }

    /// Get host information from EDR.
    pub fn get_host_info(&self, py: Python<'_>, hostname: &str) -> PyResult<Option<PyObject>> {
        let connector = self
            .edr
            .as_ref()
            .ok_or_else(|| PyRuntimeError::new_err("Bridge not initialized"))?;

        let connector = Arc::clone(connector);
        let hostname = hostname.to_string();

        match get_runtime().block_on(async move { connector.get_host_info(&hostname).await }) {
            Ok(result) => {
                let obj = pythonize::pythonize(py, &result)
                    .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))?;
                Ok(Some(obj))
            }
            Err(tw_connectors::ConnectorError::NotFound(_)) => Ok(None),
            Err(e) => Err(connector_error_to_py(e)),
        }
    }

    /// Search SIEM logs.
    pub fn search_siem(&self, py: Python<'_>, query: &str, hours: u32) -> PyResult<PyObject> {
        let connector = self
            .siem
            .as_ref()
            .ok_or_else(|| PyRuntimeError::new_err("Bridge not initialized"))?;

        let connector = Arc::clone(connector);
        let query = query.to_string();
        let timerange = TimeRange::last_hours(hours as i64);

        let result = get_runtime()
            .block_on(async move { connector.search(&query, timerange).await })
            .map_err(connector_error_to_py)?;

        pythonize::pythonize(py, &result)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))
    }

    /// Create a ticket.
    pub fn create_ticket(
        &self,
        _title: &str,
        _description: &str,
        _priority: &str,
        _labels: Vec<String>,
    ) -> PyResult<String> {
        // Placeholder - returns a mock ticket ID
        Ok(format!("MOCK-{}", Uuid::new_v4()))
    }

    /// Submit triage analysis to the orchestrator.
    pub fn submit_analysis(
        &self,
        incident_id: &str,
        verdict: &str,
        confidence: f64,
        _summary: &str,
        _recommended_actions: Vec<String>,
    ) -> PyResult<bool> {
        // Placeholder - would submit to the orchestrator
        tracing::info!(
            "Analysis submitted for incident {}: {} (confidence: {})",
            incident_id,
            verdict,
            confidence
        );
        Ok(true)
    }

    /// Check if the bridge is healthy.
    pub fn health_check(&self) -> PyResult<bool> {
        Ok(self.threat_intel.is_some() && self.siem.is_some() && self.edr.is_some())
    }

    /// Shutdown the bridge.
    pub fn shutdown(&mut self) -> PyResult<()> {
        tracing::info!("TriageWardenBridge shutting down");
        self.threat_intel = None;
        self.siem = None;
        self.edr = None;
        Ok(())
    }
}

/// Python module definition.
#[pymodule]
fn tw_bridge(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    // Legacy classes
    m.add_class::<PyTriageRequest>()?;
    m.add_class::<PyTriageResult>()?;
    m.add_class::<PyThreatIntelResult>()?;
    m.add_class::<PyHostInfo>()?;
    m.add_class::<BridgeConfig>()?;
    m.add_class::<TriageWardenBridge>()?;

    // New specialized bridges
    m.add_class::<ThreatIntelBridge>()?;
    m.add_class::<SIEMBridge>()?;
    m.add_class::<EDRBridge>()?;
    m.add_class::<PolicyBridge>()?;

    // Add version
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;

    Ok(())
}

/// Tests for the bridge module.
///
/// These tests verify the bridge logic works correctly without requiring
/// Python to be linked. They test the underlying connector operations
/// through the bridge structures.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_runtime() {
        // Ensure runtime can be created and accessed multiple times
        let rt1 = get_runtime();
        let rt2 = get_runtime();
        assert!(std::ptr::eq(rt1, rt2));
    }

    #[test]
    fn test_triage_request_creation() {
        let request =
            PyTriageRequest::new("test-123".to_string(), "{}".to_string(), "[]".to_string());
        assert_eq!(request.incident_id, "test-123");
        assert_eq!(request.alert_data, "{}");
        assert_eq!(request.enrichments, "[]");
    }

    #[test]
    fn test_triage_result_failure() {
        let result = PyTriageResult::failure("Test error".to_string());
        assert!(!result.success);
        assert_eq!(result.verdict, "error");
        assert_eq!(result.confidence, 0.0);
        assert_eq!(result.error, Some("Test error".to_string()));
    }

    #[test]
    fn test_triage_result_success() {
        let result = PyTriageResult::new(
            true,
            "malicious".to_string(),
            0.95,
            "Malware detected".to_string(),
            "Multiple indicators of compromise found".to_string(),
            r#"["isolate_host", "scan_file"]"#.to_string(),
            r#"["T1059.001", "T1071.001"]"#.to_string(),
            None,
        );
        assert!(result.success);
        assert_eq!(result.verdict, "malicious");
        assert_eq!(result.confidence, 0.95);
        assert!(result.error.is_none());
    }

    #[test]
    fn test_threat_intel_result_unknown() {
        let result = PyThreatIntelResult::unknown("hash".to_string(), "abc123".to_string());
        assert_eq!(result.indicator_type, "hash");
        assert_eq!(result.indicator, "abc123");
        assert_eq!(result.verdict, "unknown");
        assert_eq!(result.malicious_score, 0);
        assert_eq!(result.malicious_count, 0);
        assert_eq!(result.total_engines, 0);
        assert_eq!(result.source, "none");
    }

    #[test]
    fn test_threat_intel_result_malicious() {
        let result = PyThreatIntelResult::new(
            "sha256".to_string(),
            "abc123def456".to_string(),
            "malicious".to_string(),
            95,
            68,
            72,
            r#"["malware", "trojan"]"#.to_string(),
            "VirusTotal".to_string(),
        );
        assert_eq!(result.verdict, "malicious");
        assert_eq!(result.malicious_score, 95);
    }

    #[test]
    fn test_bridge_config() {
        let config = BridgeConfig::new("/etc/tw/config.yaml".to_string());
        assert_eq!(config.config_path, "/etc/tw/config.yaml");
    }

    // Tests for bridge creation using connectors directly
    // These don't require Python linking

    #[test]
    fn test_threat_intel_connector_lookup_known_hash() {
        let connector = MockThreatIntelConnector::new("test");

        let result = get_runtime()
            .block_on(async move {
                connector
                    .lookup_hash("44d88612fea8a8f36de82e1278abb02f")
                    .await
            })
            .unwrap();

        assert_eq!(
            result.verdict,
            tw_connectors::traits::ThreatVerdict::Malicious
        );
        assert_eq!(result.malicious_score, 95);
    }

    #[test]
    fn test_threat_intel_connector_lookup_unknown_hash() {
        let connector = MockThreatIntelConnector::new("test");

        let result = get_runtime()
            .block_on(async move { connector.lookup_hash("unknown_hash_value").await })
            .unwrap();

        assert_eq!(
            result.verdict,
            tw_connectors::traits::ThreatVerdict::Unknown
        );
    }

    #[test]
    fn test_threat_intel_connector_lookup_ip() {
        let connector = MockThreatIntelConnector::new("test");

        let result = get_runtime()
            .block_on(async move { connector.lookup_ip(&"203.0.113.100".parse().unwrap()).await })
            .unwrap();

        assert_eq!(
            result.verdict,
            tw_connectors::traits::ThreatVerdict::Malicious
        );
    }

    #[test]
    fn test_threat_intel_connector_lookup_domain() {
        let connector = MockThreatIntelConnector::new("test");

        let result = get_runtime()
            .block_on(async move { connector.lookup_domain("evil.example.com").await })
            .unwrap();

        assert_eq!(
            result.verdict,
            tw_connectors::traits::ThreatVerdict::Malicious
        );
    }

    #[test]
    fn test_threat_intel_connector_lookup_clean_domain() {
        let connector = MockThreatIntelConnector::new("test");

        let result = get_runtime()
            .block_on(async move { connector.lookup_domain("google.com").await })
            .unwrap();

        assert_eq!(result.verdict, tw_connectors::traits::ThreatVerdict::Clean);
    }

    #[test]
    fn test_siem_connector_search() {
        let connector = MockSIEMConnector::with_sample_data("test");

        let result = get_runtime()
            .block_on(async move {
                connector
                    .search("login_failure", TimeRange::last_hours(24))
                    .await
            })
            .unwrap();

        assert!(result.total_count >= 1);
        assert!(!result.events.is_empty());
    }

    #[test]
    fn test_siem_connector_search_empty_query() {
        let connector = MockSIEMConnector::with_sample_data("test");

        let result = get_runtime()
            .block_on(async move { connector.search("", TimeRange::last_hours(24)).await })
            .unwrap();

        // Empty query should return all events
        assert!(result.total_count > 0);
    }

    #[test]
    fn test_siem_connector_get_alerts() {
        let connector = MockSIEMConnector::with_sample_data("test");

        let alerts = get_runtime()
            .block_on(async move { connector.get_recent_alerts(10).await })
            .unwrap();

        assert!(!alerts.is_empty());
        // Verify sorted by timestamp descending
        for i in 1..alerts.len() {
            assert!(alerts[i - 1].timestamp >= alerts[i].timestamp);
        }
    }

    #[test]
    fn test_siem_connector_get_saved_searches() {
        let connector = MockSIEMConnector::with_sample_data("test");

        let searches = get_runtime()
            .block_on(async move { connector.get_saved_searches().await })
            .unwrap();

        assert!(!searches.is_empty());
        assert!(searches.iter().any(|s| s.name == "Failed Logins"));
    }

    #[test]
    fn test_edr_connector_get_host_info() {
        let connector = MockEDRConnector::with_sample_data("test");

        let host = get_runtime()
            .block_on(async move { connector.get_host_info("workstation-001").await })
            .unwrap();

        assert_eq!(host.hostname, "workstation-001");
        assert!(!host.isolated);
        assert!(host.tags.contains(&"finance".to_string()));
    }

    #[test]
    fn test_edr_connector_host_not_found() {
        let connector = MockEDRConnector::with_sample_data("test");

        let result = get_runtime()
            .block_on(async move { connector.get_host_info("nonexistent-host").await });

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            tw_connectors::ConnectorError::NotFound(_)
        ));
    }

    #[test]
    fn test_edr_connector_isolate_host() {
        let connector = MockEDRConnector::with_sample_data("test");

        let result = get_runtime()
            .block_on(async move { connector.isolate_host("workstation-001").await })
            .unwrap();

        assert!(result.success);
        assert!(result.message.contains("isolated"));
    }

    #[test]
    fn test_edr_connector_get_detections() {
        let connector = MockEDRConnector::with_sample_data("test");

        let detections = get_runtime()
            .block_on(async move { connector.get_host_detections("workstation-001").await })
            .unwrap();

        assert!(!detections.is_empty());
        assert!(detections
            .iter()
            .any(|d| d.name == "Suspicious PowerShell Execution"));
        assert!(detections
            .iter()
            .any(|d| d.technique == Some("T1059.001".to_string())));
    }

    #[test]
    fn test_edr_connector_search_hosts() {
        let connector = MockEDRConnector::with_sample_data("test");

        let results = get_runtime()
            .block_on(async move { connector.search_hosts("finance", 10).await })
            .unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].hostname, "workstation-001");
    }

    #[test]
    fn test_edr_connector_search_hosts_by_tag() {
        let connector = MockEDRConnector::with_sample_data("test");

        let results = get_runtime()
            .block_on(async move { connector.search_hosts("critical", 10).await })
            .unwrap();

        // Should find server-001 and dc01 which have "critical" tag
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_connector_health_check() {
        use tw_connectors::traits::Connector;

        let ti_connector = MockThreatIntelConnector::new("test");
        let siem_connector = MockSIEMConnector::new("test");
        let edr_connector = MockEDRConnector::new("test");

        let ti_health = get_runtime()
            .block_on(async move { ti_connector.health_check().await })
            .unwrap();

        let siem_health = get_runtime()
            .block_on(async move { siem_connector.health_check().await })
            .unwrap();

        let edr_health = get_runtime()
            .block_on(async move { edr_connector.health_check().await })
            .unwrap();

        assert_eq!(ti_health, tw_connectors::traits::ConnectorHealth::Healthy);
        assert_eq!(siem_health, tw_connectors::traits::ConnectorHealth::Healthy);
        assert_eq!(edr_health, tw_connectors::traits::ConnectorHealth::Healthy);
    }

    #[test]
    fn test_time_range_last_hours() {
        let range = TimeRange::last_hours(24);
        let duration = range.end - range.start;
        assert_eq!(duration.num_hours(), 24);
    }

    #[test]
    fn test_time_range_last_days() {
        let range = TimeRange::last_days(7);
        let duration = range.end - range.start;
        assert_eq!(duration.num_days(), 7);
    }

    #[test]
    fn test_connector_error_conversion() {
        let err = tw_connectors::ConnectorError::NotFound("Host not found".to_string());
        let py_err = connector_error_to_py(err);

        // Verify it's a RuntimeError with the expected message
        let err_str = format!("{}", py_err);
        assert!(err_str.contains("Not found"));
    }

    // ========================================================================
    // PolicyBridge Tests
    // ========================================================================

    #[test]
    fn test_policy_bridge_kill_switch_inactive_by_default() {
        let bridge = PolicyBridge::default();
        assert!(!bridge.is_kill_switch_active());
    }

    #[test]
    fn test_policy_bridge_operation_mode_default() {
        let bridge = PolicyBridge::default();
        let mode = bridge.get_operation_mode().unwrap();
        assert_eq!(mode, "supervised");
    }

    #[test]
    fn test_policy_bridge_submit_approval_request() {
        let bridge = PolicyBridge::default();
        let request_id = bridge
            .submit_approval_request("isolate_host", "workstation-001", "analyst")
            .unwrap();

        // Verify it's a valid UUID
        assert!(request_id.parse::<Uuid>().is_ok());
    }

    #[test]
    fn test_policy_bridge_submit_approval_invalid_level() {
        let bridge = PolicyBridge::default();
        let result = bridge.submit_approval_request("isolate_host", "workstation-001", "invalid");

        assert!(result.is_err());
    }

    #[test]
    fn test_policy_engine_check_action_low_risk_high_confidence() {
        // Test that low-risk actions with high confidence are allowed
        let engine = PolicyEngine::default();

        let context = tw_policy::engine::ActionContext {
            action_type: "create_ticket".to_string(),
            target: tw_policy::engine::ActionTarget {
                target_type: "ticket".to_string(),
                identifier: "INC-001".to_string(),
                criticality: None,
                tags: vec![],
            },
            incident_severity: "medium".to_string(),
            confidence: 0.95,
            proposer: "ai".to_string(),
            metadata: std::collections::HashMap::new(),
        };

        let decision = get_runtime()
            .block_on(async { engine.evaluate(&context).await })
            .unwrap();

        assert_eq!(decision, PolicyDecision::Allowed);
    }

    #[test]
    fn test_policy_engine_deny_dangerous_action() {
        // Test that dangerous actions are denied
        let engine = PolicyEngine::default();

        let context = tw_policy::engine::ActionContext {
            action_type: "delete_user".to_string(),
            target: tw_policy::engine::ActionTarget {
                target_type: "user".to_string(),
                identifier: "user@example.com".to_string(),
                criticality: None,
                tags: vec![],
            },
            incident_severity: "critical".to_string(),
            confidence: 0.99,
            proposer: "ai".to_string(),
            metadata: std::collections::HashMap::new(),
        };

        let decision = get_runtime()
            .block_on(async { engine.evaluate(&context).await })
            .unwrap();

        assert!(matches!(decision, PolicyDecision::Denied(_)));
    }

    #[test]
    fn test_policy_engine_requires_approval_for_isolate_host() {
        let engine = PolicyEngine::default();

        let context = tw_policy::engine::ActionContext {
            action_type: "isolate_host".to_string(),
            target: tw_policy::engine::ActionTarget {
                target_type: "host".to_string(),
                identifier: "workstation-001".to_string(),
                criticality: None,
                tags: vec![],
            },
            incident_severity: "high".to_string(),
            confidence: 0.95,
            proposer: "ai".to_string(),
            metadata: std::collections::HashMap::new(),
        };

        let decision = get_runtime()
            .block_on(async { engine.evaluate(&context).await })
            .unwrap();

        assert!(matches!(
            decision,
            PolicyDecision::RequiresApproval(ApprovalLevel::Analyst)
        ));
    }

    #[test]
    fn test_mode_manager_supervised_default() {
        let manager = ModeManager::new();
        let mode = get_runtime().block_on(async { manager.get_mode().await });
        assert_eq!(mode, OperationMode::Supervised);
    }

    #[test]
    fn test_kill_switch_activation() {
        let kill_switch = KillSwitch::new();
        assert!(!kill_switch.is_active());

        get_runtime()
            .block_on(async { kill_switch.activate("test_admin").await })
            .unwrap();

        assert!(kill_switch.is_active());

        get_runtime()
            .block_on(async { kill_switch.deactivate("test_admin").await })
            .unwrap();

        assert!(!kill_switch.is_active());
    }

    #[test]
    fn test_approval_manager_request_lifecycle() {
        let manager = ApprovalManager::default();

        // Submit request
        let request = get_runtime().block_on(async {
            manager
                .submit_request(
                    "isolate_host",
                    "server-001",
                    ApprovalLevel::Senior,
                    "ai-agent",
                )
                .await
        });

        assert_eq!(request.status, tw_policy::ManagedApprovalStatus::Pending);

        // Check status
        let retrieved = get_runtime()
            .block_on(async { manager.get_request(request.id).await })
            .unwrap();

        assert_eq!(retrieved.action_type, "isolate_host");
        assert_eq!(retrieved.target, "server-001");
    }
}
