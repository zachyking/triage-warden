// PyO3's procedural macros generate code that triggers this lint incorrectly
#![allow(clippy::useless_conversion)]

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

use tw_connectors::edr::crowdstrike::{CrowdStrikeConfig, CrowdStrikeConnector};
use tw_connectors::edr::mock::MockEDRConnector;
use tw_connectors::email::m365::{M365Config, M365Connector};
use tw_connectors::email::mock::MockEmailGatewayConnector;
use tw_connectors::siem::mock::MockSIEMConnector;
use tw_connectors::siem::splunk::{SplunkConfig, SplunkConnector};
use tw_connectors::threat_intel::mock::MockThreatIntelConnector;
use tw_connectors::threat_intel::virustotal::{VirusTotalConfig, VirusTotalConnector};
use tw_connectors::ticketing::jira::{JiraConfig, JiraConnector};
use tw_connectors::ticketing::mock::MockTicketingConnector;
use tw_connectors::traits::{
    AuthConfig, ConnectorConfig, ConnectorHealth, CreateTicketRequest, EDRConnector,
    EmailGatewayConnector, EmailSearchQuery, SIEMConnector, ThreatIntelConnector, TicketPriority,
    TicketingConnector, TimeRange, UpdateTicketRequest,
};
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
    #[pyo3(signature = (success, verdict, confidence, summary, reasoning, recommended_actions, mitre_techniques, error=None))]
    #[allow(clippy::too_many_arguments)]
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
    #[allow(clippy::too_many_arguments)]
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
///
///     # Using VirusTotal connector (requires TW_VIRUSTOTAL_API_KEY env var)
///     ti = ThreatIntelBridge("virustotal")
///     result = ti.lookup_hash("abc123...")
#[pyclass]
pub struct ThreatIntelBridge {
    connector: Arc<dyn ThreatIntelConnector + Send + Sync>,
    connector_type: String,
}

#[pymethods]
impl ThreatIntelBridge {
    /// Creates a new ThreatIntelBridge.
    ///
    /// Args:
    ///     mode: Connector mode to use ("mock" or "virustotal")
    ///           - "mock": Uses mock connector for testing (default)
    ///           - "virustotal": Uses VirusTotal API (requires TW_VIRUSTOTAL_API_KEY env var)
    ///
    /// Returns:
    ///     ThreatIntelBridge instance
    ///
    /// Raises:
    ///     ValueError: If mode is not supported or API key is missing for virustotal
    #[new]
    pub fn new(mode: &str) -> PyResult<Self> {
        match mode {
            "mock" | "" => Ok(Self {
                connector: Arc::new(MockThreatIntelConnector::new("mock")),
                connector_type: "mock".to_string(),
            }),
            "virustotal" => {
                let api_key = std::env::var("TW_VIRUSTOTAL_API_KEY").map_err(|_| {
                    PyValueError::new_err(
                        "TW_VIRUSTOTAL_API_KEY environment variable not set. \
                         Please set your VirusTotal API key to use the virustotal connector.",
                    )
                })?;

                if api_key.trim().is_empty() {
                    return Err(PyValueError::new_err(
                        "TW_VIRUSTOTAL_API_KEY environment variable is empty. \
                         Please provide a valid VirusTotal API key.",
                    ));
                }

                let config = VirusTotalConfig {
                    connector: ConnectorConfig {
                        name: "virustotal".to_string(),
                        base_url: "https://www.virustotal.com".to_string(),
                        auth: AuthConfig::ApiKey {
                            key: api_key.into(),
                            header_name: "x-apikey".to_string(),
                        },
                        timeout_secs: 30,
                        max_retries: 3,
                        verify_tls: true,
                        headers: std::collections::HashMap::new(),
                    },
                    cache_ttl_secs: 3600,
                    max_cache_entries: 10000,
                    requests_per_minute: 4, // Free tier limit
                };

                let connector = VirusTotalConnector::new(config).map_err(|e| {
                    PyRuntimeError::new_err(format!("Failed to create VirusTotal connector: {}", e))
                })?;

                Ok(Self {
                    connector: Arc::new(connector),
                    connector_type: "virustotal".to_string(),
                })
            }
            _ => Err(PyValueError::new_err(format!(
                "Unsupported connector mode: '{}'. Supported modes: 'mock', 'virustotal'",
                mode
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

        Ok(pythonize::pythonize(py, &result)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))?
            .unbind())
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

        Ok(pythonize::pythonize(py, &result)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))?
            .unbind())
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

        Ok(pythonize::pythonize(py, &result)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))?
            .unbind())
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

        Ok(pythonize::pythonize(py, &result)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))?
            .unbind())
    }

    /// Check the health of the connector.
    ///
    /// Returns:
    ///     dict with health status including:
    ///         - status: "healthy", "degraded", "unhealthy", or "unknown"
    ///         - connector_type: The type of connector ("mock" or "virustotal")
    ///         - message: Additional details (for degraded/unhealthy status)
    pub fn health_check(&self, py: Python<'_>) -> PyResult<PyObject> {
        let connector = Arc::clone(&self.connector);
        let connector_type = self.connector_type.clone();

        let health = get_runtime()
            .block_on(async move { connector.health_check().await })
            .map_err(connector_error_to_py)?;

        let result = match health {
            ConnectorHealth::Healthy => serde_json::json!({
                "status": "healthy",
                "connector_type": connector_type,
                "message": null
            }),
            ConnectorHealth::Degraded(msg) => serde_json::json!({
                "status": "degraded",
                "connector_type": connector_type,
                "message": msg
            }),
            ConnectorHealth::Unhealthy(msg) => serde_json::json!({
                "status": "unhealthy",
                "connector_type": connector_type,
                "message": msg
            }),
            ConnectorHealth::Unknown => serde_json::json!({
                "status": "unknown",
                "connector_type": connector_type,
                "message": null
            }),
        };

        Ok(pythonize::pythonize(py, &result)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))?
            .unbind())
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
///
///     # Using Splunk connector (requires TW_SPLUNK_URL and TW_SPLUNK_TOKEN env vars)
///     siem = SIEMBridge("splunk")
///     results = siem.search("index=main error", 24)
#[pyclass]
pub struct SIEMBridge {
    connector: Arc<dyn SIEMConnector + Send + Sync>,
    connector_type: String,
}

#[pymethods]
impl SIEMBridge {
    /// Creates a new SIEMBridge.
    ///
    /// Args:
    ///     mode: Type of connector ("mock" or "splunk")
    ///     with_sample_data: If True and mode="mock", initializes with sample security events
    ///
    /// Environment Variables (for splunk mode):
    ///     TW_SPLUNK_URL: Splunk server URL (e.g., "<https://splunk.example.com:8089>")
    ///     TW_SPLUNK_TOKEN: Splunk authentication token
    ///
    /// Returns:
    ///     SIEMBridge instance
    ///
    /// Raises:
    ///     ValueError: If mode is not supported or Splunk configuration is missing
    #[new]
    #[pyo3(signature = (mode, with_sample_data=true))]
    pub fn new(mode: &str, with_sample_data: bool) -> PyResult<Self> {
        match mode {
            "mock" | "" => {
                let connector = if with_sample_data {
                    MockSIEMConnector::with_sample_data("mock")
                } else {
                    MockSIEMConnector::new("mock")
                };
                Ok(Self {
                    connector: Arc::new(connector),
                    connector_type: "mock".to_string(),
                })
            }
            "splunk" => {
                let url = std::env::var("TW_SPLUNK_URL").map_err(|_| {
                    PyValueError::new_err(
                        "Splunk mode requires TW_SPLUNK_URL environment variable to be set",
                    )
                })?;
                let token = std::env::var("TW_SPLUNK_TOKEN").map_err(|_| {
                    PyValueError::new_err(
                        "Splunk mode requires TW_SPLUNK_TOKEN environment variable to be set",
                    )
                })?;

                let config = SplunkConfig {
                    connector: ConnectorConfig {
                        name: "splunk".to_string(),
                        base_url: url,
                        auth: AuthConfig::BearerToken {
                            token: token.into(),
                        },
                        timeout_secs: 30,
                        max_retries: 3,
                        verify_tls: true,
                        headers: std::collections::HashMap::new(),
                    },
                    app: "search".to_string(),
                    owner: "-".to_string(),
                    output_mode: "json".to_string(),
                    search_timeout: 120,
                    max_results: 10000,
                    requests_per_second: 10,
                };

                let connector = SplunkConnector::new(config).map_err(|e| {
                    PyValueError::new_err(format!("Failed to create Splunk connector: {}", e))
                })?;

                Ok(Self {
                    connector: Arc::new(connector),
                    connector_type: "splunk".to_string(),
                })
            }
            _ => Err(PyValueError::new_err(format!(
                "Unsupported connector mode: {}. Supported: mock, splunk",
                mode
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

        Ok(pythonize::pythonize(py, &result)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))?
            .unbind())
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

        Ok(pythonize::pythonize(py, &result)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))?
            .unbind())
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

        Ok(pythonize::pythonize(py, &result)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))?
            .unbind())
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

        Ok(pythonize::pythonize(py, &result)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))?
            .unbind())
    }

    /// Check the health of the connector.
    ///
    /// Returns:
    ///     dict with health status
    pub fn health_check(&self, py: Python<'_>) -> PyResult<PyObject> {
        let connector = Arc::clone(&self.connector);

        let result = get_runtime()
            .block_on(async move { connector.health_check().await })
            .map_err(connector_error_to_py)?;

        Ok(pythonize::pythonize(py, &result)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))?
            .unbind())
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
/// Supports multiple connector types:
/// - "mock": Mock connector for testing (default, backward compatible)
/// - "crowdstrike": CrowdStrike Falcon connector (requires env vars)
///
/// Example:
///     # Mock connector (default)
///     edr = EDRBridge("mock")
///     host = edr.get_host_info("workstation-001")
///     detections = edr.get_detections("workstation-001")
///     result = edr.isolate_host("workstation-001")
///
///     # CrowdStrike connector (requires TW_CROWDSTRIKE_* env vars)
///     edr = EDRBridge("crowdstrike")
#[pyclass]
pub struct EDRBridge {
    connector: Arc<dyn EDRConnector + Send + Sync>,
    connector_type: String,
}

/// Creates a CrowdStrike connector from environment variables.
///
/// Required environment variables:
/// - TW_CROWDSTRIKE_CLIENT_ID: OAuth2 client ID
/// - TW_CROWDSTRIKE_CLIENT_SECRET: OAuth2 client secret
///
/// Optional environment variables:
/// - TW_CROWDSTRIKE_REGION: API region (default: "us-1")
///   Valid values: us-1, us-2, eu-1, us-gov-1
fn create_crowdstrike_connector() -> PyResult<CrowdStrikeConnector> {
    let client_id = std::env::var("TW_CROWDSTRIKE_CLIENT_ID").map_err(|_| {
        PyValueError::new_err(
            "Missing TW_CROWDSTRIKE_CLIENT_ID environment variable. \
             Set TW_CROWDSTRIKE_CLIENT_ID and TW_CROWDSTRIKE_CLIENT_SECRET to use CrowdStrike connector.",
        )
    })?;

    let client_secret = std::env::var("TW_CROWDSTRIKE_CLIENT_SECRET").map_err(|_| {
        PyValueError::new_err(
            "Missing TW_CROWDSTRIKE_CLIENT_SECRET environment variable. \
             Set TW_CROWDSTRIKE_CLIENT_ID and TW_CROWDSTRIKE_CLIENT_SECRET to use CrowdStrike connector.",
        )
    })?;

    let region = std::env::var("TW_CROWDSTRIKE_REGION").unwrap_or_else(|_| "us-1".to_string());

    // Build the base URL based on region
    let base_url = match region.as_str() {
        "us-1" => "https://api.crowdstrike.com",
        "us-2" => "https://api.us-2.crowdstrike.com",
        "eu-1" => "https://api.eu-1.crowdstrike.com",
        "us-gov-1" => "https://api.laggar.gcw.crowdstrike.com",
        _ => "https://api.crowdstrike.com",
    };

    let token_url = format!("{}/oauth2/token", base_url);

    let config = CrowdStrikeConfig {
        connector: ConnectorConfig {
            name: "crowdstrike".to_string(),
            base_url: base_url.to_string(),
            auth: AuthConfig::OAuth2 {
                client_id,
                client_secret: client_secret.into(),
                token_url,
                scopes: vec![
                    "hosts:read".to_string(),
                    "hosts:write".to_string(),
                    "detects:read".to_string(),
                    "real-time-response:read".to_string(),
                    "real-time-response:write".to_string(),
                ],
            },
            timeout_secs: 30,
            max_retries: 3,
            verify_tls: true,
            headers: std::collections::HashMap::new(),
        },
        region,
        member_cid: None,
    };

    CrowdStrikeConnector::new(config).map_err(|e| {
        PyRuntimeError::new_err(format!("Failed to create CrowdStrike connector: {}", e))
    })
}

#[pymethods]
impl EDRBridge {
    /// Creates a new EDRBridge.
    ///
    /// Args:
    ///     connector_type: Type of connector to use:
    ///         - "mock": Mock connector for testing (default)
    ///         - "crowdstrike": CrowdStrike Falcon connector
    ///     with_sample_data: If True, initializes mock connector with sample data (default: True)
    ///         Only applies to "mock" connector type.
    ///
    /// Returns:
    ///     EDRBridge instance
    ///
    /// Raises:
    ///     ValueError: If connector_type is not supported or required credentials are missing
    ///     RuntimeError: If connector initialization fails
    ///
    /// Environment Variables (for "crowdstrike" mode):
    ///     TW_CROWDSTRIKE_CLIENT_ID: OAuth2 client ID (required)
    ///     TW_CROWDSTRIKE_CLIENT_SECRET: OAuth2 client secret (required)
    ///     TW_CROWDSTRIKE_REGION: API region (optional, default: "us-1")
    #[new]
    #[pyo3(signature = (connector_type, with_sample_data=true))]
    pub fn new(connector_type: &str, with_sample_data: bool) -> PyResult<Self> {
        match connector_type {
            "" | "mock" => {
                let connector: Arc<dyn EDRConnector + Send + Sync> = if with_sample_data {
                    Arc::new(MockEDRConnector::with_sample_data("mock"))
                } else {
                    Arc::new(MockEDRConnector::new("mock"))
                };
                Ok(Self {
                    connector,
                    connector_type: "mock".to_string(),
                })
            }
            "crowdstrike" => {
                let connector = create_crowdstrike_connector()?;
                Ok(Self {
                    connector: Arc::new(connector),
                    connector_type: connector_type.to_string(),
                })
            }
            _ => Err(PyValueError::new_err(format!(
                "Unsupported connector type: '{}'. Supported: 'mock', 'crowdstrike'",
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

        Ok(pythonize::pythonize(py, &result)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))?
            .unbind())
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

        Ok(pythonize::pythonize(py, &result)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))?
            .unbind())
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

        Ok(pythonize::pythonize(py, &result)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))?
            .unbind())
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

        Ok(pythonize::pythonize(py, &result)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))?
            .unbind())
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

        Ok(pythonize::pythonize(py, &result)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))?
            .unbind())
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

        Ok(pythonize::pythonize(py, &result)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))?
            .unbind())
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

        Ok(pythonize::pythonize(py, &result)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))?
            .unbind())
    }

    /// Check the health of the connector.
    ///
    /// Returns:
    ///     dict with health status
    pub fn health_check(&self, py: Python<'_>) -> PyResult<PyObject> {
        let connector = Arc::clone(&self.connector);

        let result = get_runtime()
            .block_on(async move { connector.health_check().await })
            .map_err(connector_error_to_py)?;

        Ok(pythonize::pythonize(py, &result)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))?
            .unbind())
    }
}

// ============================================================================
// EmailGatewayBridge - Email Gateway Connector Bridge
// ============================================================================

/// Bridge for Email Gateway (M365/mock) operations.
///
/// Provides Python access to email gateway connectors for email search,
/// quarantine, and sender blocking operations.
///
/// Example:
///     email = EmailGatewayBridge("mock")
///     emails = email.search_emails("subject:phishing", None, None, 7)
///     result = email.quarantine_email("msg-001")
///     result = email.block_sender("attacker@evil.com")
#[pyclass]
pub struct EmailGatewayBridge {
    connector: Arc<dyn EmailGatewayConnector + Send + Sync>,
    connector_type: String,
}

#[pymethods]
impl EmailGatewayBridge {
    /// Creates a new EmailGatewayBridge.
    ///
    /// Args:
    ///     mode: Connector mode to use ("mock" or "m365")
    ///           - "mock": Uses mock connector for testing (default)
    ///           - "m365": Uses Microsoft 365 Graph API (requires env vars:
    ///                     TW_M365_TENANT_ID, TW_M365_CLIENT_ID, TW_M365_CLIENT_SECRET)
    ///
    /// Returns:
    ///     EmailGatewayBridge instance
    ///
    /// Raises:
    ///     ValueError: If mode is not supported or required env vars are missing for m365
    #[new]
    pub fn new(mode: &str) -> PyResult<Self> {
        match mode {
            "mock" | "" => Ok(Self {
                connector: Arc::new(MockEmailGatewayConnector::with_sample_data("mock")),
                connector_type: "mock".to_string(),
            }),
            "m365" => {
                let tenant_id = std::env::var("TW_M365_TENANT_ID").map_err(|_| {
                    PyValueError::new_err(
                        "TW_M365_TENANT_ID environment variable not set. \
                         Please set your Microsoft 365 tenant ID.",
                    )
                })?;

                let client_id = std::env::var("TW_M365_CLIENT_ID").map_err(|_| {
                    PyValueError::new_err(
                        "TW_M365_CLIENT_ID environment variable not set. \
                         Please set your Microsoft 365 application client ID.",
                    )
                })?;

                let client_secret = std::env::var("TW_M365_CLIENT_SECRET").map_err(|_| {
                    PyValueError::new_err(
                        "TW_M365_CLIENT_SECRET environment variable not set. \
                         Please set your Microsoft 365 application client secret.",
                    )
                })?;

                if tenant_id.trim().is_empty()
                    || client_id.trim().is_empty()
                    || client_secret.trim().is_empty()
                {
                    return Err(PyValueError::new_err(
                        "One or more M365 environment variables are empty. \
                         Please provide valid values for TW_M365_TENANT_ID, \
                         TW_M365_CLIENT_ID, and TW_M365_CLIENT_SECRET.",
                    ));
                }

                let token_url = format!(
                    "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
                    tenant_id
                );

                let config = M365Config {
                    connector: ConnectorConfig {
                        name: "m365".to_string(),
                        base_url: "https://graph.microsoft.com/v1.0".to_string(),
                        auth: AuthConfig::OAuth2 {
                            client_id,
                            client_secret: client_secret.into(),
                            token_url,
                            scopes: vec!["https://graph.microsoft.com/.default".to_string()],
                        },
                        timeout_secs: 30,
                        max_retries: 3,
                        verify_tls: true,
                        headers: std::collections::HashMap::new(),
                    },
                    tenant_id,
                    target_mailbox: None,
                    use_security_center: false,
                };

                let connector = M365Connector::new(config).map_err(|e| {
                    PyRuntimeError::new_err(format!("Failed to create M365 connector: {}", e))
                })?;

                Ok(Self {
                    connector: Arc::new(connector),
                    connector_type: "m365".to_string(),
                })
            }
            _ => Err(PyValueError::new_err(format!(
                "Unsupported connector mode: '{}'. Supported modes: 'mock', 'm365'",
                mode
            ))),
        }
    }

    /// Returns the connector type.
    pub fn get_connector_type(&self) -> String {
        self.connector_type.clone()
    }

    /// Search for emails matching the specified criteria.
    ///
    /// Args:
    ///     query: Optional search query (subject contains)
    ///     sender: Optional sender email address filter
    ///     recipient: Optional recipient email address filter
    ///     days: Number of days to search back (default: 7)
    ///
    /// Returns:
    ///     list of email dicts, each containing:
    ///         - id: Message ID
    ///         - internet_message_id: RFC 2822 message ID
    ///         - sender: Sender email address
    ///         - recipients: List of recipient addresses
    ///         - subject: Email subject
    ///         - received_at: Timestamp when received
    ///         - has_attachments: Whether email has attachments
    ///         - attachments: List of attachment metadata
    ///         - urls: URLs found in the email body
    ///         - headers: Email headers
    ///
    /// Raises:
    ///     RuntimeError: If search fails
    #[pyo3(signature = (query=None, sender=None, recipient=None, days=7))]
    pub fn search_emails(
        &self,
        py: Python<'_>,
        query: Option<&str>,
        sender: Option<&str>,
        recipient: Option<&str>,
        days: i64,
    ) -> PyResult<PyObject> {
        let connector = Arc::clone(&self.connector);
        let search_query = EmailSearchQuery {
            sender: sender.map(|s| s.to_string()),
            recipient: recipient.map(|r| r.to_string()),
            subject_contains: query.map(|q| q.to_string()),
            timerange: TimeRange::last_days(days),
            has_attachments: None,
            threat_type: None,
            limit: 100,
        };

        let result = get_runtime()
            .block_on(async move { connector.search_emails(search_query).await })
            .map_err(connector_error_to_py)?;

        Ok(pythonize::pythonize(py, &result)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))?
            .unbind())
    }

    /// Get a specific email by message ID.
    ///
    /// Args:
    ///     message_id: The message ID to retrieve
    ///
    /// Returns:
    ///     dict with email details
    ///
    /// Raises:
    ///     RuntimeError: If email not found or retrieval fails
    pub fn get_email(&self, py: Python<'_>, message_id: &str) -> PyResult<PyObject> {
        let connector = Arc::clone(&self.connector);
        let message_id = message_id.to_string();

        let result = get_runtime()
            .block_on(async move { connector.get_email(&message_id).await })
            .map_err(connector_error_to_py)?;

        Ok(pythonize::pythonize(py, &result)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))?
            .unbind())
    }

    /// Quarantine an email (move to junk/quarantine folder).
    ///
    /// Args:
    ///     message_id: The message ID to quarantine
    ///
    /// Returns:
    ///     bool: True if quarantine succeeded
    ///
    /// Raises:
    ///     RuntimeError: If quarantine fails or email not found
    pub fn quarantine_email(&self, message_id: &str) -> PyResult<bool> {
        let connector = Arc::clone(&self.connector);
        let message_id = message_id.to_string();

        let result = get_runtime()
            .block_on(async move { connector.quarantine_email(&message_id).await })
            .map_err(connector_error_to_py)?;

        Ok(result.success)
    }

    /// Release an email from quarantine (move back to inbox).
    ///
    /// Args:
    ///     message_id: The message ID to release
    ///
    /// Returns:
    ///     bool: True if release succeeded
    ///
    /// Raises:
    ///     RuntimeError: If release fails or email not found/not quarantined
    pub fn release_email(&self, message_id: &str) -> PyResult<bool> {
        let connector = Arc::clone(&self.connector);
        let message_id = message_id.to_string();

        let result = get_runtime()
            .block_on(async move { connector.release_email(&message_id).await })
            .map_err(connector_error_to_py)?;

        Ok(result.success)
    }

    /// Block a sender address.
    ///
    /// Args:
    ///     sender_address: The sender email address to block
    ///
    /// Returns:
    ///     bool: True if block succeeded
    ///
    /// Raises:
    ///     RuntimeError: If blocking fails
    pub fn block_sender(&self, sender_address: &str) -> PyResult<bool> {
        let connector = Arc::clone(&self.connector);
        let sender = sender_address.to_string();

        let result = get_runtime()
            .block_on(async move { connector.block_sender(&sender).await })
            .map_err(connector_error_to_py)?;

        Ok(result.success)
    }

    /// Unblock a sender address.
    ///
    /// Args:
    ///     sender_address: The sender email address to unblock
    ///
    /// Returns:
    ///     bool: True if unblock succeeded
    ///
    /// Raises:
    ///     RuntimeError: If unblocking fails or sender not blocked
    pub fn unblock_sender(&self, sender_address: &str) -> PyResult<bool> {
        let connector = Arc::clone(&self.connector);
        let sender = sender_address.to_string();

        let result = get_runtime()
            .block_on(async move { connector.unblock_sender(&sender).await })
            .map_err(connector_error_to_py)?;

        Ok(result.success)
    }

    /// Check the health of the email gateway connector.
    ///
    /// Returns:
    ///     dict with health status including:
    ///         - status: "healthy", "degraded", "unhealthy", or "unknown"
    ///         - connector_type: The type of connector ("mock" or "m365")
    ///         - message: Additional details (for degraded/unhealthy status)
    pub fn health_check(&self, py: Python<'_>) -> PyResult<PyObject> {
        let connector = Arc::clone(&self.connector);
        let connector_type = self.connector_type.clone();

        let health = get_runtime()
            .block_on(async move { connector.health_check().await })
            .map_err(connector_error_to_py)?;

        let result = match health {
            ConnectorHealth::Healthy => serde_json::json!({
                "status": "healthy",
                "connector_type": connector_type,
                "message": null
            }),
            ConnectorHealth::Degraded(msg) => serde_json::json!({
                "status": "degraded",
                "connector_type": connector_type,
                "message": msg
            }),
            ConnectorHealth::Unhealthy(msg) => serde_json::json!({
                "status": "unhealthy",
                "connector_type": connector_type,
                "message": msg
            }),
            ConnectorHealth::Unknown => serde_json::json!({
                "status": "unknown",
                "connector_type": connector_type,
                "message": null
            }),
        };

        Ok(pythonize::pythonize(py, &result)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))?
            .unbind())
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
            return Ok(pythonize::pythonize(py, &result)
                .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))?
                .unbind());
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

        Ok(pythonize::pythonize(py, &result)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))?
            .unbind())
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

        Ok(pythonize::pythonize(py, &result)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))?
            .unbind())
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
// TicketingBridge - Ticketing System Connector Bridge
// ============================================================================

/// Enum to hold different ticketing connector types.
enum TicketingConnectorType {
    Mock(MockTicketingConnector),
    Jira(Box<JiraConnector>),
}

/// Bridge for ticketing system operations (Jira, Mock).
///
/// Provides Python access to ticketing connectors for creating, updating,
/// and managing security incident tickets.
///
/// Example:
///     # Using mock connector for testing
///     ticketing = TicketingBridge("mock")
///     ticket = ticketing.create_ticket("Security Alert", "Malware detected", "high", ["security"])
///
///     # Using Jira connector (requires env vars)
///     ticketing = TicketingBridge("jira")
///     ticket = ticketing.create_ticket("Security Alert", "Malware detected", "high", ["security"])
#[pyclass]
pub struct TicketingBridge {
    connector: TicketingConnectorType,
    connector_type: String,
}

#[pymethods]
impl TicketingBridge {
    /// Creates a new TicketingBridge.
    ///
    /// Args:
    ///     mode: Type of connector to use ("mock" or "jira")
    ///
    /// For "jira" mode, the following environment variables are required:
    ///     - TW_JIRA_URL: Base URL of your Jira instance
    ///     - TW_JIRA_EMAIL: Email address for authentication
    ///     - TW_JIRA_API_TOKEN: API token for authentication
    ///     - TW_JIRA_PROJECT: Project key (e.g., "SEC")
    ///
    /// Returns:
    ///     TicketingBridge instance
    ///
    /// Raises:
    ///     ValueError: If mode is not supported or required env vars are missing
    #[new]
    pub fn new(mode: &str) -> PyResult<Self> {
        match mode {
            "mock" => Ok(Self {
                connector: TicketingConnectorType::Mock(MockTicketingConnector::new("mock")),
                connector_type: mode.to_string(),
            }),
            "jira" => {
                // Read configuration from environment variables
                let base_url = std::env::var("TW_JIRA_URL").map_err(|_| {
                    PyValueError::new_err(
                        "TW_JIRA_URL environment variable not set. Required for Jira mode.",
                    )
                })?;

                let email = std::env::var("TW_JIRA_EMAIL").map_err(|_| {
                    PyValueError::new_err(
                        "TW_JIRA_EMAIL environment variable not set. Required for Jira mode.",
                    )
                })?;

                let api_token = std::env::var("TW_JIRA_API_TOKEN").map_err(|_| {
                    PyValueError::new_err(
                        "TW_JIRA_API_TOKEN environment variable not set. Required for Jira mode.",
                    )
                })?;

                let project_key = std::env::var("TW_JIRA_PROJECT").map_err(|_| {
                    PyValueError::new_err(
                        "TW_JIRA_PROJECT environment variable not set. Required for Jira mode.",
                    )
                })?;

                let config = JiraConfig {
                    connector: ConnectorConfig {
                        name: "jira".to_string(),
                        base_url,
                        auth: AuthConfig::Basic {
                            username: email,
                            password: api_token.into(),
                        },
                        timeout_secs: 30,
                        max_retries: 3,
                        verify_tls: true,
                        headers: std::collections::HashMap::new(),
                    },
                    project_key,
                    default_issue_type: "Task".to_string(),
                    field_mappings: std::collections::HashMap::new(),
                    priority_mappings: std::collections::HashMap::new(),
                    is_server: false,
                    default_component: None,
                    security_level: None,
                };

                let connector = JiraConnector::new(config).map_err(|e| {
                    PyRuntimeError::new_err(format!("Failed to create Jira connector: {}", e))
                })?;

                Ok(Self {
                    connector: TicketingConnectorType::Jira(Box::new(connector)),
                    connector_type: mode.to_string(),
                })
            }
            _ => Err(PyValueError::new_err(format!(
                "Unsupported mode: {}. Supported: mock, jira",
                mode
            ))),
        }
    }

    /// Returns the connector type.
    pub fn get_connector_type(&self) -> String {
        self.connector_type.clone()
    }

    /// Create a new ticket.
    ///
    /// Args:
    ///     summary: Ticket title/summary
    ///     description: Detailed description of the issue
    ///     priority: Priority level ("lowest", "low", "medium", "high", "highest")
    ///     labels: List of labels/tags to apply
    ///
    /// Returns:
    ///     dict with ticket information including:
    ///         - id: Ticket ID
    ///         - key: Ticket key (e.g., "SEC-123")
    ///         - title: Ticket title
    ///         - description: Ticket description
    ///         - status: Current status
    ///         - priority: Priority level
    ///         - url: URL to view the ticket
    ///         - created_at: Creation timestamp
    ///         - updated_at: Last update timestamp
    ///
    /// Raises:
    ///     ValueError: If priority is invalid
    ///     RuntimeError: If ticket creation fails
    pub fn create_ticket(
        &self,
        py: Python<'_>,
        summary: &str,
        description: &str,
        priority: &str,
        labels: Vec<String>,
    ) -> PyResult<PyObject> {
        let ticket_priority = match priority.to_lowercase().as_str() {
            "lowest" => TicketPriority::Lowest,
            "low" => TicketPriority::Low,
            "medium" => TicketPriority::Medium,
            "high" => TicketPriority::High,
            "highest" => TicketPriority::Highest,
            _ => {
                return Err(PyValueError::new_err(format!(
                    "Invalid priority: {}. Must be one of: lowest, low, medium, high, highest",
                    priority
                )))
            }
        };

        let request = CreateTicketRequest {
            title: summary.to_string(),
            description: description.to_string(),
            ticket_type: "Task".to_string(),
            priority: ticket_priority,
            labels,
            assignee: None,
            custom_fields: std::collections::HashMap::new(),
        };

        let result = match &self.connector {
            TicketingConnectorType::Mock(c) => {
                get_runtime().block_on(async { c.create_ticket(request).await })
            }
            TicketingConnectorType::Jira(c) => {
                get_runtime().block_on(async { c.create_ticket(request).await })
            }
        }
        .map_err(connector_error_to_py)?;

        Ok(pythonize::pythonize(py, &result)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))?
            .unbind())
    }

    /// Get a ticket by ID or key.
    ///
    /// Args:
    ///     ticket_id: Ticket ID or key (e.g., "SEC-123" or "MOCK-1")
    ///
    /// Returns:
    ///     dict with ticket information
    ///
    /// Raises:
    ///     RuntimeError: If ticket not found or retrieval fails
    pub fn get_ticket(&self, py: Python<'_>, ticket_id: &str) -> PyResult<PyObject> {
        let result = match &self.connector {
            TicketingConnectorType::Mock(c) => {
                get_runtime().block_on(async { c.get_ticket(ticket_id).await })
            }
            TicketingConnectorType::Jira(c) => {
                get_runtime().block_on(async { c.get_ticket(ticket_id).await })
            }
        }
        .map_err(connector_error_to_py)?;

        Ok(pythonize::pythonize(py, &result)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))?
            .unbind())
    }

    /// Update an existing ticket.
    ///
    /// Args:
    ///     ticket_id: Ticket ID or key to update
    ///     updates: Dict with fields to update. Supported fields:
    ///         - title: New title (optional)
    ///         - description: New description (optional)
    ///         - status: New status (optional)
    ///         - priority: New priority (optional)
    ///         - assignee: New assignee (optional)
    ///         - add_labels: Labels to add (optional, list)
    ///         - remove_labels: Labels to remove (optional, list)
    ///
    /// Returns:
    ///     dict with updated ticket information
    ///
    /// Raises:
    ///     RuntimeError: If ticket not found or update fails
    pub fn update_ticket(
        &self,
        py: Python<'_>,
        ticket_id: &str,
        updates: &Bound<'_, PyAny>,
    ) -> PyResult<PyObject> {
        // Parse updates from Python dict
        let updates_dict: std::collections::HashMap<String, PyObject> = updates
            .extract()
            .map_err(|e| PyValueError::new_err(format!("updates must be a dict: {}", e)))?;

        let mut update_request = UpdateTicketRequest::default();

        // Extract optional fields from the dict
        if let Some(title) = updates_dict.get("title") {
            if let Ok(t) = title.bind(py).extract::<String>() {
                update_request.title = Some(t);
            }
        }

        if let Some(description) = updates_dict.get("description") {
            if let Ok(d) = description.bind(py).extract::<String>() {
                update_request.description = Some(d);
            }
        }

        if let Some(status) = updates_dict.get("status") {
            if let Ok(s) = status.bind(py).extract::<String>() {
                update_request.status = Some(s);
            }
        }

        if let Some(priority) = updates_dict.get("priority") {
            if let Ok(p) = priority.bind(py).extract::<String>() {
                let ticket_priority = match p.to_lowercase().as_str() {
                    "lowest" => TicketPriority::Lowest,
                    "low" => TicketPriority::Low,
                    "medium" => TicketPriority::Medium,
                    "high" => TicketPriority::High,
                    "highest" => TicketPriority::Highest,
                    _ => return Err(PyValueError::new_err(format!("Invalid priority: {}", p))),
                };
                update_request.priority = Some(ticket_priority);
            }
        }

        if let Some(assignee) = updates_dict.get("assignee") {
            if let Ok(a) = assignee.bind(py).extract::<String>() {
                update_request.assignee = Some(a);
            }
        }

        if let Some(add_labels) = updates_dict.get("add_labels") {
            if let Ok(labels) = add_labels.bind(py).extract::<Vec<String>>() {
                update_request.add_labels = labels;
            }
        }

        if let Some(remove_labels) = updates_dict.get("remove_labels") {
            if let Ok(labels) = remove_labels.bind(py).extract::<Vec<String>>() {
                update_request.remove_labels = labels;
            }
        }

        let ticket_id = ticket_id.to_string();
        let result =
            match &self.connector {
                TicketingConnectorType::Mock(c) => get_runtime()
                    .block_on(async { c.update_ticket(&ticket_id, update_request).await }),
                TicketingConnectorType::Jira(c) => get_runtime()
                    .block_on(async { c.update_ticket(&ticket_id, update_request).await }),
            }
            .map_err(connector_error_to_py)?;

        Ok(pythonize::pythonize(py, &result)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))?
            .unbind())
    }

    /// Add a comment to a ticket.
    ///
    /// Args:
    ///     ticket_id: Ticket ID or key
    ///     comment: Comment text to add
    ///
    /// Returns:
    ///     bool: True if comment was added successfully
    ///
    /// Raises:
    ///     RuntimeError: If ticket not found or comment fails
    pub fn add_comment(&self, ticket_id: &str, comment: &str) -> PyResult<bool> {
        let ticket_id = ticket_id.to_string();
        let comment = comment.to_string();

        match &self.connector {
            TicketingConnectorType::Mock(c) => {
                get_runtime().block_on(async { c.add_comment(&ticket_id, &comment).await })
            }
            TicketingConnectorType::Jira(c) => {
                get_runtime().block_on(async { c.add_comment(&ticket_id, &comment).await })
            }
        }
        .map_err(connector_error_to_py)?;

        Ok(true)
    }

    /// Search for tickets matching a query.
    ///
    /// Args:
    ///     query: Search query string (matches title, description, labels)
    ///
    /// Returns:
    ///     list of ticket dicts matching the query
    ///
    /// Raises:
    ///     RuntimeError: If search fails
    #[pyo3(signature = (query, limit=100))]
    pub fn search_tickets(&self, py: Python<'_>, query: &str, limit: usize) -> PyResult<PyObject> {
        let query = query.to_string();

        let result = match &self.connector {
            TicketingConnectorType::Mock(c) => {
                get_runtime().block_on(async { c.search_tickets(&query, limit).await })
            }
            TicketingConnectorType::Jira(c) => {
                get_runtime().block_on(async { c.search_tickets(&query, limit).await })
            }
        }
        .map_err(connector_error_to_py)?;

        Ok(pythonize::pythonize(py, &result)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))?
            .unbind())
    }

    /// Check the health of the ticketing connector.
    ///
    /// Returns:
    ///     dict with health status:
    ///         - status: "healthy", "degraded", or "unhealthy"
    ///         - message: Optional message with details
    pub fn health_check(&self, py: Python<'_>) -> PyResult<PyObject> {
        use tw_connectors::traits::Connector;

        let result = match &self.connector {
            TicketingConnectorType::Mock(c) => {
                get_runtime().block_on(async { c.health_check().await })
            }
            TicketingConnectorType::Jira(c) => {
                get_runtime().block_on(async { c.health_check().await })
            }
        }
        .map_err(connector_error_to_py)?;

        Ok(pythonize::pythonize(py, &result)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))?
            .unbind())
    }
}

// ============================================================================
// MetricsBridge - Metrics Export Bridge for Python
// ============================================================================

/// Bridge for exporting Python metrics to the Rust Prometheus endpoint.
///
/// Provides Python access to record metrics that are exposed via the
/// Rust Prometheus endpoint at /metrics.
///
/// The metrics recorded through this bridge are:
/// - `triage_warden_incidents_total`: Counter with severity and status labels
/// - `triage_warden_actions_total`: Counter with action_type and status labels
/// - `triage_warden_triage_duration_seconds`: Histogram of triage durations
///
/// Example:
///     from tw_bridge import MetricsBridge
///
///     metrics = MetricsBridge()
///     metrics.record_incident("high", "resolved")
///     metrics.record_action("quarantine_email", "success")
///     metrics.record_triage_duration(1.5)  # 1.5 seconds
#[pyclass]
pub struct MetricsBridge {
    /// Whether metrics recording is enabled
    enabled: bool,
}

#[pymethods]
impl MetricsBridge {
    /// Creates a new MetricsBridge.
    ///
    /// Args:
    ///     enabled: Whether metrics recording is enabled (default: True)
    ///
    /// Returns:
    ///     MetricsBridge instance
    #[new]
    #[pyo3(signature = (enabled=true))]
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    /// Record an incident with the given severity and status.
    ///
    /// This increments the `triage_warden_incidents_total` counter
    /// with labels for severity and status.
    ///
    /// Args:
    ///     severity: Incident severity (e.g., "critical", "high", "medium", "low", "info")
    ///     status: Incident status (e.g., "new", "resolved", "false_positive")
    ///
    /// Example:
    ///     metrics.record_incident("high", "resolved")
    pub fn record_incident(&self, severity: &str, status: &str) {
        if !self.enabled {
            return;
        }
        metrics::counter!(
            "triage_warden_incidents_total",
            "severity" => severity.to_string(),
            "status" => status.to_string()
        )
        .increment(1);
    }

    /// Record an action with the given action type and status.
    ///
    /// This increments the `triage_warden_actions_total` counter
    /// with labels for action_type and status.
    ///
    /// Args:
    ///     action_type: Type of action (e.g., "quarantine_email", "block_sender",
    ///                  "isolate_host", "create_ticket")
    ///     status: Action status (e.g., "success", "failure", "pending")
    ///
    /// Example:
    ///     metrics.record_action("quarantine_email", "success")
    pub fn record_action(&self, action_type: &str, status: &str) {
        if !self.enabled {
            return;
        }
        metrics::counter!(
            "triage_warden_actions_total",
            "action_type" => action_type.to_string(),
            "status" => status.to_string()
        )
        .increment(1);
    }

    /// Record triage duration in seconds.
    ///
    /// This records a value to the `triage_warden_triage_duration_seconds`
    /// histogram for tracking triage operation performance.
    ///
    /// Args:
    ///     duration_seconds: Duration of the triage operation in seconds (float)
    ///
    /// Example:
    ///     start = time.time()
    ///     # ... perform triage ...
    ///     metrics.record_triage_duration(time.time() - start)
    pub fn record_triage_duration(&self, duration_seconds: f64) {
        if !self.enabled {
            return;
        }
        metrics::histogram!("triage_warden_triage_duration_seconds").record(duration_seconds);
    }

    /// Record a stage latency measurement.
    ///
    /// This records a value to the `triage_warden_stage_latency_seconds`
    /// histogram with a stage label for tracking individual pipeline stages.
    ///
    /// Args:
    ///     stage: Name of the pipeline stage (e.g., "email_parsing", "enrichment",
    ///            "llm_analysis", "action_execution")
    ///     duration_seconds: Duration of the stage in seconds (float)
    ///
    /// Example:
    ///     metrics.record_stage_latency("email_parsing", 0.025)  # 25ms
    pub fn record_stage_latency(&self, stage: &str, duration_seconds: f64) {
        if !self.enabled {
            return;
        }
        metrics::histogram!(
            "triage_warden_stage_latency_seconds",
            "stage" => stage.to_string()
        )
        .record(duration_seconds);
    }

    /// Record an error occurrence.
    ///
    /// This increments the `triage_warden_errors_total` counter
    /// with an error_type label.
    ///
    /// Args:
    ///     error_type: Type of error (e.g., "parse_error", "llm_timeout",
    ///                 "connector_error", "policy_violation")
    ///
    /// Example:
    ///     metrics.record_error("llm_timeout")
    pub fn record_error(&self, error_type: &str) {
        if !self.enabled {
            return;
        }
        metrics::counter!(
            "triage_warden_errors_total",
            "error_type" => error_type.to_string()
        )
        .increment(1);
    }

    /// Record a triage verdict with confidence.
    ///
    /// This increments the `triage_warden_triages_total` counter
    /// with verdict and confidence_bucket labels.
    ///
    /// Args:
    ///     verdict: Triage verdict (e.g., "malicious", "suspicious", "benign", "inconclusive")
    ///     confidence: Confidence score between 0 and 1
    ///
    /// Example:
    ///     metrics.record_triage_verdict("malicious", 0.95)
    pub fn record_triage_verdict(&self, verdict: &str, confidence: f64) {
        if !self.enabled {
            return;
        }
        // Bucket confidence into ranges for Prometheus labels
        let confidence_bucket = if confidence >= 0.9 {
            "0.9-1.0"
        } else if confidence >= 0.7 {
            "0.7-0.9"
        } else if confidence >= 0.5 {
            "0.5-0.7"
        } else {
            "0.0-0.5"
        };

        metrics::counter!(
            "triage_warden_triages_total",
            "verdict" => verdict.to_string(),
            "confidence_bucket" => confidence_bucket.to_string()
        )
        .increment(1);
    }

    /// Check if metrics recording is enabled.
    ///
    /// Returns:
    ///     bool: True if metrics recording is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Enable or disable metrics recording.
    ///
    /// Args:
    ///     enabled: Whether to enable metrics recording
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
}

impl Default for MetricsBridge {
    fn default() -> Self {
        Self { enabled: true }
    }
}

// ============================================================================
// Legacy TriageWardenBridge (kept for backward compatibility)
// ============================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SubmittedAnalysis {
    incident_id: String,
    verdict: String,
    confidence: f64,
    summary: String,
    recommended_actions: Vec<String>,
    submitted_at: chrono::DateTime<chrono::Utc>,
}

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
    ticketing: Option<Arc<MockTicketingConnector>>,
    submitted_analyses: Arc<std::sync::Mutex<Vec<SubmittedAnalysis>>>,
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
            ticketing: None,
            submitted_analyses: Arc::new(std::sync::Mutex::new(Vec::new())),
        })
    }

    /// Initialize the bridge and connect to all configured services.
    pub fn initialize(&mut self) -> PyResult<bool> {
        // Initialize mock connectors
        self.threat_intel = Some(Arc::new(MockThreatIntelConnector::new("mock")));
        self.siem = Some(Arc::new(MockSIEMConnector::with_sample_data("mock")));
        self.edr = Some(Arc::new(MockEDRConnector::with_sample_data("mock")));
        self.ticketing = Some(Arc::new(MockTicketingConnector::new("mock")));

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

        Ok(pythonize::pythonize(py, &result)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))?
            .unbind())
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

        Ok(pythonize::pythonize(py, &result)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))?
            .unbind())
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

        Ok(pythonize::pythonize(py, &result)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))?
            .unbind())
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
                    .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))?
                    .unbind();
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

        Ok(pythonize::pythonize(py, &result)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization error: {}", e)))?
            .unbind())
    }

    /// Create a ticket.
    pub fn create_ticket(
        &self,
        title: &str,
        description: &str,
        priority: &str,
        labels: Vec<String>,
    ) -> PyResult<String> {
        let connector = self
            .ticketing
            .as_ref()
            .ok_or_else(|| PyRuntimeError::new_err("Bridge not initialized"))?;

        let ticket_priority = match priority.to_lowercase().as_str() {
            "lowest" => TicketPriority::Lowest,
            "low" => TicketPriority::Low,
            "medium" => TicketPriority::Medium,
            "high" => TicketPriority::High,
            "highest" => TicketPriority::Highest,
            _ => {
                return Err(PyValueError::new_err(format!(
                    "Invalid priority: {}. Must be one of: lowest, low, medium, high, highest",
                    priority
                )))
            }
        };

        let request = CreateTicketRequest {
            title: title.to_string(),
            description: description.to_string(),
            ticket_type: "Task".to_string(),
            priority: ticket_priority,
            labels,
            assignee: None,
            custom_fields: std::collections::HashMap::new(),
        };

        let ticket = get_runtime()
            .block_on(async move { connector.create_ticket(request).await })
            .map_err(connector_error_to_py)?;

        Ok(ticket.key)
    }

    /// Submit triage analysis to the orchestrator.
    pub fn submit_analysis(
        &self,
        incident_id: &str,
        verdict: &str,
        confidence: f64,
        summary: &str,
        recommended_actions: Vec<String>,
    ) -> PyResult<bool> {
        if !(0.0..=1.0).contains(&confidence) {
            return Err(PyValueError::new_err(
                "confidence must be between 0.0 and 1.0",
            ));
        }

        let analysis = SubmittedAnalysis {
            incident_id: incident_id.to_string(),
            verdict: verdict.to_string(),
            confidence,
            summary: summary.to_string(),
            recommended_actions,
            submitted_at: chrono::Utc::now(),
        };

        let mut submissions = self
            .submitted_analyses
            .lock()
            .map_err(|_| PyRuntimeError::new_err("Failed to persist submitted analysis"))?;
        submissions.push(analysis);

        tracing::info!(
            "Analysis submitted for incident {}: {} (confidence: {})",
            incident_id,
            verdict,
            confidence
        );
        Ok(true)
    }

    /// Returns the number of persisted analysis submissions.
    pub fn submitted_analysis_count(&self) -> PyResult<usize> {
        let submissions = self
            .submitted_analyses
            .lock()
            .map_err(|_| PyRuntimeError::new_err("Failed to read submitted analyses"))?;
        Ok(submissions.len())
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
        self.ticketing = None;

        if let Ok(mut submissions) = self.submitted_analyses.lock() {
            submissions.clear();
        }

        Ok(())
    }
}

/// Python module definition.
#[pymodule]
fn tw_bridge(m: &Bound<'_, PyModule>) -> PyResult<()> {
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
    m.add_class::<EmailGatewayBridge>()?;
    m.add_class::<PolicyBridge>()?;
    m.add_class::<TicketingBridge>()?;
    m.add_class::<MetricsBridge>()?;

    // Add version
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;

    Ok(())
}

// Note: Rust tests for tw-bridge are run via maturin/pytest since the crate
// requires Python linking. See python/tests/test_bridge.py for the test suite.
//
// The underlying connector functionality is tested in the tw-connectors crate,
// and policy functionality is tested in the tw-policy crate.
