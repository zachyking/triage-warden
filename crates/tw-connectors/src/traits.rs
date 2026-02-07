//! Connector trait definitions for Triage Warden.
//!
//! This module defines the interfaces that all connectors must implement,
//! providing a consistent API for interacting with external systems.

use crate::secure_string::SecureString;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use thiserror::Error;

/// Errors that can occur in connectors.
#[derive(Error, Debug, Clone)]
pub enum ConnectorError {
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("Authorization denied: {0}")]
    AuthorizationDenied(String),

    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Request failed: {0}")]
    RequestFailed(String),

    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Rate limited: retry after {0} seconds")]
    RateLimited(u64),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

/// Result type for connector operations.
pub type ConnectorResult<T> = Result<T, ConnectorError>;

/// Health status of a connector.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorHealth {
    /// Connector is healthy and operational.
    Healthy,
    /// Connector is degraded but still functional.
    Degraded(String),
    /// Connector is unhealthy and not operational.
    Unhealthy(String),
    /// Health status is unknown.
    Unknown,
}

/// Configuration for a connector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorConfig {
    /// Connector name/identifier.
    pub name: String,
    /// Base URL for the API.
    pub base_url: String,
    /// Authentication configuration.
    pub auth: AuthConfig,
    /// Request timeout in seconds.
    pub timeout_secs: u64,
    /// Maximum retries.
    pub max_retries: u32,
    /// Whether to verify TLS certificates.
    pub verify_tls: bool,
    /// Additional headers to include.
    pub headers: HashMap<String, String>,
}

/// Authentication configuration.
///
/// All credential fields use `SecureString` to ensure sensitive data is
/// automatically zeroized from memory when no longer needed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthConfig {
    /// No authentication.
    None,
    /// API key authentication.
    ApiKey {
        /// The API key (zeroized on drop).
        key: SecureString,
        /// The header name to use for the API key.
        header_name: String,
    },
    /// Bearer token authentication.
    BearerToken {
        /// The bearer token (zeroized on drop).
        token: SecureString,
    },
    /// Basic authentication.
    Basic {
        /// The username.
        username: String,
        /// The password (zeroized on drop).
        password: SecureString,
    },
    /// OAuth2 client credentials.
    OAuth2 {
        /// The client ID.
        client_id: String,
        /// The client secret (zeroized on drop).
        client_secret: SecureString,
        /// The token URL.
        token_url: String,
        /// The scopes to request.
        scopes: Vec<String>,
    },
}

/// Base trait for all connectors.
#[async_trait]
pub trait Connector: Send + Sync {
    /// Returns the connector name.
    fn name(&self) -> &str;

    /// Returns the connector type (e.g., "siem", "edr", "ticketing").
    fn connector_type(&self) -> &str;

    /// Returns the connector category.
    fn category(&self) -> ConnectorCategory {
        match self.connector_type() {
            "siem" => ConnectorCategory::Siem,
            "edr" => ConnectorCategory::Edr,
            "threat_intel" => ConnectorCategory::ThreatIntel,
            "ticketing" => ConnectorCategory::Ticketing,
            "email" => ConnectorCategory::Email,
            "cloud" => ConnectorCategory::Cloud,
            "identity" => ConnectorCategory::Identity,
            "network" => ConnectorCategory::Network,
            "sandbox" => ConnectorCategory::Sandbox,
            "collaboration" => ConnectorCategory::Collaboration,
            "itsm" => ConnectorCategory::Itsm,
            _ => ConnectorCategory::Cloud,
        }
    }

    /// Returns the capabilities this connector provides.
    fn capabilities(&self) -> Vec<String> {
        vec!["health_check".to_string(), "test_connection".to_string()]
    }

    /// Checks the health of the connector.
    async fn health_check(&self) -> ConnectorResult<ConnectorHealth>;

    /// Tests the connection to the external system.
    async fn test_connection(&self) -> ConnectorResult<bool>;
}

/// Ticketing system connector (Jira, ServiceNow, etc.).
#[async_trait]
pub trait TicketingConnector: Connector {
    /// Creates a new ticket.
    async fn create_ticket(&self, request: CreateTicketRequest) -> ConnectorResult<Ticket>;

    /// Gets a ticket by ID.
    async fn get_ticket(&self, ticket_id: &str) -> ConnectorResult<Ticket>;

    /// Updates a ticket.
    async fn update_ticket(
        &self,
        ticket_id: &str,
        update: UpdateTicketRequest,
    ) -> ConnectorResult<Ticket>;

    /// Adds a comment to a ticket.
    async fn add_comment(&self, ticket_id: &str, comment: &str) -> ConnectorResult<()>;

    /// Searches for tickets.
    async fn search_tickets(&self, query: &str, limit: usize) -> ConnectorResult<Vec<Ticket>>;

    /// Gets available ticket statuses.
    async fn get_statuses(&self) -> ConnectorResult<Vec<TicketStatus>>;
}

/// Request to create a ticket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTicketRequest {
    /// Ticket title/summary.
    pub title: String,
    /// Ticket description.
    pub description: String,
    /// Ticket type (e.g., "incident", "task").
    pub ticket_type: String,
    /// Priority level.
    pub priority: TicketPriority,
    /// Labels/tags.
    pub labels: Vec<String>,
    /// Assignee (optional).
    pub assignee: Option<String>,
    /// Custom fields.
    pub custom_fields: HashMap<String, serde_json::Value>,
}

/// Request to update a ticket.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateTicketRequest {
    /// New title (optional).
    pub title: Option<String>,
    /// New description (optional).
    pub description: Option<String>,
    /// New status (optional).
    pub status: Option<String>,
    /// New priority (optional).
    pub priority: Option<TicketPriority>,
    /// New assignee (optional).
    pub assignee: Option<String>,
    /// Labels to add.
    pub add_labels: Vec<String>,
    /// Labels to remove.
    pub remove_labels: Vec<String>,
    /// Custom field updates.
    pub custom_fields: HashMap<String, serde_json::Value>,
}

/// A ticket in the ticketing system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ticket {
    /// Ticket ID.
    pub id: String,
    /// Ticket key (e.g., "SEC-123").
    pub key: String,
    /// Ticket title.
    pub title: String,
    /// Ticket description.
    pub description: String,
    /// Current status.
    pub status: String,
    /// Priority level.
    pub priority: TicketPriority,
    /// Assignee.
    pub assignee: Option<String>,
    /// Reporter.
    pub reporter: String,
    /// Labels.
    pub labels: Vec<String>,
    /// Created timestamp.
    pub created_at: DateTime<Utc>,
    /// Updated timestamp.
    pub updated_at: DateTime<Utc>,
    /// URL to view the ticket.
    pub url: String,
    /// Custom fields.
    pub custom_fields: HashMap<String, serde_json::Value>,
}

/// Ticket priority levels.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TicketPriority {
    Lowest,
    Low,
    Medium,
    High,
    Highest,
}

/// Available ticket status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TicketStatus {
    /// Status ID.
    pub id: String,
    /// Status name.
    pub name: String,
    /// Status category.
    pub category: String,
}

/// Threat intelligence connector (VirusTotal, etc.).
#[async_trait]
pub trait ThreatIntelConnector: Connector {
    /// Looks up a file hash.
    async fn lookup_hash(&self, hash: &str) -> ConnectorResult<ThreatIntelResult>;

    /// Looks up an IP address.
    async fn lookup_ip(&self, ip: &IpAddr) -> ConnectorResult<ThreatIntelResult>;

    /// Looks up a domain.
    async fn lookup_domain(&self, domain: &str) -> ConnectorResult<ThreatIntelResult>;

    /// Looks up a URL.
    async fn lookup_url(&self, url: &str) -> ConnectorResult<ThreatIntelResult>;

    /// Submits a file for analysis (if supported).
    async fn submit_file(&self, file_path: &str) -> ConnectorResult<String>;

    /// Gets the analysis status for a submission.
    async fn get_analysis_status(&self, analysis_id: &str) -> ConnectorResult<AnalysisStatus>;
}

/// Result from a threat intelligence lookup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelResult {
    /// Type of indicator looked up.
    pub indicator_type: IndicatorType,
    /// The indicator value.
    pub indicator: String,
    /// Overall verdict.
    pub verdict: ThreatVerdict,
    /// Malicious score (0-100).
    pub malicious_score: u8,
    /// Number of engines that flagged as malicious.
    pub malicious_count: u32,
    /// Total number of engines that analyzed.
    pub total_engines: u32,
    /// Categories/tags from threat intel.
    pub categories: Vec<String>,
    /// Associated malware families.
    pub malware_families: Vec<String>,
    /// First seen timestamp.
    pub first_seen: Option<DateTime<Utc>>,
    /// Last seen timestamp.
    pub last_seen: Option<DateTime<Utc>>,
    /// Additional details.
    pub details: HashMap<String, serde_json::Value>,
    /// Source of the intelligence.
    pub source: String,
    /// Cache TTL in seconds.
    pub cache_ttl: u64,
}

/// Type of threat indicator.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IndicatorType {
    Md5,
    Sha1,
    Sha256,
    Ipv4,
    Ipv6,
    Domain,
    Url,
    Email,
}

/// Threat verdict from analysis.
#[derive(Debug, Clone, Hash, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ThreatVerdict {
    /// Known malicious.
    Malicious,
    /// Suspicious but not confirmed.
    Suspicious,
    /// Clean/benign.
    Clean,
    /// Unknown/not in database.
    Unknown,
}

/// Status of an ongoing analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisStatus {
    /// Analysis ID.
    pub id: String,
    /// Current status.
    pub status: String,
    /// Completion percentage.
    pub progress: u8,
    /// Result (if complete).
    pub result: Option<ThreatIntelResult>,
}

/// SIEM connector (Splunk, Elastic, etc.).
#[async_trait]
pub trait SIEMConnector: Connector {
    /// Executes a search query.
    async fn search(&self, query: &str, timerange: TimeRange) -> ConnectorResult<SearchResults>;

    /// Gets saved searches/alerts.
    async fn get_saved_searches(&self) -> ConnectorResult<Vec<SavedSearch>>;

    /// Subscribes to alerts (returns alert stream).
    async fn get_recent_alerts(&self, limit: usize) -> ConnectorResult<Vec<SIEMAlert>>;

    /// Gets field values for a given field.
    async fn get_field_values(
        &self,
        field: &str,
        timerange: TimeRange,
        limit: usize,
    ) -> ConnectorResult<Vec<String>>;
}

/// Time range for SIEM queries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRange {
    /// Start time.
    pub start: DateTime<Utc>,
    /// End time.
    pub end: DateTime<Utc>,
}

impl TimeRange {
    /// Creates a time range for the last N hours.
    pub fn last_hours(hours: i64) -> Self {
        let end = Utc::now();
        let start = end - chrono::Duration::hours(hours);
        Self { start, end }
    }

    /// Creates a time range for the last N days.
    pub fn last_days(days: i64) -> Self {
        let end = Utc::now();
        let start = end - chrono::Duration::days(days);
        Self { start, end }
    }
}

/// Results from a SIEM search.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResults {
    /// Search ID.
    pub search_id: String,
    /// Number of results.
    pub total_count: u64,
    /// Result events.
    pub events: Vec<SIEMEvent>,
    /// Search statistics.
    pub stats: Option<SearchStats>,
}

/// A single event from SIEM search.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SIEMEvent {
    /// Event timestamp.
    pub timestamp: DateTime<Utc>,
    /// Raw event data.
    pub raw: String,
    /// Parsed fields.
    pub fields: HashMap<String, serde_json::Value>,
    /// Source/index.
    pub source: String,
}

/// Search statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchStats {
    /// Execution time in milliseconds.
    pub execution_time_ms: u64,
    /// Events scanned.
    pub events_scanned: u64,
    /// Data scanned in bytes.
    pub bytes_scanned: u64,
}

/// A saved search/alert in the SIEM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedSearch {
    /// Search ID.
    pub id: String,
    /// Search name.
    pub name: String,
    /// Search query.
    pub query: String,
    /// Whether alerts are enabled.
    pub alerts_enabled: bool,
}

/// An alert from the SIEM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SIEMAlert {
    /// Alert ID.
    pub id: String,
    /// Alert name.
    pub name: String,
    /// Severity.
    pub severity: String,
    /// Timestamp.
    pub timestamp: DateTime<Utc>,
    /// Alert details.
    pub details: HashMap<String, serde_json::Value>,
}

/// EDR connector (CrowdStrike, Defender, etc.).
#[async_trait]
pub trait EDRConnector: Connector {
    /// Gets information about a host.
    async fn get_host_info(&self, hostname: &str) -> ConnectorResult<HostInfo>;

    /// Searches for hosts.
    async fn search_hosts(&self, query: &str, limit: usize) -> ConnectorResult<Vec<HostInfo>>;

    /// Isolates a host from the network.
    async fn isolate_host(&self, hostname: &str) -> ConnectorResult<ActionResult>;

    /// Removes host isolation.
    async fn unisolate_host(&self, hostname: &str) -> ConnectorResult<ActionResult>;

    /// Gets detections/alerts for a host.
    async fn get_host_detections(&self, hostname: &str) -> ConnectorResult<Vec<Detection>>;

    /// Gets process information for a host.
    async fn get_processes(
        &self,
        hostname: &str,
        timerange: TimeRange,
    ) -> ConnectorResult<Vec<ProcessInfo>>;

    /// Gets network connections for a host.
    async fn get_network_connections(
        &self,
        hostname: &str,
        timerange: TimeRange,
    ) -> ConnectorResult<Vec<NetworkConnection>>;
}

/// Information about a host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInfo {
    /// Hostname.
    pub hostname: String,
    /// Host ID in the EDR.
    pub host_id: String,
    /// IP addresses.
    pub ip_addresses: Vec<String>,
    /// MAC addresses.
    pub mac_addresses: Vec<String>,
    /// Operating system.
    pub os: String,
    /// OS version.
    pub os_version: String,
    /// Agent version.
    pub agent_version: String,
    /// Last seen timestamp.
    pub last_seen: DateTime<Utc>,
    /// Whether the host is isolated.
    pub isolated: bool,
    /// Host status.
    pub status: HostStatus,
    /// Tags.
    pub tags: Vec<String>,
}

/// Status of a host in EDR.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HostStatus {
    Online,
    Offline,
    Unknown,
}

/// Result of an EDR action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResult {
    /// Whether the action succeeded.
    pub success: bool,
    /// Action ID.
    pub action_id: String,
    /// Status message.
    pub message: String,
    /// Timestamp.
    pub timestamp: DateTime<Utc>,
}

/// A detection/alert from EDR.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    /// Detection ID.
    pub id: String,
    /// Detection name/type.
    pub name: String,
    /// Severity.
    pub severity: String,
    /// Timestamp.
    pub timestamp: DateTime<Utc>,
    /// Description.
    pub description: String,
    /// Tactic (MITRE ATT&CK).
    pub tactic: Option<String>,
    /// Technique (MITRE ATT&CK).
    pub technique: Option<String>,
    /// Associated file hash.
    pub file_hash: Option<String>,
    /// Associated process.
    pub process_name: Option<String>,
    /// Additional details.
    pub details: HashMap<String, serde_json::Value>,
}

/// Process information from EDR.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    /// Process ID.
    pub pid: u32,
    /// Process name.
    pub name: String,
    /// Command line.
    pub command_line: String,
    /// Parent process ID.
    pub parent_pid: Option<u32>,
    /// User running the process.
    pub user: String,
    /// Start time.
    pub start_time: DateTime<Utc>,
    /// File hash of the executable.
    pub file_hash: Option<String>,
    /// File path.
    pub file_path: Option<String>,
}

/// Network connection from EDR.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    /// Process ID.
    pub pid: u32,
    /// Process name.
    pub process_name: String,
    /// Local address.
    pub local_address: String,
    /// Local port.
    pub local_port: u16,
    /// Remote address.
    pub remote_address: String,
    /// Remote port.
    pub remote_port: u16,
    /// Protocol.
    pub protocol: String,
    /// Connection state.
    pub state: String,
    /// Timestamp.
    pub timestamp: DateTime<Utc>,
}

/// Email gateway connector (M365, Google Workspace, etc.).
#[async_trait]
pub trait EmailGatewayConnector: Connector {
    /// Searches for emails matching criteria.
    async fn search_emails(&self, query: EmailSearchQuery) -> ConnectorResult<Vec<EmailMessage>>;

    /// Gets a specific email by ID.
    async fn get_email(&self, message_id: &str) -> ConnectorResult<EmailMessage>;

    /// Quarantines/removes an email.
    async fn quarantine_email(&self, message_id: &str) -> ConnectorResult<ActionResult>;

    /// Releases an email from quarantine.
    async fn release_email(&self, message_id: &str) -> ConnectorResult<ActionResult>;

    /// Blocks a sender.
    async fn block_sender(&self, sender: &str) -> ConnectorResult<ActionResult>;

    /// Unblocks a sender.
    async fn unblock_sender(&self, sender: &str) -> ConnectorResult<ActionResult>;

    /// Gets threat explorer data for an email.
    async fn get_threat_data(&self, message_id: &str) -> ConnectorResult<EmailThreatData>;
}

/// Email search query parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailSearchQuery {
    /// Sender email address or pattern.
    pub sender: Option<String>,
    /// Recipient email address or pattern.
    pub recipient: Option<String>,
    /// Subject contains text.
    pub subject_contains: Option<String>,
    /// Time range for the search.
    pub timerange: TimeRange,
    /// Filter by has attachments.
    pub has_attachments: Option<bool>,
    /// Filter by threat type.
    pub threat_type: Option<String>,
    /// Maximum results to return.
    #[serde(default = "default_email_limit")]
    pub limit: usize,
}

fn default_email_limit() -> usize {
    100
}

/// An email message from the gateway.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailMessage {
    /// Message ID.
    pub id: String,
    /// Internet message ID (from headers).
    pub internet_message_id: String,
    /// Sender email address.
    pub sender: String,
    /// Recipient email addresses.
    pub recipients: Vec<String>,
    /// Email subject.
    pub subject: String,
    /// Received timestamp.
    pub received_at: DateTime<Utc>,
    /// Whether email has attachments.
    pub has_attachments: bool,
    /// Attachment metadata.
    pub attachments: Vec<EmailAttachment>,
    /// URLs found in the email.
    pub urls: Vec<String>,
    /// Email headers.
    pub headers: HashMap<String, String>,
    /// Threat assessment if available.
    pub threat_assessment: Option<ThreatAssessment>,
}

/// Email attachment metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailAttachment {
    /// Attachment ID.
    pub id: String,
    /// File name.
    pub name: String,
    /// Content type (MIME).
    pub content_type: String,
    /// File size in bytes.
    pub size: u64,
    /// SHA256 hash if available.
    pub sha256: Option<String>,
}

/// Threat assessment for an email.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatAssessment {
    /// Phishing verdict.
    pub phish_verdict: String,
    /// Spam verdict.
    pub spam_verdict: String,
    /// Malware verdict.
    pub malware_verdict: String,
    /// Spoof verdict.
    pub spoof_verdict: String,
}

/// Extended threat data for an email.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailThreatData {
    /// Delivery action taken.
    pub delivery_action: String,
    /// Threat types identified.
    pub threat_types: Vec<String>,
    /// Detection methods used.
    pub detection_methods: Vec<String>,
    /// URLs clicked by recipients.
    pub urls_clicked: Vec<UrlClick>,
}

/// URL click tracking data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlClick {
    /// The URL that was clicked.
    pub url: String,
    /// User who clicked.
    pub user: String,
    /// Click timestamp.
    pub clicked_at: DateTime<Utc>,
    /// Verdict at time of click.
    pub verdict: String,
}

// ============================================================================
// Framework Enhancement Types (3.1.1)
// ============================================================================

/// Category of a connector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorCategory {
    Siem,
    Edr,
    ThreatIntel,
    Ticketing,
    Email,
    Cloud,
    Identity,
    Network,
    Sandbox,
    Collaboration,
    Itsm,
}

impl std::fmt::Display for ConnectorCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Siem => "siem",
            Self::Edr => "edr",
            Self::ThreatIntel => "threat_intel",
            Self::Ticketing => "ticketing",
            Self::Email => "email",
            Self::Cloud => "cloud",
            Self::Identity => "identity",
            Self::Network => "network",
            Self::Sandbox => "sandbox",
            Self::Collaboration => "collaboration",
            Self::Itsm => "itsm",
        };
        write!(f, "{}", s)
    }
}

/// A raw alert from any alert source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawAlert {
    /// Alert ID from the source system.
    pub id: String,
    /// Alert title/name.
    pub title: String,
    /// Alert description.
    pub description: String,
    /// Severity level.
    pub severity: String,
    /// Alert timestamp.
    pub timestamp: DateTime<Utc>,
    /// Source system.
    pub source: String,
    /// Raw data from the source.
    pub raw_data: HashMap<String, serde_json::Value>,
}

/// Type of indicator of compromise.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IocType {
    IpAddress,
    Domain,
    Url,
    FileHash,
    Email,
    FileName,
    Registry,
    Process,
}

/// An indicator of compromise.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ioc {
    /// The IOC type.
    pub ioc_type: IocType,
    /// The IOC value.
    pub value: String,
}

/// Result of enriching an IOC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichmentResult {
    /// The original IOC.
    pub ioc: Ioc,
    /// Whether the IOC was found in the source.
    pub found: bool,
    /// Risk score (0-100).
    pub risk_score: Option<u8>,
    /// Enrichment data.
    pub data: HashMap<String, serde_json::Value>,
    /// Source of the enrichment.
    pub source: String,
    /// Timestamp of the enrichment.
    pub enriched_at: DateTime<Utc>,
}

/// Type of response action.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionType {
    IsolateHost,
    BlockIp,
    BlockDomain,
    BlockHash,
    DisableUser,
    QuarantineEmail,
    CreateTicket,
    Custom(String),
}

/// A response action to execute.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    /// Action type.
    pub action_type: ActionType,
    /// Target of the action.
    pub target: String,
    /// Reason for the action.
    pub reason: String,
    /// Additional parameters.
    pub parameters: HashMap<String, serde_json::Value>,
}

/// Result of a connection test.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionTestResult {
    /// Whether the connection succeeded.
    pub success: bool,
    /// Response time in milliseconds.
    pub response_time_ms: u64,
    /// Version or info about the connected system.
    pub system_info: Option<String>,
    /// Error message if connection failed.
    pub error: Option<String>,
}

/// Trait for connectors that can fetch alerts.
#[async_trait]
pub trait AlertSource: Connector {
    /// Fetches alerts since a given time, with optional limit.
    async fn fetch_alerts(
        &self,
        since: DateTime<Utc>,
        limit: Option<usize>,
    ) -> ConnectorResult<Vec<RawAlert>>;

    /// Acknowledges an alert.
    async fn acknowledge_alert(&self, alert_id: &str) -> ConnectorResult<()>;
}

/// Trait for connectors that can enrich IOCs.
#[async_trait]
pub trait Enricher: Connector {
    /// Returns the IOC types this enricher supports.
    fn supported_ioc_types(&self) -> Vec<IocType>;

    /// Enriches an IOC with additional context.
    async fn enrich(&self, ioc: &Ioc) -> ConnectorResult<EnrichmentResult>;
}

/// Trait for connectors that can execute response actions.
#[async_trait]
pub trait ActionExecutor: Connector {
    /// Returns the action types this executor supports.
    fn supported_actions(&self) -> Vec<ActionType>;

    /// Executes a response action.
    async fn execute_action(&self, action: &Action) -> ConnectorResult<ActionResult>;
}

// ============================================================================
// Identity Provider Types & Traits (3.1.3)
// ============================================================================

/// Identity user information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityUser {
    /// User ID in the identity system.
    pub id: String,
    /// Username / login.
    pub username: String,
    /// Email address.
    pub email: Option<String>,
    /// Display name.
    pub display_name: Option<String>,
    /// Whether the user is active/enabled.
    pub active: bool,
    /// Whether MFA is enabled.
    pub mfa_enabled: Option<bool>,
    /// Last login timestamp.
    pub last_login: Option<DateTime<Utc>>,
    /// User groups/roles.
    pub groups: Vec<String>,
    /// Account status (e.g., "active", "suspended", "locked").
    pub status: String,
    /// Additional attributes.
    pub attributes: HashMap<String, serde_json::Value>,
}

/// Authentication log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthLogEntry {
    /// Log entry ID.
    pub id: String,
    /// Timestamp.
    pub timestamp: DateTime<Utc>,
    /// User who authenticated.
    pub user: String,
    /// Authentication result.
    pub result: String,
    /// Source IP address.
    pub source_ip: Option<String>,
    /// User agent / client info.
    pub client_info: Option<String>,
    /// Authentication factor used.
    pub factor: Option<String>,
    /// Additional details.
    pub details: HashMap<String, serde_json::Value>,
}

/// Identity provider connector.
#[async_trait]
pub trait IdentityConnector: Connector {
    /// Gets a user by username or email.
    async fn get_user(&self, identifier: &str) -> ConnectorResult<IdentityUser>;

    /// Searches for users.
    async fn search_users(&self, query: &str, limit: usize) -> ConnectorResult<Vec<IdentityUser>>;

    /// Gets groups/roles for a user.
    async fn get_user_groups(&self, user_id: &str) -> ConnectorResult<Vec<String>>;

    /// Gets authentication logs for a user.
    async fn get_auth_logs(
        &self,
        user_id: &str,
        timerange: TimeRange,
        limit: usize,
    ) -> ConnectorResult<Vec<AuthLogEntry>>;

    /// Suspends a user account.
    async fn suspend_user(&self, user_id: &str) -> ConnectorResult<ActionResult>;

    /// Re-enables a previously suspended/blocked user account.
    async fn unsuspend_user(&self, user_id: &str) -> ConnectorResult<ActionResult>;

    /// Resets MFA for a user.
    async fn reset_mfa(&self, user_id: &str) -> ConnectorResult<ActionResult>;

    /// Revokes all active sessions for a user.
    async fn revoke_sessions(&self, user_id: &str) -> ConnectorResult<ActionResult>;
}

// ============================================================================
// Network Security Types & Traits (3.1.4)
// ============================================================================

/// Network security event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEvent {
    /// Event ID.
    pub id: String,
    /// Event timestamp.
    pub timestamp: DateTime<Utc>,
    /// Event type/category.
    pub event_type: String,
    /// Severity level.
    pub severity: String,
    /// Source IP.
    pub source_ip: Option<String>,
    /// Destination IP.
    pub destination_ip: Option<String>,
    /// Source port.
    pub source_port: Option<u16>,
    /// Destination port.
    pub destination_port: Option<u16>,
    /// Protocol.
    pub protocol: Option<String>,
    /// Action taken (allow, block, etc.).
    pub action: String,
    /// Rule or policy that matched.
    pub rule: Option<String>,
    /// Additional details.
    pub details: HashMap<String, serde_json::Value>,
}

/// Network security connector.
#[async_trait]
pub trait NetworkSecurityConnector: Connector {
    /// Gets security events.
    async fn get_events(
        &self,
        timerange: TimeRange,
        limit: usize,
    ) -> ConnectorResult<Vec<NetworkEvent>>;

    /// Blocks an IP address.
    async fn block_ip(&self, ip: &str, reason: &str) -> ConnectorResult<ActionResult>;

    /// Blocks a domain.
    async fn block_domain(&self, domain: &str, reason: &str) -> ConnectorResult<ActionResult>;

    /// Gets traffic logs for a specific IP or host.
    async fn get_traffic_logs(
        &self,
        target: &str,
        timerange: TimeRange,
        limit: usize,
    ) -> ConnectorResult<Vec<NetworkEvent>>;
}

// ============================================================================
// ITSM Types & Traits (3.1.7)
// ============================================================================

/// ITSM incident.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ITSMIncident {
    /// Incident ID.
    pub id: String,
    /// Short description / title.
    pub title: String,
    /// Full description.
    pub description: String,
    /// Severity/priority.
    pub severity: String,
    /// Current state/status.
    pub state: String,
    /// Assigned to.
    pub assigned_to: Option<String>,
    /// Assigned group.
    pub assignment_group: Option<String>,
    /// Created timestamp.
    pub created_at: DateTime<Utc>,
    /// Updated timestamp.
    pub updated_at: DateTime<Utc>,
    /// URL to the incident.
    pub url: Option<String>,
    /// Additional fields.
    pub fields: HashMap<String, serde_json::Value>,
}

/// On-call information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnCallInfo {
    /// User on call.
    pub user: String,
    /// Team or schedule name.
    pub schedule: String,
    /// Start of on-call period.
    pub start: DateTime<Utc>,
    /// End of on-call period.
    pub end: DateTime<Utc>,
}

/// CMDB asset information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CMDBAsset {
    /// Asset ID.
    pub id: String,
    /// Asset name.
    pub name: String,
    /// Asset class/type.
    pub asset_class: String,
    /// Owner.
    pub owner: Option<String>,
    /// Environment (prod, staging, dev).
    pub environment: Option<String>,
    /// Criticality level.
    pub criticality: Option<String>,
    /// Additional attributes.
    pub attributes: HashMap<String, serde_json::Value>,
}

/// ITSM / Case management connector.
#[async_trait]
pub trait ITSMConnector: Connector {
    /// Creates a new incident.
    async fn create_incident(
        &self,
        title: &str,
        description: &str,
        severity: &str,
    ) -> ConnectorResult<ITSMIncident>;

    /// Gets an incident by ID.
    async fn get_incident(&self, incident_id: &str) -> ConnectorResult<ITSMIncident>;

    /// Updates an incident.
    async fn update_incident(
        &self,
        incident_id: &str,
        updates: HashMap<String, serde_json::Value>,
    ) -> ConnectorResult<ITSMIncident>;

    /// Gets who is currently on call.
    async fn get_on_call(&self, schedule: &str) -> ConnectorResult<Vec<OnCallInfo>>;

    /// Gets an asset from the CMDB by name or identifier.
    async fn get_asset_from_cmdb(&self, identifier: &str) -> ConnectorResult<Option<CMDBAsset>>;
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_create_ticket_request() {
        let request = CreateTicketRequest {
            title: "Security Incident".to_string(),
            description: "Malware detected".to_string(),
            ticket_type: "incident".to_string(),
            priority: TicketPriority::High,
            labels: vec!["security".to_string(), "malware".to_string()],
            assignee: Some("analyst@company.com".to_string()),
            custom_fields: HashMap::new(),
        };

        assert_eq!(request.priority, TicketPriority::High);
        assert_eq!(request.labels.len(), 2);
    }
}
