//! Incident data models for Triage Warden.
//!
//! This module defines the core data structures used throughout the system
//! to represent security incidents, alerts, enrichments, and proposed actions.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Represents a security incident being triaged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    /// Unique identifier for this incident.
    pub id: Uuid,
    /// Tenant that owns this incident (multi-tenancy support).
    pub tenant_id: Uuid,
    /// Source system that generated the alert.
    pub source: AlertSource,
    /// Severity level of the incident.
    pub severity: Severity,
    /// Current status of the incident.
    pub status: IncidentStatus,
    /// Raw alert data from the source system.
    pub alert_data: serde_json::Value,
    /// Enrichments gathered during triage.
    pub enrichments: Vec<Enrichment>,
    /// AI analysis results.
    pub analysis: Option<TriageAnalysis>,
    /// Actions proposed by the AI or playbook.
    pub proposed_actions: Vec<ProposedAction>,
    /// Audit log of all actions taken on this incident.
    pub audit_log: Vec<AuditEntry>,
    /// Timestamp when the incident was created.
    pub created_at: DateTime<Utc>,
    /// Timestamp of the last update.
    pub updated_at: DateTime<Utc>,
    /// Associated ticket ID if one exists.
    pub ticket_id: Option<String>,
    /// Tags for categorization.
    pub tags: Vec<String>,
    /// Custom metadata.
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Default tenant ID for backward compatibility.
/// This is used when no tenant is specified or for single-tenant deployments.
pub const DEFAULT_TENANT_ID: Uuid = Uuid::from_u128(0x00000000_0000_0000_0000_000000000001);

impl Incident {
    /// Creates a new incident from an alert with the specified tenant.
    pub fn from_alert_with_tenant(alert: Alert, tenant_id: Uuid) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            tenant_id,
            source: alert.source,
            severity: alert.severity,
            status: IncidentStatus::New,
            alert_data: alert.data,
            enrichments: Vec::new(),
            analysis: None,
            proposed_actions: Vec::new(),
            audit_log: vec![AuditEntry::new(
                AuditAction::IncidentCreated,
                "system".to_string(),
                None,
            )],
            created_at: now,
            updated_at: now,
            ticket_id: None,
            tags: alert.tags,
            metadata: HashMap::new(),
        }
    }

    /// Creates a new incident from an alert using the default tenant.
    /// This is provided for backward compatibility with single-tenant deployments.
    pub fn from_alert(alert: Alert) -> Self {
        Self::from_alert_with_tenant(alert, DEFAULT_TENANT_ID)
    }

    /// Adds an enrichment to the incident.
    pub fn add_enrichment(&mut self, enrichment: Enrichment) {
        self.enrichments.push(enrichment);
        self.updated_at = Utc::now();
        self.audit_log.push(AuditEntry::new(
            AuditAction::EnrichmentAdded,
            "system".to_string(),
            None,
        ));
    }

    /// Sets the triage analysis.
    pub fn set_analysis(&mut self, analysis: TriageAnalysis) {
        self.analysis = Some(analysis);
        self.updated_at = Utc::now();
        self.audit_log.push(AuditEntry::new(
            AuditAction::AnalysisCompleted,
            "ai".to_string(),
            None,
        ));
    }

    /// Adds a proposed action.
    pub fn add_proposed_action(&mut self, action: ProposedAction) {
        self.proposed_actions.push(action);
        self.updated_at = Utc::now();
    }

    /// Updates the incident status.
    pub fn update_status(&mut self, status: IncidentStatus, actor: &str) {
        self.status = status.clone();
        self.updated_at = Utc::now();
        self.audit_log.push(AuditEntry::new(
            AuditAction::StatusChanged(status),
            actor.to_string(),
            None,
        ));
    }
}

/// Represents an incoming alert from a security system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    /// Unique identifier for this alert.
    pub id: String,
    /// Source system that generated the alert.
    pub source: AlertSource,
    /// Alert type/category.
    pub alert_type: String,
    /// Severity level.
    pub severity: Severity,
    /// Alert title/summary.
    pub title: String,
    /// Alert description.
    pub description: Option<String>,
    /// Raw alert data.
    pub data: serde_json::Value,
    /// Timestamp when the alert was generated.
    pub timestamp: DateTime<Utc>,
    /// Tags for categorization.
    pub tags: Vec<String>,
}

/// Source systems that can generate alerts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AlertSource {
    /// SIEM alert (Splunk, Elastic, etc.)
    Siem(String),
    /// EDR alert (CrowdStrike, Defender, etc.)
    Edr(String),
    /// Email security gateway
    EmailSecurity(String),
    /// Identity provider (Okta, Azure AD, etc.)
    IdentityProvider(String),
    /// Cloud security (AWS GuardDuty, Azure Sentinel, etc.)
    CloudSecurity(String),
    /// User reported (phishing button, etc.)
    UserReported,
    /// Custom source
    Custom(String),
}

impl std::fmt::Display for AlertSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertSource::Siem(name) => write!(f, "SIEM:{}", name),
            AlertSource::Edr(name) => write!(f, "EDR:{}", name),
            AlertSource::EmailSecurity(name) => write!(f, "Email:{}", name),
            AlertSource::IdentityProvider(name) => write!(f, "IdP:{}", name),
            AlertSource::CloudSecurity(name) => write!(f, "Cloud:{}", name),
            AlertSource::UserReported => write!(f, "UserReported"),
            AlertSource::Custom(name) => write!(f, "Custom:{}", name),
        }
    }
}

/// Severity levels for incidents.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational - no immediate action required
    Info,
    /// Low severity
    Low,
    /// Medium severity
    Medium,
    /// High severity - requires attention
    High,
    /// Critical - immediate response required
    Critical,
}

impl Severity {
    /// Returns the database-compatible string representation (lowercase).
    pub fn as_db_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "Info"),
            Severity::Low => write!(f, "Low"),
            Severity::Medium => write!(f, "Medium"),
            Severity::High => write!(f, "High"),
            Severity::Critical => write!(f, "Critical"),
        }
    }
}

/// Status of an incident in the triage workflow.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum IncidentStatus {
    /// Newly created, not yet triaged
    New,
    /// Currently being enriched with additional data
    Enriching,
    /// Being analyzed by AI
    Analyzing,
    /// Waiting for analyst review
    PendingReview,
    /// Actions awaiting approval
    PendingApproval,
    /// Actions being executed
    Executing,
    /// Confirmed as true positive, resolved
    Resolved,
    /// Confirmed as false positive
    FalsePositive,
    /// Dismissed by analyst (not requiring action)
    Dismissed,
    /// Escalated to higher tier
    Escalated,
    /// Closed without action
    Closed,
}

impl IncidentStatus {
    /// Returns the database-compatible string representation (snake_case).
    pub fn as_db_str(&self) -> &'static str {
        match self {
            IncidentStatus::New => "new",
            IncidentStatus::Enriching => "enriching",
            IncidentStatus::Analyzing => "analyzing",
            IncidentStatus::PendingReview => "pending_review",
            IncidentStatus::PendingApproval => "pending_approval",
            IncidentStatus::Executing => "executing",
            IncidentStatus::Resolved => "resolved",
            IncidentStatus::FalsePositive => "false_positive",
            IncidentStatus::Dismissed => "dismissed",
            IncidentStatus::Escalated => "escalated",
            IncidentStatus::Closed => "closed",
        }
    }
}

impl std::fmt::Display for IncidentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IncidentStatus::New => write!(f, "New"),
            IncidentStatus::Enriching => write!(f, "Enriching"),
            IncidentStatus::Analyzing => write!(f, "Analyzing"),
            IncidentStatus::PendingReview => write!(f, "Pending Review"),
            IncidentStatus::PendingApproval => write!(f, "Pending Approval"),
            IncidentStatus::Executing => write!(f, "Executing"),
            IncidentStatus::Resolved => write!(f, "Resolved"),
            IncidentStatus::FalsePositive => write!(f, "False Positive"),
            IncidentStatus::Dismissed => write!(f, "Dismissed"),
            IncidentStatus::Escalated => write!(f, "Escalated"),
            IncidentStatus::Closed => write!(f, "Closed"),
        }
    }
}

/// Enrichment data gathered during triage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Enrichment {
    /// Type of enrichment.
    pub enrichment_type: EnrichmentType,
    /// Source of the enrichment data.
    pub source: String,
    /// Enrichment data.
    pub data: serde_json::Value,
    /// Timestamp when gathered.
    pub timestamp: DateTime<Utc>,
    /// Time-to-live for caching purposes.
    pub ttl_seconds: Option<u64>,
}

/// Types of enrichments that can be gathered.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EnrichmentType {
    /// Threat intelligence lookup (hash, IP, domain)
    ThreatIntel,
    /// Host information from EDR
    HostInfo,
    /// User information from identity provider
    UserInfo,
    /// SIEM search results
    SiemSearch,
    /// Email header analysis
    EmailAnalysis,
    /// Geolocation data
    GeoLocation,
    /// WHOIS data
    Whois,
    /// MITRE ATT&CK mapping
    MitreMapping,
    /// Historical incident correlation
    HistoricalCorrelation,
    /// Custom enrichment
    Custom(String),
}

/// AI-generated triage analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageAnalysis {
    /// Assessment of whether this is a true positive.
    pub verdict: TriageVerdict,
    /// Raw confidence score from the AI (0.0 - 1.0).
    pub confidence: f64,
    /// Calibrated confidence score (0.0 - 1.0) (Stage 2.2.4).
    ///
    /// This value represents the expected accuracy based on historical feedback.
    /// When the calibrated confidence is 0.9, it means the AI is correct ~90%
    /// of the time at this confidence level.
    ///
    /// If None, calibration has not been applied (use raw confidence).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calibrated_confidence: Option<f64>,
    /// Summary of the analysis.
    pub summary: String,
    /// Detailed reasoning.
    pub reasoning: String,
    /// MITRE ATT&CK techniques identified.
    pub mitre_techniques: Vec<MitreTechnique>,
    /// Indicators of Compromise found.
    pub iocs: Vec<IoC>,
    /// Recommended actions.
    pub recommendations: Vec<String>,
    /// Risk score (0 - 100).
    pub risk_score: u8,
    /// Model/agent that performed the analysis.
    pub analyzed_by: String,
    /// Timestamp of analysis.
    pub timestamp: DateTime<Utc>,
    /// Evidence supporting the verdict (Stage 2.1.1).
    #[serde(default)]
    pub evidence: Vec<Evidence>,
    /// Steps taken during the investigation (Stage 2.1.1).
    #[serde(default)]
    pub investigation_steps: Vec<InvestigationStep>,
}

impl TriageAnalysis {
    /// Returns the effective confidence score for decision-making.
    ///
    /// Uses calibrated confidence if available, otherwise falls back to raw confidence.
    /// This should be used for workflow decisions and threshold comparisons.
    pub fn effective_confidence(&self) -> f64 {
        self.calibrated_confidence.unwrap_or(self.confidence)
    }

    /// Returns whether this analysis has been calibrated.
    pub fn is_calibrated(&self) -> bool {
        self.calibrated_confidence.is_some()
    }

    /// Applies calibration to this analysis using a calibration model.
    ///
    /// # Arguments
    ///
    /// * `calibrated_value` - The calibrated confidence value to set
    pub fn apply_calibration(&mut self, calibrated_value: f64) {
        self.calibrated_confidence = Some(calibrated_value.clamp(0.0, 1.0));
    }

    /// Clears the calibrated confidence, reverting to raw confidence.
    pub fn clear_calibration(&mut self) {
        self.calibrated_confidence = None;
    }
}

/// Verdict from triage analysis.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TriageVerdict {
    /// Confirmed malicious activity
    TruePositive,
    /// Likely malicious, needs confirmation
    LikelyTruePositive,
    /// Suspicious, requires investigation
    Suspicious,
    /// Likely benign
    LikelyFalsePositive,
    /// Confirmed benign
    FalsePositive,
    /// Unable to determine
    Inconclusive,
}

/// MITRE ATT&CK technique reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreTechnique {
    /// Technique ID (e.g., T1566.001)
    pub id: String,
    /// Technique name
    pub name: String,
    /// Tactic (e.g., Initial Access)
    pub tactic: String,
    /// Confidence in this mapping
    pub confidence: f64,
}

/// Indicator of Compromise.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoC {
    /// Type of IoC
    pub ioc_type: IoCType,
    /// Value of the IoC
    pub value: String,
    /// Context/description
    pub context: Option<String>,
    /// Maliciousness score (0.0 - 1.0)
    pub score: Option<f64>,
}

/// Types of Indicators of Compromise.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IoCType {
    Ipv4,
    Ipv6,
    Domain,
    Url,
    Md5,
    Sha1,
    Sha256,
    Email,
    FileName,
    FilePath,
    RegistryKey,
    Process,
    Other(String),
}

// ============================================================================
// Evidence Model (Stage 2.1.1)
// ============================================================================

/// A piece of evidence supporting the triage analysis verdict.
///
/// Evidence represents a specific data point that was examined during analysis
/// and contributed to the final verdict. Each piece of evidence includes its
/// source, type, value, and an explanation of its relevance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    /// Unique identifier for this evidence item.
    pub id: Uuid,
    /// Source of the evidence data.
    pub source: EvidenceSource,
    /// Type of data this evidence represents.
    pub data_type: EvidenceType,
    /// The actual evidence value/data.
    pub value: serde_json::Value,
    /// Explanation of why this evidence is relevant to the verdict.
    pub relevance: String,
    /// Confidence in this specific piece of evidence (0.0 - 1.0).
    pub confidence: f64,
    /// Optional deep link to view this evidence in its source system.
    pub link: Option<String>,
    /// Timestamp when this evidence was collected.
    pub collected_at: DateTime<Utc>,
}

impl Evidence {
    /// Creates a new evidence item.
    pub fn new(
        source: EvidenceSource,
        data_type: EvidenceType,
        value: serde_json::Value,
        relevance: String,
        confidence: f64,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            source,
            data_type,
            value,
            relevance,
            confidence,
            link: None,
            collected_at: Utc::now(),
        }
    }

    /// Sets a deep link to the source system.
    pub fn with_link(mut self, link: String) -> Self {
        self.link = Some(link);
        self
    }
}

/// Source of evidence data.
///
/// Tracks where evidence came from for audit and verification purposes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EvidenceSource {
    /// Evidence from a SIEM query (Splunk, Elastic, etc.)
    Siem {
        /// Name of the SIEM platform.
        platform: String,
        /// Query that produced this evidence.
        query: String,
        /// When the query was executed.
        timestamp: DateTime<Utc>,
    },
    /// Evidence from an EDR platform (CrowdStrike, Defender, etc.)
    Edr {
        /// Name of the EDR platform.
        platform: String,
        /// Detection ID or event ID.
        detection_id: String,
    },
    /// Evidence from threat intelligence (VirusTotal, etc.)
    ThreatIntel {
        /// Name of the TI provider.
        provider: String,
        /// Hash, IP, domain, or URL that was looked up.
        indicator: String,
        /// When the lookup was performed.
        lookup_date: DateTime<Utc>,
    },
    /// Evidence from email headers or email security gateway.
    Email {
        /// Message ID from headers.
        message_id: String,
        /// Email gateway or provider name.
        gateway: Option<String>,
    },
    /// Evidence from identity provider (Okta, Azure AD, etc.)
    IdentityProvider {
        /// Name of the IdP.
        provider: String,
        /// User or session ID referenced.
        reference_id: String,
    },
    /// Evidence from cloud security (AWS GuardDuty, Azure Sentinel, etc.)
    CloudSecurity {
        /// Cloud provider name.
        provider: String,
        /// Finding or alert ID.
        finding_id: String,
        /// Region where the finding originated.
        region: Option<String>,
    },
    /// Evidence from alert enrichments gathered during triage.
    Enrichment {
        /// Type of enrichment that provided this evidence.
        enrichment_type: String,
        /// Source name from the enrichment.
        source: String,
    },
    /// Evidence added manually by an analyst.
    Manual {
        /// ID of the analyst who added this evidence.
        analyst_id: String,
        /// Name of the analyst for display.
        analyst_name: Option<String>,
    },
    /// Evidence from a custom or unknown source.
    Custom {
        /// Source identifier.
        source_name: String,
        /// Additional metadata about the source.
        metadata: Option<serde_json::Value>,
    },
}

impl std::fmt::Display for EvidenceSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvidenceSource::Siem { platform, .. } => write!(f, "SIEM:{}", platform),
            EvidenceSource::Edr { platform, .. } => write!(f, "EDR:{}", platform),
            EvidenceSource::ThreatIntel { provider, .. } => write!(f, "ThreatIntel:{}", provider),
            EvidenceSource::Email { gateway, .. } => {
                write!(f, "Email:{}", gateway.as_deref().unwrap_or("headers"))
            }
            EvidenceSource::IdentityProvider { provider, .. } => write!(f, "IdP:{}", provider),
            EvidenceSource::CloudSecurity { provider, .. } => write!(f, "Cloud:{}", provider),
            EvidenceSource::Enrichment { source, .. } => write!(f, "Enrichment:{}", source),
            EvidenceSource::Manual { analyst_id, .. } => write!(f, "Manual:{}", analyst_id),
            EvidenceSource::Custom { source_name, .. } => write!(f, "Custom:{}", source_name),
        }
    }
}

/// Type of evidence data.
///
/// Categorizes what kind of information the evidence represents.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceType {
    /// Network-related evidence (IP, port, connection).
    NetworkActivity,
    /// File or hash-related evidence.
    FileArtifact,
    /// Process execution evidence.
    ProcessExecution,
    /// User behavior or authentication evidence.
    UserBehavior,
    /// Email content or header evidence.
    EmailContent,
    /// Threat intelligence match.
    ThreatIntelMatch,
    /// MITRE ATT&CK technique observation.
    MitreObservation,
    /// Registry or system configuration change.
    SystemChange,
    /// DNS or domain-related evidence.
    DnsActivity,
    /// URL or web traffic evidence.
    WebActivity,
    /// Cloud resource or API activity.
    CloudActivity,
    /// Authentication or identity evidence.
    AuthenticationEvent,
    /// Data exfiltration or sensitive data access.
    DataAccess,
    /// Malware signature or behavioral match.
    MalwareIndicator,
    /// Custom evidence type.
    Custom(String),
}

impl std::fmt::Display for EvidenceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvidenceType::NetworkActivity => write!(f, "Network Activity"),
            EvidenceType::FileArtifact => write!(f, "File Artifact"),
            EvidenceType::ProcessExecution => write!(f, "Process Execution"),
            EvidenceType::UserBehavior => write!(f, "User Behavior"),
            EvidenceType::EmailContent => write!(f, "Email Content"),
            EvidenceType::ThreatIntelMatch => write!(f, "Threat Intel Match"),
            EvidenceType::MitreObservation => write!(f, "MITRE Observation"),
            EvidenceType::SystemChange => write!(f, "System Change"),
            EvidenceType::DnsActivity => write!(f, "DNS Activity"),
            EvidenceType::WebActivity => write!(f, "Web Activity"),
            EvidenceType::CloudActivity => write!(f, "Cloud Activity"),
            EvidenceType::AuthenticationEvent => write!(f, "Authentication Event"),
            EvidenceType::DataAccess => write!(f, "Data Access"),
            EvidenceType::MalwareIndicator => write!(f, "Malware Indicator"),
            EvidenceType::Custom(name) => write!(f, "Custom: {}", name),
        }
    }
}

/// A step in the investigation process.
///
/// Investigation steps document what actions were taken during the analysis,
/// in what order, and what the result of each action was. This provides
/// an audit trail and helps analysts understand how the verdict was reached.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigationStep {
    /// Unique identifier for this step.
    pub id: Uuid,
    /// Order of this step in the investigation (1-indexed).
    pub order: u32,
    /// Description of the action taken.
    pub action: String,
    /// Result or output of this step.
    pub result: String,
    /// Status of this step.
    pub status: InvestigationStepStatus,
    /// Optional tool or system used for this step.
    pub tool: Option<String>,
    /// Optional reference to evidence IDs gathered in this step.
    pub evidence_ids: Vec<Uuid>,
    /// Timestamp when this step was executed.
    pub timestamp: DateTime<Utc>,
    /// Duration of this step in milliseconds.
    pub duration_ms: Option<u64>,
}

impl InvestigationStep {
    /// Creates a new investigation step.
    pub fn new(order: u32, action: String, result: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            order,
            action,
            result,
            status: InvestigationStepStatus::Completed,
            tool: None,
            evidence_ids: Vec::new(),
            timestamp: Utc::now(),
            duration_ms: None,
        }
    }

    /// Sets the tool used for this step.
    pub fn with_tool(mut self, tool: String) -> Self {
        self.tool = Some(tool);
        self
    }

    /// Sets the status of this step.
    pub fn with_status(mut self, status: InvestigationStepStatus) -> Self {
        self.status = status;
        self
    }

    /// Links evidence items to this step.
    pub fn with_evidence(mut self, evidence_ids: Vec<Uuid>) -> Self {
        self.evidence_ids = evidence_ids;
        self
    }

    /// Sets the duration of this step.
    pub fn with_duration(mut self, duration_ms: u64) -> Self {
        self.duration_ms = Some(duration_ms);
        self
    }
}

/// Status of an investigation step.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InvestigationStepStatus {
    /// Step completed successfully.
    Completed,
    /// Step failed or errored.
    Failed,
    /// Step was skipped (e.g., data not available).
    Skipped,
    /// Step is still in progress.
    InProgress,
}

/// A proposed action to be taken on an incident.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposedAction {
    /// Unique identifier for this proposed action.
    pub id: Uuid,
    /// Type of action.
    pub action_type: ActionType,
    /// Target of the action.
    pub target: ActionTarget,
    /// Parameters for the action.
    pub parameters: HashMap<String, serde_json::Value>,
    /// Reason for proposing this action.
    pub reason: String,
    /// Priority (lower = higher priority).
    pub priority: u8,
    /// Current approval status.
    pub approval_status: ApprovalStatus,
    /// Who approved/denied (if applicable).
    pub approved_by: Option<String>,
    /// Timestamp of approval decision.
    pub approval_timestamp: Option<DateTime<Utc>>,
}

impl ProposedAction {
    /// Creates a new proposed action.
    pub fn new(
        action_type: ActionType,
        target: ActionTarget,
        reason: String,
        parameters: HashMap<String, serde_json::Value>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            action_type,
            target,
            parameters,
            reason,
            priority: 50,
            approval_status: ApprovalStatus::Pending,
            approved_by: None,
            approval_timestamp: None,
        }
    }
}

/// Types of actions that can be proposed/executed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ActionType {
    /// Isolate a host from the network
    IsolateHost,
    /// Remove host isolation
    UnisolateHost,
    /// Disable a user account
    DisableUser,
    /// Enable a user account
    EnableUser,
    /// Reset user password
    ResetPassword,
    /// Revoke user sessions
    RevokeSessions,
    /// Block an IP address
    BlockIp,
    /// Unblock an IP address
    UnblockIp,
    /// Block a domain
    BlockDomain,
    /// Quarantine an email
    QuarantineEmail,
    /// Delete an email
    DeleteEmail,
    /// Block a sender
    BlockSender,
    /// Create a ticket
    CreateTicket,
    /// Update a ticket
    UpdateTicket,
    /// Add comment to ticket
    AddTicketComment,
    /// Send notification
    SendNotification,
    /// Run SIEM search
    RunSearch,
    /// Collect forensic data
    CollectForensics,
    /// Custom action
    Custom(String),
}

impl std::fmt::Display for ActionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ActionType::IsolateHost => write!(f, "Isolate Host"),
            ActionType::UnisolateHost => write!(f, "Unisolate Host"),
            ActionType::DisableUser => write!(f, "Disable User"),
            ActionType::EnableUser => write!(f, "Enable User"),
            ActionType::ResetPassword => write!(f, "Reset Password"),
            ActionType::RevokeSessions => write!(f, "Revoke Sessions"),
            ActionType::BlockIp => write!(f, "Block IP"),
            ActionType::UnblockIp => write!(f, "Unblock IP"),
            ActionType::BlockDomain => write!(f, "Block Domain"),
            ActionType::QuarantineEmail => write!(f, "Quarantine Email"),
            ActionType::DeleteEmail => write!(f, "Delete Email"),
            ActionType::BlockSender => write!(f, "Block Sender"),
            ActionType::CreateTicket => write!(f, "Create Ticket"),
            ActionType::UpdateTicket => write!(f, "Update Ticket"),
            ActionType::AddTicketComment => write!(f, "Add Ticket Comment"),
            ActionType::SendNotification => write!(f, "Send Notification"),
            ActionType::RunSearch => write!(f, "Run Search"),
            ActionType::CollectForensics => write!(f, "Collect Forensics"),
            ActionType::Custom(name) => write!(f, "Custom: {}", name),
        }
    }
}

/// Target of an action.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionTarget {
    /// A host/endpoint
    Host {
        hostname: String,
        ip: Option<String>,
    },
    /// A user account
    User {
        username: String,
        email: Option<String>,
    },
    /// An IP address
    IpAddress(String),
    /// A domain
    Domain(String),
    /// An email message
    Email { message_id: String },
    /// A ticket
    Ticket { ticket_id: String },
    /// No specific target
    None,
}

/// Approval status for proposed actions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    /// Awaiting approval
    Pending,
    /// Automatically approved by policy
    AutoApproved,
    /// Manually approved by analyst
    Approved,
    /// Denied
    Denied,
    /// Executed successfully
    Executed,
    /// Execution failed
    Failed,
}

/// Audit log entry for tracking all changes to an incident.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unique identifier for this entry.
    pub id: Uuid,
    /// Action that was performed.
    pub action: AuditAction,
    /// Actor who performed the action.
    pub actor: String,
    /// Additional details.
    pub details: Option<serde_json::Value>,
    /// Timestamp of the action.
    pub timestamp: DateTime<Utc>,
}

impl AuditEntry {
    /// Creates a new audit entry.
    pub fn new(action: AuditAction, actor: String, details: Option<serde_json::Value>) -> Self {
        Self {
            id: Uuid::new_v4(),
            action,
            actor,
            details,
            timestamp: Utc::now(),
        }
    }
}

/// Actions that are logged to the audit trail.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    /// Incident was created
    IncidentCreated,
    /// Status was changed
    StatusChanged(IncidentStatus),
    /// Enrichment was added
    EnrichmentAdded,
    /// Analysis was completed
    AnalysisCompleted,
    /// Action was proposed
    ActionProposed,
    /// Action was approved
    ActionApproved,
    /// Action was denied
    ActionDenied,
    /// Action was executed
    ActionExecuted,
    /// Action execution failed
    ActionFailed,
    /// Ticket was created
    TicketCreated,
    /// Ticket was updated
    TicketUpdated,
    /// Comment was added
    CommentAdded,
    /// Incident was escalated
    Escalated,
    /// Incident was closed
    Closed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_incident_creation() {
        let alert = Alert {
            id: "alert-123".to_string(),
            source: AlertSource::EmailSecurity("M365".to_string()),
            alert_type: "phishing".to_string(),
            severity: Severity::High,
            title: "Suspected phishing email".to_string(),
            description: Some("User reported suspicious email".to_string()),
            data: serde_json::json!({"subject": "Urgent: Update your password"}),
            timestamp: Utc::now(),
            tags: vec!["phishing".to_string(), "user-reported".to_string()],
        };

        let incident = Incident::from_alert(alert);
        assert_eq!(incident.status, IncidentStatus::New);
        assert_eq!(incident.severity, Severity::High);
        assert_eq!(incident.enrichments.len(), 0);
        assert_eq!(incident.audit_log.len(), 1);
        assert_eq!(incident.tenant_id, DEFAULT_TENANT_ID);
    }

    #[test]
    fn test_add_enrichment() {
        let alert = Alert {
            id: "alert-123".to_string(),
            source: AlertSource::Siem("Splunk".to_string()),
            alert_type: "malware".to_string(),
            severity: Severity::Critical,
            title: "Malware detected".to_string(),
            description: None,
            data: serde_json::json!({}),
            timestamp: Utc::now(),
            tags: vec![],
        };

        let mut incident = Incident::from_alert(alert);
        let enrichment = Enrichment {
            enrichment_type: EnrichmentType::ThreatIntel,
            source: "VirusTotal".to_string(),
            data: serde_json::json!({"malicious": 45, "total": 70}),
            timestamp: Utc::now(),
            ttl_seconds: Some(3600),
        };

        incident.add_enrichment(enrichment);
        assert_eq!(incident.enrichments.len(), 1);
        assert_eq!(incident.audit_log.len(), 2);
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    // ==========================================================================
    // Evidence Model Tests (Stage 2.1.1)
    // ==========================================================================

    #[test]
    fn test_evidence_creation() {
        let source = EvidenceSource::ThreatIntel {
            provider: "VirusTotal".to_string(),
            indicator: "d41d8cd98f00b204e9800998ecf8427e".to_string(),
            lookup_date: Utc::now(),
        };
        let evidence = Evidence::new(
            source,
            EvidenceType::ThreatIntelMatch,
            serde_json::json!({"malicious": 45, "total": 70}),
            "Hash was flagged by 45/70 engines".to_string(),
            0.95,
        );

        assert!(!evidence.id.is_nil());
        assert_eq!(evidence.confidence, 0.95);
        assert!(evidence.link.is_none());
    }

    #[test]
    fn test_evidence_with_link() {
        let source = EvidenceSource::Siem {
            platform: "Splunk".to_string(),
            query: "index=main sourcetype=firewall".to_string(),
            timestamp: Utc::now(),
        };
        let evidence = Evidence::new(
            source,
            EvidenceType::NetworkActivity,
            serde_json::json!({"src_ip": "192.168.1.100", "dst_ip": "10.0.0.1"}),
            "Suspicious outbound connection to known C2".to_string(),
            0.85,
        )
        .with_link("https://splunk.example.com/search?q=sid=123".to_string());

        assert!(evidence.link.is_some());
        assert!(evidence.link.unwrap().contains("splunk.example.com"));
    }

    #[test]
    fn test_evidence_source_display() {
        let siem = EvidenceSource::Siem {
            platform: "Splunk".to_string(),
            query: "test".to_string(),
            timestamp: Utc::now(),
        };
        assert_eq!(format!("{}", siem), "SIEM:Splunk");

        let edr = EvidenceSource::Edr {
            platform: "CrowdStrike".to_string(),
            detection_id: "det-123".to_string(),
        };
        assert_eq!(format!("{}", edr), "EDR:CrowdStrike");

        let ti = EvidenceSource::ThreatIntel {
            provider: "VirusTotal".to_string(),
            indicator: "hash".to_string(),
            lookup_date: Utc::now(),
        };
        assert_eq!(format!("{}", ti), "ThreatIntel:VirusTotal");

        let email = EvidenceSource::Email {
            message_id: "msg-123".to_string(),
            gateway: Some("Proofpoint".to_string()),
        };
        assert_eq!(format!("{}", email), "Email:Proofpoint");

        let email_no_gateway = EvidenceSource::Email {
            message_id: "msg-456".to_string(),
            gateway: None,
        };
        assert_eq!(format!("{}", email_no_gateway), "Email:headers");

        let manual = EvidenceSource::Manual {
            analyst_id: "analyst-001".to_string(),
            analyst_name: Some("John Doe".to_string()),
        };
        assert_eq!(format!("{}", manual), "Manual:analyst-001");
    }

    #[test]
    fn test_evidence_type_display() {
        assert_eq!(
            format!("{}", EvidenceType::NetworkActivity),
            "Network Activity"
        );
        assert_eq!(format!("{}", EvidenceType::FileArtifact), "File Artifact");
        assert_eq!(
            format!("{}", EvidenceType::ThreatIntelMatch),
            "Threat Intel Match"
        );
        assert_eq!(
            format!("{}", EvidenceType::Custom("DNS Tunnel".to_string())),
            "Custom: DNS Tunnel"
        );
    }

    #[test]
    fn test_evidence_source_equality() {
        use chrono::Duration;

        let now = Utc::now();
        let source1 = EvidenceSource::ThreatIntel {
            provider: "VirusTotal".to_string(),
            indicator: "hash123".to_string(),
            lookup_date: now,
        };
        let source2 = EvidenceSource::ThreatIntel {
            provider: "VirusTotal".to_string(),
            indicator: "hash123".to_string(),
            lookup_date: now + Duration::seconds(1), // Different timestamp
        };
        // PartialEq compares all fields including timestamp
        assert_ne!(source1, source2); // Different timestamps

        // Same timestamps should be equal
        let source1b = EvidenceSource::ThreatIntel {
            provider: "VirusTotal".to_string(),
            indicator: "hash123".to_string(),
            lookup_date: now,
        };
        assert_eq!(source1, source1b); // Same data including timestamp

        let source3 = EvidenceSource::Edr {
            platform: "CrowdStrike".to_string(),
            detection_id: "det-1".to_string(),
        };
        let source4 = EvidenceSource::Edr {
            platform: "CrowdStrike".to_string(),
            detection_id: "det-1".to_string(),
        };
        assert_eq!(source3, source4);
    }

    #[test]
    fn test_investigation_step_creation() {
        let step = InvestigationStep::new(
            1,
            "Query SIEM for related events".to_string(),
            "Found 15 related events in the last 24 hours".to_string(),
        );

        assert!(!step.id.is_nil());
        assert_eq!(step.order, 1);
        assert_eq!(step.status, InvestigationStepStatus::Completed);
        assert!(step.tool.is_none());
        assert!(step.evidence_ids.is_empty());
        assert!(step.duration_ms.is_none());
    }

    #[test]
    fn test_investigation_step_builder_pattern() {
        let evidence_id = Uuid::new_v4();
        let step = InvestigationStep::new(
            2,
            "Lookup hash in threat intelligence".to_string(),
            "Hash identified as Emotet trojan".to_string(),
        )
        .with_tool("VirusTotal API".to_string())
        .with_status(InvestigationStepStatus::Completed)
        .with_evidence(vec![evidence_id])
        .with_duration(1500);

        assert_eq!(step.order, 2);
        assert_eq!(step.tool, Some("VirusTotal API".to_string()));
        assert_eq!(step.status, InvestigationStepStatus::Completed);
        assert_eq!(step.evidence_ids.len(), 1);
        assert_eq!(step.evidence_ids[0], evidence_id);
        assert_eq!(step.duration_ms, Some(1500));
    }

    #[test]
    fn test_investigation_step_status() {
        let completed = InvestigationStep::new(1, "Action".to_string(), "Result".to_string())
            .with_status(InvestigationStepStatus::Completed);
        assert_eq!(completed.status, InvestigationStepStatus::Completed);

        let failed = InvestigationStep::new(2, "Action".to_string(), "Error".to_string())
            .with_status(InvestigationStepStatus::Failed);
        assert_eq!(failed.status, InvestigationStepStatus::Failed);

        let skipped = InvestigationStep::new(3, "Action".to_string(), "N/A".to_string())
            .with_status(InvestigationStepStatus::Skipped);
        assert_eq!(skipped.status, InvestigationStepStatus::Skipped);
    }

    #[test]
    fn test_triage_analysis_with_evidence() {
        let evidence = Evidence::new(
            EvidenceSource::ThreatIntel {
                provider: "VirusTotal".to_string(),
                indicator: "malware.exe".to_string(),
                lookup_date: Utc::now(),
            },
            EvidenceType::MalwareIndicator,
            serde_json::json!({"detection_rate": "95%"}),
            "File identified as known malware".to_string(),
            0.95,
        );

        let step = InvestigationStep::new(
            1,
            "Analyzed file hash".to_string(),
            "Malware confirmed".to_string(),
        )
        .with_evidence(vec![evidence.id]);

        let analysis = TriageAnalysis {
            verdict: TriageVerdict::TruePositive,
            confidence: 0.95,
            calibrated_confidence: None,
            summary: "Confirmed malware infection".to_string(),
            reasoning: "File hash matched known malware signature".to_string(),
            mitre_techniques: vec![],
            iocs: vec![],
            recommendations: vec!["Isolate host".to_string()],
            risk_score: 90,
            analyzed_by: "AI Agent v1".to_string(),
            timestamp: Utc::now(),
            evidence: vec![evidence],
            investigation_steps: vec![step],
        };

        assert_eq!(analysis.evidence.len(), 1);
        assert_eq!(analysis.investigation_steps.len(), 1);
        assert_eq!(analysis.investigation_steps[0].evidence_ids.len(), 1);
    }

    #[test]
    fn test_evidence_serialization() {
        let source = EvidenceSource::Siem {
            platform: "Splunk".to_string(),
            query: "index=main".to_string(),
            timestamp: Utc::now(),
        };
        let evidence = Evidence::new(
            source,
            EvidenceType::NetworkActivity,
            serde_json::json!({"ip": "10.0.0.1"}),
            "Suspicious connection".to_string(),
            0.8,
        );

        let json = serde_json::to_string(&evidence).unwrap();
        assert!(json.contains("\"type\":\"siem\""));
        assert!(json.contains("\"platform\":\"Splunk\""));
        assert!(json.contains("\"data_type\":\"network_activity\""));

        // Deserialize back
        let deserialized: Evidence = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, evidence.id);
        assert_eq!(deserialized.confidence, 0.8);
    }

    #[test]
    fn test_investigation_step_serialization() {
        let step = InvestigationStep::new(1, "Test action".to_string(), "Test result".to_string())
            .with_tool("TestTool".to_string())
            .with_duration(500);

        let json = serde_json::to_string(&step).unwrap();
        assert!(json.contains("\"order\":1"));
        assert!(json.contains("\"status\":\"completed\""));
        assert!(json.contains("\"tool\":\"TestTool\""));
        assert!(json.contains("\"duration_ms\":500"));

        let deserialized: InvestigationStep = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, step.id);
        assert_eq!(deserialized.order, 1);
        assert_eq!(deserialized.status, InvestigationStepStatus::Completed);
    }

    #[test]
    fn test_all_evidence_source_variants() {
        // Test all EvidenceSource variants serialize correctly
        let sources = vec![
            EvidenceSource::Siem {
                platform: "Splunk".to_string(),
                query: "test".to_string(),
                timestamp: Utc::now(),
            },
            EvidenceSource::Edr {
                platform: "CrowdStrike".to_string(),
                detection_id: "det-1".to_string(),
            },
            EvidenceSource::ThreatIntel {
                provider: "VT".to_string(),
                indicator: "hash".to_string(),
                lookup_date: Utc::now(),
            },
            EvidenceSource::Email {
                message_id: "msg-1".to_string(),
                gateway: Some("Proofpoint".to_string()),
            },
            EvidenceSource::IdentityProvider {
                provider: "Okta".to_string(),
                reference_id: "session-1".to_string(),
            },
            EvidenceSource::CloudSecurity {
                provider: "AWS".to_string(),
                finding_id: "finding-1".to_string(),
                region: Some("us-east-1".to_string()),
            },
            EvidenceSource::Enrichment {
                enrichment_type: "threat_intel".to_string(),
                source: "VT".to_string(),
            },
            EvidenceSource::Manual {
                analyst_id: "analyst-1".to_string(),
                analyst_name: Some("John".to_string()),
            },
            EvidenceSource::Custom {
                source_name: "custom".to_string(),
                metadata: Some(serde_json::json!({"key": "value"})),
            },
        ];

        for source in sources {
            let json = serde_json::to_string(&source).unwrap();
            let deserialized: EvidenceSource = serde_json::from_str(&json).unwrap();
            // Verify round-trip (note: timestamps may differ slightly)
            let json2 = serde_json::to_string(&deserialized).unwrap();
            assert!(!json2.is_empty());
        }
    }

    #[test]
    fn test_all_evidence_type_variants() {
        let types = vec![
            EvidenceType::NetworkActivity,
            EvidenceType::FileArtifact,
            EvidenceType::ProcessExecution,
            EvidenceType::UserBehavior,
            EvidenceType::EmailContent,
            EvidenceType::ThreatIntelMatch,
            EvidenceType::MitreObservation,
            EvidenceType::SystemChange,
            EvidenceType::DnsActivity,
            EvidenceType::WebActivity,
            EvidenceType::CloudActivity,
            EvidenceType::AuthenticationEvent,
            EvidenceType::DataAccess,
            EvidenceType::MalwareIndicator,
            EvidenceType::Custom("test".to_string()),
        ];

        for evidence_type in types {
            let json = serde_json::to_string(&evidence_type).unwrap();
            let deserialized: EvidenceType = serde_json::from_str(&json).unwrap();
            assert_eq!(evidence_type, deserialized);
        }
    }
}
