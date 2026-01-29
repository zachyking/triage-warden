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

impl Incident {
    /// Creates a new incident from an alert.
    pub fn from_alert(alert: Alert) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
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
    /// Escalated to higher tier
    Escalated,
    /// Closed without action
    Closed,
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
    /// Confidence score (0.0 - 1.0).
    pub confidence: f64,
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
    Host { hostname: String, ip: Option<String> },
    /// A user account
    User { username: String, email: Option<String> },
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
}
