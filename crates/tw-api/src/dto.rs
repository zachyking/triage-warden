//! Data Transfer Objects (DTOs) for API requests and responses.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;

use tw_core::incident::{
    ActionTarget, ActionType, ApprovalStatus, IncidentStatus, Severity, TriageVerdict,
};

// ============================================================================
// Incident DTOs
// ============================================================================

/// Response for a single incident.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct IncidentResponse {
    pub id: Uuid,
    pub source: String,
    pub severity: String,
    pub status: String,
    pub title: Option<String>,
    pub alert_type: Option<String>,
    pub verdict: Option<String>,
    pub confidence: Option<f64>,
    pub risk_score: Option<u8>,
    pub ticket_id: Option<String>,
    pub tags: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Detailed incident response including enrichments and audit log.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct IncidentDetailResponse {
    #[serde(flatten)]
    pub incident: IncidentResponse,
    pub alert_data: serde_json::Value,
    pub enrichments: Vec<EnrichmentResponse>,
    pub analysis: Option<AnalysisResponse>,
    pub proposed_actions: Vec<ActionResponse>,
    pub audit_log: Vec<AuditEntryResponse>,
}

/// Enrichment data in response.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct EnrichmentResponse {
    pub enrichment_type: String,
    pub source: String,
    pub data: serde_json::Value,
    pub timestamp: DateTime<Utc>,
}

/// Analysis data in response.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct AnalysisResponse {
    pub verdict: String,
    pub confidence: f64,
    pub risk_score: u8,
    pub summary: String,
    pub reasoning: String,
    pub recommendations: Vec<String>,
    pub mitre_techniques: Vec<MitreTechniqueResponse>,
    pub iocs: Vec<IoCResponse>,
    pub analyzed_by: String,
    pub timestamp: DateTime<Utc>,
}

/// MITRE technique in response.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct MitreTechniqueResponse {
    pub id: String,
    pub name: String,
    pub tactic: String,
    pub confidence: f64,
}

/// Indicator of Compromise in response.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct IoCResponse {
    pub ioc_type: String,
    pub value: String,
    pub context: Option<String>,
    pub score: Option<f64>,
}

/// Proposed/executed action in response.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ActionResponse {
    pub id: Uuid,
    pub action_type: String,
    pub target: serde_json::Value,
    pub reason: String,
    pub priority: u8,
    pub approval_status: String,
    pub approved_by: Option<String>,
    pub approval_timestamp: Option<DateTime<Utc>>,
}

/// Audit log entry in response.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct AuditEntryResponse {
    pub id: Uuid,
    pub action: String,
    pub actor: String,
    pub details: Option<serde_json::Value>,
    pub timestamp: DateTime<Utc>,
}

/// Query parameters for listing incidents.
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct ListIncidentsQuery {
    /// Filter by status (comma-separated).
    pub status: Option<String>,
    /// Filter by severity (comma-separated).
    pub severity: Option<String>,
    /// Filter by created after this timestamp.
    pub since: Option<DateTime<Utc>>,
    /// Filter by created before this timestamp.
    pub until: Option<DateTime<Utc>>,
    /// Page number (1-indexed).
    #[validate(range(min = 1))]
    pub page: Option<u32>,
    /// Items per page.
    #[validate(range(min = 1, max = 100))]
    pub per_page: Option<u32>,
}

/// Paginated list response.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct PaginatedResponse<T> {
    pub data: Vec<T>,
    pub pagination: PaginationInfo,
}

/// Pagination metadata.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct PaginationInfo {
    pub page: u32,
    pub per_page: u32,
    pub total_items: u64,
    pub total_pages: u32,
}

// ============================================================================
// Action DTOs
// ============================================================================

/// Request to execute an action on an incident.
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct ExecuteActionRequest {
    /// Type of action to execute.
    pub action_type: String,
    /// Target of the action.
    pub target: ActionTargetDto,
    /// Reason for the action.
    #[validate(length(min = 1, max = 1000))]
    pub reason: String,
    /// Action parameters.
    pub parameters: Option<serde_json::Value>,
    /// Skip policy check (requires elevated permissions).
    #[serde(default)]
    pub skip_policy_check: bool,
}

/// Action target DTO.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ActionTargetDto {
    Host {
        hostname: String,
        ip: Option<String>,
    },
    User {
        username: String,
        email: Option<String>,
    },
    IpAddress {
        ip: String,
    },
    Domain {
        domain: String,
    },
    Email {
        message_id: String,
    },
    Ticket {
        ticket_id: String,
    },
    None,
}

impl From<ActionTargetDto> for ActionTarget {
    fn from(dto: ActionTargetDto) -> Self {
        match dto {
            ActionTargetDto::Host { hostname, ip } => ActionTarget::Host { hostname, ip },
            ActionTargetDto::User { username, email } => ActionTarget::User { username, email },
            ActionTargetDto::IpAddress { ip } => ActionTarget::IpAddress(ip),
            ActionTargetDto::Domain { domain } => ActionTarget::Domain(domain),
            ActionTargetDto::Email { message_id } => ActionTarget::Email { message_id },
            ActionTargetDto::Ticket { ticket_id } => ActionTarget::Ticket { ticket_id },
            ActionTargetDto::None => ActionTarget::None,
        }
    }
}

/// Request to approve an action.
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct ApproveActionRequest {
    /// ID of the action to approve.
    pub action_id: Uuid,
    /// Approval decision.
    pub approved: bool,
    /// Reason for the decision (required if denied).
    pub reason: Option<String>,
}

/// Response after action execution.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ActionExecutionResponse {
    pub action_id: Uuid,
    pub incident_id: Uuid,
    pub action_type: String,
    pub status: String,
    pub message: String,
    pub result: Option<serde_json::Value>,
    pub executed_at: DateTime<Utc>,
}

// ============================================================================
// Webhook DTOs
// ============================================================================

/// Generic webhook alert payload.
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct WebhookAlertPayload {
    /// Source system identifier.
    #[validate(length(min = 1, max = 100))]
    pub source: String,
    /// Alert type/category.
    #[validate(length(min = 1, max = 100))]
    pub alert_type: String,
    /// Severity level.
    pub severity: Option<String>,
    /// Alert title.
    #[validate(length(min = 1, max = 500))]
    pub title: String,
    /// Alert description.
    pub description: Option<String>,
    /// Raw alert data.
    pub data: serde_json::Value,
    /// Alert timestamp.
    pub timestamp: Option<DateTime<Utc>>,
    /// Tags.
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Response for webhook acceptance.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct WebhookAcceptedResponse {
    pub accepted: bool,
    pub message: String,
    pub alert_id: Option<String>,
    pub incident_id: Option<Uuid>,
}

// ============================================================================
// Health DTOs
// ============================================================================

/// Health check response.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub database: DatabaseHealth,
    pub uptime_seconds: u64,
}

/// Database health status.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct DatabaseHealth {
    pub connected: bool,
    pub pool_size: u32,
    pub idle_connections: usize,
}

// ============================================================================
// Metrics DTOs
// ============================================================================

/// Metrics response (Prometheus format is separate).
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct MetricsResponse {
    pub incidents: IncidentMetrics,
    pub actions: ActionMetrics,
    pub performance: PerformanceMetrics,
}

/// Incident-related metrics.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct IncidentMetrics {
    pub total: u64,
    pub by_status: std::collections::HashMap<String, u64>,
    pub by_severity: std::collections::HashMap<String, u64>,
    pub created_last_hour: u64,
    pub resolved_last_hour: u64,
}

/// Action-related metrics.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ActionMetrics {
    pub total_executed: u64,
    pub success_rate: f64,
    pub pending_approvals: u64,
}

/// Performance metrics.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct PerformanceMetrics {
    pub mean_time_to_triage_seconds: Option<f64>,
    pub mean_time_to_respond_seconds: Option<f64>,
    pub auto_resolution_rate: Option<f64>,
}
