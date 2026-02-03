//! Data Transfer Objects (DTOs) for API requests and responses.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;

use tw_core::incident::ActionTarget;

// ============================================================================
// Sensitive Data Types
// ============================================================================

/// Maximum length for email body content in responses.
pub const MAX_EMAIL_BODY_LENGTH: usize = 200;

/// Truncation suffix appended when content is truncated.
pub const TRUNCATION_SUFFIX: &str = "...";

/// A wrapper type for sensitive fields that masks the value during serialization.
///
/// This type is used to prevent accidental exposure of sensitive data in API responses.
/// When serialized, the actual value is replaced with a masked placeholder.
///
/// # Example
/// ```
/// use tw_api::dto::SensitiveField;
///
/// let api_key = SensitiveField::new("sk-secret-key-12345");
/// // When serialized to JSON, this becomes: "***REDACTED***"
/// ```
#[derive(Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct SensitiveField(String);

impl SensitiveField {
    /// The mask value used when serializing sensitive fields.
    pub const MASK: &'static str = "***REDACTED***";

    /// Creates a new sensitive field with the given value.
    pub fn new<S: Into<String>>(value: S) -> Self {
        Self(value.into())
    }

    /// Returns the unmasked value.
    ///
    /// # Security Warning
    /// Only use this method when you absolutely need the raw value,
    /// such as when making API calls. Never expose this value in responses.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Returns a partially masked version showing first and last few characters.
    /// Useful for debugging or logs where you need some identification.
    ///
    /// # Example
    /// ```
    /// use tw_api::dto::SensitiveField;
    ///
    /// let field = SensitiveField::new("sk-secret-key-12345");
    /// assert_eq!(field.partial_mask(), "sk-***...***45");
    /// ```
    pub fn partial_mask(&self) -> String {
        if self.0.len() <= 6 {
            Self::MASK.to_string()
        } else {
            let prefix = &self.0[..3];
            let suffix = &self.0[self.0.len() - 2..];
            format!("{}***...***{}", prefix, suffix)
        }
    }
}

impl Serialize for SensitiveField {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Always serialize as the mask value
        serializer.serialize_str(Self::MASK)
    }
}

impl<'de> Deserialize<'de> for SensitiveField {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Ok(SensitiveField(value))
    }
}

impl fmt::Display for SensitiveField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Display always shows the mask to prevent accidental logging
        write!(f, "{}", Self::MASK)
    }
}

impl From<String> for SensitiveField {
    fn from(value: String) -> Self {
        SensitiveField(value)
    }
}

impl From<&str> for SensitiveField {
    fn from(value: &str) -> Self {
        SensitiveField(value.to_string())
    }
}

/// Truncates a string to the specified maximum length, adding a suffix if truncated.
///
/// # Arguments
/// * `content` - The content to truncate
/// * `max_length` - Maximum length before truncation (not including suffix)
/// * `suffix` - The suffix to append when truncated (e.g., "...")
///
/// # Returns
/// The original string if within limits, or a truncated version with suffix.
pub fn truncate_content(content: &str, max_length: usize, suffix: &str) -> String {
    if content.len() <= max_length {
        content.to_string()
    } else {
        // Find a safe truncation point that doesn't break UTF-8
        let mut end = max_length;
        while !content.is_char_boundary(end) && end > 0 {
            end -= 1;
        }
        format!("{}{}", &content[..end], suffix)
    }
}

/// Truncates email body content to the default maximum length.
///
/// This is a convenience function that uses the default MAX_EMAIL_BODY_LENGTH
/// and TRUNCATION_SUFFIX constants.
pub fn truncate_email_body(body: &str) -> String {
    truncate_content(body, MAX_EMAIL_BODY_LENGTH, TRUNCATION_SUFFIX)
}

/// Masks potentially sensitive patterns in a string.
///
/// This function identifies and masks common sensitive patterns like:
/// - API keys (various formats)
/// - Bearer tokens
/// - Basic auth credentials
/// - AWS access keys
/// - Private keys
///
/// # Arguments
/// * `content` - The content to scan for sensitive patterns
///
/// # Returns
/// The content with sensitive patterns replaced with masks.
pub fn mask_sensitive_patterns(content: &str) -> String {
    use regex::Regex;

    // Patterns that indicate sensitive data
    // Note: Using regular strings with escaped backslashes for proper regex handling
    let patterns: &[(&str, &str)] = &[
        // API keys (generic patterns)
        (
            "(?i)(api[_-]?key|apikey)[=:]\\s*['\"]?([a-zA-Z0-9_-]{16,})['\"]?",
            "$1=***REDACTED***",
        ),
        // Bearer tokens
        ("(?i)(bearer\\s+)([a-zA-Z0-9_.+-]+)", "$1***REDACTED***"),
        // Authorization headers
        (
            "(?i)(authorization[=:]\\s*)['\"]?([^'\"\\s]+)['\"]?",
            "$1***REDACTED***",
        ),
        // AWS access keys
        ("(?i)(AKIA[A-Z0-9]{16})", "***AWS_KEY_REDACTED***"),
        // Private key blocks
        (
            "-----BEGIN [A-Z ]+ PRIVATE KEY-----[\\s\\S]*?-----END [A-Z ]+ PRIVATE KEY-----",
            "***PRIVATE_KEY_REDACTED***",
        ),
        // Password patterns
        (
            "(?i)(password|passwd|pwd)[=:]\\s*['\"]?([^'\"\\s,}]+)['\"]?",
            "$1=***REDACTED***",
        ),
        // Secret patterns
        (
            "(?i)(secret|token)[=:]\\s*['\"]?([a-zA-Z0-9_-]{8,})['\"]?",
            "$1=***REDACTED***",
        ),
    ];

    let mut result = content.to_string();
    for (pattern, replacement) in patterns {
        if let Ok(re) = Regex::new(pattern) {
            result = re.replace_all(&result, *replacement).to_string();
        }
    }
    result
}

/// Sanitizes action output data by truncating long content and masking sensitive patterns.
///
/// This function processes a HashMap of action output values and:
/// 1. Truncates string values that appear to be email bodies or large content
/// 2. Masks any sensitive patterns (API keys, tokens, etc.)
///
/// # Arguments
/// * `output` - The action output HashMap to sanitize
///
/// # Returns
/// A new HashMap with sanitized values.
pub fn sanitize_action_output(
    output: std::collections::HashMap<String, serde_json::Value>,
) -> std::collections::HashMap<String, serde_json::Value> {
    output
        .into_iter()
        .map(|(key, value)| {
            let sanitized_value = sanitize_json_value(&key, value);
            (key, sanitized_value)
        })
        .collect()
}

/// Sanitizes a single JSON value based on its key and content.
fn sanitize_json_value(key: &str, value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::String(s) => {
            // Keys that should have their content truncated
            let truncate_keys = ["body", "content", "message_body", "email_body", "raw_body"];
            // Keys that should be fully masked
            let mask_keys = [
                "api_key",
                "token",
                "secret",
                "password",
                "authorization",
                "credentials",
            ];

            if mask_keys.iter().any(|k| key.to_lowercase().contains(k)) {
                serde_json::Value::String(SensitiveField::MASK.to_string())
            } else if truncate_keys.iter().any(|k| key.to_lowercase().contains(k)) {
                let truncated = truncate_email_body(&s);
                let masked = mask_sensitive_patterns(&truncated);
                serde_json::Value::String(masked)
            } else {
                // Still mask any sensitive patterns in other string fields
                let masked = mask_sensitive_patterns(&s);
                serde_json::Value::String(masked)
            }
        }
        serde_json::Value::Object(map) => {
            let sanitized: serde_json::Map<String, serde_json::Value> = map
                .into_iter()
                .map(|(k, v)| {
                    let sanitized_v = sanitize_json_value(&k, v);
                    (k, sanitized_v)
                })
                .collect();
            serde_json::Value::Object(sanitized)
        }
        serde_json::Value::Array(arr) => {
            let sanitized: Vec<serde_json::Value> = arr
                .into_iter()
                .map(|v| sanitize_json_value(key, v))
                .collect();
            serde_json::Value::Array(sanitized)
        }
        other => other,
    }
}

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
    /// Full-text search query (searches alert_data, ticket_id, tags).
    pub q: Option<String>,
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

/// Request to dismiss an incident.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct DismissRequest {
    /// Optional reason for dismissing the incident.
    #[serde(default)]
    pub reason: Option<String>,
}

/// Request to resolve an incident.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct ResolveRequest {
    /// Optional reason for resolving the incident.
    #[serde(default)]
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
    /// Overall system status: "healthy", "degraded", or "unhealthy"
    pub status: String,
    /// Application version
    pub version: String,
    /// Database health status
    pub database: DatabaseHealth,
    /// Application uptime in seconds
    pub uptime_seconds: u64,
    /// Component health statuses
    #[serde(skip_serializing_if = "Option::is_none")]
    pub components: Option<ComponentsHealth>,
}

/// Database health status.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct DatabaseHealth {
    pub connected: bool,
    pub pool_size: u32,
    pub idle_connections: usize,
}

/// Component-level health statuses.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ComponentsHealth {
    /// Kill switch status
    pub kill_switch: KillSwitchHealth,
    /// Connectors health summary
    pub connectors: ConnectorsHealth,
    /// LLM configuration status
    pub llm: LlmHealth,
    /// Event bus status
    pub event_bus: EventBusHealth,
}

/// Kill switch health status.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct KillSwitchHealth {
    /// Whether the kill switch is active (automation halted)
    pub active: bool,
    /// Who activated the kill switch (if active)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activated_by: Option<String>,
    /// When the kill switch was activated (if active)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activated_at: Option<String>,
}

/// Connectors health summary.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ConnectorsHealth {
    /// Total number of configured connectors
    pub total: u32,
    /// Number of healthy/connected connectors
    pub healthy: u32,
    /// Number of unhealthy/errored connectors
    pub unhealthy: u32,
    /// Number of disabled connectors
    pub disabled: u32,
    /// List of unhealthy connector names
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub unhealthy_connectors: Vec<String>,
}

/// LLM configuration health status.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct LlmHealth {
    /// Whether LLM features are enabled
    pub enabled: bool,
    /// Whether an API key is configured
    pub configured: bool,
    /// The configured provider name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
}

/// Event bus health status.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct EventBusHealth {
    /// Number of active subscribers
    pub subscriber_count: usize,
    /// Whether the event bus is operational
    pub operational: bool,
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

// ============================================================================
// Playbook DTOs
// ============================================================================

/// Response for a single playbook.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct PlaybookResponse {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub trigger_type: String,
    pub trigger_condition: Option<String>,
    pub stages: Vec<PlaybookStageDto>,
    pub enabled: bool,
    pub execution_count: u32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Playbook stage DTO.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PlaybookStageDto {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub parallel: bool,
    pub steps: Vec<PlaybookStepDto>,
}

/// Playbook step DTO.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PlaybookStepDto {
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<Vec<String>>,
    #[serde(default)]
    pub requires_approval: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conditions: Option<serde_json::Value>,
}

/// Request to create a new playbook.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreatePlaybookRequest {
    /// Name of the playbook.
    pub name: String,
    /// Optional description.
    pub description: Option<String>,
    /// Type of trigger (e.g., "alert", "scheduled").
    pub trigger_type: String,
    /// Optional trigger condition expression.
    pub trigger_condition: Option<String>,
    /// Whether the playbook is enabled (defaults to true).
    pub enabled: Option<bool>,
    /// Stages as JSON string.
    pub stages: Option<String>,
}

/// Request to update an existing playbook.
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdatePlaybookRequest {
    /// New name for the playbook.
    pub name: Option<String>,
    /// New description (empty string clears it).
    pub description: Option<String>,
    /// New trigger type.
    pub trigger_type: Option<String>,
    /// New trigger condition (empty string clears it).
    pub trigger_condition: Option<String>,
    /// New enabled status.
    pub enabled: Option<bool>,
    /// Stages as JSON string.
    pub stages: Option<String>,
}

// ============================================================================
// Tests for Sensitive Data Handling
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // --------------------------------------------------------------------------
    // SensitiveField Tests
    // --------------------------------------------------------------------------

    #[test]
    fn test_sensitive_field_serializes_to_mask() {
        let field = SensitiveField::new("super-secret-api-key-12345");
        let json = serde_json::to_string(&field).unwrap();
        assert_eq!(json, "\"***REDACTED***\"");
    }

    #[test]
    fn test_sensitive_field_deserializes() {
        let json = "\"my-secret-value\"";
        let field: SensitiveField = serde_json::from_str(json).unwrap();
        assert_eq!(field.expose(), "my-secret-value");
    }

    #[test]
    fn test_sensitive_field_expose() {
        let field = SensitiveField::new("secret-value");
        assert_eq!(field.expose(), "secret-value");
    }

    #[test]
    fn test_sensitive_field_display_shows_mask() {
        let field = SensitiveField::new("secret-value");
        assert_eq!(format!("{}", field), "***REDACTED***");
    }

    #[test]
    fn test_sensitive_field_partial_mask() {
        let field = SensitiveField::new("sk-secret-key-12345");
        assert_eq!(field.partial_mask(), "sk-***...***45");
    }

    #[test]
    fn test_sensitive_field_partial_mask_short_value() {
        let field = SensitiveField::new("short");
        assert_eq!(field.partial_mask(), "***REDACTED***");
    }

    #[test]
    fn test_sensitive_field_from_string() {
        let field: SensitiveField = "my-value".into();
        assert_eq!(field.expose(), "my-value");
    }

    #[test]
    fn test_sensitive_field_equality() {
        let field1 = SensitiveField::new("value");
        let field2 = SensitiveField::new("value");
        let field3 = SensitiveField::new("other");
        assert_eq!(field1, field2);
        assert_ne!(field1, field3);
    }

    // --------------------------------------------------------------------------
    // Content Truncation Tests
    // --------------------------------------------------------------------------

    #[test]
    fn test_truncate_content_short_string() {
        let content = "Short content";
        let result = truncate_content(content, 200, "...");
        assert_eq!(result, "Short content");
    }

    #[test]
    fn test_truncate_content_long_string() {
        let content = "A".repeat(300);
        let result = truncate_content(&content, 200, "...");
        assert_eq!(result.len(), 203); // 200 chars + "..."
        assert!(result.ends_with("..."));
    }

    #[test]
    fn test_truncate_content_exact_length() {
        let content = "A".repeat(200);
        let result = truncate_content(&content, 200, "...");
        assert_eq!(result, content);
    }

    #[test]
    fn test_truncate_content_unicode() {
        // Each emoji is 4 bytes
        let content = "Hello \u{1F600}\u{1F600}\u{1F600}\u{1F600} World!";
        let result = truncate_content(content, 10, "...");
        // Should not break in the middle of a multi-byte character
        assert!(result.is_char_boundary(result.len() - 3)); // Before "..."
    }

    #[test]
    fn test_truncate_email_body() {
        let long_body = "X".repeat(500);
        let result = truncate_email_body(&long_body);
        assert!(result.len() <= MAX_EMAIL_BODY_LENGTH + TRUNCATION_SUFFIX.len());
        assert!(result.ends_with(TRUNCATION_SUFFIX));
    }

    #[test]
    fn test_truncate_email_body_short() {
        let short_body = "This is a short email.";
        let result = truncate_email_body(short_body);
        assert_eq!(result, short_body);
    }

    // --------------------------------------------------------------------------
    // Sensitive Pattern Masking Tests
    // --------------------------------------------------------------------------

    #[test]
    fn test_mask_api_key_pattern() {
        let content = "Config: api_key=sk_live_1234567890abcdef";
        let result = mask_sensitive_patterns(content);
        assert!(!result.contains("sk_live_1234567890abcdef"));
        assert!(result.contains("***REDACTED***"));
    }

    #[test]
    fn test_mask_bearer_token() {
        let content = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0";
        let result = mask_sensitive_patterns(content);
        assert!(!result.contains("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"));
        assert!(result.contains("***REDACTED***"));
    }

    #[test]
    fn test_mask_aws_access_key() {
        let content = "AWS_ACCESS_KEY: AKIAIOSFODNN7EXAMPLE";
        let result = mask_sensitive_patterns(content);
        assert!(!result.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(result.contains("***AWS_KEY_REDACTED***"));
    }

    #[test]
    fn test_mask_password_pattern() {
        let content = "database password=SuperSecret123!";
        let result = mask_sensitive_patterns(content);
        assert!(!result.contains("SuperSecret123!"));
        assert!(result.contains("***REDACTED***"));
    }

    #[test]
    fn test_mask_secret_token() {
        let content = "secret_token=abcdef1234567890xyz";
        let result = mask_sensitive_patterns(content);
        assert!(!result.contains("abcdef1234567890xyz"));
        assert!(result.contains("***REDACTED***"));
    }

    #[test]
    fn test_mask_preserves_normal_content() {
        let content = "This is a normal email about the project status.";
        let result = mask_sensitive_patterns(content);
        assert_eq!(result, content);
    }

    #[test]
    fn test_mask_multiple_patterns() {
        // API key pattern requires at least 16 chars, password pattern is more flexible
        let content = "api_key=secret1234567890ab and password=mypassword123";
        let result = mask_sensitive_patterns(content);
        assert!(!result.contains("secret1234567890ab"));
        assert!(!result.contains("mypassword123"));
        assert!(result.contains("***REDACTED***"));
    }

    // --------------------------------------------------------------------------
    // Action Output Sanitization Tests
    // --------------------------------------------------------------------------

    #[test]
    fn test_sanitize_action_output_truncates_body() {
        let mut output = HashMap::new();
        let long_body = "X".repeat(500);
        output.insert("body".to_string(), serde_json::json!(long_body));

        let result = sanitize_action_output(output);
        let body = result.get("body").unwrap().as_str().unwrap();
        assert!(body.len() <= MAX_EMAIL_BODY_LENGTH + TRUNCATION_SUFFIX.len());
    }

    #[test]
    fn test_sanitize_action_output_masks_api_key() {
        let mut output = HashMap::new();
        output.insert("api_key".to_string(), serde_json::json!("sk-secret-12345"));

        let result = sanitize_action_output(output);
        let value = result.get("api_key").unwrap().as_str().unwrap();
        assert_eq!(value, "***REDACTED***");
    }

    #[test]
    fn test_sanitize_action_output_masks_token() {
        let mut output = HashMap::new();
        output.insert(
            "auth_token".to_string(),
            serde_json::json!("secret-token-value"),
        );

        let result = sanitize_action_output(output);
        let value = result.get("auth_token").unwrap().as_str().unwrap();
        assert_eq!(value, "***REDACTED***");
    }

    #[test]
    fn test_sanitize_action_output_preserves_safe_fields() {
        let mut output = HashMap::new();
        output.insert("message_id".to_string(), serde_json::json!("msg-123"));
        output.insert("status".to_string(), serde_json::json!("success"));
        output.insert(
            "user_email".to_string(),
            serde_json::json!("user@example.com"),
        );

        let result = sanitize_action_output(output);
        assert_eq!(
            result.get("message_id").unwrap().as_str().unwrap(),
            "msg-123"
        );
        assert_eq!(result.get("status").unwrap().as_str().unwrap(), "success");
        assert_eq!(
            result.get("user_email").unwrap().as_str().unwrap(),
            "user@example.com"
        );
    }

    #[test]
    fn test_sanitize_action_output_handles_nested_objects() {
        let mut output = HashMap::new();
        output.insert(
            "data".to_string(),
            serde_json::json!({
                "api_key": "secret-key",
                "safe_field": "normal value"
            }),
        );

        let result = sanitize_action_output(output);
        let data = result.get("data").unwrap().as_object().unwrap();
        assert_eq!(
            data.get("api_key").unwrap().as_str().unwrap(),
            "***REDACTED***"
        );
        assert_eq!(
            data.get("safe_field").unwrap().as_str().unwrap(),
            "normal value"
        );
    }

    #[test]
    fn test_sanitize_action_output_handles_arrays() {
        let mut output = HashMap::new();
        output.insert(
            "items".to_string(),
            serde_json::json!(["normal item", "another item"]),
        );

        let result = sanitize_action_output(output);
        let items = result.get("items").unwrap().as_array().unwrap();
        assert_eq!(items.len(), 2);
    }

    #[test]
    fn test_sanitize_action_output_masks_patterns_in_content() {
        let mut output = HashMap::new();
        // API key pattern requires at least 16 chars
        output.insert(
            "content".to_string(),
            serde_json::json!("Email body with api_key=secret1234567890ab embedded"),
        );

        let result = sanitize_action_output(output);
        let content = result.get("content").unwrap().as_str().unwrap();
        assert!(!content.contains("secret1234567890ab"));
        assert!(content.contains("***REDACTED***"));
    }

    #[test]
    fn test_sanitize_preserves_numeric_values() {
        let mut output = HashMap::new();
        output.insert("count".to_string(), serde_json::json!(42));
        output.insert("ratio".to_string(), serde_json::json!(0.95));

        let result = sanitize_action_output(output);
        assert_eq!(result.get("count").unwrap().as_i64().unwrap(), 42);
        assert_eq!(result.get("ratio").unwrap().as_f64().unwrap(), 0.95);
    }

    #[test]
    fn test_sanitize_preserves_boolean_values() {
        let mut output = HashMap::new();
        output.insert("success".to_string(), serde_json::json!(true));
        output.insert("rollback_available".to_string(), serde_json::json!(false));

        let result = sanitize_action_output(output);
        assert!(result.get("success").unwrap().as_bool().unwrap());
        assert!(!result.get("rollback_available").unwrap().as_bool().unwrap());
    }

    // --------------------------------------------------------------------------
    // Integration Tests for Full Workflow
    // --------------------------------------------------------------------------

    #[test]
    fn test_full_email_notification_sanitization() {
        let mut output = HashMap::new();
        output.insert(
            "user_email".to_string(),
            serde_json::json!("user@company.com"),
        );
        output.insert(
            "subject".to_string(),
            serde_json::json!("[Security Alert] Suspicious Activity"),
        );
        output.insert(
            "body".to_string(),
            serde_json::json!(
                "Dear User,\n\nWe detected suspicious activity on your account. \
             Your password may have been compromised. Please reset it immediately.\n\n\
             If you did not initiate this activity, please contact the security team.\n\n\
             Best regards,\nSecurity Team\n\nThis is a long email that should be truncated \
             because it exceeds the maximum allowed length for email bodies in API responses. \
             We add this extra text to ensure the truncation logic is working correctly."
            ),
        );
        output.insert(
            "notification_id".to_string(),
            serde_json::json!("notif-12345"),
        );
        output.insert("status".to_string(), serde_json::json!("queued"));

        let result = sanitize_action_output(output);

        // Body should be truncated
        let body = result.get("body").unwrap().as_str().unwrap();
        assert!(body.len() <= MAX_EMAIL_BODY_LENGTH + TRUNCATION_SUFFIX.len());
        assert!(body.ends_with(TRUNCATION_SUFFIX) || body.len() <= MAX_EMAIL_BODY_LENGTH);

        // Other fields should be preserved
        assert_eq!(
            result.get("user_email").unwrap().as_str().unwrap(),
            "user@company.com"
        );
        assert_eq!(
            result.get("notification_id").unwrap().as_str().unwrap(),
            "notif-12345"
        );
    }

    #[test]
    fn test_full_quarantine_sanitization() {
        let mut output = HashMap::new();
        output.insert("message_id".to_string(), serde_json::json!("msg-001"));
        output.insert(
            "sender".to_string(),
            serde_json::json!("attacker@malicious.com"),
        );
        output.insert(
            "subject".to_string(),
            serde_json::json!("You won $1,000,000!"),
        );
        output.insert(
            "quarantine_location".to_string(),
            serde_json::json!("quarantine/msg-001"),
        );
        output.insert("action_id".to_string(), serde_json::json!("action-xyz"));
        output.insert("success".to_string(), serde_json::json!(true));

        let result = sanitize_action_output(output);

        // All fields should be present and correct
        assert_eq!(
            result.get("message_id").unwrap().as_str().unwrap(),
            "msg-001"
        );
        assert_eq!(
            result.get("sender").unwrap().as_str().unwrap(),
            "attacker@malicious.com"
        );
        assert!(result.get("success").unwrap().as_bool().unwrap());
    }
}
