//! Audit logging for Triage Warden.
//!
//! This module provides audit trail functionality for compliance and forensics.
//!
//! # Action Audit Logging
//!
//! The module includes comprehensive action audit logging with:
//! - Detailed actor identity tracking (actor_id, actor_username)
//! - Automatic masking of sensitive parameters (api_key, password, token, secret)
//! - Structured JSON format for log aggregation
//! - Correlation IDs for linking related audit entries
//! - Duration tracking for performance monitoring

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;
use uuid::Uuid;

/// An entry in the audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    /// Unique entry ID.
    pub id: Uuid,
    /// Timestamp.
    pub timestamp: DateTime<Utc>,
    /// Event type.
    pub event_type: AuditEventType,
    /// Actor (user or system component).
    pub actor: String,
    /// Incident ID (if applicable).
    pub incident_id: Option<Uuid>,
    /// Action ID (if applicable).
    pub action_id: Option<Uuid>,
    /// Description of the event.
    pub description: String,
    /// Additional details.
    pub details: serde_json::Value,
    /// Result/outcome.
    pub result: AuditResult,
}

/// Types of auditable events.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    /// System startup/shutdown.
    SystemLifecycle,
    /// Configuration change.
    ConfigChange,
    /// Incident created.
    IncidentCreated,
    /// Incident status changed.
    IncidentStatusChanged,
    /// Analysis completed.
    AnalysisCompleted,
    /// Action proposed.
    ActionProposed,
    /// Action approved.
    ActionApproved,
    /// Action denied.
    ActionDenied,
    /// Action executed.
    ActionExecuted,
    /// Action failed.
    ActionFailed,
    /// Action rolled back.
    ActionRolledBack,
    /// Policy evaluated.
    PolicyEvaluated,
    /// Approval request created.
    ApprovalRequested,
    /// Approval decision made.
    ApprovalDecision,
    /// Kill switch activated.
    KillSwitchActivated,
    /// Kill switch deactivated.
    KillSwitchDeactivated,
    /// User login.
    UserLogin,
    /// User logout.
    UserLogout,
    /// API access.
    ApiAccess,
    /// Data export.
    DataExport,

    // Security events
    /// Successful login attempt.
    LoginSuccess,
    /// Failed login attempt.
    LoginFailure,
    /// API key created.
    ApiKeyCreated,
    /// API key revoked.
    ApiKeyRevoked,
    /// API key used for authentication.
    ApiKeyUsed,
    /// Permission denied (403).
    PermissionDenied,
    /// Rate limit exceeded (429).
    RateLimitExceeded,
    /// Session created.
    SessionCreated,
    /// Session expired.
    SessionExpired,
    /// Session invalidated.
    SessionInvalidated,
    /// User account disabled.
    AccountDisabled,
    /// User account enabled.
    AccountEnabled,
    /// Password changed.
    PasswordChanged,
    /// User created.
    UserCreated,
    /// User deleted.
    UserDeleted,
    /// User role changed.
    UserRoleChanged,
    /// Webhook signature validation failed.
    WebhookSignatureInvalid,
    /// Suspicious activity detected.
    SuspiciousActivity,

    /// Custom event.
    Custom(String),
}

/// Result of an audited operation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditResult {
    Success,
    Failure(String),
    Denied(String),
    Pending,
}

/// Audit log with in-memory storage and optional persistence.
pub struct AuditLog {
    /// In-memory log entries.
    entries: Arc<RwLock<VecDeque<AuditLogEntry>>>,
    /// Maximum entries to keep in memory.
    max_entries: usize,
    /// Whether to also log to tracing.
    log_to_tracing: bool,
}

impl AuditLog {
    /// Creates a new audit log.
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: Arc::new(RwLock::new(VecDeque::with_capacity(max_entries))),
            max_entries,
            log_to_tracing: true,
        }
    }

    /// Creates an audit log without tracing output.
    pub fn without_tracing(max_entries: usize) -> Self {
        Self {
            entries: Arc::new(RwLock::new(VecDeque::with_capacity(max_entries))),
            max_entries,
            log_to_tracing: false,
        }
    }

    /// Logs an audit entry.
    pub async fn log(&self, entry: AuditLogEntry) {
        if self.log_to_tracing {
            info!(
                event_type = ?entry.event_type,
                actor = %entry.actor,
                incident_id = ?entry.incident_id,
                result = ?entry.result,
                "Audit: {}",
                entry.description
            );
        }

        let mut entries = self.entries.write().await;
        if entries.len() >= self.max_entries {
            entries.pop_front();
        }
        entries.push_back(entry);
    }

    /// Logs an event with builder pattern.
    pub async fn log_event(
        &self,
        event_type: AuditEventType,
        actor: &str,
        description: &str,
        result: AuditResult,
    ) {
        let entry = AuditLogEntry {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_type,
            actor: actor.to_string(),
            incident_id: None,
            action_id: None,
            description: description.to_string(),
            details: serde_json::json!({}),
            result,
        };
        self.log(entry).await;
    }

    /// Logs an incident event.
    pub async fn log_incident_event(
        &self,
        event_type: AuditEventType,
        actor: &str,
        incident_id: Uuid,
        description: &str,
        details: serde_json::Value,
        result: AuditResult,
    ) {
        let entry = AuditLogEntry {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_type,
            actor: actor.to_string(),
            incident_id: Some(incident_id),
            action_id: None,
            description: description.to_string(),
            details,
            result,
        };
        self.log(entry).await;
    }

    /// Logs an action event.
    #[allow(clippy::too_many_arguments)]
    pub async fn log_action_event(
        &self,
        event_type: AuditEventType,
        actor: &str,
        incident_id: Uuid,
        action_id: Uuid,
        description: &str,
        details: serde_json::Value,
        result: AuditResult,
    ) {
        let entry = AuditLogEntry {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_type,
            actor: actor.to_string(),
            incident_id: Some(incident_id),
            action_id: Some(action_id),
            description: description.to_string(),
            details,
            result,
        };
        self.log(entry).await;
    }

    /// Gets all entries.
    pub async fn get_entries(&self) -> Vec<AuditLogEntry> {
        let entries = self.entries.read().await;
        entries.iter().cloned().collect()
    }

    /// Gets entries for a specific incident.
    pub async fn get_incident_entries(&self, incident_id: Uuid) -> Vec<AuditLogEntry> {
        let entries = self.entries.read().await;
        entries
            .iter()
            .filter(|e| e.incident_id == Some(incident_id))
            .cloned()
            .collect()
    }

    /// Gets entries by event type.
    pub async fn get_entries_by_type(&self, event_type: AuditEventType) -> Vec<AuditLogEntry> {
        let entries = self.entries.read().await;
        entries
            .iter()
            .filter(|e| e.event_type == event_type)
            .cloned()
            .collect()
    }

    /// Gets entries within a time range.
    pub async fn get_entries_in_range(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Vec<AuditLogEntry> {
        let entries = self.entries.read().await;
        entries
            .iter()
            .filter(|e| e.timestamp >= start && e.timestamp <= end)
            .cloned()
            .collect()
    }

    /// Gets entries by actor.
    pub async fn get_entries_by_actor(&self, actor: &str) -> Vec<AuditLogEntry> {
        let entries = self.entries.read().await;
        entries
            .iter()
            .filter(|e| e.actor == actor)
            .cloned()
            .collect()
    }

    /// Logs a security event (convenience method for security-related events).
    pub async fn log_security_event(
        &self,
        event_type: AuditEventType,
        actor: &str,
        description: &str,
        details: serde_json::Value,
        result: AuditResult,
    ) {
        let entry = AuditLogEntry {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_type,
            actor: actor.to_string(),
            incident_id: None,
            action_id: None,
            description: description.to_string(),
            details,
            result,
        };
        self.log(entry).await;
    }

    /// Logs a login attempt.
    pub async fn log_login_attempt(&self, username: &str, ip_address: &str, success: bool) {
        let event_type = if success {
            AuditEventType::LoginSuccess
        } else {
            AuditEventType::LoginFailure
        };
        let result = if success {
            AuditResult::Success
        } else {
            AuditResult::Failure("Invalid credentials".to_string())
        };
        let description = if success {
            format!("User '{}' logged in successfully", username)
        } else {
            format!("Failed login attempt for user '{}'", username)
        };

        self.log_security_event(
            event_type,
            username,
            &description,
            serde_json::json!({
                "ip_address": ip_address,
                "username": username,
            }),
            result,
        )
        .await;
    }

    /// Logs an API key event.
    pub async fn log_api_key_event(
        &self,
        event_type: AuditEventType,
        actor: &str,
        key_prefix: &str,
        user_id: Option<Uuid>,
    ) {
        let description = match &event_type {
            AuditEventType::ApiKeyCreated => format!("API key '{}' created", key_prefix),
            AuditEventType::ApiKeyRevoked => format!("API key '{}' revoked", key_prefix),
            AuditEventType::ApiKeyUsed => {
                format!("API key '{}' used for authentication", key_prefix)
            }
            _ => format!("API key event for '{}'", key_prefix),
        };

        self.log_security_event(
            event_type,
            actor,
            &description,
            serde_json::json!({
                "key_prefix": key_prefix,
                "user_id": user_id,
            }),
            AuditResult::Success,
        )
        .await;
    }

    /// Logs a rate limit exceeded event.
    pub async fn log_rate_limit_exceeded(&self, ip_address: &str, endpoint: &str) {
        self.log_security_event(
            AuditEventType::RateLimitExceeded,
            ip_address,
            &format!("Rate limit exceeded for endpoint '{}'", endpoint),
            serde_json::json!({
                "ip_address": ip_address,
                "endpoint": endpoint,
            }),
            AuditResult::Denied("Rate limit exceeded".to_string()),
        )
        .await;
    }

    /// Logs a permission denied event.
    pub async fn log_permission_denied(
        &self,
        actor: &str,
        resource: &str,
        required_permission: &str,
    ) {
        self.log_security_event(
            AuditEventType::PermissionDenied,
            actor,
            &format!(
                "Permission denied for resource '{}', required: {}",
                resource, required_permission
            ),
            serde_json::json!({
                "resource": resource,
                "required_permission": required_permission,
            }),
            AuditResult::Denied(format!("Missing permission: {}", required_permission)),
        )
        .await;
    }

    /// Gets security-related entries (login, API key, permission events).
    pub async fn get_security_entries(&self) -> Vec<AuditLogEntry> {
        let entries = self.entries.read().await;
        entries
            .iter()
            .filter(|e| {
                matches!(
                    e.event_type,
                    AuditEventType::LoginSuccess
                        | AuditEventType::LoginFailure
                        | AuditEventType::ApiKeyCreated
                        | AuditEventType::ApiKeyRevoked
                        | AuditEventType::ApiKeyUsed
                        | AuditEventType::PermissionDenied
                        | AuditEventType::RateLimitExceeded
                        | AuditEventType::SessionCreated
                        | AuditEventType::SessionExpired
                        | AuditEventType::SessionInvalidated
                        | AuditEventType::AccountDisabled
                        | AuditEventType::AccountEnabled
                        | AuditEventType::PasswordChanged
                        | AuditEventType::UserCreated
                        | AuditEventType::UserDeleted
                        | AuditEventType::UserRoleChanged
                        | AuditEventType::WebhookSignatureInvalid
                        | AuditEventType::SuspiciousActivity
                )
            })
            .cloned()
            .collect()
    }

    /// Exports entries as JSON.
    pub async fn export_json(&self) -> String {
        let entries = self.get_entries().await;
        serde_json::to_string_pretty(&entries).unwrap_or_else(|_| "[]".to_string())
    }

    /// Gets the number of entries.
    pub async fn len(&self) -> usize {
        self.entries.read().await.len()
    }

    /// Checks if the audit log is empty.
    pub async fn is_empty(&self) -> bool {
        self.entries.read().await.is_empty()
    }

    /// Clears all entries.
    pub async fn clear(&self) {
        self.entries.write().await.clear();
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new(10000)
    }
}

// =============================================================================
// Action Audit Logging
// =============================================================================

/// Sensitive parameter names that should be masked in audit logs.
const SENSITIVE_PARAMS: &[&str] = &[
    "api_key",
    "apikey",
    "api-key",
    "password",
    "passwd",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "bearer",
    "authorization",
    "auth",
    "credential",
    "credentials",
    "private_key",
    "privatekey",
    "secret_key",
    "secretkey",
    "client_secret",
    "webhook_secret",
];

/// The masked value used to replace sensitive parameters.
const MASKED_VALUE: &str = "[REDACTED]";

/// Detailed audit entry for action execution.
///
/// This struct captures comprehensive information about an action execution
/// for compliance, forensics, and debugging purposes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionAuditEntry {
    /// Unique identifier for this audit entry.
    pub id: Uuid,
    /// Correlation ID for linking related audit entries (e.g., request chain).
    pub correlation_id: Uuid,
    /// Timestamp when the action started.
    pub timestamp: DateTime<Utc>,
    /// Unique identifier of the actor executing the action.
    pub actor_id: Uuid,
    /// Human-readable actor name (username or service name).
    pub actor_username: String,
    /// Role of the actor at the time of execution.
    pub actor_role: String,
    /// IP address of the actor (if available).
    pub actor_ip: Option<String>,
    /// Session ID (if available).
    pub session_id: Option<String>,
    /// Name of the action being executed.
    pub action_name: String,
    /// Target of the action (e.g., hostname, user ID, email address).
    pub target: Option<String>,
    /// Incident ID associated with this action (if any).
    pub incident_id: Option<Uuid>,
    /// Masked action parameters (sensitive values redacted).
    pub parameters: HashMap<String, serde_json::Value>,
    /// Whether this was a dry run.
    pub dry_run: bool,
    /// Result of the action execution.
    pub result: ActionAuditResult,
    /// Human-readable result message.
    pub result_message: String,
    /// Duration of the action execution in milliseconds.
    pub duration_ms: u64,
    /// Additional metadata for the action.
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Result of an action execution for audit purposes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ActionAuditResult {
    /// Action completed successfully.
    Success,
    /// Action failed during execution.
    Failure,
    /// Action was denied by authorization.
    Denied,
    /// Action timed out.
    Timeout,
    /// Action was skipped (e.g., dry run).
    Skipped,
}

impl ActionAuditEntry {
    /// Creates a new action audit entry builder.
    pub fn builder(
        correlation_id: Uuid,
        actor_id: Uuid,
        actor_username: impl Into<String>,
        actor_role: impl Into<String>,
        action_name: impl Into<String>,
    ) -> ActionAuditEntryBuilder {
        ActionAuditEntryBuilder {
            correlation_id,
            actor_id,
            actor_username: actor_username.into(),
            actor_role: actor_role.into(),
            actor_ip: None,
            session_id: None,
            action_name: action_name.into(),
            target: None,
            incident_id: None,
            parameters: HashMap::new(),
            dry_run: false,
            metadata: HashMap::new(),
        }
    }

    /// Exports the audit entry as a structured JSON string.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }

    /// Exports the audit entry as a pretty-printed JSON string.
    pub fn to_json_pretty(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }
}

/// Builder for constructing ActionAuditEntry instances.
pub struct ActionAuditEntryBuilder {
    correlation_id: Uuid,
    actor_id: Uuid,
    actor_username: String,
    actor_role: String,
    actor_ip: Option<String>,
    session_id: Option<String>,
    action_name: String,
    target: Option<String>,
    incident_id: Option<Uuid>,
    parameters: HashMap<String, serde_json::Value>,
    dry_run: bool,
    metadata: HashMap<String, serde_json::Value>,
}

impl ActionAuditEntryBuilder {
    /// Sets the actor's IP address.
    pub fn with_actor_ip(mut self, ip: impl Into<String>) -> Self {
        self.actor_ip = Some(ip.into());
        self
    }

    /// Sets the session ID.
    pub fn with_session_id(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    /// Sets the action target.
    pub fn with_target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }

    /// Sets the incident ID.
    pub fn with_incident_id(mut self, incident_id: Uuid) -> Self {
        self.incident_id = Some(incident_id);
        self
    }

    /// Sets the action parameters (will be automatically masked).
    pub fn with_parameters(mut self, params: HashMap<String, serde_json::Value>) -> Self {
        self.parameters = mask_sensitive_parameters(&params);
        self
    }

    /// Sets the dry run flag.
    pub fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }

    /// Adds metadata to the audit entry.
    pub fn with_metadata(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }

    /// Builds the audit entry with a successful result.
    pub fn success(self, message: impl Into<String>, duration_ms: u64) -> ActionAuditEntry {
        self.build(ActionAuditResult::Success, message, duration_ms)
    }

    /// Builds the audit entry with a failure result.
    pub fn failure(self, message: impl Into<String>, duration_ms: u64) -> ActionAuditEntry {
        self.build(ActionAuditResult::Failure, message, duration_ms)
    }

    /// Builds the audit entry with a denied result.
    pub fn denied(self, message: impl Into<String>, duration_ms: u64) -> ActionAuditEntry {
        self.build(ActionAuditResult::Denied, message, duration_ms)
    }

    /// Builds the audit entry with a timeout result.
    pub fn timeout(self, message: impl Into<String>, duration_ms: u64) -> ActionAuditEntry {
        self.build(ActionAuditResult::Timeout, message, duration_ms)
    }

    /// Builds the audit entry with a skipped result.
    pub fn skipped(self, message: impl Into<String>, duration_ms: u64) -> ActionAuditEntry {
        self.build(ActionAuditResult::Skipped, message, duration_ms)
    }

    /// Builds the audit entry with the specified result.
    fn build(
        self,
        result: ActionAuditResult,
        message: impl Into<String>,
        duration_ms: u64,
    ) -> ActionAuditEntry {
        ActionAuditEntry {
            id: Uuid::new_v4(),
            correlation_id: self.correlation_id,
            timestamp: Utc::now(),
            actor_id: self.actor_id,
            actor_username: self.actor_username,
            actor_role: self.actor_role,
            actor_ip: self.actor_ip,
            session_id: self.session_id,
            action_name: self.action_name,
            target: self.target,
            incident_id: self.incident_id,
            parameters: self.parameters,
            dry_run: self.dry_run,
            result,
            result_message: message.into(),
            duration_ms,
            metadata: self.metadata,
        }
    }
}

/// Masks sensitive parameters in a parameter map.
///
/// This function replaces the values of sensitive parameters (like passwords,
/// API keys, tokens, etc.) with a masked placeholder to prevent sensitive
/// data from appearing in audit logs.
pub fn mask_sensitive_parameters(
    params: &HashMap<String, serde_json::Value>,
) -> HashMap<String, serde_json::Value> {
    params
        .iter()
        .map(|(key, value)| {
            let masked_value = if is_sensitive_param(key) {
                serde_json::json!(MASKED_VALUE)
            } else {
                mask_sensitive_in_value(value)
            };
            (key.clone(), masked_value)
        })
        .collect()
}

/// Checks if a parameter name indicates a sensitive value.
fn is_sensitive_param(name: &str) -> bool {
    let lower = name.to_lowercase();
    SENSITIVE_PARAMS.iter().any(|&sensitive| {
        lower == sensitive
            || lower.contains(sensitive)
            || lower.ends_with("_key")
            || lower.ends_with("_token")
            || lower.ends_with("_secret")
            || lower.ends_with("_password")
    })
}

/// Recursively masks sensitive values within a JSON value.
fn mask_sensitive_in_value(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let masked_map: serde_json::Map<String, serde_json::Value> = map
                .iter()
                .map(|(k, v)| {
                    let masked_v = if is_sensitive_param(k) {
                        serde_json::json!(MASKED_VALUE)
                    } else {
                        mask_sensitive_in_value(v)
                    };
                    (k.clone(), masked_v)
                })
                .collect();
            serde_json::Value::Object(masked_map)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(mask_sensitive_in_value).collect())
        }
        _ => value.clone(),
    }
}

/// Action audit log with dedicated storage for action execution records.
pub struct ActionAuditLog {
    /// In-memory action audit entries.
    entries: Arc<RwLock<VecDeque<ActionAuditEntry>>>,
    /// Maximum entries to keep in memory.
    max_entries: usize,
    /// Whether to also log to tracing.
    log_to_tracing: bool,
}

impl ActionAuditLog {
    /// Creates a new action audit log.
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: Arc::new(RwLock::new(VecDeque::with_capacity(max_entries))),
            max_entries,
            log_to_tracing: true,
        }
    }

    /// Creates an action audit log without tracing output.
    pub fn without_tracing(max_entries: usize) -> Self {
        Self {
            entries: Arc::new(RwLock::new(VecDeque::with_capacity(max_entries))),
            max_entries,
            log_to_tracing: false,
        }
    }

    /// Logs an action audit entry.
    pub async fn log(&self, entry: ActionAuditEntry) {
        if self.log_to_tracing {
            // Log as structured JSON for log aggregation systems
            info!(
                target: "action_audit",
                correlation_id = %entry.correlation_id,
                actor_id = %entry.actor_id,
                actor_username = %entry.actor_username,
                action_name = %entry.action_name,
                target = ?entry.target,
                incident_id = ?entry.incident_id,
                result = ?entry.result,
                duration_ms = entry.duration_ms,
                dry_run = entry.dry_run,
                "Action audit: {} by {} - {:?} ({} ms)",
                entry.action_name,
                entry.actor_username,
                entry.result,
                entry.duration_ms
            );
        }

        let mut entries = self.entries.write().await;
        if entries.len() >= self.max_entries {
            entries.pop_front();
        }
        entries.push_back(entry);
    }

    /// Gets all action audit entries.
    pub async fn get_entries(&self) -> Vec<ActionAuditEntry> {
        self.entries.read().await.iter().cloned().collect()
    }

    /// Gets action audit entries by correlation ID.
    pub async fn get_by_correlation_id(&self, correlation_id: Uuid) -> Vec<ActionAuditEntry> {
        self.entries
            .read()
            .await
            .iter()
            .filter(|e| e.correlation_id == correlation_id)
            .cloned()
            .collect()
    }

    /// Gets action audit entries by actor ID.
    pub async fn get_by_actor_id(&self, actor_id: Uuid) -> Vec<ActionAuditEntry> {
        self.entries
            .read()
            .await
            .iter()
            .filter(|e| e.actor_id == actor_id)
            .cloned()
            .collect()
    }

    /// Gets action audit entries by action name.
    pub async fn get_by_action_name(&self, action_name: &str) -> Vec<ActionAuditEntry> {
        self.entries
            .read()
            .await
            .iter()
            .filter(|e| e.action_name == action_name)
            .cloned()
            .collect()
    }

    /// Gets action audit entries by incident ID.
    pub async fn get_by_incident_id(&self, incident_id: Uuid) -> Vec<ActionAuditEntry> {
        self.entries
            .read()
            .await
            .iter()
            .filter(|e| e.incident_id == Some(incident_id))
            .cloned()
            .collect()
    }

    /// Gets action audit entries by result type.
    pub async fn get_by_result(&self, result: ActionAuditResult) -> Vec<ActionAuditEntry> {
        self.entries
            .read()
            .await
            .iter()
            .filter(|e| e.result == result)
            .cloned()
            .collect()
    }

    /// Gets action audit entries within a time range.
    pub async fn get_in_time_range(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Vec<ActionAuditEntry> {
        self.entries
            .read()
            .await
            .iter()
            .filter(|e| e.timestamp >= start && e.timestamp <= end)
            .cloned()
            .collect()
    }

    /// Exports all entries as JSON.
    pub async fn export_json(&self) -> String {
        let entries = self.get_entries().await;
        serde_json::to_string_pretty(&entries).unwrap_or_else(|_| "[]".to_string())
    }

    /// Exports entries as newline-delimited JSON (NDJSON) for log streaming.
    pub async fn export_ndjson(&self) -> String {
        let entries = self.get_entries().await;
        entries
            .iter()
            .map(|e| e.to_json())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Gets the number of entries.
    pub async fn len(&self) -> usize {
        self.entries.read().await.len()
    }

    /// Checks if the action audit log is empty.
    pub async fn is_empty(&self) -> bool {
        self.entries.read().await.is_empty()
    }

    /// Clears all entries.
    pub async fn clear(&self) {
        self.entries.write().await.clear();
    }
}

impl Default for ActionAuditLog {
    fn default() -> Self {
        Self::new(10000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_log_event() {
        let audit_log = AuditLog::without_tracing(100);

        audit_log
            .log_event(
                AuditEventType::SystemLifecycle,
                "system",
                "System started",
                AuditResult::Success,
            )
            .await;

        let entries = audit_log.get_entries().await;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].event_type, AuditEventType::SystemLifecycle);
    }

    #[tokio::test]
    async fn test_incident_event() {
        let audit_log = AuditLog::without_tracing(100);
        let incident_id = Uuid::new_v4();

        audit_log
            .log_incident_event(
                AuditEventType::IncidentCreated,
                "ai",
                incident_id,
                "Incident created from alert",
                serde_json::json!({"severity": "high"}),
                AuditResult::Success,
            )
            .await;

        let entries = audit_log.get_incident_entries(incident_id).await;
        assert_eq!(entries.len(), 1);
    }

    #[tokio::test]
    async fn test_max_entries() {
        let audit_log = AuditLog::without_tracing(5);

        for i in 0..10 {
            audit_log
                .log_event(
                    AuditEventType::Custom(format!("event-{}", i)),
                    "test",
                    &format!("Event {}", i),
                    AuditResult::Success,
                )
                .await;
        }

        assert_eq!(audit_log.len().await, 5);

        // First events should have been evicted
        let entries = audit_log.get_entries().await;
        assert!(matches!(
            &entries[0].event_type,
            AuditEventType::Custom(s) if s == "event-5"
        ));
    }

    #[tokio::test]
    async fn test_get_by_actor() {
        let audit_log = AuditLog::without_tracing(100);

        audit_log
            .log_event(
                AuditEventType::ActionApproved,
                "analyst@company.com",
                "Action approved",
                AuditResult::Success,
            )
            .await;

        audit_log
            .log_event(
                AuditEventType::ActionExecuted,
                "system",
                "Action executed",
                AuditResult::Success,
            )
            .await;

        let analyst_entries = audit_log.get_entries_by_actor("analyst@company.com").await;
        assert_eq!(analyst_entries.len(), 1);

        let system_entries = audit_log.get_entries_by_actor("system").await;
        assert_eq!(system_entries.len(), 1);
    }

    #[tokio::test]
    async fn test_export_json() {
        let audit_log = AuditLog::without_tracing(100);

        audit_log
            .log_event(
                AuditEventType::SystemLifecycle,
                "system",
                "Test event",
                AuditResult::Success,
            )
            .await;

        let json = audit_log.export_json().await;
        assert!(json.contains("SystemLifecycle") || json.contains("system_lifecycle"));
    }

    // ==========================================================================
    // Action Audit Entry Tests
    // ==========================================================================

    #[test]
    fn test_action_audit_entry_builder_success() {
        let correlation_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();

        let entry = ActionAuditEntry::builder(
            correlation_id,
            actor_id,
            "analyst@example.com",
            "analyst",
            "isolate_host",
        )
        .with_target("web-server-01")
        .with_incident_id(Uuid::new_v4())
        .success("Host isolated successfully", 150);

        assert_eq!(entry.correlation_id, correlation_id);
        assert_eq!(entry.actor_id, actor_id);
        assert_eq!(entry.actor_username, "analyst@example.com");
        assert_eq!(entry.actor_role, "analyst");
        assert_eq!(entry.action_name, "isolate_host");
        assert_eq!(entry.target, Some("web-server-01".to_string()));
        assert_eq!(entry.result, ActionAuditResult::Success);
        assert_eq!(entry.result_message, "Host isolated successfully");
        assert_eq!(entry.duration_ms, 150);
    }

    #[test]
    fn test_action_audit_entry_builder_failure() {
        let entry = ActionAuditEntry::builder(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "system",
            "admin",
            "block_sender",
        )
        .with_target("malicious@example.com")
        .failure("Connection timeout to mail server", 5000);

        assert_eq!(entry.result, ActionAuditResult::Failure);
        assert_eq!(entry.result_message, "Connection timeout to mail server");
    }

    #[test]
    fn test_action_audit_entry_builder_denied() {
        let entry = ActionAuditEntry::builder(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "viewer@example.com",
            "viewer",
            "disable_user",
        )
        .denied("Insufficient permissions: ExecuteActions required", 5);

        assert_eq!(entry.result, ActionAuditResult::Denied);
    }

    #[test]
    fn test_action_audit_entry_builder_timeout() {
        let entry = ActionAuditEntry::builder(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "analyst@example.com",
            "analyst",
            "quarantine_email",
        )
        .timeout("Action did not complete within 60 seconds", 60000);

        assert_eq!(entry.result, ActionAuditResult::Timeout);
    }

    #[test]
    fn test_action_audit_entry_builder_skipped() {
        let entry = ActionAuditEntry::builder(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "analyst@example.com",
            "analyst",
            "isolate_host",
        )
        .with_dry_run(true)
        .skipped("Dry run - action would be executed", 10);

        assert_eq!(entry.result, ActionAuditResult::Skipped);
        assert!(entry.dry_run);
    }

    #[test]
    fn test_action_audit_entry_to_json() {
        let entry = ActionAuditEntry::builder(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "analyst@example.com",
            "analyst",
            "isolate_host",
        )
        .success("Host isolated", 100);

        let json = entry.to_json();
        assert!(json.contains("isolate_host"));
        assert!(json.contains("analyst@example.com"));
        assert!(json.contains("success"));
    }

    #[test]
    fn test_mask_sensitive_parameters_basic() {
        let mut params = HashMap::new();
        params.insert("target".to_string(), serde_json::json!("host-01"));
        params.insert("api_key".to_string(), serde_json::json!("secret123"));
        params.insert("password".to_string(), serde_json::json!("hunter2"));
        params.insert("normal_param".to_string(), serde_json::json!("value"));

        let masked = mask_sensitive_parameters(&params);

        assert_eq!(masked.get("target").unwrap(), &serde_json::json!("host-01"));
        assert_eq!(
            masked.get("api_key").unwrap(),
            &serde_json::json!("[REDACTED]")
        );
        assert_eq!(
            masked.get("password").unwrap(),
            &serde_json::json!("[REDACTED]")
        );
        assert_eq!(
            masked.get("normal_param").unwrap(),
            &serde_json::json!("value")
        );
    }

    #[test]
    fn test_mask_sensitive_parameters_nested() {
        let mut params = HashMap::new();
        params.insert(
            "config".to_string(),
            serde_json::json!({
                "host": "localhost",
                "connection_info": {
                    "api_key": "secret123",
                    "username": "admin"
                }
            }),
        );

        let masked = mask_sensitive_parameters(&params);
        let config = masked.get("config").unwrap().as_object().unwrap();
        let connection_info = config.get("connection_info").unwrap().as_object().unwrap();

        assert_eq!(connection_info.get("api_key").unwrap(), "[REDACTED]");
        assert_eq!(connection_info.get("username").unwrap(), "admin");
    }

    #[test]
    fn test_mask_sensitive_parameters_array() {
        let mut params = HashMap::new();
        params.insert(
            "items".to_string(),
            serde_json::json!([
                {"name": "item1", "token": "abc123"},
                {"name": "item2", "value": "normal"}
            ]),
        );

        let masked = mask_sensitive_parameters(&params);
        let items = masked.get("items").unwrap().as_array().unwrap();

        let item1 = items[0].as_object().unwrap();
        assert_eq!(item1.get("token").unwrap(), "[REDACTED]");

        let item2 = items[1].as_object().unwrap();
        assert_eq!(item2.get("value").unwrap(), "normal");
    }

    #[test]
    fn test_mask_sensitive_parameters_suffix_patterns() {
        let mut params = HashMap::new();
        params.insert("service_api_key".to_string(), serde_json::json!("key123"));
        params.insert("oauth_token".to_string(), serde_json::json!("token123"));
        params.insert("client_secret".to_string(), serde_json::json!("secret123"));
        params.insert("admin_password".to_string(), serde_json::json!("pass123"));

        let masked = mask_sensitive_parameters(&params);

        assert_eq!(
            masked.get("service_api_key").unwrap(),
            &serde_json::json!("[REDACTED]")
        );
        assert_eq!(
            masked.get("oauth_token").unwrap(),
            &serde_json::json!("[REDACTED]")
        );
        assert_eq!(
            masked.get("client_secret").unwrap(),
            &serde_json::json!("[REDACTED]")
        );
        assert_eq!(
            masked.get("admin_password").unwrap(),
            &serde_json::json!("[REDACTED]")
        );
    }

    #[test]
    fn test_is_sensitive_param() {
        assert!(is_sensitive_param("api_key"));
        assert!(is_sensitive_param("API_KEY"));
        assert!(is_sensitive_param("password"));
        assert!(is_sensitive_param("secret"));
        assert!(is_sensitive_param("token"));
        assert!(is_sensitive_param("access_token"));
        assert!(is_sensitive_param("refresh_token"));
        assert!(is_sensitive_param("authorization"));
        assert!(is_sensitive_param("credential"));
        assert!(is_sensitive_param("private_key"));
        assert!(is_sensitive_param("client_secret"));
        assert!(is_sensitive_param("service_api_key"));
        assert!(is_sensitive_param("oauth_token"));
        assert!(is_sensitive_param("db_password"));

        assert!(!is_sensitive_param("hostname"));
        assert!(!is_sensitive_param("port"));
        assert!(!is_sensitive_param("target"));
        assert!(!is_sensitive_param("action_name"));
    }

    #[tokio::test]
    async fn test_action_audit_log_basic() {
        let audit_log = ActionAuditLog::without_tracing(100);

        let entry = ActionAuditEntry::builder(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "analyst@example.com",
            "analyst",
            "isolate_host",
        )
        .success("Host isolated", 100);

        audit_log.log(entry).await;

        assert_eq!(audit_log.len().await, 1);
        let entries = audit_log.get_entries().await;
        assert_eq!(entries[0].action_name, "isolate_host");
    }

    #[tokio::test]
    async fn test_action_audit_log_by_actor_id() {
        let audit_log = ActionAuditLog::without_tracing(100);
        let actor_id = Uuid::new_v4();

        let entry1 = ActionAuditEntry::builder(
            Uuid::new_v4(),
            actor_id,
            "analyst@example.com",
            "analyst",
            "isolate_host",
        )
        .success("Success", 100);

        let entry2 = ActionAuditEntry::builder(
            Uuid::new_v4(),
            Uuid::new_v4(), // Different actor
            "admin@example.com",
            "admin",
            "disable_user",
        )
        .success("Success", 50);

        audit_log.log(entry1).await;
        audit_log.log(entry2).await;

        let by_actor = audit_log.get_by_actor_id(actor_id).await;
        assert_eq!(by_actor.len(), 1);
        assert_eq!(by_actor[0].actor_username, "analyst@example.com");
    }

    #[tokio::test]
    async fn test_action_audit_log_by_correlation_id() {
        let audit_log = ActionAuditLog::without_tracing(100);
        let correlation_id = Uuid::new_v4();

        let entry1 = ActionAuditEntry::builder(
            correlation_id,
            Uuid::new_v4(),
            "analyst@example.com",
            "analyst",
            "isolate_host",
        )
        .success("Step 1", 100);

        let entry2 = ActionAuditEntry::builder(
            correlation_id,
            Uuid::new_v4(),
            "system",
            "system",
            "notify_user",
        )
        .success("Step 2", 50);

        let entry3 = ActionAuditEntry::builder(
            Uuid::new_v4(), // Different correlation
            Uuid::new_v4(),
            "admin@example.com",
            "admin",
            "disable_user",
        )
        .success("Unrelated", 30);

        audit_log.log(entry1).await;
        audit_log.log(entry2).await;
        audit_log.log(entry3).await;

        let by_correlation = audit_log.get_by_correlation_id(correlation_id).await;
        assert_eq!(by_correlation.len(), 2);
    }

    #[tokio::test]
    async fn test_action_audit_log_by_result() {
        let audit_log = ActionAuditLog::without_tracing(100);

        let success_entry = ActionAuditEntry::builder(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "analyst@example.com",
            "analyst",
            "isolate_host",
        )
        .success("Success", 100);

        let failure_entry = ActionAuditEntry::builder(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "analyst@example.com",
            "analyst",
            "block_sender",
        )
        .failure("Connection failed", 5000);

        audit_log.log(success_entry).await;
        audit_log.log(failure_entry).await;

        let successes = audit_log.get_by_result(ActionAuditResult::Success).await;
        assert_eq!(successes.len(), 1);

        let failures = audit_log.get_by_result(ActionAuditResult::Failure).await;
        assert_eq!(failures.len(), 1);
    }

    #[tokio::test]
    async fn test_action_audit_log_max_entries() {
        let audit_log = ActionAuditLog::without_tracing(3);

        for i in 0..5 {
            let entry = ActionAuditEntry::builder(
                Uuid::new_v4(),
                Uuid::new_v4(),
                format!("user{}@example.com", i),
                "analyst",
                "test_action",
            )
            .success(format!("Entry {}", i), i as u64 * 10);

            audit_log.log(entry).await;
        }

        assert_eq!(audit_log.len().await, 3);

        let entries = audit_log.get_entries().await;
        // Should have entries 2, 3, 4 (0 and 1 were evicted)
        assert_eq!(entries[0].actor_username, "user2@example.com");
        assert_eq!(entries[2].actor_username, "user4@example.com");
    }

    #[tokio::test]
    async fn test_action_audit_log_export_ndjson() {
        let audit_log = ActionAuditLog::without_tracing(100);

        for i in 0..3 {
            let entry = ActionAuditEntry::builder(
                Uuid::new_v4(),
                Uuid::new_v4(),
                format!("user{}@example.com", i),
                "analyst",
                "test_action",
            )
            .success(format!("Entry {}", i), i as u64 * 10);

            audit_log.log(entry).await;
        }

        let ndjson = audit_log.export_ndjson().await;
        let lines: Vec<&str> = ndjson.lines().collect();
        assert_eq!(lines.len(), 3);

        // Each line should be valid JSON
        for line in lines {
            assert!(serde_json::from_str::<ActionAuditEntry>(line).is_ok());
        }
    }

    #[test]
    fn test_action_audit_entry_with_full_metadata() {
        let correlation_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();
        let incident_id = Uuid::new_v4();

        let mut params = HashMap::new();
        params.insert("target".to_string(), serde_json::json!("host-01"));
        params.insert("api_key".to_string(), serde_json::json!("secret123"));

        let entry = ActionAuditEntry::builder(
            correlation_id,
            actor_id,
            "analyst@example.com",
            "analyst",
            "isolate_host",
        )
        .with_actor_ip("192.168.1.100")
        .with_session_id("session-abc123")
        .with_target("host-01")
        .with_incident_id(incident_id)
        .with_parameters(params)
        .with_dry_run(false)
        .with_metadata("playbook", serde_json::json!("incident-response-01"))
        .success("Host isolated successfully", 250);

        assert_eq!(entry.actor_ip, Some("192.168.1.100".to_string()));
        assert_eq!(entry.session_id, Some("session-abc123".to_string()));
        assert_eq!(entry.incident_id, Some(incident_id));
        assert!(!entry.dry_run);

        // Verify sensitive parameters are masked
        assert_eq!(
            entry.parameters.get("api_key").unwrap(),
            &serde_json::json!("[REDACTED]")
        );
        assert_eq!(
            entry.parameters.get("target").unwrap(),
            &serde_json::json!("host-01")
        );

        // Verify metadata
        assert_eq!(
            entry.metadata.get("playbook").unwrap(),
            &serde_json::json!("incident-response-01")
        );
    }
}
