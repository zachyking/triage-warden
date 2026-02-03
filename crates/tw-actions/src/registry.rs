//! Action registry for Triage Warden.
//!
//! This module provides the action trait definition and registry for
//! managing and executing automated response actions.
//!
//! # Audit Logging
//!
//! The registry provides comprehensive audit logging for all action executions:
//! - Actor identity tracking (user ID, username, role, IP address)
//! - Automatic masking of sensitive parameters
//! - Correlation IDs for linking related operations
//! - Duration tracking for performance monitoring
//! - Prometheus metrics for observability

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, info, instrument, warn};
use tw_core::{is_destructive_action, AuthorizationContext};
use tw_observability::{
    ActionAuditEntry, ActionAuditLog, ActionAuditResult as AuditResult, MetricsCollector,
};
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

/// Errors that can occur during action execution.
#[derive(Error, Debug)]
pub enum ActionError {
    #[error("Action not found: {0}")]
    NotFound(String),

    #[error("Invalid parameters: {0}")]
    InvalidParameters(String),

    #[error("Execution failed: {0}")]
    ExecutionFailed(String),

    #[error("Connector error: {0}")]
    ConnectorError(String),

    #[error("Timeout: action did not complete within {0} seconds")]
    Timeout(u64),

    #[error("Rollback failed: {0}")]
    RollbackFailed(String),

    #[error("Rollback data integrity check failed: data has been tampered with")]
    RollbackDataTampered,

    #[error("Invalid rollback data format: {0}")]
    InvalidRollbackData(String),

    #[error("Action not supported: {0}")]
    NotSupported(String),

    #[error("Action requires manual approval: {0}")]
    RequiresApproval(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),
}

/// Result of an action execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResult {
    /// Unique execution ID.
    pub execution_id: Uuid,
    /// Action name.
    pub action_name: String,
    /// Whether the action succeeded.
    pub success: bool,
    /// Result message.
    pub message: String,
    /// Execution start time.
    pub started_at: DateTime<Utc>,
    /// Execution end time.
    pub completed_at: DateTime<Utc>,
    /// Duration in milliseconds.
    pub duration_ms: u64,
    /// Additional output data.
    pub output: HashMap<String, serde_json::Value>,
    /// Whether the action can be rolled back.
    pub rollback_available: bool,
    /// Rollback data (if rollback is available).
    pub rollback_data: Option<serde_json::Value>,
}

impl ActionResult {
    /// Creates a successful result.
    pub fn success(
        action_name: &str,
        message: &str,
        started_at: DateTime<Utc>,
        output: HashMap<String, serde_json::Value>,
    ) -> Self {
        let completed_at = Utc::now();
        Self {
            execution_id: Uuid::new_v4(),
            action_name: action_name.to_string(),
            success: true,
            message: message.to_string(),
            started_at,
            completed_at,
            duration_ms: (completed_at - started_at).num_milliseconds() as u64,
            output,
            rollback_available: false,
            rollback_data: None,
        }
    }

    /// Creates a failed result.
    pub fn failure(action_name: &str, error: &str, started_at: DateTime<Utc>) -> Self {
        let completed_at = Utc::now();
        Self {
            execution_id: Uuid::new_v4(),
            action_name: action_name.to_string(),
            success: false,
            message: error.to_string(),
            started_at,
            completed_at,
            duration_ms: (completed_at - started_at).num_milliseconds() as u64,
            output: HashMap::new(),
            rollback_available: false,
            rollback_data: None,
        }
    }

    /// Marks the result as having rollback available.
    pub fn with_rollback(mut self, rollback_data: serde_json::Value) -> Self {
        self.rollback_available = true;
        self.rollback_data = Some(rollback_data);
        self
    }
}

/// Context provided to actions during execution.
#[derive(Debug, Clone)]
pub struct ActionContext {
    /// Incident ID this action is for.
    pub incident_id: Uuid,
    /// Action parameters.
    pub parameters: HashMap<String, serde_json::Value>,
    /// Timeout in seconds.
    pub timeout_secs: u64,
    /// Whether this is a dry run.
    pub dry_run: bool,
    /// Additional context data.
    pub metadata: HashMap<String, serde_json::Value>,
    /// Permissions of the user executing this action.
    permissions: Vec<Permission>,
    /// Whether this action has been approved through the approval workflow.
    approved: bool,
    /// Permission level of the user who approved this action (if approved).
    approver_permission: Option<Permission>,
    /// Authorization context for the user executing this action.
    pub auth_context: Option<AuthorizationContext>,
}

impl ActionContext {
    /// Creates a new action context.
    pub fn new(incident_id: Uuid) -> Self {
        Self {
            incident_id,
            parameters: HashMap::new(),
            timeout_secs: 60,
            dry_run: false,
            metadata: HashMap::new(),
            permissions: vec![Permission::Operator], // Default permission
            approved: false,
            approver_permission: None,
            auth_context: None,
        }
    }

    /// Sets the authorization context.
    pub fn with_auth_context(mut self, auth_context: AuthorizationContext) -> Self {
        self.auth_context = Some(auth_context);
        self
    }

    /// Sets a parameter.
    pub fn with_param(mut self, key: &str, value: serde_json::Value) -> Self {
        self.parameters.insert(key.to_string(), value);
        self
    }

    /// Sets the timeout.
    pub fn with_timeout(mut self, timeout_secs: u64) -> Self {
        self.timeout_secs = timeout_secs;
        self
    }

    /// Sets dry run mode.
    pub fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }

    /// Adds a permission to the context (for the executing user).
    pub fn with_permission(mut self, permission: Permission) -> Self {
        if !self.permissions.contains(&permission) {
            self.permissions.push(permission);
        }
        self
    }

    /// Sets the permissions for the executing user.
    pub fn with_permissions(mut self, permissions: Vec<Permission>) -> Self {
        self.permissions = permissions;
        self
    }

    /// Marks this action as approved through the approval workflow.
    /// The approver_permission indicates the permission level of the approving user.
    pub fn with_approval(mut self, approver_permission: Permission) -> Self {
        self.approved = true;
        self.approver_permission = Some(approver_permission);
        self
    }

    /// Checks if the executing user has a specific permission.
    pub fn has_permission(&self, permission: Permission) -> bool {
        self.permissions.contains(&permission)
    }

    /// Checks if this action has been approved through the approval workflow.
    pub fn is_approved(&self) -> bool {
        self.approved
    }

    /// Checks if the approver has a specific permission.
    /// Returns false if not approved or if the approver doesn't have the permission.
    pub fn approval_has_permission(&self, permission: Permission) -> bool {
        self.approver_permission == Some(permission)
    }

    /// Gets a parameter value.
    pub fn get_param(&self, key: &str) -> Option<&serde_json::Value> {
        self.parameters.get(key)
    }

    /// Gets a parameter as a string.
    pub fn get_string(&self, key: &str) -> Option<String> {
        self.parameters
            .get(key)
            .and_then(|v| v.as_str())
            .map(String::from)
    }

    /// Gets a required parameter as a string.
    pub fn require_string(&self, key: &str) -> Result<String, ActionError> {
        self.get_string(key).ok_or_else(|| {
            ActionError::InvalidParameters(format!("Missing required parameter: {}", key))
        })
    }
}

/// Trait for action implementations.
#[async_trait]
pub trait Action: Send + Sync {
    /// Returns the action name.
    fn name(&self) -> &str;

    /// Returns the action description.
    fn description(&self) -> &str;

    /// Returns the required parameters for this action.
    fn required_parameters(&self) -> Vec<ParameterDef>;

    /// Validates the action parameters.
    fn validate(&self, context: &ActionContext) -> Result<(), ActionError> {
        for param in self.required_parameters() {
            if param.required && !context.parameters.contains_key(&param.name) {
                return Err(ActionError::InvalidParameters(format!(
                    "Missing required parameter: {}",
                    param.name
                )));
            }
        }
        Ok(())
    }

    /// Executes the action.
    async fn execute(&self, context: ActionContext) -> Result<ActionResult, ActionError>;

    /// Rolls back the action (if supported).
    async fn rollback(
        &self,
        _rollback_data: serde_json::Value,
    ) -> Result<ActionResult, ActionError> {
        Err(ActionError::NotSupported(format!(
            "Rollback not supported for action: {}",
            self.name()
        )))
    }

    /// Returns whether this action supports rollback.
    fn supports_rollback(&self) -> bool {
        false
    }
}

/// Definition of an action parameter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterDef {
    /// Parameter name.
    pub name: String,
    /// Parameter description.
    pub description: String,
    /// Parameter type.
    pub param_type: ParameterType,
    /// Whether the parameter is required.
    pub required: bool,
    /// Default value (if any).
    pub default: Option<serde_json::Value>,
}

impl ParameterDef {
    /// Creates a new required parameter definition.
    pub fn required(name: &str, description: &str, param_type: ParameterType) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            param_type,
            required: true,
            default: None,
        }
    }

    /// Creates a new optional parameter definition.
    pub fn optional(
        name: &str,
        description: &str,
        param_type: ParameterType,
        default: serde_json::Value,
    ) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            param_type,
            required: false,
            default: Some(default),
        }
    }
}

/// Types of action parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParameterType {
    String,
    Integer,
    Boolean,
    List,
    Object,
}

/// Permission levels for action execution and approval.
///
/// These permissions control what actions a user can perform and approve.
/// The approval workflow enforces that critical actions require approval
/// from users with appropriate permissions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    /// Standard operator permission - can execute most actions
    Operator,
    /// Security analyst - can execute security-related actions
    SecurityAnalyst,
    /// System administrator - can approve critical actions including
    /// emergency overrides for critical host isolation
    SystemAdmin,
    /// Read-only viewer - cannot execute actions
    Viewer,
}

/// HMAC-signed rollback data structure.
///
/// This wraps rollback data with an HMAC-SHA256 signature to prevent
/// malicious tampering with rollback instructions. The signature is
/// verified before any rollback operation is executed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedRollbackData {
    /// The actual rollback data payload.
    pub data: serde_json::Value,
    /// HMAC-SHA256 signature of the serialized data (hex-encoded).
    pub signature: String,
    /// Timestamp when the rollback data was created.
    pub created_at: DateTime<Utc>,
    /// Action name this rollback data is for.
    pub action_name: String,
    /// Execution ID this rollback corresponds to.
    pub execution_id: Uuid,
}

/// Context for rollback data signing operations.
const ROLLBACK_SIGNATURE_INFO: &[u8] = b"tw-rollback-signature-v1";

impl SignedRollbackData {
    /// Creates new signed rollback data.
    ///
    /// The signature is computed using HMAC-SHA256 with a key derived from
    /// the provided encryption key using HKDF.
    pub fn new(
        data: serde_json::Value,
        action_name: &str,
        execution_id: Uuid,
        encryption_key: &[u8],
    ) -> Result<Self, ActionError> {
        let created_at = Utc::now();

        // Create the unsigned structure first to compute signature
        let mut unsigned = Self {
            data: data.clone(),
            signature: String::new(),
            created_at,
            action_name: action_name.to_string(),
            execution_id,
        };

        // Compute and set signature
        unsigned.signature = unsigned.compute_signature(encryption_key)?;

        Ok(unsigned)
    }

    /// Derives a signing key from the encryption key using HKDF.
    fn derive_signing_key(encryption_key: &[u8]) -> Result<[u8; 32], ActionError> {
        let hk = Hkdf::<Sha256>::new(None, encryption_key);
        let mut signing_key = [0u8; 32];
        hk.expand(ROLLBACK_SIGNATURE_INFO, &mut signing_key)
            .map_err(|_| {
                ActionError::InvalidRollbackData("Failed to derive signing key".to_string())
            })?;
        Ok(signing_key)
    }

    /// Computes the HMAC signature for the rollback data.
    fn compute_signature(&self, encryption_key: &[u8]) -> Result<String, ActionError> {
        let signing_key = Self::derive_signing_key(encryption_key)?;

        // Create canonical message to sign: action_name|execution_id|created_at|data
        let message = format!(
            "{}|{}|{}|{}",
            self.action_name,
            self.execution_id,
            self.created_at.timestamp_millis(),
            serde_json::to_string(&self.data).map_err(|e| {
                ActionError::InvalidRollbackData(format!("Failed to serialize data: {}", e))
            })?
        );

        let mut mac = HmacSha256::new_from_slice(&signing_key).map_err(|_| {
            ActionError::InvalidRollbackData("Failed to create HMAC instance".to_string())
        })?;

        mac.update(message.as_bytes());
        let result = mac.finalize();

        Ok(hex::encode(result.into_bytes()))
    }

    /// Verifies the signature of the rollback data.
    ///
    /// Returns `Ok(())` if the signature is valid, or `Err(ActionError::RollbackDataTampered)`
    /// if the data has been modified.
    pub fn verify(&self, encryption_key: &[u8]) -> Result<(), ActionError> {
        let expected_signature = self.compute_signature(encryption_key)?;

        // Use constant-time comparison to prevent timing attacks
        if !constant_time_eq(self.signature.as_bytes(), expected_signature.as_bytes()) {
            warn!(
                action = %self.action_name,
                execution_id = %self.execution_id,
                "Rollback data signature verification failed - possible tampering detected"
            );
            return Err(ActionError::RollbackDataTampered);
        }

        debug!(
            action = %self.action_name,
            execution_id = %self.execution_id,
            "Rollback data signature verified successfully"
        );

        Ok(())
    }

    /// Parses signed rollback data from a JSON value.
    pub fn from_json(value: serde_json::Value) -> Result<Self, ActionError> {
        serde_json::from_value(value).map_err(|e| {
            ActionError::InvalidRollbackData(format!("Failed to parse signed rollback data: {}", e))
        })
    }

    /// Converts to JSON value for storage.
    pub fn to_json(&self) -> Result<serde_json::Value, ActionError> {
        serde_json::to_value(self).map_err(|e| {
            ActionError::InvalidRollbackData(format!(
                "Failed to serialize signed rollback data: {}",
                e
            ))
        })
    }
}

/// Constant-time byte comparison to prevent timing attacks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// Registry for managing available actions.
pub struct ActionRegistry {
    actions: HashMap<String, Arc<dyn Action>>,
    /// Encryption key used for signing rollback data.
    /// If None, signed rollback operations will fail.
    encryption_key: Option<Vec<u8>>,
    /// Action audit log for comprehensive action tracking.
    audit_log: Option<Arc<ActionAuditLog>>,
    /// Metrics collector for Prometheus metrics.
    metrics: Option<Arc<MetricsCollector>>,
}

impl ActionRegistry {
    /// Creates a new empty action registry.
    pub fn new() -> Self {
        Self {
            actions: HashMap::new(),
            encryption_key: None,
            audit_log: None,
            metrics: None,
        }
    }

    /// Creates a new action registry with an encryption key for signing rollback data.
    pub fn with_encryption_key(encryption_key: Vec<u8>) -> Self {
        Self {
            actions: HashMap::new(),
            encryption_key: Some(encryption_key),
            audit_log: None,
            metrics: None,
        }
    }

    /// Sets the encryption key for signing rollback data.
    pub fn set_encryption_key(&mut self, key: Vec<u8>) {
        self.encryption_key = Some(key);
    }

    /// Sets the audit log for action execution tracking.
    pub fn set_audit_log(&mut self, audit_log: Arc<ActionAuditLog>) {
        self.audit_log = Some(audit_log);
    }

    /// Creates a new action registry with audit logging enabled.
    pub fn with_audit_log(mut self, audit_log: Arc<ActionAuditLog>) -> Self {
        self.audit_log = Some(audit_log);
        self
    }

    /// Sets the metrics collector for Prometheus metrics.
    pub fn set_metrics(&mut self, metrics: Arc<MetricsCollector>) {
        self.metrics = Some(metrics);
    }

    /// Creates a new action registry with metrics collection enabled.
    pub fn with_metrics(mut self, metrics: Arc<MetricsCollector>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Gets the encryption key, returning an error if not configured.
    fn get_encryption_key(&self) -> Result<&[u8], ActionError> {
        self.encryption_key.as_deref().ok_or_else(|| {
            ActionError::InvalidRollbackData(
                "Encryption key not configured for rollback signing".to_string(),
            )
        })
    }

    /// Signs rollback data for secure storage.
    ///
    /// This creates a SignedRollbackData structure that includes an HMAC signature
    /// to detect tampering. The signature is derived from the configured encryption key.
    pub fn sign_rollback_data(
        &self,
        data: serde_json::Value,
        action_name: &str,
        execution_id: Uuid,
    ) -> Result<SignedRollbackData, ActionError> {
        let key = self.get_encryption_key()?;
        SignedRollbackData::new(data, action_name, execution_id, key)
    }

    /// Registers an action.
    pub fn register(&mut self, action: Arc<dyn Action>) {
        let name = action.name().to_string();
        info!("Registering action: {}", name);
        self.actions.insert(name, action);
    }

    /// Gets an action by name.
    pub fn get(&self, name: &str) -> Option<Arc<dyn Action>> {
        self.actions.get(name).cloned()
    }

    /// Lists all registered actions.
    pub fn list(&self) -> Vec<&str> {
        self.actions.keys().map(|s| s.as_str()).collect()
    }

    /// Executes an action by name with comprehensive audit logging.
    ///
    /// This method provides full audit trail including:
    /// - Actor identity (user ID, username, role, IP address)
    /// - Action parameters (with sensitive values automatically masked)
    /// - Execution duration and result
    /// - Correlation ID for linking related operations
    #[instrument(skip(self, context), fields(action = %name))]
    pub async fn execute(
        &self,
        name: &str,
        context: ActionContext,
    ) -> Result<ActionResult, ActionError> {
        self.execute_with_correlation(name, context, Uuid::new_v4())
            .await
    }

    /// Executes an action with a specific correlation ID for audit trail linking.
    ///
    /// Use this method when you need to link multiple action executions together
    /// in the audit log (e.g., actions in a playbook or workflow).
    #[instrument(skip(self, context), fields(action = %name, correlation_id = %correlation_id))]
    pub async fn execute_with_correlation(
        &self,
        name: &str,
        context: ActionContext,
        correlation_id: Uuid,
    ) -> Result<ActionResult, ActionError> {
        let start_time = Utc::now();
        let start_instant = std::time::Instant::now();

        let action = self
            .get(name)
            .ok_or_else(|| ActionError::NotFound(name.to_string()))?;

        // Authorization check
        let auth_context = context.auth_context.as_ref().ok_or_else(|| {
            let error = ActionError::Unauthorized(
                "No authorization context provided for action execution".to_string(),
            );
            // Log audit entry for missing auth context
            self.log_audit_denied(
                correlation_id,
                Uuid::nil(),
                "unknown",
                "unknown",
                None,
                None,
                name,
                context.incident_id,
                &context.parameters,
                context.dry_run,
                "No authorization context provided",
                start_instant.elapsed().as_millis() as u64,
            );
            error
        })?;

        // Extract actor information for audit logging
        let actor_id = auth_context.actor_id;
        let actor_username = auth_context.actor_name.clone();
        let actor_role = auth_context.role.as_str().to_string();
        let actor_ip = auth_context.ip_address.clone();
        let session_id = auth_context.session_id.clone();

        // Determine target from parameters (common patterns)
        let target = context
            .get_string("target")
            .or_else(|| context.get_string("hostname"))
            .or_else(|| context.get_string("host"))
            .or_else(|| context.get_string("email"))
            .or_else(|| context.get_string("user_id"))
            .or_else(|| context.get_string("sender"));

        // Check if this is a destructive action requiring approval permission
        if is_destructive_action(name) {
            if let Err(e) = auth_context.validate_destructive_permission() {
                warn!(
                    executor = %auth_context.audit_identity(),
                    action = %name,
                    "Authorization failed for destructive action: {}",
                    e
                );

                self.log_audit_denied(
                    correlation_id,
                    actor_id,
                    &actor_username,
                    &actor_role,
                    actor_ip.as_deref(),
                    session_id.as_deref(),
                    name,
                    context.incident_id,
                    &context.parameters,
                    context.dry_run,
                    &e.to_string(),
                    start_instant.elapsed().as_millis() as u64,
                );

                return Err(ActionError::Unauthorized(e.to_string()));
            }
        } else if let Err(e) = auth_context.validate_execute_permission() {
            warn!(
                executor = %auth_context.audit_identity(),
                action = %name,
                "Authorization failed: {}",
                e
            );

            self.log_audit_denied(
                correlation_id,
                actor_id,
                &actor_username,
                &actor_role,
                actor_ip.as_deref(),
                session_id.as_deref(),
                name,
                context.incident_id,
                &context.parameters,
                context.dry_run,
                &e.to_string(),
                start_instant.elapsed().as_millis() as u64,
            );

            return Err(ActionError::Unauthorized(e.to_string()));
        }

        // Log the execution with executor identity
        info!(
            executor = %auth_context.audit_identity(),
            action = %name,
            incident_id = %context.incident_id,
            correlation_id = %correlation_id,
            "Executing action"
        );

        // Validate parameters
        if let Err(e) = action.validate(&context) {
            self.log_audit_entry(
                correlation_id,
                actor_id,
                &actor_username,
                &actor_role,
                actor_ip.as_deref(),
                session_id.as_deref(),
                name,
                target.as_deref(),
                context.incident_id,
                &context.parameters,
                context.dry_run,
                AuditResult::Failure,
                &format!("Parameter validation failed: {}", e),
                start_instant.elapsed().as_millis() as u64,
            );
            return Err(e);
        }

        if context.dry_run {
            debug!("Dry run mode - skipping actual execution");

            self.log_audit_entry(
                correlation_id,
                actor_id,
                &actor_username,
                &actor_role,
                actor_ip.as_deref(),
                session_id.as_deref(),
                name,
                target.as_deref(),
                context.incident_id,
                &context.parameters,
                true,
                AuditResult::Skipped,
                "Dry run - action would be executed",
                start_instant.elapsed().as_millis() as u64,
            );

            return Ok(ActionResult::success(
                name,
                "Dry run - action would be executed",
                start_time,
                HashMap::new(),
            ));
        }

        // Execute with timeout
        let timeout = tokio::time::Duration::from_secs(context.timeout_secs);
        let incident_id = context.incident_id;
        let params = context.parameters.clone();

        match tokio::time::timeout(timeout, action.execute(context)).await {
            Ok(Ok(result)) => {
                let duration_ms = start_instant.elapsed().as_millis() as u64;

                self.log_audit_entry(
                    correlation_id,
                    actor_id,
                    &actor_username,
                    &actor_role,
                    actor_ip.as_deref(),
                    session_id.as_deref(),
                    name,
                    target.as_deref(),
                    incident_id,
                    &params,
                    false,
                    AuditResult::Success,
                    &result.message,
                    duration_ms,
                );

                Ok(result)
            }
            Ok(Err(e)) => {
                let duration_ms = start_instant.elapsed().as_millis() as u64;

                self.log_audit_entry(
                    correlation_id,
                    actor_id,
                    &actor_username,
                    &actor_role,
                    actor_ip.as_deref(),
                    session_id.as_deref(),
                    name,
                    target.as_deref(),
                    incident_id,
                    &params,
                    false,
                    AuditResult::Failure,
                    &e.to_string(),
                    duration_ms,
                );

                Err(e)
            }
            Err(_) => {
                let duration_ms = start_instant.elapsed().as_millis() as u64;

                self.log_audit_entry(
                    correlation_id,
                    actor_id,
                    &actor_username,
                    &actor_role,
                    actor_ip.as_deref(),
                    session_id.as_deref(),
                    name,
                    target.as_deref(),
                    incident_id,
                    &params,
                    false,
                    AuditResult::Timeout,
                    &format!(
                        "Action did not complete within {} seconds",
                        timeout.as_secs()
                    ),
                    duration_ms,
                );

                Err(ActionError::Timeout(timeout.as_secs()))
            }
        }
    }

    /// Internal helper to log an audit entry.
    #[allow(clippy::too_many_arguments)]
    fn log_audit_entry(
        &self,
        correlation_id: Uuid,
        actor_id: Uuid,
        actor_username: &str,
        actor_role: &str,
        actor_ip: Option<&str>,
        session_id: Option<&str>,
        action_name: &str,
        target: Option<&str>,
        incident_id: Uuid,
        parameters: &HashMap<String, serde_json::Value>,
        dry_run: bool,
        result: AuditResult,
        message: &str,
        duration_ms: u64,
    ) {
        // Record metrics
        if let Some(metrics) = &self.metrics {
            let result_str = match result {
                AuditResult::Success => "success",
                AuditResult::Failure => "failure",
                AuditResult::Denied => "denied",
                AuditResult::Timeout => "timeout",
                AuditResult::Skipped => "skipped",
            };
            metrics.record_action_audit(
                action_name,
                result_str,
                actor_role,
                duration_ms as f64 / 1000.0,
                dry_run,
            );
        }

        // Log to audit log
        if let Some(audit_log) = &self.audit_log {
            let mut builder = ActionAuditEntry::builder(
                correlation_id,
                actor_id,
                actor_username,
                actor_role,
                action_name,
            )
            .with_incident_id(incident_id)
            .with_parameters(parameters.clone())
            .with_dry_run(dry_run);

            if let Some(ip) = actor_ip {
                builder = builder.with_actor_ip(ip);
            }
            if let Some(session) = session_id {
                builder = builder.with_session_id(session);
            }
            if let Some(t) = target {
                builder = builder.with_target(t);
            }

            let entry = match result {
                AuditResult::Success => builder.success(message, duration_ms),
                AuditResult::Failure => builder.failure(message, duration_ms),
                AuditResult::Denied => builder.denied(message, duration_ms),
                AuditResult::Timeout => builder.timeout(message, duration_ms),
                AuditResult::Skipped => builder.skipped(message, duration_ms),
            };

            // Spawn async logging task
            let audit_log = Arc::clone(audit_log);
            tokio::spawn(async move {
                audit_log.log(entry).await;
            });
        }
    }

    /// Internal helper to log a denied audit entry.
    #[allow(clippy::too_many_arguments)]
    fn log_audit_denied(
        &self,
        correlation_id: Uuid,
        actor_id: Uuid,
        actor_username: &str,
        actor_role: &str,
        actor_ip: Option<&str>,
        session_id: Option<&str>,
        action_name: &str,
        incident_id: Uuid,
        parameters: &HashMap<String, serde_json::Value>,
        dry_run: bool,
        reason: &str,
        duration_ms: u64,
    ) {
        // Record authorization denial metric
        if let Some(metrics) = &self.metrics {
            metrics.record_action_authorization_denied(action_name, "insufficient_permissions");
        }

        self.log_audit_entry(
            correlation_id,
            actor_id,
            actor_username,
            actor_role,
            actor_ip,
            session_id,
            action_name,
            None,
            incident_id,
            parameters,
            dry_run,
            AuditResult::Denied,
            reason,
            duration_ms,
        );
    }

    /// Rolls back an action by name (legacy method - no signature verification).
    ///
    /// **DEPRECATED**: Use `rollback_signed` instead for secure rollback operations.
    /// This method is retained for backwards compatibility but does not verify
    /// the integrity of rollback data.
    #[instrument(skip(self, rollback_data), fields(action = %name))]
    #[deprecated(
        since = "0.2.0",
        note = "Use rollback_signed for secure rollback with signature verification"
    )]
    pub async fn rollback(
        &self,
        name: &str,
        rollback_data: serde_json::Value,
    ) -> Result<ActionResult, ActionError> {
        warn!(
            action = %name,
            "Using deprecated unsigned rollback - consider using rollback_signed"
        );

        let action = self
            .get(name)
            .ok_or_else(|| ActionError::NotFound(name.to_string()))?;

        if !action.supports_rollback() {
            return Err(ActionError::NotSupported(format!(
                "Rollback not supported for action: {}",
                name
            )));
        }

        action.rollback(rollback_data).await
    }

    /// Rolls back an action using signed rollback data.
    ///
    /// This method verifies the HMAC signature of the rollback data before
    /// executing the rollback operation. If the signature is invalid (indicating
    /// the data has been tampered with), the rollback is rejected with an error.
    ///
    /// # Security
    ///
    /// The signature verification ensures that:
    /// - The rollback data has not been modified since it was created
    /// - The data was signed by a system with access to the encryption key
    /// - The action name matches the original action that created the data
    ///
    /// # Errors
    ///
    /// Returns `ActionError::RollbackDataTampered` if the signature verification fails.
    /// Returns `ActionError::InvalidRollbackData` if the data cannot be parsed.
    #[instrument(skip(self, signed_rollback_data), fields(action = %name))]
    pub async fn rollback_signed(
        &self,
        name: &str,
        signed_rollback_data: serde_json::Value,
    ) -> Result<ActionResult, ActionError> {
        // Parse the signed rollback data
        let signed_data = SignedRollbackData::from_json(signed_rollback_data)?;

        // Verify the action name matches
        if signed_data.action_name != name {
            warn!(
                expected_action = %name,
                actual_action = %signed_data.action_name,
                "Rollback action name mismatch"
            );
            return Err(ActionError::InvalidRollbackData(format!(
                "Action name mismatch: expected '{}', got '{}'",
                name, signed_data.action_name
            )));
        }

        // Verify the signature
        let key = self.get_encryption_key()?;
        signed_data.verify(key)?;

        info!(
            action = %name,
            execution_id = %signed_data.execution_id,
            "Rollback signature verified, proceeding with rollback"
        );

        // Get the action and perform rollback
        let action = self
            .get(name)
            .ok_or_else(|| ActionError::NotFound(name.to_string()))?;

        if !action.supports_rollback() {
            return Err(ActionError::NotSupported(format!(
                "Rollback not supported for action: {}",
                name
            )));
        }

        action.rollback(signed_data.data).await
    }

    /// Gets action metadata.
    pub fn get_action_info(&self, name: &str) -> Option<ActionInfo> {
        self.actions.get(name).map(|a| ActionInfo {
            name: a.name().to_string(),
            description: a.description().to_string(),
            parameters: a.required_parameters(),
            supports_rollback: a.supports_rollback(),
        })
    }

    /// Gets all action metadata.
    pub fn get_all_action_info(&self) -> Vec<ActionInfo> {
        self.actions
            .values()
            .map(|a| ActionInfo {
                name: a.name().to_string(),
                description: a.description().to_string(),
                parameters: a.required_parameters(),
                supports_rollback: a.supports_rollback(),
            })
            .collect()
    }
}

impl Default for ActionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Information about a registered action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionInfo {
    pub name: String,
    pub description: String,
    pub parameters: Vec<ParameterDef>,
    pub supports_rollback: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tw_core::AuthorizationContext;

    struct TestAction;

    #[async_trait]
    impl Action for TestAction {
        fn name(&self) -> &str {
            "test_action"
        }

        fn description(&self) -> &str {
            "A test action"
        }

        fn required_parameters(&self) -> Vec<ParameterDef> {
            vec![ParameterDef::required(
                "target",
                "The target",
                ParameterType::String,
            )]
        }

        async fn execute(&self, context: ActionContext) -> Result<ActionResult, ActionError> {
            let target = context.require_string("target")?;
            Ok(ActionResult::success(
                self.name(),
                &format!("Executed on {}", target),
                Utc::now(),
                HashMap::new(),
            ))
        }
    }

    /// Creates a test authorization context with full permissions.
    fn test_auth_context() -> AuthorizationContext {
        AuthorizationContext::system()
            .with_session("test-session")
            .with_ip_address("127.0.0.1")
    }

    #[tokio::test]
    async fn test_registry_execute() {
        let mut registry = ActionRegistry::new();
        registry.register(Arc::new(TestAction));

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("target", serde_json::json!("test-host"))
            .with_auth_context(test_auth_context());

        let result = registry.execute("test_action", context).await.unwrap();
        assert!(result.success);
    }

    #[tokio::test]
    async fn test_missing_parameter() {
        let mut registry = ActionRegistry::new();
        registry.register(Arc::new(TestAction));

        let context = ActionContext::new(Uuid::new_v4()).with_auth_context(test_auth_context());

        let result = registry.execute("test_action", context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
    }

    #[tokio::test]
    async fn test_dry_run() {
        let mut registry = ActionRegistry::new();
        registry.register(Arc::new(TestAction));

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("target", serde_json::json!("test-host"))
            .with_dry_run(true)
            .with_auth_context(test_auth_context());

        let result = registry.execute("test_action", context).await.unwrap();
        assert!(result.success);
        assert!(result.message.contains("Dry run"));
    }

    #[tokio::test]
    async fn test_execute_without_auth_context_fails() {
        let mut registry = ActionRegistry::new();
        registry.register(Arc::new(TestAction));

        let context =
            ActionContext::new(Uuid::new_v4()).with_param("target", serde_json::json!("test-host"));

        let result = registry.execute("test_action", context).await;
        assert!(matches!(result, Err(ActionError::Unauthorized(_))));
    }

    #[tokio::test]
    async fn test_execute_with_audit_log() {
        let audit_log = Arc::new(ActionAuditLog::without_tracing(100));
        let mut registry = ActionRegistry::new();
        registry.set_audit_log(Arc::clone(&audit_log));
        registry.register(Arc::new(TestAction));

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("target", serde_json::json!("test-host"))
            .with_auth_context(test_auth_context());

        let result = registry.execute("test_action", context).await.unwrap();
        assert!(result.success);

        // Wait a bit for the async audit log to complete
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let entries = audit_log.get_entries().await;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].action_name, "test_action");
        assert_eq!(
            entries[0].result,
            tw_observability::ActionAuditResult::Success
        );
    }

    #[tokio::test]
    async fn test_execute_with_correlation_id() {
        let audit_log = Arc::new(ActionAuditLog::without_tracing(100));
        let mut registry = ActionRegistry::new();
        registry.set_audit_log(Arc::clone(&audit_log));
        registry.register(Arc::new(TestAction));

        let correlation_id = Uuid::new_v4();
        let context = ActionContext::new(Uuid::new_v4())
            .with_param("target", serde_json::json!("test-host"))
            .with_auth_context(test_auth_context());

        let result = registry
            .execute_with_correlation("test_action", context, correlation_id)
            .await
            .unwrap();
        assert!(result.success);

        // Wait a bit for the async audit log to complete
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let entries = audit_log.get_by_correlation_id(correlation_id).await;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].correlation_id, correlation_id);
    }

    #[tokio::test]
    async fn test_audit_masks_sensitive_parameters() {
        let audit_log = Arc::new(ActionAuditLog::without_tracing(100));
        let mut registry = ActionRegistry::new();
        registry.set_audit_log(Arc::clone(&audit_log));
        registry.register(Arc::new(TestAction));

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("target", serde_json::json!("test-host"))
            .with_param("api_key", serde_json::json!("super-secret-key"))
            .with_param("password", serde_json::json!("hunter2"))
            .with_auth_context(test_auth_context());

        let _result = registry.execute("test_action", context).await.unwrap();

        // Wait a bit for the async audit log to complete
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let entries = audit_log.get_entries().await;
        assert_eq!(entries.len(), 1);

        // Verify sensitive parameters are masked
        let params = &entries[0].parameters;
        assert_eq!(
            params.get("target").unwrap(),
            &serde_json::json!("test-host")
        );
        assert_eq!(
            params.get("api_key").unwrap(),
            &serde_json::json!("[REDACTED]")
        );
        assert_eq!(
            params.get("password").unwrap(),
            &serde_json::json!("[REDACTED]")
        );
    }

    #[test]
    fn test_action_info() {
        let mut registry = ActionRegistry::new();
        registry.register(Arc::new(TestAction));

        let info = registry.get_action_info("test_action").unwrap();
        assert_eq!(info.name, "test_action");
        assert_eq!(info.parameters.len(), 1);
    }

    // Test action that supports rollback
    struct RollbackTestAction;

    #[async_trait]
    impl Action for RollbackTestAction {
        fn name(&self) -> &str {
            "rollback_test_action"
        }

        fn description(&self) -> &str {
            "A test action that supports rollback"
        }

        fn required_parameters(&self) -> Vec<ParameterDef> {
            vec![]
        }

        async fn execute(&self, _context: ActionContext) -> Result<ActionResult, ActionError> {
            let rollback_data = serde_json::json!({
                "original_state": "active",
                "host": "test-host"
            });
            Ok(ActionResult::success(
                self.name(),
                "Executed successfully",
                Utc::now(),
                HashMap::new(),
            )
            .with_rollback(rollback_data))
        }

        async fn rollback(
            &self,
            rollback_data: serde_json::Value,
        ) -> Result<ActionResult, ActionError> {
            let host = rollback_data
                .get("host")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            Ok(ActionResult::success(
                self.name(),
                &format!("Rolled back on {}", host),
                Utc::now(),
                HashMap::new(),
            ))
        }

        fn supports_rollback(&self) -> bool {
            true
        }
    }

    #[test]
    fn test_signed_rollback_data_creation() {
        let encryption_key = b"test-encryption-key-32-bytes-xx";
        let data = serde_json::json!({"host": "test-host", "original_state": "active"});
        let execution_id = Uuid::new_v4();

        let signed =
            SignedRollbackData::new(data.clone(), "test_action", execution_id, encryption_key)
                .expect("Should create signed data");

        assert_eq!(signed.action_name, "test_action");
        assert_eq!(signed.execution_id, execution_id);
        assert_eq!(signed.data, data);
        assert!(!signed.signature.is_empty());
    }

    #[test]
    fn test_signed_rollback_data_verification_succeeds() {
        let encryption_key = b"test-encryption-key-32-bytes-xx";
        let data = serde_json::json!({"host": "test-host", "original_state": "active"});
        let execution_id = Uuid::new_v4();

        let signed = SignedRollbackData::new(data, "test_action", execution_id, encryption_key)
            .expect("Should create signed data");

        // Verification should succeed with same key
        signed
            .verify(encryption_key)
            .expect("Verification should succeed");
    }

    #[test]
    fn test_signed_rollback_data_detects_tampered_data() {
        let encryption_key = b"test-encryption-key-32-bytes-xx";
        let data = serde_json::json!({"host": "test-host", "original_state": "active"});
        let execution_id = Uuid::new_v4();

        let mut signed = SignedRollbackData::new(data, "test_action", execution_id, encryption_key)
            .expect("Should create signed data");

        // Tamper with the data
        signed.data = serde_json::json!({"host": "malicious-host", "original_state": "deleted"});

        // Verification should fail
        let result = signed.verify(encryption_key);
        assert!(matches!(result, Err(ActionError::RollbackDataTampered)));
    }

    #[test]
    fn test_signed_rollback_data_detects_wrong_key() {
        let encryption_key = b"test-encryption-key-32-bytes-xx";
        let wrong_key = b"wrong-encryption-key-32-bytes-x";
        let data = serde_json::json!({"host": "test-host", "original_state": "active"});
        let execution_id = Uuid::new_v4();

        let signed = SignedRollbackData::new(data, "test_action", execution_id, encryption_key)
            .expect("Should create signed data");

        // Verification should fail with wrong key
        let result = signed.verify(wrong_key);
        assert!(matches!(result, Err(ActionError::RollbackDataTampered)));
    }

    #[test]
    fn test_signed_rollback_data_detects_tampered_signature() {
        let encryption_key = b"test-encryption-key-32-bytes-xx";
        let data = serde_json::json!({"host": "test-host", "original_state": "active"});
        let execution_id = Uuid::new_v4();

        let mut signed = SignedRollbackData::new(data, "test_action", execution_id, encryption_key)
            .expect("Should create signed data");

        // Tamper with the signature
        signed.signature = "0".repeat(64); // Valid hex but wrong signature

        // Verification should fail
        let result = signed.verify(encryption_key);
        assert!(matches!(result, Err(ActionError::RollbackDataTampered)));
    }

    #[test]
    fn test_signed_rollback_data_serialization() {
        let encryption_key = b"test-encryption-key-32-bytes-xx";
        let data = serde_json::json!({"host": "test-host", "original_state": "active"});
        let execution_id = Uuid::new_v4();

        let signed =
            SignedRollbackData::new(data.clone(), "test_action", execution_id, encryption_key)
                .expect("Should create signed data");

        // Serialize to JSON
        let json = signed.to_json().expect("Should serialize to JSON");

        // Deserialize back
        let deserialized =
            SignedRollbackData::from_json(json).expect("Should deserialize from JSON");

        // Verification should still succeed
        deserialized
            .verify(encryption_key)
            .expect("Verification should succeed after serialization round-trip");

        assert_eq!(deserialized.data, data);
        assert_eq!(deserialized.action_name, "test_action");
        assert_eq!(deserialized.execution_id, execution_id);
    }

    #[tokio::test]
    async fn test_rollback_signed_succeeds() {
        let encryption_key = b"test-encryption-key-32-bytes-xx".to_vec();
        let mut registry = ActionRegistry::with_encryption_key(encryption_key);
        registry.register(Arc::new(RollbackTestAction));

        let data = serde_json::json!({"host": "test-host", "original_state": "active"});
        let execution_id = Uuid::new_v4();

        // Create signed rollback data
        let signed = registry
            .sign_rollback_data(data, "rollback_test_action", execution_id)
            .expect("Should sign data");

        let signed_json = signed.to_json().expect("Should serialize");

        // Execute rollback
        let result = registry
            .rollback_signed("rollback_test_action", signed_json)
            .await
            .expect("Rollback should succeed");

        assert!(result.success);
        assert!(result.message.contains("Rolled back"));
    }

    #[tokio::test]
    async fn test_rollback_signed_rejects_tampered_data() {
        let encryption_key = b"test-encryption-key-32-bytes-xx".to_vec();
        let mut registry = ActionRegistry::with_encryption_key(encryption_key);
        registry.register(Arc::new(RollbackTestAction));

        let data = serde_json::json!({"host": "test-host", "original_state": "active"});
        let execution_id = Uuid::new_v4();

        // Create signed rollback data
        let mut signed = registry
            .sign_rollback_data(data, "rollback_test_action", execution_id)
            .expect("Should sign data");

        // Tamper with the data
        signed.data = serde_json::json!({"host": "evil-host", "original_state": "destroyed"});

        let signed_json = signed.to_json().expect("Should serialize");

        // Execute rollback - should fail
        let result = registry
            .rollback_signed("rollback_test_action", signed_json)
            .await;

        assert!(matches!(result, Err(ActionError::RollbackDataTampered)));
    }

    #[tokio::test]
    async fn test_rollback_signed_rejects_action_name_mismatch() {
        let encryption_key = b"test-encryption-key-32-bytes-xx".to_vec();
        let mut registry = ActionRegistry::with_encryption_key(encryption_key);
        registry.register(Arc::new(RollbackTestAction));

        let data = serde_json::json!({"host": "test-host", "original_state": "active"});
        let execution_id = Uuid::new_v4();

        // Create signed rollback data for a different action
        let signed = registry
            .sign_rollback_data(data, "different_action", execution_id)
            .expect("Should sign data");

        let signed_json = signed.to_json().expect("Should serialize");

        // Try to use it for rollback_test_action - should fail
        let result = registry
            .rollback_signed("rollback_test_action", signed_json)
            .await;

        assert!(matches!(result, Err(ActionError::InvalidRollbackData(_))));
    }

    #[tokio::test]
    async fn test_rollback_signed_requires_encryption_key() {
        let mut registry = ActionRegistry::new(); // No encryption key
        registry.register(Arc::new(RollbackTestAction));

        let signed_json = serde_json::json!({
            "data": {"host": "test"},
            "signature": "abc123",
            "created_at": "2024-01-01T00:00:00Z",
            "action_name": "rollback_test_action",
            "execution_id": Uuid::new_v4().to_string()
        });

        let result = registry
            .rollback_signed("rollback_test_action", signed_json)
            .await;

        assert!(matches!(result, Err(ActionError::InvalidRollbackData(_))));
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hell"));
        assert!(!constant_time_eq(b"", b"x"));
        assert!(constant_time_eq(b"", b""));
    }
}
