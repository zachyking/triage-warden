//! Approval workflows for Triage Warden.
//!
//! This module implements the approval system for actions that require
//! human review before execution.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, info, instrument, warn};
use uuid::Uuid;

/// Errors that can occur in approval workflows.
#[derive(Error, Debug)]
pub enum ApprovalError {
    #[error("Approval request not found: {0}")]
    NotFound(Uuid),

    #[error("Approval request expired")]
    Expired,

    #[error("Approval request already processed")]
    AlreadyProcessed,

    #[error("Insufficient privileges for approval level: {0:?}")]
    InsufficientPrivileges(ApprovalLevel),

    #[error("Invalid approver: {0}")]
    InvalidApprover(String),

    #[error("Insufficient privileges to escalate: user level {user_level:?} cannot escalate to {target_level:?} (minimum required: {minimum_required:?})")]
    InsufficientEscalationPrivileges {
        user_level: ApprovalLevel,
        target_level: ApprovalLevel,
        minimum_required: ApprovalLevel,
    },

    #[error("Cannot escalate beyond Executive level")]
    MaxEscalationReached,

    #[error("Concurrent modification conflict: request version {expected} does not match current version {actual}")]
    ConcurrentModification { expected: u64, actual: u64 },
}

/// Level of approval required for an action.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalLevel {
    /// Any analyst can approve.
    Analyst,
    /// Senior analyst or above.
    Senior,
    /// SOC manager or above.
    Manager,
    /// CISO or equivalent.
    Executive,
}

impl std::fmt::Display for ApprovalLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApprovalLevel::Analyst => write!(f, "Analyst"),
            ApprovalLevel::Senior => write!(f, "Senior"),
            ApprovalLevel::Manager => write!(f, "Manager"),
            ApprovalLevel::Executive => write!(f, "Executive"),
        }
    }
}

/// Status of an approval request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    /// Awaiting approval.
    Pending,
    /// Approved.
    Approved,
    /// Denied.
    Denied,
    /// Expired without action.
    Expired,
    /// Cancelled by requester.
    Cancelled,
}

/// An approval request for a proposed action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    /// Unique identifier.
    pub id: Uuid,
    /// Incident this approval is for.
    pub incident_id: Uuid,
    /// Action ID being approved.
    pub action_id: Uuid,
    /// Type of action.
    pub action_type: String,
    /// Target of the action.
    pub target: String,
    /// Reason for the action.
    pub reason: String,
    /// Required approval level.
    pub required_level: ApprovalLevel,
    /// Current status.
    pub status: ApprovalStatus,
    /// Who requested the approval.
    pub requested_by: String,
    /// When the request was created.
    pub created_at: DateTime<Utc>,
    /// When the request expires.
    pub expires_at: DateTime<Utc>,
    /// Who processed the request (if processed).
    pub processed_by: Option<String>,
    /// When the request was processed.
    pub processed_at: Option<DateTime<Utc>>,
    /// Comment from the approver.
    pub approver_comment: Option<String>,
    /// Additional context for the approver.
    pub context: HashMap<String, serde_json::Value>,
    /// Version number for optimistic locking (used for concurrent modification detection).
    #[serde(default)]
    pub version: u64,
}

impl ApprovalRequest {
    /// Creates a new approval request.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        incident_id: Uuid,
        action_id: Uuid,
        action_type: String,
        target: String,
        reason: String,
        required_level: ApprovalLevel,
        requested_by: String,
        ttl_minutes: i64,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            incident_id,
            action_id,
            action_type,
            target,
            reason,
            required_level,
            status: ApprovalStatus::Pending,
            requested_by,
            created_at: now,
            expires_at: now + Duration::minutes(ttl_minutes),
            processed_by: None,
            processed_at: None,
            approver_comment: None,
            context: HashMap::new(),
            version: 0,
        }
    }

    /// Returns the current version for optimistic locking.
    pub fn version(&self) -> u64 {
        self.version
    }

    /// Checks if the request has expired.
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Checks if the request is still pending.
    pub fn is_pending(&self) -> bool {
        self.status == ApprovalStatus::Pending && !self.is_expired()
    }

    /// Adds context for the approver.
    pub fn add_context(&mut self, key: &str, value: serde_json::Value) {
        self.context.insert(key.to_string(), value);
    }
}

/// Configuration for approval workflows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalConfig {
    /// Default TTL for approval requests (minutes).
    pub default_ttl_minutes: i64,
    /// TTL by approval level.
    pub level_ttl_minutes: HashMap<ApprovalLevel, i64>,
    /// Notification channels by approval level.
    pub notification_channels: HashMap<ApprovalLevel, Vec<String>>,
    /// Whether to auto-deny on expiration.
    pub auto_deny_on_expiration: bool,
    /// Whether to allow escalation.
    pub allow_escalation: bool,
}

impl Default for ApprovalConfig {
    fn default() -> Self {
        let mut level_ttl = HashMap::new();
        level_ttl.insert(ApprovalLevel::Analyst, 30);
        level_ttl.insert(ApprovalLevel::Senior, 60);
        level_ttl.insert(ApprovalLevel::Manager, 120);
        level_ttl.insert(ApprovalLevel::Executive, 240);

        Self {
            default_ttl_minutes: 60,
            level_ttl_minutes: level_ttl,
            notification_channels: HashMap::new(),
            auto_deny_on_expiration: true,
            allow_escalation: true,
        }
    }
}

/// Manages approval workflows.
pub struct ApprovalWorkflow {
    /// Configuration.
    config: ApprovalConfig,
    /// Pending approval requests.
    requests: Arc<RwLock<HashMap<Uuid, ApprovalRequest>>>,
    /// Approver role mappings.
    approver_levels: Arc<RwLock<HashMap<String, ApprovalLevel>>>,
}

impl ApprovalWorkflow {
    /// Creates a new approval workflow manager.
    pub fn new(config: ApprovalConfig) -> Self {
        Self {
            config,
            requests: Arc::new(RwLock::new(HashMap::new())),
            approver_levels: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Registers an approver with their level.
    pub async fn register_approver(&self, user_id: &str, level: ApprovalLevel) {
        let mut levels = self.approver_levels.write().await;
        levels.insert(user_id.to_string(), level);
        info!("Registered approver {} at level {:?}", user_id, level);
    }

    /// Gets the approval level for a user.
    pub async fn get_approver_level(&self, user_id: &str) -> Option<ApprovalLevel> {
        let levels = self.approver_levels.read().await;
        levels.get(user_id).copied()
    }

    /// Creates a new approval request.
    #[allow(clippy::too_many_arguments)]
    #[instrument(skip(self))]
    pub async fn create_request(
        &self,
        incident_id: Uuid,
        action_id: Uuid,
        action_type: String,
        target: String,
        reason: String,
        required_level: ApprovalLevel,
        requested_by: String,
    ) -> ApprovalRequest {
        let ttl = self
            .config
            .level_ttl_minutes
            .get(&required_level)
            .copied()
            .unwrap_or(self.config.default_ttl_minutes);

        let request = ApprovalRequest::new(
            incident_id,
            action_id,
            action_type,
            target,
            reason,
            required_level,
            requested_by,
            ttl,
        );

        let mut requests = self.requests.write().await;
        requests.insert(request.id, request.clone());

        info!(
            "Created approval request {} for action {} (level: {:?})",
            request.id, action_id, required_level
        );

        request
    }

    /// Gets a pending approval request.
    pub async fn get_request(&self, id: Uuid) -> Option<ApprovalRequest> {
        let requests = self.requests.read().await;
        requests.get(&id).cloned()
    }

    /// Gets all pending requests.
    pub async fn get_pending_requests(&self) -> Vec<ApprovalRequest> {
        let requests = self.requests.read().await;
        requests
            .values()
            .filter(|r| r.is_pending())
            .cloned()
            .collect()
    }

    /// Gets pending requests for a specific incident.
    pub async fn get_incident_requests(&self, incident_id: Uuid) -> Vec<ApprovalRequest> {
        let requests = self.requests.read().await;
        requests
            .values()
            .filter(|r| r.incident_id == incident_id && r.is_pending())
            .cloned()
            .collect()
    }

    /// Approves a request.
    #[instrument(skip(self))]
    pub async fn approve(
        &self,
        request_id: Uuid,
        approver: &str,
        comment: Option<String>,
    ) -> Result<ApprovalRequest, ApprovalError> {
        // Check approver level
        let approver_level = self
            .get_approver_level(approver)
            .await
            .ok_or_else(|| ApprovalError::InvalidApprover(approver.to_string()))?;

        let mut requests = self.requests.write().await;
        let request = requests
            .get_mut(&request_id)
            .ok_or(ApprovalError::NotFound(request_id))?;

        // Check if already processed
        if request.status != ApprovalStatus::Pending {
            return Err(ApprovalError::AlreadyProcessed);
        }

        // Check if expired
        if request.is_expired() {
            request.status = ApprovalStatus::Expired;
            return Err(ApprovalError::Expired);
        }

        // Check approval level
        if approver_level < request.required_level {
            return Err(ApprovalError::InsufficientPrivileges(
                request.required_level,
            ));
        }

        // Approve
        request.status = ApprovalStatus::Approved;
        request.processed_by = Some(approver.to_string());
        request.processed_at = Some(Utc::now());
        request.approver_comment = comment;

        info!(
            "Request {} approved by {} (level: {:?})",
            request_id, approver, approver_level
        );

        Ok(request.clone())
    }

    /// Denies a request.
    #[instrument(skip(self))]
    pub async fn deny(
        &self,
        request_id: Uuid,
        approver: &str,
        reason: String,
    ) -> Result<ApprovalRequest, ApprovalError> {
        // Check approver level
        let approver_level = self
            .get_approver_level(approver)
            .await
            .ok_or_else(|| ApprovalError::InvalidApprover(approver.to_string()))?;

        let mut requests = self.requests.write().await;
        let request = requests
            .get_mut(&request_id)
            .ok_or(ApprovalError::NotFound(request_id))?;

        // Check if already processed
        if request.status != ApprovalStatus::Pending {
            return Err(ApprovalError::AlreadyProcessed);
        }

        // Check if expired
        if request.is_expired() {
            request.status = ApprovalStatus::Expired;
            return Err(ApprovalError::Expired);
        }

        // Any approver at or above the required level can deny
        if approver_level < request.required_level {
            return Err(ApprovalError::InsufficientPrivileges(
                request.required_level,
            ));
        }

        // Deny
        request.status = ApprovalStatus::Denied;
        request.processed_by = Some(approver.to_string());
        request.processed_at = Some(Utc::now());
        request.approver_comment = Some(reason);

        info!(
            "Request {} denied by {} (level: {:?})",
            request_id, approver, approver_level
        );

        Ok(request.clone())
    }

    /// Cancels a request (by the requester).
    pub async fn cancel(&self, request_id: Uuid, cancelled_by: &str) -> Result<(), ApprovalError> {
        let mut requests = self.requests.write().await;
        let request = requests
            .get_mut(&request_id)
            .ok_or(ApprovalError::NotFound(request_id))?;

        if request.status != ApprovalStatus::Pending {
            return Err(ApprovalError::AlreadyProcessed);
        }

        request.status = ApprovalStatus::Cancelled;
        request.processed_by = Some(cancelled_by.to_string());
        request.processed_at = Some(Utc::now());

        info!("Request {} cancelled by {}", request_id, cancelled_by);

        Ok(())
    }

    /// Escalates a request to a higher approval level.
    ///
    /// This method uses optimistic locking to prevent race conditions when
    /// multiple concurrent escalation attempts occur. The version parameter
    /// must match the current version of the request for the escalation to succeed.
    #[instrument(skip(self))]
    pub async fn escalate(
        &self,
        request_id: Uuid,
        escalated_by: &str,
        reason: &str,
    ) -> Result<ApprovalRequest, ApprovalError> {
        // Get the current version for compare-and-swap
        let expected_version = {
            let requests = self.requests.read().await;
            let request = requests
                .get(&request_id)
                .ok_or(ApprovalError::NotFound(request_id))?;
            request.version
        };

        // Perform the escalation with version check
        self.escalate_with_version(request_id, escalated_by, reason, expected_version)
            .await
    }

    /// Escalates a request with explicit version checking for optimistic locking.
    ///
    /// This method atomically updates the approval level and TTL in a single operation,
    /// using compare-and-swap semantics to detect concurrent modifications.
    ///
    /// # Authorization
    /// The escalating user must have an approval level at least equal to the
    /// current required level of the request. This ensures that only users
    /// with appropriate privileges can escalate requests to higher levels.
    ///
    /// # Arguments
    /// * `request_id` - The ID of the approval request to escalate
    /// * `escalated_by` - The user performing the escalation
    /// * `reason` - The reason for escalation
    /// * `expected_version` - The expected version number for optimistic locking
    ///
    /// # Returns
    /// * `Ok(ApprovalRequest)` - The updated request if escalation succeeded
    /// * `Err(ApprovalError::ConcurrentModification)` - If another operation modified the request
    /// * `Err(ApprovalError::MaxEscalationReached)` - If already at Executive level
    /// * `Err(ApprovalError::InsufficientEscalationPrivileges)` - If user lacks required privileges
    /// * `Err(ApprovalError::InvalidApprover)` - If user is not a registered approver
    /// * `Err(ApprovalError::Expired)` - If the request has expired
    #[instrument(skip(self), fields(escalated_by = %escalated_by, request_id = %request_id))]
    pub async fn escalate_with_version(
        &self,
        request_id: Uuid,
        escalated_by: &str,
        reason: &str,
        expected_version: u64,
    ) -> Result<ApprovalRequest, ApprovalError> {
        if !self.config.allow_escalation {
            return Err(ApprovalError::InsufficientPrivileges(
                ApprovalLevel::Executive,
            ));
        }

        // Verify the escalating user is a registered approver and get their level
        // This check is performed before acquiring the write lock for efficiency
        let escalator_level = self
            .get_approver_level(escalated_by)
            .await
            .ok_or_else(|| ApprovalError::InvalidApprover(escalated_by.to_string()))?;

        // Acquire write lock for atomic update
        let mut requests = self.requests.write().await;
        let request = requests
            .get_mut(&request_id)
            .ok_or(ApprovalError::NotFound(request_id))?;

        // Compare-and-swap: verify version hasn't changed
        if request.version != expected_version {
            warn!(
                "Concurrent modification detected for request {}: expected version {}, found {}",
                request_id, expected_version, request.version
            );
            return Err(ApprovalError::ConcurrentModification {
                expected: expected_version,
                actual: request.version,
            });
        }

        if request.status != ApprovalStatus::Pending {
            return Err(ApprovalError::AlreadyProcessed);
        }

        // Check if request is expired
        if request.is_expired() {
            request.status = ApprovalStatus::Expired;
            return Err(ApprovalError::Expired);
        }

        // Check if already at max level
        if request.required_level == ApprovalLevel::Executive {
            warn!(
                "Escalation attempt on request {} failed: already at Executive level (attempted by {})",
                request_id, escalated_by
            );
            return Err(ApprovalError::MaxEscalationReached);
        }

        // Calculate new level
        let new_level = match request.required_level {
            ApprovalLevel::Analyst => ApprovalLevel::Senior,
            ApprovalLevel::Senior => ApprovalLevel::Manager,
            ApprovalLevel::Manager => ApprovalLevel::Executive,
            ApprovalLevel::Executive => unreachable!(), // Handled above
        };

        // Privilege check: User must have at least the current required level to escalate
        // This ensures only appropriately privileged users can escalate requests
        if escalator_level < request.required_level {
            warn!(
                "Escalation privilege check failed for request {}: user {} has level {:?}, requires at least {:?} to escalate to {:?}",
                request_id, escalated_by, escalator_level, request.required_level, new_level
            );
            return Err(ApprovalError::InsufficientEscalationPrivileges {
                user_level: escalator_level,
                target_level: new_level,
                minimum_required: request.required_level,
            });
        }

        let previous_level = request.required_level;

        // Calculate new TTL
        let new_ttl = self
            .config
            .level_ttl_minutes
            .get(&new_level)
            .copied()
            .unwrap_or(self.config.default_ttl_minutes);
        let escalation_timestamp = Utc::now();
        let new_expires_at = escalation_timestamp + Duration::minutes(new_ttl);

        // ATOMIC UPDATE: Update all fields together within the same lock
        // This ensures level, TTL, context, and version are updated atomically
        request.required_level = new_level;
        request.expires_at = new_expires_at;

        // Include comprehensive escalation audit information in context
        request
            .context
            .insert("escalation_reason".to_string(), serde_json::json!(reason));
        request
            .context
            .insert("escalated_by".to_string(), serde_json::json!(escalated_by));
        request.context.insert(
            "escalator_level".to_string(),
            serde_json::json!(format!("{:?}", escalator_level)),
        );
        request.context.insert(
            "escalation_timestamp".to_string(),
            serde_json::json!(escalation_timestamp.to_rfc3339()),
        );
        request.context.insert(
            "previous_level".to_string(),
            serde_json::json!(format!("{:?}", previous_level)),
        );

        // Increment version for next compare-and-swap operation
        request.version += 1;

        info!(
            "Request {} escalated from {:?} to {:?} by {} (user level: {:?}, version {} -> {})",
            request_id,
            previous_level,
            new_level,
            escalated_by,
            escalator_level,
            expected_version,
            request.version
        );

        Ok(request.clone())
    }

    /// Attempts to escalate with automatic retry on concurrent modification.
    ///
    /// This method will retry the escalation up to `max_retries` times if
    /// concurrent modifications are detected, re-reading the current version
    /// before each retry.
    ///
    /// # Arguments
    /// * `request_id` - The ID of the approval request to escalate
    /// * `escalated_by` - The user performing the escalation
    /// * `reason` - The reason for escalation
    /// * `max_retries` - Maximum number of retry attempts (default: 3)
    pub async fn escalate_with_retry(
        &self,
        request_id: Uuid,
        escalated_by: &str,
        reason: &str,
        max_retries: usize,
    ) -> Result<ApprovalRequest, ApprovalError> {
        let mut attempts = 0;

        loop {
            // Get current version
            let expected_version = {
                let requests = self.requests.read().await;
                let request = requests
                    .get(&request_id)
                    .ok_or(ApprovalError::NotFound(request_id))?;
                request.version
            };

            match self
                .escalate_with_version(request_id, escalated_by, reason, expected_version)
                .await
            {
                Ok(request) => return Ok(request),
                Err(ApprovalError::ConcurrentModification { .. }) => {
                    attempts += 1;
                    if attempts >= max_retries {
                        warn!(
                            "Escalation failed after {} retries due to concurrent modifications",
                            max_retries
                        );
                        return Err(ApprovalError::ConcurrentModification {
                            expected: expected_version,
                            actual: expected_version + 1, // Approximate
                        });
                    }
                    debug!(
                        "Retrying escalation for request {} (attempt {}/{})",
                        request_id,
                        attempts + 1,
                        max_retries
                    );
                    // Small yield to allow other operations to complete
                    tokio::task::yield_now().await;
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Processes expired requests.
    pub async fn process_expired(&self) -> Vec<ApprovalRequest> {
        let mut requests = self.requests.write().await;
        let mut expired = Vec::new();

        for request in requests.values_mut() {
            if request.status == ApprovalStatus::Pending
                && request.is_expired()
                && self.config.auto_deny_on_expiration
            {
                request.status = ApprovalStatus::Expired;
                request.approver_comment = Some("Auto-expired".to_string());
                expired.push(request.clone());
                warn!("Request {} auto-expired", request.id);
            }
        }

        expired
    }

    /// Cleans up old processed requests.
    pub async fn cleanup(&self, max_age_hours: i64) {
        let cutoff = Utc::now() - Duration::hours(max_age_hours);
        let mut requests = self.requests.write().await;

        let initial_count = requests.len();
        requests.retain(|_, r| {
            r.status == ApprovalStatus::Pending
                || r.processed_at.map(|t| t > cutoff).unwrap_or(true)
        });

        let removed = initial_count - requests.len();
        if removed > 0 {
            debug!("Cleaned up {} old approval requests", removed);
        }
    }
}

impl Default for ApprovalWorkflow {
    fn default() -> Self {
        Self::new(ApprovalConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_request() {
        let workflow = ApprovalWorkflow::default();

        let request = workflow
            .create_request(
                Uuid::new_v4(),
                Uuid::new_v4(),
                "isolate_host".to_string(),
                "workstation-001".to_string(),
                "Malware detected".to_string(),
                ApprovalLevel::Analyst,
                "ai".to_string(),
            )
            .await;

        assert_eq!(request.status, ApprovalStatus::Pending);
        assert!(request.is_pending());
    }

    #[tokio::test]
    async fn test_approve_request() {
        let workflow = ApprovalWorkflow::default();
        workflow
            .register_approver("analyst1", ApprovalLevel::Analyst)
            .await;

        let request = workflow
            .create_request(
                Uuid::new_v4(),
                Uuid::new_v4(),
                "isolate_host".to_string(),
                "workstation-001".to_string(),
                "Malware detected".to_string(),
                ApprovalLevel::Analyst,
                "ai".to_string(),
            )
            .await;

        let approved = workflow
            .approve(request.id, "analyst1", Some("Looks good".to_string()))
            .await
            .unwrap();

        assert_eq!(approved.status, ApprovalStatus::Approved);
        assert_eq!(approved.processed_by, Some("analyst1".to_string()));
    }

    #[tokio::test]
    async fn test_insufficient_privileges() {
        let workflow = ApprovalWorkflow::default();
        workflow
            .register_approver("analyst1", ApprovalLevel::Analyst)
            .await;

        let request = workflow
            .create_request(
                Uuid::new_v4(),
                Uuid::new_v4(),
                "isolate_host".to_string(),
                "server-001".to_string(),
                "Critical asset".to_string(),
                ApprovalLevel::Manager,
                "ai".to_string(),
            )
            .await;

        let result = workflow.approve(request.id, "analyst1", None).await;
        assert!(matches!(
            result,
            Err(ApprovalError::InsufficientPrivileges(_))
        ));
    }

    #[tokio::test]
    async fn test_deny_request() {
        let workflow = ApprovalWorkflow::default();
        workflow
            .register_approver("analyst1", ApprovalLevel::Senior)
            .await;

        let request = workflow
            .create_request(
                Uuid::new_v4(),
                Uuid::new_v4(),
                "isolate_host".to_string(),
                "workstation-001".to_string(),
                "Suspicious".to_string(),
                ApprovalLevel::Analyst,
                "ai".to_string(),
            )
            .await;

        let denied = workflow
            .deny(request.id, "analyst1", "False positive".to_string())
            .await
            .unwrap();

        assert_eq!(denied.status, ApprovalStatus::Denied);
    }

    #[tokio::test]
    async fn test_escalation() {
        let workflow = ApprovalWorkflow::default();
        // Register the user with sufficient privileges (Analyst level)
        workflow
            .register_approver("analyst1", ApprovalLevel::Analyst)
            .await;

        let request = workflow
            .create_request(
                Uuid::new_v4(),
                Uuid::new_v4(),
                "isolate_host".to_string(),
                "server-001".to_string(),
                "Critical".to_string(),
                ApprovalLevel::Analyst,
                "ai".to_string(),
            )
            .await;

        let escalated = workflow
            .escalate(request.id, "analyst1", "Need manager approval")
            .await
            .unwrap();

        assert_eq!(escalated.required_level, ApprovalLevel::Senior);
        // Verify audit context contains escalator level
        assert!(escalated.context.contains_key("escalator_level"));
        assert_eq!(
            escalated.context.get("escalator_level"),
            Some(&serde_json::json!("Analyst"))
        );
    }

    #[tokio::test]
    async fn test_approval_level_ordering() {
        assert!(ApprovalLevel::Executive > ApprovalLevel::Manager);
        assert!(ApprovalLevel::Manager > ApprovalLevel::Senior);
        assert!(ApprovalLevel::Senior > ApprovalLevel::Analyst);
    }

    #[tokio::test]
    async fn test_escalation_increments_version() {
        let workflow = ApprovalWorkflow::default();
        // Register users with appropriate privilege levels
        workflow
            .register_approver("analyst1", ApprovalLevel::Analyst)
            .await;
        workflow
            .register_approver("senior1", ApprovalLevel::Senior)
            .await;

        let request = workflow
            .create_request(
                Uuid::new_v4(),
                Uuid::new_v4(),
                "isolate_host".to_string(),
                "server-001".to_string(),
                "Critical".to_string(),
                ApprovalLevel::Analyst,
                "ai".to_string(),
            )
            .await;

        assert_eq!(request.version, 0);

        let escalated = workflow
            .escalate(request.id, "analyst1", "Need senior approval")
            .await
            .unwrap();

        assert_eq!(escalated.version, 1);
        assert_eq!(escalated.required_level, ApprovalLevel::Senior);

        // Escalate again - need Senior level user to escalate from Senior
        let escalated2 = workflow
            .escalate(request.id, "senior1", "Need manager approval")
            .await
            .unwrap();

        assert_eq!(escalated2.version, 2);
        assert_eq!(escalated2.required_level, ApprovalLevel::Manager);
    }

    #[tokio::test]
    async fn test_escalation_with_stale_version_fails() {
        let workflow = ApprovalWorkflow::default();
        // Register users with appropriate privileges
        workflow
            .register_approver("user1", ApprovalLevel::Analyst)
            .await;
        workflow
            .register_approver("user2", ApprovalLevel::Analyst)
            .await;

        let request = workflow
            .create_request(
                Uuid::new_v4(),
                Uuid::new_v4(),
                "isolate_host".to_string(),
                "server-001".to_string(),
                "Critical".to_string(),
                ApprovalLevel::Analyst,
                "ai".to_string(),
            )
            .await;

        // First escalation succeeds
        let _ = workflow
            .escalate_with_version(request.id, "user1", "First escalation", 0)
            .await
            .unwrap();

        // Second escalation with stale version should fail
        let result = workflow
            .escalate_with_version(request.id, "user2", "Second escalation", 0)
            .await;

        assert!(matches!(
            result,
            Err(ApprovalError::ConcurrentModification {
                expected: 0,
                actual: 1
            })
        ));
    }

    #[tokio::test]
    async fn test_escalation_max_level_error() {
        let workflow = ApprovalWorkflow::default();
        // Executive level user is required to escalate Executive-level requests
        workflow
            .register_approver("exec1", ApprovalLevel::Executive)
            .await;

        let request = workflow
            .create_request(
                Uuid::new_v4(),
                Uuid::new_v4(),
                "isolate_host".to_string(),
                "server-001".to_string(),
                "Critical".to_string(),
                ApprovalLevel::Executive,
                "ai".to_string(),
            )
            .await;

        let result = workflow
            .escalate(request.id, "exec1", "Cannot escalate higher")
            .await;

        assert!(matches!(result, Err(ApprovalError::MaxEscalationReached)));
    }

    #[tokio::test]
    async fn test_escalation_updates_ttl_atomically() {
        let workflow = ApprovalWorkflow::default();
        workflow
            .register_approver("analyst1", ApprovalLevel::Analyst)
            .await;

        let request = workflow
            .create_request(
                Uuid::new_v4(),
                Uuid::new_v4(),
                "isolate_host".to_string(),
                "server-001".to_string(),
                "Critical".to_string(),
                ApprovalLevel::Analyst,
                "ai".to_string(),
            )
            .await;

        let original_expires_at = request.expires_at;

        let escalated = workflow
            .escalate(request.id, "analyst1", "Need senior approval")
            .await
            .unwrap();

        // TTL should be updated (Senior level has 60 min TTL vs Analyst's 30 min)
        // The new expires_at should be recalculated from now
        assert!(escalated.expires_at > original_expires_at);

        // Verify context contains escalation metadata including escalator level
        assert!(escalated.context.contains_key("escalation_reason"));
        assert!(escalated.context.contains_key("escalated_by"));
        assert!(escalated.context.contains_key("escalation_timestamp"));
        assert!(escalated.context.contains_key("escalator_level"));
        assert!(escalated.context.contains_key("previous_level"));
    }

    #[tokio::test]
    async fn test_concurrent_escalations_only_one_succeeds() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let workflow = Arc::new(ApprovalWorkflow::default());

        // Register all concurrent users with appropriate privileges
        for i in 0..10 {
            workflow
                .register_approver(&format!("user{}", i), ApprovalLevel::Analyst)
                .await;
        }

        let request = workflow
            .create_request(
                Uuid::new_v4(),
                Uuid::new_v4(),
                "isolate_host".to_string(),
                "server-001".to_string(),
                "Critical".to_string(),
                ApprovalLevel::Analyst,
                "ai".to_string(),
            )
            .await;

        let request_id = request.id;
        let success_count = Arc::new(AtomicUsize::new(0));
        let conflict_count = Arc::new(AtomicUsize::new(0));

        // Spawn multiple concurrent escalation attempts
        let mut handles = Vec::new();
        for i in 0..10 {
            let wf = workflow.clone();
            let sc = success_count.clone();
            let cc = conflict_count.clone();
            let handle = tokio::spawn(async move {
                let result = wf
                    .escalate_with_version(
                        request_id,
                        &format!("user{}", i),
                        "Concurrent escalation",
                        0,
                    )
                    .await;
                match result {
                    Ok(_) => {
                        sc.fetch_add(1, Ordering::SeqCst);
                    }
                    Err(ApprovalError::ConcurrentModification { .. }) => {
                        cc.fetch_add(1, Ordering::SeqCst);
                    }
                    Err(_) => {}
                }
            });
            handles.push(handle);
        }

        // Wait for all tasks to complete
        for handle in handles {
            handle.await.unwrap();
        }

        // Exactly one should succeed, the rest should fail with concurrent modification
        assert_eq!(success_count.load(Ordering::SeqCst), 1);
        assert_eq!(conflict_count.load(Ordering::SeqCst), 9);

        // Verify the request was escalated exactly once
        let final_request = workflow.get_request(request_id).await.unwrap();
        assert_eq!(final_request.required_level, ApprovalLevel::Senior);
        assert_eq!(final_request.version, 1);
    }

    #[tokio::test]
    async fn test_escalate_with_retry_succeeds_after_conflict() {
        let workflow = Arc::new(ApprovalWorkflow::default());
        // Register users with appropriate privileges
        workflow
            .register_approver("user1", ApprovalLevel::Analyst)
            .await;
        workflow
            .register_approver("user2", ApprovalLevel::Senior)
            .await;

        let request = workflow
            .create_request(
                Uuid::new_v4(),
                Uuid::new_v4(),
                "isolate_host".to_string(),
                "server-001".to_string(),
                "Critical".to_string(),
                ApprovalLevel::Analyst,
                "ai".to_string(),
            )
            .await;

        let request_id = request.id;

        // First, do an escalation to Senior
        let _ = workflow
            .escalate(request_id, "user1", "First escalation")
            .await
            .unwrap();

        // Use retry version which should handle the version mismatch
        // user2 needs Senior level to escalate from Senior
        let result = workflow
            .escalate_with_retry(request_id, "user2", "Retry escalation", 3)
            .await;

        assert!(result.is_ok());
        let escalated = result.unwrap();
        assert_eq!(escalated.required_level, ApprovalLevel::Manager);
        assert_eq!(escalated.version, 2);
    }

    #[tokio::test]
    async fn test_escalation_context_preserves_history() {
        let workflow = ApprovalWorkflow::default();
        workflow
            .register_approver("analyst1", ApprovalLevel::Analyst)
            .await;
        workflow
            .register_approver("senior1", ApprovalLevel::Senior)
            .await;

        let request = workflow
            .create_request(
                Uuid::new_v4(),
                Uuid::new_v4(),
                "isolate_host".to_string(),
                "server-001".to_string(),
                "Critical".to_string(),
                ApprovalLevel::Analyst,
                "ai".to_string(),
            )
            .await;

        // First escalation
        let escalated1 = workflow
            .escalate(request.id, "analyst1", "Need senior review")
            .await
            .unwrap();

        assert_eq!(
            escalated1.context.get("previous_level"),
            Some(&serde_json::json!("Analyst"))
        );
        assert_eq!(
            escalated1.context.get("escalation_reason"),
            Some(&serde_json::json!("Need senior review"))
        );
        assert_eq!(
            escalated1.context.get("escalator_level"),
            Some(&serde_json::json!("Analyst"))
        );

        // Second escalation (overwrites context, but that's expected per-escalation)
        // senior1 needs Senior level to escalate from Senior
        let escalated2 = workflow
            .escalate(request.id, "senior1", "Need manager approval")
            .await
            .unwrap();

        assert_eq!(
            escalated2.context.get("previous_level"),
            Some(&serde_json::json!("Senior"))
        );
        assert_eq!(
            escalated2.context.get("escalation_reason"),
            Some(&serde_json::json!("Need manager approval"))
        );
        assert_eq!(
            escalated2.context.get("escalator_level"),
            Some(&serde_json::json!("Senior"))
        );
    }

    #[tokio::test]
    async fn test_escalation_full_chain() {
        let workflow = ApprovalWorkflow::default();
        // Register users at each level for the escalation chain
        workflow
            .register_approver("user1", ApprovalLevel::Analyst)
            .await;
        workflow
            .register_approver("user2", ApprovalLevel::Senior)
            .await;
        workflow
            .register_approver("user3", ApprovalLevel::Manager)
            .await;
        workflow
            .register_approver("user4", ApprovalLevel::Executive)
            .await;

        let request = workflow
            .create_request(
                Uuid::new_v4(),
                Uuid::new_v4(),
                "isolate_host".to_string(),
                "server-001".to_string(),
                "Critical".to_string(),
                ApprovalLevel::Analyst,
                "ai".to_string(),
            )
            .await;

        // Escalate through all levels - each escalation requires user with current level
        let e1 = workflow
            .escalate(request.id, "user1", "To Senior")
            .await
            .unwrap();
        assert_eq!(e1.required_level, ApprovalLevel::Senior);
        assert_eq!(e1.version, 1);

        let e2 = workflow
            .escalate(request.id, "user2", "To Manager")
            .await
            .unwrap();
        assert_eq!(e2.required_level, ApprovalLevel::Manager);
        assert_eq!(e2.version, 2);

        let e3 = workflow
            .escalate(request.id, "user3", "To Executive")
            .await
            .unwrap();
        assert_eq!(e3.required_level, ApprovalLevel::Executive);
        assert_eq!(e3.version, 3);

        // Further escalation should fail (already at Executive)
        let result = workflow
            .escalate(request.id, "user4", "Beyond Executive")
            .await;
        assert!(matches!(result, Err(ApprovalError::MaxEscalationReached)));
    }

    #[tokio::test]
    async fn test_escalation_of_processed_request_fails() {
        let workflow = ApprovalWorkflow::default();
        workflow
            .register_approver("analyst1", ApprovalLevel::Analyst)
            .await;
        workflow
            .register_approver("user1", ApprovalLevel::Analyst)
            .await;

        let request = workflow
            .create_request(
                Uuid::new_v4(),
                Uuid::new_v4(),
                "isolate_host".to_string(),
                "server-001".to_string(),
                "Critical".to_string(),
                ApprovalLevel::Analyst,
                "ai".to_string(),
            )
            .await;

        // Approve the request first
        let _ = workflow
            .approve(request.id, "analyst1", Some("Approved".to_string()))
            .await
            .unwrap();

        // Attempt to escalate should fail
        let result = workflow.escalate(request.id, "user1", "Too late").await;

        assert!(matches!(result, Err(ApprovalError::AlreadyProcessed)));
    }

    // ==================== Task 7.3: Escalation Privilege Check Tests ====================

    #[tokio::test]
    async fn test_escalation_requires_registered_approver() {
        let workflow = ApprovalWorkflow::default();

        let request = workflow
            .create_request(
                Uuid::new_v4(),
                Uuid::new_v4(),
                "isolate_host".to_string(),
                "server-001".to_string(),
                "Critical".to_string(),
                ApprovalLevel::Analyst,
                "ai".to_string(),
            )
            .await;

        // Unregistered user should not be able to escalate
        let result = workflow
            .escalate(request.id, "unregistered_user", "Escalation attempt")
            .await;

        assert!(matches!(result, Err(ApprovalError::InvalidApprover(_))));
        if let Err(ApprovalError::InvalidApprover(user)) = result {
            assert_eq!(user, "unregistered_user");
        }
    }

    #[tokio::test]
    async fn test_escalation_privilege_check_analyst_cannot_escalate_senior_request() {
        let workflow = ApprovalWorkflow::default();
        workflow
            .register_approver("analyst1", ApprovalLevel::Analyst)
            .await;
        workflow
            .register_approver("senior1", ApprovalLevel::Senior)
            .await;

        // Create a request that's already at Senior level
        let request = workflow
            .create_request(
                Uuid::new_v4(),
                Uuid::new_v4(),
                "isolate_host".to_string(),
                "server-001".to_string(),
                "Critical".to_string(),
                ApprovalLevel::Senior,
                "ai".to_string(),
            )
            .await;

        // Analyst should not be able to escalate a Senior-level request
        let result = workflow
            .escalate(request.id, "analyst1", "Trying to escalate")
            .await;

        assert!(matches!(
            result,
            Err(ApprovalError::InsufficientEscalationPrivileges { .. })
        ));

        if let Err(ApprovalError::InsufficientEscalationPrivileges {
            user_level,
            target_level,
            minimum_required,
        }) = result
        {
            assert_eq!(user_level, ApprovalLevel::Analyst);
            assert_eq!(target_level, ApprovalLevel::Manager);
            assert_eq!(minimum_required, ApprovalLevel::Senior);
        }

        // But Senior user should be able to escalate
        let result = workflow
            .escalate(request.id, "senior1", "Senior escalating")
            .await;
        assert!(result.is_ok());
        let escalated = result.unwrap();
        assert_eq!(escalated.required_level, ApprovalLevel::Manager);
    }

    #[tokio::test]
    async fn test_escalation_privilege_check_analyst_can_escalate_analyst_request() {
        let workflow = ApprovalWorkflow::default();
        workflow
            .register_approver("analyst1", ApprovalLevel::Analyst)
            .await;

        let request = workflow
            .create_request(
                Uuid::new_v4(),
                Uuid::new_v4(),
                "isolate_host".to_string(),
                "server-001".to_string(),
                "Critical".to_string(),
                ApprovalLevel::Analyst,
                "ai".to_string(),
            )
            .await;

        // Analyst should be able to escalate an Analyst-level request
        let result = workflow
            .escalate(request.id, "analyst1", "Escalating to Senior")
            .await;

        assert!(result.is_ok());
        let escalated = result.unwrap();
        assert_eq!(escalated.required_level, ApprovalLevel::Senior);
    }

    #[tokio::test]
    async fn test_escalation_privilege_check_higher_level_user_can_escalate() {
        let workflow = ApprovalWorkflow::default();
        workflow
            .register_approver("manager1", ApprovalLevel::Manager)
            .await;

        let request = workflow
            .create_request(
                Uuid::new_v4(),
                Uuid::new_v4(),
                "isolate_host".to_string(),
                "server-001".to_string(),
                "Critical".to_string(),
                ApprovalLevel::Analyst,
                "ai".to_string(),
            )
            .await;

        // Manager should be able to escalate an Analyst-level request
        let result = workflow
            .escalate(request.id, "manager1", "Manager escalating")
            .await;

        assert!(result.is_ok());
        let escalated = result.unwrap();
        assert_eq!(escalated.required_level, ApprovalLevel::Senior);
        assert_eq!(
            escalated.context.get("escalator_level"),
            Some(&serde_json::json!("Manager"))
        );
    }

    #[tokio::test]
    async fn test_escalation_privilege_check_senior_cannot_escalate_manager_request() {
        let workflow = ApprovalWorkflow::default();
        workflow
            .register_approver("senior1", ApprovalLevel::Senior)
            .await;

        let request = workflow
            .create_request(
                Uuid::new_v4(),
                Uuid::new_v4(),
                "isolate_host".to_string(),
                "server-001".to_string(),
                "Critical".to_string(),
                ApprovalLevel::Manager,
                "ai".to_string(),
            )
            .await;

        // Senior should not be able to escalate a Manager-level request
        let result = workflow
            .escalate(request.id, "senior1", "Trying to escalate")
            .await;

        assert!(matches!(
            result,
            Err(ApprovalError::InsufficientEscalationPrivileges { .. })
        ));

        if let Err(ApprovalError::InsufficientEscalationPrivileges {
            user_level,
            target_level,
            minimum_required,
        }) = result
        {
            assert_eq!(user_level, ApprovalLevel::Senior);
            assert_eq!(target_level, ApprovalLevel::Executive);
            assert_eq!(minimum_required, ApprovalLevel::Manager);
        }
    }

    #[tokio::test]
    async fn test_escalation_audit_log_includes_actor_info() {
        let workflow = ApprovalWorkflow::default();
        workflow
            .register_approver("senior_analyst", ApprovalLevel::Senior)
            .await;

        let request = workflow
            .create_request(
                Uuid::new_v4(),
                Uuid::new_v4(),
                "isolate_host".to_string(),
                "server-001".to_string(),
                "Critical".to_string(),
                ApprovalLevel::Analyst,
                "ai".to_string(),
            )
            .await;

        let escalated = workflow
            .escalate(request.id, "senior_analyst", "Escalating for review")
            .await
            .unwrap();

        // Verify comprehensive audit context
        assert_eq!(
            escalated.context.get("escalated_by"),
            Some(&serde_json::json!("senior_analyst"))
        );
        assert_eq!(
            escalated.context.get("escalator_level"),
            Some(&serde_json::json!("Senior"))
        );
        assert_eq!(
            escalated.context.get("escalation_reason"),
            Some(&serde_json::json!("Escalating for review"))
        );
        assert_eq!(
            escalated.context.get("previous_level"),
            Some(&serde_json::json!("Analyst"))
        );
        assert!(escalated.context.contains_key("escalation_timestamp"));

        // Verify timestamp is a valid RFC3339 string
        if let Some(serde_json::Value::String(ts)) = escalated.context.get("escalation_timestamp") {
            assert!(ts.contains('T'), "Timestamp should be in RFC3339 format");
        }
    }

    #[tokio::test]
    async fn test_escalation_error_message_is_clear() {
        let workflow = ApprovalWorkflow::default();
        workflow
            .register_approver("analyst1", ApprovalLevel::Analyst)
            .await;

        let request = workflow
            .create_request(
                Uuid::new_v4(),
                Uuid::new_v4(),
                "isolate_host".to_string(),
                "server-001".to_string(),
                "Critical".to_string(),
                ApprovalLevel::Manager,
                "ai".to_string(),
            )
            .await;

        let result = workflow
            .escalate(request.id, "analyst1", "Trying to escalate")
            .await;

        // Verify error message contains all relevant information
        let error = result.unwrap_err();
        let error_message = error.to_string();

        assert!(
            error_message.contains("Analyst"),
            "Error should mention user's level"
        );
        assert!(
            error_message.contains("Executive"),
            "Error should mention target level"
        );
        assert!(
            error_message.contains("Manager"),
            "Error should mention minimum required level"
        );
    }
}
