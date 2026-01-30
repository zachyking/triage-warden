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
        }
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
    #[instrument(skip(self))]
    pub async fn escalate(
        &self,
        request_id: Uuid,
        escalated_by: &str,
        reason: &str,
    ) -> Result<ApprovalRequest, ApprovalError> {
        if !self.config.allow_escalation {
            return Err(ApprovalError::InsufficientPrivileges(
                ApprovalLevel::Executive,
            ));
        }

        let mut requests = self.requests.write().await;
        let request = requests
            .get_mut(&request_id)
            .ok_or(ApprovalError::NotFound(request_id))?;

        if request.status != ApprovalStatus::Pending {
            return Err(ApprovalError::AlreadyProcessed);
        }

        // Escalate to next level
        let new_level = match request.required_level {
            ApprovalLevel::Analyst => ApprovalLevel::Senior,
            ApprovalLevel::Senior => ApprovalLevel::Manager,
            ApprovalLevel::Manager => ApprovalLevel::Executive,
            ApprovalLevel::Executive => ApprovalLevel::Executive, // Can't escalate higher
        };

        request.required_level = new_level;
        request
            .context
            .insert("escalation_reason".to_string(), serde_json::json!(reason));
        request
            .context
            .insert("escalated_by".to_string(), serde_json::json!(escalated_by));

        // Update TTL
        let new_ttl = self
            .config
            .level_ttl_minutes
            .get(&new_level)
            .copied()
            .unwrap_or(self.config.default_ttl_minutes);
        request.expires_at = Utc::now() + Duration::minutes(new_ttl);

        info!(
            "Request {} escalated to {:?} by {}",
            request_id, new_level, escalated_by
        );

        Ok(request.clone())
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
    }

    #[tokio::test]
    async fn test_approval_level_ordering() {
        assert!(ApprovalLevel::Executive > ApprovalLevel::Manager);
        assert!(ApprovalLevel::Manager > ApprovalLevel::Senior);
        assert!(ApprovalLevel::Senior > ApprovalLevel::Analyst);
    }
}
