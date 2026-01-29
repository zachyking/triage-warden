//! Approval tracking system for actions requiring human approval.
//!
//! This module provides a lightweight approval manager for tracking
//! approval requests and their lifecycle.

use crate::approval::ApprovalLevel;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{info, warn};
use uuid::Uuid;

/// Errors that can occur in approval management.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ApprovalError {
    /// Approval request not found.
    #[error("Approval request not found: {0}")]
    NotFound(Uuid),

    /// Approval request has already been decided.
    #[error("Approval request has already been decided")]
    AlreadyDecided,

    /// Approval request has expired.
    #[error("Approval request has expired")]
    Expired,
}

/// Status of an approval request in the manager.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    /// Awaiting decision.
    Pending,
    /// Approved by an approver.
    Approved,
    /// Denied by an approver.
    Denied,
    /// Expired without action.
    Expired,
    /// Cancelled by the requester or system.
    Cancelled,
}

/// An approval request tracked by the manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    /// Unique identifier for the request.
    pub id: Uuid,
    /// Type of action requiring approval.
    pub action_type: String,
    /// Target of the action (e.g., hostname, IP address).
    pub target: String,
    /// Required approval level.
    pub required_level: ApprovalLevel,
    /// Who requested the approval.
    pub requester: String,
    /// When the request was created.
    pub created_at: DateTime<Utc>,
    /// When the request expires.
    pub expires_at: DateTime<Utc>,
    /// Current status of the request.
    pub status: ApprovalStatus,
    /// Who made the decision (if decided).
    pub decision_by: Option<String>,
    /// When the decision was made.
    pub decision_at: Option<DateTime<Utc>>,
    /// Comment from the decision maker.
    pub decision_comment: Option<String>,
}

impl ApprovalRequest {
    /// Checks if the request has expired based on current time.
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Checks if the request is still pending and not expired.
    pub fn is_pending(&self) -> bool {
        self.status == ApprovalStatus::Pending && !self.is_expired()
    }
}

/// Manager for tracking approval requests.
///
/// Provides thread-safe storage and operations for approval requests,
/// including submission, approval, denial, cancellation, and cleanup.
#[derive(Clone)]
pub struct ApprovalManager {
    /// Storage for approval requests.
    requests: Arc<RwLock<HashMap<Uuid, ApprovalRequest>>>,
    /// Default expiration time in seconds.
    default_expiration_secs: u64,
}

impl ApprovalManager {
    /// Creates a new ApprovalManager with the specified expiration time.
    ///
    /// # Arguments
    ///
    /// * `expiration_secs` - Default expiration time for requests in seconds
    pub fn new(expiration_secs: u64) -> Self {
        Self {
            requests: Arc::new(RwLock::new(HashMap::new())),
            default_expiration_secs: expiration_secs,
        }
    }

    /// Submits a new approval request.
    ///
    /// # Arguments
    ///
    /// * `action_type` - Type of action requiring approval
    /// * `target` - Target of the action
    /// * `level` - Required approval level
    /// * `requester` - Who is requesting the approval
    ///
    /// # Returns
    ///
    /// The created ApprovalRequest
    pub async fn submit_request(
        &self,
        action_type: &str,
        target: &str,
        level: ApprovalLevel,
        requester: &str,
    ) -> ApprovalRequest {
        let now = Utc::now();
        let request = ApprovalRequest {
            id: Uuid::new_v4(),
            action_type: action_type.to_string(),
            target: target.to_string(),
            required_level: level,
            requester: requester.to_string(),
            created_at: now,
            expires_at: now + Duration::seconds(self.default_expiration_secs as i64),
            status: ApprovalStatus::Pending,
            decision_by: None,
            decision_at: None,
            decision_comment: None,
        };

        let mut requests = self.requests.write().await;
        requests.insert(request.id, request.clone());

        info!(
            request_id = %request.id,
            action_type = %action_type,
            target = %target,
            level = ?level,
            requester = %requester,
            expires_at = %request.expires_at,
            "Approval request submitted"
        );

        request
    }

    /// Approves a pending request.
    ///
    /// # Arguments
    ///
    /// * `request_id` - ID of the request to approve
    /// * `approver` - Who is approving the request
    /// * `comment` - Optional comment from the approver
    ///
    /// # Returns
    ///
    /// The updated ApprovalRequest or an error
    pub async fn approve(
        &self,
        request_id: Uuid,
        approver: &str,
        comment: Option<&str>,
    ) -> Result<ApprovalRequest, ApprovalError> {
        let mut requests = self.requests.write().await;
        let request = requests
            .get_mut(&request_id)
            .ok_or(ApprovalError::NotFound(request_id))?;

        // Check if already decided
        if request.status != ApprovalStatus::Pending {
            return Err(ApprovalError::AlreadyDecided);
        }

        // Check if expired
        if request.is_expired() {
            request.status = ApprovalStatus::Expired;
            warn!(
                request_id = %request_id,
                "Attempted to approve expired request"
            );
            return Err(ApprovalError::Expired);
        }

        // Update the request
        request.status = ApprovalStatus::Approved;
        request.decision_by = Some(approver.to_string());
        request.decision_at = Some(Utc::now());
        request.decision_comment = comment.map(String::from);

        info!(
            request_id = %request_id,
            approver = %approver,
            action_type = %request.action_type,
            target = %request.target,
            comment = ?comment,
            "Approval request approved"
        );

        Ok(request.clone())
    }

    /// Denies a pending request.
    ///
    /// # Arguments
    ///
    /// * `request_id` - ID of the request to deny
    /// * `denier` - Who is denying the request
    /// * `reason` - Reason for denial
    ///
    /// # Returns
    ///
    /// The updated ApprovalRequest or an error
    pub async fn deny(
        &self,
        request_id: Uuid,
        denier: &str,
        reason: &str,
    ) -> Result<ApprovalRequest, ApprovalError> {
        let mut requests = self.requests.write().await;
        let request = requests
            .get_mut(&request_id)
            .ok_or(ApprovalError::NotFound(request_id))?;

        // Check if already decided
        if request.status != ApprovalStatus::Pending {
            return Err(ApprovalError::AlreadyDecided);
        }

        // Check if expired
        if request.is_expired() {
            request.status = ApprovalStatus::Expired;
            warn!(
                request_id = %request_id,
                "Attempted to deny expired request"
            );
            return Err(ApprovalError::Expired);
        }

        // Update the request
        request.status = ApprovalStatus::Denied;
        request.decision_by = Some(denier.to_string());
        request.decision_at = Some(Utc::now());
        request.decision_comment = Some(reason.to_string());

        info!(
            request_id = %request_id,
            denier = %denier,
            action_type = %request.action_type,
            target = %request.target,
            reason = %reason,
            "Approval request denied"
        );

        Ok(request.clone())
    }

    /// Cancels a pending request.
    ///
    /// # Arguments
    ///
    /// * `request_id` - ID of the request to cancel
    ///
    /// # Returns
    ///
    /// Ok(()) on success or an error
    pub async fn cancel(&self, request_id: Uuid) -> Result<(), ApprovalError> {
        let mut requests = self.requests.write().await;
        let request = requests
            .get_mut(&request_id)
            .ok_or(ApprovalError::NotFound(request_id))?;

        // Check if already decided
        if request.status != ApprovalStatus::Pending {
            return Err(ApprovalError::AlreadyDecided);
        }

        // Update the request
        request.status = ApprovalStatus::Cancelled;
        request.decision_at = Some(Utc::now());

        info!(
            request_id = %request_id,
            action_type = %request.action_type,
            target = %request.target,
            "Approval request cancelled"
        );

        Ok(())
    }

    /// Gets a request by ID.
    ///
    /// # Arguments
    ///
    /// * `request_id` - ID of the request to retrieve
    ///
    /// # Returns
    ///
    /// The ApprovalRequest if found, None otherwise
    pub async fn get_request(&self, request_id: Uuid) -> Option<ApprovalRequest> {
        let requests = self.requests.read().await;
        requests.get(&request_id).cloned()
    }

    /// Lists all pending requests that have not expired.
    ///
    /// # Returns
    ///
    /// A vector of pending ApprovalRequests
    pub async fn list_pending(&self) -> Vec<ApprovalRequest> {
        let requests = self.requests.read().await;
        requests
            .values()
            .filter(|r| r.is_pending())
            .cloned()
            .collect()
    }

    /// Marks expired requests and returns the count of newly expired requests.
    ///
    /// This method scans all pending requests and marks those that have
    /// passed their expiration time as Expired.
    ///
    /// # Returns
    ///
    /// The number of requests that were marked as expired
    pub async fn cleanup_expired(&self) -> usize {
        let mut requests = self.requests.write().await;
        let mut count = 0;

        for request in requests.values_mut() {
            if request.status == ApprovalStatus::Pending && request.is_expired() {
                request.status = ApprovalStatus::Expired;
                request.decision_at = Some(Utc::now());
                count += 1;

                info!(
                    request_id = %request.id,
                    action_type = %request.action_type,
                    target = %request.target,
                    "Approval request expired"
                );
            }
        }

        if count > 0 {
            warn!(count = count, "Cleaned up expired approval requests");
        }

        count
    }
}

impl Default for ApprovalManager {
    fn default() -> Self {
        Self::new(3600) // Default: 1 hour
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_submit_request() {
        let manager = ApprovalManager::new(3600);

        let request = manager
            .submit_request(
                "isolate_host",
                "workstation-001",
                ApprovalLevel::Analyst,
                "ai-system",
            )
            .await;

        assert_eq!(request.action_type, "isolate_host");
        assert_eq!(request.target, "workstation-001");
        assert_eq!(request.required_level, ApprovalLevel::Analyst);
        assert_eq!(request.requester, "ai-system");
        assert_eq!(request.status, ApprovalStatus::Pending);
        assert!(request.decision_by.is_none());
        assert!(request.decision_at.is_none());
        assert!(request.decision_comment.is_none());
    }

    #[tokio::test]
    async fn test_approve_request() {
        let manager = ApprovalManager::new(3600);

        let request = manager
            .submit_request(
                "block_ip",
                "192.168.1.100",
                ApprovalLevel::Senior,
                "ai-system",
            )
            .await;

        let approved = manager
            .approve(request.id, "analyst@example.com", Some("Looks legitimate"))
            .await
            .unwrap();

        assert_eq!(approved.status, ApprovalStatus::Approved);
        assert_eq!(approved.decision_by, Some("analyst@example.com".to_string()));
        assert!(approved.decision_at.is_some());
        assert_eq!(
            approved.decision_comment,
            Some("Looks legitimate".to_string())
        );
    }

    #[tokio::test]
    async fn test_approve_without_comment() {
        let manager = ApprovalManager::new(3600);

        let request = manager
            .submit_request(
                "block_ip",
                "192.168.1.100",
                ApprovalLevel::Analyst,
                "ai-system",
            )
            .await;

        let approved = manager
            .approve(request.id, "analyst@example.com", None)
            .await
            .unwrap();

        assert_eq!(approved.status, ApprovalStatus::Approved);
        assert!(approved.decision_comment.is_none());
    }

    #[tokio::test]
    async fn test_deny_request() {
        let manager = ApprovalManager::new(3600);

        let request = manager
            .submit_request(
                "disable_account",
                "user@example.com",
                ApprovalLevel::Manager,
                "ai-system",
            )
            .await;

        let denied = manager
            .deny(request.id, "manager@example.com", "False positive")
            .await
            .unwrap();

        assert_eq!(denied.status, ApprovalStatus::Denied);
        assert_eq!(denied.decision_by, Some("manager@example.com".to_string()));
        assert!(denied.decision_at.is_some());
        assert_eq!(denied.decision_comment, Some("False positive".to_string()));
    }

    #[tokio::test]
    async fn test_cancel_request() {
        let manager = ApprovalManager::new(3600);

        let request = manager
            .submit_request(
                "quarantine_file",
                "/tmp/suspicious.exe",
                ApprovalLevel::Analyst,
                "ai-system",
            )
            .await;

        manager.cancel(request.id).await.unwrap();

        let updated = manager.get_request(request.id).await.unwrap();
        assert_eq!(updated.status, ApprovalStatus::Cancelled);
        assert!(updated.decision_at.is_some());
    }

    #[tokio::test]
    async fn test_get_request() {
        let manager = ApprovalManager::new(3600);

        let request = manager
            .submit_request(
                "isolate_host",
                "server-001",
                ApprovalLevel::Executive,
                "ai-system",
            )
            .await;

        let retrieved = manager.get_request(request.id).await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().id, request.id);

        // Non-existent request
        let non_existent = manager.get_request(Uuid::new_v4()).await;
        assert!(non_existent.is_none());
    }

    #[tokio::test]
    async fn test_list_pending() {
        let manager = ApprovalManager::new(3600);

        // Create multiple requests
        let request1 = manager
            .submit_request(
                "action1",
                "target1",
                ApprovalLevel::Analyst,
                "requester",
            )
            .await;

        let request2 = manager
            .submit_request(
                "action2",
                "target2",
                ApprovalLevel::Senior,
                "requester",
            )
            .await;

        let request3 = manager
            .submit_request(
                "action3",
                "target3",
                ApprovalLevel::Manager,
                "requester",
            )
            .await;

        // Approve one, deny another
        manager
            .approve(request1.id, "approver", None)
            .await
            .unwrap();
        manager
            .deny(request2.id, "denier", "Not needed")
            .await
            .unwrap();

        let pending = manager.list_pending().await;
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, request3.id);
    }

    #[tokio::test]
    async fn test_approve_not_found() {
        let manager = ApprovalManager::new(3600);

        let result = manager
            .approve(Uuid::new_v4(), "approver", None)
            .await;

        assert!(matches!(result, Err(ApprovalError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_approve_already_decided() {
        let manager = ApprovalManager::new(3600);

        let request = manager
            .submit_request(
                "action",
                "target",
                ApprovalLevel::Analyst,
                "requester",
            )
            .await;

        // First approval succeeds
        manager
            .approve(request.id, "approver1", None)
            .await
            .unwrap();

        // Second approval fails
        let result = manager.approve(request.id, "approver2", None).await;
        assert!(matches!(result, Err(ApprovalError::AlreadyDecided)));
    }

    #[tokio::test]
    async fn test_deny_already_decided() {
        let manager = ApprovalManager::new(3600);

        let request = manager
            .submit_request(
                "action",
                "target",
                ApprovalLevel::Analyst,
                "requester",
            )
            .await;

        // First denial succeeds
        manager
            .deny(request.id, "denier1", "reason1")
            .await
            .unwrap();

        // Second denial fails
        let result = manager.deny(request.id, "denier2", "reason2").await;
        assert!(matches!(result, Err(ApprovalError::AlreadyDecided)));
    }

    #[tokio::test]
    async fn test_cancel_already_decided() {
        let manager = ApprovalManager::new(3600);

        let request = manager
            .submit_request(
                "action",
                "target",
                ApprovalLevel::Analyst,
                "requester",
            )
            .await;

        // Approve first
        manager
            .approve(request.id, "approver", None)
            .await
            .unwrap();

        // Cancel fails
        let result = manager.cancel(request.id).await;
        assert!(matches!(result, Err(ApprovalError::AlreadyDecided)));
    }

    #[tokio::test]
    async fn test_deny_not_found() {
        let manager = ApprovalManager::new(3600);

        let result = manager
            .deny(Uuid::new_v4(), "denier", "reason")
            .await;

        assert!(matches!(result, Err(ApprovalError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_cancel_not_found() {
        let manager = ApprovalManager::new(3600);

        let result = manager.cancel(Uuid::new_v4()).await;
        assert!(matches!(result, Err(ApprovalError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_cleanup_expired() {
        // Use a very short expiration (1 second)
        let manager = ApprovalManager::new(1);

        // Create a request
        let request = manager
            .submit_request(
                "action",
                "target",
                ApprovalLevel::Analyst,
                "requester",
            )
            .await;

        // Wait for expiration
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        // Cleanup should mark it as expired
        let count = manager.cleanup_expired().await;
        assert_eq!(count, 1);

        // Verify status
        let updated = manager.get_request(request.id).await.unwrap();
        assert_eq!(updated.status, ApprovalStatus::Expired);
        assert!(updated.decision_at.is_some());
    }

    #[tokio::test]
    async fn test_approve_expired_request() {
        // Use a very short expiration (1 second)
        let manager = ApprovalManager::new(1);

        let request = manager
            .submit_request(
                "action",
                "target",
                ApprovalLevel::Analyst,
                "requester",
            )
            .await;

        // Wait for expiration
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        // Attempting to approve should fail with Expired
        let result = manager.approve(request.id, "approver", None).await;
        assert!(matches!(result, Err(ApprovalError::Expired)));

        // Verify status was updated to Expired
        let updated = manager.get_request(request.id).await.unwrap();
        assert_eq!(updated.status, ApprovalStatus::Expired);
    }

    #[tokio::test]
    async fn test_deny_expired_request() {
        // Use a very short expiration (1 second)
        let manager = ApprovalManager::new(1);

        let request = manager
            .submit_request(
                "action",
                "target",
                ApprovalLevel::Analyst,
                "requester",
            )
            .await;

        // Wait for expiration
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        // Attempting to deny should fail with Expired
        let result = manager.deny(request.id, "denier", "reason").await;
        assert!(matches!(result, Err(ApprovalError::Expired)));
    }

    #[tokio::test]
    async fn test_default_expiration() {
        let manager = ApprovalManager::default();
        assert_eq!(manager.default_expiration_secs, 3600);
    }

    #[tokio::test]
    async fn test_request_is_pending() {
        let manager = ApprovalManager::new(3600);

        let request = manager
            .submit_request(
                "action",
                "target",
                ApprovalLevel::Analyst,
                "requester",
            )
            .await;

        assert!(request.is_pending());
        assert!(!request.is_expired());
    }

    #[tokio::test]
    async fn test_cleanup_expired_multiple() {
        // Use a very short expiration (1 second)
        let manager = ApprovalManager::new(1);

        // Create multiple requests
        manager
            .submit_request("action1", "target1", ApprovalLevel::Analyst, "requester")
            .await;
        manager
            .submit_request("action2", "target2", ApprovalLevel::Senior, "requester")
            .await;
        let approved_request = manager
            .submit_request("action3", "target3", ApprovalLevel::Manager, "requester")
            .await;

        // Approve one before expiration
        manager
            .approve(approved_request.id, "approver", None)
            .await
            .unwrap();

        // Wait for expiration
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        // Cleanup should only mark pending ones as expired
        let count = manager.cleanup_expired().await;
        assert_eq!(count, 2); // Only the 2 pending ones

        // Verify the approved one is still approved
        let approved = manager.get_request(approved_request.id).await.unwrap();
        assert_eq!(approved.status, ApprovalStatus::Approved);
    }

    #[tokio::test]
    async fn test_cleanup_no_expired() {
        let manager = ApprovalManager::new(3600);

        // Create a request with long expiration
        manager
            .submit_request(
                "action",
                "target",
                ApprovalLevel::Analyst,
                "requester",
            )
            .await;

        // Cleanup should find nothing expired
        let count = manager.cleanup_expired().await;
        assert_eq!(count, 0);
    }
}
