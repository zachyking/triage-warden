//! Access review campaign and attestation models.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Scope of an access review campaign.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReviewScope {
    /// Review all users/roles in the tenant.
    TenantWide,
    /// Review explicit users only.
    Users(Vec<Uuid>),
    /// Review explicit roles only.
    Roles(Vec<Uuid>),
    /// Custom campaign scope descriptor.
    Custom(String),
}

/// Lifecycle status for an access review campaign.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReviewStatus {
    Draft,
    Active,
    Overdue,
    Completed,
    Cancelled,
}

/// Decision outcome for a reviewed access grant.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccessDecisionOutcome {
    Certified,
    Revoked,
    Modified,
    Escalated,
}

/// Reviewer decision for a target user/role access grant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessDecision {
    pub id: Uuid,
    pub review_id: Uuid,
    pub target_user_id: Uuid,
    pub role_id: Option<Uuid>,
    pub decision: AccessDecisionOutcome,
    pub decided_by: Uuid,
    pub decided_at: DateTime<Utc>,
    pub reason: Option<String>,
    pub access_change_applied: bool,
}

impl AccessDecision {
    /// Creates a new access decision record.
    pub fn new(
        review_id: Uuid,
        target_user_id: Uuid,
        role_id: Option<Uuid>,
        decision: AccessDecisionOutcome,
        decided_by: Uuid,
        reason: Option<String>,
        access_change_applied: bool,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            review_id,
            target_user_id,
            role_id,
            decision,
            decided_by,
            decided_at: Utc::now(),
            reason,
            access_change_applied,
        }
    }
}

/// Access review campaign and attestation state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessReview {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub scope: ReviewScope,
    pub reviewers: Vec<Uuid>,
    pub deadline: DateTime<Utc>,
    pub status: ReviewStatus,
    pub decisions: Vec<AccessDecision>,
    pub reminder_sent_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl AccessReview {
    /// Creates a draft campaign.
    pub fn new(
        tenant_id: Uuid,
        name: impl Into<String>,
        scope: ReviewScope,
        reviewers: Vec<Uuid>,
        deadline: DateTime<Utc>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            tenant_id,
            name: name.into(),
            scope,
            reviewers,
            deadline,
            status: ReviewStatus::Draft,
            decisions: Vec::new(),
            reminder_sent_at: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Adds an attestation decision and updates campaign timestamp.
    pub fn add_decision(&mut self, decision: AccessDecision) {
        self.decisions.push(decision);
        self.updated_at = Utc::now();
    }

    /// Updates campaign status and refreshes timestamp.
    pub fn set_status(&mut self, status: ReviewStatus) {
        self.status = status;
        self.updated_at = Utc::now();
    }

    /// Sets reminder marker timestamp.
    pub fn mark_reminder_sent(&mut self, at: DateTime<Utc>) {
        self.reminder_sent_at = Some(at);
        self.updated_at = at;
    }

    /// Returns true when a reminder should be sent for this campaign.
    pub fn is_due_for_reminder(&self, now: DateTime<Utc>, within_days: i64) -> bool {
        if !matches!(self.status, ReviewStatus::Active | ReviewStatus::Overdue) {
            return false;
        }

        if self.deadline < now {
            return true;
        }

        let reminder_window = now + Duration::days(within_days.max(0));
        if self.deadline > reminder_window {
            return false;
        }

        match self.reminder_sent_at {
            Some(sent) => sent < now - Duration::hours(24),
            None => true,
        }
    }

    /// Refreshes status to overdue when deadline has passed.
    pub fn refresh_deadline_status(&mut self, now: DateTime<Utc>) {
        if matches!(self.status, ReviewStatus::Active) && self.deadline < now {
            self.status = ReviewStatus::Overdue;
            self.updated_at = now;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_due_for_reminder_when_deadline_near() {
        let now = Utc::now();
        let mut review = AccessReview::new(
            Uuid::new_v4(),
            "Q2 Access Review",
            ReviewScope::TenantWide,
            vec![Uuid::new_v4()],
            now + Duration::days(1),
        );
        review.set_status(ReviewStatus::Active);
        assert!(review.is_due_for_reminder(now, 2));
        review.mark_reminder_sent(now);
        assert!(!review.is_due_for_reminder(now, 2));
    }

    #[test]
    fn test_refresh_deadline_status_to_overdue() {
        let now = Utc::now();
        let mut review = AccessReview::new(
            Uuid::new_v4(),
            "Expired Campaign",
            ReviewScope::TenantWide,
            vec![Uuid::new_v4()],
            now - Duration::hours(1),
        );
        review.set_status(ReviewStatus::Active);
        review.refresh_deadline_status(now);
        assert_eq!(review.status, ReviewStatus::Overdue);
    }
}
