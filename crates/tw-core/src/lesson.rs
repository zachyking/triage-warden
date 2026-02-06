//! Lessons learned tracking for post-incident improvement.
//!
//! This module provides data models for capturing, tracking, and managing
//! lessons learned from security incidents, enabling continuous improvement
//! of detection, response, and prevention processes.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ============================================================================
// Lesson Category
// ============================================================================

/// Category of the lesson learned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LessonCategory {
    /// Improvement to detection capabilities.
    Detection,
    /// Improvement to incident response processes.
    Response,
    /// Preventive measures to avoid future incidents.
    Prevention,
    /// Process or workflow improvements.
    Process,
    /// Training or awareness needs.
    Training,
    /// Tooling improvements or new tool requirements.
    Tooling,
}

impl LessonCategory {
    /// Returns the string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            LessonCategory::Detection => "detection",
            LessonCategory::Response => "response",
            LessonCategory::Prevention => "prevention",
            LessonCategory::Process => "process",
            LessonCategory::Training => "training",
            LessonCategory::Tooling => "tooling",
        }
    }

    /// Parse from string.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "detection" => Some(LessonCategory::Detection),
            "response" => Some(LessonCategory::Response),
            "prevention" => Some(LessonCategory::Prevention),
            "process" => Some(LessonCategory::Process),
            "training" => Some(LessonCategory::Training),
            "tooling" => Some(LessonCategory::Tooling),
            _ => None,
        }
    }

    /// Returns all categories.
    pub fn all() -> &'static [LessonCategory] {
        &[
            LessonCategory::Detection,
            LessonCategory::Response,
            LessonCategory::Prevention,
            LessonCategory::Process,
            LessonCategory::Training,
            LessonCategory::Tooling,
        ]
    }
}

impl std::fmt::Display for LessonCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ============================================================================
// Lesson Status
// ============================================================================

/// Status of the lesson learned tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LessonStatus {
    /// Lesson has been identified but not yet acted upon.
    Identified,
    /// Work is in progress to address the lesson.
    InProgress,
    /// Lesson has been implemented/addressed.
    Implemented,
    /// Decided not to implement (with justification).
    WontFix,
}

impl LessonStatus {
    /// Returns the string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            LessonStatus::Identified => "identified",
            LessonStatus::InProgress => "in_progress",
            LessonStatus::Implemented => "implemented",
            LessonStatus::WontFix => "wont_fix",
        }
    }

    /// Parse from string.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "identified" => Some(LessonStatus::Identified),
            "in_progress" => Some(LessonStatus::InProgress),
            "implemented" => Some(LessonStatus::Implemented),
            "wont_fix" => Some(LessonStatus::WontFix),
            _ => None,
        }
    }

    /// Returns all statuses.
    pub fn all() -> &'static [LessonStatus] {
        &[
            LessonStatus::Identified,
            LessonStatus::InProgress,
            LessonStatus::Implemented,
            LessonStatus::WontFix,
        ]
    }

    /// Check if this is a terminal status.
    pub fn is_terminal(&self) -> bool {
        matches!(self, LessonStatus::Implemented | LessonStatus::WontFix)
    }
}

impl std::fmt::Display for LessonStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ============================================================================
// Lesson Learned
// ============================================================================

/// A lesson learned from a security incident.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LessonLearned {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant ID for multi-tenancy.
    pub tenant_id: Uuid,

    /// The incident this lesson relates to.
    pub incident_id: Uuid,

    /// Category of the lesson.
    pub category: LessonCategory,

    /// Short title describing the lesson.
    pub title: String,

    /// Detailed description of what was learned.
    pub description: String,

    /// Recommended action or change.
    pub recommendation: String,

    /// Current status.
    pub status: LessonStatus,

    /// User responsible for implementing the recommendation.
    #[serde(default)]
    pub owner: Option<Uuid>,

    /// Target date for implementation.
    #[serde(default)]
    pub due_date: Option<DateTime<Utc>>,

    /// When this lesson was created.
    pub created_at: DateTime<Utc>,

    /// When this lesson was last updated.
    pub updated_at: DateTime<Utc>,
}

impl LessonLearned {
    /// Create a new lesson learned.
    pub fn new(
        tenant_id: Uuid,
        incident_id: Uuid,
        category: LessonCategory,
        title: impl Into<String>,
        description: impl Into<String>,
        recommendation: impl Into<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            tenant_id,
            incident_id,
            category,
            title: title.into(),
            description: description.into(),
            recommendation: recommendation.into(),
            status: LessonStatus::Identified,
            owner: None,
            due_date: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Set the owner.
    pub fn with_owner(mut self, owner: Uuid) -> Self {
        self.owner = Some(owner);
        self
    }

    /// Set the due date.
    pub fn with_due_date(mut self, due_date: DateTime<Utc>) -> Self {
        self.due_date = Some(due_date);
        self
    }

    /// Transition to a new status.
    pub fn transition_status(&mut self, new_status: LessonStatus) -> bool {
        // Allow any transition except from terminal states (unless going to same state)
        if self.status.is_terminal() && self.status != new_status {
            return false;
        }
        self.status = new_status;
        self.updated_at = Utc::now();
        true
    }

    /// Check if the lesson is overdue.
    pub fn is_overdue(&self) -> bool {
        if self.status.is_terminal() {
            return false;
        }
        self.due_date.map(|due| Utc::now() > due).unwrap_or(false)
    }
}

// ============================================================================
// Create/Update DTOs
// ============================================================================

/// Request to create a lesson learned.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateLessonRequest {
    /// The incident this lesson relates to.
    pub incident_id: Uuid,

    /// Category.
    pub category: LessonCategory,

    /// Short title.
    pub title: String,

    /// Detailed description.
    pub description: String,

    /// Recommended action.
    pub recommendation: String,

    /// Owner user ID.
    #[serde(default)]
    pub owner: Option<Uuid>,

    /// Due date.
    #[serde(default)]
    pub due_date: Option<DateTime<Utc>>,
}

impl CreateLessonRequest {
    /// Build a LessonLearned from this request.
    pub fn build(self, tenant_id: Uuid) -> LessonLearned {
        let mut lesson = LessonLearned::new(
            tenant_id,
            self.incident_id,
            self.category,
            self.title,
            self.description,
            self.recommendation,
        );
        lesson.owner = self.owner;
        lesson.due_date = self.due_date;
        lesson
    }
}

/// Request to update a lesson learned.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateLessonRequest {
    /// Updated category.
    #[serde(default)]
    pub category: Option<LessonCategory>,

    /// Updated title.
    #[serde(default)]
    pub title: Option<String>,

    /// Updated description.
    #[serde(default)]
    pub description: Option<String>,

    /// Updated recommendation.
    #[serde(default)]
    pub recommendation: Option<String>,

    /// Updated status.
    #[serde(default)]
    pub status: Option<LessonStatus>,

    /// Updated owner.
    #[serde(default)]
    pub owner: Option<Option<Uuid>>,

    /// Updated due date.
    #[serde(default)]
    pub due_date: Option<Option<DateTime<Utc>>>,
}

impl UpdateLessonRequest {
    /// Apply this update to a lesson.
    pub fn apply(&self, lesson: &mut LessonLearned) -> bool {
        if let Some(category) = self.category {
            lesson.category = category;
        }
        if let Some(ref title) = self.title {
            lesson.title = title.clone();
        }
        if let Some(ref description) = self.description {
            lesson.description = description.clone();
        }
        if let Some(ref recommendation) = self.recommendation {
            lesson.recommendation = recommendation.clone();
        }
        if let Some(status) = self.status {
            if !lesson.transition_status(status) {
                return false;
            }
        }
        if let Some(ref owner) = self.owner {
            lesson.owner = *owner;
        }
        if let Some(ref due_date) = self.due_date {
            lesson.due_date = *due_date;
        }
        lesson.updated_at = Utc::now();
        true
    }
}

// ============================================================================
// Filter
// ============================================================================

/// Filter criteria for querying lessons.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LessonFilter {
    /// Filter by category.
    #[serde(default)]
    pub category: Option<LessonCategory>,

    /// Filter by status.
    #[serde(default)]
    pub status: Option<LessonStatus>,

    /// Filter by incident ID.
    #[serde(default)]
    pub incident_id: Option<Uuid>,

    /// Filter by owner.
    #[serde(default)]
    pub owner: Option<Uuid>,

    /// Maximum results.
    #[serde(default)]
    pub limit: Option<usize>,

    /// Offset for pagination.
    #[serde(default)]
    pub offset: Option<usize>,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lesson_category_serialization() {
        assert_eq!(LessonCategory::Detection.as_str(), "detection");
        assert_eq!(LessonCategory::Response.as_str(), "response");
        assert_eq!(LessonCategory::Prevention.as_str(), "prevention");
        assert_eq!(LessonCategory::Process.as_str(), "process");
        assert_eq!(LessonCategory::Training.as_str(), "training");
        assert_eq!(LessonCategory::Tooling.as_str(), "tooling");
    }

    #[test]
    fn test_lesson_category_parse() {
        assert_eq!(
            LessonCategory::parse("detection"),
            Some(LessonCategory::Detection)
        );
        assert_eq!(
            LessonCategory::parse("tooling"),
            Some(LessonCategory::Tooling)
        );
        assert_eq!(LessonCategory::parse("invalid"), None);
    }

    #[test]
    fn test_lesson_status_serialization() {
        assert_eq!(LessonStatus::Identified.as_str(), "identified");
        assert_eq!(LessonStatus::InProgress.as_str(), "in_progress");
        assert_eq!(LessonStatus::Implemented.as_str(), "implemented");
        assert_eq!(LessonStatus::WontFix.as_str(), "wont_fix");
    }

    #[test]
    fn test_lesson_status_parse() {
        assert_eq!(
            LessonStatus::parse("identified"),
            Some(LessonStatus::Identified)
        );
        assert_eq!(
            LessonStatus::parse("in_progress"),
            Some(LessonStatus::InProgress)
        );
        assert_eq!(LessonStatus::parse("wont_fix"), Some(LessonStatus::WontFix));
        assert_eq!(LessonStatus::parse("invalid"), None);
    }

    #[test]
    fn test_lesson_status_is_terminal() {
        assert!(!LessonStatus::Identified.is_terminal());
        assert!(!LessonStatus::InProgress.is_terminal());
        assert!(LessonStatus::Implemented.is_terminal());
        assert!(LessonStatus::WontFix.is_terminal());
    }

    #[test]
    fn test_lesson_creation() {
        let tenant_id = Uuid::new_v4();
        let incident_id = Uuid::new_v4();
        let lesson = LessonLearned::new(
            tenant_id,
            incident_id,
            LessonCategory::Detection,
            "Improve phishing detection",
            "Current rules missed variant of attack",
            "Add new YARA rule for attachment type",
        );

        assert_eq!(lesson.tenant_id, tenant_id);
        assert_eq!(lesson.incident_id, incident_id);
        assert_eq!(lesson.category, LessonCategory::Detection);
        assert_eq!(lesson.status, LessonStatus::Identified);
        assert!(lesson.owner.is_none());
        assert!(lesson.due_date.is_none());
    }

    #[test]
    fn test_lesson_builder() {
        let tenant_id = Uuid::new_v4();
        let incident_id = Uuid::new_v4();
        let owner_id = Uuid::new_v4();
        let due = Utc::now() + chrono::Duration::days(30);

        let lesson = LessonLearned::new(
            tenant_id,
            incident_id,
            LessonCategory::Response,
            "Title",
            "Description",
            "Recommendation",
        )
        .with_owner(owner_id)
        .with_due_date(due);

        assert_eq!(lesson.owner, Some(owner_id));
        assert!(lesson.due_date.is_some());
    }

    #[test]
    fn test_lesson_status_transition() {
        let tenant_id = Uuid::new_v4();
        let incident_id = Uuid::new_v4();
        let mut lesson = LessonLearned::new(
            tenant_id,
            incident_id,
            LessonCategory::Process,
            "Title",
            "Description",
            "Recommendation",
        );

        assert!(lesson.transition_status(LessonStatus::InProgress));
        assert_eq!(lesson.status, LessonStatus::InProgress);

        assert!(lesson.transition_status(LessonStatus::Implemented));
        assert_eq!(lesson.status, LessonStatus::Implemented);

        // Cannot transition from terminal state
        assert!(!lesson.transition_status(LessonStatus::Identified));
        assert_eq!(lesson.status, LessonStatus::Implemented);
    }

    #[test]
    fn test_lesson_is_overdue() {
        let tenant_id = Uuid::new_v4();
        let incident_id = Uuid::new_v4();
        let mut lesson = LessonLearned::new(
            tenant_id,
            incident_id,
            LessonCategory::Tooling,
            "Title",
            "Description",
            "Recommendation",
        );

        // No due date - not overdue
        assert!(!lesson.is_overdue());

        // Past due date - overdue
        lesson.due_date = Some(Utc::now() - chrono::Duration::days(1));
        assert!(lesson.is_overdue());

        // Future due date - not overdue
        lesson.due_date = Some(Utc::now() + chrono::Duration::days(1));
        assert!(!lesson.is_overdue());

        // Completed - not overdue even with past due date
        lesson.due_date = Some(Utc::now() - chrono::Duration::days(1));
        lesson.status = LessonStatus::Implemented;
        assert!(!lesson.is_overdue());
    }

    #[test]
    fn test_create_lesson_request_build() {
        let tenant_id = Uuid::new_v4();
        let incident_id = Uuid::new_v4();

        let request = CreateLessonRequest {
            incident_id,
            category: LessonCategory::Training,
            title: "Training need".to_string(),
            description: "Team needs phishing awareness".to_string(),
            recommendation: "Schedule training session".to_string(),
            owner: None,
            due_date: None,
        };

        let lesson = request.build(tenant_id);
        assert_eq!(lesson.tenant_id, tenant_id);
        assert_eq!(lesson.incident_id, incident_id);
        assert_eq!(lesson.category, LessonCategory::Training);
        assert_eq!(lesson.status, LessonStatus::Identified);
    }

    #[test]
    fn test_update_lesson_request_apply() {
        let tenant_id = Uuid::new_v4();
        let incident_id = Uuid::new_v4();
        let mut lesson = LessonLearned::new(
            tenant_id,
            incident_id,
            LessonCategory::Detection,
            "Old title",
            "Old description",
            "Old recommendation",
        );

        let update = UpdateLessonRequest {
            title: Some("New title".to_string()),
            status: Some(LessonStatus::InProgress),
            ..Default::default()
        };

        let success = update.apply(&mut lesson);
        assert!(success);
        assert_eq!(lesson.title, "New title");
        assert_eq!(lesson.status, LessonStatus::InProgress);
        // description should remain unchanged
        assert_eq!(lesson.description, "Old description");
    }

    #[test]
    fn test_update_lesson_blocked_transition() {
        let tenant_id = Uuid::new_v4();
        let incident_id = Uuid::new_v4();
        let mut lesson = LessonLearned::new(
            tenant_id,
            incident_id,
            LessonCategory::Detection,
            "Title",
            "Desc",
            "Rec",
        );
        lesson.status = LessonStatus::Implemented;

        let update = UpdateLessonRequest {
            status: Some(LessonStatus::Identified),
            ..Default::default()
        };

        let success = update.apply(&mut lesson);
        assert!(!success);
        assert_eq!(lesson.status, LessonStatus::Implemented);
    }

    #[test]
    fn test_lesson_filter_default() {
        let filter = LessonFilter::default();
        assert!(filter.category.is_none());
        assert!(filter.status.is_none());
        assert!(filter.incident_id.is_none());
        assert!(filter.owner.is_none());
        assert!(filter.limit.is_none());
        assert!(filter.offset.is_none());
    }
}
