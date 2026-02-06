//! Lessons learned management endpoints.
//!
//! This module provides REST endpoints for capturing, tracking, and managing
//! lessons learned from security incidents.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::get,
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;

use crate::auth::RequireAnalyst;
use crate::error::ApiError;
use crate::state::AppState;
use tw_core::lesson::{CreateLessonRequest, LessonCategory, LessonLearned, LessonStatus};

/// Creates lessons routes.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(list_lessons).post(create_lesson))
        .route(
            "/:id",
            get(get_lesson).put(update_lesson).delete(delete_lesson),
        )
}

/// Creates routes for lessons by incident.
pub fn incident_lessons_routes() -> Router<AppState> {
    Router::new().route("/", get(get_lessons_for_incident))
}

// ============================================================================
// DTOs
// ============================================================================

/// Query parameters for listing lessons.
#[derive(Debug, Deserialize, Validate)]
pub struct ListLessonsQuery {
    /// Filter by category.
    pub category: Option<String>,
    /// Filter by status.
    pub status: Option<String>,
    /// Filter by incident ID.
    pub incident_id: Option<Uuid>,
    /// Filter by owner.
    pub owner: Option<Uuid>,
    /// Page size limit.
    #[validate(range(min = 1, max = 200))]
    pub limit: Option<usize>,
    /// Offset for pagination.
    pub offset: Option<usize>,
}

/// Request body for creating a lesson.
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct CreateLessonBody {
    /// Related incident ID.
    pub incident_id: Uuid,
    /// Lesson category.
    pub category: String,
    /// Short title.
    #[validate(length(min = 1, max = 500))]
    pub title: String,
    /// Detailed description.
    #[validate(length(min = 1))]
    pub description: String,
    /// Recommendation.
    #[validate(length(min = 1))]
    pub recommendation: String,
    /// Owner user ID.
    pub owner: Option<Uuid>,
    /// Due date.
    pub due_date: Option<DateTime<Utc>>,
}

/// Request body for updating a lesson.
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct UpdateLessonBody {
    /// Updated category.
    pub category: Option<String>,
    /// Updated title.
    #[validate(length(min = 1, max = 500))]
    pub title: Option<String>,
    /// Updated description.
    pub description: Option<String>,
    /// Updated recommendation.
    pub recommendation: Option<String>,
    /// Updated status.
    pub status: Option<String>,
    /// Updated owner (null to unassign).
    pub owner: Option<Option<Uuid>>,
    /// Updated due date (null to remove).
    pub due_date: Option<Option<DateTime<Utc>>>,
}

/// Lesson response DTO.
#[derive(Debug, Serialize, ToSchema)]
pub struct LessonResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub incident_id: Uuid,
    pub category: String,
    pub title: String,
    pub description: String,
    pub recommendation: String,
    pub status: String,
    pub owner: Option<Uuid>,
    pub due_date: Option<DateTime<Utc>>,
    pub is_overdue: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<LessonLearned> for LessonResponse {
    fn from(lesson: LessonLearned) -> Self {
        let is_overdue = lesson.is_overdue();
        Self {
            id: lesson.id,
            tenant_id: lesson.tenant_id,
            incident_id: lesson.incident_id,
            category: lesson.category.as_str().to_string(),
            title: lesson.title,
            description: lesson.description,
            recommendation: lesson.recommendation,
            status: lesson.status.as_str().to_string(),
            owner: lesson.owner,
            due_date: lesson.due_date,
            is_overdue,
            created_at: lesson.created_at,
            updated_at: lesson.updated_at,
        }
    }
}

/// Paginated lessons response.
#[derive(Debug, Serialize, ToSchema)]
pub struct LessonListResponse {
    pub items: Vec<LessonResponse>,
    pub total: usize,
}

// ============================================================================
// Handlers
// ============================================================================

/// Create a new lesson learned.
async fn create_lesson(
    State(_state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    Json(body): Json<CreateLessonBody>,
) -> Result<(StatusCode, Json<LessonResponse>), ApiError> {
    body.validate()?;

    let category = parse_category(&body.category)?;

    let request = CreateLessonRequest {
        incident_id: body.incident_id,
        category,
        title: body.title,
        description: body.description,
        recommendation: body.recommendation,
        owner: body.owner,
        due_date: body.due_date,
    };

    let lesson = request.build(tw_core::auth::DEFAULT_TENANT_ID);

    // In a real implementation, we would persist to the database.
    // For now, return the created lesson.
    Ok((StatusCode::CREATED, Json(LessonResponse::from(lesson))))
}

/// List lessons with optional filters.
async fn list_lessons(
    State(_state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    Query(query): Query<ListLessonsQuery>,
) -> Result<Json<LessonListResponse>, ApiError> {
    query.validate()?;

    // Validate category if provided
    if let Some(ref cat) = query.category {
        parse_category(cat)?;
    }

    // Validate status if provided
    if let Some(ref status) = query.status {
        parse_status(status)?;
    }
    Ok(Json(LessonListResponse {
        items: vec![],
        total: 0,
    }))
}

/// Get a specific lesson by ID.
async fn get_lesson(
    State(_state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    Path(id): Path<Uuid>,
) -> Result<Json<LessonResponse>, ApiError> {
    // In a real implementation, we would query the database.
    Err(ApiError::NotFound(format!("Lesson {} not found", id)))
}

/// Update a lesson.
async fn update_lesson(
    State(_state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateLessonBody>,
) -> Result<Json<LessonResponse>, ApiError> {
    body.validate()?;

    // Validate category if provided
    if let Some(ref cat) = body.category {
        parse_category(cat)?;
    }

    // Validate status if provided
    if let Some(ref status) = body.status {
        parse_status(status)?;
    }
    Err(ApiError::NotFound(format!("Lesson {} not found", id)))
}

/// Delete a lesson.
async fn delete_lesson(
    State(_state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    // In a real implementation, we would delete from the database.
    Err(ApiError::NotFound(format!("Lesson {} not found", id)))
}

/// Get lessons for a specific incident.
async fn get_lessons_for_incident(
    State(_state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    Path(incident_id): Path<Uuid>,
) -> Result<Json<Vec<LessonResponse>>, ApiError> {
    // In a real implementation, we would query by incident_id.
    let _ = incident_id;
    Ok(Json(vec![]))
}

// ============================================================================
// Helper Functions
// ============================================================================

fn parse_category(s: &str) -> Result<LessonCategory, ApiError> {
    LessonCategory::parse(s)
        .ok_or_else(|| ApiError::BadRequest(format!("Invalid lesson category: {}", s)))
}

fn parse_status(s: &str) -> Result<LessonStatus, ApiError> {
    LessonStatus::parse(s)
        .ok_or_else(|| ApiError::BadRequest(format!("Invalid lesson status: {}", s)))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lesson_response_from_lesson() {
        let tenant_id = Uuid::new_v4();
        let incident_id = Uuid::new_v4();
        let lesson = LessonLearned::new(
            tenant_id,
            incident_id,
            LessonCategory::Detection,
            "Test Lesson",
            "Description",
            "Recommendation",
        );

        let response = LessonResponse::from(lesson.clone());

        assert_eq!(response.id, lesson.id);
        assert_eq!(response.category, "detection");
        assert_eq!(response.status, "identified");
        assert!(!response.is_overdue);
    }

    #[test]
    fn test_lesson_response_overdue() {
        let tenant_id = Uuid::new_v4();
        let incident_id = Uuid::new_v4();
        let mut lesson = LessonLearned::new(
            tenant_id,
            incident_id,
            LessonCategory::Response,
            "Overdue Lesson",
            "Description",
            "Recommendation",
        );
        lesson.due_date = Some(Utc::now() - chrono::Duration::days(1));

        let response = LessonResponse::from(lesson);
        assert!(response.is_overdue);
    }

    #[test]
    fn testparse_category_valid() {
        assert!(parse_category("detection").is_ok());
        assert!(parse_category("response").is_ok());
        assert!(parse_category("prevention").is_ok());
        assert!(parse_category("process").is_ok());
        assert!(parse_category("training").is_ok());
        assert!(parse_category("tooling").is_ok());
    }

    #[test]
    fn testparse_category_invalid() {
        assert!(parse_category("invalid").is_err());
    }

    #[test]
    fn testparse_status_valid() {
        assert!(parse_status("identified").is_ok());
        assert!(parse_status("in_progress").is_ok());
        assert!(parse_status("implemented").is_ok());
        assert!(parse_status("wont_fix").is_ok());
    }

    #[test]
    fn testparse_status_invalid() {
        assert!(parse_status("invalid").is_err());
    }

    #[test]
    fn test_lesson_list_response_serialization() {
        let response = LessonListResponse {
            items: vec![],
            total: 0,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"total\":0"));
        assert!(json.contains("\"items\":[]"));
    }

    #[test]
    fn test_create_lesson_body_validation() {
        let body = CreateLessonBody {
            incident_id: Uuid::new_v4(),
            category: "detection".to_string(),
            title: "Title".to_string(),
            description: "Description".to_string(),
            recommendation: "Recommendation".to_string(),
            owner: None,
            due_date: None,
        };

        assert!(body.validate().is_ok());
    }
}
