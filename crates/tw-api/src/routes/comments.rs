//! Comment management endpoints for incident collaboration.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

use crate::auth::RequireAnalyst;
use crate::error::ApiError;
use crate::state::AppState;
use tw_core::auth::DEFAULT_TENANT_ID;
use tw_core::collaboration::comment::{CommentType, IncidentComment};
use tw_core::db::comment_repo::CommentFilter;
use tw_core::db::create_comment_repository;
use tw_core::db::pagination::Pagination;

/// Creates comment routes.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(list_comments).post(create_comment))
        .route(
            "/:id",
            get(get_comment).put(update_comment).delete(delete_comment),
        )
}

// ============================================================================
// DTOs
// ============================================================================

/// Query parameters for listing comments.
#[derive(Debug, Deserialize, Validate)]
pub struct ListCommentsQuery {
    /// Filter by incident ID.
    pub incident_id: Option<Uuid>,
    /// Filter by comment type.
    pub comment_type: Option<String>,
    /// Filter by author ID.
    pub author_id: Option<Uuid>,
    /// Page number (1-indexed).
    #[validate(range(min = 1))]
    pub page: Option<u32>,
    /// Items per page.
    #[validate(range(min = 1, max = 200))]
    pub per_page: Option<u32>,
}

/// Request body for creating a comment.
#[derive(Debug, Deserialize, Validate)]
pub struct CreateCommentApiRequest {
    /// Incident this comment belongs to.
    pub incident_id: Uuid,
    /// Comment text content.
    #[validate(length(min = 1, max = 10000))]
    pub content: String,
    /// Type of comment.
    pub comment_type: String,
    /// User IDs mentioned in this comment.
    #[serde(default)]
    pub mentions: Vec<Uuid>,
}

/// Request body for updating a comment.
#[derive(Debug, Deserialize, Validate)]
pub struct UpdateCommentApiRequest {
    /// Updated content.
    #[validate(length(min = 1, max = 10000))]
    pub content: Option<String>,
    /// Updated comment type.
    pub comment_type: Option<String>,
}

/// Comment response DTO.
#[derive(Debug, Serialize)]
pub struct CommentResponse {
    pub id: Uuid,
    pub incident_id: Uuid,
    pub author_id: Uuid,
    pub content: String,
    pub comment_type: String,
    pub mentions: Vec<Uuid>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub edited: bool,
}

/// Paginated comments response.
#[derive(Debug, Serialize)]
pub struct PaginatedCommentsResponse {
    pub data: Vec<CommentResponse>,
    pub page: u32,
    pub per_page: u32,
    pub total_items: u64,
}

// ============================================================================
// Handlers
// ============================================================================

/// List comments with optional filters.
async fn list_comments(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    Query(query): Query<ListCommentsQuery>,
) -> Result<Json<PaginatedCommentsResponse>, ApiError> {
    query.validate()?;

    let page = query.page.unwrap_or(1);
    let per_page = query.per_page.unwrap_or(20);

    let comment_type = query
        .comment_type
        .as_deref()
        .map(parse_comment_type)
        .transpose()?;

    let filter = CommentFilter {
        tenant_id: Some(DEFAULT_TENANT_ID),
        incident_id: query.incident_id,
        author_id: query.author_id,
        comment_type,
    };

    let pagination = Pagination::new(page, per_page);
    let repo = create_comment_repository(&state.db);
    let result = repo
        .list(&filter, &pagination)
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to list comments: {}", e)))?;

    Ok(Json(PaginatedCommentsResponse {
        data: result.items.iter().map(comment_to_response).collect(),
        page: result.page,
        per_page: result.per_page,
        total_items: result.total,
    }))
}

/// Create a new comment on an incident.
async fn create_comment(
    State(state): State<AppState>,
    RequireAnalyst(user): RequireAnalyst,
    Json(request): Json<CreateCommentApiRequest>,
) -> Result<(StatusCode, Json<CommentResponse>), ApiError> {
    request.validate()?;

    let comment_type = parse_comment_type(&request.comment_type)?;

    let comment = IncidentComment::new(request.incident_id, user.id, request.content, comment_type)
        .with_mentions(request.mentions);

    let repo = create_comment_repository(&state.db);
    repo.create(&comment, DEFAULT_TENANT_ID)
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to create comment: {}", e)))?;

    let response = comment_to_response(&comment);
    Ok((StatusCode::CREATED, Json(response)))
}

/// Get a specific comment by ID.
async fn get_comment(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    Path(id): Path<Uuid>,
) -> Result<Json<CommentResponse>, ApiError> {
    let repo = create_comment_repository(&state.db);
    let comment = repo
        .get_for_tenant(id, DEFAULT_TENANT_ID)
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to get comment: {}", e)))?
        .ok_or_else(|| ApiError::NotFound(format!("Comment {} not found", id)))?;

    Ok(Json(comment_to_response(&comment)))
}

/// Update a comment.
async fn update_comment(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateCommentApiRequest>,
) -> Result<Json<CommentResponse>, ApiError> {
    request.validate()?;

    let parsed_comment_type = request
        .comment_type
        .as_deref()
        .map(parse_comment_type)
        .transpose()?;

    let update = tw_core::collaboration::comment::UpdateCommentRequest {
        content: request.content,
        comment_type: parsed_comment_type,
    };

    let repo = create_comment_repository(&state.db);
    let comment = repo
        .update(id, DEFAULT_TENANT_ID, &update)
        .await
        .map_err(|e| match e {
            tw_core::db::DbError::NotFound { .. } => {
                ApiError::NotFound(format!("Comment {} not found", id))
            }
            _ => ApiError::Internal(format!("Failed to update comment: {}", e)),
        })?;

    Ok(Json(comment_to_response(&comment)))
}

/// Delete a comment.
async fn delete_comment(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let repo = create_comment_repository(&state.db);
    let deleted = repo
        .delete(id, DEFAULT_TENANT_ID)
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to delete comment: {}", e)))?;

    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NotFound(format!("Comment {} not found", id)))
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn comment_to_response(comment: &IncidentComment) -> CommentResponse {
    CommentResponse {
        id: comment.id,
        incident_id: comment.incident_id,
        author_id: comment.author_id,
        content: comment.content.clone(),
        comment_type: comment.comment_type.to_string(),
        mentions: comment.mentions.clone(),
        created_at: comment.created_at,
        updated_at: comment.updated_at,
        edited: comment.edited,
    }
}

fn parse_comment_type(s: &str) -> Result<CommentType, ApiError> {
    match s.to_lowercase().as_str() {
        "note" => Ok(CommentType::Note),
        "analysis" => Ok(CommentType::Analysis),
        "action_taken" => Ok(CommentType::ActionTaken),
        "question" => Ok(CommentType::Question),
        "resolution" => Ok(CommentType::Resolution),
        _ => Err(ApiError::BadRequest(format!(
            "Invalid comment type: {}. Must be one of: note, analysis, action_taken, question, resolution",
            s
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_comment_type_valid() {
        assert!(matches!(parse_comment_type("note"), Ok(CommentType::Note)));
        assert!(matches!(
            parse_comment_type("analysis"),
            Ok(CommentType::Analysis)
        ));
        assert!(matches!(
            parse_comment_type("action_taken"),
            Ok(CommentType::ActionTaken)
        ));
        assert!(matches!(
            parse_comment_type("question"),
            Ok(CommentType::Question)
        ));
        assert!(matches!(
            parse_comment_type("resolution"),
            Ok(CommentType::Resolution)
        ));
    }

    #[test]
    fn test_parse_comment_type_case_insensitive() {
        assert!(matches!(parse_comment_type("NOTE"), Ok(CommentType::Note)));
        assert!(matches!(
            parse_comment_type("Analysis"),
            Ok(CommentType::Analysis)
        ));
    }

    #[test]
    fn test_parse_comment_type_invalid() {
        assert!(parse_comment_type("invalid").is_err());
        assert!(parse_comment_type("").is_err());
    }

    #[test]
    fn test_comment_to_response() {
        let incident_id = Uuid::new_v4();
        let author_id = Uuid::new_v4();
        let mention = Uuid::new_v4();

        let comment = IncidentComment::new(
            incident_id,
            author_id,
            "Found lateral movement evidence".to_string(),
            CommentType::Analysis,
        )
        .with_mentions(vec![mention]);

        let response = comment_to_response(&comment);

        assert_eq!(response.id, comment.id);
        assert_eq!(response.incident_id, incident_id);
        assert_eq!(response.author_id, author_id);
        assert_eq!(response.content, "Found lateral movement evidence");
        assert_eq!(response.comment_type, "analysis");
        assert_eq!(response.mentions, vec![mention]);
        assert!(!response.edited);
    }

    #[test]
    fn test_comment_response_serialization() {
        let response = CommentResponse {
            id: Uuid::nil(),
            incident_id: Uuid::nil(),
            author_id: Uuid::nil(),
            content: "Test".to_string(),
            comment_type: "note".to_string(),
            mentions: vec![],
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            edited: false,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"comment_type\":\"note\""));
    }

    #[test]
    fn test_create_comment_request_deserialization() {
        let json = r#"{
            "incident_id": "00000000-0000-0000-0000-000000000000",
            "content": "Test comment",
            "comment_type": "note",
            "mentions": []
        }"#;

        let request: CreateCommentApiRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.content, "Test comment");
        assert_eq!(request.comment_type, "note");
    }

    #[test]
    fn test_update_comment_request_partial() {
        let json = r#"{"content": "Updated"}"#;
        let request: UpdateCommentApiRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.content, Some("Updated".to_string()));
        assert!(request.comment_type.is_none());
    }
}
