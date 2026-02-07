//! Activity feed endpoints for incident audit trails.

use axum::{
    extract::{Path, Query, State},
    routing::get,
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

use crate::auth::RequireAnalyst;
use crate::error::ApiError;
use crate::middleware::OptionalTenant;
use crate::state::AppState;
use tw_core::collaboration::activity::{ActivityFilter, ActivityType};
use tw_core::db::create_activity_repository;
use tw_core::db::pagination::Pagination;

fn tenant_id_or_default(tenant: Option<tw_core::tenant::TenantContext>) -> Uuid {
    tenant
        .map(|ctx| ctx.tenant_id)
        .unwrap_or(tw_core::auth::DEFAULT_TENANT_ID)
}

/// Creates activity feed routes.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(get_activity_feed))
        .route("/incidents/:id", get(get_incident_activity))
}

// ============================================================================
// DTOs
// ============================================================================

/// Query parameters for the activity feed.
#[derive(Debug, Deserialize, Validate)]
pub struct ActivityFeedQuery {
    /// Filter by activity types (comma-separated).
    pub activity_types: Option<String>,
    /// Filter by actor ID.
    pub actor_id: Option<Uuid>,
    /// Filter by incident ID.
    pub incident_id: Option<Uuid>,
    /// Only return activities after this timestamp.
    pub since: Option<DateTime<Utc>>,
    /// Maximum number of entries to return.
    #[validate(range(min = 1, max = 200))]
    pub limit: Option<u32>,
    /// Number of entries to skip.
    pub offset: Option<u32>,
}

/// Activity entry response DTO.
#[derive(Debug, Serialize)]
pub struct ActivityEntryResponse {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub actor_id: Option<Uuid>,
    pub actor_name: Option<String>,
    pub activity_type: String,
    pub incident_id: Option<Uuid>,
    pub description: String,
    pub metadata: Option<serde_json::Value>,
}

/// Activity feed response.
#[derive(Debug, Serialize)]
pub struct ActivityFeedResponse {
    pub entries: Vec<ActivityEntryResponse>,
    pub total: u64,
    pub has_more: bool,
}

// ============================================================================
// Handlers
// ============================================================================

/// Get the global activity feed with optional filters.
async fn get_activity_feed(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
    Query(query): Query<ActivityFeedQuery>,
) -> Result<Json<ActivityFeedResponse>, ApiError> {
    query.validate()?;
    let tenant_id = tenant_id_or_default(tenant);

    let activity_types = query
        .activity_types
        .as_deref()
        .map(|types_str| {
            types_str
                .split(',')
                .map(|s| parse_activity_type(s.trim()))
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?;

    let limit = query.limit.unwrap_or(50);
    let offset = query.offset.unwrap_or(0);

    let filter = ActivityFilter {
        activity_types,
        actor_id: query.actor_id,
        incident_id: query.incident_id,
        since: query.since,
        limit: Some(limit),
        offset: Some(offset),
    };

    let pagination = Pagination::new((offset / limit) + 1, limit);
    let repo = create_activity_repository(&state.db);
    let result = repo
        .list(&filter, tenant_id, &pagination)
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to list activity: {}", e)))?;

    let has_more = (offset as u64 + result.items.len() as u64) < result.total;

    Ok(Json(ActivityFeedResponse {
        entries: result
            .items
            .iter()
            .map(activity_entry_to_response)
            .collect(),
        total: result.total,
        has_more,
    }))
}

/// Get activity feed for a specific incident.
async fn get_incident_activity(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
    Path(id): Path<Uuid>,
    Query(query): Query<ActivityFeedQuery>,
) -> Result<Json<ActivityFeedResponse>, ApiError> {
    query.validate()?;
    let tenant_id = tenant_id_or_default(tenant);

    let activity_types = query
        .activity_types
        .as_deref()
        .map(|types_str| {
            types_str
                .split(',')
                .map(|s| parse_activity_type(s.trim()))
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?;

    let limit = query.limit.unwrap_or(50);
    let offset = query.offset.unwrap_or(0);

    let filter = ActivityFilter {
        activity_types,
        actor_id: query.actor_id,
        incident_id: Some(id),
        since: query.since,
        limit: Some(limit),
        offset: Some(offset),
    };

    let pagination = Pagination::new((offset / limit) + 1, limit);
    let repo = create_activity_repository(&state.db);
    let result = repo
        .list(&filter, tenant_id, &pagination)
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to list activity: {}", e)))?;

    let has_more = (offset as u64 + result.items.len() as u64) < result.total;

    Ok(Json(ActivityFeedResponse {
        entries: result
            .items
            .iter()
            .map(activity_entry_to_response)
            .collect(),
        total: result.total,
        has_more,
    }))
}

// ============================================================================
// Helpers
// ============================================================================

fn parse_activity_type(s: &str) -> Result<ActivityType, ApiError> {
    match s.to_lowercase().as_str() {
        "incident_created" => Ok(ActivityType::IncidentCreated),
        "incident_updated" => Ok(ActivityType::IncidentUpdated),
        "incident_assigned" => Ok(ActivityType::IncidentAssigned),
        "comment_added" => Ok(ActivityType::CommentAdded),
        "action_executed" => Ok(ActivityType::ActionExecuted),
        "verdict_changed" => Ok(ActivityType::VerdictChanged),
        "severity_changed" => Ok(ActivityType::SeverityChanged),
        "status_changed" => Ok(ActivityType::StatusChanged),
        _ => Err(ApiError::BadRequest(format!(
            "Invalid activity type: {}. Must be one of: incident_created, incident_updated, \
             incident_assigned, comment_added, action_executed, verdict_changed, \
             severity_changed, status_changed",
            s
        ))),
    }
}

fn activity_entry_to_response(
    entry: &tw_core::collaboration::activity::ActivityEntry,
) -> ActivityEntryResponse {
    ActivityEntryResponse {
        id: entry.id,
        timestamp: entry.timestamp,
        actor_id: entry.actor_id,
        actor_name: entry.actor_name.clone(),
        activity_type: entry.activity_type.to_string(),
        incident_id: entry.incident_id,
        description: entry.description.clone(),
        metadata: entry.metadata.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_activity_type_valid() {
        assert!(matches!(
            parse_activity_type("incident_created"),
            Ok(ActivityType::IncidentCreated)
        ));
        assert!(matches!(
            parse_activity_type("incident_updated"),
            Ok(ActivityType::IncidentUpdated)
        ));
        assert!(matches!(
            parse_activity_type("incident_assigned"),
            Ok(ActivityType::IncidentAssigned)
        ));
        assert!(matches!(
            parse_activity_type("comment_added"),
            Ok(ActivityType::CommentAdded)
        ));
        assert!(matches!(
            parse_activity_type("action_executed"),
            Ok(ActivityType::ActionExecuted)
        ));
        assert!(matches!(
            parse_activity_type("verdict_changed"),
            Ok(ActivityType::VerdictChanged)
        ));
        assert!(matches!(
            parse_activity_type("severity_changed"),
            Ok(ActivityType::SeverityChanged)
        ));
        assert!(matches!(
            parse_activity_type("status_changed"),
            Ok(ActivityType::StatusChanged)
        ));
    }

    #[test]
    fn test_parse_activity_type_case_insensitive() {
        assert!(matches!(
            parse_activity_type("INCIDENT_CREATED"),
            Ok(ActivityType::IncidentCreated)
        ));
    }

    #[test]
    fn test_parse_activity_type_invalid() {
        assert!(parse_activity_type("invalid").is_err());
        assert!(parse_activity_type("").is_err());
    }

    #[test]
    fn test_activity_entry_to_response() {
        let entry = tw_core::collaboration::activity::ActivityEntry::new(
            ActivityType::SeverityChanged,
            "Severity escalated to critical".to_string(),
        )
        .with_actor(Uuid::new_v4(), "Alice".to_string())
        .with_incident(Uuid::new_v4());

        let response = activity_entry_to_response(&entry);

        assert_eq!(response.id, entry.id);
        assert_eq!(response.activity_type, "severity_changed");
        assert_eq!(response.actor_name, Some("Alice".to_string()));
        assert!(response.incident_id.is_some());
    }

    #[test]
    fn test_activity_feed_response_serialization() {
        let response = ActivityFeedResponse {
            entries: vec![],
            total: 0,
            has_more: false,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"total\":0"));
        assert!(json.contains("\"has_more\":false"));
    }

    #[test]
    fn test_activity_entry_response_serialization() {
        let response = ActivityEntryResponse {
            id: Uuid::nil(),
            timestamp: Utc::now(),
            actor_id: None,
            actor_name: None,
            activity_type: "incident_created".to_string(),
            incident_id: Some(Uuid::nil()),
            description: "New incident from alert".to_string(),
            metadata: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("incident_created"));
        assert!(json.contains("New incident from alert"));
    }
}
