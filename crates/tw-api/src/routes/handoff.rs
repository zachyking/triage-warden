//! Shift handoff report endpoints.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

use crate::auth::RequireAnalyst;
use crate::error::ApiError;
use crate::state::AppState;
use tw_core::collaboration::handoff::{IncidentSummary, ShiftHandoff};
use tw_core::db::{
    create_handoff_repository, create_incident_repository, IncidentFilter, Pagination,
};
use tw_core::incident::IncidentStatus;

/// Creates handoff routes.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", post(create_handoff))
        .route("/latest", get(get_latest_handoff))
        .route("/:id", get(get_handoff))
}

// ============================================================================
// DTOs
// ============================================================================

/// Request body for generating a shift handoff report.
#[derive(Debug, Deserialize, Validate)]
pub struct CreateHandoffApiRequest {
    /// Start of the shift being handed off.
    pub shift_start: DateTime<Utc>,
    /// End of the shift being handed off.
    pub shift_end: DateTime<Utc>,
    /// Optional notes from the outgoing analyst.
    #[validate(length(max = 5000))]
    pub notes: Option<String>,
}

/// Incident summary in handoff response.
#[derive(Debug, Serialize)]
pub struct IncidentSummaryResponse {
    pub id: Uuid,
    pub title: String,
    pub severity: String,
    pub status: String,
    pub assigned_to: Option<String>,
    pub last_updated: DateTime<Utc>,
}

/// Action summary in handoff response.
#[derive(Debug, Serialize)]
pub struct ActionSummaryResponse {
    pub id: Uuid,
    pub description: String,
    pub status: String,
    pub incident_id: Uuid,
}

/// Handoff report response DTO.
#[derive(Debug, Serialize)]
pub struct HandoffResponse {
    pub id: Uuid,
    pub shift_start: DateTime<Utc>,
    pub shift_end: DateTime<Utc>,
    pub analyst_id: Uuid,
    pub analyst_name: String,
    pub open_incidents: Vec<IncidentSummaryResponse>,
    pub pending_actions: Vec<ActionSummaryResponse>,
    pub notable_events: Vec<String>,
    pub recommendations: Vec<String>,
    pub created_at: DateTime<Utc>,
}

// ============================================================================
// Handlers
// ============================================================================

/// Generate a new shift handoff report.
async fn create_handoff(
    State(state): State<AppState>,
    RequireAnalyst(user): RequireAnalyst,
    Json(request): Json<CreateHandoffApiRequest>,
) -> Result<(StatusCode, Json<HandoffResponse>), ApiError> {
    request.validate()?;

    if request.shift_end <= request.shift_start {
        return Err(ApiError::BadRequest(
            "shift_end must be after shift_start".to_string(),
        ));
    }

    let tenant_id = tw_core::auth::DEFAULT_TENANT_ID;

    let mut handoff = ShiftHandoff::new(
        request.shift_start,
        request.shift_end,
        user.id,
        user.username.clone(),
    );

    // Query open incidents to populate the handoff report
    let incident_repo = create_incident_repository(&state.db);
    let open_statuses = vec![
        IncidentStatus::New,
        IncidentStatus::Enriching,
        IncidentStatus::Analyzing,
        IncidentStatus::PendingReview,
        IncidentStatus::PendingApproval,
        IncidentStatus::Executing,
    ];
    let filter = IncidentFilter {
        tenant_id: Some(tenant_id),
        status: Some(open_statuses),
        ..Default::default()
    };
    let pagination = Pagination::new(1, 100);
    if let Ok(incidents) = incident_repo.list(&filter, &pagination).await {
        for inc in incidents {
            let title = inc
                .alert_data
                .get("title")
                .and_then(|v| v.as_str())
                .unwrap_or("Untitled Incident")
                .to_string();
            handoff.add_incident(IncidentSummary {
                id: inc.id,
                title,
                severity: inc.severity.as_db_str().to_string(),
                status: inc.status.as_db_str().to_string(),
                assigned_to: None,
                last_updated: inc.updated_at,
            });
        }
    }

    let handoff_repo = create_handoff_repository(&state.db);
    let created = handoff_repo.create(tenant_id, &handoff).await?;

    let response = handoff_to_response(&created);
    Ok((StatusCode::CREATED, Json(response)))
}

/// Get the most recently generated handoff report.
async fn get_latest_handoff(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
) -> Result<Json<HandoffResponse>, ApiError> {
    let tenant_id = tw_core::auth::DEFAULT_TENANT_ID;
    let repo = create_handoff_repository(&state.db);

    let handoff = repo
        .get_latest(tenant_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("No handoff reports found".to_string()))?;

    Ok(Json(handoff_to_response(&handoff)))
}

/// Get a specific handoff report by ID.
async fn get_handoff(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    Path(id): Path<Uuid>,
) -> Result<Json<HandoffResponse>, ApiError> {
    let tenant_id = tw_core::auth::DEFAULT_TENANT_ID;
    let repo = create_handoff_repository(&state.db);

    let handoff = repo
        .get_for_tenant(id, tenant_id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Handoff report {} not found", id)))?;

    Ok(Json(handoff_to_response(&handoff)))
}

// ============================================================================
// Helpers
// ============================================================================

fn handoff_to_response(handoff: &ShiftHandoff) -> HandoffResponse {
    HandoffResponse {
        id: handoff.id,
        shift_start: handoff.shift_start,
        shift_end: handoff.shift_end,
        analyst_id: handoff.analyst_id,
        analyst_name: handoff.analyst_name.clone(),
        open_incidents: handoff
            .open_incidents
            .iter()
            .map(|i| IncidentSummaryResponse {
                id: i.id,
                title: i.title.clone(),
                severity: i.severity.clone(),
                status: i.status.clone(),
                assigned_to: i.assigned_to.clone(),
                last_updated: i.last_updated,
            })
            .collect(),
        pending_actions: handoff
            .pending_actions
            .iter()
            .map(|a| ActionSummaryResponse {
                id: a.id,
                description: a.description.clone(),
                status: a.status.clone(),
                incident_id: a.incident_id,
            })
            .collect(),
        notable_events: handoff.notable_events.clone(),
        recommendations: handoff.recommendations.clone(),
        created_at: handoff.created_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tw_core::collaboration::handoff::{ActionSummary, IncidentSummary};

    #[test]
    fn test_handoff_to_response_empty() {
        let handoff = ShiftHandoff::new(
            Utc::now() - chrono::Duration::hours(8),
            Utc::now(),
            Uuid::new_v4(),
            "Alice".to_string(),
        );

        let response = handoff_to_response(&handoff);

        assert_eq!(response.id, handoff.id);
        assert_eq!(response.analyst_name, "Alice");
        assert!(response.open_incidents.is_empty());
        assert!(response.pending_actions.is_empty());
        assert!(response.notable_events.is_empty());
        assert!(response.recommendations.is_empty());
    }

    #[test]
    fn test_handoff_to_response_with_data() {
        let mut handoff = ShiftHandoff::new(
            Utc::now() - chrono::Duration::hours(8),
            Utc::now(),
            Uuid::new_v4(),
            "Bob".to_string(),
        );

        handoff.add_incident(IncidentSummary {
            id: Uuid::new_v4(),
            title: "Ransomware detected".to_string(),
            severity: "critical".to_string(),
            status: "investigating".to_string(),
            assigned_to: Some("Bob".to_string()),
            last_updated: Utc::now(),
        });

        handoff.add_action(ActionSummary {
            id: Uuid::new_v4(),
            description: "Isolate host".to_string(),
            status: "pending".to_string(),
            incident_id: Uuid::new_v4(),
        });

        handoff.add_notable_event("Major phishing campaign detected".to_string());
        handoff.add_recommendation("Monitor INC-1234 closely".to_string());

        let response = handoff_to_response(&handoff);

        assert_eq!(response.open_incidents.len(), 1);
        assert_eq!(response.open_incidents[0].title, "Ransomware detected");
        assert_eq!(response.pending_actions.len(), 1);
        assert_eq!(response.notable_events.len(), 1);
        assert_eq!(response.recommendations.len(), 1);
    }

    #[test]
    fn test_handoff_response_serialization() {
        let response = HandoffResponse {
            id: Uuid::nil(),
            shift_start: Utc::now(),
            shift_end: Utc::now(),
            analyst_id: Uuid::nil(),
            analyst_name: "Test".to_string(),
            open_incidents: vec![],
            pending_actions: vec![],
            notable_events: vec!["Test event".to_string()],
            recommendations: vec![],
            created_at: Utc::now(),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"analyst_name\":\"Test\""));
        assert!(json.contains("Test event"));
    }

    #[test]
    fn test_create_handoff_request_deserialization() {
        let json = r#"{
            "shift_start": "2025-01-15T08:00:00Z",
            "shift_end": "2025-01-15T16:00:00Z",
            "notes": "Quiet shift"
        }"#;

        let request: CreateHandoffApiRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.notes, Some("Quiet shift".to_string()));
    }

    #[test]
    fn test_create_handoff_request_without_notes() {
        let json = r#"{
            "shift_start": "2025-01-15T08:00:00Z",
            "shift_end": "2025-01-15T16:00:00Z"
        }"#;

        let request: CreateHandoffApiRequest = serde_json::from_str(json).unwrap();
        assert!(request.notes.is_none());
    }

    #[test]
    fn test_incident_summary_response_serialization() {
        let response = IncidentSummaryResponse {
            id: Uuid::nil(),
            title: "Test Incident".to_string(),
            severity: "high".to_string(),
            status: "open".to_string(),
            assigned_to: Some("Alice".to_string()),
            last_updated: Utc::now(),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("Test Incident"));
        assert!(json.contains("Alice"));
    }

    #[test]
    fn test_action_summary_response_serialization() {
        let response = ActionSummaryResponse {
            id: Uuid::nil(),
            description: "Block malicious IP".to_string(),
            status: "pending".to_string(),
            incident_id: Uuid::nil(),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("Block malicious IP"));
    }
}
