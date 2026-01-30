//! Incident management endpoints.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use uuid::Uuid;
use validator::Validate;

use crate::dto::{
    ActionExecutionResponse, ActionResponse, AnalysisResponse, ApproveActionRequest,
    AuditEntryResponse, DismissRequest, EnrichmentResponse, ExecuteActionRequest,
    IncidentDetailResponse, IncidentResponse, IoCResponse, ListIncidentsQuery,
    MitreTechniqueResponse, PaginatedResponse, PaginationInfo, ResolveRequest,
};
use crate::error::ApiError;
use crate::state::AppState;
use tw_core::db::{
    create_audit_repository, create_incident_repository, AuditRepository, IncidentFilter,
    IncidentRepository, Pagination,
};
use tw_core::incident::{
    ApprovalStatus, AuditAction, AuditEntry, Incident, IncidentStatus, ProposedAction, Severity,
};

/// Creates incident routes.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(list_incidents))
        .route("/:id", get(get_incident))
        .route("/:id/actions", post(execute_action))
        .route("/:id/approve", post(approve_action))
        .route("/:id/dismiss", post(dismiss_incident))
        .route("/:id/resolve", post(resolve_incident))
        .route("/:id/enrich", post(enrich_incident))
}

/// List incidents with filtering and pagination.
#[utoipa::path(
    get,
    path = "/api/incidents",
    params(
        ("status" = Option<String>, Query, description = "Filter by status (comma-separated)"),
        ("severity" = Option<String>, Query, description = "Filter by severity (comma-separated)"),
        ("since" = Option<String>, Query, description = "Filter by created after timestamp"),
        ("until" = Option<String>, Query, description = "Filter by created before timestamp"),
        ("page" = Option<u32>, Query, description = "Page number (1-indexed)"),
        ("per_page" = Option<u32>, Query, description = "Items per page (max 100)")
    ),
    responses(
        (status = 200, description = "List of incidents", body = PaginatedResponse<IncidentResponse>),
        (status = 400, description = "Invalid query parameters"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Incidents"
)]
async fn list_incidents(
    State(state): State<AppState>,
    Query(query): Query<ListIncidentsQuery>,
) -> Result<Json<PaginatedResponse<IncidentResponse>>, ApiError> {
    // Validate query parameters
    query.validate()?;

    let repo: Box<dyn IncidentRepository> = create_incident_repository(&state.db);

    // Build filter from query
    let filter = IncidentFilter {
        status: query.status.map(|s| parse_statuses(&s)),
        severity: query.severity.map(|s| parse_severities(&s)),
        since: query.since,
        until: query.until,
        tags: None,
        has_ticket: None,
    };

    let pagination = Pagination {
        page: query.page.unwrap_or(1),
        per_page: query.per_page.unwrap_or(20),
    };

    // Get incidents and count
    let incidents: Vec<Incident> = repo.list(&filter, &pagination).await?;
    let total: u64 = repo.count(&filter).await?;

    let total_pages = ((total as f64) / (pagination.per_page as f64)).ceil() as u32;

    let data: Vec<IncidentResponse> = incidents.into_iter().map(incident_to_response).collect();

    Ok(Json(PaginatedResponse {
        data,
        pagination: PaginationInfo {
            page: pagination.page,
            per_page: pagination.per_page,
            total_items: total,
            total_pages,
        },
    }))
}

/// Get a single incident by ID.
#[utoipa::path(
    get,
    path = "/api/incidents/{id}",
    params(
        ("id" = Uuid, Path, description = "Incident ID")
    ),
    responses(
        (status = 200, description = "Incident details", body = IncidentDetailResponse),
        (status = 404, description = "Incident not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Incidents"
)]
async fn get_incident(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<IncidentDetailResponse>, ApiError> {
    let incident_repo: Box<dyn IncidentRepository> = create_incident_repository(&state.db);
    let audit_repo: Box<dyn AuditRepository> = create_audit_repository(&state.db);

    let incident: Incident = incident_repo
        .get(id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Incident {} not found", id)))?;

    // Get audit log for this incident
    let audit_entries: Vec<tw_core::incident::AuditEntry> = audit_repo.get_for_incident(id).await?;

    let response = incident_to_detail_response(incident, audit_entries);

    Ok(Json(response))
}

/// Execute an action on an incident.
#[utoipa::path(
    post,
    path = "/api/incidents/{id}/actions",
    params(
        ("id" = Uuid, Path, description = "Incident ID")
    ),
    request_body = ExecuteActionRequest,
    responses(
        (status = 202, description = "Action accepted for execution", body = ActionExecutionResponse),
        (status = 400, description = "Invalid request"),
        (status = 403, description = "Action denied by policy"),
        (status = 404, description = "Incident not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Incidents"
)]
async fn execute_action(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(request): Json<ExecuteActionRequest>,
) -> Result<(StatusCode, Json<ActionExecutionResponse>), ApiError> {
    request.validate()?;

    let incident_repo: Box<dyn IncidentRepository> = create_incident_repository(&state.db);

    // Verify incident exists
    let _incident: Incident = incident_repo
        .get(id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Incident {} not found", id)))?;

    // Parse action type
    let action_type = parse_action_type(&request.action_type).ok_or_else(|| {
        ApiError::BadRequest(format!("Unknown action type: {}", request.action_type))
    })?;

    // Create proposed action
    let action_id = Uuid::new_v4();
    let target = request.target.into();
    let parameters = request
        .parameters
        .and_then(|p| p.as_object().cloned())
        .map(|obj| obj.into_iter().collect())
        .unwrap_or_default();

    // TODO: Evaluate policy engine
    // For now, we'll mark as auto-approved for low-risk actions
    let approval_status = if request.skip_policy_check {
        ApprovalStatus::AutoApproved
    } else {
        ApprovalStatus::Pending
    };

    let response = ActionExecutionResponse {
        action_id,
        incident_id: id,
        action_type: request.action_type,
        status: format!("{:?}", approval_status).to_lowercase(),
        message: if approval_status == ApprovalStatus::Pending {
            "Action pending approval".to_string()
        } else {
            "Action queued for execution".to_string()
        },
        result: None,
        executed_at: Utc::now(),
    };

    // Publish event
    let _ = state
        .event_bus
        .publish(tw_core::TriageEvent::ActionsProposed {
            incident_id: id,
            actions: vec![ProposedAction::new(
                action_type,
                target,
                request.reason,
                parameters,
            )],
        })
        .await;

    Ok((StatusCode::ACCEPTED, Json(response)))
}

/// Approve or deny a pending action.
#[utoipa::path(
    post,
    path = "/api/incidents/{id}/approve",
    params(
        ("id" = Uuid, Path, description = "Incident ID")
    ),
    request_body = ApproveActionRequest,
    responses(
        (status = 200, description = "Action approval processed", body = ActionExecutionResponse),
        (status = 400, description = "Invalid request"),
        (status = 404, description = "Incident or action not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Incidents"
)]
async fn approve_action(
    State(state): State<AppState>,
    Path(incident_id): Path<Uuid>,
    axum::Form(request): axum::Form<ApproveActionRequest>,
) -> Result<axum::response::Response, ApiError> {
    use axum::response::IntoResponse;

    request.validate()?;

    let incident_repo: Box<dyn IncidentRepository> = create_incident_repository(&state.db);

    // Verify incident exists
    let mut incident: Incident = incident_repo
        .get(incident_id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Incident {} not found", incident_id)))?;

    // Find and update the action
    let action_idx = incident
        .proposed_actions
        .iter()
        .position(|a| a.id == request.action_id)
        .ok_or_else(|| ApiError::NotFound(format!("Action {} not found", request.action_id)))?;

    if incident.proposed_actions[action_idx].approval_status != ApprovalStatus::Pending {
        return Err(ApiError::BadRequest(format!(
            "Action is not pending approval (current status: {:?})",
            incident.proposed_actions[action_idx].approval_status
        )));
    }

    // Update the action's approval status
    let new_status = if request.approved {
        ApprovalStatus::Approved
    } else {
        ApprovalStatus::Denied
    };

    incident.proposed_actions[action_idx].approval_status = new_status;
    incident.proposed_actions[action_idx].approved_by = Some("api_user".to_string());
    incident.proposed_actions[action_idx].approval_timestamp = Some(Utc::now());

    // If no more pending actions, update incident status
    let has_pending = incident
        .proposed_actions
        .iter()
        .any(|a| a.approval_status == ApprovalStatus::Pending);

    if !has_pending {
        incident.status = if request.approved {
            tw_core::incident::IncidentStatus::Executing
        } else {
            tw_core::incident::IncidentStatus::PendingReview
        };
    }

    // Save to database
    incident_repo.save(&incident).await?;

    // Publish approval event
    if request.approved {
        let _ = state
            .event_bus
            .publish(tw_core::TriageEvent::ActionApproved {
                incident_id,
                action_id: request.action_id,
                approved_by: "api_user".to_string(),
            })
            .await;
    } else {
        let _ = state
            .event_bus
            .publish(tw_core::TriageEvent::ActionDenied {
                incident_id,
                action_id: request.action_id,
                denied_by: "api_user".to_string(),
                reason: request
                    .reason
                    .unwrap_or_else(|| "No reason provided".to_string()),
            })
            .await;
    }

    // Return empty response with HX-Trigger for toast
    let toast_type = if request.approved { "success" } else { "info" };
    let toast_title = if request.approved {
        "Action Approved"
    } else {
        "Action Rejected"
    };
    let toast_message = if request.approved {
        "The action has been approved and will execute shortly."
    } else {
        "The action has been rejected."
    };

    let trigger_json = serde_json::json!({
        "showToast": {
            "type": toast_type,
            "title": toast_title,
            "message": toast_message
        }
    });

    Ok((
        [(
            axum::http::header::HeaderName::from_static("hx-trigger"),
            trigger_json.to_string(),
        )],
        "",
    )
        .into_response())
}

/// Dismiss an incident.
#[utoipa::path(
    post,
    path = "/api/incidents/{id}/dismiss",
    params(
        ("id" = Uuid, Path, description = "Incident ID")
    ),
    request_body = DismissRequest,
    responses(
        (status = 200, description = "Incident dismissed"),
        (status = 404, description = "Incident not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Incidents"
)]
async fn dismiss_incident(
    State(state): State<AppState>,
    Path(incident_id): Path<Uuid>,
    axum::Form(request): axum::Form<DismissRequest>,
) -> Result<axum::response::Response, ApiError> {
    use axum::response::IntoResponse;

    let incident_repo: Box<dyn IncidentRepository> = create_incident_repository(&state.db);
    let audit_repo: Box<dyn AuditRepository> = create_audit_repository(&state.db);

    // Get the incident
    let mut incident: Incident = incident_repo
        .get(incident_id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Incident {} not found", incident_id)))?;

    // Update status to Dismissed
    incident.status = IncidentStatus::Dismissed;
    incident.updated_at = Utc::now();

    // Save to database
    incident_repo.save(&incident).await?;

    // Create audit log entry
    let details = request
        .reason
        .as_ref()
        .map(|r| serde_json::json!({ "reason": r }));
    let audit_entry = AuditEntry::new(
        AuditAction::StatusChanged(IncidentStatus::Dismissed),
        "api_user".to_string(),
        details,
    );
    audit_repo.log(incident_id, &audit_entry).await?;

    // Publish status change event
    let _ = state
        .event_bus
        .publish(tw_core::TriageEvent::StatusChanged {
            incident_id,
            old_status: incident.status.clone(),
            new_status: IncidentStatus::Dismissed,
        })
        .await;

    // Return empty response with HX-Trigger for toast
    let trigger_json = serde_json::json!({
        "showToast": {
            "type": "success",
            "title": "Incident Dismissed",
            "message": "The incident has been dismissed."
        }
    });

    Ok((
        [(
            axum::http::header::HeaderName::from_static("hx-trigger"),
            trigger_json.to_string(),
        )],
        "",
    )
        .into_response())
}

/// Resolve an incident.
#[utoipa::path(
    post,
    path = "/api/incidents/{id}/resolve",
    params(
        ("id" = Uuid, Path, description = "Incident ID")
    ),
    request_body = ResolveRequest,
    responses(
        (status = 200, description = "Incident resolved"),
        (status = 404, description = "Incident not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Incidents"
)]
async fn resolve_incident(
    State(state): State<AppState>,
    Path(incident_id): Path<Uuid>,
    axum::Form(request): axum::Form<ResolveRequest>,
) -> Result<axum::response::Response, ApiError> {
    use axum::response::IntoResponse;

    let incident_repo: Box<dyn IncidentRepository> = create_incident_repository(&state.db);
    let audit_repo: Box<dyn AuditRepository> = create_audit_repository(&state.db);

    // Get the incident
    let mut incident: Incident = incident_repo
        .get(incident_id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Incident {} not found", incident_id)))?;

    let old_status = incident.status.clone();

    // Update status to Resolved
    incident.status = IncidentStatus::Resolved;
    incident.updated_at = Utc::now();

    // Save to database
    incident_repo.save(&incident).await?;

    // Create audit log entry
    let details = request
        .reason
        .as_ref()
        .map(|r| serde_json::json!({ "reason": r }));
    let audit_entry = AuditEntry::new(
        AuditAction::StatusChanged(IncidentStatus::Resolved),
        "api_user".to_string(),
        details,
    );
    audit_repo.log(incident_id, &audit_entry).await?;

    // Publish status change event
    let _ = state
        .event_bus
        .publish(tw_core::TriageEvent::StatusChanged {
            incident_id,
            old_status,
            new_status: IncidentStatus::Resolved,
        })
        .await;

    // Return empty response with HX-Trigger for toast
    let trigger_json = serde_json::json!({
        "showToast": {
            "type": "success",
            "title": "Incident Resolved",
            "message": "The incident has been marked as resolved."
        }
    });

    Ok((
        [(
            axum::http::header::HeaderName::from_static("hx-trigger"),
            trigger_json.to_string(),
        )],
        "",
    )
        .into_response())
}

/// Trigger re-enrichment for an incident.
#[utoipa::path(
    post,
    path = "/api/incidents/{id}/enrich",
    params(
        ("id" = Uuid, Path, description = "Incident ID")
    ),
    responses(
        (status = 200, description = "Enrichment requested"),
        (status = 404, description = "Incident not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Incidents"
)]
async fn enrich_incident(
    State(state): State<AppState>,
    Path(incident_id): Path<Uuid>,
) -> Result<axum::response::Response, ApiError> {
    use axum::response::IntoResponse;

    let incident_repo: Box<dyn IncidentRepository> = create_incident_repository(&state.db);
    let audit_repo: Box<dyn AuditRepository> = create_audit_repository(&state.db);

    // Verify incident exists
    let mut incident: Incident = incident_repo
        .get(incident_id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Incident {} not found", incident_id)))?;

    // Update status to Enriching
    let old_status = incident.status.clone();
    incident.status = IncidentStatus::Enriching;
    incident.updated_at = Utc::now();

    // Save to database
    incident_repo.save(&incident).await?;

    // Create audit log entry
    let audit_entry = AuditEntry::new(
        AuditAction::EnrichmentAdded,
        "api_user".to_string(),
        Some(serde_json::json!({ "action": "re-enrichment requested" })),
    );
    audit_repo.log(incident_id, &audit_entry).await?;

    // Publish enrichment requested event
    let _ = state
        .event_bus
        .publish(tw_core::TriageEvent::EnrichmentRequested { incident_id })
        .await;

    // Also publish status change event
    let _ = state
        .event_bus
        .publish(tw_core::TriageEvent::StatusChanged {
            incident_id,
            old_status,
            new_status: IncidentStatus::Enriching,
        })
        .await;

    // Return empty response with HX-Trigger for toast
    let trigger_json = serde_json::json!({
        "showToast": {
            "type": "info",
            "title": "Enrichment Started",
            "message": "Re-enrichment has been triggered for this incident."
        }
    });

    Ok((
        [(
            axum::http::header::HeaderName::from_static("hx-trigger"),
            trigger_json.to_string(),
        )],
        "",
    )
        .into_response())
}

// Helper functions

fn incident_to_response(incident: Incident) -> IncidentResponse {
    let (verdict, confidence, risk_score) = incident
        .analysis
        .as_ref()
        .map(|a| {
            (
                Some(format!("{:?}", a.verdict).to_lowercase()),
                Some(a.confidence),
                Some(a.risk_score),
            )
        })
        .unwrap_or((None, None, None));

    // Extract title and alert_type from alert_data
    let title = incident
        .alert_data
        .get("title")
        .and_then(|v| v.as_str())
        .map(String::from);
    let alert_type = incident
        .alert_data
        .get("alert_type")
        .and_then(|v| v.as_str())
        .map(String::from);

    IncidentResponse {
        id: incident.id,
        source: format!("{}", incident.source),
        severity: format!("{:?}", incident.severity).to_lowercase(),
        status: format!("{:?}", incident.status).to_lowercase(),
        title,
        alert_type,
        verdict,
        confidence,
        risk_score,
        ticket_id: incident.ticket_id,
        tags: incident.tags,
        created_at: incident.created_at,
        updated_at: incident.updated_at,
    }
}

fn incident_to_detail_response(
    incident: Incident,
    audit_entries: Vec<tw_core::incident::AuditEntry>,
) -> IncidentDetailResponse {
    let base = incident_to_response(incident.clone());

    let enrichments: Vec<EnrichmentResponse> = incident
        .enrichments
        .into_iter()
        .map(|e| EnrichmentResponse {
            enrichment_type: format!("{:?}", e.enrichment_type),
            source: e.source,
            data: e.data,
            timestamp: e.timestamp,
        })
        .collect();

    let analysis = incident.analysis.map(|a| AnalysisResponse {
        verdict: format!("{:?}", a.verdict).to_lowercase(),
        confidence: a.confidence,
        risk_score: a.risk_score,
        summary: a.summary,
        reasoning: a.reasoning,
        recommendations: a.recommendations,
        mitre_techniques: a
            .mitre_techniques
            .into_iter()
            .map(|t| MitreTechniqueResponse {
                id: t.id,
                name: t.name,
                tactic: t.tactic,
                confidence: t.confidence,
            })
            .collect(),
        iocs: a
            .iocs
            .into_iter()
            .map(|i| IoCResponse {
                ioc_type: format!("{:?}", i.ioc_type),
                value: i.value,
                context: i.context,
                score: i.score,
            })
            .collect(),
        analyzed_by: a.analyzed_by,
        timestamp: a.timestamp,
    });

    let proposed_actions: Vec<ActionResponse> = incident
        .proposed_actions
        .into_iter()
        .map(|a| ActionResponse {
            id: a.id,
            action_type: format!("{}", a.action_type),
            target: serde_json::to_value(&a.target).unwrap_or_default(),
            reason: a.reason,
            priority: a.priority,
            approval_status: format!("{:?}", a.approval_status).to_lowercase(),
            approved_by: a.approved_by,
            approval_timestamp: a.approval_timestamp,
        })
        .collect();

    let audit_log: Vec<AuditEntryResponse> = audit_entries
        .into_iter()
        .map(|e| AuditEntryResponse {
            id: e.id,
            action: format!("{:?}", e.action),
            actor: e.actor,
            details: e.details,
            timestamp: e.timestamp,
        })
        .collect();

    IncidentDetailResponse {
        incident: base,
        alert_data: incident.alert_data,
        enrichments,
        analysis,
        proposed_actions,
        audit_log,
    }
}

fn parse_statuses(s: &str) -> Vec<IncidentStatus> {
    s.split(',')
        .filter_map(|status| match status.trim().to_lowercase().as_str() {
            "new" => Some(IncidentStatus::New),
            "enriching" => Some(IncidentStatus::Enriching),
            "analyzing" => Some(IncidentStatus::Analyzing),
            "pending_review" => Some(IncidentStatus::PendingReview),
            "pending_approval" => Some(IncidentStatus::PendingApproval),
            "executing" => Some(IncidentStatus::Executing),
            "resolved" => Some(IncidentStatus::Resolved),
            "false_positive" => Some(IncidentStatus::FalsePositive),
            "dismissed" => Some(IncidentStatus::Dismissed),
            "escalated" => Some(IncidentStatus::Escalated),
            "closed" => Some(IncidentStatus::Closed),
            _ => None,
        })
        .collect()
}

fn parse_severities(s: &str) -> Vec<Severity> {
    s.split(',')
        .filter_map(|sev| match sev.trim().to_lowercase().as_str() {
            "info" => Some(Severity::Info),
            "low" => Some(Severity::Low),
            "medium" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            "critical" => Some(Severity::Critical),
            _ => None,
        })
        .collect()
}

fn parse_action_type(s: &str) -> Option<tw_core::incident::ActionType> {
    use tw_core::incident::ActionType;

    match s.to_lowercase().as_str() {
        "isolate_host" => Some(ActionType::IsolateHost),
        "unisolate_host" => Some(ActionType::UnisolateHost),
        "disable_user" => Some(ActionType::DisableUser),
        "enable_user" => Some(ActionType::EnableUser),
        "reset_password" => Some(ActionType::ResetPassword),
        "revoke_sessions" => Some(ActionType::RevokeSessions),
        "block_ip" => Some(ActionType::BlockIp),
        "unblock_ip" => Some(ActionType::UnblockIp),
        "block_domain" => Some(ActionType::BlockDomain),
        "quarantine_email" => Some(ActionType::QuarantineEmail),
        "delete_email" => Some(ActionType::DeleteEmail),
        "block_sender" => Some(ActionType::BlockSender),
        "create_ticket" => Some(ActionType::CreateTicket),
        "update_ticket" => Some(ActionType::UpdateTicket),
        "add_ticket_comment" => Some(ActionType::AddTicketComment),
        "send_notification" => Some(ActionType::SendNotification),
        "run_search" => Some(ActionType::RunSearch),
        "collect_forensics" => Some(ActionType::CollectForensics),
        _ => Some(ActionType::Custom(s.to_string())),
    }
}
