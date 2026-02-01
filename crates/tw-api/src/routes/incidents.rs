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
use tw_policy::engine::{ActionContext, ActionTarget as PolicyActionTarget};

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

    // Extract parameters as a HashMap (used for both policy context and action parameters)
    let parameters: std::collections::HashMap<String, serde_json::Value> = request
        .parameters
        .as_ref()
        .and_then(|p| p.as_object().cloned())
        .map(|obj| obj.into_iter().collect())
        .unwrap_or_default();

    // Evaluate policy engine for action approval
    let approval_status = if request.skip_policy_check {
        tracing::info!(
            incident_id = %id,
            action_type = %request.action_type,
            "Policy check skipped by request"
        );
        ApprovalStatus::AutoApproved
    } else {
        // Build ActionContext for policy evaluation
        let policy_target = build_policy_target(&target);
        let incident_severity = format!("{:?}", _incident.severity).to_lowercase();
        let confidence = _incident
            .analysis
            .as_ref()
            .map(|a| a.confidence)
            .unwrap_or(0.5);

        let context = ActionContext {
            action_type: request.action_type.clone(),
            target: policy_target,
            incident_severity,
            confidence,
            proposer: "api".to_string(),
            metadata: parameters.clone(),
        };

        // Evaluate the policy
        match state.policy_engine.evaluate(&context).await {
            Ok(tw_policy::PolicyDecision::Allowed) => {
                tracing::info!(
                    incident_id = %id,
                    action_type = %request.action_type,
                    "Policy decision: auto-approved"
                );
                ApprovalStatus::AutoApproved
            }
            Ok(tw_policy::PolicyDecision::Denied(reason)) => {
                tracing::warn!(
                    incident_id = %id,
                    action_type = %request.action_type,
                    rule = %reason.rule_name,
                    message = %reason.message,
                    "Policy decision: denied"
                );
                return Err(ApiError::Forbidden(format!(
                    "Action denied by policy '{}': {}",
                    reason.rule_name, reason.message
                )));
            }
            Ok(tw_policy::PolicyDecision::RequiresApproval(level)) => {
                tracing::info!(
                    incident_id = %id,
                    action_type = %request.action_type,
                    approval_level = ?level,
                    "Policy decision: requires approval"
                );
                ApprovalStatus::Pending
            }
            Err(e) => {
                tracing::error!(
                    incident_id = %id,
                    action_type = %request.action_type,
                    error = %e,
                    "Policy evaluation failed, defaulting to pending approval"
                );
                ApprovalStatus::Pending
            }
        }
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

/// Converts a tw_core ActionTarget to a tw_policy ActionTarget for policy evaluation.
fn build_policy_target(target: &tw_core::incident::ActionTarget) -> PolicyActionTarget {
    use tw_core::incident::ActionTarget;

    match target {
        ActionTarget::Host { hostname, ip: _ } => PolicyActionTarget {
            target_type: "host".to_string(),
            identifier: hostname.clone(),
            criticality: None,
            tags: vec![],
        },
        ActionTarget::User { username, email: _ } => PolicyActionTarget {
            target_type: "user".to_string(),
            identifier: username.clone(),
            criticality: None,
            tags: vec![],
        },
        ActionTarget::IpAddress(ip) => PolicyActionTarget {
            target_type: "ip".to_string(),
            identifier: ip.clone(),
            criticality: None,
            tags: vec![],
        },
        ActionTarget::Domain(domain) => PolicyActionTarget {
            target_type: "domain".to_string(),
            identifier: domain.clone(),
            criticality: None,
            tags: vec![],
        },
        ActionTarget::Email { message_id } => PolicyActionTarget {
            target_type: "email".to_string(),
            identifier: message_id.clone(),
            criticality: None,
            tags: vec![],
        },
        ActionTarget::Ticket { ticket_id } => PolicyActionTarget {
            target_type: "ticket".to_string(),
            identifier: ticket_id.clone(),
            criticality: None,
            tags: vec![],
        },
        ActionTarget::None => PolicyActionTarget {
            target_type: "none".to_string(),
            identifier: String::new(),
            criticality: None,
            tags: vec![],
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        Router,
    };
    use tower::ServiceExt;
    use tw_core::db::DbPool;
    use tw_core::incident::{
        Alert, AlertSource, ApprovalStatus, Incident, IncidentStatus, Severity,
    };
    use tw_core::EventBus;

    /// Creates an in-memory SQLite pool for testing.
    async fn create_test_pool() -> sqlx::SqlitePool {
        let db_url = format!(
            "sqlite:file:test_incidents_{}?mode=memory&cache=shared",
            Uuid::new_v4()
        );

        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect(&db_url)
            .await
            .expect("Failed to create pool");

        // Create schema manually with all status values including 'dismissed'
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                source TEXT NOT NULL,
                severity TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
                status TEXT NOT NULL CHECK (status IN ('new', 'enriching', 'analyzing', 'pending_review', 'pending_approval', 'executing', 'resolved', 'false_positive', 'dismissed', 'escalated', 'closed')),
                alert_data TEXT NOT NULL,
                enrichments TEXT NOT NULL DEFAULT '[]',
                analysis TEXT,
                proposed_actions TEXT NOT NULL DEFAULT '[]',
                ticket_id TEXT,
                tags TEXT NOT NULL DEFAULT '[]',
                metadata TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
            CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
            CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents(created_at);
            CREATE INDEX IF NOT EXISTS idx_incidents_updated_at ON incidents(updated_at);
            "#,
        )
        .execute(&pool)
        .await
        .expect("Failed to create incidents table");

        // Create audit_logs table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS audit_logs (
                id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
                action TEXT NOT NULL,
                actor TEXT NOT NULL,
                details TEXT,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_audit_logs_incident_id ON audit_logs(incident_id);
            CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
            "#,
        )
        .execute(&pool)
        .await
        .expect("Failed to create audit_logs table");

        // Create actions table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS actions (
                id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
                action_type TEXT NOT NULL,
                target TEXT NOT NULL,
                parameters TEXT NOT NULL DEFAULT '{}',
                reason TEXT NOT NULL,
                priority INTEGER NOT NULL DEFAULT 50,
                approval_status TEXT NOT NULL CHECK (approval_status IN ('pending', 'auto_approved', 'approved', 'denied', 'executed', 'failed')),
                approved_by TEXT,
                approval_timestamp TEXT,
                result TEXT,
                created_at TEXT NOT NULL,
                executed_at TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_actions_incident_id ON actions(incident_id);
            CREATE INDEX IF NOT EXISTS idx_actions_status ON actions(approval_status);
            CREATE INDEX IF NOT EXISTS idx_actions_created_at ON actions(created_at);
            "#,
        )
        .execute(&pool)
        .await
        .expect("Failed to create actions table");

        pool
    }

    /// Creates an AppState with the test pool.
    async fn create_test_state() -> AppState {
        let pool = create_test_pool().await;
        let db = DbPool::Sqlite(pool);
        let event_bus = EventBus::new(100);
        AppState::new(db, event_bus)
    }

    /// Creates a test router with the incidents routes.
    async fn create_test_router() -> (Router, AppState) {
        let state = create_test_state().await;
        let router = Router::new()
            .nest("/api/incidents", routes())
            .with_state(state.clone());
        (router, state)
    }

    /// Creates a test incident and saves it to the database.
    async fn create_test_incident(state: &AppState) -> Incident {
        let alert = Alert {
            id: format!("alert-{}", Uuid::new_v4()),
            source: AlertSource::EmailSecurity("M365".to_string()),
            alert_type: "phishing".to_string(),
            severity: Severity::High,
            title: "Suspected phishing email".to_string(),
            description: Some("User reported suspicious email".to_string()),
            data: serde_json::json!({
                "title": "Suspected phishing email",
                "alert_type": "phishing",
                "subject": "Urgent: Update your password"
            }),
            timestamp: Utc::now(),
            tags: vec!["phishing".to_string(), "user-reported".to_string()],
        };

        let incident = Incident::from_alert(alert);
        let repo = create_incident_repository(&state.db);
        repo.create(&incident)
            .await
            .expect("Failed to create incident");
        incident
    }

    /// Creates a test incident with a pending action.
    async fn create_incident_with_pending_action(state: &AppState) -> (Incident, Uuid) {
        let alert = Alert {
            id: format!("alert-{}", Uuid::new_v4()),
            source: AlertSource::Edr("CrowdStrike".to_string()),
            alert_type: "malware".to_string(),
            severity: Severity::Critical,
            title: "Malware detected".to_string(),
            description: Some("Ransomware activity detected".to_string()),
            data: serde_json::json!({
                "title": "Malware detected",
                "alert_type": "malware",
                "hostname": "workstation-123"
            }),
            timestamp: Utc::now(),
            tags: vec!["malware".to_string(), "ransomware".to_string()],
        };

        let mut incident = Incident::from_alert(alert);
        incident.status = IncidentStatus::PendingApproval;

        let action = tw_core::incident::ProposedAction::new(
            tw_core::incident::ActionType::IsolateHost,
            tw_core::incident::ActionTarget::Host {
                hostname: "workstation-123".to_string(),
                ip: Some("192.168.1.100".to_string()),
            },
            "Isolate host to prevent lateral movement".to_string(),
            std::collections::HashMap::new(),
        );
        let action_id = action.id;
        incident.proposed_actions.push(action);

        let repo = create_incident_repository(&state.db);
        repo.create(&incident)
            .await
            .expect("Failed to create incident");
        (incident, action_id)
    }

    // ==============================================
    // List Incidents Tests
    // ==============================================

    #[tokio::test]
    async fn test_list_incidents_empty() {
        let (app, _state) = create_test_router().await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/incidents")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let result: PaginatedResponse<IncidentResponse> =
            serde_json::from_slice(&body).expect("Failed to parse response");

        assert_eq!(result.data.len(), 0);
        assert_eq!(result.pagination.total_items, 0);
        assert_eq!(result.pagination.page, 1);
        assert_eq!(result.pagination.per_page, 20);
    }

    #[tokio::test]
    async fn test_list_incidents_with_data() {
        let (app, state) = create_test_router().await;

        // Create test incidents
        let _incident1 = create_test_incident(&state).await;
        let _incident2 = create_test_incident(&state).await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/incidents")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let result: PaginatedResponse<IncidentResponse> =
            serde_json::from_slice(&body).expect("Failed to parse response");

        assert_eq!(result.data.len(), 2);
        assert_eq!(result.pagination.total_items, 2);
    }

    #[tokio::test]
    async fn test_list_incidents_with_status_filter() {
        let (app, state) = create_test_router().await;

        // Create a new incident
        let _incident = create_test_incident(&state).await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/incidents?status=new")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let result: PaginatedResponse<IncidentResponse> =
            serde_json::from_slice(&body).expect("Failed to parse response");

        assert_eq!(result.data.len(), 1);
        assert_eq!(result.data[0].status, "new");
    }

    #[tokio::test]
    async fn test_list_incidents_with_severity_filter() {
        let (app, state) = create_test_router().await;

        // Create a high severity incident
        let _incident = create_test_incident(&state).await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/incidents?severity=high")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let result: PaginatedResponse<IncidentResponse> =
            serde_json::from_slice(&body).expect("Failed to parse response");

        assert_eq!(result.data.len(), 1);
        assert_eq!(result.data[0].severity, "high");
    }

    #[tokio::test]
    async fn test_list_incidents_with_pagination() {
        let (app, state) = create_test_router().await;

        // Create 5 incidents
        for _ in 0..5 {
            create_test_incident(&state).await;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/incidents?page=1&per_page=2")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let result: PaginatedResponse<IncidentResponse> =
            serde_json::from_slice(&body).expect("Failed to parse response");

        assert_eq!(result.data.len(), 2);
        assert_eq!(result.pagination.total_items, 5);
        assert_eq!(result.pagination.total_pages, 3);
        assert_eq!(result.pagination.page, 1);
        assert_eq!(result.pagination.per_page, 2);
    }

    #[tokio::test]
    async fn test_list_incidents_invalid_pagination() {
        let (app, _state) = create_test_router().await;

        // Page 0 is invalid (minimum is 1)
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/incidents?page=0")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn test_list_incidents_per_page_exceeds_max() {
        let (app, _state) = create_test_router().await;

        // per_page 101 is invalid (max is 100)
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/incidents?per_page=101")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    // ==============================================
    // Get Incident Tests
    // ==============================================

    #[tokio::test]
    async fn test_get_incident_success() {
        let (app, state) = create_test_router().await;

        let incident = create_test_incident(&state).await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri(&format!("/api/incidents/{}", incident.id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let result: IncidentDetailResponse =
            serde_json::from_slice(&body).expect("Failed to parse response");

        assert_eq!(result.incident.id, incident.id);
        assert_eq!(result.incident.severity, "high");
        assert_eq!(result.incident.status, "new");
    }

    #[tokio::test]
    async fn test_get_incident_not_found() {
        let (app, _state) = create_test_router().await;

        let nonexistent_id = Uuid::new_v4();

        let response = app
            .oneshot(
                Request::builder()
                    .uri(&format!("/api/incidents/{}", nonexistent_id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_get_incident_with_enrichments() {
        let (app, state) = create_test_router().await;

        // Create incident with enrichment
        let alert = Alert {
            id: format!("alert-{}", Uuid::new_v4()),
            source: AlertSource::Siem("Splunk".to_string()),
            alert_type: "malware".to_string(),
            severity: Severity::Critical,
            title: "Malware detected".to_string(),
            description: None,
            data: serde_json::json!({"title": "Malware detected", "alert_type": "malware"}),
            timestamp: Utc::now(),
            tags: vec![],
        };

        let mut incident = Incident::from_alert(alert);
        let enrichment = tw_core::incident::Enrichment {
            enrichment_type: tw_core::incident::EnrichmentType::ThreatIntel,
            source: "VirusTotal".to_string(),
            data: serde_json::json!({"malicious": 45, "total": 70}),
            timestamp: Utc::now(),
            ttl_seconds: Some(3600),
        };
        incident.add_enrichment(enrichment);

        let repo = create_incident_repository(&state.db);
        repo.create(&incident)
            .await
            .expect("Failed to create incident");

        let response = app
            .oneshot(
                Request::builder()
                    .uri(&format!("/api/incidents/{}", incident.id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let result: IncidentDetailResponse =
            serde_json::from_slice(&body).expect("Failed to parse response");

        assert_eq!(result.enrichments.len(), 1);
        assert_eq!(result.enrichments[0].source, "VirusTotal");
    }

    // ==============================================
    // Execute Action Tests
    // ==============================================

    #[tokio::test]
    async fn test_execute_action_success() {
        let (app, state) = create_test_router().await;

        let incident = create_test_incident(&state).await;

        let request_body = serde_json::json!({
            "action_type": "isolate_host",
            "target": {
                "type": "host",
                "hostname": "workstation-123",
                "ip": "192.168.1.100"
            },
            "reason": "Isolate to prevent lateral movement"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&format!("/api/incidents/{}/actions", incident.id))
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::to_string(&request_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::ACCEPTED);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let result: ActionExecutionResponse =
            serde_json::from_slice(&body).expect("Failed to parse response");

        assert_eq!(result.incident_id, incident.id);
        assert_eq!(result.action_type, "isolate_host");
        assert_eq!(result.status, "pending");
    }

    #[tokio::test]
    async fn test_execute_action_skip_policy_check() {
        let (app, state) = create_test_router().await;

        let incident = create_test_incident(&state).await;

        let request_body = serde_json::json!({
            "action_type": "block_ip",
            "target": {
                "type": "ip_address",
                "ip": "10.0.0.1"
            },
            "reason": "Block malicious IP",
            "skip_policy_check": true
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&format!("/api/incidents/{}/actions", incident.id))
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::to_string(&request_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::ACCEPTED);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let result: ActionExecutionResponse =
            serde_json::from_slice(&body).expect("Failed to parse response");

        assert_eq!(result.status, "autoapproved");
    }

    #[tokio::test]
    async fn test_execute_action_incident_not_found() {
        let (app, _state) = create_test_router().await;

        let nonexistent_id = Uuid::new_v4();

        let request_body = serde_json::json!({
            "action_type": "isolate_host",
            "target": {
                "type": "host",
                "hostname": "workstation-123"
            },
            "reason": "Test action"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&format!("/api/incidents/{}/actions", nonexistent_id))
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::to_string(&request_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_execute_action_invalid_request() {
        let (app, state) = create_test_router().await;

        let incident = create_test_incident(&state).await;

        // Missing required fields - returns 422 UNPROCESSABLE_ENTITY for validation errors
        let request_body = serde_json::json!({
            "action_type": "isolate_host"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&format!("/api/incidents/{}/actions", incident.id))
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::to_string(&request_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Missing fields result in either BAD_REQUEST (parsing error) or UNPROCESSABLE_ENTITY (validation)
        assert!(
            response.status() == StatusCode::BAD_REQUEST
                || response.status() == StatusCode::UNPROCESSABLE_ENTITY
        );
    }

    // ==============================================
    // Approve Action Tests
    // ==============================================

    #[tokio::test]
    async fn test_approve_action_success() {
        let (app, state) = create_test_router().await;

        let (incident, action_id) = create_incident_with_pending_action(&state).await;

        let form_data = format!("action_id={}&approved=true", action_id);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&format!("/api/incidents/{}/approve", incident.id))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .body(Body::from(form_data))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Check HX-Trigger header for toast notification
        let hx_trigger = response.headers().get("hx-trigger");
        assert!(hx_trigger.is_some());

        let trigger_value = hx_trigger.unwrap().to_str().unwrap();
        assert!(trigger_value.contains("showToast"));
        assert!(trigger_value.contains("success"));
    }

    #[tokio::test]
    async fn test_reject_action_success() {
        let (app, state) = create_test_router().await;

        let (incident, action_id) = create_incident_with_pending_action(&state).await;

        let form_data = format!(
            "action_id={}&approved=false&reason=Not%20authorized",
            action_id
        );

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&format!("/api/incidents/{}/approve", incident.id))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .body(Body::from(form_data))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Verify action was rejected
        let repo = create_incident_repository(&state.db);
        let updated_incident = repo.get(incident.id).await.unwrap().unwrap();
        assert_eq!(
            updated_incident.proposed_actions[0].approval_status,
            ApprovalStatus::Denied
        );
    }

    #[tokio::test]
    async fn test_approve_action_incident_not_found() {
        let (app, _state) = create_test_router().await;

        let nonexistent_id = Uuid::new_v4();
        let action_id = Uuid::new_v4();

        let form_data = format!("action_id={}&approved=true", action_id);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&format!("/api/incidents/{}/approve", nonexistent_id))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .body(Body::from(form_data))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_approve_action_not_found() {
        let (app, state) = create_test_router().await;

        let incident = create_test_incident(&state).await;
        let nonexistent_action_id = Uuid::new_v4();

        let form_data = format!("action_id={}&approved=true", nonexistent_action_id);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&format!("/api/incidents/{}/approve", incident.id))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .body(Body::from(form_data))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_approve_already_approved_action() {
        let (app, state) = create_test_router().await;

        let (incident, action_id) = create_incident_with_pending_action(&state).await;

        // First approve the action
        let repo = create_incident_repository(&state.db);
        let mut updated_incident = repo.get(incident.id).await.unwrap().unwrap();
        updated_incident.proposed_actions[0].approval_status = ApprovalStatus::Approved;
        repo.save(&updated_incident).await.unwrap();

        // Try to approve again
        let form_data = format!("action_id={}&approved=true", action_id);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&format!("/api/incidents/{}/approve", incident.id))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .body(Body::from(form_data))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    // ==============================================
    // Dismiss Incident Tests
    // ==============================================

    #[tokio::test]
    async fn test_dismiss_incident_success() {
        let (app, state) = create_test_router().await;

        let incident = create_test_incident(&state).await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&format!("/api/incidents/{}/dismiss", incident.id))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .body(Body::from("reason=False%20positive"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Verify incident was dismissed
        let repo = create_incident_repository(&state.db);
        let updated_incident = repo.get(incident.id).await.unwrap().unwrap();
        assert_eq!(updated_incident.status, IncidentStatus::Dismissed);

        // Check HX-Trigger header
        let hx_trigger = response.headers().get("hx-trigger");
        assert!(hx_trigger.is_some());
    }

    #[tokio::test]
    async fn test_dismiss_incident_without_reason() {
        let (app, state) = create_test_router().await;

        let incident = create_test_incident(&state).await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&format!("/api/incidents/{}/dismiss", incident.id))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Verify incident was dismissed
        let repo = create_incident_repository(&state.db);
        let updated_incident = repo.get(incident.id).await.unwrap().unwrap();
        assert_eq!(updated_incident.status, IncidentStatus::Dismissed);
    }

    #[tokio::test]
    async fn test_dismiss_incident_not_found() {
        let (app, _state) = create_test_router().await;

        let nonexistent_id = Uuid::new_v4();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&format!("/api/incidents/{}/dismiss", nonexistent_id))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // ==============================================
    // Resolve Incident Tests
    // ==============================================

    #[tokio::test]
    async fn test_resolve_incident_success() {
        let (app, state) = create_test_router().await;

        let incident = create_test_incident(&state).await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&format!("/api/incidents/{}/resolve", incident.id))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .body(Body::from("reason=Threat%20mitigated"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Verify incident was resolved
        let repo = create_incident_repository(&state.db);
        let updated_incident = repo.get(incident.id).await.unwrap().unwrap();
        assert_eq!(updated_incident.status, IncidentStatus::Resolved);
    }

    #[tokio::test]
    async fn test_resolve_incident_without_reason() {
        let (app, state) = create_test_router().await;

        let incident = create_test_incident(&state).await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&format!("/api/incidents/{}/resolve", incident.id))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Verify incident was resolved
        let repo = create_incident_repository(&state.db);
        let updated_incident = repo.get(incident.id).await.unwrap().unwrap();
        assert_eq!(updated_incident.status, IncidentStatus::Resolved);
    }

    #[tokio::test]
    async fn test_resolve_incident_not_found() {
        let (app, _state) = create_test_router().await;

        let nonexistent_id = Uuid::new_v4();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&format!("/api/incidents/{}/resolve", nonexistent_id))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // ==============================================
    // Enrich Incident Tests
    // ==============================================

    #[tokio::test]
    async fn test_enrich_incident_success() {
        let (app, state) = create_test_router().await;

        let incident = create_test_incident(&state).await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&format!("/api/incidents/{}/enrich", incident.id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Verify incident status changed to Enriching
        let repo = create_incident_repository(&state.db);
        let updated_incident = repo.get(incident.id).await.unwrap().unwrap();
        assert_eq!(updated_incident.status, IncidentStatus::Enriching);

        // Check HX-Trigger header
        let hx_trigger = response.headers().get("hx-trigger");
        assert!(hx_trigger.is_some());
        let trigger_value = hx_trigger.unwrap().to_str().unwrap();
        assert!(trigger_value.contains("Enrichment Started"));
    }

    #[tokio::test]
    async fn test_enrich_incident_not_found() {
        let (app, _state) = create_test_router().await;

        let nonexistent_id = Uuid::new_v4();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&format!("/api/incidents/{}/enrich", nonexistent_id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // ==============================================
    // Helper Functions Tests
    // ==============================================

    #[test]
    fn test_parse_statuses() {
        let statuses = parse_statuses("new,enriching,resolved");
        assert_eq!(statuses.len(), 3);
        assert!(statuses.contains(&IncidentStatus::New));
        assert!(statuses.contains(&IncidentStatus::Enriching));
        assert!(statuses.contains(&IncidentStatus::Resolved));
    }

    #[test]
    fn test_parse_statuses_with_spaces() {
        let statuses = parse_statuses("new, pending_review, false_positive");
        assert_eq!(statuses.len(), 3);
        assert!(statuses.contains(&IncidentStatus::New));
        assert!(statuses.contains(&IncidentStatus::PendingReview));
        assert!(statuses.contains(&IncidentStatus::FalsePositive));
    }

    #[test]
    fn test_parse_statuses_invalid() {
        let statuses = parse_statuses("new,invalid,resolved");
        assert_eq!(statuses.len(), 2);
        assert!(statuses.contains(&IncidentStatus::New));
        assert!(statuses.contains(&IncidentStatus::Resolved));
    }

    #[test]
    fn test_parse_severities() {
        let severities = parse_severities("low,medium,high");
        assert_eq!(severities.len(), 3);
        assert!(severities.contains(&Severity::Low));
        assert!(severities.contains(&Severity::Medium));
        assert!(severities.contains(&Severity::High));
    }

    #[test]
    fn test_parse_severities_with_spaces() {
        let severities = parse_severities("info, critical");
        assert_eq!(severities.len(), 2);
        assert!(severities.contains(&Severity::Info));
        assert!(severities.contains(&Severity::Critical));
    }

    #[test]
    fn test_parse_severities_invalid() {
        let severities = parse_severities("low,invalid,critical");
        assert_eq!(severities.len(), 2);
        assert!(severities.contains(&Severity::Low));
        assert!(severities.contains(&Severity::Critical));
    }

    #[test]
    fn test_parse_action_type_known_types() {
        assert_eq!(
            parse_action_type("isolate_host"),
            Some(tw_core::incident::ActionType::IsolateHost)
        );
        assert_eq!(
            parse_action_type("disable_user"),
            Some(tw_core::incident::ActionType::DisableUser)
        );
        assert_eq!(
            parse_action_type("block_ip"),
            Some(tw_core::incident::ActionType::BlockIp)
        );
        assert_eq!(
            parse_action_type("quarantine_email"),
            Some(tw_core::incident::ActionType::QuarantineEmail)
        );
        assert_eq!(
            parse_action_type("create_ticket"),
            Some(tw_core::incident::ActionType::CreateTicket)
        );
    }

    #[test]
    fn test_parse_action_type_custom() {
        let action = parse_action_type("custom_action");
        assert_eq!(
            action,
            Some(tw_core::incident::ActionType::Custom(
                "custom_action".to_string()
            ))
        );
    }

    #[test]
    fn test_parse_action_type_case_insensitive() {
        assert_eq!(
            parse_action_type("ISOLATE_HOST"),
            Some(tw_core::incident::ActionType::IsolateHost)
        );
        assert_eq!(
            parse_action_type("Block_IP"),
            Some(tw_core::incident::ActionType::BlockIp)
        );
    }

    #[test]
    fn test_incident_to_response() {
        let alert = Alert {
            id: "test-alert".to_string(),
            source: AlertSource::EmailSecurity("M365".to_string()),
            alert_type: "phishing".to_string(),
            severity: Severity::High,
            title: "Test Alert".to_string(),
            description: None,
            data: serde_json::json!({
                "title": "Test Alert",
                "alert_type": "phishing"
            }),
            timestamp: Utc::now(),
            tags: vec!["test".to_string()],
        };

        let incident = Incident::from_alert(alert);
        let response = incident_to_response(incident.clone());

        assert_eq!(response.id, incident.id);
        assert_eq!(response.severity, "high");
        assert_eq!(response.status, "new");
        assert_eq!(response.title, Some("Test Alert".to_string()));
        assert_eq!(response.alert_type, Some("phishing".to_string()));
        assert!(response.tags.contains(&"test".to_string()));
    }

    #[test]
    fn test_incident_to_detail_response() {
        let alert = Alert {
            id: "test-alert".to_string(),
            source: AlertSource::Siem("Splunk".to_string()),
            alert_type: "malware".to_string(),
            severity: Severity::Critical,
            title: "Malware Detected".to_string(),
            description: Some("Ransomware activity".to_string()),
            data: serde_json::json!({
                "title": "Malware Detected",
                "alert_type": "malware"
            }),
            timestamp: Utc::now(),
            tags: vec![],
        };

        let incident = Incident::from_alert(alert);
        let audit_entries = vec![];
        let response = incident_to_detail_response(incident.clone(), audit_entries);

        assert_eq!(response.incident.id, incident.id);
        assert_eq!(response.incident.severity, "critical");
        assert!(response.analysis.is_none());
        assert!(response.enrichments.is_empty());
        assert!(response.proposed_actions.is_empty());
    }
}
