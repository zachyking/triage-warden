//! Feedback API endpoints (Task 2.2.2).
//!
//! This module provides REST endpoints for managing analyst feedback on AI-generated
//! triage analyses, as well as feedback analytics for tracking AI performance.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{delete, get, post, put},
    Json, Router,
};
use chrono::{Datelike, Duration, Utc};
use uuid::Uuid;
use validator::Validate;

use crate::auth::RequireAnalyst;
use crate::dto::{
    AccuracyBreakdownItem, AccuracyByDimensionResponse, AccuracyTrendQuery, AccuracyTrendResponse,
    CreateFeedbackRequest, FeedbackCalibrationMetricsResponse, FeedbackResponse,
    FeedbackStatsQuery, FeedbackStatsResponse, ListFeedbackQuery, PaginatedResponse,
    PaginationInfo, TrendDataPoint, UpdateFeedbackRequest,
};
use crate::error::ApiError;
use crate::middleware::OptionalTenant;
use crate::state::AppState;
use tw_core::auth::DEFAULT_TENANT_ID;
use tw_core::db::{
    create_feedback_repository, create_incident_repository, FeedbackFilter, FeedbackRepository,
    FeedbackUpdate, IncidentRepository, Pagination, DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE,
};
use tw_core::feedback::{AnalystFeedback, FeedbackStats, FeedbackType};
use tw_core::incident::{Severity, TriageVerdict};

fn tenant_id_or_default(tenant: Option<tw_core::tenant::TenantContext>) -> Uuid {
    tenant.map(|ctx| ctx.tenant_id).unwrap_or(DEFAULT_TENANT_ID)
}

/// Creates feedback routes.
pub fn routes() -> Router<AppState> {
    Router::new()
        // Analytics endpoints (more specific routes first)
        .route("/stats", get(get_feedback_stats))
        .route("/accuracy/by-verdict", get(get_accuracy_by_verdict))
        .route("/accuracy/by-type", get(get_accuracy_by_type))
        .route("/trends", get(get_accuracy_trends))
        // CRUD endpoints
        .route("/", get(list_feedback))
        .route("/:id", get(get_feedback))
        .route("/:id", put(update_feedback))
        .route("/:id", delete(delete_feedback))
}

/// Creates routes for feedback on a specific incident.
/// These are mounted under /api/incidents/{id}/feedback
pub fn incident_feedback_routes() -> Router<AppState> {
    Router::new()
        .route("/", post(create_feedback_for_incident))
        .route("/", get(get_feedback_for_incident))
}

// ============================================================================
// CRUD Endpoints
// ============================================================================

/// Create feedback for an incident.
#[utoipa::path(
    post,
    path = "/api/incidents/{incident_id}/feedback",
    params(
        ("incident_id" = Uuid, Path, description = "Incident ID")
    ),
    request_body = CreateFeedbackRequest,
    responses(
        (status = 201, description = "Feedback created", body = FeedbackResponse),
        (status = 400, description = "Invalid request"),
        (status = 404, description = "Incident not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Feedback"
)]
async fn create_feedback_for_incident(
    State(state): State<AppState>,
    RequireAnalyst(user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
    Path(incident_id): Path<Uuid>,
    Json(request): Json<CreateFeedbackRequest>,
) -> Result<(StatusCode, Json<FeedbackResponse>), ApiError> {
    request.validate()?;
    let tenant_id = tenant_id_or_default(tenant);

    let incident_repo: Box<dyn IncidentRepository> = create_incident_repository(&state.db);
    let feedback_repo: Box<dyn FeedbackRepository> = create_feedback_repository(&state.db);

    // Get the incident to validate it exists and get analysis data
    let incident = incident_repo
        .get_for_tenant(incident_id, tenant_id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Incident {} not found", incident_id)))?;

    // Get the analysis from the incident
    let analysis = incident.analysis.as_ref().ok_or_else(|| {
        ApiError::BadRequest("Cannot provide feedback on incident without analysis".to_string())
    })?;

    // Parse feedback type
    let feedback_type = parse_feedback_type(&request.feedback_type).ok_or_else(|| {
        ApiError::BadRequest(format!("Unknown feedback type: {}", request.feedback_type))
    })?;

    // Parse corrected verdict if provided
    let corrected_verdict = request
        .corrected_verdict
        .as_ref()
        .map(|v| parse_verdict(v))
        .transpose()
        .map_err(ApiError::BadRequest)?;

    // Parse corrected severity if provided
    let corrected_severity = request
        .corrected_severity
        .as_ref()
        .map(|s| parse_severity(s))
        .transpose()
        .map_err(ApiError::BadRequest)?;

    // Build the feedback entry
    let mut feedback = AnalystFeedback::correct(
        incident_id,
        tenant_id,
        user.id,
        analysis.verdict.clone(),
        incident.severity,
        analysis.confidence,
    );

    // Override with actual feedback type and corrections
    feedback.feedback_type = feedback_type;
    feedback.corrected_verdict = corrected_verdict;
    feedback.corrected_severity = corrected_severity;
    feedback.notes = request.notes;
    feedback.original_mitre_techniques = analysis
        .mitre_techniques
        .iter()
        .map(|t| t.id.clone())
        .collect();
    feedback.corrected_mitre_techniques = request.corrected_mitre_techniques;

    // Save the feedback
    let created = feedback_repo.create(&feedback).await?;

    // Publish event for feedback received
    state
        .event_bus
        .publish_with_fallback(tw_core::TriageEvent::FeedbackReceived {
            incident_id,
            feedback_id: created.id,
            feedback_type: feedback_type.to_string(),
            is_correction: created.is_correction(),
        })
        .await;

    let response = feedback_to_response(created);
    Ok((StatusCode::CREATED, Json(response)))
}

/// Get all feedback for a specific incident.
#[utoipa::path(
    get,
    path = "/api/incidents/{incident_id}/feedback",
    params(
        ("incident_id" = Uuid, Path, description = "Incident ID")
    ),
    responses(
        (status = 200, description = "List of feedback for incident", body = Vec<FeedbackResponse>),
        (status = 404, description = "Incident not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Feedback"
)]
async fn get_feedback_for_incident(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
    Path(incident_id): Path<Uuid>,
) -> Result<Json<Vec<FeedbackResponse>>, ApiError> {
    let tenant_id = tenant_id_or_default(tenant);
    let incident_repo: Box<dyn IncidentRepository> = create_incident_repository(&state.db);
    let feedback_repo: Box<dyn FeedbackRepository> = create_feedback_repository(&state.db);

    // Verify incident exists
    let _incident = incident_repo
        .get_for_tenant(incident_id, tenant_id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Incident {} not found", incident_id)))?;

    let feedback_list = feedback_repo
        .get_for_incident(tenant_id, incident_id)
        .await?;

    let responses: Vec<FeedbackResponse> = feedback_list
        .into_iter()
        .map(feedback_to_response)
        .collect();

    Ok(Json(responses))
}

/// List all feedback with optional filtering.
#[utoipa::path(
    get,
    path = "/api/feedback",
    params(
        ("feedback_type" = Option<String>, Query, description = "Filter by feedback type"),
        ("analyst_id" = Option<Uuid>, Query, description = "Filter by analyst ID"),
        ("original_verdict" = Option<String>, Query, description = "Filter by original verdict"),
        ("has_correction" = Option<bool>, Query, description = "Filter by whether a correction was made"),
        ("since" = Option<String>, Query, description = "Filter by minimum created_at timestamp"),
        ("until" = Option<String>, Query, description = "Filter by maximum created_at timestamp"),
        ("page" = Option<u32>, Query, description = "Page number (1-indexed)"),
        ("per_page" = Option<u32>, Query, description = "Items per page (max 200)")
    ),
    responses(
        (status = 200, description = "Paginated list of feedback", body = PaginatedResponse<FeedbackResponse>),
        (status = 400, description = "Invalid query parameters"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Feedback"
)]
async fn list_feedback(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
    Query(query): Query<ListFeedbackQuery>,
) -> Result<Json<PaginatedResponse<FeedbackResponse>>, ApiError> {
    query.validate()?;
    let tenant_id = tenant_id_or_default(tenant);

    let feedback_repo: Box<dyn FeedbackRepository> = create_feedback_repository(&state.db);

    // Build filter from query
    let feedback_type = query
        .feedback_type
        .as_ref()
        .and_then(|ft| parse_feedback_type(ft));
    let original_verdict = query
        .original_verdict
        .as_ref()
        .and_then(|v| parse_verdict(v).ok());

    let filter = FeedbackFilter {
        tenant_id: Some(tenant_id),
        incident_id: None,
        analyst_id: query.analyst_id,
        feedback_type,
        original_verdict,
        has_correction: query.has_correction,
        since: query.since,
        until: query.until,
    };

    let pagination = Pagination::new(
        query.page.unwrap_or(1),
        query
            .per_page
            .unwrap_or(DEFAULT_PAGE_SIZE)
            .min(MAX_PAGE_SIZE),
    );

    let result = feedback_repo.list(&filter, &pagination).await?;

    let data: Vec<FeedbackResponse> = result.items.into_iter().map(feedback_to_response).collect();

    Ok(Json(PaginatedResponse {
        data,
        pagination: PaginationInfo {
            page: pagination.page,
            per_page: pagination.per_page,
            total_items: result.total,
            total_pages: ((result.total as f64) / (pagination.per_page as f64)).ceil() as u32,
        },
    }))
}

/// Get a specific feedback entry by ID.
#[utoipa::path(
    get,
    path = "/api/feedback/{id}",
    params(
        ("id" = Uuid, Path, description = "Feedback ID")
    ),
    responses(
        (status = 200, description = "Feedback details", body = FeedbackResponse),
        (status = 404, description = "Feedback not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Feedback"
)]
async fn get_feedback(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
    Path(id): Path<Uuid>,
) -> Result<Json<FeedbackResponse>, ApiError> {
    let tenant_id = tenant_id_or_default(tenant);
    let feedback_repo: Box<dyn FeedbackRepository> = create_feedback_repository(&state.db);

    let feedback = feedback_repo
        .get_for_tenant(id, tenant_id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Feedback {} not found", id)))?;

    Ok(Json(feedback_to_response(feedback)))
}

/// Update a feedback entry.
#[utoipa::path(
    put,
    path = "/api/feedback/{id}",
    params(
        ("id" = Uuid, Path, description = "Feedback ID")
    ),
    request_body = UpdateFeedbackRequest,
    responses(
        (status = 200, description = "Feedback updated", body = FeedbackResponse),
        (status = 400, description = "Invalid request"),
        (status = 404, description = "Feedback not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Feedback"
)]
async fn update_feedback(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateFeedbackRequest>,
) -> Result<Json<FeedbackResponse>, ApiError> {
    request.validate()?;
    let tenant_id = tenant_id_or_default(tenant);

    let feedback_repo: Box<dyn FeedbackRepository> = create_feedback_repository(&state.db);

    // Build the update struct
    let corrected_verdict = request
        .corrected_verdict
        .map(|cv| {
            cv.map(|v| parse_verdict(&v))
                .transpose()
                .map_err(ApiError::BadRequest)
        })
        .transpose()?;

    let corrected_severity = request
        .corrected_severity
        .map(|cs| {
            cs.map(|s| parse_severity(&s))
                .transpose()
                .map_err(ApiError::BadRequest)
        })
        .transpose()?;

    let feedback_type = request
        .feedback_type
        .map(|ft| {
            parse_feedback_type(&ft)
                .ok_or_else(|| ApiError::BadRequest(format!("Unknown feedback type: {}", ft)))
        })
        .transpose()?;

    let update = FeedbackUpdate {
        corrected_verdict,
        corrected_severity,
        feedback_type,
        notes: request.notes,
        corrected_mitre_techniques: request.corrected_mitre_techniques,
    };

    let updated = feedback_repo.update(id, tenant_id, &update).await?;

    Ok(Json(feedback_to_response(updated)))
}

/// Delete a feedback entry.
#[utoipa::path(
    delete,
    path = "/api/feedback/{id}",
    params(
        ("id" = Uuid, Path, description = "Feedback ID")
    ),
    responses(
        (status = 204, description = "Feedback deleted"),
        (status = 404, description = "Feedback not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Feedback"
)]
async fn delete_feedback(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let tenant_id = tenant_id_or_default(tenant);
    let feedback_repo: Box<dyn FeedbackRepository> = create_feedback_repository(&state.db);

    let deleted = feedback_repo.delete(id, tenant_id).await?;

    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NotFound(format!("Feedback {} not found", id)))
    }
}

// ============================================================================
// Analytics Endpoints
// ============================================================================

/// Get aggregate feedback statistics.
#[utoipa::path(
    get,
    path = "/api/feedback/stats",
    params(
        ("since" = Option<String>, Query, description = "Filter by minimum created_at timestamp"),
        ("until" = Option<String>, Query, description = "Filter by maximum created_at timestamp")
    ),
    responses(
        (status = 200, description = "Feedback statistics", body = FeedbackStatsResponse),
        (status = 500, description = "Internal server error")
    ),
    tag = "Feedback Analytics"
)]
async fn get_feedback_stats(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
    Query(query): Query<FeedbackStatsQuery>,
) -> Result<Json<FeedbackStatsResponse>, ApiError> {
    let tenant_id = tenant_id_or_default(tenant);
    let feedback_repo: Box<dyn FeedbackRepository> = create_feedback_repository(&state.db);

    let stats = if let (Some(since), Some(until)) = (query.since, query.until) {
        feedback_repo
            .get_stats_for_range(tenant_id, since, until)
            .await?
    } else {
        feedback_repo.get_stats(tenant_id).await?
    };

    Ok(Json(stats_to_response(stats)))
}

/// Get accuracy breakdown by verdict type.
#[utoipa::path(
    get,
    path = "/api/feedback/accuracy/by-verdict",
    params(
        ("since" = Option<String>, Query, description = "Filter by minimum created_at timestamp"),
        ("until" = Option<String>, Query, description = "Filter by maximum created_at timestamp")
    ),
    responses(
        (status = 200, description = "Accuracy by verdict type", body = AccuracyByDimensionResponse),
        (status = 500, description = "Internal server error")
    ),
    tag = "Feedback Analytics"
)]
async fn get_accuracy_by_verdict(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
    Query(query): Query<FeedbackStatsQuery>,
) -> Result<Json<AccuracyByDimensionResponse>, ApiError> {
    let tenant_id = tenant_id_or_default(tenant);
    let feedback_repo: Box<dyn FeedbackRepository> = create_feedback_repository(&state.db);

    // Get stats for each verdict type
    let verdicts = [
        TriageVerdict::TruePositive,
        TriageVerdict::LikelyTruePositive,
        TriageVerdict::Suspicious,
        TriageVerdict::LikelyFalsePositive,
        TriageVerdict::FalsePositive,
        TriageVerdict::Inconclusive,
    ];

    let mut items = Vec::new();

    for verdict in verdicts {
        let filter = FeedbackFilter {
            tenant_id: Some(tenant_id),
            original_verdict: Some(verdict.clone()),
            since: query.since,
            until: query.until,
            ..Default::default()
        };

        let count = feedback_repo.count(&filter).await?;
        if count > 0 {
            // Get paginated results to calculate stats
            let pagination = Pagination::new(1, count.min(10000) as u32);
            let result = feedback_repo.list(&filter, &pagination).await?;

            let stats = calculate_stats_from_feedback(&result.items);
            items.push(AccuracyBreakdownItem {
                dimension: format!("{:?}", verdict).to_lowercase(),
                stats: stats_to_response(stats),
            });
        }
    }

    Ok(Json(AccuracyByDimensionResponse { items }))
}

/// Get accuracy breakdown by feedback type.
#[utoipa::path(
    get,
    path = "/api/feedback/accuracy/by-type",
    params(
        ("since" = Option<String>, Query, description = "Filter by minimum created_at timestamp"),
        ("until" = Option<String>, Query, description = "Filter by maximum created_at timestamp")
    ),
    responses(
        (status = 200, description = "Accuracy by feedback type", body = AccuracyByDimensionResponse),
        (status = 500, description = "Internal server error")
    ),
    tag = "Feedback Analytics"
)]
async fn get_accuracy_by_type(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
    Query(query): Query<FeedbackStatsQuery>,
) -> Result<Json<AccuracyByDimensionResponse>, ApiError> {
    let tenant_id = tenant_id_or_default(tenant);
    let feedback_repo: Box<dyn FeedbackRepository> = create_feedback_repository(&state.db);

    // Get stats for each feedback type
    let feedback_types = [
        FeedbackType::Correct,
        FeedbackType::IncorrectVerdict,
        FeedbackType::IncorrectSeverity,
        FeedbackType::MissingContext,
        FeedbackType::IncorrectMitre,
        FeedbackType::Other,
    ];

    let mut items = Vec::new();

    for feedback_type in feedback_types {
        let filter = FeedbackFilter {
            tenant_id: Some(tenant_id),
            feedback_type: Some(feedback_type),
            since: query.since,
            until: query.until,
            ..Default::default()
        };

        let count = feedback_repo.count(&filter).await?;
        if count > 0 {
            let pagination = Pagination::new(1, count.min(10000) as u32);
            let result = feedback_repo.list(&filter, &pagination).await?;

            let stats = calculate_stats_from_feedback(&result.items);
            items.push(AccuracyBreakdownItem {
                dimension: feedback_type.as_db_str().to_string(),
                stats: stats_to_response(stats),
            });
        }
    }

    Ok(Json(AccuracyByDimensionResponse { items }))
}

/// Get accuracy trends over time.
#[utoipa::path(
    get,
    path = "/api/feedback/trends",
    params(
        ("granularity" = Option<String>, Query, description = "Granularity: day, week, or month"),
        ("since" = Option<String>, Query, description = "Filter by minimum created_at timestamp"),
        ("until" = Option<String>, Query, description = "Filter by maximum created_at timestamp")
    ),
    responses(
        (status = 200, description = "Accuracy trends", body = AccuracyTrendResponse),
        (status = 400, description = "Invalid query parameters"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Feedback Analytics"
)]
async fn get_accuracy_trends(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
    Query(query): Query<AccuracyTrendQuery>,
) -> Result<Json<AccuracyTrendResponse>, ApiError> {
    let tenant_id = tenant_id_or_default(tenant);
    let feedback_repo: Box<dyn FeedbackRepository> = create_feedback_repository(&state.db);

    let granularity = query.granularity.as_deref().unwrap_or("week");

    // Validate granularity
    if !["day", "week", "month"].contains(&granularity) {
        return Err(ApiError::BadRequest(format!(
            "Invalid granularity: {}. Must be day, week, or month",
            granularity
        )));
    }

    // Default time range: last 12 periods
    let now = Utc::now();
    let default_periods = 12;
    let (since, until) = match (query.since, query.until) {
        (Some(s), Some(u)) => (s, u),
        (Some(s), None) => (s, now),
        (None, Some(u)) => {
            let since = match granularity {
                "day" => u - Duration::days(default_periods),
                "week" => u - Duration::weeks(default_periods),
                "month" => u - Duration::days(default_periods * 30),
                _ => u - Duration::weeks(default_periods),
            };
            (since, u)
        }
        (None, None) => {
            let since = match granularity {
                "day" => now - Duration::days(default_periods),
                "week" => now - Duration::weeks(default_periods),
                "month" => now - Duration::days(default_periods * 30),
                _ => now - Duration::weeks(default_periods),
            };
            (since, now)
        }
    };

    // Get all feedback in the range
    let filter = FeedbackFilter {
        tenant_id: Some(tenant_id),
        since: Some(since),
        until: Some(until),
        ..Default::default()
    };

    let count = feedback_repo.count(&filter).await?;
    let pagination = Pagination::new(1, count.min(50000) as u32);
    let result = feedback_repo.list(&filter, &pagination).await?;

    // Group feedback by period
    let trends = group_feedback_by_period(&result.items, granularity);

    Ok(Json(AccuracyTrendResponse { trends }))
}

// ============================================================================
// Helper Functions
// ============================================================================

fn feedback_to_response(feedback: AnalystFeedback) -> FeedbackResponse {
    FeedbackResponse {
        id: feedback.id,
        incident_id: feedback.incident_id,
        analyst_id: feedback.analyst_id,
        original_verdict: format!("{:?}", feedback.original_verdict).to_lowercase(),
        corrected_verdict: feedback
            .corrected_verdict
            .map(|v| format!("{:?}", v).to_lowercase()),
        original_severity: format!("{:?}", feedback.original_severity).to_lowercase(),
        corrected_severity: feedback
            .corrected_severity
            .map(|s| format!("{:?}", s).to_lowercase()),
        original_confidence: feedback.original_confidence,
        feedback_type: feedback.feedback_type.as_db_str().to_string(),
        notes: feedback.notes,
        original_mitre_techniques: feedback.original_mitre_techniques,
        corrected_mitre_techniques: feedback.corrected_mitre_techniques,
        created_at: feedback.created_at,
        updated_at: feedback.updated_at,
    }
}

fn stats_to_response(stats: FeedbackStats) -> FeedbackStatsResponse {
    let calibration_metrics =
        stats
            .calibration_metrics
            .map(|c| FeedbackCalibrationMetricsResponse {
                mean_raw_confidence: c.mean_raw_confidence,
                mean_accuracy: c.mean_accuracy,
                expected_calibration_error: c.expected_calibration_error,
                brier_score: c.brier_score,
                overconfidence_rate: c.overconfidence_rate,
                underconfidence_rate: c.underconfidence_rate,
                sample_count: c.sample_count,
                quality: c.quality().to_string(),
            });

    FeedbackStatsResponse {
        total_feedback: stats.total_feedback,
        correct_count: stats.correct_count,
        incorrect_verdict_count: stats.incorrect_verdict_count,
        incorrect_severity_count: stats.incorrect_severity_count,
        missing_context_count: stats.missing_context_count,
        incorrect_mitre_count: stats.incorrect_mitre_count,
        other_count: stats.other_count,
        accuracy_rate: stats.accuracy_rate,
        verdict_accuracy_rate: stats.verdict_accuracy_rate,
        severity_accuracy_rate: stats.severity_accuracy_rate,
        calibration_metrics,
    }
}

fn calculate_stats_from_feedback(feedback_list: &[AnalystFeedback]) -> FeedbackStats {
    let mut stats = FeedbackStats {
        total_feedback: feedback_list.len() as u64,
        ..Default::default()
    };

    for feedback in feedback_list {
        match feedback.feedback_type {
            FeedbackType::Correct => stats.correct_count += 1,
            FeedbackType::IncorrectVerdict => stats.incorrect_verdict_count += 1,
            FeedbackType::IncorrectSeverity => stats.incorrect_severity_count += 1,
            FeedbackType::MissingContext => stats.missing_context_count += 1,
            FeedbackType::IncorrectMitre => stats.incorrect_mitre_count += 1,
            FeedbackType::Other => stats.other_count += 1,
        }
    }

    stats.calculate_accuracy();
    stats
}

fn group_feedback_by_period(
    feedback_list: &[AnalystFeedback],
    granularity: &str,
) -> Vec<TrendDataPoint> {
    use std::collections::BTreeMap;

    let mut periods: BTreeMap<String, Vec<&AnalystFeedback>> = BTreeMap::new();

    for feedback in feedback_list {
        let period_key = match granularity {
            "day" => feedback.created_at.format("%Y-%m-%d").to_string(),
            "week" => {
                let date = feedback.created_at.date_naive();
                let iso_week = date.iso_week();
                format!("{}-W{:02}", iso_week.year(), iso_week.week())
            }
            "month" => feedback.created_at.format("%Y-%m").to_string(),
            _ => feedback.created_at.format("%Y-%m-%d").to_string(),
        };

        periods.entry(period_key).or_default().push(feedback);
    }

    periods
        .into_iter()
        .map(|(period, items)| {
            let stats =
                calculate_stats_from_feedback(&items.into_iter().cloned().collect::<Vec<_>>());
            TrendDataPoint {
                period,
                accuracy_rate: stats.accuracy_rate,
                verdict_accuracy_rate: stats.verdict_accuracy_rate,
                count: stats.total_feedback,
            }
        })
        .collect()
}

fn parse_feedback_type(s: &str) -> Option<FeedbackType> {
    FeedbackType::from_db_str(s)
}

fn parse_verdict(s: &str) -> Result<TriageVerdict, String> {
    match s.to_lowercase().as_str() {
        "true_positive" | "truepositive" => Ok(TriageVerdict::TruePositive),
        "likely_true_positive" | "likelytruepositive" => Ok(TriageVerdict::LikelyTruePositive),
        "suspicious" => Ok(TriageVerdict::Suspicious),
        "likely_false_positive" | "likelyfalsepositive" => Ok(TriageVerdict::LikelyFalsePositive),
        "false_positive" | "falsepositive" => Ok(TriageVerdict::FalsePositive),
        "inconclusive" => Ok(TriageVerdict::Inconclusive),
        _ => Err(format!("Unknown verdict: {}", s)),
    }
}

fn parse_severity(s: &str) -> Result<Severity, String> {
    match s.to_lowercase().as_str() {
        "info" => Ok(Severity::Info),
        "low" => Ok(Severity::Low),
        "medium" => Ok(Severity::Medium),
        "high" => Ok(Severity::High),
        "critical" => Ok(Severity::Critical),
        _ => Err(format!("Unknown severity: {}", s)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============================================================================
    // Unit Tests for Helper Functions
    // ============================================================================

    #[test]
    fn test_parse_feedback_type() {
        assert_eq!(parse_feedback_type("correct"), Some(FeedbackType::Correct));
        assert_eq!(
            parse_feedback_type("incorrect_verdict"),
            Some(FeedbackType::IncorrectVerdict)
        );
        assert_eq!(
            parse_feedback_type("incorrect_severity"),
            Some(FeedbackType::IncorrectSeverity)
        );
        assert_eq!(
            parse_feedback_type("missing_context"),
            Some(FeedbackType::MissingContext)
        );
        assert_eq!(
            parse_feedback_type("incorrect_mitre"),
            Some(FeedbackType::IncorrectMitre)
        );
        assert_eq!(parse_feedback_type("other"), Some(FeedbackType::Other));
        assert_eq!(parse_feedback_type("unknown"), None);
    }

    #[test]
    fn test_parse_verdict() {
        assert_eq!(
            parse_verdict("true_positive").unwrap(),
            TriageVerdict::TruePositive
        );
        assert_eq!(
            parse_verdict("TruePositive").unwrap(),
            TriageVerdict::TruePositive
        );
        assert_eq!(
            parse_verdict("false_positive").unwrap(),
            TriageVerdict::FalsePositive
        );
        assert_eq!(
            parse_verdict("suspicious").unwrap(),
            TriageVerdict::Suspicious
        );
        assert!(parse_verdict("unknown").is_err());
    }

    #[test]
    fn test_parse_severity() {
        assert_eq!(parse_severity("info").unwrap(), Severity::Info);
        assert_eq!(parse_severity("low").unwrap(), Severity::Low);
        assert_eq!(parse_severity("medium").unwrap(), Severity::Medium);
        assert_eq!(parse_severity("high").unwrap(), Severity::High);
        assert_eq!(parse_severity("critical").unwrap(), Severity::Critical);
        assert!(parse_severity("unknown").is_err());
    }

    #[test]
    fn test_calculate_stats_from_feedback() {
        // Empty feedback list
        let empty: Vec<AnalystFeedback> = vec![];
        let stats = calculate_stats_from_feedback(&empty);
        assert_eq!(stats.total_feedback, 0);
        assert_eq!(stats.accuracy_rate, 0.0);
    }

    #[test]
    fn test_feedback_to_response() {
        let feedback = AnalystFeedback::correct(
            Uuid::new_v4(),
            DEFAULT_TENANT_ID,
            Uuid::new_v4(),
            TriageVerdict::TruePositive,
            Severity::High,
            0.85,
        );

        let response = feedback_to_response(feedback.clone());

        assert_eq!(response.id, feedback.id);
        assert_eq!(response.incident_id, feedback.incident_id);
        assert_eq!(response.original_verdict, "truepositive");
        assert_eq!(response.original_severity, "high");
        assert_eq!(response.feedback_type, "correct");
        assert!((response.original_confidence - 0.85).abs() < 0.001);
    }

    #[test]
    fn test_feedback_to_response_with_corrections() {
        let mut feedback = AnalystFeedback::with_corrected_verdict(
            Uuid::new_v4(),
            DEFAULT_TENANT_ID,
            Uuid::new_v4(),
            TriageVerdict::FalsePositive,
            TriageVerdict::TruePositive,
            Severity::Medium,
            0.75,
        );
        feedback.corrected_severity = Some(Severity::High);

        let response = feedback_to_response(feedback);

        assert_eq!(response.original_verdict, "falsepositive");
        assert_eq!(response.corrected_verdict, Some("truepositive".to_string()));
        assert_eq!(response.original_severity, "medium");
        assert_eq!(response.corrected_severity, Some("high".to_string()));
    }

    #[test]
    fn test_stats_to_response() {
        let mut stats = FeedbackStats {
            total_feedback: 100,
            correct_count: 80,
            incorrect_verdict_count: 10,
            incorrect_severity_count: 5,
            missing_context_count: 3,
            incorrect_mitre_count: 2,
            other_count: 0,
            ..Default::default()
        };
        stats.calculate_accuracy();

        let response = stats_to_response(stats);

        assert_eq!(response.total_feedback, 100);
        assert_eq!(response.correct_count, 80);
        assert!((response.accuracy_rate - 0.80).abs() < 0.001);
        assert!(response.calibration_metrics.is_none());
    }

    #[test]
    fn test_calculate_stats_from_feedback_with_data() {
        let mut feedback_list = Vec::new();

        // Add 5 correct feedback
        for _ in 0..5 {
            feedback_list.push(AnalystFeedback::correct(
                Uuid::new_v4(),
                DEFAULT_TENANT_ID,
                Uuid::new_v4(),
                TriageVerdict::TruePositive,
                Severity::High,
                0.9,
            ));
        }

        // Add 2 incorrect verdict feedback
        for _ in 0..2 {
            feedback_list.push(AnalystFeedback::with_corrected_verdict(
                Uuid::new_v4(),
                DEFAULT_TENANT_ID,
                Uuid::new_v4(),
                TriageVerdict::FalsePositive,
                TriageVerdict::TruePositive,
                Severity::Medium,
                0.7,
            ));
        }

        // Add 1 incorrect severity feedback
        feedback_list.push(AnalystFeedback::with_corrected_severity(
            Uuid::new_v4(),
            DEFAULT_TENANT_ID,
            Uuid::new_v4(),
            TriageVerdict::TruePositive,
            Severity::Low,
            Severity::High,
            0.8,
        ));

        let stats = calculate_stats_from_feedback(&feedback_list);

        assert_eq!(stats.total_feedback, 8);
        assert_eq!(stats.correct_count, 5);
        assert_eq!(stats.incorrect_verdict_count, 2);
        assert_eq!(stats.incorrect_severity_count, 1);
        assert!((stats.accuracy_rate - 0.625).abs() < 0.001); // 5/8 = 0.625
    }

    #[test]
    fn test_group_feedback_by_period_empty() {
        let empty: Vec<AnalystFeedback> = vec![];
        let trends = group_feedback_by_period(&empty, "week");
        assert!(trends.is_empty());
    }
}
