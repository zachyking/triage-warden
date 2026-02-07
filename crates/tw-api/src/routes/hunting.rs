//! Threat Hunting API endpoints (Stage 5.1).
//!
//! Provides REST endpoints for managing threat hunts, executing hunts,
//! viewing findings, and accessing the built-in query library.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::RequireAnalyst;
use crate::error::ApiError;
use crate::middleware::OptionalTenant;
use crate::state::AppState;
use tw_core::db::{create_incident_repository, create_settings_repository, IncidentRepository};
use tw_core::hunting::{
    Finding, HuntExecutor, HuntResult, HuntSchedule, HuntStatus, HuntType, HuntingHunt,
    HuntingQuery, QueryType,
};
use tw_core::incident::{Alert, AlertSource, Incident, Severity};

const HUNTS_SETTINGS_KEY: &str = "hunting_hunts_v1";
const HUNT_RESULTS_SETTINGS_KEY: &str = "hunting_results_v1";

// ============================================================================
// DTOs
// ============================================================================

/// Request to create a new hunt.
#[derive(Debug, Deserialize)]
pub struct CreateHuntRequest {
    pub name: String,
    pub description: Option<String>,
    pub hypothesis: String,
    pub hunt_type: Option<String>,
    pub queries: Option<Vec<HuntingQueryDto>>,
    pub schedule: Option<HuntScheduleDto>,
    pub mitre_techniques: Option<Vec<String>>,
    pub data_sources: Option<Vec<String>>,
    pub tags: Option<Vec<String>>,
    pub enabled: Option<bool>,
}

/// Request to update an existing hunt.
#[derive(Debug, Deserialize)]
pub struct UpdateHuntRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub hypothesis: Option<String>,
    pub hunt_type: Option<String>,
    pub queries: Option<Vec<HuntingQueryDto>>,
    pub schedule: Option<HuntScheduleDto>,
    pub mitre_techniques: Option<Vec<String>>,
    pub data_sources: Option<Vec<String>>,
    pub tags: Option<Vec<String>>,
    pub enabled: Option<bool>,
    pub status: Option<String>,
}

/// DTO for hunt queries in requests.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HuntingQueryDto {
    pub id: Option<String>,
    pub query_type: String,
    pub query: String,
    pub description: Option<String>,
    pub timeout_secs: Option<u64>,
    pub expected_baseline: Option<u64>,
}

/// DTO for hunt schedule.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HuntScheduleDto {
    pub cron_expression: String,
    pub timezone: Option<String>,
    pub max_runtime_secs: Option<u64>,
}

/// Hunt response DTO.
#[derive(Debug, Serialize)]
pub struct HuntResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub description: String,
    pub hypothesis: String,
    pub hunt_type: String,
    pub queries: Vec<HuntingQueryDto>,
    pub schedule: Option<HuntScheduleDto>,
    pub mitre_techniques: Vec<String>,
    pub data_sources: Vec<String>,
    pub status: String,
    pub created_by: String,
    pub created_at: String,
    pub updated_at: String,
    pub last_run: Option<String>,
    pub last_result: Option<HuntResultSummaryDto>,
    pub tags: Vec<String>,
    pub enabled: bool,
}

/// Result summary DTO.
#[derive(Debug, Serialize)]
pub struct HuntResultSummaryDto {
    pub total_findings: usize,
    pub critical_findings: usize,
    pub executed_at: String,
    pub duration_secs: f64,
}

/// Hunt execution result DTO.
#[derive(Debug, Serialize)]
pub struct HuntResultResponse {
    pub hunt_id: Uuid,
    pub findings: Vec<FindingResponse>,
    pub queries_executed: usize,
    pub queries_failed: usize,
    pub started_at: String,
    pub completed_at: String,
    pub status: String,
    pub duration_secs: f64,
}

/// Finding response DTO.
#[derive(Debug, Serialize)]
pub struct FindingResponse {
    pub id: Uuid,
    pub hunt_id: Uuid,
    pub finding_type: serde_json::Value,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub evidence: serde_json::Value,
    pub query_id: String,
    pub detected_at: String,
    pub promoted_to_incident: Option<Uuid>,
}

/// Built-in query response DTO.
#[derive(Debug, Serialize)]
pub struct BuiltInQueryResponse {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: String,
    pub mitre_techniques: Vec<String>,
    pub query_templates: serde_json::Value,
    pub default_baseline: Option<u64>,
    pub data_sources: Vec<String>,
    pub parameters: Vec<QueryParameterResponse>,
}

/// Query parameter response DTO.
#[derive(Debug, Serialize)]
pub struct QueryParameterResponse {
    pub name: String,
    pub description: String,
    pub param_type: String,
    pub default_value: Option<String>,
    pub required: bool,
}

/// Query parameters for listing hunts.
#[derive(Debug, Deserialize)]
pub struct ListHuntsQuery {
    pub status: Option<String>,
    pub hunt_type: Option<String>,
    pub category: Option<String>,
    pub tag: Option<String>,
    pub page: Option<u32>,
    pub page_size: Option<u32>,
}

// ============================================================================
// Conversion helpers
// ============================================================================

fn hunt_to_response(hunt: &HuntingHunt) -> HuntResponse {
    HuntResponse {
        id: hunt.id,
        tenant_id: hunt.tenant_id,
        name: hunt.name.clone(),
        description: hunt.description.clone(),
        hypothesis: hunt.hypothesis.clone(),
        hunt_type: serde_json::to_value(&hunt.hunt_type)
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_else(|| "on_demand".to_string()),
        queries: hunt
            .queries
            .iter()
            .map(|q| HuntingQueryDto {
                id: Some(q.id.clone()),
                query_type: serde_json::to_value(&q.query_type)
                    .ok()
                    .and_then(|v| v.as_str().map(|s| s.to_string()))
                    .unwrap_or_else(|| "custom".to_string()),
                query: q.query.clone(),
                description: Some(q.description.clone()),
                timeout_secs: Some(q.timeout_secs),
                expected_baseline: q.expected_baseline,
            })
            .collect(),
        schedule: hunt.schedule.as_ref().map(|s| HuntScheduleDto {
            cron_expression: s.cron_expression.clone(),
            timezone: Some(s.timezone.clone()),
            max_runtime_secs: Some(s.max_runtime_secs),
        }),
        mitre_techniques: hunt.mitre_techniques.clone(),
        data_sources: hunt.data_sources.clone(),
        status: serde_json::to_value(&hunt.status)
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_else(|| "draft".to_string()),
        created_by: hunt.created_by.clone(),
        created_at: hunt.created_at.to_rfc3339(),
        updated_at: hunt.updated_at.to_rfc3339(),
        last_run: hunt.last_run.map(|t| t.to_rfc3339()),
        last_result: hunt.last_result.as_ref().map(|r| HuntResultSummaryDto {
            total_findings: r.total_findings,
            critical_findings: r.critical_findings,
            executed_at: r.executed_at.to_rfc3339(),
            duration_secs: r.duration_secs,
        }),
        tags: hunt.tags.clone(),
        enabled: hunt.enabled,
    }
}

pub(crate) fn parse_hunt_type(s: &str) -> HuntType {
    match s {
        "scheduled" => HuntType::Scheduled,
        "continuous" => HuntType::Continuous,
        "triggered" => HuntType::Triggered,
        _ => HuntType::OnDemand,
    }
}

fn parse_hunt_status(s: &str) -> HuntStatus {
    match s {
        "active" => HuntStatus::Active,
        "paused" => HuntStatus::Paused,
        "completed" => HuntStatus::Completed,
        "failed" => HuntStatus::Failed,
        "archived" => HuntStatus::Archived,
        _ => HuntStatus::Draft,
    }
}

fn parse_query_type(s: &str) -> QueryType {
    match s {
        "splunk" => QueryType::Splunk,
        "elasticsearch" => QueryType::Elasticsearch,
        "sql" => QueryType::Sql,
        "kusto" => QueryType::Kusto,
        other => QueryType::Custom(other.to_string()),
    }
}

fn dto_to_query(dto: &HuntingQueryDto) -> HuntingQuery {
    HuntingQuery {
        id: dto.id.clone().unwrap_or_else(|| Uuid::new_v4().to_string()),
        query_type: parse_query_type(&dto.query_type),
        query: dto.query.clone(),
        description: dto.description.clone().unwrap_or_default(),
        timeout_secs: dto.timeout_secs.unwrap_or(300),
        expected_baseline: dto.expected_baseline,
    }
}

fn finding_to_response(f: &Finding) -> FindingResponse {
    FindingResponse {
        id: f.id,
        hunt_id: f.hunt_id,
        finding_type: serde_json::to_value(&f.finding_type).unwrap_or_default(),
        severity: format!("{}", f.severity),
        title: f.title.clone(),
        description: f.description.clone(),
        evidence: f.evidence.clone(),
        query_id: f.query_id.clone(),
        detected_at: f.detected_at.to_rfc3339(),
        promoted_to_incident: f.promoted_to_incident,
    }
}

fn result_to_response(r: &HuntResult) -> HuntResultResponse {
    HuntResultResponse {
        hunt_id: r.hunt_id,
        findings: r.findings.iter().map(finding_to_response).collect(),
        queries_executed: r.queries_executed,
        queries_failed: r.queries_failed,
        started_at: r.started_at.to_rfc3339(),
        completed_at: r.completed_at.to_rfc3339(),
        status: serde_json::to_value(&r.status)
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_else(|| "unknown".to_string()),
        duration_secs: r.duration_secs(),
    }
}

fn tenant_id_or_default(tenant: Option<tw_core::tenant::TenantContext>) -> Uuid {
    tenant
        .map(|ctx| ctx.tenant_id)
        .unwrap_or(tw_core::auth::DEFAULT_TENANT_ID)
}

async fn load_hunts(state: &AppState, tenant_id: Uuid) -> Result<Vec<HuntingHunt>, ApiError> {
    let repo = create_settings_repository(&state.db, state.encryptor.clone());
    let raw = repo
        .get_raw(tenant_id, HUNTS_SETTINGS_KEY)
        .await
        .map_err(ApiError::from)?;

    match raw {
        Some(raw) => serde_json::from_str(&raw)
            .map_err(|e| ApiError::Internal(format!("Failed to parse stored hunts: {}", e))),
        None => Ok(vec![]),
    }
}

async fn save_hunts(
    state: &AppState,
    tenant_id: Uuid,
    hunts: &[HuntingHunt],
) -> Result<(), ApiError> {
    let repo = create_settings_repository(&state.db, state.encryptor.clone());
    let serialized = serde_json::to_string(hunts)
        .map_err(|e| ApiError::Internal(format!("Failed to serialize hunts: {}", e)))?;
    repo.save_raw(tenant_id, HUNTS_SETTINGS_KEY, &serialized)
        .await
        .map_err(ApiError::from)
}

async fn load_hunt_results(state: &AppState, tenant_id: Uuid) -> Result<Vec<HuntResult>, ApiError> {
    let repo = create_settings_repository(&state.db, state.encryptor.clone());
    let raw = repo
        .get_raw(tenant_id, HUNT_RESULTS_SETTINGS_KEY)
        .await
        .map_err(ApiError::from)?;

    match raw {
        Some(raw) => serde_json::from_str(&raw)
            .map_err(|e| ApiError::Internal(format!("Failed to parse stored hunt results: {}", e))),
        None => Ok(vec![]),
    }
}

async fn save_hunt_results(
    state: &AppState,
    tenant_id: Uuid,
    results: &[HuntResult],
) -> Result<(), ApiError> {
    let repo = create_settings_repository(&state.db, state.encryptor.clone());
    let serialized = serde_json::to_string(results)
        .map_err(|e| ApiError::Internal(format!("Failed to serialize hunt results: {}", e)))?;
    repo.save_raw(tenant_id, HUNT_RESULTS_SETTINGS_KEY, &serialized)
        .await
        .map_err(ApiError::from)
}

fn parse_finding_severity_to_incident(severity: &str) -> Severity {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

// ============================================================================
// Route handler functions
// ============================================================================

/// GET /api/v1/hunts - List all hunts
async fn list_hunts(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
    Query(params): Query<ListHuntsQuery>,
) -> Result<Json<Vec<HuntResponse>>, ApiError> {
    let tenant_id = tenant_id_or_default(tenant);
    let mut hunts = load_hunts(&state, tenant_id).await?;

    if let Some(status) = &params.status {
        let wanted = parse_hunt_status(status);
        hunts.retain(|h| h.status == wanted);
    }
    if let Some(hunt_type) = &params.hunt_type {
        let wanted = parse_hunt_type(hunt_type);
        hunts.retain(|h| h.hunt_type == wanted);
    }
    if let Some(tag) = &params.tag {
        let tag = tag.to_ascii_lowercase();
        hunts.retain(|h| h.tags.iter().any(|t| t.to_ascii_lowercase() == tag));
    }

    hunts.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));

    let page = params.page.unwrap_or(1).max(1);
    let page_size = params.page_size.unwrap_or(50).clamp(1, 200);
    let start = ((page - 1) as usize) * (page_size as usize);

    let response = hunts
        .into_iter()
        .skip(start)
        .take(page_size as usize)
        .map(|h| hunt_to_response(&h))
        .collect::<Vec<_>>();

    Ok(Json(response))
}

/// POST /api/v1/hunts - Create a new hunt
async fn create_hunt(
    State(state): State<AppState>,
    RequireAnalyst(user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
    Json(request): Json<CreateHuntRequest>,
) -> Result<(StatusCode, Json<HuntResponse>), ApiError> {
    let tenant_id = tenant_id_or_default(tenant);

    if request.name.trim().is_empty() {
        return Err(ApiError::BadRequest("Hunt name is required".to_string()));
    }
    if request.hypothesis.trim().is_empty() {
        return Err(ApiError::BadRequest(
            "Hunt hypothesis is required".to_string(),
        ));
    }

    let mut hunt = HuntingHunt::new(&request.name, &request.hypothesis);

    if let Some(desc) = &request.description {
        hunt = hunt.with_description(desc);
    }
    if let Some(ht) = &request.hunt_type {
        hunt = hunt.with_hunt_type(parse_hunt_type(ht));
    }
    if let Some(queries) = &request.queries {
        for q in queries {
            hunt = hunt.with_query(dto_to_query(q));
        }
    }
    if let Some(schedule) = &request.schedule {
        hunt = hunt.with_schedule(HuntSchedule {
            cron_expression: schedule.cron_expression.clone(),
            timezone: schedule
                .timezone
                .clone()
                .unwrap_or_else(|| "UTC".to_string()),
            max_runtime_secs: schedule.max_runtime_secs.unwrap_or(3600),
        });
    }
    if let Some(techniques) = &request.mitre_techniques {
        for t in techniques {
            hunt = hunt.with_mitre_technique(t);
        }
    }
    if let Some(sources) = &request.data_sources {
        for s in sources {
            hunt = hunt.with_data_source(s);
        }
    }
    if let Some(tags) = &request.tags {
        for t in tags {
            hunt = hunt.with_tag(t);
        }
    }
    if let Some(enabled) = request.enabled {
        hunt = hunt.with_enabled(enabled);
    }
    hunt = hunt
        .with_tenant(tenant_id)
        .with_created_by(user.username.clone());
    if hunt.enabled && hunt.status == HuntStatus::Draft {
        hunt.status = HuntStatus::Active;
    }

    let mut hunts = load_hunts(&state, tenant_id).await?;
    hunts.push(hunt.clone());
    save_hunts(&state, tenant_id, &hunts).await?;

    Ok((StatusCode::CREATED, Json(hunt_to_response(&hunt))))
}

/// GET /api/v1/hunts/:id - Get hunt details
async fn get_hunt(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
    Path(id): Path<Uuid>,
) -> Result<Json<HuntResponse>, ApiError> {
    let tenant_id = tenant_id_or_default(tenant);
    let hunts = load_hunts(&state, tenant_id).await?;
    let hunt = hunts
        .into_iter()
        .find(|h| h.id == id)
        .ok_or_else(|| ApiError::NotFound(format!("Hunt {} not found", id)))?;
    Ok(Json(hunt_to_response(&hunt)))
}

/// PUT /api/v1/hunts/:id - Update a hunt
async fn update_hunt(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateHuntRequest>,
) -> Result<Json<HuntResponse>, ApiError> {
    let tenant_id = tenant_id_or_default(tenant);
    // Validate status field if provided
    if let Some(ref status) = request.status {
        let _ = parse_hunt_status(status);
    }
    // Validate hunt_type field if provided
    if let Some(ref ht) = request.hunt_type {
        let _ = parse_hunt_type(ht);
    }

    let mut hunts = load_hunts(&state, tenant_id).await?;
    let hunt = hunts
        .iter_mut()
        .find(|h| h.id == id)
        .ok_or_else(|| ApiError::NotFound(format!("Hunt {} not found", id)))?;

    if let Some(name) = request.name {
        if name.trim().is_empty() {
            return Err(ApiError::BadRequest(
                "Hunt name cannot be empty".to_string(),
            ));
        }
        hunt.name = name;
    }
    if let Some(description) = request.description {
        hunt.description = description;
    }
    if let Some(hypothesis) = request.hypothesis {
        if hypothesis.trim().is_empty() {
            return Err(ApiError::BadRequest(
                "Hunt hypothesis cannot be empty".to_string(),
            ));
        }
        hunt.hypothesis = hypothesis;
    }
    if let Some(hunt_type) = request.hunt_type {
        hunt.hunt_type = parse_hunt_type(&hunt_type);
    }
    if let Some(queries) = request.queries {
        hunt.queries = queries.iter().map(dto_to_query).collect();
    }
    if let Some(schedule) = request.schedule {
        hunt.schedule = Some(HuntSchedule {
            cron_expression: schedule.cron_expression,
            timezone: schedule.timezone.unwrap_or_else(|| "UTC".to_string()),
            max_runtime_secs: schedule.max_runtime_secs.unwrap_or(3600),
        });
    }
    if let Some(mitre_techniques) = request.mitre_techniques {
        hunt.mitre_techniques = mitre_techniques;
    }
    if let Some(data_sources) = request.data_sources {
        hunt.data_sources = data_sources;
    }
    if let Some(tags) = request.tags {
        hunt.tags = tags;
    }
    if let Some(enabled) = request.enabled {
        hunt.enabled = enabled;
    }
    if let Some(status) = request.status {
        hunt.status = parse_hunt_status(&status);
    }

    hunt.updated_at = Utc::now();

    let response = hunt_to_response(hunt);
    save_hunts(&state, tenant_id, &hunts).await?;
    Ok(Json(response))
}

/// DELETE /api/v1/hunts/:id - Delete a hunt
async fn delete_hunt(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let tenant_id = tenant_id_or_default(tenant);
    let mut hunts = load_hunts(&state, tenant_id).await?;
    let len_before = hunts.len();
    hunts.retain(|h| h.id != id);
    if hunts.len() == len_before {
        return Err(ApiError::NotFound(format!("Hunt {} not found", id)));
    }

    let mut results = load_hunt_results(&state, tenant_id).await?;
    results.retain(|r| r.hunt_id != id);

    save_hunts(&state, tenant_id, &hunts).await?;
    save_hunt_results(&state, tenant_id, &results).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// POST /api/v1/hunts/:id/execute - Trigger hunt execution
async fn execute_hunt(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
    Path(id): Path<Uuid>,
) -> Result<Json<HuntResultResponse>, ApiError> {
    let tenant_id = tenant_id_or_default(tenant);
    let mut hunts = load_hunts(&state, tenant_id).await?;
    let hunt = hunts
        .iter_mut()
        .find(|h| h.id == id)
        .ok_or_else(|| ApiError::NotFound(format!("Hunt {} not found", id)))?;

    let executor = HuntExecutor::new();
    let result = executor.execute(hunt).await;

    hunt.last_run = Some(result.completed_at);
    hunt.last_result = Some(tw_core::hunting::HuntResultSummary {
        total_findings: result.total_findings(),
        critical_findings: result.critical_findings(),
        executed_at: result.completed_at,
        duration_secs: result.duration_secs(),
    });
    hunt.status = match result.status {
        tw_core::hunting::ExecutionStatus::Failed => HuntStatus::Failed,
        _ => HuntStatus::Completed,
    };
    hunt.updated_at = Utc::now();

    let mut results = load_hunt_results(&state, tenant_id).await?;
    results.push(result.clone());

    save_hunts(&state, tenant_id, &hunts).await?;
    save_hunt_results(&state, tenant_id, &results).await?;

    Ok(Json(result_to_response(&result)))
}

/// GET /api/v1/hunts/:id/results - Get hunt results/findings
async fn get_hunt_results(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<HuntResultResponse>>, ApiError> {
    let tenant_id = tenant_id_or_default(tenant);
    let hunts = load_hunts(&state, tenant_id).await?;
    if !hunts.iter().any(|h| h.id == id) {
        return Err(ApiError::NotFound(format!("Hunt {} not found", id)));
    }

    let mut results = load_hunt_results(&state, tenant_id).await?;
    results.retain(|r| r.hunt_id == id);
    results.sort_by(|a, b| b.completed_at.cmp(&a.completed_at));

    Ok(Json(
        results.iter().map(result_to_response).collect::<Vec<_>>(),
    ))
}

/// GET /api/v1/hunts/queries/library - List built-in queries
async fn get_query_library(
    State(_state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
) -> Result<Json<Vec<BuiltInQueryResponse>>, ApiError> {
    let queries = tw_core::hunting::get_built_in_queries();
    let responses: Vec<BuiltInQueryResponse> = queries
        .into_iter()
        .map(|q| BuiltInQueryResponse {
            id: q.id,
            name: q.name,
            description: q.description,
            category: format!("{}", q.category),
            mitre_techniques: q.mitre_techniques,
            query_templates: serde_json::to_value(&q.query_templates).unwrap_or_default(),
            default_baseline: q.default_baseline,
            data_sources: q.data_sources,
            parameters: q
                .parameters
                .into_iter()
                .map(|p| QueryParameterResponse {
                    name: p.name,
                    description: p.description,
                    param_type: serde_json::to_value(&p.param_type)
                        .ok()
                        .and_then(|v| v.as_str().map(|s| s.to_string()))
                        .unwrap_or_else(|| "string".to_string()),
                    default_value: p.default_value,
                    required: p.required,
                })
                .collect(),
        })
        .collect();

    Ok(Json(responses))
}

/// POST /api/v1/hunts/:id/findings/:finding_id/promote - Promote finding to incident
async fn promote_finding(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
    Path((hunt_id, finding_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tenant_id = tenant_id_or_default(tenant);
    let mut results = load_hunt_results(&state, tenant_id).await?;

    let mut found_finding: Option<Finding> = None;
    for result in &mut results {
        if result.hunt_id != hunt_id {
            continue;
        }
        if let Some(finding) = result.findings.iter_mut().find(|f| f.id == finding_id) {
            if finding.promoted_to_incident.is_some() {
                return Err(ApiError::Conflict(format!(
                    "Finding {} is already promoted to incident",
                    finding_id
                )));
            }
            found_finding = Some(finding.clone());
            break;
        }
    }

    let finding = found_finding.ok_or_else(|| {
        ApiError::NotFound(format!(
            "Finding {} in hunt {} not found",
            finding_id, hunt_id
        ))
    })?;

    let alert = Alert {
        id: finding.id.to_string(),
        source: AlertSource::Custom("hunting".to_string()),
        alert_type: "hunt_finding".to_string(),
        severity: parse_finding_severity_to_incident(&finding.severity.to_string()),
        title: finding.title.clone(),
        description: Some(finding.description.clone()),
        data: serde_json::json!({
            "hunt_id": hunt_id,
            "finding_id": finding.id,
            "finding_type": finding.finding_type,
            "query_id": finding.query_id,
            "evidence": finding.evidence,
        }),
        timestamp: finding.detected_at,
        tags: vec!["hunting".to_string(), format!("hunt:{}", hunt_id)],
    };

    let incident = Incident::from_alert_with_tenant(alert, tenant_id);
    let incident_repo: Box<dyn IncidentRepository> = create_incident_repository(&state.db);
    let created = incident_repo.create(&incident).await?;

    for result in &mut results {
        if result.hunt_id != hunt_id {
            continue;
        }
        if let Some(finding) = result.findings.iter_mut().find(|f| f.id == finding_id) {
            finding.promoted_to_incident = Some(created.id);
            break;
        }
    }

    save_hunt_results(&state, tenant_id, &results).await?;

    Ok(Json(serde_json::json!({
        "finding_id": finding_id,
        "incident_id": created.id,
        "message": "Finding promoted to incident successfully"
    })))
}

// ============================================================================
// Router
// ============================================================================

/// Creates the hunting API routes.
pub fn routes() -> Router<AppState> {
    Router::new()
        // Built-in query library (more specific route first)
        .route("/queries/library", get(get_query_library))
        // CRUD
        .route("/", get(list_hunts).post(create_hunt))
        .route("/:id", get(get_hunt).put(update_hunt).delete(delete_hunt))
        // Execution
        .route("/:id/execute", post(execute_hunt))
        .route("/:id/results", get(get_hunt_results))
        // Finding promotion
        .route("/:id/findings/:finding_id/promote", post(promote_finding))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use tw_core::hunting::{ExecutionStatus, FindingSeverity, FindingType, HuntResultSummary};

    #[test]
    fn test_hunt_to_response_basic() {
        let hunt = HuntingHunt::new("Test Hunt", "Test hypothesis")
            .with_description("A test hunt")
            .with_tag("test")
            .with_mitre_technique("T1558.003");

        let response = hunt_to_response(&hunt);
        assert_eq!(response.name, "Test Hunt");
        assert_eq!(response.hypothesis, "Test hypothesis");
        assert_eq!(response.description, "A test hunt");
        assert_eq!(response.tags, vec!["test"]);
        assert_eq!(response.mitre_techniques, vec!["T1558.003"]);
        assert_eq!(response.status, "draft");
        assert_eq!(response.hunt_type, "on_demand");
        assert!(!response.enabled);
    }

    #[test]
    fn test_hunt_to_response_with_schedule() {
        let hunt = HuntingHunt::new("Scheduled Hunt", "Hypothesis").with_schedule(HuntSchedule {
            cron_expression: "0 */6 * * *".to_string(),
            timezone: "UTC".to_string(),
            max_runtime_secs: 1800,
        });

        let response = hunt_to_response(&hunt);
        assert!(response.schedule.is_some());
        let schedule = response.schedule.unwrap();
        assert_eq!(schedule.cron_expression, "0 */6 * * *");
        assert_eq!(schedule.timezone, Some("UTC".to_string()));
    }

    #[test]
    fn test_hunt_to_response_with_queries() {
        let hunt = HuntingHunt::new("Query Hunt", "Hypothesis").with_query(HuntingQuery {
            id: "q1".to_string(),
            query_type: QueryType::Splunk,
            query: "index=main".to_string(),
            description: "Test query".to_string(),
            timeout_secs: 120,
            expected_baseline: Some(10),
        });

        let response = hunt_to_response(&hunt);
        assert_eq!(response.queries.len(), 1);
        assert_eq!(response.queries[0].query, "index=main");
        assert_eq!(response.queries[0].query_type, "splunk");
    }

    #[test]
    fn test_hunt_to_response_with_result() {
        let mut hunt = HuntingHunt::new("Result Hunt", "Hypothesis");
        hunt.last_result = Some(HuntResultSummary {
            total_findings: 5,
            critical_findings: 2,
            executed_at: Utc::now(),
            duration_secs: 30.5,
        });

        let response = hunt_to_response(&hunt);
        assert!(response.last_result.is_some());
        let result = response.last_result.unwrap();
        assert_eq!(result.total_findings, 5);
        assert_eq!(result.critical_findings, 2);
    }

    #[test]
    fn test_parse_hunt_type_variants() {
        assert_eq!(parse_hunt_type("scheduled"), HuntType::Scheduled);
        assert_eq!(parse_hunt_type("continuous"), HuntType::Continuous);
        assert_eq!(parse_hunt_type("triggered"), HuntType::Triggered);
        assert_eq!(parse_hunt_type("on_demand"), HuntType::OnDemand);
        assert_eq!(parse_hunt_type("unknown"), HuntType::OnDemand);
    }

    #[test]
    fn test_parse_hunt_status_variants() {
        assert_eq!(parse_hunt_status("active"), HuntStatus::Active);
        assert_eq!(parse_hunt_status("paused"), HuntStatus::Paused);
        assert_eq!(parse_hunt_status("completed"), HuntStatus::Completed);
        assert_eq!(parse_hunt_status("failed"), HuntStatus::Failed);
        assert_eq!(parse_hunt_status("archived"), HuntStatus::Archived);
        assert_eq!(parse_hunt_status("draft"), HuntStatus::Draft);
        assert_eq!(parse_hunt_status("unknown"), HuntStatus::Draft);
    }

    #[test]
    fn test_parse_query_type_variants() {
        assert_eq!(parse_query_type("splunk"), QueryType::Splunk);
        assert_eq!(parse_query_type("elasticsearch"), QueryType::Elasticsearch);
        assert_eq!(parse_query_type("sql"), QueryType::Sql);
        assert_eq!(parse_query_type("kusto"), QueryType::Kusto);
        assert_eq!(
            parse_query_type("sigma"),
            QueryType::Custom("sigma".to_string())
        );
    }

    #[test]
    fn test_dto_to_query() {
        let dto = HuntingQueryDto {
            id: Some("q-test".to_string()),
            query_type: "splunk".to_string(),
            query: "index=main | stats count".to_string(),
            description: Some("Count events".to_string()),
            timeout_secs: Some(180),
            expected_baseline: Some(50),
        };

        let query = dto_to_query(&dto);
        assert_eq!(query.id, "q-test");
        assert_eq!(query.query_type, QueryType::Splunk);
        assert_eq!(query.timeout_secs, 180);
        assert_eq!(query.expected_baseline, Some(50));
    }

    #[test]
    fn test_dto_to_query_defaults() {
        let dto = HuntingQueryDto {
            id: None,
            query_type: "elasticsearch".to_string(),
            query: "event.code: 4625".to_string(),
            description: None,
            timeout_secs: None,
            expected_baseline: None,
        };

        let query = dto_to_query(&dto);
        assert!(!query.id.is_empty()); // UUID generated
        assert_eq!(query.timeout_secs, 300); // Default
        assert_eq!(query.description, ""); // Default
    }

    #[test]
    fn test_finding_to_response() {
        let finding = Finding::new(
            Uuid::new_v4(),
            FindingType::PatternMatch {
                pattern: "mimikatz".to_string(),
            },
            FindingSeverity::Critical,
            "Mimikatz detected",
            "Credential dumping tool detected",
            "q1",
        );

        let response = finding_to_response(&finding);
        assert_eq!(response.title, "Mimikatz detected");
        assert_eq!(response.severity, "Critical");
        assert_eq!(response.query_id, "q1");
    }

    #[test]
    fn test_result_to_response() {
        let result = HuntResult {
            hunt_id: Uuid::new_v4(),
            findings: vec![],
            queries_executed: 3,
            queries_failed: 1,
            started_at: Utc::now(),
            completed_at: Utc::now(),
            status: ExecutionStatus::PartialFailure,
        };

        let response = result_to_response(&result);
        assert_eq!(response.queries_executed, 3);
        assert_eq!(response.queries_failed, 1);
        assert_eq!(response.status, "partial_failure");
    }
}
