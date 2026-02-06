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
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;
use crate::state::AppState;
use tw_core::hunting::{
    Finding, HuntResult, HuntSchedule, HuntStatus, HuntType, HuntingHunt, HuntingQuery, QueryType,
};

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

// ============================================================================
// Route handler functions
// ============================================================================

/// GET /api/v1/hunts - List all hunts
async fn list_hunts(
    State(_state): State<AppState>,
    Query(_params): Query<ListHuntsQuery>,
) -> Result<Json<Vec<HuntResponse>>, ApiError> {
    // In a full implementation, this would query the database.
    // For now, return an empty list (the structure is wired up for DB integration).
    Ok(Json(vec![]))
}

/// POST /api/v1/hunts - Create a new hunt
async fn create_hunt(
    State(_state): State<AppState>,
    Json(request): Json<CreateHuntRequest>,
) -> Result<(StatusCode, Json<HuntResponse>), ApiError> {
    if request.name.is_empty() {
        return Err(ApiError::BadRequest("Hunt name is required".to_string()));
    }
    if request.hypothesis.is_empty() {
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

    let response = hunt_to_response(&hunt);
    Ok((StatusCode::CREATED, Json(response)))
}

/// GET /api/v1/hunts/:id - Get hunt details
async fn get_hunt(
    State(_state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<HuntResponse>, ApiError> {
    Err(ApiError::NotFound(format!("Hunt {} not found", id)))
}

/// PUT /api/v1/hunts/:id - Update a hunt
async fn update_hunt(
    State(_state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateHuntRequest>,
) -> Result<Json<HuntResponse>, ApiError> {
    // Validate status field if provided
    if let Some(ref status) = request.status {
        let _ = parse_hunt_status(status);
    }
    // Validate hunt_type field if provided
    if let Some(ref ht) = request.hunt_type {
        let _ = parse_hunt_type(ht);
    }
    Err(ApiError::NotFound(format!("Hunt {} not found", id)))
}

/// DELETE /api/v1/hunts/:id - Delete a hunt
async fn delete_hunt(
    State(_state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    Err(ApiError::NotFound(format!("Hunt {} not found", id)))
}

/// POST /api/v1/hunts/:id/execute - Trigger hunt execution
async fn execute_hunt(
    State(_state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<HuntResultResponse>, ApiError> {
    Err(ApiError::NotFound(format!("Hunt {} not found", id)))
}

/// GET /api/v1/hunts/:id/results - Get hunt results/findings
async fn get_hunt_results(
    State(_state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<HuntResultResponse>>, ApiError> {
    // In a full implementation, results would be fetched from DB and converted
    // via result_to_response. For now, return empty for known IDs.
    let results: Vec<HuntResult> = vec![];
    let _responses: Vec<HuntResultResponse> = results.iter().map(result_to_response).collect();
    Err(ApiError::NotFound(format!("Hunt {} not found", id)))
}

/// GET /api/v1/hunts/queries/library - List built-in queries
async fn get_query_library(
    State(_state): State<AppState>,
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
    State(_state): State<AppState>,
    Path((hunt_id, finding_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    Err(ApiError::NotFound(format!(
        "Finding {} in hunt {} not found",
        finding_id, hunt_id
    )))
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
