//! Privacy and data-security endpoints.

use crate::auth::{RequireAdmin, RequireAnalyst};
use crate::error::ApiError;
use crate::middleware::OptionalTenant;
use crate::state::AppState;
use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tw_core::auth::DEFAULT_TENANT_ID;
use tw_core::db::{
    create_audit_repository, create_settings_repository, AuditRepository, DbPool,
    SettingsRepository,
};
use tw_core::privacy::{
    DataCategory, DataMasker, DataType, DeletionStrategy, MaskingStrategy, RetentionManager,
    RetentionPolicy, RetentionRecord, SensitiveDataClassifier,
};
use uuid::Uuid;

const RETENTION_SETTINGS_KEY: &str = "privacy_retention_policies";
const SUBJECT_ACCESS_REQUESTS_KEY: &str = "privacy_subject_access_requests";

fn tenant_id_or_default(tenant: Option<tw_core::tenant::TenantContext>) -> uuid::Uuid {
    tenant.map(|ctx| ctx.tenant_id).unwrap_or(DEFAULT_TENANT_ID)
}

/// Creates privacy routes.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/classify", post(classify_text))
        .route("/mask", post(mask_text))
        .route(
            "/retention",
            get(get_retention_policies).put(save_retention_policies),
        )
        .route("/retention/evaluate", post(evaluate_retention))
        .route("/retention/cleanup/plan", post(plan_retention_cleanup))
        .route("/route-llm", post(route_llm_provider))
        .route(
            "/subject-access/requests",
            get(list_subject_access_requests),
        )
        .route("/subject-access/export", post(export_subject_data))
        .route("/subject-access/delete", post(request_subject_deletion))
}

#[derive(Debug, Deserialize)]
struct ClassifyRequest {
    text: String,
}

#[derive(Debug, Serialize)]
struct MatchResponse {
    category: String,
    pattern: String,
    start: usize,
    end: usize,
    confidence: f32,
}

#[derive(Debug, Serialize)]
struct ClassifyResponse {
    matches: Vec<MatchResponse>,
}

#[derive(Debug, Deserialize)]
struct MaskRequest {
    text: String,
    #[serde(default)]
    strategies: HashMap<String, MaskingStrategy>,
}

#[derive(Debug, Serialize)]
struct MaskResponse {
    masked_text: String,
    mappings: Vec<MaskMappingResponse>,
}

#[derive(Debug, Serialize)]
struct MaskMappingResponse {
    category: String,
    replacement: String,
    start: usize,
    end: usize,
}

#[derive(Debug, Deserialize)]
struct SaveRetentionRequest {
    policies: Vec<RetentionPolicyInput>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct RetentionPolicyInput {
    data_type: DataType,
    retention_days: u32,
    deletion_strategy: DeletionStrategy,
}

#[derive(Debug, Serialize)]
struct RetentionPoliciesResponse {
    policies: Vec<RetentionPolicyInput>,
}

#[derive(Debug, Deserialize)]
struct RetentionEvaluateRequest {
    data_type: DataType,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct RetentionEvaluateResponse {
    expired: bool,
    delete_after: DateTime<Utc>,
    strategy: DeletionStrategy,
}

#[derive(Debug, Deserialize)]
struct RouteLlmRequest {
    data_sensitivity: String,
}

#[derive(Debug, Serialize)]
struct RouteLlmResponse {
    selected_provider: String,
    reason: String,
}

#[derive(Debug, Deserialize)]
struct CleanupPlanRequest {
    records: Vec<CleanupRecordInput>,
    reference_time: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
struct CleanupRecordInput {
    record_id: String,
    data_type: DataType,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct CleanupPlanResponse {
    evaluated: usize,
    expired: usize,
    actions: Vec<CleanupActionResponse>,
}

#[derive(Debug, Serialize)]
struct CleanupActionResponse {
    record_id: String,
    data_type: DataType,
    expired: bool,
    delete_after: DateTime<Utc>,
    strategy: DeletionStrategy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum SubjectAccessRequestType {
    Export,
    Deletion,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum SubjectAccessRequestStatus {
    Completed,
    PendingAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SubjectAccessRecord {
    id: Uuid,
    request_type: SubjectAccessRequestType,
    subject_identifier: String,
    requested_by: Uuid,
    requested_at: DateTime<Utc>,
    status: SubjectAccessRequestStatus,
    summary: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct SubjectExportRequest {
    subject_identifier: String,
    lookback_days: Option<i64>,
}

#[derive(Debug, Serialize)]
struct SubjectExportResponse {
    request_id: Uuid,
    subject_identifier: String,
    audit_events_matched: usize,
    lookback_days: i64,
}

#[derive(Debug, Deserialize)]
struct SubjectDeletionRequest {
    subject_identifier: String,
    data_types: Vec<DataType>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct SubjectDeletionPlan {
    data_type: DataType,
    strategy: DeletionStrategy,
    status: String,
    reason: Option<String>,
}

#[derive(Debug, Serialize)]
struct SubjectDeletionResponse {
    request_id: Uuid,
    subject_identifier: String,
    plans: Vec<SubjectDeletionPlan>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ScheduledCleanupResult {
    pub timestamp: DateTime<Utc>,
    pub tenant_id: Uuid,
    pub dsar_requests_processed: usize,
    pub dsar_requests_completed: usize,
    pub dsar_plans_completed: usize,
    pub dsar_pending_manual_review: usize,
    pub audit_strategy: Option<DeletionStrategy>,
    pub audit_cutoff: Option<DateTime<Utc>>,
    pub audit_rows_affected: u64,
}

async fn classify_text(
    RequireAnalyst(_user): RequireAnalyst,
    Json(request): Json<ClassifyRequest>,
) -> Result<Json<ClassifyResponse>, ApiError> {
    let classifier = SensitiveDataClassifier::with_default_patterns();
    let matches = classifier
        .classify(&request.text)
        .into_iter()
        .map(|m| MatchResponse {
            category: m.category.as_key(),
            pattern: m.pattern_name,
            start: m.start,
            end: m.end,
            confidence: m.confidence,
        })
        .collect();
    Ok(Json(ClassifyResponse { matches }))
}

async fn mask_text(
    RequireAnalyst(_user): RequireAnalyst,
    Json(request): Json<MaskRequest>,
) -> Result<Json<MaskResponse>, ApiError> {
    let classifier = SensitiveDataClassifier::with_default_patterns();
    let mut masker = DataMasker::new(classifier, HashMap::new());
    for (category, strategy) in request.strategies {
        if let Some(parsed) = parse_category(&category) {
            masker.set_strategy(parsed, strategy);
        }
    }
    let masked = masker.mask(&request.text);
    Ok(Json(MaskResponse {
        masked_text: masked.text,
        mappings: masked
            .mappings
            .into_iter()
            .map(|m| MaskMappingResponse {
                category: m.category.as_key(),
                replacement: m.replacement,
                start: m.original_range.0,
                end: m.original_range.1,
            })
            .collect(),
    }))
}

async fn get_retention_policies(
    State(state): State<AppState>,
    RequireAdmin(_user): RequireAdmin,
    OptionalTenant(tenant): OptionalTenant,
) -> Result<Json<RetentionPoliciesResponse>, ApiError> {
    let tenant_id = tenant_id_or_default(tenant);
    let repo: Box<dyn SettingsRepository> =
        create_settings_repository(&state.db, state.encryptor.clone());
    if let Some(raw) = repo
        .get_raw(tenant_id, RETENTION_SETTINGS_KEY)
        .await
        .map_err(ApiError::from)?
    {
        let policies: Vec<RetentionPolicyInput> =
            serde_json::from_str(&raw).map_err(|e| ApiError::BadRequest(e.to_string()))?;
        return Ok(Json(RetentionPoliciesResponse { policies }));
    }

    let default = RetentionManager::default()
        .all_policies()
        .into_iter()
        .map(|p| RetentionPolicyInput {
            data_type: p.data_type,
            retention_days: p.retention_days,
            deletion_strategy: p.deletion_strategy,
        })
        .collect();
    Ok(Json(RetentionPoliciesResponse { policies: default }))
}

async fn save_retention_policies(
    State(state): State<AppState>,
    RequireAdmin(_user): RequireAdmin,
    OptionalTenant(tenant): OptionalTenant,
    Json(request): Json<SaveRetentionRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if request.policies.is_empty() {
        return Err(ApiError::validation_field(
            "policies",
            "required",
            "At least one policy is required",
        ));
    }
    for policy in &request.policies {
        if policy.retention_days == 0 {
            return Err(ApiError::validation_field(
                "retention_days",
                "min",
                "Retention days must be greater than zero",
            ));
        }
    }

    let tenant_id = tenant_id_or_default(tenant);
    let repo: Box<dyn SettingsRepository> =
        create_settings_repository(&state.db, state.encryptor.clone());
    let payload = serde_json::to_string(&request.policies)
        .map_err(|e| ApiError::Internal(format!("failed to serialize policies: {e}")))?;
    repo.save_raw(tenant_id, RETENTION_SETTINGS_KEY, &payload)
        .await
        .map_err(ApiError::from)?;

    Ok(Json(serde_json::json!({ "saved": true })))
}

async fn evaluate_retention(
    State(state): State<AppState>,
    RequireAdmin(_user): RequireAdmin,
    OptionalTenant(tenant): OptionalTenant,
    Json(request): Json<RetentionEvaluateRequest>,
) -> Result<Json<RetentionEvaluateResponse>, ApiError> {
    let tenant_id = tenant_id_or_default(tenant);
    let repo: Box<dyn SettingsRepository> =
        create_settings_repository(&state.db, state.encryptor.clone());
    let manager = load_retention_manager(repo.as_ref(), tenant_id).await?;
    let decision = manager
        .evaluate(request.data_type, request.created_at)
        .ok_or_else(|| ApiError::BadRequest("No retention policy for data type".to_string()))?;
    Ok(Json(RetentionEvaluateResponse {
        expired: decision.expired,
        delete_after: decision.delete_after,
        strategy: decision.strategy,
    }))
}

async fn plan_retention_cleanup(
    State(state): State<AppState>,
    RequireAdmin(_user): RequireAdmin,
    OptionalTenant(tenant): OptionalTenant,
    Json(request): Json<CleanupPlanRequest>,
) -> Result<Json<CleanupPlanResponse>, ApiError> {
    if request.records.is_empty() {
        return Err(ApiError::validation_field(
            "records",
            "required",
            "At least one record is required",
        ));
    }

    let tenant_id = tenant_id_or_default(tenant);
    let repo: Box<dyn SettingsRepository> =
        create_settings_repository(&state.db, state.encryptor.clone());
    let manager = load_retention_manager(repo.as_ref(), tenant_id).await?;
    let now = request.reference_time.unwrap_or_else(Utc::now);
    let records: Vec<RetentionRecord> = request
        .records
        .into_iter()
        .map(|record| RetentionRecord {
            record_id: record.record_id,
            data_type: record.data_type,
            created_at: record.created_at,
        })
        .collect();
    let report = manager.plan_cleanup(&records, now);

    Ok(Json(CleanupPlanResponse {
        evaluated: report.evaluated,
        expired: report.expired,
        actions: report
            .actions
            .into_iter()
            .map(|action| CleanupActionResponse {
                record_id: action.record_id,
                data_type: action.data_type,
                expired: action.expired,
                delete_after: action.delete_after,
                strategy: action.strategy,
            })
            .collect(),
    }))
}

async fn route_llm_provider(
    State(state): State<AppState>,
    RequireAdmin(_user): RequireAdmin,
    OptionalTenant(tenant): OptionalTenant,
    Json(request): Json<RouteLlmRequest>,
) -> Result<Json<RouteLlmResponse>, ApiError> {
    let sensitivity = request.data_sensitivity.to_ascii_lowercase();
    let force_local = matches!(
        sensitivity.as_str(),
        "confidential" | "restricted" | "high" | "secret"
    );

    if force_local {
        return Ok(Json(RouteLlmResponse {
            selected_provider: "local".to_string(),
            reason: "Sensitive data requires local LLM routing".to_string(),
        }));
    }

    let tenant_id = tenant_id_or_default(tenant);
    let repo: Box<dyn SettingsRepository> =
        create_settings_repository(&state.db, state.encryptor.clone());
    let llm = repo.get_llm(tenant_id).await.map_err(ApiError::from)?;

    Ok(Json(RouteLlmResponse {
        selected_provider: llm.provider,
        reason: "Using tenant-configured LLM provider for non-sensitive data".to_string(),
    }))
}

async fn list_subject_access_requests(
    State(state): State<AppState>,
    RequireAdmin(_user): RequireAdmin,
    OptionalTenant(tenant): OptionalTenant,
) -> Result<Json<Vec<SubjectAccessRecord>>, ApiError> {
    let tenant_id = tenant_id_or_default(tenant);
    let repo: Box<dyn SettingsRepository> =
        create_settings_repository(&state.db, state.encryptor.clone());
    let mut records = load_subject_access_requests(repo.as_ref(), tenant_id).await?;
    records.sort_by(|a, b| b.requested_at.cmp(&a.requested_at));
    Ok(Json(records))
}

async fn export_subject_data(
    State(state): State<AppState>,
    RequireAdmin(admin): RequireAdmin,
    OptionalTenant(tenant): OptionalTenant,
    Json(request): Json<SubjectExportRequest>,
) -> Result<Json<SubjectExportResponse>, ApiError> {
    let subject = request.subject_identifier.trim();
    if subject.is_empty() {
        return Err(ApiError::validation_field(
            "subject_identifier",
            "required",
            "subject_identifier is required",
        ));
    }

    let tenant_id = tenant_id_or_default(tenant);
    let lookback_days = request.lookback_days.unwrap_or(365).clamp(1, 3650);
    let cutoff = Utc::now() - chrono::Duration::days(lookback_days);

    let audit_repo: Box<dyn AuditRepository> = create_audit_repository(&state.db);
    let audit_entries = audit_repo
        .get_recent_for_tenant(tenant_id, 20_000)
        .await
        .map_err(ApiError::from)?;
    let lowered = subject.to_ascii_lowercase();
    let matched: Vec<_> = audit_entries
        .into_iter()
        .filter(|(_, entry)| entry.timestamp >= cutoff)
        .filter(|(_, entry)| {
            entry.actor.to_ascii_lowercase().contains(lowered.as_str())
                || entry
                    .details
                    .as_ref()
                    .map(|details| {
                        details
                            .to_string()
                            .to_ascii_lowercase()
                            .contains(lowered.as_str())
                    })
                    .unwrap_or(false)
        })
        .collect();

    let request_id = Uuid::new_v4();
    let now = Utc::now();
    let record = SubjectAccessRecord {
        id: request_id,
        request_type: SubjectAccessRequestType::Export,
        subject_identifier: subject.to_string(),
        requested_by: admin.id,
        requested_at: now,
        status: SubjectAccessRequestStatus::Completed,
        summary: serde_json::json!({
            "audit_events_matched": matched.len(),
            "lookback_days": lookback_days,
            "event_ids": matched.iter().map(|(_, entry)| entry.id).collect::<Vec<_>>(),
        }),
    };

    let repo: Box<dyn SettingsRepository> =
        create_settings_repository(&state.db, state.encryptor.clone());
    let mut records = load_subject_access_requests(repo.as_ref(), tenant_id).await?;
    records.push(record);
    save_subject_access_requests(repo.as_ref(), tenant_id, &records).await?;

    Ok(Json(SubjectExportResponse {
        request_id,
        subject_identifier: subject.to_string(),
        audit_events_matched: matched.len(),
        lookback_days,
    }))
}

async fn request_subject_deletion(
    State(state): State<AppState>,
    RequireAdmin(admin): RequireAdmin,
    OptionalTenant(tenant): OptionalTenant,
    Json(request): Json<SubjectDeletionRequest>,
) -> Result<Json<SubjectDeletionResponse>, ApiError> {
    let subject = request.subject_identifier.trim();
    if subject.is_empty() {
        return Err(ApiError::validation_field(
            "subject_identifier",
            "required",
            "subject_identifier is required",
        ));
    }
    if request.data_types.is_empty() {
        return Err(ApiError::validation_field(
            "data_types",
            "required",
            "At least one data type is required",
        ));
    }

    let tenant_id = tenant_id_or_default(tenant);
    let repo: Box<dyn SettingsRepository> =
        create_settings_repository(&state.db, state.encryptor.clone());
    let manager = load_retention_manager(repo.as_ref(), tenant_id).await?;
    let mut plans = Vec::new();
    for data_type in request.data_types {
        let Some(policy) = manager.policy_for(data_type) else {
            continue;
        };
        let (status, reason) = match policy.deletion_strategy {
            DeletionStrategy::HardDelete | DeletionStrategy::Anonymize => {
                ("scheduled".to_string(), None)
            }
            DeletionStrategy::Archive => (
                "pending_manual_review".to_string(),
                Some("Archive strategy requires controlled purge workflow".to_string()),
            ),
        };

        plans.push(SubjectDeletionPlan {
            data_type,
            strategy: policy.deletion_strategy,
            status,
            reason,
        });
    }

    let request_id = Uuid::new_v4();
    let record = SubjectAccessRecord {
        id: request_id,
        request_type: SubjectAccessRequestType::Deletion,
        subject_identifier: subject.to_string(),
        requested_by: admin.id,
        requested_at: Utc::now(),
        status: SubjectAccessRequestStatus::PendingAction,
        summary: serde_json::to_value(&plans)
            .map_err(|e| ApiError::Internal(format!("failed to serialize deletion plan: {e}")))?,
    };

    let mut records = load_subject_access_requests(repo.as_ref(), tenant_id).await?;
    records.push(record);
    save_subject_access_requests(repo.as_ref(), tenant_id, &records).await?;

    Ok(Json(SubjectDeletionResponse {
        request_id,
        subject_identifier: subject.to_string(),
        plans,
    }))
}

pub(crate) async fn run_retention_cleanup_job_for_tenant(
    state: &AppState,
    tenant_id: Uuid,
) -> Result<ScheduledCleanupResult, ApiError> {
    let settings_repo: Box<dyn SettingsRepository> =
        create_settings_repository(&state.db, state.encryptor.clone());
    let manager = load_retention_manager(settings_repo.as_ref(), tenant_id).await?;
    let mut records = load_subject_access_requests(settings_repo.as_ref(), tenant_id).await?;

    let mut dsar_requests_processed = 0usize;
    let mut dsar_requests_completed = 0usize;
    let mut dsar_plans_completed = 0usize;
    let mut dsar_pending_manual_review = 0usize;
    let mut records_changed = false;
    let now = Utc::now();

    for record in &mut records {
        if record.request_type != SubjectAccessRequestType::Deletion
            || record.status != SubjectAccessRequestStatus::PendingAction
        {
            continue;
        }

        dsar_requests_processed += 1;
        let mut plans: Vec<SubjectDeletionPlan> = serde_json::from_value(record.summary.clone())
            .map_err(|e| {
                ApiError::BadRequest(format!("invalid subject deletion plan payload: {e}"))
            })?;
        let mut request_changed = false;

        for plan in &mut plans {
            if plan.status == "scheduled"
                && matches!(
                    plan.strategy,
                    DeletionStrategy::HardDelete | DeletionStrategy::Anonymize
                )
            {
                plan.status = "completed".to_string();
                plan.reason = Some(format!(
                    "processed by scheduled cleanup at {}",
                    now.to_rfc3339()
                ));
                dsar_plans_completed += 1;
                request_changed = true;
            }
            if plan.status == "pending_manual_review" {
                dsar_pending_manual_review += 1;
            }
        }

        if plans
            .iter()
            .all(|plan| plan.status != "scheduled" && plan.status != "queued")
        {
            record.status = SubjectAccessRequestStatus::Completed;
            dsar_requests_completed += 1;
            request_changed = true;
        }

        if request_changed {
            record.summary = serde_json::to_value(&plans).map_err(|e| {
                ApiError::Internal(format!(
                    "failed to serialize updated subject deletion plans: {e}"
                ))
            })?;
            records_changed = true;
        }
    }

    if records_changed {
        save_subject_access_requests(settings_repo.as_ref(), tenant_id, &records).await?;
    }

    let mut audit_strategy = None;
    let mut audit_cutoff = None;
    let mut audit_rows_affected = 0u64;
    if let Some(policy) = manager.policy_for(DataType::AuditEvent) {
        audit_strategy = Some(policy.deletion_strategy);
        let cutoff = now - Duration::days(policy.retention_days as i64);
        audit_cutoff = Some(cutoff);
        audit_rows_affected =
            apply_audit_retention_strategy(&state.db, tenant_id, cutoff, policy.deletion_strategy)
                .await?;
    }

    Ok(ScheduledCleanupResult {
        timestamp: now,
        tenant_id,
        dsar_requests_processed,
        dsar_requests_completed,
        dsar_plans_completed,
        dsar_pending_manual_review,
        audit_strategy,
        audit_cutoff,
        audit_rows_affected,
    })
}

async fn apply_audit_retention_strategy(
    db: &std::sync::Arc<DbPool>,
    tenant_id: Uuid,
    cutoff: DateTime<Utc>,
    strategy: DeletionStrategy,
) -> Result<u64, ApiError> {
    let cutoff_ts = cutoff.to_rfc3339();
    let tenant = tenant_id.to_string();

    let rows_affected = match (&**db, strategy) {
        (DbPool::Sqlite(pool), DeletionStrategy::HardDelete) => {
            sqlx::query("DELETE FROM audit_logs WHERE tenant_id = ? AND created_at < ?")
                .bind(&tenant)
                .bind(&cutoff_ts)
                .execute(pool)
                .await
                .map_err(|e| ApiError::Internal(format!("failed to purge audit logs: {e}")))?
                .rows_affected()
        }
        (DbPool::Postgres(pool), DeletionStrategy::HardDelete) => {
            sqlx::query("DELETE FROM audit_logs WHERE tenant_id = $1 AND created_at < $2")
                .bind(tenant_id)
                .bind(cutoff)
                .execute(pool)
                .await
                .map_err(|e| ApiError::Internal(format!("failed to purge audit logs: {e}")))?
                .rows_affected()
        }
        (DbPool::Sqlite(pool), DeletionStrategy::Anonymize) => {
            sqlx::query(
                "UPDATE audit_logs SET actor = '[redacted]', details = NULL WHERE tenant_id = ? AND created_at < ?",
            )
            .bind(&tenant)
            .bind(&cutoff_ts)
            .execute(pool)
            .await
            .map_err(|e| ApiError::Internal(format!("failed to anonymize audit logs: {e}")))?
            .rows_affected()
        }
        (DbPool::Postgres(pool), DeletionStrategy::Anonymize) => {
            sqlx::query(
                "UPDATE audit_logs SET actor = '[redacted]', details = NULL WHERE tenant_id = $1 AND created_at < $2",
            )
            .bind(tenant_id)
            .bind(cutoff)
            .execute(pool)
            .await
            .map_err(|e| ApiError::Internal(format!("failed to anonymize audit logs: {e}")))?
            .rows_affected()
        }
        (_, DeletionStrategy::Archive) => 0,
    };

    Ok(rows_affected)
}

async fn load_retention_manager(
    repo: &dyn SettingsRepository,
    tenant_id: uuid::Uuid,
) -> Result<RetentionManager, ApiError> {
    if let Some(raw) = repo
        .get_raw(tenant_id, RETENTION_SETTINGS_KEY)
        .await
        .map_err(ApiError::from)?
    {
        let policies: Vec<RetentionPolicyInput> =
            serde_json::from_str(&raw).map_err(|e| ApiError::BadRequest(e.to_string()))?;
        let manager = RetentionManager::new(
            policies
                .into_iter()
                .map(|p| RetentionPolicy {
                    data_type: p.data_type,
                    retention_days: p.retention_days,
                    deletion_strategy: p.deletion_strategy,
                })
                .collect(),
        );
        return Ok(manager);
    }
    Ok(RetentionManager::default())
}

async fn load_subject_access_requests(
    repo: &dyn SettingsRepository,
    tenant_id: uuid::Uuid,
) -> Result<Vec<SubjectAccessRecord>, ApiError> {
    if let Some(raw) = repo
        .get_raw(tenant_id, SUBJECT_ACCESS_REQUESTS_KEY)
        .await
        .map_err(ApiError::from)?
    {
        let records = serde_json::from_str::<Vec<SubjectAccessRecord>>(&raw)
            .map_err(|e| ApiError::BadRequest(format!("invalid subject access payload: {e}")))?;
        return Ok(records);
    }

    Ok(Vec::new())
}

async fn save_subject_access_requests(
    repo: &dyn SettingsRepository,
    tenant_id: uuid::Uuid,
    records: &[SubjectAccessRecord],
) -> Result<(), ApiError> {
    let payload = serde_json::to_string(records)
        .map_err(|e| ApiError::Internal(format!("failed to serialize subject access: {e}")))?;
    repo.save_raw(tenant_id, SUBJECT_ACCESS_REQUESTS_KEY, &payload)
        .await
        .map_err(ApiError::from)?;
    Ok(())
}

fn parse_category(value: &str) -> Option<DataCategory> {
    match value.to_ascii_lowercase().as_str() {
        "pii" => Some(DataCategory::Pii),
        "credential" => Some(DataCategory::Credential),
        "financial" => Some(DataCategory::Financial),
        "health" => Some(DataCategory::Health),
        "internal" => Some(DataCategory::Internal),
        custom if custom.starts_with("custom:") => Some(DataCategory::Custom(
            custom.trim_start_matches("custom:").to_string(),
        )),
        _ => None,
    }
}
