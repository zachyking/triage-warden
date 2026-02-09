//! Immutable audit chain endpoints.

use crate::auth::{RequireAdmin, RequireAnalyst};
use crate::error::ApiError;
use crate::middleware::OptionalTenant;
use crate::state::AppState;
use axum::extract::{Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tw_core::audit::immutable::ImmutableAuditPayload;
use tw_core::auth::DEFAULT_TENANT_ID;
use tw_core::db::{
    create_audit_repository, create_settings_repository, AuditRepository, SettingsRepository,
};
use tw_core::{
    verify_immutable_audit_chain, AuditActor, AuditEventType, AuditOutcome, AuditResource,
    ImmutableAuditLog,
};

const IMMUTABLE_ANCHOR_KEY: &str = "immutable_audit_anchor";
const IMMUTABLE_ARCHIVE_INDEX_KEY: &str = "immutable_audit_archive_index";
const IMMUTABLE_VERIFY_ALERTS_KEY: &str = "immutable_audit_verify_alerts";
const IMMUTABLE_VERIFY_LAST_KEY: &str = "immutable_audit_verify_last";

fn tenant_id_or_default(tenant: Option<tw_core::tenant::TenantContext>) -> uuid::Uuid {
    tenant.map(|ctx| ctx.tenant_id).unwrap_or(DEFAULT_TENANT_ID)
}

/// Creates immutable audit routes.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/immutable/anchor", post(anchor_chain))
        .route("/immutable/verify", get(verify_chain))
        .route("/immutable/verify/job", post(run_verify_job))
        .route("/immutable/verify/alerts", get(list_verify_alerts))
        .route("/immutable/export", get(export_chain))
        .route("/immutable/archive", post(archive_chain))
        .route("/immutable/archive/index", get(list_archives))
        .route("/immutable/archive/latest", get(get_latest_archive))
}

#[derive(Debug, Deserialize)]
struct AuditQuery {
    limit: Option<u32>,
}

#[derive(Debug, Serialize)]
struct AnchorResponse {
    anchored: bool,
    entries: usize,
    root_hash: String,
}

#[derive(Debug, Serialize)]
struct VerifyResponse {
    valid: bool,
    entries: usize,
    current_root: Option<String>,
    anchored_root: Option<String>,
    reason: Option<String>,
}

#[derive(Debug, Serialize)]
struct ExportResponse {
    entries: Vec<ImmutableAuditLog>,
    root_hash: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct ImmutableArchiveMetadata {
    archive_id: uuid::Uuid,
    archived_at: DateTime<Utc>,
    entries: usize,
    root_hash: String,
    #[serde(default)]
    external_archive_path: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct ImmutableArchiveRecord {
    metadata: ImmutableArchiveMetadata,
    entries: Vec<ImmutableAuditLog>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct VerifyAlert {
    timestamp: DateTime<Utc>,
    entries: usize,
    current_root: Option<String>,
    anchored_root: Option<String>,
    reason: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct VerifyJobResult {
    timestamp: DateTime<Utc>,
    valid: bool,
    entries: usize,
    current_root: Option<String>,
    anchored_root: Option<String>,
    reason: Option<String>,
    alert_created: bool,
}

async fn anchor_chain(
    State(state): State<AppState>,
    RequireAdmin(_admin): RequireAdmin,
    OptionalTenant(tenant): OptionalTenant,
    Query(query): Query<AuditQuery>,
) -> Result<Json<AnchorResponse>, ApiError> {
    let tenant_id = tenant_id_or_default(tenant);
    let chain = build_immutable_chain(&state, tenant_id, query.limit.unwrap_or(5000)).await?;
    let root_hash = chain.last().map(|e| e.hash.clone()).unwrap_or_default();

    let settings_repo: Box<dyn SettingsRepository> =
        create_settings_repository(&state.db, state.encryptor.clone());
    settings_repo
        .save_raw(tenant_id, IMMUTABLE_ANCHOR_KEY, &root_hash)
        .await
        .map_err(ApiError::from)?;

    Ok(Json(AnchorResponse {
        anchored: true,
        entries: chain.len(),
        root_hash,
    }))
}

async fn verify_chain(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
    Query(query): Query<AuditQuery>,
) -> Result<Json<VerifyResponse>, ApiError> {
    let tenant_id = tenant_id_or_default(tenant);
    let chain = build_immutable_chain(&state, tenant_id, query.limit.unwrap_or(5000)).await?;
    let current_root = chain.last().map(|e| e.hash.clone());

    let settings_repo: Box<dyn SettingsRepository> =
        create_settings_repository(&state.db, state.encryptor.clone());
    let anchored_root = settings_repo
        .get_raw(tenant_id, IMMUTABLE_ANCHOR_KEY)
        .await
        .map_err(ApiError::from)?;

    let chain_valid = verify_immutable_audit_chain(&chain).is_ok();
    let anchor_matches = match (&current_root, &anchored_root) {
        (Some(current), Some(anchor)) => current == anchor,
        (_, None) => true,
        _ => false,
    };

    Ok(Json(VerifyResponse {
        valid: chain_valid && anchor_matches,
        entries: chain.len(),
        current_root,
        anchored_root,
        reason: if chain_valid {
            if anchor_matches {
                None
            } else {
                Some("Current root hash does not match anchored root".to_string())
            }
        } else {
            Some("Immutable chain verification failed".to_string())
        },
    }))
}

async fn run_verify_job(
    State(state): State<AppState>,
    RequireAdmin(_admin): RequireAdmin,
    OptionalTenant(tenant): OptionalTenant,
    Query(query): Query<AuditQuery>,
) -> Result<Json<VerifyJobResult>, ApiError> {
    let tenant_id = tenant_id_or_default(tenant);
    let chain = build_immutable_chain(&state, tenant_id, query.limit.unwrap_or(5000)).await?;
    let current_root = chain.last().map(|e| e.hash.clone());

    let settings_repo: Box<dyn SettingsRepository> =
        create_settings_repository(&state.db, state.encryptor.clone());
    let anchored_root = settings_repo
        .get_raw(tenant_id, IMMUTABLE_ANCHOR_KEY)
        .await
        .map_err(ApiError::from)?;
    let chain_valid = verify_immutable_audit_chain(&chain).is_ok();
    let anchor_matches = match (&current_root, &anchored_root) {
        (Some(current), Some(anchor)) => current == anchor,
        (_, None) => true,
        _ => false,
    };
    let valid = chain_valid && anchor_matches;
    let reason = if chain_valid {
        if anchor_matches {
            None
        } else {
            Some("Current root hash does not match anchored root".to_string())
        }
    } else {
        Some("Immutable chain verification failed".to_string())
    };

    let mut alert_created = false;
    if let Some(reason_value) = reason.clone() {
        let mut alerts = load_verify_alerts(settings_repo.as_ref(), tenant_id).await?;
        alerts.push(VerifyAlert {
            timestamp: Utc::now(),
            entries: chain.len(),
            current_root: current_root.clone(),
            anchored_root: anchored_root.clone(),
            reason: reason_value.clone(),
        });
        // Keep only recent alerts to bound payload size.
        if alerts.len() > 100 {
            let start = alerts.len() - 100;
            alerts = alerts[start..].to_vec();
        }
        save_verify_alerts(settings_repo.as_ref(), tenant_id, &alerts).await?;
        tracing::error!(
            tenant_id = %tenant_id,
            entries = chain.len(),
            reason = %reason_value,
            "Immutable audit verification job detected integrity failure"
        );
        alert_created = true;
    }

    let result = VerifyJobResult {
        timestamp: Utc::now(),
        valid,
        entries: chain.len(),
        current_root,
        anchored_root,
        reason,
        alert_created,
    };

    settings_repo
        .save_raw(
            tenant_id,
            IMMUTABLE_VERIFY_LAST_KEY,
            &serde_json::to_string(&result).map_err(|e| {
                ApiError::Internal(format!("failed to serialize verify job result: {e}"))
            })?,
        )
        .await
        .map_err(ApiError::from)?;

    Ok(Json(result))
}

async fn list_verify_alerts(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
) -> Result<Json<Vec<VerifyAlert>>, ApiError> {
    let tenant_id = tenant_id_or_default(tenant);
    let settings_repo: Box<dyn SettingsRepository> =
        create_settings_repository(&state.db, state.encryptor.clone());
    let mut alerts = load_verify_alerts(settings_repo.as_ref(), tenant_id).await?;
    alerts.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    Ok(Json(alerts))
}

async fn export_chain(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
    Query(query): Query<AuditQuery>,
) -> Result<Json<ExportResponse>, ApiError> {
    let tenant_id = tenant_id_or_default(tenant);
    let chain = build_immutable_chain(&state, tenant_id, query.limit.unwrap_or(5000)).await?;
    let root_hash = chain.last().map(|entry| entry.hash.clone());
    Ok(Json(ExportResponse {
        entries: chain,
        root_hash,
    }))
}

async fn archive_chain(
    State(state): State<AppState>,
    RequireAdmin(_admin): RequireAdmin,
    OptionalTenant(tenant): OptionalTenant,
    Query(query): Query<AuditQuery>,
) -> Result<Json<ImmutableArchiveMetadata>, ApiError> {
    let tenant_id = tenant_id_or_default(tenant);
    let chain = build_immutable_chain(&state, tenant_id, query.limit.unwrap_or(5000)).await?;
    let root_hash = chain.last().map(|e| e.hash.clone()).unwrap_or_default();
    let metadata = ImmutableArchiveMetadata {
        archive_id: uuid::Uuid::new_v4(),
        archived_at: Utc::now(),
        entries: chain.len(),
        root_hash,
        external_archive_path: None,
    };
    let mut record = ImmutableArchiveRecord {
        metadata: metadata.clone(),
        entries: chain,
    };
    let mut persisted_metadata = metadata;
    if let Some(path) = archive_to_external_storage(tenant_id, &record).await? {
        record.metadata.external_archive_path = Some(path.clone());
        persisted_metadata.external_archive_path = Some(path);
    }

    let settings_repo: Box<dyn SettingsRepository> =
        create_settings_repository(&state.db, state.encryptor.clone());
    let record_key = format!("immutable_audit_archive_{}", persisted_metadata.archive_id);
    settings_repo
        .save_raw(
            tenant_id,
            &record_key,
            &serde_json::to_string(&record)
                .map_err(|e| ApiError::Internal(format!("failed to serialize archive: {e}")))?,
        )
        .await
        .map_err(ApiError::from)?;

    let mut index = load_archive_index(settings_repo.as_ref(), tenant_id).await?;
    index.retain(|entry| entry.archive_id != persisted_metadata.archive_id);
    index.push(persisted_metadata.clone());
    save_archive_index(settings_repo.as_ref(), tenant_id, &index).await?;

    Ok(Json(persisted_metadata))
}

async fn list_archives(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
) -> Result<Json<Vec<ImmutableArchiveMetadata>>, ApiError> {
    let tenant_id = tenant_id_or_default(tenant);
    let settings_repo: Box<dyn SettingsRepository> =
        create_settings_repository(&state.db, state.encryptor.clone());
    let mut index = load_archive_index(settings_repo.as_ref(), tenant_id).await?;
    index.sort_by(|a, b| b.archived_at.cmp(&a.archived_at));
    Ok(Json(index))
}

async fn get_latest_archive(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
) -> Result<Json<Option<ImmutableArchiveRecord>>, ApiError> {
    let tenant_id = tenant_id_or_default(tenant);
    let settings_repo: Box<dyn SettingsRepository> =
        create_settings_repository(&state.db, state.encryptor.clone());
    let mut index = load_archive_index(settings_repo.as_ref(), tenant_id).await?;
    index.sort_by(|a, b| b.archived_at.cmp(&a.archived_at));

    let Some(latest) = index.first() else {
        return Ok(Json(None));
    };

    let key = format!("immutable_audit_archive_{}", latest.archive_id);
    let Some(raw) = settings_repo
        .get_raw(tenant_id, &key)
        .await
        .map_err(ApiError::from)?
    else {
        return Ok(Json(None));
    };

    let record: ImmutableArchiveRecord = serde_json::from_str(&raw)
        .map_err(|e| ApiError::Internal(format!("failed to parse archive record: {e}")))?;
    Ok(Json(Some(record)))
}

async fn load_archive_index(
    repo: &dyn SettingsRepository,
    tenant_id: uuid::Uuid,
) -> Result<Vec<ImmutableArchiveMetadata>, ApiError> {
    if let Some(raw) = repo
        .get_raw(tenant_id, IMMUTABLE_ARCHIVE_INDEX_KEY)
        .await
        .map_err(ApiError::from)?
    {
        let parsed = serde_json::from_str::<Vec<ImmutableArchiveMetadata>>(&raw)
            .map_err(|e| ApiError::BadRequest(format!("invalid immutable archive index: {e}")))?;
        return Ok(parsed);
    }

    Ok(Vec::new())
}

async fn save_archive_index(
    repo: &dyn SettingsRepository,
    tenant_id: uuid::Uuid,
    entries: &[ImmutableArchiveMetadata],
) -> Result<(), ApiError> {
    let payload = serde_json::to_string(entries)
        .map_err(|e| ApiError::Internal(format!("failed to serialize archive index: {e}")))?;
    repo.save_raw(tenant_id, IMMUTABLE_ARCHIVE_INDEX_KEY, &payload)
        .await
        .map_err(ApiError::from)?;
    Ok(())
}

async fn load_verify_alerts(
    repo: &dyn SettingsRepository,
    tenant_id: uuid::Uuid,
) -> Result<Vec<VerifyAlert>, ApiError> {
    if let Some(raw) = repo
        .get_raw(tenant_id, IMMUTABLE_VERIFY_ALERTS_KEY)
        .await
        .map_err(ApiError::from)?
    {
        let parsed = serde_json::from_str::<Vec<VerifyAlert>>(&raw)
            .map_err(|e| ApiError::BadRequest(format!("invalid verify alerts payload: {e}")))?;
        return Ok(parsed);
    }

    Ok(Vec::new())
}

async fn save_verify_alerts(
    repo: &dyn SettingsRepository,
    tenant_id: uuid::Uuid,
    alerts: &[VerifyAlert],
) -> Result<(), ApiError> {
    let payload = serde_json::to_string(alerts)
        .map_err(|e| ApiError::Internal(format!("failed to serialize verify alerts: {e}")))?;
    repo.save_raw(tenant_id, IMMUTABLE_VERIFY_ALERTS_KEY, &payload)
        .await
        .map_err(ApiError::from)?;
    Ok(())
}

async fn archive_to_external_storage(
    tenant_id: uuid::Uuid,
    record: &ImmutableArchiveRecord,
) -> Result<Option<String>, ApiError> {
    let Ok(directory) = std::env::var("TW_IMMUTABLE_ARCHIVE_DIR") else {
        return Ok(None);
    };

    let base = PathBuf::from(directory);
    tokio::fs::create_dir_all(&base)
        .await
        .map_err(|e| ApiError::Internal(format!("failed to create archive directory: {e}")))?;
    let filename = format!(
        "immutable_audit_{}_{}.json",
        tenant_id, record.metadata.archive_id
    );
    let full_path = base.join(filename);
    let payload = serde_json::to_vec_pretty(record)
        .map_err(|e| ApiError::Internal(format!("failed to serialize archive payload: {e}")))?;
    tokio::fs::write(&full_path, payload)
        .await
        .map_err(|e| ApiError::Internal(format!("failed to write archive payload: {e}")))?;

    Ok(Some(full_path.to_string_lossy().to_string()))
}

async fn build_immutable_chain(
    state: &AppState,
    tenant_id: uuid::Uuid,
    limit: u32,
) -> Result<Vec<ImmutableAuditLog>, ApiError> {
    let audit_repo: Box<dyn AuditRepository> = create_audit_repository(&state.db);
    let mut entries = audit_repo
        .get_recent_for_tenant(tenant_id, limit)
        .await
        .map_err(ApiError::from)?;
    entries.sort_by_key(|(_, entry)| entry.timestamp);

    let mut chain: Vec<ImmutableAuditLog> = Vec::new();
    for (incident_id, entry) in entries {
        let previous = chain.last();
        let immutable = ImmutableAuditLog::from_seed(
            entry.id,
            entry.timestamp,
            previous,
            ImmutableAuditPayload::new(
                map_event_type(&entry.action),
                AuditActor {
                    id: entry.actor.clone(),
                    kind: "actor".to_string(),
                },
                AuditResource {
                    kind: "incident".to_string(),
                    id: Some(incident_id.to_string()),
                },
                format!("{:?}", entry.action),
                AuditOutcome::Success,
                entry.details.unwrap_or_default(),
            ),
        );
        chain.push(immutable);
    }
    Ok(chain)
}

fn map_event_type(action: &tw_core::incident::AuditAction) -> AuditEventType {
    match action {
        tw_core::incident::AuditAction::IncidentCreated => AuditEventType::ActionRequested,
        tw_core::incident::AuditAction::StatusChanged(_) => AuditEventType::ActionExecuted,
        tw_core::incident::AuditAction::ActionApproved => AuditEventType::ActionApproved,
        tw_core::incident::AuditAction::ActionDenied => AuditEventType::ActionRejected,
        tw_core::incident::AuditAction::ActionExecuted => AuditEventType::ActionExecuted,
        tw_core::incident::AuditAction::ActionFailed => AuditEventType::ActionFailed,
        tw_core::incident::AuditAction::AnalysisCompleted => AuditEventType::AiAnalysisRequested,
        _ => AuditEventType::Custom(format!("{:?}", action)),
    }
}
