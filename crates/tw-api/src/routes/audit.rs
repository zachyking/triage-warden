//! Immutable audit chain endpoints.

use crate::auth::{RequireAdmin, RequireAnalyst};
use crate::error::ApiError;
use crate::middleware::OptionalTenant;
use crate::state::AppState;
use axum::extract::{Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
pub(crate) struct VerifyJobResult {
    pub timestamp: DateTime<Utc>,
    pub valid: bool,
    pub entries: usize,
    pub current_root: Option<String>,
    pub anchored_root: Option<String>,
    pub reason: Option<String>,
    pub alert_created: bool,
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
    let result = run_verify_job_for_tenant(&state, tenant_id, query.limit.unwrap_or(5000)).await?;
    Ok(Json(result))
}

pub(crate) async fn run_verify_job_for_tenant(
    state: &AppState,
    tenant_id: uuid::Uuid,
    limit: u32,
) -> Result<VerifyJobResult, ApiError> {
    let chain = build_immutable_chain(state, tenant_id, limit).await?;
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

    Ok(result)
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
    match resolve_archive_target()? {
        Some(ExternalArchiveTarget::Filesystem) => archive_to_filesystem(tenant_id, record).await,
        Some(ExternalArchiveTarget::S3) => archive_to_s3(tenant_id, record).await,
        Some(ExternalArchiveTarget::AzureBlob) => archive_to_azure_blob(tenant_id, record).await,
        None => Ok(None),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExternalArchiveTarget {
    Filesystem,
    S3,
    AzureBlob,
}

type HmacSha256 = Hmac<Sha256>;

fn resolve_archive_target() -> Result<Option<ExternalArchiveTarget>, ApiError> {
    if let Ok(raw) = std::env::var("TW_IMMUTABLE_ARCHIVE_TARGET") {
        let normalized = raw.trim().to_ascii_lowercase();
        let target = match normalized.as_str() {
            "" => None,
            "filesystem" => Some(ExternalArchiveTarget::Filesystem),
            "s3" => Some(ExternalArchiveTarget::S3),
            "azure_blob" | "azure-blob" | "azureblob" => Some(ExternalArchiveTarget::AzureBlob),
            _ => {
                return Err(ApiError::Internal(format!(
                    "invalid TW_IMMUTABLE_ARCHIVE_TARGET '{}'",
                    raw
                )))
            }
        };
        return Ok(target);
    }

    if std::env::var("TW_IMMUTABLE_ARCHIVE_DIR")
        .ok()
        .is_some_and(|v| !v.trim().is_empty())
    {
        return Ok(Some(ExternalArchiveTarget::Filesystem));
    }

    Ok(None)
}

async fn archive_to_filesystem(
    tenant_id: uuid::Uuid,
    record: &ImmutableArchiveRecord,
) -> Result<Option<String>, ApiError> {
    let directory = required_env_var("TW_IMMUTABLE_ARCHIVE_DIR")?;
    let base = PathBuf::from(directory);
    tokio::fs::create_dir_all(&base)
        .await
        .map_err(|e| ApiError::Internal(format!("failed to create archive directory: {e}")))?;
    let full_path = base.join(archive_filename(tenant_id, record.metadata.archive_id));
    let payload = serde_json::to_vec_pretty(record)
        .map_err(|e| ApiError::Internal(format!("failed to serialize archive payload: {e}")))?;
    tokio::fs::write(&full_path, payload)
        .await
        .map_err(|e| ApiError::Internal(format!("failed to write archive payload: {e}")))?;

    Ok(Some(full_path.to_string_lossy().to_string()))
}

async fn archive_to_s3(
    tenant_id: uuid::Uuid,
    record: &ImmutableArchiveRecord,
) -> Result<Option<String>, ApiError> {
    let bucket = required_env_var("TW_IMMUTABLE_ARCHIVE_S3_BUCKET")?;
    let region = std::env::var("TW_IMMUTABLE_ARCHIVE_S3_REGION")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "us-east-1".to_string());
    let access_key_id = std::env::var("TW_IMMUTABLE_ARCHIVE_S3_ACCESS_KEY_ID")
        .or_else(|_| std::env::var("AWS_ACCESS_KEY_ID"))
        .map_err(|_| {
            ApiError::Internal(
                "Missing S3 access key id (TW_IMMUTABLE_ARCHIVE_S3_ACCESS_KEY_ID/AWS_ACCESS_KEY_ID)"
                    .to_string(),
            )
        })?;
    let secret_access_key = std::env::var("TW_IMMUTABLE_ARCHIVE_S3_SECRET_ACCESS_KEY")
        .or_else(|_| std::env::var("AWS_SECRET_ACCESS_KEY"))
        .map_err(|_| {
            ApiError::Internal(
                "Missing S3 secret key (TW_IMMUTABLE_ARCHIVE_S3_SECRET_ACCESS_KEY/AWS_SECRET_ACCESS_KEY)"
                    .to_string(),
            )
        })?;
    let session_token = std::env::var("TW_IMMUTABLE_ARCHIVE_S3_SESSION_TOKEN")
        .or_else(|_| std::env::var("AWS_SESSION_TOKEN"))
        .ok()
        .filter(|v| !v.trim().is_empty());
    let prefix = std::env::var("TW_IMMUTABLE_ARCHIVE_S3_PREFIX")
        .unwrap_or_else(|_| "immutable-audit".to_string());

    let object_key = archive_object_key(&prefix, tenant_id, record.metadata.archive_id);
    let host = format!("{bucket}.s3.{region}.amazonaws.com");
    let url = format!("https://{host}/{object_key}");
    let payload = serde_json::to_vec_pretty(record)
        .map_err(|e| ApiError::Internal(format!("failed to serialize archive payload: {e}")))?;
    let payload_hash = hex::encode(Sha256::digest(&payload));

    let now = Utc::now();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date_stamp = now.format("%Y%m%d").to_string();

    let mut canonical_headers = format!(
        "host:{host}\n\
x-amz-content-sha256:{payload_hash}\n\
x-amz-date:{amz_date}\n"
    );
    let mut signed_headers = "host;x-amz-content-sha256;x-amz-date".to_string();

    if let Some(token) = session_token.as_deref() {
        canonical_headers.push_str(&format!("x-amz-security-token:{token}\n"));
        signed_headers.push_str(";x-amz-security-token");
    }

    let canonical_request =
        format!("PUT\n/{object_key}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}");
    let canonical_request_hash = hex::encode(Sha256::digest(canonical_request.as_bytes()));
    let credential_scope = format!("{date_stamp}/{region}/s3/aws4_request");
    let string_to_sign =
        format!("AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{canonical_request_hash}");

    let k_date = hmac_sha256(format!("AWS4{secret_access_key}").as_bytes(), &date_stamp)?;
    let k_region = hmac_sha256(&k_date, &region)?;
    let k_service = hmac_sha256(&k_region, "s3")?;
    let k_signing = hmac_sha256(&k_service, "aws4_request")?;
    let signature = hex::encode(hmac_sha256(&k_signing, &string_to_sign)?);
    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
        access_key_id, credential_scope, signed_headers, signature
    );

    let client = reqwest::Client::new();
    let mut request = client
        .put(&url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header("x-amz-content-sha256", payload_hash)
        .header("x-amz-date", amz_date)
        .header(reqwest::header::AUTHORIZATION, authorization)
        .body(payload);

    if let Some(token) = session_token {
        request = request.header("x-amz-security-token", token);
    }

    let response = request
        .send()
        .await
        .map_err(|e| ApiError::Internal(format!("failed to upload archive to S3: {e}")))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(ApiError::Internal(format!(
            "S3 archive upload failed: status={} body={}",
            status, body
        )));
    }

    Ok(Some(format!("s3://{bucket}/{object_key}")))
}

async fn archive_to_azure_blob(
    tenant_id: uuid::Uuid,
    record: &ImmutableArchiveRecord,
) -> Result<Option<String>, ApiError> {
    let account = required_env_var("TW_IMMUTABLE_ARCHIVE_AZURE_ACCOUNT")?;
    let container = required_env_var("TW_IMMUTABLE_ARCHIVE_AZURE_CONTAINER")?;
    let account_key_b64 = required_env_var("TW_IMMUTABLE_ARCHIVE_AZURE_ACCOUNT_KEY")?;
    let key = base64::engine::general_purpose::STANDARD
        .decode(account_key_b64.trim())
        .map_err(|e| ApiError::Internal(format!("invalid Azure account key: {e}")))?;
    let endpoint = std::env::var("TW_IMMUTABLE_ARCHIVE_AZURE_ENDPOINT")
        .unwrap_or_else(|_| format!("https://{}.blob.core.windows.net", account));
    let prefix = std::env::var("TW_IMMUTABLE_ARCHIVE_AZURE_PREFIX")
        .unwrap_or_else(|_| "immutable-audit".to_string());

    let blob_name = archive_object_key(&prefix, tenant_id, record.metadata.archive_id);
    let base = endpoint.trim_end_matches('/');
    let url = format!("{base}/{container}/{blob_name}");
    let payload = serde_json::to_vec_pretty(record)
        .map_err(|e| ApiError::Internal(format!("failed to serialize archive payload: {e}")))?;
    let content_length = payload.len();
    let x_ms_date = Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();
    let x_ms_version = std::env::var("TW_IMMUTABLE_ARCHIVE_AZURE_VERSION")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "2023-11-03".to_string());

    let canonicalized_headers =
        format!("x-ms-blob-type:BlockBlob\nx-ms-date:{x_ms_date}\nx-ms-version:{x_ms_version}\n");
    let canonicalized_resource = format!("/{account}/{container}/{blob_name}");
    let string_to_sign = format!(
        "PUT\n\n\n{content_length}\n\napplication/json\n\n\n\n\n\n\n{canonicalized_headers}{canonicalized_resource}"
    );
    let signature =
        base64::engine::general_purpose::STANDARD.encode(hmac_sha256(&key, &string_to_sign)?);
    let authorization = format!("SharedKey {account}:{signature}");

    let response = reqwest::Client::new()
        .put(&url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header(reqwest::header::CONTENT_LENGTH, content_length)
        .header("x-ms-blob-type", "BlockBlob")
        .header("x-ms-date", x_ms_date)
        .header("x-ms-version", x_ms_version)
        .header(reqwest::header::AUTHORIZATION, authorization)
        .body(payload)
        .send()
        .await
        .map_err(|e| ApiError::Internal(format!("failed to upload archive to Azure Blob: {e}")))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(ApiError::Internal(format!(
            "Azure Blob archive upload failed: status={} body={}",
            status, body
        )));
    }

    Ok(Some(url))
}

fn required_env_var(key: &str) -> Result<String, ApiError> {
    std::env::var(key)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| ApiError::Internal(format!("Missing environment variable: {key}")))
}

fn archive_filename(tenant_id: uuid::Uuid, archive_id: uuid::Uuid) -> String {
    format!("immutable_audit_{}_{}.json", tenant_id, archive_id)
}

fn archive_object_key(prefix: &str, tenant_id: uuid::Uuid, archive_id: uuid::Uuid) -> String {
    let object_name = format!("immutable_audit_{}.json", archive_id);
    let trimmed = prefix.trim().trim_matches('/');
    if trimmed.is_empty() {
        format!("{tenant_id}/{object_name}")
    } else {
        format!("{trimmed}/{tenant_id}/{object_name}")
    }
}

fn hmac_sha256(key: &[u8], data: &str) -> Result<Vec<u8>, ApiError> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|e| ApiError::Internal(format!("failed to initialize HMAC: {e}")))?;
    mac.update(data.as_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
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
