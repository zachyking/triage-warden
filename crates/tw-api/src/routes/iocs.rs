//! Custom IoC management API endpoints (Task 3.3.3).
//!
//! Provides REST endpoints for CRUD operations on custom IoCs,
//! bulk import, search, and IoC list management.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use uuid::Uuid;

use crate::auth::RequireAnalyst;
use crate::error::ApiError;
use crate::middleware::OptionalTenant;
use crate::state::AppState;
use tw_core::custom_ioc::{CustomIoc, IocClassification, IocType};
use tw_core::db::create_settings_repository;

const IOCS_SETTINGS_KEY: &str = "custom_iocs_v1";

fn stable_uuid(seed: &str) -> Uuid {
    let digest = Sha256::digest(seed.as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

// ---- DTOs ----

/// Response for an IoC.
#[derive(Debug, Serialize, Deserialize)]
pub struct IocResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub ioc_type: String,
    pub value: String,
    pub classification: String,
    pub source: String,
    pub confidence: f32,
    pub tags: Vec<String>,
    pub expiration: Option<DateTime<Utc>>,
    pub context: Option<String>,
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Request to create an IoC.
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateIocApiRequest {
    pub ioc_type: String,
    pub value: String,
    pub classification: String,
    pub source: String,
    pub confidence: Option<f32>,
    pub tags: Option<Vec<String>>,
    pub expiration: Option<DateTime<Utc>>,
    pub context: Option<String>,
}

/// Request to update an IoC.
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateIocApiRequest {
    pub classification: Option<String>,
    pub confidence: Option<f32>,
    pub tags: Option<Vec<String>>,
    pub expiration: Option<Option<DateTime<Utc>>>,
    pub context: Option<String>,
}

/// Search query parameters.
#[derive(Debug, Deserialize)]
pub struct IocSearchQuery {
    pub ioc_type: Option<String>,
    pub value: Option<String>,
    pub classification: Option<String>,
    pub tag: Option<String>,
    pub include_expired: Option<bool>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

/// Bulk import request.
#[derive(Debug, Serialize, Deserialize)]
pub struct BulkImportRequest {
    pub format: String, // "csv" or "json"
    pub data: String,
    pub default_classification: Option<String>,
    pub default_source: Option<String>,
}

/// Bulk import response.
#[derive(Debug, Serialize, Deserialize)]
pub struct BulkImportResponse {
    pub imported: u64,
    pub failed: u64,
    pub duplicates: u64,
    pub errors: Vec<ImportErrorDetail>,
}

/// Import error detail.
#[derive(Debug, Serialize, Deserialize)]
pub struct ImportErrorDetail {
    pub line: u64,
    pub value: String,
    pub error: String,
}

/// IoC list response.
#[derive(Debug, Serialize, Deserialize)]
pub struct IocListResponse {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub list_type: String,
    pub entry_count: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Paginated IoC response.
#[derive(Debug, Serialize, Deserialize)]
pub struct PaginatedIocResponse {
    pub data: Vec<IocResponse>,
    pub total: u64,
    pub limit: usize,
    pub offset: usize,
}

fn tenant_id_or_default(tenant: Option<tw_core::tenant::TenantContext>) -> Uuid {
    tenant
        .map(|ctx| ctx.tenant_id)
        .unwrap_or(tw_core::auth::DEFAULT_TENANT_ID)
}

fn parse_ioc_type(raw: &str) -> IocType {
    match raw.trim().to_ascii_lowercase().as_str() {
        "ipv4" => IocType::Ipv4,
        "ipv6" => IocType::Ipv6,
        "domain" => IocType::Domain,
        "url" => IocType::Url,
        "md5" => IocType::Md5,
        "sha1" => IocType::Sha1,
        "sha256" => IocType::Sha256,
        "email" => IocType::Email,
        "file_name" | "filename" => IocType::FileName,
        "registry_key" | "registrykey" => IocType::RegistryKey,
        "mutex" => IocType::Mutex,
        "user_agent" | "useragent" => IocType::UserAgent,
        "ja3" => IocType::JA3,
        other => IocType::Custom(other.to_string()),
    }
}

fn parse_classification(raw: &str) -> Result<IocClassification, ApiError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "malicious" => Ok(IocClassification::Malicious),
        "suspicious" => Ok(IocClassification::Suspicious),
        "benign" => Ok(IocClassification::Benign),
        "blocked" => Ok(IocClassification::Blocked),
        "informational" | "info" => Ok(IocClassification::Informational),
        _ => Err(ApiError::BadRequest(format!(
            "Invalid IoC classification: {}",
            raw
        ))),
    }
}

fn classification_as_str(classification: &IocClassification) -> &'static str {
    match classification {
        IocClassification::Malicious => "malicious",
        IocClassification::Suspicious => "suspicious",
        IocClassification::Benign => "benign",
        IocClassification::Blocked => "blocked",
        IocClassification::Informational => "informational",
    }
}

fn ioc_to_response(ioc: &CustomIoc) -> IocResponse {
    IocResponse {
        id: ioc.id,
        tenant_id: ioc.tenant_id,
        ioc_type: ioc.ioc_type.to_string(),
        value: ioc.value.clone(),
        classification: classification_as_str(&ioc.classification).to_string(),
        source: ioc.source.clone(),
        confidence: ioc.confidence,
        tags: ioc.tags.clone(),
        expiration: ioc.expiration,
        context: ioc.context.clone(),
        created_by: ioc.created_by,
        created_at: ioc.created_at,
        updated_at: ioc.updated_at,
    }
}

async fn load_iocs(state: &AppState, tenant_id: Uuid) -> Result<Vec<CustomIoc>, ApiError> {
    let repo = create_settings_repository(&state.db, state.encryptor.clone());
    let raw = repo
        .get_raw(tenant_id, IOCS_SETTINGS_KEY)
        .await
        .map_err(ApiError::from)?;

    match raw {
        Some(raw) => serde_json::from_str(&raw)
            .map_err(|e| ApiError::Internal(format!("Failed to parse stored IoCs: {}", e))),
        None => Ok(vec![]),
    }
}

async fn save_iocs(state: &AppState, tenant_id: Uuid, iocs: &[CustomIoc]) -> Result<(), ApiError> {
    let repo = create_settings_repository(&state.db, state.encryptor.clone());
    let serialized = serde_json::to_string(iocs)
        .map_err(|e| ApiError::Internal(format!("Failed to serialize IoCs: {}", e)))?;
    repo.save_raw(tenant_id, IOCS_SETTINGS_KEY, &serialized)
        .await
        .map_err(ApiError::from)
}

// ---- Routes ----

/// Creates IoC management routes.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(list_iocs).post(create_ioc))
        .route("/search", get(search_iocs))
        .route("/import", post(bulk_import))
        .route("/lists", get(list_ioc_lists))
        .route("/:id", get(get_ioc).put(update_ioc).delete(delete_ioc))
}

// ---- Handlers ----

/// GET /api/iocs - List all IoCs with pagination.
async fn list_iocs(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
    Query(query): Query<IocSearchQuery>,
) -> Result<Json<PaginatedIocResponse>, ApiError> {
    let tenant_id = tenant_id_or_default(tenant);
    let limit = query.limit.unwrap_or(100).min(1000);
    let offset = query.offset.unwrap_or(0);

    let mut iocs = load_iocs(&state, tenant_id).await?;

    if let Some(ioc_type) = &query.ioc_type {
        let wanted = parse_ioc_type(ioc_type).to_string();
        iocs.retain(|i| i.ioc_type.to_string() == wanted);
    }
    if let Some(classification) = &query.classification {
        let wanted = parse_classification(classification)?;
        iocs.retain(|i| i.classification == wanted);
    }
    if let Some(value) = &query.value {
        let value = value.to_ascii_lowercase();
        iocs.retain(|i| i.value.to_ascii_lowercase().contains(&value));
    }
    if let Some(tag) = &query.tag {
        let tag = tag.to_ascii_lowercase();
        iocs.retain(|i| i.tags.iter().any(|t| t.to_ascii_lowercase() == tag));
    }
    if !query.include_expired.unwrap_or(false) {
        iocs.retain(CustomIoc::is_active);
    }

    iocs.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
    let total = iocs.len() as u64;
    let data = iocs
        .iter()
        .skip(offset)
        .take(limit)
        .map(ioc_to_response)
        .collect::<Vec<_>>();

    Ok(Json(PaginatedIocResponse {
        data,
        total,
        limit,
        offset,
    }))
}

/// POST /api/iocs - Create a new IoC.
async fn create_ioc(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
    Json(request): Json<CreateIocApiRequest>,
) -> Result<(StatusCode, Json<IocResponse>), ApiError> {
    let tenant_id = tenant_id_or_default(tenant);
    if request.value.trim().is_empty() {
        return Err(ApiError::BadRequest("IoC value is required".to_string()));
    }
    if request.source.trim().is_empty() {
        return Err(ApiError::BadRequest("IoC source is required".to_string()));
    }

    let ioc_type = parse_ioc_type(&request.ioc_type);
    let classification = parse_classification(&request.classification)?;

    let mut iocs = load_iocs(&state, tenant_id).await?;

    if iocs.iter().any(|existing| {
        existing.ioc_type.to_string() == ioc_type.to_string()
            && existing.value.eq_ignore_ascii_case(request.value.trim())
    }) {
        return Err(ApiError::Conflict("IoC already exists".to_string()));
    }

    let mut ioc = CustomIoc::new(
        tenant_id,
        ioc_type,
        request.value.trim().to_string(),
        classification,
        request.source.trim().to_string(),
    );
    ioc.confidence = request.confidence.unwrap_or(0.5).clamp(0.0, 1.0);
    ioc.tags = request.tags.unwrap_or_default();
    ioc.expiration = request.expiration;
    ioc.context = request.context;
    ioc.updated_at = Utc::now();

    iocs.push(ioc.clone());
    save_iocs(&state, tenant_id, &iocs).await?;

    Ok((StatusCode::CREATED, Json(ioc_to_response(&ioc))))
}

/// GET /api/iocs/:id - Get a specific IoC.
async fn get_ioc(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
    Path(id): Path<Uuid>,
) -> Result<Json<IocResponse>, ApiError> {
    let tenant_id = tenant_id_or_default(tenant);
    let iocs = load_iocs(&state, tenant_id).await?;
    let ioc = iocs
        .iter()
        .find(|ioc| ioc.id == id)
        .ok_or_else(|| ApiError::NotFound(format!("IoC {} not found", id)))?;
    Ok(Json(ioc_to_response(ioc)))
}

/// PUT /api/iocs/:id - Update an IoC.
async fn update_ioc(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateIocApiRequest>,
) -> Result<Json<IocResponse>, ApiError> {
    let tenant_id = tenant_id_or_default(tenant);
    let mut iocs = load_iocs(&state, tenant_id).await?;
    let ioc = iocs
        .iter_mut()
        .find(|ioc| ioc.id == id)
        .ok_or_else(|| ApiError::NotFound(format!("IoC {} not found", id)))?;

    if let Some(classification) = request.classification {
        ioc.classification = parse_classification(&classification)?;
    }
    if let Some(confidence) = request.confidence {
        ioc.confidence = confidence.clamp(0.0, 1.0);
    }
    if let Some(tags) = request.tags {
        ioc.tags = tags;
    }
    if let Some(expiration) = request.expiration {
        ioc.expiration = expiration;
    }
    if let Some(context) = request.context {
        ioc.context = Some(context);
    }
    ioc.updated_at = Utc::now();

    let response = ioc_to_response(ioc);
    save_iocs(&state, tenant_id, &iocs).await?;
    Ok(Json(response))
}

/// DELETE /api/iocs/:id - Delete an IoC.
async fn delete_ioc(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let tenant_id = tenant_id_or_default(tenant);
    let mut iocs = load_iocs(&state, tenant_id).await?;
    let len_before = iocs.len();
    iocs.retain(|ioc| ioc.id != id);
    if iocs.len() == len_before {
        return Err(ApiError::NotFound(format!("IoC {} not found", id)));
    }
    save_iocs(&state, tenant_id, &iocs).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// GET /api/iocs/search - Search IoCs.
async fn search_iocs(
    State(state): State<AppState>,
    RequireAnalyst(user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
    Query(query): Query<IocSearchQuery>,
) -> Result<Json<PaginatedIocResponse>, ApiError> {
    list_iocs(
        State(state),
        RequireAnalyst(user),
        OptionalTenant(tenant),
        Query(query),
    )
    .await
}

/// POST /api/iocs/import - Bulk import IoCs.
async fn bulk_import(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
    Json(request): Json<BulkImportRequest>,
) -> Result<Json<BulkImportResponse>, ApiError> {
    let tenant_id = tenant_id_or_default(tenant);
    let mut iocs = load_iocs(&state, tenant_id).await?;
    let mut seen: HashSet<(String, String)> = iocs
        .iter()
        .map(|ioc| {
            (
                ioc.ioc_type.to_string().to_ascii_lowercase(),
                ioc.value.to_ascii_lowercase(),
            )
        })
        .collect();

    let default_classification = request
        .default_classification
        .as_deref()
        .map(parse_classification)
        .transpose()?
        .unwrap_or(IocClassification::Suspicious);
    let default_source = request
        .default_source
        .as_deref()
        .unwrap_or("bulk_import")
        .to_string();

    let mut imported = 0u64;
    let mut failed = 0u64;
    let mut duplicates = 0u64;
    let mut errors = Vec::new();

    match request.format.as_str() {
        "json" => {
            let items: Vec<CreateIocApiRequest> = serde_json::from_str(&request.data)
                .map_err(|e| ApiError::BadRequest(format!("Invalid JSON import payload: {}", e)))?;

            for (idx, item) in items.into_iter().enumerate() {
                let line = (idx + 1) as u64;
                if item.value.trim().is_empty() {
                    failed += 1;
                    errors.push(ImportErrorDetail {
                        line,
                        value: item.value,
                        error: "IoC value is required".to_string(),
                    });
                    continue;
                }

                let ioc_type = parse_ioc_type(&item.ioc_type);
                let classification = if item.classification.trim().is_empty() {
                    default_classification.clone()
                } else {
                    match parse_classification(&item.classification) {
                        Ok(c) => c,
                        Err(e) => {
                            failed += 1;
                            errors.push(ImportErrorDetail {
                                line,
                                value: item.value,
                                error: e.to_string(),
                            });
                            continue;
                        }
                    }
                };

                let key = (
                    ioc_type.to_string().to_ascii_lowercase(),
                    item.value.to_ascii_lowercase(),
                );
                if seen.contains(&key) {
                    duplicates += 1;
                    continue;
                }

                let mut ioc = CustomIoc::new(
                    tenant_id,
                    ioc_type,
                    item.value.trim().to_string(),
                    classification,
                    if item.source.trim().is_empty() {
                        default_source.clone()
                    } else {
                        item.source.trim().to_string()
                    },
                );
                ioc.confidence = item.confidence.unwrap_or(0.5).clamp(0.0, 1.0);
                ioc.tags = item.tags.unwrap_or_default();
                ioc.expiration = item.expiration;
                ioc.context = item.context;
                ioc.updated_at = Utc::now();

                iocs.push(ioc);
                seen.insert(key);
                imported += 1;
            }
        }
        "csv" => {
            for (idx, line_raw) in request.data.lines().enumerate() {
                let line = (idx + 1) as u64;
                let line_trimmed = line_raw.trim();
                if line_trimmed.is_empty() {
                    continue;
                }
                if idx == 0 && line_trimmed.to_ascii_lowercase().starts_with("ioc_type,") {
                    continue;
                }

                let cols: Vec<&str> = line_trimmed.split(',').map(|s| s.trim()).collect();
                if cols.len() < 2 {
                    failed += 1;
                    errors.push(ImportErrorDetail {
                        line,
                        value: line_trimmed.to_string(),
                        error: "Expected at least ioc_type,value".to_string(),
                    });
                    continue;
                }

                let ioc_type = parse_ioc_type(cols[0]);
                let value = cols[1].to_string();
                if value.trim().is_empty() {
                    failed += 1;
                    errors.push(ImportErrorDetail {
                        line,
                        value,
                        error: "IoC value is required".to_string(),
                    });
                    continue;
                }

                let classification = if cols.get(2).is_some_and(|c| !c.is_empty()) {
                    match parse_classification(cols[2]) {
                        Ok(c) => c,
                        Err(e) => {
                            failed += 1;
                            errors.push(ImportErrorDetail {
                                line,
                                value: value.clone(),
                                error: e.to_string(),
                            });
                            continue;
                        }
                    }
                } else {
                    default_classification.clone()
                };

                let source = cols
                    .get(3)
                    .filter(|s| !s.is_empty())
                    .copied()
                    .unwrap_or(&default_source)
                    .to_string();
                let confidence = cols
                    .get(4)
                    .and_then(|s| {
                        if s.is_empty() {
                            None
                        } else {
                            s.parse::<f32>().ok()
                        }
                    })
                    .unwrap_or(0.5)
                    .clamp(0.0, 1.0);
                let tags = cols
                    .get(5)
                    .filter(|s| !s.is_empty())
                    .map(|s| {
                        s.split(';')
                            .map(|t| t.trim().to_string())
                            .filter(|t| !t.is_empty())
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                let context = cols
                    .get(6)
                    .and_then(|s| (!s.is_empty()).then(|| s.to_string()));

                let key = (
                    ioc_type.to_string().to_ascii_lowercase(),
                    value.to_ascii_lowercase(),
                );
                if seen.contains(&key) {
                    duplicates += 1;
                    continue;
                }

                let mut ioc =
                    CustomIoc::new(tenant_id, ioc_type, value.clone(), classification, source);
                ioc.confidence = confidence;
                ioc.tags = tags;
                ioc.context = context;
                ioc.updated_at = Utc::now();

                iocs.push(ioc);
                seen.insert(key);
                imported += 1;
            }
        }
        _ => {
            return Err(ApiError::BadRequest(format!(
                "Unsupported import format: {}. Use 'csv' or 'json'.",
                request.format
            )))
        }
    }

    save_iocs(&state, tenant_id, &iocs).await?;

    Ok(Json(BulkImportResponse {
        imported,
        failed,
        duplicates,
        errors,
    }))
}

/// GET /api/iocs/lists - List IoC lists.
async fn list_ioc_lists(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
) -> Result<Json<Vec<IocListResponse>>, ApiError> {
    let tenant_id = tenant_id_or_default(tenant);
    let iocs = load_iocs(&state, tenant_id).await?;
    let now = Utc::now();

    let allow_count = iocs
        .iter()
        .filter(|ioc| ioc.classification == IocClassification::Benign)
        .count() as u64;
    let block_count = iocs
        .iter()
        .filter(|ioc| {
            matches!(
                ioc.classification,
                IocClassification::Malicious | IocClassification::Blocked
            )
        })
        .count() as u64;
    let watch_count = iocs
        .iter()
        .filter(|ioc| {
            matches!(
                ioc.classification,
                IocClassification::Suspicious | IocClassification::Informational
            )
        })
        .count() as u64;

    let lists = vec![
        IocListResponse {
            id: stable_uuid(&format!("{}:allow-list", tenant_id)),
            name: "Allow List".to_string(),
            description: Some("Known benign indicators".to_string()),
            list_type: "allow_list".to_string(),
            entry_count: allow_count,
            created_at: now,
            updated_at: now,
        },
        IocListResponse {
            id: stable_uuid(&format!("{}:block-list", tenant_id)),
            name: "Block List".to_string(),
            description: Some("Known malicious or blocked indicators".to_string()),
            list_type: "block_list".to_string(),
            entry_count: block_count,
            created_at: now,
            updated_at: now,
        },
        IocListResponse {
            id: stable_uuid(&format!("{}:watch-list", tenant_id)),
            name: "Watch List".to_string(),
            description: Some("Indicators under investigation".to_string()),
            list_type: "watch_list".to_string(),
            entry_count: watch_count,
            created_at: now,
            updated_at: now,
        },
    ];

    Ok(Json(lists))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_ioc_request_serialization() {
        let req = CreateIocApiRequest {
            ioc_type: "ipv4".to_string(),
            value: "192.168.1.100".to_string(),
            classification: "malicious".to_string(),
            source: "manual".to_string(),
            confidence: Some(0.9),
            tags: Some(vec!["c2".to_string()]),
            expiration: None,
            context: None,
        };

        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("192.168.1.100"));
    }

    #[test]
    fn test_paginated_response_serialization() {
        let resp = PaginatedIocResponse {
            data: vec![],
            total: 0,
            limit: 100,
            offset: 0,
        };

        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"total\":0"));
    }

    #[test]
    fn test_bulk_import_response() {
        let resp = BulkImportResponse {
            imported: 50,
            failed: 2,
            duplicates: 3,
            errors: vec![ImportErrorDetail {
                line: 10,
                value: "bad-value".to_string(),
                error: "Invalid format".to_string(),
            }],
        };

        assert_eq!(resp.imported, 50);
        assert_eq!(resp.errors.len(), 1);
    }

    #[test]
    fn test_ioc_search_query_defaults() {
        let json = "{}";
        let query: IocSearchQuery = serde_json::from_str(json).unwrap();
        assert!(query.ioc_type.is_none());
        assert!(query.limit.is_none());
    }
}
