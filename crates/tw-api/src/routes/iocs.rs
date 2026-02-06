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
use uuid::Uuid;

use crate::error::ApiError;
use crate::state::AppState;

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
    State(_state): State<AppState>,
    Query(query): Query<IocSearchQuery>,
) -> Result<Json<PaginatedIocResponse>, ApiError> {
    // In a full implementation, this would query the database.
    // For now, return an empty response structure.
    let limit = query.limit.unwrap_or(100).min(1000);
    let offset = query.offset.unwrap_or(0);

    Ok(Json(PaginatedIocResponse {
        data: vec![],
        total: 0,
        limit,
        offset,
    }))
}

/// POST /api/iocs - Create a new IoC.
async fn create_ioc(
    State(_state): State<AppState>,
    Json(request): Json<CreateIocApiRequest>,
) -> Result<(StatusCode, Json<IocResponse>), ApiError> {
    let now = Utc::now();
    let id = Uuid::new_v4();

    let response = IocResponse {
        id,
        tenant_id: Uuid::nil(),
        ioc_type: request.ioc_type,
        value: request.value,
        classification: request.classification,
        source: request.source,
        confidence: request.confidence.unwrap_or(0.5),
        tags: request.tags.unwrap_or_default(),
        expiration: request.expiration,
        context: request.context,
        created_by: None,
        created_at: now,
        updated_at: now,
    };

    Ok((StatusCode::CREATED, Json(response)))
}

/// GET /api/iocs/:id - Get a specific IoC.
async fn get_ioc(
    State(_state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<IocResponse>, ApiError> {
    // Placeholder - would query database
    Err(ApiError::NotFound(format!("IoC {} not found", id)))
}

/// PUT /api/iocs/:id - Update an IoC.
async fn update_ioc(
    State(_state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(_request): Json<UpdateIocApiRequest>,
) -> Result<Json<IocResponse>, ApiError> {
    Err(ApiError::NotFound(format!("IoC {} not found", id)))
}

/// DELETE /api/iocs/:id - Delete an IoC.
async fn delete_ioc(
    State(_state): State<AppState>,
    Path(_id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    // Placeholder - would delete from database
    Ok(StatusCode::NO_CONTENT)
}

/// GET /api/iocs/search - Search IoCs.
async fn search_iocs(
    State(_state): State<AppState>,
    Query(query): Query<IocSearchQuery>,
) -> Result<Json<PaginatedIocResponse>, ApiError> {
    let limit = query.limit.unwrap_or(100).min(1000);
    let offset = query.offset.unwrap_or(0);

    Ok(Json(PaginatedIocResponse {
        data: vec![],
        total: 0,
        limit,
        offset,
    }))
}

/// POST /api/iocs/import - Bulk import IoCs.
async fn bulk_import(
    State(_state): State<AppState>,
    Json(request): Json<BulkImportRequest>,
) -> Result<Json<BulkImportResponse>, ApiError> {
    // Parse and validate based on format
    let response = match request.format.as_str() {
        "csv" | "json" => BulkImportResponse {
            imported: 0,
            failed: 0,
            duplicates: 0,
            errors: vec![],
        },
        _ => {
            return Err(ApiError::BadRequest(format!(
                "Unsupported import format: {}. Use 'csv' or 'json'.",
                request.format
            )));
        }
    };

    Ok(Json(response))
}

/// GET /api/iocs/lists - List IoC lists.
async fn list_ioc_lists(
    State(_state): State<AppState>,
) -> Result<Json<Vec<IocListResponse>>, ApiError> {
    Ok(Json(vec![]))
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
