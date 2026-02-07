//! Knowledge base management endpoints.
//!
//! This module provides API endpoints for managing knowledge base documents
//! including runbooks, threat intel reports, security policies, and more.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{delete, get, post, put},
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;

use crate::auth::RequireAnalyst;
use crate::error::ApiError;
use crate::middleware::OptionalTenant;
use crate::state::AppState;
use tw_core::auth::DEFAULT_TENANT_ID;
use tw_core::db::{create_knowledge_repository, Pagination};
use tw_core::knowledge::{
    CreateKnowledgeDocument, DocumentMetadata, KnowledgeDocument, KnowledgeFilter, KnowledgeStats,
    KnowledgeType, UpdateKnowledgeDocument,
};

/// Creates knowledge base routes.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(list_documents))
        .route("/", post(create_document))
        .route("/search", get(search_documents))
        .route("/stats", get(get_stats))
        .route("/types", get(list_document_types))
        .route("/:id", get(get_document))
        .route("/:id", put(update_document))
        .route("/:id", delete(delete_document))
        .route("/:id/reindex", post(reindex_document))
}

fn tenant_id_or_default(tenant: Option<tw_core::tenant::TenantContext>) -> Uuid {
    tenant.map(|ctx| ctx.tenant_id).unwrap_or(DEFAULT_TENANT_ID)
}

/// Topic for asynchronous knowledge indexing jobs.
const KNOWLEDGE_INDEXING_TOPIC: &str = "knowledge.indexing";

#[derive(Debug, Clone, Copy)]
enum KnowledgeIndexAction {
    Upsert,
    Delete,
}

impl KnowledgeIndexAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Upsert => "upsert",
            Self::Delete => "delete",
        }
    }
}

#[derive(Debug, Serialize)]
struct KnowledgeIndexJob {
    action: &'static str,
    tenant_id: Uuid,
    document_id: Uuid,
    queued_at: DateTime<Utc>,
}

fn build_knowledge_index_job(
    action: KnowledgeIndexAction,
    tenant_id: Uuid,
    document_id: Uuid,
) -> KnowledgeIndexJob {
    KnowledgeIndexJob {
        action: action.as_str(),
        tenant_id,
        document_id,
        queued_at: Utc::now(),
    }
}

/// Triggers asynchronous indexing or deletion for a knowledge document.
///
/// Priority:
/// 1) If a message queue is configured, publish a job for an external worker.
/// 2) Otherwise, for upsert actions, perform a local async fallback and mark
///    the document as indexed.
async fn trigger_knowledge_index_job(
    state: &AppState,
    tenant_id: Uuid,
    document_id: Uuid,
    action: KnowledgeIndexAction,
) {
    let job = build_knowledge_index_job(action, tenant_id, document_id);

    if let Some(queue) = &state.message_queue {
        match serde_json::to_vec(&job) {
            Ok(payload) => match queue.publish(KNOWLEDGE_INDEXING_TOPIC, &payload).await {
                Ok(message_id) => {
                    debug!(
                        %message_id,
                        tenant_id = %tenant_id,
                        document_id = %document_id,
                        action = job.action,
                        "Published knowledge indexing job"
                    );
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        tenant_id = %tenant_id,
                        document_id = %document_id,
                        action = job.action,
                        "Failed to publish knowledge indexing job"
                    );
                }
            },
            Err(e) => {
                warn!(
                    error = %e,
                    tenant_id = %tenant_id,
                    document_id = %document_id,
                    action = job.action,
                    "Failed to serialize knowledge indexing job"
                );
            }
        }
        return;
    }

    if matches!(action, KnowledgeIndexAction::Upsert) {
        let db = state.db.clone();
        tokio::spawn(async move {
            let repo = create_knowledge_repository(db.as_ref());
            if let Err(e) = repo.mark_indexed(document_id, Utc::now()).await {
                warn!(
                    error = %e,
                    document_id = %document_id,
                    "Local knowledge indexing fallback failed"
                );
                return;
            }

            debug!(
                document_id = %document_id,
                "Local knowledge indexing fallback completed"
            );
        });
    } else {
        debug!(
            tenant_id = %tenant_id,
            document_id = %document_id,
            "No queue configured; skipping async knowledge deletion hook"
        );
    }
}

// ============================================================================
// Request/Response DTOs
// ============================================================================

/// Query parameters for listing knowledge documents.
#[derive(Debug, Clone, Deserialize, Validate, ToSchema)]
pub struct ListQuery {
    /// Filter by document types (comma-separated).
    pub doc_types: Option<String>,
    /// Filter by active status.
    pub is_active: Option<bool>,
    /// Filter by tags (comma-separated).
    pub tags: Option<String>,
    /// Full-text search query.
    pub search: Option<String>,
    /// Created after this timestamp.
    pub created_after: Option<DateTime<Utc>>,
    /// Created before this timestamp.
    pub created_before: Option<DateTime<Utc>>,
    /// Page number (1-indexed).
    #[validate(range(min = 1))]
    pub page: Option<u32>,
    /// Items per page.
    #[validate(range(min = 1, max = 100))]
    pub per_page: Option<u32>,
}

impl ListQuery {
    fn to_filter(&self) -> KnowledgeFilter {
        let doc_types = self.doc_types.as_ref().map(|types| {
            types
                .split(',')
                .filter_map(|t| KnowledgeType::parse(t.trim()))
                .collect()
        });

        let tags = self
            .tags
            .as_ref()
            .map(|t| t.split(',').map(|s| s.trim().to_string()).collect());

        KnowledgeFilter {
            doc_types,
            tags,
            is_active: self.is_active,
            search_query: self.search.clone(),
            created_after: self.created_after,
            created_before: self.created_before,
            ..Default::default()
        }
    }
}

/// Query parameters for semantic search.
#[derive(Debug, Clone, Deserialize, Validate, ToSchema)]
pub struct SearchQuery {
    /// Search query text (required).
    pub q: String,
    /// Filter by document types (comma-separated).
    pub doc_types: Option<String>,
    /// Maximum results to return.
    #[validate(range(min = 1, max = 50))]
    pub limit: Option<usize>,
}

/// Request body for creating a document.
#[derive(Debug, Clone, Deserialize, Validate, ToSchema)]
pub struct CreateDocumentRequest {
    /// Document type.
    pub doc_type: String,
    /// Document title.
    #[validate(length(min = 1, max = 500))]
    pub title: String,
    /// Document content (markdown or plain text).
    #[validate(length(min = 1))]
    pub content: String,
    /// Optional summary.
    #[validate(length(max = 2000))]
    pub summary: Option<String>,
    /// Optional metadata.
    pub metadata: Option<MetadataRequest>,
}

/// Request body for updating a document.
#[derive(Debug, Clone, Deserialize, Validate, ToSchema)]
pub struct UpdateDocumentRequest {
    /// Updated title.
    #[validate(length(min = 1, max = 500))]
    pub title: Option<String>,
    /// Updated content.
    pub content: Option<String>,
    /// Updated summary.
    #[validate(length(max = 2000))]
    pub summary: Option<String>,
    /// Updated document type.
    pub doc_type: Option<String>,
    /// Updated metadata.
    pub metadata: Option<MetadataRequest>,
    /// Update active status.
    pub is_active: Option<bool>,
}

/// Metadata in API requests.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct MetadataRequest {
    /// Document author.
    pub author: Option<String>,
    /// Version string.
    pub version: Option<String>,
    /// Source URL.
    pub source_url: Option<String>,
    /// MITRE ATT&CK technique IDs.
    pub mitre_techniques: Option<Vec<String>>,
    /// Related incident types.
    pub related_incident_types: Option<Vec<String>>,
    /// Keywords for search.
    pub keywords: Option<Vec<String>>,
    /// Tags for categorization.
    pub tags: Option<Vec<String>>,
}

impl MetadataRequest {
    fn to_metadata(&self) -> DocumentMetadata {
        let mut meta = DocumentMetadata::new();

        if let Some(ref author) = self.author {
            meta.author = Some(author.clone());
        }
        if let Some(ref version) = self.version {
            meta.version = Some(version.clone());
        }
        if let Some(ref url) = self.source_url {
            meta.source_url = Some(url.clone());
        }
        if let Some(ref techniques) = self.mitre_techniques {
            meta.mitre_techniques = techniques.clone();
        }
        if let Some(ref types) = self.related_incident_types {
            meta.related_incident_types = types.clone();
        }
        if let Some(ref keywords) = self.keywords {
            meta.keywords = keywords.clone();
        }
        if let Some(ref tags) = self.tags {
            meta.tags = tags.clone();
        }

        meta
    }
}

/// Response for a single document.
#[derive(Debug, Serialize, ToSchema)]
pub struct DocumentResponse {
    pub id: Uuid,
    pub doc_type: String,
    pub title: String,
    pub content: String,
    pub summary: Option<String>,
    pub metadata: MetadataResponse,
    pub is_active: bool,
    pub is_indexed: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub indexed_at: Option<DateTime<Utc>>,
    pub created_by: Option<Uuid>,
    pub updated_by: Option<Uuid>,
}

impl From<KnowledgeDocument> for DocumentResponse {
    fn from(doc: KnowledgeDocument) -> Self {
        Self {
            id: doc.id,
            doc_type: doc.doc_type.as_str().to_string(),
            title: doc.title,
            content: doc.content,
            summary: doc.summary,
            metadata: MetadataResponse::from(doc.metadata),
            is_active: doc.is_active,
            is_indexed: doc.indexed_at.is_some(),
            created_at: doc.created_at,
            updated_at: doc.updated_at,
            indexed_at: doc.indexed_at,
            created_by: doc.created_by,
            updated_by: doc.updated_by,
        }
    }
}

/// Metadata in API responses.
#[derive(Debug, Serialize, ToSchema)]
pub struct MetadataResponse {
    pub author: Option<String>,
    pub version: Option<String>,
    pub source_url: Option<String>,
    pub mitre_techniques: Vec<String>,
    pub related_incident_types: Vec<String>,
    pub keywords: Vec<String>,
    pub tags: Vec<String>,
    pub original_format: Option<String>,
    pub original_filename: Option<String>,
}

impl From<DocumentMetadata> for MetadataResponse {
    fn from(meta: DocumentMetadata) -> Self {
        Self {
            author: meta.author,
            version: meta.version,
            source_url: meta.source_url,
            mitre_techniques: meta.mitre_techniques,
            related_incident_types: meta.related_incident_types,
            keywords: meta.keywords,
            tags: meta.tags,
            original_format: meta.original_format,
            original_filename: meta.original_filename,
        }
    }
}

/// Paginated list response.
#[derive(Debug, Serialize, ToSchema)]
pub struct DocumentListResponse {
    pub items: Vec<DocumentResponse>,
    pub total: u64,
    pub page: u32,
    pub per_page: u32,
    pub total_pages: u32,
}

/// Search result response.
#[derive(Debug, Serialize, ToSchema)]
pub struct SearchResultResponse {
    pub document_id: Uuid,
    pub title: String,
    pub doc_type: String,
    pub score: f32,
    pub snippet: Option<String>,
    pub tags: Vec<String>,
    pub mitre_techniques: Vec<String>,
}

/// Search results response.
#[derive(Debug, Serialize, ToSchema)]
pub struct SearchResponse {
    pub results: Vec<SearchResultResponse>,
    pub query: String,
    pub total: usize,
}

/// Statistics response.
#[derive(Debug, Serialize, ToSchema)]
pub struct StatsResponse {
    pub total_documents: u64,
    pub indexed_documents: u64,
    pub by_type: std::collections::HashMap<String, u64>,
    pub top_tags: Vec<TagCount>,
    pub top_mitre_techniques: Vec<TagCount>,
}

/// Tag count for statistics.
#[derive(Debug, Serialize, ToSchema)]
pub struct TagCount {
    pub name: String,
    pub count: u64,
}

impl From<KnowledgeStats> for StatsResponse {
    fn from(stats: KnowledgeStats) -> Self {
        Self {
            total_documents: stats.total_documents,
            indexed_documents: stats.indexed_documents,
            by_type: stats.by_type,
            top_tags: stats
                .top_tags
                .into_iter()
                .map(|(name, count)| TagCount { name, count })
                .collect(),
            top_mitre_techniques: stats
                .top_mitre_techniques
                .into_iter()
                .map(|(name, count)| TagCount { name, count })
                .collect(),
        }
    }
}

/// Document type info.
#[derive(Debug, Serialize, ToSchema)]
pub struct DocumentTypeInfo {
    pub value: String,
    pub label: String,
    pub description: String,
}

// ============================================================================
// Route Handlers
// ============================================================================

/// List knowledge documents.
#[utoipa::path(
    get,
    path = "/api/knowledge",
    params(
        ("doc_types" = Option<String>, Query, description = "Filter by document types (comma-separated)"),
        ("is_active" = Option<bool>, Query, description = "Filter by active status"),
        ("tags" = Option<String>, Query, description = "Filter by tags (comma-separated)"),
        ("search" = Option<String>, Query, description = "Full-text search query"),
        ("page" = Option<u32>, Query, description = "Page number (1-indexed)"),
        ("per_page" = Option<u32>, Query, description = "Items per page (max 100)"),
    ),
    responses(
        (status = 200, description = "Documents retrieved", body = DocumentListResponse),
        (status = 400, description = "Invalid query parameters"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Knowledge"
)]
async fn list_documents(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
    Query(query): Query<ListQuery>,
) -> Result<Json<DocumentListResponse>, ApiError> {
    query.validate()?;

    let tenant_id = tenant_id_or_default(tenant);
    let repo = create_knowledge_repository(&state.db);
    let filter = query.to_filter();
    let page = query.page.unwrap_or(1);
    let per_page = query.per_page.unwrap_or(20);
    let pagination = Pagination::new(page, per_page);

    let result = repo
        .list(tenant_id, &filter, &pagination)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let total_pages = ((result.total as f64) / (per_page as f64)).ceil() as u32;

    Ok(Json(DocumentListResponse {
        items: result
            .items
            .into_iter()
            .map(DocumentResponse::from)
            .collect(),
        total: result.total,
        page,
        per_page,
        total_pages,
    }))
}

/// Create a new knowledge document.
#[utoipa::path(
    post,
    path = "/api/knowledge",
    request_body = CreateDocumentRequest,
    responses(
        (status = 201, description = "Document created", body = DocumentResponse),
        (status = 400, description = "Invalid request body"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Knowledge"
)]
async fn create_document(
    State(state): State<AppState>,
    RequireAnalyst(user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
    Json(request): Json<CreateDocumentRequest>,
) -> Result<(StatusCode, Json<DocumentResponse>), ApiError> {
    request.validate()?;

    let tenant_id = tenant_id_or_default(tenant);
    let doc_type = KnowledgeType::parse(&request.doc_type).ok_or_else(|| {
        ApiError::BadRequest(format!("Invalid document type: {}", request.doc_type))
    })?;

    let create = CreateKnowledgeDocument {
        doc_type,
        title: request.title,
        content: request.content,
        summary: request.summary,
        metadata: request.metadata.map(|m| m.to_metadata()),
    };

    let document = create.build(tenant_id, Some(user.id));

    let repo = create_knowledge_repository(&state.db);
    let created = repo
        .create(&document)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    trigger_knowledge_index_job(&state, tenant_id, created.id, KnowledgeIndexAction::Upsert).await;

    Ok((StatusCode::CREATED, Json(DocumentResponse::from(created))))
}

/// Get a knowledge document by ID.
#[utoipa::path(
    get,
    path = "/api/knowledge/{id}",
    params(
        ("id" = Uuid, Path, description = "Document ID")
    ),
    responses(
        (status = 200, description = "Document retrieved", body = DocumentResponse),
        (status = 404, description = "Document not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Knowledge"
)]
async fn get_document(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
    Path(id): Path<Uuid>,
) -> Result<Json<DocumentResponse>, ApiError> {
    let tenant_id = tenant_id_or_default(tenant);
    let repo = create_knowledge_repository(&state.db);

    let document = repo
        .get_for_tenant(id, tenant_id)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .ok_or(ApiError::NotFound("Document not found".to_string()))?;

    Ok(Json(DocumentResponse::from(document)))
}

/// Update a knowledge document.
#[utoipa::path(
    put,
    path = "/api/knowledge/{id}",
    params(
        ("id" = Uuid, Path, description = "Document ID")
    ),
    request_body = UpdateDocumentRequest,
    responses(
        (status = 200, description = "Document updated", body = DocumentResponse),
        (status = 400, description = "Invalid request body"),
        (status = 404, description = "Document not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Knowledge"
)]
async fn update_document(
    State(state): State<AppState>,
    RequireAnalyst(user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateDocumentRequest>,
) -> Result<Json<DocumentResponse>, ApiError> {
    request.validate()?;

    let tenant_id = tenant_id_or_default(tenant);
    let doc_type = request
        .doc_type
        .as_ref()
        .map(|t| {
            KnowledgeType::parse(t)
                .ok_or_else(|| ApiError::BadRequest(format!("Invalid document type: {}", t)))
        })
        .transpose()?;

    let update = UpdateKnowledgeDocument {
        title: request.title,
        content: request.content,
        summary: request.summary,
        doc_type,
        metadata: request.metadata.map(|m| m.to_metadata()),
        is_active: request.is_active,
    };

    let repo = create_knowledge_repository(&state.db);

    let updated = repo
        .update(id, tenant_id, &update, Some(user.id))
        .await
        .map_err(|e| match e {
            tw_core::db::DbError::NotFound { .. } => {
                ApiError::NotFound("Document not found".to_string())
            }
            _ => ApiError::Internal(e.to_string()),
        })?;

    trigger_knowledge_index_job(&state, tenant_id, updated.id, KnowledgeIndexAction::Upsert).await;

    Ok(Json(DocumentResponse::from(updated)))
}

/// Delete a knowledge document.
#[utoipa::path(
    delete,
    path = "/api/knowledge/{id}",
    params(
        ("id" = Uuid, Path, description = "Document ID")
    ),
    responses(
        (status = 204, description = "Document deleted"),
        (status = 404, description = "Document not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Knowledge"
)]
async fn delete_document(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let tenant_id = tenant_id_or_default(tenant);
    let repo = create_knowledge_repository(&state.db);

    let deleted = repo
        .delete(id, tenant_id)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    if !deleted {
        return Err(ApiError::NotFound("Document not found".to_string()));
    }

    trigger_knowledge_index_job(&state, tenant_id, id, KnowledgeIndexAction::Delete).await;

    Ok(StatusCode::NO_CONTENT)
}

/// Semantic search over knowledge documents.
#[utoipa::path(
    get,
    path = "/api/knowledge/search",
    params(
        ("q" = String, Query, description = "Search query text"),
        ("doc_types" = Option<String>, Query, description = "Filter by document types (comma-separated)"),
        ("limit" = Option<usize>, Query, description = "Maximum results (default: 10, max: 50)"),
    ),
    responses(
        (status = 200, description = "Search results", body = SearchResponse),
        (status = 400, description = "Invalid query parameters"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Knowledge"
)]
async fn search_documents(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
    Query(query): Query<SearchQuery>,
) -> Result<Json<SearchResponse>, ApiError> {
    query.validate()?;

    if query.q.trim().is_empty() {
        return Err(ApiError::BadRequest(
            "Search query cannot be empty".to_string(),
        ));
    }

    let tenant_id = tenant_id_or_default(tenant);
    let repo = create_knowledge_repository(&state.db);
    let limit = query.limit.unwrap_or(10).min(50);

    // Build filter for full-text search
    let filter = KnowledgeFilter {
        doc_types: query.doc_types.as_ref().map(|types| {
            types
                .split(',')
                .filter_map(|t| KnowledgeType::parse(t.trim()))
                .collect()
        }),
        is_active: Some(true),
        ..Default::default()
    };

    // Use text search (for now, semantic search requires embedding service integration)
    let documents = repo
        .search_text(tenant_id, &query.q, &filter, limit)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let results: Vec<SearchResultResponse> = documents
        .into_iter()
        .map(|doc| SearchResultResponse {
            document_id: doc.id,
            title: doc.title,
            doc_type: doc.doc_type.as_str().to_string(),
            score: 1.0, // Text search doesn't have a score, use 1.0 as placeholder
            snippet: doc.summary.or_else(|| {
                // Generate snippet from content
                let content = &doc.content;
                if content.len() > 200 {
                    Some(format!("{}...", &content[..200]))
                } else {
                    Some(content.clone())
                }
            }),
            tags: doc.metadata.tags,
            mitre_techniques: doc.metadata.mitre_techniques,
        })
        .collect();

    let total = results.len();

    Ok(Json(SearchResponse {
        results,
        query: query.q,
        total,
    }))
}

/// Get knowledge base statistics.
#[utoipa::path(
    get,
    path = "/api/knowledge/stats",
    responses(
        (status = 200, description = "Statistics retrieved", body = StatsResponse),
        (status = 500, description = "Internal server error")
    ),
    tag = "Knowledge"
)]
async fn get_stats(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
) -> Result<Json<StatsResponse>, ApiError> {
    let tenant_id = tenant_id_or_default(tenant);
    let repo = create_knowledge_repository(&state.db);

    let stats = repo
        .get_stats(tenant_id)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    Ok(Json(StatsResponse::from(stats)))
}

/// List available document types.
#[utoipa::path(
    get,
    path = "/api/knowledge/types",
    responses(
        (status = 200, description = "Document types", body = Vec<DocumentTypeInfo>),
    ),
    tag = "Knowledge"
)]
async fn list_document_types(RequireAnalyst(_user): RequireAnalyst) -> Json<Vec<DocumentTypeInfo>> {
    let types: Vec<DocumentTypeInfo> = KnowledgeType::all()
        .iter()
        .map(|t| DocumentTypeInfo {
            value: t.as_str().to_string(),
            label: format!("{:?}", t),
            description: t.description().to_string(),
        })
        .collect();

    Json(types)
}

/// Trigger re-indexing of a document.
#[utoipa::path(
    post,
    path = "/api/knowledge/{id}/reindex",
    params(
        ("id" = Uuid, Path, description = "Document ID")
    ),
    responses(
        (status = 202, description = "Re-indexing triggered"),
        (status = 404, description = "Document not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Knowledge"
)]
async fn reindex_document(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let tenant_id = tenant_id_or_default(tenant);
    let repo = create_knowledge_repository(&state.db);

    // Verify document exists
    let _document = repo
        .get_for_tenant(id, tenant_id)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .ok_or(ApiError::NotFound("Document not found".to_string()))?;

    trigger_knowledge_index_job(&state, tenant_id, id, KnowledgeIndexAction::Upsert).await;

    Ok(StatusCode::ACCEPTED)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metadata_request_to_metadata() {
        let request = MetadataRequest {
            author: Some("Test Author".to_string()),
            version: Some("1.0".to_string()),
            source_url: None,
            mitre_techniques: Some(vec!["T1566".to_string()]),
            related_incident_types: None,
            keywords: Some(vec!["phishing".to_string()]),
            tags: Some(vec!["security".to_string()]),
        };

        let meta = request.to_metadata();

        assert_eq!(meta.author, Some("Test Author".to_string()));
        assert_eq!(meta.version, Some("1.0".to_string()));
        assert_eq!(meta.mitre_techniques, vec!["T1566".to_string()]);
        assert_eq!(meta.keywords, vec!["phishing".to_string()]);
        assert_eq!(meta.tags, vec!["security".to_string()]);
    }

    #[test]
    fn test_list_query_to_filter() {
        let query = ListQuery {
            doc_types: Some("runbook,security_policy".to_string()),
            is_active: Some(true),
            tags: Some("phishing,email".to_string()),
            search: Some("response".to_string()),
            created_after: None,
            created_before: None,
            page: None,
            per_page: None,
        };

        let filter = query.to_filter();

        assert!(filter.doc_types.is_some());
        let types = filter.doc_types.unwrap();
        assert_eq!(types.len(), 2);
        assert!(types.contains(&KnowledgeType::Runbook));
        assert!(types.contains(&KnowledgeType::SecurityPolicy));

        assert_eq!(filter.is_active, Some(true));
        assert_eq!(filter.search_query, Some("response".to_string()));

        let tags = filter.tags.unwrap();
        assert_eq!(tags.len(), 2);
    }

    #[test]
    fn test_knowledge_index_action_as_str() {
        assert_eq!(KnowledgeIndexAction::Upsert.as_str(), "upsert");
        assert_eq!(KnowledgeIndexAction::Delete.as_str(), "delete");
    }

    #[test]
    fn test_build_knowledge_index_job() {
        let tenant_id = Uuid::new_v4();
        let document_id = Uuid::new_v4();

        let job = build_knowledge_index_job(KnowledgeIndexAction::Upsert, tenant_id, document_id);

        assert_eq!(job.action, "upsert");
        assert_eq!(job.tenant_id, tenant_id);
        assert_eq!(job.document_id, document_id);
    }
}
