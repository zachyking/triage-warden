//! Knowledge document repository for database operations.
//!
//! This module provides persistence for knowledge base documents used in RAG,
//! supporting both SQLite and PostgreSQL backends.

use super::pagination::{PaginatedResult, Pagination};
use super::{DbError, DbPool};
use crate::knowledge::{
    KnowledgeDocument, KnowledgeFilter, KnowledgeStats, KnowledgeType, UpdateKnowledgeDocument,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Repository trait for knowledge document persistence.
///
/// All methods that query or modify documents are tenant-scoped for security.
#[async_trait]
pub trait KnowledgeRepository: Send + Sync {
    /// Creates a new knowledge document.
    async fn create(&self, document: &KnowledgeDocument) -> Result<KnowledgeDocument, DbError>;

    /// Gets a document by ID without tenant scoping (admin use only).
    async fn get(&self, id: Uuid) -> Result<Option<KnowledgeDocument>, DbError>;

    /// Gets a document by ID, scoped to a specific tenant.
    async fn get_for_tenant(
        &self,
        id: Uuid,
        tenant_id: Uuid,
    ) -> Result<Option<KnowledgeDocument>, DbError>;

    /// Lists documents with optional filtering and pagination.
    async fn list(
        &self,
        tenant_id: Uuid,
        filter: &KnowledgeFilter,
        pagination: &Pagination,
    ) -> Result<PaginatedResult<KnowledgeDocument>, DbError>;

    /// Counts documents matching the filter.
    async fn count(&self, tenant_id: Uuid, filter: &KnowledgeFilter) -> Result<u64, DbError>;

    /// Updates a document.
    async fn update(
        &self,
        id: Uuid,
        tenant_id: Uuid,
        update: &UpdateKnowledgeDocument,
        updated_by: Option<Uuid>,
    ) -> Result<KnowledgeDocument, DbError>;

    /// Marks a document's indexed_at timestamp.
    async fn mark_indexed(&self, id: Uuid, indexed_at: DateTime<Utc>) -> Result<(), DbError>;

    /// Deletes a document.
    async fn delete(&self, id: Uuid, tenant_id: Uuid) -> Result<bool, DbError>;

    /// Gets documents that need indexing (indexed_at is null or before updated_at).
    async fn get_needs_indexing(
        &self,
        tenant_id: Uuid,
        limit: usize,
    ) -> Result<Vec<KnowledgeDocument>, DbError>;

    /// Full-text search within documents.
    async fn search_text(
        &self,
        tenant_id: Uuid,
        query: &str,
        filter: &KnowledgeFilter,
        limit: usize,
    ) -> Result<Vec<KnowledgeDocument>, DbError>;

    /// Gets aggregate statistics about the knowledge base.
    async fn get_stats(&self, tenant_id: Uuid) -> Result<KnowledgeStats, DbError>;

    /// Gets all documents by type.
    async fn get_by_type(
        &self,
        tenant_id: Uuid,
        doc_type: KnowledgeType,
        limit: usize,
    ) -> Result<Vec<KnowledgeDocument>, DbError>;
}

/// SQLite implementation of KnowledgeRepository.
#[cfg(feature = "database")]
pub struct SqliteKnowledgeRepository {
    pool: sqlx::SqlitePool,
}

#[cfg(feature = "database")]
impl SqliteKnowledgeRepository {
    pub fn new(pool: sqlx::SqlitePool) -> Self {
        Self { pool }
    }
}

#[cfg(feature = "database")]
#[async_trait]
impl KnowledgeRepository for SqliteKnowledgeRepository {
    async fn create(&self, document: &KnowledgeDocument) -> Result<KnowledgeDocument, DbError> {
        let id = document.id.to_string();
        let tenant_id = document.tenant_id.to_string();
        let doc_type = document.doc_type.as_str();
        let metadata = serde_json::to_string(&document.metadata)?;
        let created_at = document.created_at.to_rfc3339();
        let updated_at = document.updated_at.to_rfc3339();
        let indexed_at = document.indexed_at.map(|t| t.to_rfc3339());
        let created_by = document.created_by.map(|u| u.to_string());
        let updated_by = document.updated_by.map(|u| u.to_string());

        sqlx::query(
            r#"
            INSERT INTO knowledge_documents (
                id, tenant_id, doc_type, title, content, summary,
                metadata, is_active, created_at, updated_at, indexed_at,
                created_by, updated_by
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&id)
        .bind(&tenant_id)
        .bind(doc_type)
        .bind(&document.title)
        .bind(&document.content)
        .bind(&document.summary)
        .bind(&metadata)
        .bind(document.is_active as i32)
        .bind(&created_at)
        .bind(&updated_at)
        .bind(&indexed_at)
        .bind(&created_by)
        .bind(&updated_by)
        .execute(&self.pool)
        .await?;

        Ok(document.clone())
    }

    async fn get(&self, id: Uuid) -> Result<Option<KnowledgeDocument>, DbError> {
        let id_str = id.to_string();

        let row: Option<KnowledgeRow> = sqlx::query_as(
            r#"
            SELECT id, tenant_id, doc_type, title, content, summary,
                   metadata, is_active, created_at, updated_at, indexed_at,
                   created_by, updated_by
            FROM knowledge_documents
            WHERE id = ?
            "#,
        )
        .bind(&id_str)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => Ok(Some(row.try_into()?)),
            None => Ok(None),
        }
    }

    async fn get_for_tenant(
        &self,
        id: Uuid,
        tenant_id: Uuid,
    ) -> Result<Option<KnowledgeDocument>, DbError> {
        let id_str = id.to_string();
        let tenant_id_str = tenant_id.to_string();

        let row: Option<KnowledgeRow> = sqlx::query_as(
            r#"
            SELECT id, tenant_id, doc_type, title, content, summary,
                   metadata, is_active, created_at, updated_at, indexed_at,
                   created_by, updated_by
            FROM knowledge_documents
            WHERE id = ? AND tenant_id = ?
            "#,
        )
        .bind(&id_str)
        .bind(&tenant_id_str)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => Ok(Some(row.try_into()?)),
            None => Ok(None),
        }
    }

    async fn list(
        &self,
        tenant_id: Uuid,
        filter: &KnowledgeFilter,
        pagination: &Pagination,
    ) -> Result<PaginatedResult<KnowledgeDocument>, DbError> {
        let tenant_id_str = tenant_id.to_string();

        let mut query = String::from(
            r#"
            SELECT id, tenant_id, doc_type, title, content, summary,
                   metadata, is_active, created_at, updated_at, indexed_at,
                   created_by, updated_by
            FROM knowledge_documents
            WHERE tenant_id = ?
            "#,
        );

        let mut count_query =
            String::from("SELECT COUNT(*) FROM knowledge_documents WHERE tenant_id = ?");

        // Build filter clauses
        if let Some(ref doc_types) = filter.doc_types {
            if !doc_types.is_empty() {
                let placeholders: Vec<String> = doc_types.iter().map(|_| "?".to_string()).collect();
                let clause = format!(" AND doc_type IN ({})", placeholders.join(", "));
                query.push_str(&clause);
                count_query.push_str(&clause);
            }
        }

        if let Some(is_active) = filter.is_active {
            let clause = format!(" AND is_active = {}", if is_active { 1 } else { 0 });
            query.push_str(&clause);
            count_query.push_str(&clause);
        }

        if filter.created_after.is_some() {
            query.push_str(" AND created_at >= ?");
            count_query.push_str(" AND created_at >= ?");
        }

        if filter.created_before.is_some() {
            query.push_str(" AND created_at <= ?");
            count_query.push_str(" AND created_at <= ?");
        }

        query.push_str(" ORDER BY created_at DESC LIMIT ? OFFSET ?");

        // Build query with bindings
        let mut query_builder = sqlx::query_as::<_, KnowledgeRow>(&query);
        query_builder = query_builder.bind(&tenant_id_str);

        if let Some(ref doc_types) = filter.doc_types {
            for dt in doc_types {
                query_builder = query_builder.bind(dt.as_str());
            }
        }

        if let Some(created_after) = filter.created_after {
            query_builder = query_builder.bind(created_after.to_rfc3339());
        }

        if let Some(created_before) = filter.created_before {
            query_builder = query_builder.bind(created_before.to_rfc3339());
        }

        query_builder = query_builder
            .bind(pagination.limit() as i64)
            .bind(pagination.offset() as i64);

        let rows: Vec<KnowledgeRow> = query_builder.fetch_all(&self.pool).await?;
        let items: Result<Vec<KnowledgeDocument>, DbError> =
            rows.into_iter().map(|r| r.try_into()).collect();

        // Get total count
        let mut count_builder = sqlx::query_scalar::<_, i64>(&count_query);
        count_builder = count_builder.bind(&tenant_id_str);

        if let Some(ref doc_types) = filter.doc_types {
            for dt in doc_types {
                count_builder = count_builder.bind(dt.as_str());
            }
        }

        if let Some(created_after) = filter.created_after {
            count_builder = count_builder.bind(created_after.to_rfc3339());
        }

        if let Some(created_before) = filter.created_before {
            count_builder = count_builder.bind(created_before.to_rfc3339());
        }

        let total: i64 = count_builder.fetch_one(&self.pool).await?;

        Ok(PaginatedResult::new(items?, total as u64, pagination))
    }

    async fn count(&self, tenant_id: Uuid, filter: &KnowledgeFilter) -> Result<u64, DbError> {
        let tenant_id_str = tenant_id.to_string();

        let mut query =
            String::from("SELECT COUNT(*) FROM knowledge_documents WHERE tenant_id = ?");

        if let Some(ref doc_types) = filter.doc_types {
            if !doc_types.is_empty() {
                let placeholders: Vec<String> = doc_types.iter().map(|_| "?".to_string()).collect();
                query.push_str(&format!(" AND doc_type IN ({})", placeholders.join(", ")));
            }
        }

        if let Some(is_active) = filter.is_active {
            query.push_str(&format!(
                " AND is_active = {}",
                if is_active { 1 } else { 0 }
            ));
        }

        let mut query_builder = sqlx::query_scalar::<_, i64>(&query);
        query_builder = query_builder.bind(&tenant_id_str);

        if let Some(ref doc_types) = filter.doc_types {
            for dt in doc_types {
                query_builder = query_builder.bind(dt.as_str());
            }
        }

        let count: i64 = query_builder.fetch_one(&self.pool).await?;
        Ok(count as u64)
    }

    async fn update(
        &self,
        id: Uuid,
        tenant_id: Uuid,
        update: &UpdateKnowledgeDocument,
        updated_by: Option<Uuid>,
    ) -> Result<KnowledgeDocument, DbError> {
        let id_str = id.to_string();
        let tenant_id_str = tenant_id.to_string();
        let now = Utc::now().to_rfc3339();
        let updated_by_str = updated_by.map(|u| u.to_string());

        let mut set_clauses = vec!["updated_at = ?".to_string()];
        let mut content_changed = false;

        if update.title.is_some() {
            set_clauses.push("title = ?".to_string());
            content_changed = true;
        }
        if update.content.is_some() {
            set_clauses.push("content = ?".to_string());
            content_changed = true;
        }
        if update.summary.is_some() {
            set_clauses.push("summary = ?".to_string());
        }
        if update.doc_type.is_some() {
            set_clauses.push("doc_type = ?".to_string());
        }
        if update.metadata.is_some() {
            set_clauses.push("metadata = ?".to_string());
            content_changed = true;
        }
        if update.is_active.is_some() {
            set_clauses.push("is_active = ?".to_string());
        }
        if updated_by.is_some() {
            set_clauses.push("updated_by = ?".to_string());
        }
        if content_changed {
            set_clauses.push("indexed_at = NULL".to_string());
        }

        let query = format!(
            "UPDATE knowledge_documents SET {} WHERE id = ? AND tenant_id = ?",
            set_clauses.join(", ")
        );

        let mut query_builder = sqlx::query(&query);
        query_builder = query_builder.bind(&now);

        if let Some(ref title) = update.title {
            query_builder = query_builder.bind(title);
        }
        if let Some(ref content) = update.content {
            query_builder = query_builder.bind(content);
        }
        if let Some(ref summary) = update.summary {
            query_builder = query_builder.bind(summary);
        }
        if let Some(doc_type) = update.doc_type {
            query_builder = query_builder.bind(doc_type.as_str());
        }
        if let Some(ref metadata) = update.metadata {
            query_builder = query_builder.bind(serde_json::to_string(metadata)?);
        }
        if let Some(is_active) = update.is_active {
            query_builder = query_builder.bind(is_active as i32);
        }
        if updated_by.is_some() {
            query_builder = query_builder.bind(&updated_by_str);
        }

        query_builder = query_builder.bind(&id_str).bind(&tenant_id_str);

        let result = query_builder.execute(&self.pool).await?;

        if result.rows_affected() == 0 {
            return Err(DbError::NotFound {
                entity: "KnowledgeDocument".to_string(),
                id: id.to_string(),
            });
        }

        self.get_for_tenant(id, tenant_id)
            .await?
            .ok_or_else(|| DbError::NotFound {
                entity: "KnowledgeDocument".to_string(),
                id: id.to_string(),
            })
    }

    async fn mark_indexed(&self, id: Uuid, indexed_at: DateTime<Utc>) -> Result<(), DbError> {
        let id_str = id.to_string();
        let indexed_at_str = indexed_at.to_rfc3339();

        let result = sqlx::query("UPDATE knowledge_documents SET indexed_at = ? WHERE id = ?")
            .bind(&indexed_at_str)
            .bind(&id_str)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(DbError::NotFound {
                entity: "KnowledgeDocument".to_string(),
                id: id.to_string(),
            });
        }

        Ok(())
    }

    async fn delete(&self, id: Uuid, tenant_id: Uuid) -> Result<bool, DbError> {
        let id_str = id.to_string();
        let tenant_id_str = tenant_id.to_string();

        let result = sqlx::query("DELETE FROM knowledge_documents WHERE id = ? AND tenant_id = ?")
            .bind(&id_str)
            .bind(&tenant_id_str)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    async fn get_needs_indexing(
        &self,
        tenant_id: Uuid,
        limit: usize,
    ) -> Result<Vec<KnowledgeDocument>, DbError> {
        let tenant_id_str = tenant_id.to_string();

        let rows: Vec<KnowledgeRow> = sqlx::query_as(
            r#"
            SELECT id, tenant_id, doc_type, title, content, summary,
                   metadata, is_active, created_at, updated_at, indexed_at,
                   created_by, updated_by
            FROM knowledge_documents
            WHERE tenant_id = ? AND is_active = 1
              AND (indexed_at IS NULL OR indexed_at < updated_at)
            ORDER BY updated_at ASC
            LIMIT ?
            "#,
        )
        .bind(&tenant_id_str)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into()).collect()
    }

    async fn search_text(
        &self,
        tenant_id: Uuid,
        query: &str,
        filter: &KnowledgeFilter,
        limit: usize,
    ) -> Result<Vec<KnowledgeDocument>, DbError> {
        let tenant_id_str = tenant_id.to_string();

        // Use FTS5 for full-text search
        let mut sql = String::from(
            r#"
            SELECT kd.id, kd.tenant_id, kd.doc_type, kd.title, kd.content, kd.summary,
                   kd.metadata, kd.is_active, kd.created_at, kd.updated_at, kd.indexed_at,
                   kd.created_by, kd.updated_by
            FROM knowledge_documents kd
            JOIN knowledge_documents_fts fts ON kd.rowid = fts.rowid
            WHERE kd.tenant_id = ? AND knowledge_documents_fts MATCH ?
            "#,
        );

        if let Some(is_active) = filter.is_active {
            sql.push_str(&format!(
                " AND kd.is_active = {}",
                if is_active { 1 } else { 0 }
            ));
        }

        if let Some(ref doc_types) = filter.doc_types {
            if !doc_types.is_empty() {
                let types: Vec<String> = doc_types
                    .iter()
                    .map(|t| format!("'{}'", t.as_str()))
                    .collect();
                sql.push_str(&format!(" AND kd.doc_type IN ({})", types.join(", ")));
            }
        }

        sql.push_str(" ORDER BY rank LIMIT ?");

        let rows: Vec<KnowledgeRow> = sqlx::query_as(&sql)
            .bind(&tenant_id_str)
            .bind(query)
            .bind(limit as i64)
            .fetch_all(&self.pool)
            .await?;

        rows.into_iter().map(|r| r.try_into()).collect()
    }

    async fn get_stats(&self, tenant_id: Uuid) -> Result<KnowledgeStats, DbError> {
        let tenant_id_str = tenant_id.to_string();

        // Get total and indexed counts
        let row: StatsRow = sqlx::query_as(
            r#"
            SELECT
                COUNT(*) as total_documents,
                SUM(CASE WHEN indexed_at IS NOT NULL AND indexed_at >= updated_at THEN 1 ELSE 0 END) as indexed_documents
            FROM knowledge_documents
            WHERE tenant_id = ?
            "#,
        )
        .bind(&tenant_id_str)
        .fetch_one(&self.pool)
        .await?;

        // Get counts by type
        let type_counts: Vec<TypeCountRow> = sqlx::query_as(
            r#"
            SELECT doc_type, COUNT(*) as count
            FROM knowledge_documents
            WHERE tenant_id = ?
            GROUP BY doc_type
            "#,
        )
        .bind(&tenant_id_str)
        .fetch_all(&self.pool)
        .await?;

        let by_type = type_counts
            .into_iter()
            .map(|r| (r.doc_type, r.count as u64))
            .collect();

        Ok(KnowledgeStats {
            total_documents: row.total_documents as u64,
            indexed_documents: row.indexed_documents as u64,
            by_type,
            top_tags: vec![],
            top_mitre_techniques: vec![],
        })
    }

    async fn get_by_type(
        &self,
        tenant_id: Uuid,
        doc_type: KnowledgeType,
        limit: usize,
    ) -> Result<Vec<KnowledgeDocument>, DbError> {
        let tenant_id_str = tenant_id.to_string();

        let rows: Vec<KnowledgeRow> = sqlx::query_as(
            r#"
            SELECT id, tenant_id, doc_type, title, content, summary,
                   metadata, is_active, created_at, updated_at, indexed_at,
                   created_by, updated_by
            FROM knowledge_documents
            WHERE tenant_id = ? AND doc_type = ? AND is_active = 1
            ORDER BY created_at DESC
            LIMIT ?
            "#,
        )
        .bind(&tenant_id_str)
        .bind(doc_type.as_str())
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into()).collect()
    }
}

/// PostgreSQL implementation of KnowledgeRepository.
#[cfg(feature = "database")]
pub struct PgKnowledgeRepository {
    pool: sqlx::PgPool,
}

#[cfg(feature = "database")]
impl PgKnowledgeRepository {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

#[cfg(feature = "database")]
#[async_trait]
impl KnowledgeRepository for PgKnowledgeRepository {
    async fn create(&self, document: &KnowledgeDocument) -> Result<KnowledgeDocument, DbError> {
        let metadata = serde_json::to_value(&document.metadata)?;

        sqlx::query(
            r#"
            INSERT INTO knowledge_documents (
                id, tenant_id, doc_type, title, content, summary,
                metadata, is_active, created_at, updated_at, indexed_at,
                created_by, updated_by
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            "#,
        )
        .bind(document.id)
        .bind(document.tenant_id)
        .bind(document.doc_type.as_str())
        .bind(&document.title)
        .bind(&document.content)
        .bind(&document.summary)
        .bind(&metadata)
        .bind(document.is_active)
        .bind(document.created_at)
        .bind(document.updated_at)
        .bind(document.indexed_at)
        .bind(document.created_by)
        .bind(document.updated_by)
        .execute(&self.pool)
        .await?;

        Ok(document.clone())
    }

    async fn get(&self, id: Uuid) -> Result<Option<KnowledgeDocument>, DbError> {
        let row: Option<PgKnowledgeRow> = sqlx::query_as(
            r#"
            SELECT id, tenant_id, doc_type, title, content, summary,
                   metadata, is_active, created_at, updated_at, indexed_at,
                   created_by, updated_by
            FROM knowledge_documents
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => Ok(Some(row.try_into()?)),
            None => Ok(None),
        }
    }

    async fn get_for_tenant(
        &self,
        id: Uuid,
        tenant_id: Uuid,
    ) -> Result<Option<KnowledgeDocument>, DbError> {
        let row: Option<PgKnowledgeRow> = sqlx::query_as(
            r#"
            SELECT id, tenant_id, doc_type, title, content, summary,
                   metadata, is_active, created_at, updated_at, indexed_at,
                   created_by, updated_by
            FROM knowledge_documents
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => Ok(Some(row.try_into()?)),
            None => Ok(None),
        }
    }

    async fn list(
        &self,
        tenant_id: Uuid,
        filter: &KnowledgeFilter,
        pagination: &Pagination,
    ) -> Result<PaginatedResult<KnowledgeDocument>, DbError> {
        let doc_types: Option<Vec<String>> = filter
            .doc_types
            .as_ref()
            .map(|types| types.iter().map(|t| t.as_str().to_string()).collect());

        let rows: Vec<PgKnowledgeRow> = sqlx::query_as(
            r#"
            SELECT id, tenant_id, doc_type, title, content, summary,
                   metadata, is_active, created_at, updated_at, indexed_at,
                   created_by, updated_by
            FROM knowledge_documents
            WHERE tenant_id = $1
              AND ($2::text[] IS NULL OR doc_type = ANY($2))
              AND ($3::boolean IS NULL OR is_active = $3)
              AND ($4::timestamptz IS NULL OR created_at >= $4)
              AND ($5::timestamptz IS NULL OR created_at <= $5)
            ORDER BY created_at DESC
            LIMIT $6 OFFSET $7
            "#,
        )
        .bind(tenant_id)
        .bind(&doc_types)
        .bind(filter.is_active)
        .bind(filter.created_after)
        .bind(filter.created_before)
        .bind(pagination.limit() as i64)
        .bind(pagination.offset() as i64)
        .fetch_all(&self.pool)
        .await?;

        let items: Result<Vec<KnowledgeDocument>, DbError> =
            rows.into_iter().map(|r| r.try_into()).collect();

        let total = self.count(tenant_id, filter).await?;

        Ok(PaginatedResult::new(items?, total, pagination))
    }

    async fn count(&self, tenant_id: Uuid, filter: &KnowledgeFilter) -> Result<u64, DbError> {
        let doc_types: Option<Vec<String>> = filter
            .doc_types
            .as_ref()
            .map(|types| types.iter().map(|t| t.as_str().to_string()).collect());

        let count: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*)
            FROM knowledge_documents
            WHERE tenant_id = $1
              AND ($2::text[] IS NULL OR doc_type = ANY($2))
              AND ($3::boolean IS NULL OR is_active = $3)
              AND ($4::timestamptz IS NULL OR created_at >= $4)
              AND ($5::timestamptz IS NULL OR created_at <= $5)
            "#,
        )
        .bind(tenant_id)
        .bind(&doc_types)
        .bind(filter.is_active)
        .bind(filter.created_after)
        .bind(filter.created_before)
        .fetch_one(&self.pool)
        .await?;

        Ok(count as u64)
    }

    async fn update(
        &self,
        id: Uuid,
        tenant_id: Uuid,
        update: &UpdateKnowledgeDocument,
        updated_by: Option<Uuid>,
    ) -> Result<KnowledgeDocument, DbError> {
        let metadata = update
            .metadata
            .as_ref()
            .map(serde_json::to_value)
            .transpose()?;
        let doc_type = update.doc_type.map(|t| t.as_str().to_string());

        // Determine if content changed (requires re-indexing)
        let content_changed =
            update.title.is_some() || update.content.is_some() || update.metadata.is_some();

        let result = sqlx::query(
            r#"
            UPDATE knowledge_documents SET
                title = COALESCE($3, title),
                content = COALESCE($4, content),
                summary = COALESCE($5, summary),
                doc_type = COALESCE($6, doc_type),
                metadata = COALESCE($7, metadata),
                is_active = COALESCE($8, is_active),
                updated_by = COALESCE($9, updated_by),
                updated_at = NOW(),
                indexed_at = CASE WHEN $10 THEN NULL ELSE indexed_at END
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&update.title)
        .bind(&update.content)
        .bind(&update.summary)
        .bind(&doc_type)
        .bind(&metadata)
        .bind(update.is_active)
        .bind(updated_by)
        .bind(content_changed)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(DbError::NotFound {
                entity: "KnowledgeDocument".to_string(),
                id: id.to_string(),
            });
        }

        self.get_for_tenant(id, tenant_id)
            .await?
            .ok_or_else(|| DbError::NotFound {
                entity: "KnowledgeDocument".to_string(),
                id: id.to_string(),
            })
    }

    async fn mark_indexed(&self, id: Uuid, indexed_at: DateTime<Utc>) -> Result<(), DbError> {
        let result = sqlx::query("UPDATE knowledge_documents SET indexed_at = $2 WHERE id = $1")
            .bind(id)
            .bind(indexed_at)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(DbError::NotFound {
                entity: "KnowledgeDocument".to_string(),
                id: id.to_string(),
            });
        }

        Ok(())
    }

    async fn delete(&self, id: Uuid, tenant_id: Uuid) -> Result<bool, DbError> {
        let result =
            sqlx::query("DELETE FROM knowledge_documents WHERE id = $1 AND tenant_id = $2")
                .bind(id)
                .bind(tenant_id)
                .execute(&self.pool)
                .await?;

        Ok(result.rows_affected() > 0)
    }

    async fn get_needs_indexing(
        &self,
        tenant_id: Uuid,
        limit: usize,
    ) -> Result<Vec<KnowledgeDocument>, DbError> {
        let rows: Vec<PgKnowledgeRow> = sqlx::query_as(
            r#"
            SELECT id, tenant_id, doc_type, title, content, summary,
                   metadata, is_active, created_at, updated_at, indexed_at,
                   created_by, updated_by
            FROM knowledge_documents
            WHERE tenant_id = $1 AND is_active = true
              AND (indexed_at IS NULL OR indexed_at < updated_at)
            ORDER BY updated_at ASC
            LIMIT $2
            "#,
        )
        .bind(tenant_id)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into()).collect()
    }

    async fn search_text(
        &self,
        tenant_id: Uuid,
        query: &str,
        filter: &KnowledgeFilter,
        limit: usize,
    ) -> Result<Vec<KnowledgeDocument>, DbError> {
        let doc_types: Option<Vec<String>> = filter
            .doc_types
            .as_ref()
            .map(|types| types.iter().map(|t| t.as_str().to_string()).collect());

        let rows: Vec<PgKnowledgeRow> = sqlx::query_as(
            r#"
            SELECT id, tenant_id, doc_type, title, content, summary,
                   metadata, is_active, created_at, updated_at, indexed_at,
                   created_by, updated_by
            FROM knowledge_documents
            WHERE tenant_id = $1
              AND search_vector @@ plainto_tsquery('english', $2)
              AND ($3::text[] IS NULL OR doc_type = ANY($3))
              AND ($4::boolean IS NULL OR is_active = $4)
            ORDER BY ts_rank(search_vector, plainto_tsquery('english', $2)) DESC
            LIMIT $5
            "#,
        )
        .bind(tenant_id)
        .bind(query)
        .bind(&doc_types)
        .bind(filter.is_active)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into()).collect()
    }

    async fn get_stats(&self, tenant_id: Uuid) -> Result<KnowledgeStats, DbError> {
        let row: PgStatsRow = sqlx::query_as(
            r#"
            SELECT
                COUNT(*) as total_documents,
                SUM(CASE WHEN indexed_at IS NOT NULL AND indexed_at >= updated_at THEN 1 ELSE 0 END) as indexed_documents
            FROM knowledge_documents
            WHERE tenant_id = $1
            "#,
        )
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await?;

        // Get counts by type
        let type_counts: Vec<PgTypeCountRow> = sqlx::query_as(
            r#"
            SELECT doc_type, COUNT(*) as count
            FROM knowledge_documents
            WHERE tenant_id = $1
            GROUP BY doc_type
            "#,
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;

        let by_type = type_counts
            .into_iter()
            .map(|r| (r.doc_type, r.count as u64))
            .collect();

        // Get top tags from metadata
        let top_tags: Vec<TagCountRow> = sqlx::query_as(
            r#"
            SELECT tag, COUNT(*) as count
            FROM knowledge_documents,
                 jsonb_array_elements_text(COALESCE(metadata->'tags', '[]'::jsonb)) as tag
            WHERE tenant_id = $1
            GROUP BY tag
            ORDER BY count DESC
            LIMIT 10
            "#,
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();

        // Get top MITRE techniques
        let top_mitre: Vec<TagCountRow> = sqlx::query_as(
            r#"
            SELECT technique as tag, COUNT(*) as count
            FROM knowledge_documents,
                 jsonb_array_elements_text(COALESCE(metadata->'mitre_techniques', '[]'::jsonb)) as technique
            WHERE tenant_id = $1
            GROUP BY technique
            ORDER BY count DESC
            LIMIT 10
            "#,
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();

        Ok(KnowledgeStats {
            total_documents: row.total_documents as u64,
            indexed_documents: row.indexed_documents.unwrap_or(0) as u64,
            by_type,
            top_tags: top_tags
                .into_iter()
                .map(|r| (r.tag, r.count as u64))
                .collect(),
            top_mitre_techniques: top_mitre
                .into_iter()
                .map(|r| (r.tag, r.count as u64))
                .collect(),
        })
    }

    async fn get_by_type(
        &self,
        tenant_id: Uuid,
        doc_type: KnowledgeType,
        limit: usize,
    ) -> Result<Vec<KnowledgeDocument>, DbError> {
        let rows: Vec<PgKnowledgeRow> = sqlx::query_as(
            r#"
            SELECT id, tenant_id, doc_type, title, content, summary,
                   metadata, is_active, created_at, updated_at, indexed_at,
                   created_by, updated_by
            FROM knowledge_documents
            WHERE tenant_id = $1 AND doc_type = $2 AND is_active = true
            ORDER BY created_at DESC
            LIMIT $3
            "#,
        )
        .bind(tenant_id)
        .bind(doc_type.as_str())
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into()).collect()
    }
}

/// Factory function to create the appropriate repository based on pool type.
#[cfg(feature = "database")]
pub fn create_knowledge_repository(pool: &DbPool) -> Box<dyn KnowledgeRepository> {
    match pool {
        DbPool::Sqlite(pool) => Box::new(SqliteKnowledgeRepository::new(pool.clone())),
        DbPool::Postgres(pool) => Box::new(PgKnowledgeRepository::new(pool.clone())),
    }
}

// ============================================================================
// Row Mapping Types
// ============================================================================

#[cfg(feature = "database")]
#[derive(sqlx::FromRow)]
struct KnowledgeRow {
    id: String,
    tenant_id: String,
    doc_type: String,
    title: String,
    content: String,
    summary: Option<String>,
    metadata: String,
    is_active: i32,
    created_at: String,
    updated_at: String,
    indexed_at: Option<String>,
    created_by: Option<String>,
    updated_by: Option<String>,
}

#[cfg(feature = "database")]
impl TryFrom<KnowledgeRow> for KnowledgeDocument {
    type Error = DbError;

    fn try_from(row: KnowledgeRow) -> Result<Self, Self::Error> {
        Ok(KnowledgeDocument {
            id: Uuid::parse_str(&row.id).map_err(|e| DbError::Serialization(e.to_string()))?,
            tenant_id: Uuid::parse_str(&row.tenant_id)
                .map_err(|e| DbError::Serialization(e.to_string()))?,
            doc_type: KnowledgeType::parse(&row.doc_type).ok_or_else(|| {
                DbError::Serialization(format!("Unknown knowledge type: {}", row.doc_type))
            })?,
            title: row.title,
            content: row.content,
            summary: row.summary,
            metadata: serde_json::from_str(&row.metadata).unwrap_or_default(),
            embedding: None,
            is_active: row.is_active != 0,
            created_at: DateTime::parse_from_rfc3339(&row.created_at)
                .map_err(|e| DbError::Serialization(e.to_string()))?
                .with_timezone(&Utc),
            updated_at: DateTime::parse_from_rfc3339(&row.updated_at)
                .map_err(|e| DbError::Serialization(e.to_string()))?
                .with_timezone(&Utc),
            indexed_at: row
                .indexed_at
                .map(|s| DateTime::parse_from_rfc3339(&s))
                .transpose()
                .map_err(|e| DbError::Serialization(e.to_string()))?
                .map(|dt| dt.with_timezone(&Utc)),
            created_by: row
                .created_by
                .map(|s| Uuid::parse_str(&s))
                .transpose()
                .map_err(|e| DbError::Serialization(e.to_string()))?,
            updated_by: row
                .updated_by
                .map(|s| Uuid::parse_str(&s))
                .transpose()
                .map_err(|e| DbError::Serialization(e.to_string()))?,
        })
    }
}

#[cfg(feature = "database")]
#[derive(sqlx::FromRow)]
struct PgKnowledgeRow {
    id: Uuid,
    tenant_id: Uuid,
    doc_type: String,
    title: String,
    content: String,
    summary: Option<String>,
    metadata: serde_json::Value,
    is_active: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    indexed_at: Option<DateTime<Utc>>,
    created_by: Option<Uuid>,
    updated_by: Option<Uuid>,
}

#[cfg(feature = "database")]
impl TryFrom<PgKnowledgeRow> for KnowledgeDocument {
    type Error = DbError;

    fn try_from(row: PgKnowledgeRow) -> Result<Self, Self::Error> {
        Ok(KnowledgeDocument {
            id: row.id,
            tenant_id: row.tenant_id,
            doc_type: KnowledgeType::parse(&row.doc_type).ok_or_else(|| {
                DbError::Serialization(format!("Unknown knowledge type: {}", row.doc_type))
            })?,
            title: row.title,
            content: row.content,
            summary: row.summary,
            metadata: serde_json::from_value(row.metadata).unwrap_or_default(),
            embedding: None,
            is_active: row.is_active,
            created_at: row.created_at,
            updated_at: row.updated_at,
            indexed_at: row.indexed_at,
            created_by: row.created_by,
            updated_by: row.updated_by,
        })
    }
}

#[cfg(feature = "database")]
#[derive(sqlx::FromRow)]
struct StatsRow {
    total_documents: i64,
    indexed_documents: i64,
}

#[cfg(feature = "database")]
#[derive(sqlx::FromRow)]
struct PgStatsRow {
    total_documents: i64,
    indexed_documents: Option<i64>,
}

#[cfg(feature = "database")]
#[derive(sqlx::FromRow)]
struct TypeCountRow {
    doc_type: String,
    count: i64,
}

#[cfg(feature = "database")]
#[derive(sqlx::FromRow)]
struct PgTypeCountRow {
    doc_type: String,
    count: i64,
}

#[cfg(feature = "database")]
#[derive(sqlx::FromRow)]
struct TagCountRow {
    tag: String,
    count: i64,
}
