//! Comment repository for database operations.
//!
//! This module provides persistence for incident comments,
//! supporting both SQLite and PostgreSQL backends.

use super::pagination::{PaginatedResult, Pagination};
use super::{DbError, DbPool};
use crate::collaboration::comment::{CommentType, IncidentComment, UpdateCommentRequest};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Filter criteria for listing comments.
#[derive(Debug, Clone, Default)]
pub struct CommentFilter {
    /// Filter by tenant (required for multi-tenant queries).
    pub tenant_id: Option<Uuid>,
    /// Filter by incident ID.
    pub incident_id: Option<Uuid>,
    /// Filter by author ID.
    pub author_id: Option<Uuid>,
    /// Filter by comment type.
    pub comment_type: Option<CommentType>,
}

/// Repository trait for comment persistence.
#[async_trait]
pub trait CommentRepository: Send + Sync {
    /// Creates a new comment.
    async fn create(
        &self,
        comment: &IncidentComment,
        tenant_id: Uuid,
    ) -> Result<IncidentComment, DbError>;

    /// Gets a comment by ID without tenant scoping.
    async fn get(&self, id: Uuid) -> Result<Option<IncidentComment>, DbError>;

    /// Gets a comment by ID, scoped to a specific tenant.
    async fn get_for_tenant(
        &self,
        id: Uuid,
        tenant_id: Uuid,
    ) -> Result<Option<IncidentComment>, DbError>;

    /// Lists comments with optional filtering and pagination.
    async fn list(
        &self,
        filter: &CommentFilter,
        pagination: &Pagination,
    ) -> Result<PaginatedResult<IncidentComment>, DbError>;

    /// Counts comments matching the filter.
    async fn count(&self, filter: &CommentFilter) -> Result<u64, DbError>;

    /// Updates a comment.
    async fn update(
        &self,
        id: Uuid,
        tenant_id: Uuid,
        update: &UpdateCommentRequest,
    ) -> Result<IncidentComment, DbError>;

    /// Deletes a comment.
    async fn delete(&self, id: Uuid, tenant_id: Uuid) -> Result<bool, DbError>;

    /// Gets comments for a specific incident within a tenant.
    async fn get_for_incident(
        &self,
        tenant_id: Uuid,
        incident_id: Uuid,
    ) -> Result<Vec<IncidentComment>, DbError>;
}

// Helper function to parse CommentType from database string.
fn comment_type_from_db_str(s: &str) -> Result<CommentType, DbError> {
    match s {
        "note" => Ok(CommentType::Note),
        "analysis" => Ok(CommentType::Analysis),
        "action_taken" => Ok(CommentType::ActionTaken),
        "question" => Ok(CommentType::Question),
        "resolution" => Ok(CommentType::Resolution),
        _ => Err(DbError::Serialization(format!(
            "Unknown comment type: {}",
            s
        ))),
    }
}

// ============================================================================
// SQLite Implementation
// ============================================================================

#[cfg(feature = "database")]
#[derive(sqlx::FromRow)]
struct CommentRow {
    id: String,
    incident_id: String,
    author_id: String,
    content: String,
    comment_type: String,
    mentions: String,
    tenant_id: String,
    created_at: String,
    updated_at: String,
    edited: i32,
}

#[cfg(feature = "database")]
impl TryFrom<CommentRow> for IncidentComment {
    type Error = DbError;

    fn try_from(row: CommentRow) -> Result<Self, Self::Error> {
        let _tenant_id = row.tenant_id; // consumed but not stored on the model
        Ok(IncidentComment {
            id: Uuid::parse_str(&row.id).map_err(|e| DbError::Serialization(e.to_string()))?,
            incident_id: Uuid::parse_str(&row.incident_id)
                .map_err(|e| DbError::Serialization(e.to_string()))?,
            author_id: Uuid::parse_str(&row.author_id)
                .map_err(|e| DbError::Serialization(e.to_string()))?,
            content: row.content,
            comment_type: comment_type_from_db_str(&row.comment_type)?,
            mentions: serde_json::from_str(&row.mentions)?,
            created_at: DateTime::parse_from_rfc3339(&row.created_at)
                .map_err(|e| DbError::Serialization(e.to_string()))?
                .with_timezone(&Utc),
            updated_at: DateTime::parse_from_rfc3339(&row.updated_at)
                .map_err(|e| DbError::Serialization(e.to_string()))?
                .with_timezone(&Utc),
            edited: row.edited != 0,
        })
    }
}

/// SQLite implementation of CommentRepository.
#[cfg(feature = "database")]
pub struct SqliteCommentRepository {
    pool: sqlx::SqlitePool,
}

#[cfg(feature = "database")]
impl SqliteCommentRepository {
    pub fn new(pool: sqlx::SqlitePool) -> Self {
        Self { pool }
    }
}

#[cfg(feature = "database")]
#[async_trait]
impl CommentRepository for SqliteCommentRepository {
    async fn create(
        &self,
        comment: &IncidentComment,
        tenant_id: Uuid,
    ) -> Result<IncidentComment, DbError> {
        let id = comment.id.to_string();
        let incident_id = comment.incident_id.to_string();
        let author_id = comment.author_id.to_string();
        let comment_type = comment.comment_type.to_string();
        let mentions = serde_json::to_string(&comment.mentions)?;
        let tenant_id_str = tenant_id.to_string();
        let created_at = comment.created_at.to_rfc3339();
        let updated_at = comment.updated_at.to_rfc3339();
        let edited = if comment.edited { 1i32 } else { 0i32 };

        sqlx::query(
            r#"
            INSERT INTO incident_comments (
                id, incident_id, author_id, content, comment_type,
                mentions, tenant_id, created_at, updated_at, edited
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&id)
        .bind(&incident_id)
        .bind(&author_id)
        .bind(&comment.content)
        .bind(&comment_type)
        .bind(&mentions)
        .bind(&tenant_id_str)
        .bind(&created_at)
        .bind(&updated_at)
        .bind(edited)
        .execute(&self.pool)
        .await?;

        Ok(comment.clone())
    }

    async fn get(&self, id: Uuid) -> Result<Option<IncidentComment>, DbError> {
        let id_str = id.to_string();

        let row: Option<CommentRow> = sqlx::query_as(
            r#"
            SELECT id, incident_id, author_id, content, comment_type,
                   mentions, tenant_id, created_at, updated_at, edited
            FROM incident_comments
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
    ) -> Result<Option<IncidentComment>, DbError> {
        let id_str = id.to_string();
        let tenant_id_str = tenant_id.to_string();

        let row: Option<CommentRow> = sqlx::query_as(
            r#"
            SELECT id, incident_id, author_id, content, comment_type,
                   mentions, tenant_id, created_at, updated_at, edited
            FROM incident_comments
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
        filter: &CommentFilter,
        pagination: &Pagination,
    ) -> Result<PaginatedResult<IncidentComment>, DbError> {
        let mut query = String::from(
            r#"
            SELECT id, incident_id, author_id, content, comment_type,
                   mentions, tenant_id, created_at, updated_at, edited
            FROM incident_comments WHERE 1=1
            "#,
        );

        if filter.tenant_id.is_some() {
            query.push_str(" AND tenant_id = ?");
        }
        if filter.incident_id.is_some() {
            query.push_str(" AND incident_id = ?");
        }
        if filter.author_id.is_some() {
            query.push_str(" AND author_id = ?");
        }
        if filter.comment_type.is_some() {
            query.push_str(" AND comment_type = ?");
        }

        query.push_str(" ORDER BY created_at DESC LIMIT ? OFFSET ?");

        let mut query_builder = sqlx::query_as::<_, CommentRow>(&query);

        if let Some(tenant_id) = filter.tenant_id {
            query_builder = query_builder.bind(tenant_id.to_string());
        }
        if let Some(incident_id) = filter.incident_id {
            query_builder = query_builder.bind(incident_id.to_string());
        }
        if let Some(author_id) = filter.author_id {
            query_builder = query_builder.bind(author_id.to_string());
        }
        if let Some(comment_type) = &filter.comment_type {
            query_builder = query_builder.bind(comment_type.to_string());
        }

        query_builder = query_builder
            .bind(pagination.limit() as i64)
            .bind(pagination.offset() as i64);

        let rows: Vec<CommentRow> = query_builder.fetch_all(&self.pool).await?;
        let items: Result<Vec<IncidentComment>, DbError> =
            rows.into_iter().map(|r| r.try_into()).collect();
        let total = self.count(filter).await?;

        Ok(PaginatedResult::new(items?, total, pagination))
    }

    async fn count(&self, filter: &CommentFilter) -> Result<u64, DbError> {
        let mut query = String::from("SELECT COUNT(*) FROM incident_comments WHERE 1=1");

        if filter.tenant_id.is_some() {
            query.push_str(" AND tenant_id = ?");
        }
        if filter.incident_id.is_some() {
            query.push_str(" AND incident_id = ?");
        }
        if filter.author_id.is_some() {
            query.push_str(" AND author_id = ?");
        }
        if filter.comment_type.is_some() {
            query.push_str(" AND comment_type = ?");
        }

        let mut query_builder = sqlx::query_scalar::<_, i64>(&query);

        if let Some(tenant_id) = filter.tenant_id {
            query_builder = query_builder.bind(tenant_id.to_string());
        }
        if let Some(incident_id) = filter.incident_id {
            query_builder = query_builder.bind(incident_id.to_string());
        }
        if let Some(author_id) = filter.author_id {
            query_builder = query_builder.bind(author_id.to_string());
        }
        if let Some(comment_type) = &filter.comment_type {
            query_builder = query_builder.bind(comment_type.to_string());
        }

        let count: i64 = query_builder.fetch_one(&self.pool).await?;
        Ok(count as u64)
    }

    async fn update(
        &self,
        id: Uuid,
        tenant_id: Uuid,
        update: &UpdateCommentRequest,
    ) -> Result<IncidentComment, DbError> {
        let id_str = id.to_string();
        let tenant_id_str = tenant_id.to_string();
        let now = Utc::now().to_rfc3339();

        let mut set_clauses = vec!["updated_at = ?".to_string()];
        let mut values: Vec<Option<String>> = vec![Some(now)];

        if let Some(content) = &update.content {
            set_clauses.push("content = ?".to_string());
            values.push(Some(content.clone()));
            set_clauses.push("edited = ?".to_string());
            values.push(Some("1".to_string()));
        }

        if let Some(comment_type) = &update.comment_type {
            set_clauses.push("comment_type = ?".to_string());
            values.push(Some(comment_type.to_string()));
        }

        let query = format!(
            "UPDATE incident_comments SET {} WHERE id = ? AND tenant_id = ?",
            set_clauses.join(", ")
        );

        let mut query_builder = sqlx::query(&query);
        for value in &values {
            query_builder = query_builder.bind(value);
        }
        query_builder = query_builder.bind(&id_str).bind(&tenant_id_str);

        let result = query_builder.execute(&self.pool).await?;

        if result.rows_affected() == 0 {
            return Err(DbError::NotFound {
                entity: "IncidentComment".to_string(),
                id: id.to_string(),
            });
        }

        self.get_for_tenant(id, tenant_id)
            .await?
            .ok_or_else(|| DbError::NotFound {
                entity: "IncidentComment".to_string(),
                id: id.to_string(),
            })
    }

    async fn delete(&self, id: Uuid, tenant_id: Uuid) -> Result<bool, DbError> {
        let id_str = id.to_string();
        let tenant_id_str = tenant_id.to_string();

        let result = sqlx::query("DELETE FROM incident_comments WHERE id = ? AND tenant_id = ?")
            .bind(&id_str)
            .bind(&tenant_id_str)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    async fn get_for_incident(
        &self,
        tenant_id: Uuid,
        incident_id: Uuid,
    ) -> Result<Vec<IncidentComment>, DbError> {
        let tenant_id_str = tenant_id.to_string();
        let incident_id_str = incident_id.to_string();

        let rows: Vec<CommentRow> = sqlx::query_as(
            r#"
            SELECT id, incident_id, author_id, content, comment_type,
                   mentions, tenant_id, created_at, updated_at, edited
            FROM incident_comments
            WHERE tenant_id = ? AND incident_id = ?
            ORDER BY created_at DESC
            "#,
        )
        .bind(&tenant_id_str)
        .bind(&incident_id_str)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into()).collect()
    }
}

// ============================================================================
// PostgreSQL Implementation
// ============================================================================

#[cfg(feature = "database")]
#[derive(sqlx::FromRow)]
struct PgCommentRow {
    id: Uuid,
    incident_id: Uuid,
    author_id: Uuid,
    content: String,
    comment_type: String,
    mentions: serde_json::Value,
    #[allow(dead_code)]
    tenant_id: Uuid,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    edited: bool,
}

#[cfg(feature = "database")]
impl TryFrom<PgCommentRow> for IncidentComment {
    type Error = DbError;

    fn try_from(row: PgCommentRow) -> Result<Self, Self::Error> {
        Ok(IncidentComment {
            id: row.id,
            incident_id: row.incident_id,
            author_id: row.author_id,
            content: row.content,
            comment_type: comment_type_from_db_str(&row.comment_type)?,
            mentions: serde_json::from_value(row.mentions)?,
            created_at: row.created_at,
            updated_at: row.updated_at,
            edited: row.edited,
        })
    }
}

/// PostgreSQL implementation of CommentRepository.
#[cfg(feature = "database")]
pub struct PgCommentRepository {
    pool: sqlx::PgPool,
}

#[cfg(feature = "database")]
impl PgCommentRepository {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

#[cfg(feature = "database")]
#[async_trait]
impl CommentRepository for PgCommentRepository {
    async fn create(
        &self,
        comment: &IncidentComment,
        tenant_id: Uuid,
    ) -> Result<IncidentComment, DbError> {
        let comment_type = comment.comment_type.to_string();

        sqlx::query(
            r#"
            INSERT INTO incident_comments (
                id, incident_id, author_id, content, comment_type,
                mentions, tenant_id, created_at, updated_at, edited
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#,
        )
        .bind(comment.id)
        .bind(comment.incident_id)
        .bind(comment.author_id)
        .bind(&comment.content)
        .bind(&comment_type)
        .bind(serde_json::to_value(&comment.mentions)?)
        .bind(tenant_id)
        .bind(comment.created_at)
        .bind(comment.updated_at)
        .bind(comment.edited)
        .execute(&self.pool)
        .await?;

        Ok(comment.clone())
    }

    async fn get(&self, id: Uuid) -> Result<Option<IncidentComment>, DbError> {
        let row: Option<PgCommentRow> = sqlx::query_as(
            r#"
            SELECT id, incident_id, author_id, content, comment_type,
                   mentions, tenant_id, created_at, updated_at, edited
            FROM incident_comments
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
    ) -> Result<Option<IncidentComment>, DbError> {
        let row: Option<PgCommentRow> = sqlx::query_as(
            r#"
            SELECT id, incident_id, author_id, content, comment_type,
                   mentions, tenant_id, created_at, updated_at, edited
            FROM incident_comments
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
        filter: &CommentFilter,
        pagination: &Pagination,
    ) -> Result<PaginatedResult<IncidentComment>, DbError> {
        let query = r#"
            SELECT id, incident_id, author_id, content, comment_type,
                   mentions, tenant_id, created_at, updated_at, edited
            FROM incident_comments
            WHERE ($1::uuid IS NULL OR tenant_id = $1)
              AND ($2::uuid IS NULL OR incident_id = $2)
              AND ($3::uuid IS NULL OR author_id = $3)
              AND ($4::text IS NULL OR comment_type = $4)
            ORDER BY created_at DESC
            LIMIT $5 OFFSET $6
            "#;

        let rows: Vec<PgCommentRow> = sqlx::query_as(query)
            .bind(filter.tenant_id)
            .bind(filter.incident_id)
            .bind(filter.author_id)
            .bind(filter.comment_type.as_ref().map(|ct| ct.to_string()))
            .bind(pagination.limit() as i64)
            .bind(pagination.offset() as i64)
            .fetch_all(&self.pool)
            .await?;

        let items: Result<Vec<IncidentComment>, DbError> =
            rows.into_iter().map(|r| r.try_into()).collect();
        let total = self.count(filter).await?;

        Ok(PaginatedResult::new(items?, total, pagination))
    }

    async fn count(&self, filter: &CommentFilter) -> Result<u64, DbError> {
        let query = r#"
            SELECT COUNT(*)
            FROM incident_comments
            WHERE ($1::uuid IS NULL OR tenant_id = $1)
              AND ($2::uuid IS NULL OR incident_id = $2)
              AND ($3::uuid IS NULL OR author_id = $3)
              AND ($4::text IS NULL OR comment_type = $4)
            "#;

        let count: i64 = sqlx::query_scalar(query)
            .bind(filter.tenant_id)
            .bind(filter.incident_id)
            .bind(filter.author_id)
            .bind(filter.comment_type.as_ref().map(|ct| ct.to_string()))
            .fetch_one(&self.pool)
            .await?;

        Ok(count as u64)
    }

    async fn update(
        &self,
        id: Uuid,
        tenant_id: Uuid,
        update: &UpdateCommentRequest,
    ) -> Result<IncidentComment, DbError> {
        let has_content = update.content.is_some();

        sqlx::query(
            r#"
            UPDATE incident_comments SET
                content = COALESCE($3, content),
                comment_type = COALESCE($4, comment_type),
                edited = CASE WHEN $5 THEN TRUE ELSE edited END,
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&update.content)
        .bind(update.comment_type.as_ref().map(|ct| ct.to_string()))
        .bind(has_content)
        .execute(&self.pool)
        .await?;

        self.get_for_tenant(id, tenant_id)
            .await?
            .ok_or_else(|| DbError::NotFound {
                entity: "IncidentComment".to_string(),
                id: id.to_string(),
            })
    }

    async fn delete(&self, id: Uuid, tenant_id: Uuid) -> Result<bool, DbError> {
        let result = sqlx::query("DELETE FROM incident_comments WHERE id = $1 AND tenant_id = $2")
            .bind(id)
            .bind(tenant_id)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    async fn get_for_incident(
        &self,
        tenant_id: Uuid,
        incident_id: Uuid,
    ) -> Result<Vec<IncidentComment>, DbError> {
        let rows: Vec<PgCommentRow> = sqlx::query_as(
            r#"
            SELECT id, incident_id, author_id, content, comment_type,
                   mentions, tenant_id, created_at, updated_at, edited
            FROM incident_comments
            WHERE tenant_id = $1 AND incident_id = $2
            ORDER BY created_at DESC
            "#,
        )
        .bind(tenant_id)
        .bind(incident_id)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into()).collect()
    }
}

// ============================================================================
// Factory
// ============================================================================

/// Factory function to create the appropriate repository based on pool type.
#[cfg(feature = "database")]
pub fn create_comment_repository(pool: &DbPool) -> Box<dyn CommentRepository> {
    match pool {
        DbPool::Sqlite(pool) => Box::new(SqliteCommentRepository::new(pool.clone())),
        DbPool::Postgres(pool) => Box::new(PgCommentRepository::new(pool.clone())),
    }
}
