//! Lesson learned repository for database operations.
//!
//! This module provides persistence for lessons learned from security incidents,
//! supporting both SQLite and PostgreSQL backends.

use super::pagination::{PaginatedResult, Pagination};
use super::{DbError, DbPool};
use crate::lesson::{
    LessonCategory, LessonFilter, LessonLearned, LessonStatus, UpdateLessonRequest,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Repository trait for lesson learned persistence.
///
/// All methods that query or modify lessons are tenant-scoped for security.
#[async_trait]
pub trait LessonRepository: Send + Sync {
    /// Creates a new lesson learned entry.
    async fn create(&self, lesson: &LessonLearned) -> Result<LessonLearned, DbError>;

    /// Gets a lesson by ID without tenant scoping (admin use only).
    async fn get(&self, id: Uuid) -> Result<Option<LessonLearned>, DbError>;

    /// Gets a lesson by ID, scoped to a specific tenant.
    async fn get_for_tenant(
        &self,
        id: Uuid,
        tenant_id: Uuid,
    ) -> Result<Option<LessonLearned>, DbError>;

    /// Lists lessons with optional filtering and pagination.
    async fn list(
        &self,
        tenant_id: Uuid,
        filter: &LessonFilter,
        pagination: &Pagination,
    ) -> Result<PaginatedResult<LessonLearned>, DbError>;

    /// Counts lessons matching the filter.
    async fn count(&self, tenant_id: Uuid, filter: &LessonFilter) -> Result<u64, DbError>;

    /// Updates a lesson.
    async fn update(
        &self,
        id: Uuid,
        tenant_id: Uuid,
        update: &UpdateLessonRequest,
    ) -> Result<LessonLearned, DbError>;

    /// Deletes a lesson.
    async fn delete(&self, id: Uuid, tenant_id: Uuid) -> Result<bool, DbError>;

    /// Gets lessons for a specific incident.
    async fn get_for_incident(
        &self,
        tenant_id: Uuid,
        incident_id: Uuid,
    ) -> Result<Vec<LessonLearned>, DbError>;
}

// ============================================================================
// SQLite Implementation
// ============================================================================

#[cfg(feature = "database")]
pub struct SqliteLessonRepository {
    pool: sqlx::SqlitePool,
}

#[cfg(feature = "database")]
impl SqliteLessonRepository {
    pub fn new(pool: sqlx::SqlitePool) -> Self {
        Self { pool }
    }
}

#[cfg(feature = "database")]
#[derive(sqlx::FromRow)]
struct LessonRow {
    id: String,
    tenant_id: String,
    incident_id: String,
    category: String,
    title: String,
    description: String,
    recommendation: String,
    status: String,
    owner: Option<String>,
    due_date: Option<String>,
    created_at: String,
    updated_at: String,
}

#[cfg(feature = "database")]
impl TryFrom<LessonRow> for LessonLearned {
    type Error = DbError;

    fn try_from(row: LessonRow) -> Result<Self, Self::Error> {
        Ok(LessonLearned {
            id: Uuid::parse_str(&row.id).map_err(|e| DbError::Serialization(e.to_string()))?,
            tenant_id: Uuid::parse_str(&row.tenant_id)
                .map_err(|e| DbError::Serialization(e.to_string()))?,
            incident_id: Uuid::parse_str(&row.incident_id)
                .map_err(|e| DbError::Serialization(e.to_string()))?,
            category: LessonCategory::parse(&row.category).ok_or_else(|| {
                DbError::Serialization(format!("Unknown lesson category: {}", row.category))
            })?,
            title: row.title,
            description: row.description,
            recommendation: row.recommendation,
            status: LessonStatus::parse(&row.status).ok_or_else(|| {
                DbError::Serialization(format!("Unknown lesson status: {}", row.status))
            })?,
            owner: row
                .owner
                .map(|o| Uuid::parse_str(&o))
                .transpose()
                .map_err(|e| DbError::Serialization(e.to_string()))?,
            due_date: row
                .due_date
                .map(|d| DateTime::parse_from_rfc3339(&d))
                .transpose()
                .map_err(|e| DbError::Serialization(e.to_string()))?
                .map(|d| d.with_timezone(&Utc)),
            created_at: DateTime::parse_from_rfc3339(&row.created_at)
                .map_err(|e| DbError::Serialization(e.to_string()))?
                .with_timezone(&Utc),
            updated_at: DateTime::parse_from_rfc3339(&row.updated_at)
                .map_err(|e| DbError::Serialization(e.to_string()))?
                .with_timezone(&Utc),
        })
    }
}

#[cfg(feature = "database")]
#[async_trait]
impl LessonRepository for SqliteLessonRepository {
    async fn create(&self, lesson: &LessonLearned) -> Result<LessonLearned, DbError> {
        let id = lesson.id.to_string();
        let tenant_id = lesson.tenant_id.to_string();
        let incident_id = lesson.incident_id.to_string();
        let category = lesson.category.as_str();
        let status = lesson.status.as_str();
        let owner = lesson.owner.map(|o| o.to_string());
        let due_date = lesson.due_date.map(|d| d.to_rfc3339());
        let created_at = lesson.created_at.to_rfc3339();
        let updated_at = lesson.updated_at.to_rfc3339();

        sqlx::query(
            r#"
            INSERT INTO lessons_learned (
                id, tenant_id, incident_id, category, title, description,
                recommendation, status, owner, due_date, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&id)
        .bind(&tenant_id)
        .bind(&incident_id)
        .bind(category)
        .bind(&lesson.title)
        .bind(&lesson.description)
        .bind(&lesson.recommendation)
        .bind(status)
        .bind(&owner)
        .bind(&due_date)
        .bind(&created_at)
        .bind(&updated_at)
        .execute(&self.pool)
        .await?;

        Ok(lesson.clone())
    }

    async fn get(&self, id: Uuid) -> Result<Option<LessonLearned>, DbError> {
        let id_str = id.to_string();

        let row: Option<LessonRow> = sqlx::query_as(
            r#"
            SELECT id, tenant_id, incident_id, category, title, description,
                   recommendation, status, owner, due_date, created_at, updated_at
            FROM lessons_learned
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
    ) -> Result<Option<LessonLearned>, DbError> {
        let id_str = id.to_string();
        let tenant_id_str = tenant_id.to_string();

        let row: Option<LessonRow> = sqlx::query_as(
            r#"
            SELECT id, tenant_id, incident_id, category, title, description,
                   recommendation, status, owner, due_date, created_at, updated_at
            FROM lessons_learned
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
        filter: &LessonFilter,
        pagination: &Pagination,
    ) -> Result<PaginatedResult<LessonLearned>, DbError> {
        let mut query = String::from(
            r#"
            SELECT id, tenant_id, incident_id, category, title, description,
                   recommendation, status, owner, due_date, created_at, updated_at
            FROM lessons_learned WHERE tenant_id = ?
            "#,
        );

        if filter.category.is_some() {
            query.push_str(" AND category = ?");
        }
        if filter.status.is_some() {
            query.push_str(" AND status = ?");
        }
        if filter.incident_id.is_some() {
            query.push_str(" AND incident_id = ?");
        }
        if filter.owner.is_some() {
            query.push_str(" AND owner = ?");
        }

        query.push_str(" ORDER BY created_at DESC LIMIT ? OFFSET ?");

        let mut query_builder = sqlx::query_as::<_, LessonRow>(&query);
        query_builder = query_builder.bind(tenant_id.to_string());

        if let Some(category) = &filter.category {
            query_builder = query_builder.bind(category.as_str());
        }
        if let Some(status) = &filter.status {
            query_builder = query_builder.bind(status.as_str());
        }
        if let Some(incident_id) = filter.incident_id {
            query_builder = query_builder.bind(incident_id.to_string());
        }
        if let Some(owner) = filter.owner {
            query_builder = query_builder.bind(owner.to_string());
        }

        query_builder = query_builder
            .bind(pagination.limit() as i64)
            .bind(pagination.offset() as i64);

        let rows: Vec<LessonRow> = query_builder.fetch_all(&self.pool).await?;
        let items: Result<Vec<LessonLearned>, DbError> =
            rows.into_iter().map(|r| r.try_into()).collect();
        let total = self.count(tenant_id, filter).await?;

        Ok(PaginatedResult::new(items?, total, pagination))
    }

    async fn count(&self, tenant_id: Uuid, filter: &LessonFilter) -> Result<u64, DbError> {
        let mut query = String::from("SELECT COUNT(*) FROM lessons_learned WHERE tenant_id = ?");

        if filter.category.is_some() {
            query.push_str(" AND category = ?");
        }
        if filter.status.is_some() {
            query.push_str(" AND status = ?");
        }
        if filter.incident_id.is_some() {
            query.push_str(" AND incident_id = ?");
        }
        if filter.owner.is_some() {
            query.push_str(" AND owner = ?");
        }

        let mut query_builder = sqlx::query_scalar::<_, i64>(&query);
        query_builder = query_builder.bind(tenant_id.to_string());

        if let Some(category) = &filter.category {
            query_builder = query_builder.bind(category.as_str());
        }
        if let Some(status) = &filter.status {
            query_builder = query_builder.bind(status.as_str());
        }
        if let Some(incident_id) = filter.incident_id {
            query_builder = query_builder.bind(incident_id.to_string());
        }
        if let Some(owner) = filter.owner {
            query_builder = query_builder.bind(owner.to_string());
        }

        let count: i64 = query_builder.fetch_one(&self.pool).await?;
        Ok(count as u64)
    }

    async fn update(
        &self,
        id: Uuid,
        tenant_id: Uuid,
        update: &UpdateLessonRequest,
    ) -> Result<LessonLearned, DbError> {
        // Fetch existing lesson
        let mut lesson =
            self.get_for_tenant(id, tenant_id)
                .await?
                .ok_or_else(|| DbError::NotFound {
                    entity: "LessonLearned".to_string(),
                    id: id.to_string(),
                })?;

        // Apply update
        let success = update.apply(&mut lesson);
        if !success {
            return Err(DbError::Constraint("Invalid status transition".to_string()));
        }

        // Save the updated lesson back
        let id_str = id.to_string();
        let tenant_id_str = tenant_id.to_string();
        let category = lesson.category.as_str();
        let status = lesson.status.as_str();
        let owner = lesson.owner.map(|o| o.to_string());
        let due_date = lesson.due_date.map(|d| d.to_rfc3339());
        let updated_at = lesson.updated_at.to_rfc3339();

        sqlx::query(
            r#"
            UPDATE lessons_learned SET
                category = ?, title = ?, description = ?, recommendation = ?,
                status = ?, owner = ?, due_date = ?, updated_at = ?
            WHERE id = ? AND tenant_id = ?
            "#,
        )
        .bind(category)
        .bind(&lesson.title)
        .bind(&lesson.description)
        .bind(&lesson.recommendation)
        .bind(status)
        .bind(&owner)
        .bind(&due_date)
        .bind(&updated_at)
        .bind(&id_str)
        .bind(&tenant_id_str)
        .execute(&self.pool)
        .await?;

        Ok(lesson)
    }

    async fn delete(&self, id: Uuid, tenant_id: Uuid) -> Result<bool, DbError> {
        let id_str = id.to_string();
        let tenant_id_str = tenant_id.to_string();

        let result = sqlx::query("DELETE FROM lessons_learned WHERE id = ? AND tenant_id = ?")
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
    ) -> Result<Vec<LessonLearned>, DbError> {
        let tenant_id_str = tenant_id.to_string();
        let incident_id_str = incident_id.to_string();

        let rows: Vec<LessonRow> = sqlx::query_as(
            r#"
            SELECT id, tenant_id, incident_id, category, title, description,
                   recommendation, status, owner, due_date, created_at, updated_at
            FROM lessons_learned
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
pub struct PgLessonRepository {
    pool: sqlx::PgPool,
}

#[cfg(feature = "database")]
impl PgLessonRepository {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

#[cfg(feature = "database")]
#[derive(sqlx::FromRow)]
struct PgLessonRow {
    id: Uuid,
    tenant_id: Uuid,
    incident_id: Uuid,
    category: String,
    title: String,
    description: String,
    recommendation: String,
    status: String,
    owner: Option<Uuid>,
    due_date: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[cfg(feature = "database")]
impl TryFrom<PgLessonRow> for LessonLearned {
    type Error = DbError;

    fn try_from(row: PgLessonRow) -> Result<Self, Self::Error> {
        Ok(LessonLearned {
            id: row.id,
            tenant_id: row.tenant_id,
            incident_id: row.incident_id,
            category: LessonCategory::parse(&row.category).ok_or_else(|| {
                DbError::Serialization(format!("Unknown lesson category: {}", row.category))
            })?,
            title: row.title,
            description: row.description,
            recommendation: row.recommendation,
            status: LessonStatus::parse(&row.status).ok_or_else(|| {
                DbError::Serialization(format!("Unknown lesson status: {}", row.status))
            })?,
            owner: row.owner,
            due_date: row.due_date,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

#[cfg(feature = "database")]
#[async_trait]
impl LessonRepository for PgLessonRepository {
    async fn create(&self, lesson: &LessonLearned) -> Result<LessonLearned, DbError> {
        let category = lesson.category.as_str();
        let status = lesson.status.as_str();

        sqlx::query(
            r#"
            INSERT INTO lessons_learned (
                id, tenant_id, incident_id, category, title, description,
                recommendation, status, owner, due_date, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            "#,
        )
        .bind(lesson.id)
        .bind(lesson.tenant_id)
        .bind(lesson.incident_id)
        .bind(category)
        .bind(&lesson.title)
        .bind(&lesson.description)
        .bind(&lesson.recommendation)
        .bind(status)
        .bind(lesson.owner)
        .bind(lesson.due_date)
        .bind(lesson.created_at)
        .bind(lesson.updated_at)
        .execute(&self.pool)
        .await?;

        Ok(lesson.clone())
    }

    async fn get(&self, id: Uuid) -> Result<Option<LessonLearned>, DbError> {
        let row: Option<PgLessonRow> = sqlx::query_as(
            r#"
            SELECT id, tenant_id, incident_id, category, title, description,
                   recommendation, status, owner, due_date, created_at, updated_at
            FROM lessons_learned
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
    ) -> Result<Option<LessonLearned>, DbError> {
        let row: Option<PgLessonRow> = sqlx::query_as(
            r#"
            SELECT id, tenant_id, incident_id, category, title, description,
                   recommendation, status, owner, due_date, created_at, updated_at
            FROM lessons_learned
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
        filter: &LessonFilter,
        pagination: &Pagination,
    ) -> Result<PaginatedResult<LessonLearned>, DbError> {
        let query = r#"
            SELECT id, tenant_id, incident_id, category, title, description,
                   recommendation, status, owner, due_date, created_at, updated_at
            FROM lessons_learned
            WHERE tenant_id = $1
              AND ($2::text IS NULL OR category = $2)
              AND ($3::text IS NULL OR status = $3)
              AND ($4::uuid IS NULL OR incident_id = $4)
              AND ($5::uuid IS NULL OR owner = $5)
            ORDER BY created_at DESC
            LIMIT $6 OFFSET $7
            "#;

        let rows: Vec<PgLessonRow> = sqlx::query_as(query)
            .bind(tenant_id)
            .bind(filter.category.as_ref().map(|c| c.as_str()))
            .bind(filter.status.as_ref().map(|s| s.as_str()))
            .bind(filter.incident_id)
            .bind(filter.owner)
            .bind(pagination.limit() as i64)
            .bind(pagination.offset() as i64)
            .fetch_all(&self.pool)
            .await?;

        let items: Result<Vec<LessonLearned>, DbError> =
            rows.into_iter().map(|r| r.try_into()).collect();
        let total = self.count(tenant_id, filter).await?;

        Ok(PaginatedResult::new(items?, total, pagination))
    }

    async fn count(&self, tenant_id: Uuid, filter: &LessonFilter) -> Result<u64, DbError> {
        let query = r#"
            SELECT COUNT(*)
            FROM lessons_learned
            WHERE tenant_id = $1
              AND ($2::text IS NULL OR category = $2)
              AND ($3::text IS NULL OR status = $3)
              AND ($4::uuid IS NULL OR incident_id = $4)
              AND ($5::uuid IS NULL OR owner = $5)
            "#;

        let count: i64 = sqlx::query_scalar(query)
            .bind(tenant_id)
            .bind(filter.category.as_ref().map(|c| c.as_str()))
            .bind(filter.status.as_ref().map(|s| s.as_str()))
            .bind(filter.incident_id)
            .bind(filter.owner)
            .fetch_one(&self.pool)
            .await?;

        Ok(count as u64)
    }

    async fn update(
        &self,
        id: Uuid,
        tenant_id: Uuid,
        update: &UpdateLessonRequest,
    ) -> Result<LessonLearned, DbError> {
        // Fetch existing lesson
        let mut lesson =
            self.get_for_tenant(id, tenant_id)
                .await?
                .ok_or_else(|| DbError::NotFound {
                    entity: "LessonLearned".to_string(),
                    id: id.to_string(),
                })?;

        // Apply update
        let success = update.apply(&mut lesson);
        if !success {
            return Err(DbError::Constraint("Invalid status transition".to_string()));
        }

        // Save back
        let category = lesson.category.as_str();
        let status = lesson.status.as_str();

        sqlx::query(
            r#"
            UPDATE lessons_learned SET
                category = $3, title = $4, description = $5, recommendation = $6,
                status = $7, owner = $8, due_date = $9, updated_at = $10
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(category)
        .bind(&lesson.title)
        .bind(&lesson.description)
        .bind(&lesson.recommendation)
        .bind(status)
        .bind(lesson.owner)
        .bind(lesson.due_date)
        .bind(lesson.updated_at)
        .execute(&self.pool)
        .await?;

        Ok(lesson)
    }

    async fn delete(&self, id: Uuid, tenant_id: Uuid) -> Result<bool, DbError> {
        let result = sqlx::query("DELETE FROM lessons_learned WHERE id = $1 AND tenant_id = $2")
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
    ) -> Result<Vec<LessonLearned>, DbError> {
        let rows: Vec<PgLessonRow> = sqlx::query_as(
            r#"
            SELECT id, tenant_id, incident_id, category, title, description,
                   recommendation, status, owner, due_date, created_at, updated_at
            FROM lessons_learned
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
pub fn create_lesson_repository(pool: &DbPool) -> Box<dyn LessonRepository> {
    match pool {
        DbPool::Sqlite(pool) => Box::new(SqliteLessonRepository::new(pool.clone())),
        DbPool::Postgres(pool) => Box::new(PgLessonRepository::new(pool.clone())),
    }
}
