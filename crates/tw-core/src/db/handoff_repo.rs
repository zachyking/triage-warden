//! Shift handoff repository for database operations.
//!
//! This module provides persistence for shift handoff reports,
//! supporting both SQLite and PostgreSQL backends.

use super::pagination::{PaginatedResult, Pagination};
use super::{DbError, DbPool};
use crate::collaboration::handoff::ShiftHandoff;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Repository trait for shift handoff persistence.
///
/// All methods that query or modify handoffs are tenant-scoped for security.
#[async_trait]
pub trait HandoffRepository: Send + Sync {
    /// Creates a new handoff report.
    async fn create(
        &self,
        tenant_id: Uuid,
        handoff: &ShiftHandoff,
    ) -> Result<ShiftHandoff, DbError>;

    /// Gets a handoff by ID without tenant scoping (admin use only).
    async fn get(&self, id: Uuid) -> Result<Option<ShiftHandoff>, DbError>;

    /// Gets a handoff by ID, scoped to a specific tenant.
    async fn get_for_tenant(
        &self,
        id: Uuid,
        tenant_id: Uuid,
    ) -> Result<Option<ShiftHandoff>, DbError>;

    /// Gets the most recently created handoff for a tenant.
    async fn get_latest(&self, tenant_id: Uuid) -> Result<Option<ShiftHandoff>, DbError>;

    /// Lists handoffs with pagination.
    async fn list(
        &self,
        tenant_id: Uuid,
        pagination: &Pagination,
    ) -> Result<PaginatedResult<ShiftHandoff>, DbError>;

    /// Deletes a handoff report.
    async fn delete(&self, id: Uuid, tenant_id: Uuid) -> Result<bool, DbError>;
}

// ============================================================================
// SQLite Implementation
// ============================================================================

#[cfg(feature = "database")]
pub struct SqliteHandoffRepository {
    pool: sqlx::SqlitePool,
}

#[cfg(feature = "database")]
impl SqliteHandoffRepository {
    pub fn new(pool: sqlx::SqlitePool) -> Self {
        Self { pool }
    }
}

#[cfg(feature = "database")]
#[derive(sqlx::FromRow)]
struct HandoffRow {
    id: String,
    #[allow(dead_code)]
    tenant_id: String,
    shift_start: String,
    shift_end: String,
    analyst_id: String,
    analyst_name: String,
    open_incidents: String,
    pending_actions: String,
    notable_events: String,
    recommendations: String,
    created_at: String,
}

#[cfg(feature = "database")]
impl TryFrom<HandoffRow> for ShiftHandoff {
    type Error = DbError;

    fn try_from(row: HandoffRow) -> Result<Self, Self::Error> {
        Ok(ShiftHandoff {
            id: Uuid::parse_str(&row.id).map_err(|e| DbError::Serialization(e.to_string()))?,
            shift_start: DateTime::parse_from_rfc3339(&row.shift_start)
                .map_err(|e| DbError::Serialization(e.to_string()))?
                .with_timezone(&Utc),
            shift_end: DateTime::parse_from_rfc3339(&row.shift_end)
                .map_err(|e| DbError::Serialization(e.to_string()))?
                .with_timezone(&Utc),
            analyst_id: Uuid::parse_str(&row.analyst_id)
                .map_err(|e| DbError::Serialization(e.to_string()))?,
            analyst_name: row.analyst_name,
            open_incidents: serde_json::from_str(&row.open_incidents)?,
            pending_actions: serde_json::from_str(&row.pending_actions)?,
            notable_events: serde_json::from_str(&row.notable_events)?,
            recommendations: serde_json::from_str(&row.recommendations)?,
            created_at: DateTime::parse_from_rfc3339(&row.created_at)
                .map_err(|e| DbError::Serialization(e.to_string()))?
                .with_timezone(&Utc),
        })
    }
}

#[cfg(feature = "database")]
#[async_trait]
impl HandoffRepository for SqliteHandoffRepository {
    async fn create(
        &self,
        tenant_id: Uuid,
        handoff: &ShiftHandoff,
    ) -> Result<ShiftHandoff, DbError> {
        let id = handoff.id.to_string();
        let tenant_id_str = tenant_id.to_string();
        let shift_start = handoff.shift_start.to_rfc3339();
        let shift_end = handoff.shift_end.to_rfc3339();
        let analyst_id = handoff.analyst_id.to_string();
        let open_incidents = serde_json::to_string(&handoff.open_incidents)?;
        let pending_actions = serde_json::to_string(&handoff.pending_actions)?;
        let notable_events = serde_json::to_string(&handoff.notable_events)?;
        let recommendations = serde_json::to_string(&handoff.recommendations)?;
        let created_at = handoff.created_at.to_rfc3339();

        sqlx::query(
            r#"
            INSERT INTO shift_handoffs (
                id, tenant_id, shift_start, shift_end, analyst_id, analyst_name,
                open_incidents, pending_actions, notable_events, recommendations, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&id)
        .bind(&tenant_id_str)
        .bind(&shift_start)
        .bind(&shift_end)
        .bind(&analyst_id)
        .bind(&handoff.analyst_name)
        .bind(&open_incidents)
        .bind(&pending_actions)
        .bind(&notable_events)
        .bind(&recommendations)
        .bind(&created_at)
        .execute(&self.pool)
        .await?;

        Ok(handoff.clone())
    }

    async fn get(&self, id: Uuid) -> Result<Option<ShiftHandoff>, DbError> {
        let id_str = id.to_string();

        let row: Option<HandoffRow> = sqlx::query_as(
            r#"
            SELECT id, tenant_id, shift_start, shift_end, analyst_id, analyst_name,
                   open_incidents, pending_actions, notable_events, recommendations, created_at
            FROM shift_handoffs
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
    ) -> Result<Option<ShiftHandoff>, DbError> {
        let id_str = id.to_string();
        let tenant_id_str = tenant_id.to_string();

        let row: Option<HandoffRow> = sqlx::query_as(
            r#"
            SELECT id, tenant_id, shift_start, shift_end, analyst_id, analyst_name,
                   open_incidents, pending_actions, notable_events, recommendations, created_at
            FROM shift_handoffs
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

    async fn get_latest(&self, tenant_id: Uuid) -> Result<Option<ShiftHandoff>, DbError> {
        let tenant_id_str = tenant_id.to_string();

        let row: Option<HandoffRow> = sqlx::query_as(
            r#"
            SELECT id, tenant_id, shift_start, shift_end, analyst_id, analyst_name,
                   open_incidents, pending_actions, notable_events, recommendations, created_at
            FROM shift_handoffs
            WHERE tenant_id = ?
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )
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
        pagination: &Pagination,
    ) -> Result<PaginatedResult<ShiftHandoff>, DbError> {
        let tenant_id_str = tenant_id.to_string();

        let rows: Vec<HandoffRow> = sqlx::query_as(
            r#"
            SELECT id, tenant_id, shift_start, shift_end, analyst_id, analyst_name,
                   open_incidents, pending_actions, notable_events, recommendations, created_at
            FROM shift_handoffs
            WHERE tenant_id = ?
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
            "#,
        )
        .bind(&tenant_id_str)
        .bind(pagination.limit() as i64)
        .bind(pagination.offset() as i64)
        .fetch_all(&self.pool)
        .await?;

        let items: Result<Vec<ShiftHandoff>, DbError> =
            rows.into_iter().map(|r| r.try_into()).collect();

        // Count total
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM shift_handoffs WHERE tenant_id = ?")
                .bind(&tenant_id_str)
                .fetch_one(&self.pool)
                .await?;

        Ok(PaginatedResult::new(items?, count as u64, pagination))
    }

    async fn delete(&self, id: Uuid, tenant_id: Uuid) -> Result<bool, DbError> {
        let id_str = id.to_string();
        let tenant_id_str = tenant_id.to_string();

        let result = sqlx::query("DELETE FROM shift_handoffs WHERE id = ? AND tenant_id = ?")
            .bind(&id_str)
            .bind(&tenant_id_str)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }
}

// ============================================================================
// PostgreSQL Implementation
// ============================================================================

#[cfg(feature = "database")]
pub struct PgHandoffRepository {
    pool: sqlx::PgPool,
}

#[cfg(feature = "database")]
impl PgHandoffRepository {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

#[cfg(feature = "database")]
#[derive(sqlx::FromRow)]
struct PgHandoffRow {
    id: Uuid,
    #[allow(dead_code)]
    tenant_id: Uuid,
    shift_start: DateTime<Utc>,
    shift_end: DateTime<Utc>,
    analyst_id: Uuid,
    analyst_name: String,
    open_incidents: serde_json::Value,
    pending_actions: serde_json::Value,
    notable_events: serde_json::Value,
    recommendations: serde_json::Value,
    created_at: DateTime<Utc>,
}

#[cfg(feature = "database")]
impl TryFrom<PgHandoffRow> for ShiftHandoff {
    type Error = DbError;

    fn try_from(row: PgHandoffRow) -> Result<Self, Self::Error> {
        Ok(ShiftHandoff {
            id: row.id,
            shift_start: row.shift_start,
            shift_end: row.shift_end,
            analyst_id: row.analyst_id,
            analyst_name: row.analyst_name,
            open_incidents: serde_json::from_value(row.open_incidents)?,
            pending_actions: serde_json::from_value(row.pending_actions)?,
            notable_events: serde_json::from_value(row.notable_events)?,
            recommendations: serde_json::from_value(row.recommendations)?,
            created_at: row.created_at,
        })
    }
}

#[cfg(feature = "database")]
#[async_trait]
impl HandoffRepository for PgHandoffRepository {
    async fn create(
        &self,
        tenant_id: Uuid,
        handoff: &ShiftHandoff,
    ) -> Result<ShiftHandoff, DbError> {
        let open_incidents = serde_json::to_value(&handoff.open_incidents)?;
        let pending_actions = serde_json::to_value(&handoff.pending_actions)?;
        let notable_events = serde_json::to_value(&handoff.notable_events)?;
        let recommendations = serde_json::to_value(&handoff.recommendations)?;

        sqlx::query(
            r#"
            INSERT INTO shift_handoffs (
                id, tenant_id, shift_start, shift_end, analyst_id, analyst_name,
                open_incidents, pending_actions, notable_events, recommendations, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            "#,
        )
        .bind(handoff.id)
        .bind(tenant_id)
        .bind(handoff.shift_start)
        .bind(handoff.shift_end)
        .bind(handoff.analyst_id)
        .bind(&handoff.analyst_name)
        .bind(&open_incidents)
        .bind(&pending_actions)
        .bind(&notable_events)
        .bind(&recommendations)
        .bind(handoff.created_at)
        .execute(&self.pool)
        .await?;

        Ok(handoff.clone())
    }

    async fn get(&self, id: Uuid) -> Result<Option<ShiftHandoff>, DbError> {
        let row: Option<PgHandoffRow> = sqlx::query_as(
            r#"
            SELECT id, tenant_id, shift_start, shift_end, analyst_id, analyst_name,
                   open_incidents, pending_actions, notable_events, recommendations, created_at
            FROM shift_handoffs
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
    ) -> Result<Option<ShiftHandoff>, DbError> {
        let row: Option<PgHandoffRow> = sqlx::query_as(
            r#"
            SELECT id, tenant_id, shift_start, shift_end, analyst_id, analyst_name,
                   open_incidents, pending_actions, notable_events, recommendations, created_at
            FROM shift_handoffs
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

    async fn get_latest(&self, tenant_id: Uuid) -> Result<Option<ShiftHandoff>, DbError> {
        let row: Option<PgHandoffRow> = sqlx::query_as(
            r#"
            SELECT id, tenant_id, shift_start, shift_end, analyst_id, analyst_name,
                   open_incidents, pending_actions, notable_events, recommendations, created_at
            FROM shift_handoffs
            WHERE tenant_id = $1
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )
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
        pagination: &Pagination,
    ) -> Result<PaginatedResult<ShiftHandoff>, DbError> {
        let rows: Vec<PgHandoffRow> = sqlx::query_as(
            r#"
            SELECT id, tenant_id, shift_start, shift_end, analyst_id, analyst_name,
                   open_incidents, pending_actions, notable_events, recommendations, created_at
            FROM shift_handoffs
            WHERE tenant_id = $1
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(tenant_id)
        .bind(pagination.limit() as i64)
        .bind(pagination.offset() as i64)
        .fetch_all(&self.pool)
        .await?;

        let items: Result<Vec<ShiftHandoff>, DbError> =
            rows.into_iter().map(|r| r.try_into()).collect();

        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM shift_handoffs WHERE tenant_id = $1")
                .bind(tenant_id)
                .fetch_one(&self.pool)
                .await?;

        Ok(PaginatedResult::new(items?, count as u64, pagination))
    }

    async fn delete(&self, id: Uuid, tenant_id: Uuid) -> Result<bool, DbError> {
        let result = sqlx::query("DELETE FROM shift_handoffs WHERE id = $1 AND tenant_id = $2")
            .bind(id)
            .bind(tenant_id)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }
}

// ============================================================================
// Factory
// ============================================================================

/// Factory function to create the appropriate repository based on pool type.
#[cfg(feature = "database")]
pub fn create_handoff_repository(pool: &DbPool) -> Box<dyn HandoffRepository> {
    match pool {
        DbPool::Sqlite(pool) => Box::new(SqliteHandoffRepository::new(pool.clone())),
        DbPool::Postgres(pool) => Box::new(PgHandoffRepository::new(pool.clone())),
    }
}
