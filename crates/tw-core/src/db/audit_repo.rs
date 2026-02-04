//! Audit log repository for database operations.

use super::pagination::{AuditLogFilter, PaginatedResult, Pagination};
use super::{DbError, DbPool};
use crate::incident::AuditEntry;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Repository trait for audit log persistence.
#[async_trait]
pub trait AuditRepository: Send + Sync {
    /// Logs an audit entry.
    async fn log(
        &self,
        tenant_id: Uuid,
        incident_id: Uuid,
        entry: &AuditEntry,
    ) -> Result<(), DbError>;

    /// Logs multiple audit entries in a single transaction.
    async fn log_batch(
        &self,
        tenant_id: Uuid,
        incident_id: Uuid,
        entries: &[AuditEntry],
    ) -> Result<(), DbError>;

    /// Gets all audit entries for an incident within a tenant.
    async fn get_for_incident(
        &self,
        tenant_id: Uuid,
        incident_id: Uuid,
    ) -> Result<Vec<AuditEntry>, DbError>;

    /// Gets recent audit entries for a tenant across all incidents.
    async fn get_recent_for_tenant(
        &self,
        tenant_id: Uuid,
        limit: u32,
    ) -> Result<Vec<(Uuid, AuditEntry)>, DbError>;

    /// Gets audit entries by actor within a tenant.
    async fn get_by_actor_for_tenant(
        &self,
        tenant_id: Uuid,
        actor: &str,
        limit: u32,
    ) -> Result<Vec<(Uuid, AuditEntry)>, DbError>;

    /// Lists audit entries with filtering and pagination.
    /// Returns a tuple of (incident_id, audit_entry) for each entry.
    async fn list_paginated(
        &self,
        filter: &AuditLogFilter,
        pagination: &Pagination,
    ) -> Result<PaginatedResult<(Uuid, AuditEntry)>, DbError>;

    /// Counts audit entries matching the filter.
    async fn count(&self, filter: &AuditLogFilter) -> Result<u64, DbError>;
}

/// SQLite implementation of AuditRepository.
#[cfg(feature = "database")]
pub struct SqliteAuditRepository {
    pool: sqlx::SqlitePool,
}

#[cfg(feature = "database")]
impl SqliteAuditRepository {
    pub fn new(pool: sqlx::SqlitePool) -> Self {
        Self { pool }
    }
}

#[cfg(feature = "database")]
#[async_trait]
impl AuditRepository for SqliteAuditRepository {
    async fn log(
        &self,
        tenant_id: Uuid,
        incident_id: Uuid,
        entry: &AuditEntry,
    ) -> Result<(), DbError> {
        let id = entry.id.to_string();
        let tenant_id_str = tenant_id.to_string();
        let incident_id_str = incident_id.to_string();
        let action = serde_json::to_string(&entry.action)?;
        let details = entry
            .details
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        let created_at = entry.timestamp.to_rfc3339();

        sqlx::query(
            r#"
            INSERT INTO audit_logs (id, tenant_id, incident_id, action, actor, details, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&id)
        .bind(&tenant_id_str)
        .bind(&incident_id_str)
        .bind(&action)
        .bind(&entry.actor)
        .bind(&details)
        .bind(&created_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn log_batch(
        &self,
        tenant_id: Uuid,
        incident_id: Uuid,
        entries: &[AuditEntry],
    ) -> Result<(), DbError> {
        let mut tx = self.pool.begin().await?;
        let tenant_id_str = tenant_id.to_string();
        let incident_id_str = incident_id.to_string();

        for entry in entries {
            let id = entry.id.to_string();
            let action = serde_json::to_string(&entry.action)?;
            let details = entry
                .details
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?;
            let created_at = entry.timestamp.to_rfc3339();

            sqlx::query(
                r#"
                INSERT INTO audit_logs (id, tenant_id, incident_id, action, actor, details, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind(&id)
            .bind(&tenant_id_str)
            .bind(&incident_id_str)
            .bind(&action)
            .bind(&entry.actor)
            .bind(&details)
            .bind(&created_at)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    async fn get_for_incident(
        &self,
        tenant_id: Uuid,
        incident_id: Uuid,
    ) -> Result<Vec<AuditEntry>, DbError> {
        let tenant_id_str = tenant_id.to_string();
        let incident_id_str = incident_id.to_string();

        let rows: Vec<AuditLogRow> = sqlx::query_as(
            r#"
            SELECT id, tenant_id, incident_id, action, actor, details, created_at
            FROM audit_logs
            WHERE tenant_id = ? AND incident_id = ?
            ORDER BY created_at ASC
            "#,
        )
        .bind(&tenant_id_str)
        .bind(&incident_id_str)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into()).collect()
    }

    async fn get_recent_for_tenant(
        &self,
        tenant_id: Uuid,
        limit: u32,
    ) -> Result<Vec<(Uuid, AuditEntry)>, DbError> {
        let tenant_id_str = tenant_id.to_string();

        let rows: Vec<AuditLogRow> = sqlx::query_as(
            r#"
            SELECT id, tenant_id, incident_id, action, actor, details, created_at
            FROM audit_logs
            WHERE tenant_id = ?
            ORDER BY created_at DESC
            LIMIT ?
            "#,
        )
        .bind(&tenant_id_str)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|r| {
                let incident_id = Uuid::parse_str(&r.incident_id)
                    .map_err(|e| DbError::Serialization(e.to_string()))?;
                let entry: AuditEntry = r.try_into()?;
                Ok((incident_id, entry))
            })
            .collect()
    }

    async fn get_by_actor_for_tenant(
        &self,
        tenant_id: Uuid,
        actor: &str,
        limit: u32,
    ) -> Result<Vec<(Uuid, AuditEntry)>, DbError> {
        let tenant_id_str = tenant_id.to_string();

        let rows: Vec<AuditLogRow> = sqlx::query_as(
            r#"
            SELECT id, tenant_id, incident_id, action, actor, details, created_at
            FROM audit_logs
            WHERE tenant_id = ? AND actor = ?
            ORDER BY created_at DESC
            LIMIT ?
            "#,
        )
        .bind(&tenant_id_str)
        .bind(actor)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|r| {
                let incident_id = Uuid::parse_str(&r.incident_id)
                    .map_err(|e| DbError::Serialization(e.to_string()))?;
                let entry: AuditEntry = r.try_into()?;
                Ok((incident_id, entry))
            })
            .collect()
    }

    async fn list_paginated(
        &self,
        filter: &AuditLogFilter,
        pagination: &Pagination,
    ) -> Result<PaginatedResult<(Uuid, AuditEntry)>, DbError> {
        // Build dynamic query with filters
        let mut query = String::from(
            "SELECT id, tenant_id, incident_id, action, actor, details, created_at FROM audit_logs WHERE 1=1",
        );

        if filter.tenant_id.is_some() {
            query.push_str(" AND tenant_id = ?");
        }

        if filter.incident_id.is_some() {
            query.push_str(" AND incident_id = ?");
        }

        if filter.actor.is_some() {
            query.push_str(" AND actor = ?");
        }

        if filter.since.is_some() {
            query.push_str(" AND created_at >= ?");
        }

        if filter.until.is_some() {
            query.push_str(" AND created_at <= ?");
        }

        query.push_str(" ORDER BY created_at DESC LIMIT ? OFFSET ?");

        let mut query_builder = sqlx::query_as::<_, AuditLogRow>(&query);

        if let Some(tenant_id) = filter.tenant_id {
            query_builder = query_builder.bind(tenant_id.to_string());
        }

        if let Some(incident_id) = filter.incident_id {
            query_builder = query_builder.bind(incident_id.to_string());
        }

        if let Some(actor) = &filter.actor {
            query_builder = query_builder.bind(actor.clone());
        }

        if let Some(since) = &filter.since {
            query_builder = query_builder.bind(since.to_rfc3339());
        }

        if let Some(until) = &filter.until {
            query_builder = query_builder.bind(until.to_rfc3339());
        }

        query_builder = query_builder
            .bind(pagination.limit() as i64)
            .bind(pagination.offset() as i64);

        let rows: Vec<AuditLogRow> = query_builder.fetch_all(&self.pool).await?;

        let items: Result<Vec<(Uuid, AuditEntry)>, DbError> = rows
            .into_iter()
            .map(|r| {
                let incident_id = Uuid::parse_str(&r.incident_id)
                    .map_err(|e| DbError::Serialization(e.to_string()))?;
                let entry: AuditEntry = r.try_into()?;
                Ok((incident_id, entry))
            })
            .collect();

        let total = self.count(filter).await?;

        Ok(PaginatedResult::new(items?, total, pagination))
    }

    async fn count(&self, filter: &AuditLogFilter) -> Result<u64, DbError> {
        let mut query = String::from("SELECT COUNT(*) as count FROM audit_logs WHERE 1=1");

        if filter.tenant_id.is_some() {
            query.push_str(" AND tenant_id = ?");
        }

        if filter.incident_id.is_some() {
            query.push_str(" AND incident_id = ?");
        }

        if filter.actor.is_some() {
            query.push_str(" AND actor = ?");
        }

        if filter.since.is_some() {
            query.push_str(" AND created_at >= ?");
        }

        if filter.until.is_some() {
            query.push_str(" AND created_at <= ?");
        }

        let mut query_builder = sqlx::query_scalar::<_, i64>(&query);

        if let Some(tenant_id) = filter.tenant_id {
            query_builder = query_builder.bind(tenant_id.to_string());
        }

        if let Some(incident_id) = filter.incident_id {
            query_builder = query_builder.bind(incident_id.to_string());
        }

        if let Some(actor) = &filter.actor {
            query_builder = query_builder.bind(actor.clone());
        }

        if let Some(since) = &filter.since {
            query_builder = query_builder.bind(since.to_rfc3339());
        }

        if let Some(until) = &filter.until {
            query_builder = query_builder.bind(until.to_rfc3339());
        }

        let count: i64 = query_builder.fetch_one(&self.pool).await?;

        Ok(count as u64)
    }
}

/// PostgreSQL implementation of AuditRepository.
#[cfg(feature = "database")]
pub struct PgAuditRepository {
    pool: sqlx::PgPool,
}

#[cfg(feature = "database")]
impl PgAuditRepository {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

#[cfg(feature = "database")]
#[async_trait]
impl AuditRepository for PgAuditRepository {
    async fn log(
        &self,
        tenant_id: Uuid,
        incident_id: Uuid,
        entry: &AuditEntry,
    ) -> Result<(), DbError> {
        let action = serde_json::to_string(&entry.action)?;

        sqlx::query(
            r#"
            INSERT INTO audit_logs (id, tenant_id, incident_id, action, actor, details, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
        )
        .bind(entry.id)
        .bind(tenant_id)
        .bind(incident_id)
        .bind(&action)
        .bind(&entry.actor)
        .bind(&entry.details)
        .bind(entry.timestamp)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn log_batch(
        &self,
        tenant_id: Uuid,
        incident_id: Uuid,
        entries: &[AuditEntry],
    ) -> Result<(), DbError> {
        let mut tx = self.pool.begin().await?;

        for entry in entries {
            let action = serde_json::to_string(&entry.action)?;

            sqlx::query(
                r#"
                INSERT INTO audit_logs (id, tenant_id, incident_id, action, actor, details, created_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                "#,
            )
            .bind(entry.id)
            .bind(tenant_id)
            .bind(incident_id)
            .bind(&action)
            .bind(&entry.actor)
            .bind(&entry.details)
            .bind(entry.timestamp)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    async fn get_for_incident(
        &self,
        tenant_id: Uuid,
        incident_id: Uuid,
    ) -> Result<Vec<AuditEntry>, DbError> {
        let rows: Vec<PgAuditLogRow> = sqlx::query_as(
            r#"
            SELECT id, tenant_id, incident_id, action, actor, details, created_at
            FROM audit_logs
            WHERE tenant_id = $1 AND incident_id = $2
            ORDER BY created_at ASC
            "#,
        )
        .bind(tenant_id)
        .bind(incident_id)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into()).collect()
    }

    async fn get_recent_for_tenant(
        &self,
        tenant_id: Uuid,
        limit: u32,
    ) -> Result<Vec<(Uuid, AuditEntry)>, DbError> {
        let rows: Vec<PgAuditLogRow> = sqlx::query_as(
            r#"
            SELECT id, tenant_id, incident_id, action, actor, details, created_at
            FROM audit_logs
            WHERE tenant_id = $1
            ORDER BY created_at DESC
            LIMIT $2
            "#,
        )
        .bind(tenant_id)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|r| {
                let incident_id = r.incident_id;
                let entry: AuditEntry = r.try_into()?;
                Ok((incident_id, entry))
            })
            .collect()
    }

    async fn get_by_actor_for_tenant(
        &self,
        tenant_id: Uuid,
        actor: &str,
        limit: u32,
    ) -> Result<Vec<(Uuid, AuditEntry)>, DbError> {
        let rows: Vec<PgAuditLogRow> = sqlx::query_as(
            r#"
            SELECT id, tenant_id, incident_id, action, actor, details, created_at
            FROM audit_logs
            WHERE tenant_id = $1 AND actor = $2
            ORDER BY created_at DESC
            LIMIT $3
            "#,
        )
        .bind(tenant_id)
        .bind(actor)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|r| {
                let incident_id = r.incident_id;
                let entry: AuditEntry = r.try_into()?;
                Ok((incident_id, entry))
            })
            .collect()
    }

    async fn list_paginated(
        &self,
        filter: &AuditLogFilter,
        pagination: &Pagination,
    ) -> Result<PaginatedResult<(Uuid, AuditEntry)>, DbError> {
        let rows: Vec<PgAuditLogRow> = sqlx::query_as(
            r#"
            SELECT id, tenant_id, incident_id, action, actor, details, created_at
            FROM audit_logs
            WHERE ($1::uuid IS NULL OR tenant_id = $1)
              AND ($2::uuid IS NULL OR incident_id = $2)
              AND ($3::text IS NULL OR actor = $3)
              AND ($4::timestamptz IS NULL OR created_at >= $4)
              AND ($5::timestamptz IS NULL OR created_at <= $5)
            ORDER BY created_at DESC
            LIMIT $6 OFFSET $7
            "#,
        )
        .bind(filter.tenant_id)
        .bind(filter.incident_id)
        .bind(&filter.actor)
        .bind(filter.since)
        .bind(filter.until)
        .bind(pagination.limit() as i64)
        .bind(pagination.offset() as i64)
        .fetch_all(&self.pool)
        .await?;

        let items: Result<Vec<(Uuid, AuditEntry)>, DbError> = rows
            .into_iter()
            .map(|r| {
                let incident_id = r.incident_id;
                let entry: AuditEntry = r.try_into()?;
                Ok((incident_id, entry))
            })
            .collect();

        let total = self.count(filter).await?;

        Ok(PaginatedResult::new(items?, total, pagination))
    }

    async fn count(&self, filter: &AuditLogFilter) -> Result<u64, DbError> {
        let count: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*)
            FROM audit_logs
            WHERE ($1::uuid IS NULL OR tenant_id = $1)
              AND ($2::uuid IS NULL OR incident_id = $2)
              AND ($3::text IS NULL OR actor = $3)
              AND ($4::timestamptz IS NULL OR created_at >= $4)
              AND ($5::timestamptz IS NULL OR created_at <= $5)
            "#,
        )
        .bind(filter.tenant_id)
        .bind(filter.incident_id)
        .bind(&filter.actor)
        .bind(filter.since)
        .bind(filter.until)
        .fetch_one(&self.pool)
        .await?;

        Ok(count as u64)
    }
}

/// Factory function to create the appropriate repository based on pool type.
#[cfg(feature = "database")]
pub fn create_audit_repository(pool: &DbPool) -> Box<dyn AuditRepository> {
    match pool {
        DbPool::Sqlite(pool) => Box::new(SqliteAuditRepository::new(pool.clone())),
        DbPool::Postgres(pool) => Box::new(PgAuditRepository::new(pool.clone())),
    }
}

// Helper structs for SQLx row mapping

#[cfg(feature = "database")]
#[derive(sqlx::FromRow)]
struct AuditLogRow {
    id: String,
    #[allow(dead_code)]
    tenant_id: String,
    incident_id: String,
    action: String,
    actor: String,
    details: Option<String>,
    created_at: String,
}

#[cfg(feature = "database")]
impl TryFrom<AuditLogRow> for AuditEntry {
    type Error = DbError;

    fn try_from(row: AuditLogRow) -> Result<Self, Self::Error> {
        Ok(AuditEntry {
            id: Uuid::parse_str(&row.id).map_err(|e| DbError::Serialization(e.to_string()))?,
            action: serde_json::from_str(&row.action)?,
            actor: row.actor,
            details: row.details.map(|d| serde_json::from_str(&d)).transpose()?,
            timestamp: DateTime::parse_from_rfc3339(&row.created_at)
                .map_err(|e| DbError::Serialization(e.to_string()))?
                .with_timezone(&Utc),
        })
    }
}

#[cfg(feature = "database")]
#[derive(sqlx::FromRow)]
struct PgAuditLogRow {
    id: Uuid,
    #[allow(dead_code)]
    tenant_id: Uuid,
    incident_id: Uuid,
    action: String,
    actor: String,
    details: Option<serde_json::Value>,
    created_at: DateTime<Utc>,
}

#[cfg(feature = "database")]
impl TryFrom<PgAuditLogRow> for AuditEntry {
    type Error = DbError;

    fn try_from(row: PgAuditLogRow) -> Result<Self, Self::Error> {
        Ok(AuditEntry {
            id: row.id,
            action: serde_json::from_str(&row.action)?,
            actor: row.actor,
            details: row.details,
            timestamp: row.created_at,
        })
    }
}
