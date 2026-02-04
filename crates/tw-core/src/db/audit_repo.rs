//! Audit log repository for database operations.

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
