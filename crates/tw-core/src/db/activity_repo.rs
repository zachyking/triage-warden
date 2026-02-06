//! Activity repository for database operations.
//!
//! This module provides persistence for activity feed entries,
//! supporting both SQLite and PostgreSQL backends.

use super::pagination::{PaginatedResult, Pagination};
use super::{DbError, DbPool};
use crate::collaboration::activity::{ActivityEntry, ActivityFilter, ActivityType};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Repository trait for activity persistence.
#[async_trait]
pub trait ActivityRepository: Send + Sync {
    /// Creates a new activity entry.
    async fn create(
        &self,
        entry: &ActivityEntry,
        tenant_id: Uuid,
    ) -> Result<ActivityEntry, DbError>;

    /// Lists activity entries with optional filtering and pagination.
    async fn list(
        &self,
        filter: &ActivityFilter,
        tenant_id: Uuid,
        pagination: &Pagination,
    ) -> Result<PaginatedResult<ActivityEntry>, DbError>;

    /// Counts activity entries matching the filter.
    async fn count(&self, filter: &ActivityFilter, tenant_id: Uuid) -> Result<u64, DbError>;

    /// Gets activity entries for a specific incident within a tenant.
    async fn get_for_incident(
        &self,
        tenant_id: Uuid,
        incident_id: Uuid,
    ) -> Result<Vec<ActivityEntry>, DbError>;

    /// Deletes activity entries older than the given timestamp.
    async fn delete_old(&self, before: DateTime<Utc>) -> Result<u64, DbError>;
}

// Helper function to parse ActivityType from database string.
fn activity_type_from_db_str(s: &str) -> Result<ActivityType, DbError> {
    match s {
        "incident_created" => Ok(ActivityType::IncidentCreated),
        "incident_updated" => Ok(ActivityType::IncidentUpdated),
        "incident_assigned" => Ok(ActivityType::IncidentAssigned),
        "comment_added" => Ok(ActivityType::CommentAdded),
        "action_executed" => Ok(ActivityType::ActionExecuted),
        "verdict_changed" => Ok(ActivityType::VerdictChanged),
        "severity_changed" => Ok(ActivityType::SeverityChanged),
        "status_changed" => Ok(ActivityType::StatusChanged),
        _ => Err(DbError::Serialization(format!(
            "Unknown activity type: {}",
            s
        ))),
    }
}

// ============================================================================
// SQLite Implementation
// ============================================================================

#[cfg(feature = "database")]
#[derive(sqlx::FromRow)]
struct ActivityRow {
    id: String,
    timestamp: String,
    actor_id: Option<String>,
    actor_name: Option<String>,
    activity_type: String,
    incident_id: Option<String>,
    description: String,
    metadata: Option<String>,
    #[allow(dead_code)]
    tenant_id: String,
}

#[cfg(feature = "database")]
impl TryFrom<ActivityRow> for ActivityEntry {
    type Error = DbError;

    fn try_from(row: ActivityRow) -> Result<Self, Self::Error> {
        Ok(ActivityEntry {
            id: Uuid::parse_str(&row.id).map_err(|e| DbError::Serialization(e.to_string()))?,
            timestamp: DateTime::parse_from_rfc3339(&row.timestamp)
                .map_err(|e| DbError::Serialization(e.to_string()))?
                .with_timezone(&Utc),
            actor_id: row
                .actor_id
                .map(|s| Uuid::parse_str(&s))
                .transpose()
                .map_err(|e| DbError::Serialization(e.to_string()))?,
            actor_name: row.actor_name,
            activity_type: activity_type_from_db_str(&row.activity_type)?,
            incident_id: row
                .incident_id
                .map(|s| Uuid::parse_str(&s))
                .transpose()
                .map_err(|e| DbError::Serialization(e.to_string()))?,
            description: row.description,
            metadata: row.metadata.map(|s| serde_json::from_str(&s)).transpose()?,
        })
    }
}

/// SQLite implementation of ActivityRepository.
#[cfg(feature = "database")]
pub struct SqliteActivityRepository {
    pool: sqlx::SqlitePool,
}

#[cfg(feature = "database")]
impl SqliteActivityRepository {
    pub fn new(pool: sqlx::SqlitePool) -> Self {
        Self { pool }
    }
}

#[cfg(feature = "database")]
#[async_trait]
impl ActivityRepository for SqliteActivityRepository {
    async fn create(
        &self,
        entry: &ActivityEntry,
        tenant_id: Uuid,
    ) -> Result<ActivityEntry, DbError> {
        let id = entry.id.to_string();
        let timestamp = entry.timestamp.to_rfc3339();
        let actor_id = entry.actor_id.map(|a| a.to_string());
        let activity_type = entry.activity_type.to_string();
        let incident_id = entry.incident_id.map(|i| i.to_string());
        let metadata = entry
            .metadata
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        let tenant_id_str = tenant_id.to_string();

        sqlx::query(
            r#"
            INSERT INTO activity_entries (
                id, timestamp, actor_id, actor_name, activity_type,
                incident_id, description, metadata, tenant_id
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&id)
        .bind(&timestamp)
        .bind(&actor_id)
        .bind(&entry.actor_name)
        .bind(&activity_type)
        .bind(&incident_id)
        .bind(&entry.description)
        .bind(&metadata)
        .bind(&tenant_id_str)
        .execute(&self.pool)
        .await?;

        Ok(entry.clone())
    }

    async fn list(
        &self,
        filter: &ActivityFilter,
        tenant_id: Uuid,
        pagination: &Pagination,
    ) -> Result<PaginatedResult<ActivityEntry>, DbError> {
        let mut query = String::from(
            r#"
            SELECT id, timestamp, actor_id, actor_name, activity_type,
                   incident_id, description, metadata, tenant_id
            FROM activity_entries WHERE tenant_id = ?
            "#,
        );

        if filter.incident_id.is_some() {
            query.push_str(" AND incident_id = ?");
        }
        if filter.actor_id.is_some() {
            query.push_str(" AND actor_id = ?");
        }
        if filter.since.is_some() {
            query.push_str(" AND timestamp >= ?");
        }
        // activity_types filtering is handled after fetching if needed,
        // but we can also build an IN clause for efficiency
        if let Some(types) = &filter.activity_types {
            if !types.is_empty() {
                let placeholders: Vec<&str> = types.iter().map(|_| "?").collect();
                query.push_str(&format!(
                    " AND activity_type IN ({})",
                    placeholders.join(", ")
                ));
            }
        }

        query.push_str(" ORDER BY timestamp DESC LIMIT ? OFFSET ?");

        let mut query_builder = sqlx::query_as::<_, ActivityRow>(&query);

        query_builder = query_builder.bind(tenant_id.to_string());

        if let Some(incident_id) = filter.incident_id {
            query_builder = query_builder.bind(incident_id.to_string());
        }
        if let Some(actor_id) = filter.actor_id {
            query_builder = query_builder.bind(actor_id.to_string());
        }
        if let Some(since) = &filter.since {
            query_builder = query_builder.bind(since.to_rfc3339());
        }
        if let Some(types) = &filter.activity_types {
            for t in types {
                query_builder = query_builder.bind(t.to_string());
            }
        }

        query_builder = query_builder
            .bind(pagination.limit() as i64)
            .bind(pagination.offset() as i64);

        let rows: Vec<ActivityRow> = query_builder.fetch_all(&self.pool).await?;
        let items: Result<Vec<ActivityEntry>, DbError> =
            rows.into_iter().map(|r| r.try_into()).collect();
        let total = self.count(filter, tenant_id).await?;

        Ok(PaginatedResult::new(items?, total, pagination))
    }

    async fn count(&self, filter: &ActivityFilter, tenant_id: Uuid) -> Result<u64, DbError> {
        let mut query = String::from("SELECT COUNT(*) FROM activity_entries WHERE tenant_id = ?");

        if filter.incident_id.is_some() {
            query.push_str(" AND incident_id = ?");
        }
        if filter.actor_id.is_some() {
            query.push_str(" AND actor_id = ?");
        }
        if filter.since.is_some() {
            query.push_str(" AND timestamp >= ?");
        }
        if let Some(types) = &filter.activity_types {
            if !types.is_empty() {
                let placeholders: Vec<&str> = types.iter().map(|_| "?").collect();
                query.push_str(&format!(
                    " AND activity_type IN ({})",
                    placeholders.join(", ")
                ));
            }
        }

        let mut query_builder = sqlx::query_scalar::<_, i64>(&query);

        query_builder = query_builder.bind(tenant_id.to_string());

        if let Some(incident_id) = filter.incident_id {
            query_builder = query_builder.bind(incident_id.to_string());
        }
        if let Some(actor_id) = filter.actor_id {
            query_builder = query_builder.bind(actor_id.to_string());
        }
        if let Some(since) = &filter.since {
            query_builder = query_builder.bind(since.to_rfc3339());
        }
        if let Some(types) = &filter.activity_types {
            for t in types {
                query_builder = query_builder.bind(t.to_string());
            }
        }

        let count: i64 = query_builder.fetch_one(&self.pool).await?;
        Ok(count as u64)
    }

    async fn get_for_incident(
        &self,
        tenant_id: Uuid,
        incident_id: Uuid,
    ) -> Result<Vec<ActivityEntry>, DbError> {
        let tenant_id_str = tenant_id.to_string();
        let incident_id_str = incident_id.to_string();

        let rows: Vec<ActivityRow> = sqlx::query_as(
            r#"
            SELECT id, timestamp, actor_id, actor_name, activity_type,
                   incident_id, description, metadata, tenant_id
            FROM activity_entries
            WHERE tenant_id = ? AND incident_id = ?
            ORDER BY timestamp DESC
            "#,
        )
        .bind(&tenant_id_str)
        .bind(&incident_id_str)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into()).collect()
    }

    async fn delete_old(&self, before: DateTime<Utc>) -> Result<u64, DbError> {
        let before_str = before.to_rfc3339();

        let result = sqlx::query("DELETE FROM activity_entries WHERE timestamp < ?")
            .bind(&before_str)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected())
    }
}

// ============================================================================
// PostgreSQL Implementation
// ============================================================================

#[cfg(feature = "database")]
#[derive(sqlx::FromRow)]
struct PgActivityRow {
    id: Uuid,
    timestamp: DateTime<Utc>,
    actor_id: Option<Uuid>,
    actor_name: Option<String>,
    activity_type: String,
    incident_id: Option<Uuid>,
    description: String,
    metadata: Option<serde_json::Value>,
    #[allow(dead_code)]
    tenant_id: Uuid,
}

#[cfg(feature = "database")]
impl TryFrom<PgActivityRow> for ActivityEntry {
    type Error = DbError;

    fn try_from(row: PgActivityRow) -> Result<Self, Self::Error> {
        Ok(ActivityEntry {
            id: row.id,
            timestamp: row.timestamp,
            actor_id: row.actor_id,
            actor_name: row.actor_name,
            activity_type: activity_type_from_db_str(&row.activity_type)?,
            incident_id: row.incident_id,
            description: row.description,
            metadata: row.metadata,
        })
    }
}

/// PostgreSQL implementation of ActivityRepository.
#[cfg(feature = "database")]
pub struct PgActivityRepository {
    pool: sqlx::PgPool,
}

#[cfg(feature = "database")]
impl PgActivityRepository {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

#[cfg(feature = "database")]
#[async_trait]
impl ActivityRepository for PgActivityRepository {
    async fn create(
        &self,
        entry: &ActivityEntry,
        tenant_id: Uuid,
    ) -> Result<ActivityEntry, DbError> {
        let activity_type = entry.activity_type.to_string();

        sqlx::query(
            r#"
            INSERT INTO activity_entries (
                id, timestamp, actor_id, actor_name, activity_type,
                incident_id, description, metadata, tenant_id
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
        )
        .bind(entry.id)
        .bind(entry.timestamp)
        .bind(entry.actor_id)
        .bind(&entry.actor_name)
        .bind(&activity_type)
        .bind(entry.incident_id)
        .bind(&entry.description)
        .bind(&entry.metadata)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;

        Ok(entry.clone())
    }

    async fn list(
        &self,
        filter: &ActivityFilter,
        tenant_id: Uuid,
        pagination: &Pagination,
    ) -> Result<PaginatedResult<ActivityEntry>, DbError> {
        // Build activity_types array for the IN clause
        let activity_type_strings: Option<Vec<String>> = filter
            .activity_types
            .as_ref()
            .map(|types| types.iter().map(|t| t.to_string()).collect());

        let query = r#"
            SELECT id, timestamp, actor_id, actor_name, activity_type,
                   incident_id, description, metadata, tenant_id
            FROM activity_entries
            WHERE tenant_id = $1
              AND ($2::uuid IS NULL OR incident_id = $2)
              AND ($3::uuid IS NULL OR actor_id = $3)
              AND ($4::timestamptz IS NULL OR timestamp >= $4)
              AND ($5::text[] IS NULL OR activity_type = ANY($5))
            ORDER BY timestamp DESC
            LIMIT $6 OFFSET $7
            "#;

        let rows: Vec<PgActivityRow> = sqlx::query_as(query)
            .bind(tenant_id)
            .bind(filter.incident_id)
            .bind(filter.actor_id)
            .bind(filter.since)
            .bind(&activity_type_strings)
            .bind(pagination.limit() as i64)
            .bind(pagination.offset() as i64)
            .fetch_all(&self.pool)
            .await?;

        let items: Result<Vec<ActivityEntry>, DbError> =
            rows.into_iter().map(|r| r.try_into()).collect();
        let total = self.count(filter, tenant_id).await?;

        Ok(PaginatedResult::new(items?, total, pagination))
    }

    async fn count(&self, filter: &ActivityFilter, tenant_id: Uuid) -> Result<u64, DbError> {
        let activity_type_strings: Option<Vec<String>> = filter
            .activity_types
            .as_ref()
            .map(|types| types.iter().map(|t| t.to_string()).collect());

        let query = r#"
            SELECT COUNT(*)
            FROM activity_entries
            WHERE tenant_id = $1
              AND ($2::uuid IS NULL OR incident_id = $2)
              AND ($3::uuid IS NULL OR actor_id = $3)
              AND ($4::timestamptz IS NULL OR timestamp >= $4)
              AND ($5::text[] IS NULL OR activity_type = ANY($5))
            "#;

        let count: i64 = sqlx::query_scalar(query)
            .bind(tenant_id)
            .bind(filter.incident_id)
            .bind(filter.actor_id)
            .bind(filter.since)
            .bind(&activity_type_strings)
            .fetch_one(&self.pool)
            .await?;

        Ok(count as u64)
    }

    async fn get_for_incident(
        &self,
        tenant_id: Uuid,
        incident_id: Uuid,
    ) -> Result<Vec<ActivityEntry>, DbError> {
        let rows: Vec<PgActivityRow> = sqlx::query_as(
            r#"
            SELECT id, timestamp, actor_id, actor_name, activity_type,
                   incident_id, description, metadata, tenant_id
            FROM activity_entries
            WHERE tenant_id = $1 AND incident_id = $2
            ORDER BY timestamp DESC
            "#,
        )
        .bind(tenant_id)
        .bind(incident_id)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into()).collect()
    }

    async fn delete_old(&self, before: DateTime<Utc>) -> Result<u64, DbError> {
        let result = sqlx::query("DELETE FROM activity_entries WHERE timestamp < $1")
            .bind(before)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected())
    }
}

// ============================================================================
// Factory
// ============================================================================

/// Factory function to create the appropriate repository based on pool type.
#[cfg(feature = "database")]
pub fn create_activity_repository(pool: &DbPool) -> Box<dyn ActivityRepository> {
    match pool {
        DbPool::Sqlite(pool) => Box::new(SqliteActivityRepository::new(pool.clone())),
        DbPool::Postgres(pool) => Box::new(PgActivityRepository::new(pool.clone())),
    }
}
