//! Playbook repository for database operations.

use super::{DbError, DbPool};
use crate::playbook::{Playbook, PlaybookStage};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Filter criteria for listing playbooks.
#[derive(Debug, Clone, Default)]
pub struct PlaybookFilter {
    /// Filter by enabled status.
    pub enabled: Option<bool>,
    /// Filter by trigger type.
    pub trigger_type: Option<String>,
    /// Filter by name (partial match).
    pub name_contains: Option<String>,
}

/// Partial update for a playbook.
#[derive(Debug, Clone, Default)]
pub struct PlaybookUpdate {
    pub name: Option<String>,
    pub description: Option<Option<String>>,
    pub trigger_type: Option<String>,
    pub trigger_condition: Option<Option<String>>,
    pub stages: Option<Vec<PlaybookStage>>,
    pub enabled: Option<bool>,
}

/// Repository trait for playbook persistence.
#[async_trait]
pub trait PlaybookRepository: Send + Sync {
    /// Creates a new playbook.
    async fn create(&self, playbook: &Playbook) -> Result<Playbook, DbError>;

    /// Gets a playbook by ID.
    async fn get(&self, id: Uuid) -> Result<Option<Playbook>, DbError>;

    /// Gets a playbook by name.
    async fn get_by_name(&self, name: &str) -> Result<Option<Playbook>, DbError>;

    /// Lists playbooks with optional filtering.
    async fn list(&self, filter: &PlaybookFilter) -> Result<Vec<Playbook>, DbError>;

    /// Updates a playbook.
    async fn update(&self, id: Uuid, update: &PlaybookUpdate) -> Result<Playbook, DbError>;

    /// Deletes a playbook.
    async fn delete(&self, id: Uuid) -> Result<bool, DbError>;

    /// Toggles the enabled status of a playbook.
    async fn toggle_enabled(&self, id: Uuid) -> Result<Playbook, DbError>;

    /// Increments the execution count of a playbook.
    async fn increment_execution_count(&self, id: Uuid) -> Result<Playbook, DbError>;
}

/// SQLite implementation of PlaybookRepository.
#[cfg(feature = "database")]
pub struct SqlitePlaybookRepository {
    pool: sqlx::SqlitePool,
}

#[cfg(feature = "database")]
impl SqlitePlaybookRepository {
    pub fn new(pool: sqlx::SqlitePool) -> Self {
        Self { pool }
    }
}

#[cfg(feature = "database")]
#[async_trait]
impl PlaybookRepository for SqlitePlaybookRepository {
    async fn create(&self, playbook: &Playbook) -> Result<Playbook, DbError> {
        let id = playbook.id.to_string();
        let stages = serde_json::to_string(&playbook.stages)?;
        let enabled = if playbook.enabled { 1 } else { 0 };
        let created_at = playbook.created_at.to_rfc3339();
        let updated_at = playbook.updated_at.to_rfc3339();

        sqlx::query(
            r#"
            INSERT INTO playbooks (id, name, description, trigger_type, trigger_condition, stages, enabled, execution_count, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&id)
        .bind(&playbook.name)
        .bind(&playbook.description)
        .bind(&playbook.trigger_type)
        .bind(&playbook.trigger_condition)
        .bind(&stages)
        .bind(enabled)
        .bind(playbook.execution_count as i64)
        .bind(&created_at)
        .bind(&updated_at)
        .execute(&self.pool)
        .await?;

        Ok(playbook.clone())
    }

    async fn get(&self, id: Uuid) -> Result<Option<Playbook>, DbError> {
        let id_str = id.to_string();

        let row: Option<PlaybookRow> = sqlx::query_as(
            r#"SELECT id, name, description, trigger_type, trigger_condition, stages, enabled, execution_count, created_at, updated_at FROM playbooks WHERE id = ?"#,
        )
        .bind(&id_str)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => Ok(Some(row.try_into()?)),
            None => Ok(None),
        }
    }

    async fn get_by_name(&self, name: &str) -> Result<Option<Playbook>, DbError> {
        let row: Option<PlaybookRow> = sqlx::query_as(
            r#"SELECT id, name, description, trigger_type, trigger_condition, stages, enabled, execution_count, created_at, updated_at FROM playbooks WHERE name = ?"#,
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => Ok(Some(row.try_into()?)),
            None => Ok(None),
        }
    }

    async fn list(&self, filter: &PlaybookFilter) -> Result<Vec<Playbook>, DbError> {
        let mut query = String::from(
            "SELECT id, name, description, trigger_type, trigger_condition, stages, enabled, execution_count, created_at, updated_at FROM playbooks WHERE 1=1",
        );

        if filter.enabled.is_some() {
            query.push_str(" AND enabled = ?");
        }

        if filter.trigger_type.is_some() {
            query.push_str(" AND trigger_type = ?");
        }

        if filter.name_contains.is_some() {
            query.push_str(" AND name LIKE ?");
        }

        query.push_str(" ORDER BY created_at DESC");

        let mut query_builder = sqlx::query_as::<_, PlaybookRow>(&query);

        if let Some(enabled) = filter.enabled {
            query_builder = query_builder.bind(if enabled { 1 } else { 0 });
        }

        if let Some(trigger_type) = &filter.trigger_type {
            query_builder = query_builder.bind(trigger_type);
        }

        if let Some(name_contains) = &filter.name_contains {
            query_builder = query_builder.bind(format!("%{}%", name_contains));
        }

        let rows: Vec<PlaybookRow> = query_builder.fetch_all(&self.pool).await?;

        rows.into_iter().map(|r| r.try_into()).collect()
    }

    async fn update(&self, id: Uuid, update: &PlaybookUpdate) -> Result<Playbook, DbError> {
        let id_str = id.to_string();
        let now = Utc::now().to_rfc3339();

        let mut set_clauses = vec!["updated_at = ?".to_string()];
        let mut bindings: Vec<SqliteBinding> = vec![SqliteBinding::String(now)];

        if let Some(name) = &update.name {
            set_clauses.push("name = ?".to_string());
            bindings.push(SqliteBinding::String(name.clone()));
        }

        if let Some(description) = &update.description {
            set_clauses.push("description = ?".to_string());
            bindings.push(SqliteBinding::OptionalString(description.clone()));
        }

        if let Some(trigger_type) = &update.trigger_type {
            set_clauses.push("trigger_type = ?".to_string());
            bindings.push(SqliteBinding::String(trigger_type.clone()));
        }

        if let Some(trigger_condition) = &update.trigger_condition {
            set_clauses.push("trigger_condition = ?".to_string());
            bindings.push(SqliteBinding::OptionalString(trigger_condition.clone()));
        }

        if let Some(stages) = &update.stages {
            set_clauses.push("stages = ?".to_string());
            bindings.push(SqliteBinding::String(serde_json::to_string(stages)?));
        }

        if let Some(enabled) = update.enabled {
            set_clauses.push("enabled = ?".to_string());
            bindings.push(SqliteBinding::Int(if enabled { 1 } else { 0 }));
        }

        let query = format!(
            "UPDATE playbooks SET {} WHERE id = ?",
            set_clauses.join(", ")
        );

        let mut query_builder = sqlx::query(&query);

        for binding in bindings {
            query_builder = match binding {
                SqliteBinding::String(s) => query_builder.bind(s),
                SqliteBinding::OptionalString(s) => query_builder.bind(s),
                SqliteBinding::Int(i) => query_builder.bind(i),
            };
        }

        query_builder = query_builder.bind(&id_str);
        query_builder.execute(&self.pool).await?;

        self.get(id).await?.ok_or_else(|| DbError::NotFound {
            entity: "Playbook".to_string(),
            id: id.to_string(),
        })
    }

    async fn delete(&self, id: Uuid) -> Result<bool, DbError> {
        let id_str = id.to_string();

        let result = sqlx::query("DELETE FROM playbooks WHERE id = ?")
            .bind(&id_str)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    async fn toggle_enabled(&self, id: Uuid) -> Result<Playbook, DbError> {
        let id_str = id.to_string();
        let now = Utc::now().to_rfc3339();

        sqlx::query(r#"UPDATE playbooks SET enabled = NOT enabled, updated_at = ? WHERE id = ?"#)
            .bind(&now)
            .bind(&id_str)
            .execute(&self.pool)
            .await?;

        self.get(id).await?.ok_or_else(|| DbError::NotFound {
            entity: "Playbook".to_string(),
            id: id.to_string(),
        })
    }

    async fn increment_execution_count(&self, id: Uuid) -> Result<Playbook, DbError> {
        let id_str = id.to_string();
        let now = Utc::now().to_rfc3339();

        sqlx::query(
            r#"UPDATE playbooks SET execution_count = execution_count + 1, updated_at = ? WHERE id = ?"#,
        )
        .bind(&now)
        .bind(&id_str)
        .execute(&self.pool)
        .await?;

        self.get(id).await?.ok_or_else(|| DbError::NotFound {
            entity: "Playbook".to_string(),
            id: id.to_string(),
        })
    }
}

/// PostgreSQL implementation of PlaybookRepository.
#[cfg(feature = "database")]
pub struct PgPlaybookRepository {
    pool: sqlx::PgPool,
}

#[cfg(feature = "database")]
impl PgPlaybookRepository {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

#[cfg(feature = "database")]
#[async_trait]
impl PlaybookRepository for PgPlaybookRepository {
    async fn create(&self, playbook: &Playbook) -> Result<Playbook, DbError> {
        let stages = serde_json::to_value(&playbook.stages)?;

        sqlx::query(
            r#"
            INSERT INTO playbooks (id, name, description, trigger_type, trigger_condition, stages, enabled, execution_count, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#,
        )
        .bind(playbook.id)
        .bind(&playbook.name)
        .bind(&playbook.description)
        .bind(&playbook.trigger_type)
        .bind(&playbook.trigger_condition)
        .bind(&stages)
        .bind(playbook.enabled)
        .bind(playbook.execution_count as i32)
        .bind(playbook.created_at)
        .bind(playbook.updated_at)
        .execute(&self.pool)
        .await?;

        Ok(playbook.clone())
    }

    async fn get(&self, id: Uuid) -> Result<Option<Playbook>, DbError> {
        let row: Option<PgPlaybookRow> = sqlx::query_as(
            r#"SELECT id, name, description, trigger_type, trigger_condition, stages, enabled, execution_count, created_at, updated_at FROM playbooks WHERE id = $1"#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => Ok(Some(row.try_into()?)),
            None => Ok(None),
        }
    }

    async fn get_by_name(&self, name: &str) -> Result<Option<Playbook>, DbError> {
        let row: Option<PgPlaybookRow> = sqlx::query_as(
            r#"SELECT id, name, description, trigger_type, trigger_condition, stages, enabled, execution_count, created_at, updated_at FROM playbooks WHERE name = $1"#,
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => Ok(Some(row.try_into()?)),
            None => Ok(None),
        }
    }

    async fn list(&self, filter: &PlaybookFilter) -> Result<Vec<Playbook>, DbError> {
        let rows: Vec<PgPlaybookRow> = sqlx::query_as(
            r#"
            SELECT id, name, description, trigger_type, trigger_condition, stages, enabled, execution_count, created_at, updated_at
            FROM playbooks
            WHERE ($1::boolean IS NULL OR enabled = $1)
              AND ($2::text IS NULL OR trigger_type = $2)
              AND ($3::text IS NULL OR name ILIKE '%' || $3 || '%')
            ORDER BY created_at DESC
            "#,
        )
        .bind(filter.enabled)
        .bind(&filter.trigger_type)
        .bind(&filter.name_contains)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into()).collect()
    }

    async fn update(&self, id: Uuid, update: &PlaybookUpdate) -> Result<Playbook, DbError> {
        let stages_json = update
            .stages
            .as_ref()
            .map(serde_json::to_value)
            .transpose()?;

        sqlx::query(
            r#"
            UPDATE playbooks SET
                name = COALESCE($2, name),
                description = CASE WHEN $3::boolean THEN $4 ELSE description END,
                trigger_type = COALESCE($5, trigger_type),
                trigger_condition = CASE WHEN $6::boolean THEN $7 ELSE trigger_condition END,
                stages = COALESCE($8, stages),
                enabled = COALESCE($9, enabled),
                updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(&update.name)
        .bind(update.description.is_some())
        .bind(update.description.as_ref().and_then(|d| d.clone()))
        .bind(&update.trigger_type)
        .bind(update.trigger_condition.is_some())
        .bind(update.trigger_condition.as_ref().and_then(|c| c.clone()))
        .bind(&stages_json)
        .bind(update.enabled)
        .execute(&self.pool)
        .await?;

        self.get(id).await?.ok_or_else(|| DbError::NotFound {
            entity: "Playbook".to_string(),
            id: id.to_string(),
        })
    }

    async fn delete(&self, id: Uuid) -> Result<bool, DbError> {
        let result = sqlx::query("DELETE FROM playbooks WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    async fn toggle_enabled(&self, id: Uuid) -> Result<Playbook, DbError> {
        sqlx::query(
            r#"UPDATE playbooks SET enabled = NOT enabled, updated_at = NOW() WHERE id = $1"#,
        )
        .bind(id)
        .execute(&self.pool)
        .await?;

        self.get(id).await?.ok_or_else(|| DbError::NotFound {
            entity: "Playbook".to_string(),
            id: id.to_string(),
        })
    }

    async fn increment_execution_count(&self, id: Uuid) -> Result<Playbook, DbError> {
        sqlx::query(
            r#"UPDATE playbooks SET execution_count = execution_count + 1, updated_at = NOW() WHERE id = $1"#,
        )
        .bind(id)
        .execute(&self.pool)
        .await?;

        self.get(id).await?.ok_or_else(|| DbError::NotFound {
            entity: "Playbook".to_string(),
            id: id.to_string(),
        })
    }
}

/// Factory function to create the appropriate repository based on pool type.
#[cfg(feature = "database")]
pub fn create_playbook_repository(pool: &DbPool) -> Box<dyn PlaybookRepository> {
    match pool {
        DbPool::Sqlite(pool) => Box::new(SqlitePlaybookRepository::new(pool.clone())),
        DbPool::Postgres(pool) => Box::new(PgPlaybookRepository::new(pool.clone())),
    }
}

// Helper enum for SQLite dynamic bindings
#[cfg(feature = "database")]
enum SqliteBinding {
    String(String),
    OptionalString(Option<String>),
    Int(i32),
}

// Helper structs for SQLx row mapping

#[cfg(feature = "database")]
#[derive(sqlx::FromRow)]
struct PlaybookRow {
    id: String,
    name: String,
    description: Option<String>,
    trigger_type: String,
    trigger_condition: Option<String>,
    stages: String,
    enabled: i32,
    execution_count: i64,
    created_at: String,
    updated_at: String,
}

#[cfg(feature = "database")]
impl TryFrom<PlaybookRow> for Playbook {
    type Error = DbError;

    fn try_from(row: PlaybookRow) -> Result<Self, Self::Error> {
        Ok(Playbook {
            id: Uuid::parse_str(&row.id).map_err(|e| DbError::Serialization(e.to_string()))?,
            name: row.name,
            description: row.description,
            trigger_type: row.trigger_type,
            trigger_condition: row.trigger_condition,
            stages: serde_json::from_str(&row.stages)?,
            enabled: row.enabled != 0,
            execution_count: row.execution_count as u32,
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
#[derive(sqlx::FromRow)]
struct PgPlaybookRow {
    id: Uuid,
    name: String,
    description: Option<String>,
    trigger_type: String,
    trigger_condition: Option<String>,
    stages: serde_json::Value,
    enabled: bool,
    execution_count: i32,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[cfg(feature = "database")]
impl TryFrom<PgPlaybookRow> for Playbook {
    type Error = DbError;

    fn try_from(row: PgPlaybookRow) -> Result<Self, Self::Error> {
        Ok(Playbook {
            id: row.id,
            name: row.name,
            description: row.description,
            trigger_type: row.trigger_type,
            trigger_condition: row.trigger_condition,
            stages: serde_json::from_value(row.stages)?,
            enabled: row.enabled,
            execution_count: row.execution_count as u32,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_playbook_filter_default() {
        let f = PlaybookFilter::default();
        assert!(f.enabled.is_none());
        assert!(f.trigger_type.is_none());
        assert!(f.name_contains.is_none());
    }

    #[test]
    fn test_playbook_update_default() {
        let u = PlaybookUpdate::default();
        assert!(u.name.is_none());
        assert!(u.description.is_none());
        assert!(u.enabled.is_none());
    }
}
