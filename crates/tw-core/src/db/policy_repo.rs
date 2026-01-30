//! Policy repository for database operations.

use super::{DbError, DbPool};
use crate::policy::{ApprovalLevel, Policy, PolicyAction};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Partial update for a policy.
#[derive(Debug, Clone, Default)]
pub struct PolicyUpdate {
    pub name: Option<String>,
    pub description: Option<Option<String>>,
    pub condition: Option<String>,
    pub action: Option<PolicyAction>,
    pub approval_level: Option<Option<ApprovalLevel>>,
    pub priority: Option<i32>,
    pub enabled: Option<bool>,
}

/// Repository trait for policy persistence.
#[async_trait]
pub trait PolicyRepository: Send + Sync {
    /// Creates a new policy.
    async fn create(&self, policy: &Policy) -> Result<Policy, DbError>;

    /// Gets a policy by ID.
    async fn get(&self, id: Uuid) -> Result<Option<Policy>, DbError>;

    /// Lists all policies ordered by priority.
    async fn list(&self) -> Result<Vec<Policy>, DbError>;

    /// Updates a policy.
    async fn update(&self, id: Uuid, update: &PolicyUpdate) -> Result<Policy, DbError>;

    /// Deletes a policy.
    async fn delete(&self, id: Uuid) -> Result<bool, DbError>;

    /// Toggles the enabled status of a policy.
    async fn toggle_enabled(&self, id: Uuid) -> Result<Policy, DbError>;

    /// Lists only enabled policies ordered by priority (for policy engine).
    async fn list_enabled(&self) -> Result<Vec<Policy>, DbError>;
}

/// SQLite implementation of PolicyRepository.
#[cfg(feature = "database")]
pub struct SqlitePolicyRepository {
    pool: sqlx::SqlitePool,
}

#[cfg(feature = "database")]
impl SqlitePolicyRepository {
    pub fn new(pool: sqlx::SqlitePool) -> Self {
        Self { pool }
    }
}

#[cfg(feature = "database")]
#[async_trait]
impl PolicyRepository for SqlitePolicyRepository {
    async fn create(&self, policy: &Policy) -> Result<Policy, DbError> {
        let id = policy.id.to_string();
        let action = policy.action.as_db_str();
        let approval_level = policy.approval_level.as_ref().map(|l| l.as_db_str());
        let created_at = policy.created_at.to_rfc3339();
        let updated_at = policy.updated_at.to_rfc3339();

        sqlx::query(
            r#"
            INSERT INTO policies (id, name, description, condition, action, approval_level, priority, enabled, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&id)
        .bind(&policy.name)
        .bind(&policy.description)
        .bind(&policy.condition)
        .bind(action)
        .bind(approval_level)
        .bind(policy.priority)
        .bind(policy.enabled)
        .bind(&created_at)
        .bind(&updated_at)
        .execute(&self.pool)
        .await?;

        Ok(policy.clone())
    }

    async fn get(&self, id: Uuid) -> Result<Option<Policy>, DbError> {
        let id_str = id.to_string();

        let row: Option<PolicyRow> = sqlx::query_as(
            r#"SELECT id, name, description, condition, action, approval_level, priority, enabled, created_at, updated_at FROM policies WHERE id = ?"#,
        )
        .bind(&id_str)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => Ok(Some(row.try_into()?)),
            None => Ok(None),
        }
    }

    async fn list(&self) -> Result<Vec<Policy>, DbError> {
        let rows: Vec<PolicyRow> = sqlx::query_as(
            r#"SELECT id, name, description, condition, action, approval_level, priority, enabled, created_at, updated_at FROM policies ORDER BY priority ASC, created_at ASC"#,
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into()).collect()
    }

    async fn update(&self, id: Uuid, update: &PolicyUpdate) -> Result<Policy, DbError> {
        let id_str = id.to_string();
        let now = Utc::now().to_rfc3339();

        // Build dynamic update query
        let mut set_clauses = vec!["updated_at = ?".to_string()];
        let mut values: Vec<Option<String>> = vec![Some(now)];

        if let Some(name) = &update.name {
            set_clauses.push("name = ?".to_string());
            values.push(Some(name.clone()));
        }

        if let Some(description) = &update.description {
            set_clauses.push("description = ?".to_string());
            values.push(description.clone());
        }

        if let Some(condition) = &update.condition {
            set_clauses.push("condition = ?".to_string());
            values.push(Some(condition.clone()));
        }

        if let Some(action) = &update.action {
            set_clauses.push("action = ?".to_string());
            values.push(Some(action.as_db_str().to_string()));
        }

        if let Some(approval_level) = &update.approval_level {
            set_clauses.push("approval_level = ?".to_string());
            values.push(approval_level.as_ref().map(|l| l.as_db_str().to_string()));
        }

        if let Some(priority) = &update.priority {
            set_clauses.push("priority = ?".to_string());
            values.push(Some(priority.to_string()));
        }

        if let Some(enabled) = &update.enabled {
            set_clauses.push("enabled = ?".to_string());
            values.push(Some(if *enabled { "1" } else { "0" }.to_string()));
        }

        let query = format!(
            "UPDATE policies SET {} WHERE id = ?",
            set_clauses.join(", ")
        );

        let mut query_builder = sqlx::query(&query);

        for value in &values {
            query_builder = query_builder.bind(value);
        }

        query_builder = query_builder.bind(&id_str);
        query_builder.execute(&self.pool).await?;

        self.get(id).await?.ok_or_else(|| DbError::NotFound {
            entity: "Policy".to_string(),
            id: id.to_string(),
        })
    }

    async fn delete(&self, id: Uuid) -> Result<bool, DbError> {
        let id_str = id.to_string();

        let result = sqlx::query("DELETE FROM policies WHERE id = ?")
            .bind(&id_str)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    async fn toggle_enabled(&self, id: Uuid) -> Result<Policy, DbError> {
        let id_str = id.to_string();
        let now = Utc::now().to_rfc3339();

        sqlx::query(r#"UPDATE policies SET enabled = NOT enabled, updated_at = ? WHERE id = ?"#)
            .bind(&now)
            .bind(&id_str)
            .execute(&self.pool)
            .await?;

        self.get(id).await?.ok_or_else(|| DbError::NotFound {
            entity: "Policy".to_string(),
            id: id.to_string(),
        })
    }

    async fn list_enabled(&self) -> Result<Vec<Policy>, DbError> {
        let rows: Vec<PolicyRow> = sqlx::query_as(
            r#"SELECT id, name, description, condition, action, approval_level, priority, enabled, created_at, updated_at FROM policies WHERE enabled = 1 ORDER BY priority ASC, created_at ASC"#,
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into()).collect()
    }
}

/// PostgreSQL implementation of PolicyRepository.
#[cfg(feature = "database")]
pub struct PgPolicyRepository {
    pool: sqlx::PgPool,
}

#[cfg(feature = "database")]
impl PgPolicyRepository {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

#[cfg(feature = "database")]
#[async_trait]
impl PolicyRepository for PgPolicyRepository {
    async fn create(&self, policy: &Policy) -> Result<Policy, DbError> {
        let action = policy.action.as_db_str();
        let approval_level = policy.approval_level.as_ref().map(|l| l.as_db_str());

        sqlx::query(
            r#"
            INSERT INTO policies (id, name, description, condition, action, approval_level, priority, enabled, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#,
        )
        .bind(policy.id)
        .bind(&policy.name)
        .bind(&policy.description)
        .bind(&policy.condition)
        .bind(action)
        .bind(approval_level)
        .bind(policy.priority)
        .bind(policy.enabled)
        .bind(policy.created_at)
        .bind(policy.updated_at)
        .execute(&self.pool)
        .await?;

        Ok(policy.clone())
    }

    async fn get(&self, id: Uuid) -> Result<Option<Policy>, DbError> {
        let row: Option<PgPolicyRow> = sqlx::query_as(
            r#"SELECT id, name, description, condition, action, approval_level, priority, enabled, created_at, updated_at FROM policies WHERE id = $1"#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => Ok(Some(row.try_into()?)),
            None => Ok(None),
        }
    }

    async fn list(&self) -> Result<Vec<Policy>, DbError> {
        let rows: Vec<PgPolicyRow> = sqlx::query_as(
            r#"SELECT id, name, description, condition, action, approval_level, priority, enabled, created_at, updated_at FROM policies ORDER BY priority ASC, created_at ASC"#,
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into()).collect()
    }

    async fn update(&self, id: Uuid, update: &PolicyUpdate) -> Result<Policy, DbError> {
        sqlx::query(
            r#"
            UPDATE policies SET
                name = COALESCE($2, name),
                description = CASE WHEN $3::boolean THEN $4 ELSE description END,
                condition = COALESCE($5, condition),
                action = COALESCE($6, action),
                approval_level = CASE WHEN $7::boolean THEN $8 ELSE approval_level END,
                priority = COALESCE($9, priority),
                enabled = COALESCE($10, enabled),
                updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(&update.name)
        .bind(update.description.is_some())
        .bind(update.description.as_ref().and_then(|d| d.as_ref()))
        .bind(&update.condition)
        .bind(update.action.as_ref().map(|a| a.as_db_str()))
        .bind(update.approval_level.is_some())
        .bind(
            update
                .approval_level
                .as_ref()
                .and_then(|l| l.as_ref().map(|a| a.as_db_str())),
        )
        .bind(update.priority)
        .bind(update.enabled)
        .execute(&self.pool)
        .await?;

        self.get(id).await?.ok_or_else(|| DbError::NotFound {
            entity: "Policy".to_string(),
            id: id.to_string(),
        })
    }

    async fn delete(&self, id: Uuid) -> Result<bool, DbError> {
        let result = sqlx::query("DELETE FROM policies WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    async fn toggle_enabled(&self, id: Uuid) -> Result<Policy, DbError> {
        sqlx::query(
            r#"UPDATE policies SET enabled = NOT enabled, updated_at = NOW() WHERE id = $1"#,
        )
        .bind(id)
        .execute(&self.pool)
        .await?;

        self.get(id).await?.ok_or_else(|| DbError::NotFound {
            entity: "Policy".to_string(),
            id: id.to_string(),
        })
    }

    async fn list_enabled(&self) -> Result<Vec<Policy>, DbError> {
        let rows: Vec<PgPolicyRow> = sqlx::query_as(
            r#"SELECT id, name, description, condition, action, approval_level, priority, enabled, created_at, updated_at FROM policies WHERE enabled = true ORDER BY priority ASC, created_at ASC"#,
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into()).collect()
    }
}

/// Factory function to create the appropriate repository based on pool type.
#[cfg(feature = "database")]
pub fn create_policy_repository(pool: &DbPool) -> Box<dyn PolicyRepository> {
    match pool {
        DbPool::Sqlite(pool) => Box::new(SqlitePolicyRepository::new(pool.clone())),
        DbPool::Postgres(pool) => Box::new(PgPolicyRepository::new(pool.clone())),
    }
}

// Helper structs for SQLx row mapping

#[cfg(feature = "database")]
#[derive(sqlx::FromRow)]
struct PolicyRow {
    id: String,
    name: String,
    description: Option<String>,
    condition: String,
    action: String,
    approval_level: Option<String>,
    priority: i32,
    enabled: bool,
    created_at: String,
    updated_at: String,
}

#[cfg(feature = "database")]
impl TryFrom<PolicyRow> for Policy {
    type Error = DbError;

    fn try_from(row: PolicyRow) -> Result<Self, Self::Error> {
        let action = PolicyAction::from_db_str(&row.action).ok_or_else(|| {
            DbError::Serialization(format!("Unknown policy action: {}", row.action))
        })?;

        let approval_level = row
            .approval_level
            .as_ref()
            .map(|s| {
                ApprovalLevel::from_db_str(s)
                    .ok_or_else(|| DbError::Serialization(format!("Unknown approval level: {}", s)))
            })
            .transpose()?;

        Ok(Policy {
            id: Uuid::parse_str(&row.id).map_err(|e| DbError::Serialization(e.to_string()))?,
            name: row.name,
            description: row.description,
            condition: row.condition,
            action,
            approval_level,
            priority: row.priority,
            enabled: row.enabled,
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
struct PgPolicyRow {
    id: Uuid,
    name: String,
    description: Option<String>,
    condition: String,
    action: String,
    approval_level: Option<String>,
    priority: i32,
    enabled: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[cfg(feature = "database")]
impl TryFrom<PgPolicyRow> for Policy {
    type Error = DbError;

    fn try_from(row: PgPolicyRow) -> Result<Self, Self::Error> {
        let action = PolicyAction::from_db_str(&row.action).ok_or_else(|| {
            DbError::Serialization(format!("Unknown policy action: {}", row.action))
        })?;

        let approval_level = row
            .approval_level
            .as_ref()
            .map(|s| {
                ApprovalLevel::from_db_str(s)
                    .ok_or_else(|| DbError::Serialization(format!("Unknown approval level: {}", s)))
            })
            .transpose()?;

        Ok(Policy {
            id: row.id,
            name: row.name,
            description: row.description,
            condition: row.condition,
            action,
            approval_level,
            priority: row.priority,
            enabled: row.enabled,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_update_default() {
        let update = PolicyUpdate::default();
        assert!(update.name.is_none());
        assert!(update.description.is_none());
        assert!(update.condition.is_none());
        assert!(update.action.is_none());
        assert!(update.approval_level.is_none());
        assert!(update.priority.is_none());
        assert!(update.enabled.is_none());
    }
}
