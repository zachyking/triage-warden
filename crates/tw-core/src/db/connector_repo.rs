//! Connector repository for database operations.

use super::{DbError, DbPool};
use crate::connector::{ConnectorConfig, ConnectorStatus, ConnectorType};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Partial update for a connector configuration.
#[derive(Debug, Clone, Default)]
pub struct ConnectorUpdate {
    /// New name for the connector.
    pub name: Option<String>,
    /// New configuration JSON.
    pub config: Option<serde_json::Value>,
    /// New enabled state.
    pub enabled: Option<bool>,
}

/// Repository trait for connector configuration persistence.
#[async_trait]
pub trait ConnectorRepository: Send + Sync {
    /// Creates a new connector configuration.
    async fn create(&self, connector: &ConnectorConfig) -> Result<ConnectorConfig, DbError>;

    /// Gets a connector configuration by ID.
    async fn get(&self, id: Uuid) -> Result<Option<ConnectorConfig>, DbError>;

    /// Lists all connector configurations.
    async fn list(&self) -> Result<Vec<ConnectorConfig>, DbError>;

    /// Lists connector configurations by type.
    async fn list_by_type(
        &self,
        connector_type: ConnectorType,
    ) -> Result<Vec<ConnectorConfig>, DbError>;

    /// Lists enabled connector configurations.
    async fn list_enabled(&self) -> Result<Vec<ConnectorConfig>, DbError>;

    /// Updates a connector configuration.
    async fn update(&self, id: Uuid, update: &ConnectorUpdate) -> Result<ConnectorConfig, DbError>;

    /// Deletes a connector configuration.
    async fn delete(&self, id: Uuid) -> Result<bool, DbError>;

    /// Updates the status of a connector.
    async fn update_status(
        &self,
        id: Uuid,
        status: ConnectorStatus,
    ) -> Result<ConnectorConfig, DbError>;

    /// Updates the last health check timestamp.
    async fn update_health_check(&self, id: Uuid) -> Result<ConnectorConfig, DbError>;
}

/// SQLite implementation of ConnectorRepository.
#[cfg(feature = "database")]
pub struct SqliteConnectorRepository {
    pool: sqlx::SqlitePool,
}

#[cfg(feature = "database")]
impl SqliteConnectorRepository {
    pub fn new(pool: sqlx::SqlitePool) -> Self {
        Self { pool }
    }
}

#[cfg(feature = "database")]
#[async_trait]
impl ConnectorRepository for SqliteConnectorRepository {
    async fn create(&self, connector: &ConnectorConfig) -> Result<ConnectorConfig, DbError> {
        let id = connector.id.to_string();
        let connector_type = connector.connector_type.as_db_str();
        let config = serde_json::to_string(&connector.config)?;
        let status = connector.status.as_db_str();
        let last_health_check = connector.last_health_check.map(|dt| dt.to_rfc3339());
        let created_at = connector.created_at.to_rfc3339();
        let updated_at = connector.updated_at.to_rfc3339();

        sqlx::query(
            r#"
            INSERT INTO connectors (id, name, connector_type, config, status, enabled, last_health_check, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&id)
        .bind(&connector.name)
        .bind(connector_type)
        .bind(&config)
        .bind(status)
        .bind(connector.enabled)
        .bind(&last_health_check)
        .bind(&created_at)
        .bind(&updated_at)
        .execute(&self.pool)
        .await?;

        Ok(connector.clone())
    }

    async fn get(&self, id: Uuid) -> Result<Option<ConnectorConfig>, DbError> {
        let id_str = id.to_string();

        let row: Option<ConnectorRow> = sqlx::query_as(
            r#"
            SELECT id, name, connector_type, config, status, enabled, last_health_check, created_at, updated_at
            FROM connectors
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

    async fn list(&self) -> Result<Vec<ConnectorConfig>, DbError> {
        let rows: Vec<ConnectorRow> = sqlx::query_as(
            r#"
            SELECT id, name, connector_type, config, status, enabled, last_health_check, created_at, updated_at
            FROM connectors
            ORDER BY name ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into()).collect()
    }

    async fn list_by_type(
        &self,
        connector_type: ConnectorType,
    ) -> Result<Vec<ConnectorConfig>, DbError> {
        let type_str = connector_type.as_db_str();

        let rows: Vec<ConnectorRow> = sqlx::query_as(
            r#"
            SELECT id, name, connector_type, config, status, enabled, last_health_check, created_at, updated_at
            FROM connectors
            WHERE connector_type = ?
            ORDER BY name ASC
            "#,
        )
        .bind(type_str)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into()).collect()
    }

    async fn list_enabled(&self) -> Result<Vec<ConnectorConfig>, DbError> {
        let rows: Vec<ConnectorRow> = sqlx::query_as(
            r#"
            SELECT id, name, connector_type, config, status, enabled, last_health_check, created_at, updated_at
            FROM connectors
            WHERE enabled = TRUE
            ORDER BY name ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into()).collect()
    }

    async fn update(&self, id: Uuid, update: &ConnectorUpdate) -> Result<ConnectorConfig, DbError> {
        let id_str = id.to_string();
        let now = Utc::now().to_rfc3339();

        // Build dynamic update query
        let mut set_clauses = vec!["updated_at = ?".to_string()];
        let mut values: Vec<String> = vec![now];

        if let Some(name) = &update.name {
            set_clauses.push("name = ?".to_string());
            values.push(name.clone());
        }

        if let Some(config) = &update.config {
            set_clauses.push("config = ?".to_string());
            values.push(serde_json::to_string(config)?);
        }

        let query = format!(
            "UPDATE connectors SET {} WHERE id = ?",
            set_clauses.join(", ")
        );

        let mut query_builder = sqlx::query(&query);

        for value in &values {
            query_builder = query_builder.bind(value);
        }

        // Handle enabled separately since it's a boolean
        if let Some(enabled) = update.enabled {
            // Re-build query with enabled
            let mut set_clauses = vec!["updated_at = ?".to_string()];

            if update.name.is_some() {
                set_clauses.push("name = ?".to_string());
            }

            if update.config.is_some() {
                set_clauses.push("config = ?".to_string());
            }

            set_clauses.push("enabled = ?".to_string());

            let query = format!(
                "UPDATE connectors SET {} WHERE id = ?",
                set_clauses.join(", ")
            );

            let mut query_builder = sqlx::query(&query);
            query_builder = query_builder.bind(Utc::now().to_rfc3339());

            if let Some(name) = &update.name {
                query_builder = query_builder.bind(name);
            }

            if let Some(config) = &update.config {
                query_builder = query_builder.bind(serde_json::to_string(config)?);
            }

            query_builder = query_builder.bind(enabled);
            query_builder = query_builder.bind(&id_str);
            query_builder.execute(&self.pool).await?;
        } else {
            query_builder = query_builder.bind(&id_str);
            query_builder.execute(&self.pool).await?;
        }

        self.get(id).await?.ok_or_else(|| DbError::NotFound {
            entity: "Connector".to_string(),
            id: id.to_string(),
        })
    }

    async fn delete(&self, id: Uuid) -> Result<bool, DbError> {
        let id_str = id.to_string();

        let result = sqlx::query("DELETE FROM connectors WHERE id = ?")
            .bind(&id_str)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    async fn update_status(
        &self,
        id: Uuid,
        status: ConnectorStatus,
    ) -> Result<ConnectorConfig, DbError> {
        let id_str = id.to_string();
        let status_str = status.as_db_str();
        let now = Utc::now().to_rfc3339();

        sqlx::query(
            r#"
            UPDATE connectors
            SET status = ?, updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(status_str)
        .bind(&now)
        .bind(&id_str)
        .execute(&self.pool)
        .await?;

        self.get(id).await?.ok_or_else(|| DbError::NotFound {
            entity: "Connector".to_string(),
            id: id.to_string(),
        })
    }

    async fn update_health_check(&self, id: Uuid) -> Result<ConnectorConfig, DbError> {
        let id_str = id.to_string();
        let now = Utc::now().to_rfc3339();

        sqlx::query(
            r#"
            UPDATE connectors
            SET last_health_check = ?, updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(&now)
        .bind(&now)
        .bind(&id_str)
        .execute(&self.pool)
        .await?;

        self.get(id).await?.ok_or_else(|| DbError::NotFound {
            entity: "Connector".to_string(),
            id: id.to_string(),
        })
    }
}

/// PostgreSQL implementation of ConnectorRepository.
#[cfg(feature = "database")]
pub struct PgConnectorRepository {
    pool: sqlx::PgPool,
}

#[cfg(feature = "database")]
impl PgConnectorRepository {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

#[cfg(feature = "database")]
#[async_trait]
impl ConnectorRepository for PgConnectorRepository {
    async fn create(&self, connector: &ConnectorConfig) -> Result<ConnectorConfig, DbError> {
        let connector_type = connector.connector_type.as_db_str();
        let status = connector.status.as_db_str();

        sqlx::query(
            r#"
            INSERT INTO connectors (id, name, connector_type, config, status, enabled, last_health_check, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
        )
        .bind(connector.id)
        .bind(&connector.name)
        .bind(connector_type)
        .bind(&connector.config)
        .bind(status)
        .bind(connector.enabled)
        .bind(connector.last_health_check)
        .bind(connector.created_at)
        .bind(connector.updated_at)
        .execute(&self.pool)
        .await?;

        Ok(connector.clone())
    }

    async fn get(&self, id: Uuid) -> Result<Option<ConnectorConfig>, DbError> {
        let row: Option<PgConnectorRow> = sqlx::query_as(
            r#"
            SELECT id, name, connector_type, config, status, enabled, last_health_check, created_at, updated_at
            FROM connectors
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

    async fn list(&self) -> Result<Vec<ConnectorConfig>, DbError> {
        let rows: Vec<PgConnectorRow> = sqlx::query_as(
            r#"
            SELECT id, name, connector_type, config, status, enabled, last_health_check, created_at, updated_at
            FROM connectors
            ORDER BY name ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into()).collect()
    }

    async fn list_by_type(
        &self,
        connector_type: ConnectorType,
    ) -> Result<Vec<ConnectorConfig>, DbError> {
        let type_str = connector_type.as_db_str();

        let rows: Vec<PgConnectorRow> = sqlx::query_as(
            r#"
            SELECT id, name, connector_type, config, status, enabled, last_health_check, created_at, updated_at
            FROM connectors
            WHERE connector_type = $1
            ORDER BY name ASC
            "#,
        )
        .bind(type_str)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into()).collect()
    }

    async fn list_enabled(&self) -> Result<Vec<ConnectorConfig>, DbError> {
        let rows: Vec<PgConnectorRow> = sqlx::query_as(
            r#"
            SELECT id, name, connector_type, config, status, enabled, last_health_check, created_at, updated_at
            FROM connectors
            WHERE enabled = TRUE
            ORDER BY name ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into()).collect()
    }

    async fn update(&self, id: Uuid, update: &ConnectorUpdate) -> Result<ConnectorConfig, DbError> {
        sqlx::query(
            r#"
            UPDATE connectors SET
                name = COALESCE($2, name),
                config = COALESCE($3, config),
                enabled = COALESCE($4, enabled),
                updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(&update.name)
        .bind(&update.config)
        .bind(update.enabled)
        .execute(&self.pool)
        .await?;

        self.get(id).await?.ok_or_else(|| DbError::NotFound {
            entity: "Connector".to_string(),
            id: id.to_string(),
        })
    }

    async fn delete(&self, id: Uuid) -> Result<bool, DbError> {
        let result = sqlx::query("DELETE FROM connectors WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    async fn update_status(
        &self,
        id: Uuid,
        status: ConnectorStatus,
    ) -> Result<ConnectorConfig, DbError> {
        let status_str = status.as_db_str();

        sqlx::query(
            r#"
            UPDATE connectors
            SET status = $2, updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(status_str)
        .execute(&self.pool)
        .await?;

        self.get(id).await?.ok_or_else(|| DbError::NotFound {
            entity: "Connector".to_string(),
            id: id.to_string(),
        })
    }

    async fn update_health_check(&self, id: Uuid) -> Result<ConnectorConfig, DbError> {
        sqlx::query(
            r#"
            UPDATE connectors
            SET last_health_check = NOW(), updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(id)
        .execute(&self.pool)
        .await?;

        self.get(id).await?.ok_or_else(|| DbError::NotFound {
            entity: "Connector".to_string(),
            id: id.to_string(),
        })
    }
}

/// Factory function to create the appropriate repository based on pool type.
#[cfg(feature = "database")]
pub fn create_connector_repository(pool: &DbPool) -> Box<dyn ConnectorRepository> {
    match pool {
        DbPool::Sqlite(pool) => Box::new(SqliteConnectorRepository::new(pool.clone())),
        DbPool::Postgres(pool) => Box::new(PgConnectorRepository::new(pool.clone())),
    }
}

// Helper structs for SQLx row mapping

#[cfg(feature = "database")]
#[derive(sqlx::FromRow)]
struct ConnectorRow {
    id: String,
    name: String,
    connector_type: String,
    config: String,
    status: String,
    enabled: bool,
    last_health_check: Option<String>,
    created_at: String,
    updated_at: String,
}

#[cfg(feature = "database")]
impl TryFrom<ConnectorRow> for ConnectorConfig {
    type Error = DbError;

    fn try_from(row: ConnectorRow) -> Result<Self, Self::Error> {
        let connector_type = ConnectorType::from_db_str(&row.connector_type).ok_or_else(|| {
            DbError::Serialization(format!("Unknown connector type: {}", row.connector_type))
        })?;

        let status = ConnectorStatus::from_db_str(&row.status).ok_or_else(|| {
            DbError::Serialization(format!("Unknown connector status: {}", row.status))
        })?;

        let last_health_check = row
            .last_health_check
            .map(|dt| {
                DateTime::parse_from_rfc3339(&dt)
                    .map_err(|e| DbError::Serialization(e.to_string()))
                    .map(|dt| dt.with_timezone(&Utc))
            })
            .transpose()?;

        Ok(ConnectorConfig {
            id: Uuid::parse_str(&row.id).map_err(|e| DbError::Serialization(e.to_string()))?,
            name: row.name,
            connector_type,
            config: serde_json::from_str(&row.config)?,
            status,
            enabled: row.enabled,
            last_health_check,
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
struct PgConnectorRow {
    id: Uuid,
    name: String,
    connector_type: String,
    config: serde_json::Value,
    status: String,
    enabled: bool,
    last_health_check: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[cfg(feature = "database")]
impl TryFrom<PgConnectorRow> for ConnectorConfig {
    type Error = DbError;

    fn try_from(row: PgConnectorRow) -> Result<Self, Self::Error> {
        let connector_type = ConnectorType::from_db_str(&row.connector_type).ok_or_else(|| {
            DbError::Serialization(format!("Unknown connector type: {}", row.connector_type))
        })?;

        let status = ConnectorStatus::from_db_str(&row.status).ok_or_else(|| {
            DbError::Serialization(format!("Unknown connector status: {}", row.status))
        })?;

        Ok(ConnectorConfig {
            id: row.id,
            name: row.name,
            connector_type,
            config: row.config,
            status,
            enabled: row.enabled,
            last_health_check: row.last_health_check,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connector_update_default() {
        let update = ConnectorUpdate::default();
        assert!(update.name.is_none());
        assert!(update.config.is_none());
        assert!(update.enabled.is_none());
    }
}
