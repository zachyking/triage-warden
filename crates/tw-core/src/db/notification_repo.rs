//! Notification channel repository for database operations.

use super::{DbError, DbPool};
use crate::notification::{ChannelType, NotificationChannel, NotificationChannelUpdate};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Filter for listing notification channels.
#[derive(Debug, Clone, Default)]
pub struct NotificationChannelFilter {
    /// Filter by tenant ID.
    pub tenant_id: Option<Uuid>,
    /// Filter by enabled status.
    pub enabled: Option<bool>,
}

/// Repository trait for notification channel persistence.
#[async_trait]
pub trait NotificationChannelRepository: Send + Sync {
    /// Creates a new notification channel for a tenant.
    async fn create(
        &self,
        tenant_id: Uuid,
        channel: &NotificationChannel,
    ) -> Result<NotificationChannel, DbError>;

    /// Gets a notification channel by ID.
    async fn get(&self, id: Uuid) -> Result<Option<NotificationChannel>, DbError>;

    /// Gets a notification channel by ID within a specific tenant (ensures tenant isolation).
    async fn get_for_tenant(
        &self,
        id: Uuid,
        tenant_id: Uuid,
    ) -> Result<Option<NotificationChannel>, DbError>;

    /// Lists all notification channels.
    async fn list(&self) -> Result<Vec<NotificationChannel>, DbError>;

    /// Lists notification channels for a specific tenant.
    async fn list_for_tenant(&self, tenant_id: Uuid) -> Result<Vec<NotificationChannel>, DbError>;

    /// Updates a notification channel.
    async fn update(
        &self,
        id: Uuid,
        update: &NotificationChannelUpdate,
    ) -> Result<NotificationChannel, DbError>;

    /// Updates a notification channel within a specific tenant (ensures tenant isolation).
    async fn update_for_tenant(
        &self,
        id: Uuid,
        tenant_id: Uuid,
        update: &NotificationChannelUpdate,
    ) -> Result<NotificationChannel, DbError>;

    /// Deletes a notification channel.
    async fn delete(&self, id: Uuid) -> Result<bool, DbError>;

    /// Deletes a notification channel within a specific tenant (ensures tenant isolation).
    async fn delete_for_tenant(&self, id: Uuid, tenant_id: Uuid) -> Result<bool, DbError>;

    /// Toggles the enabled status of a notification channel.
    async fn toggle_enabled(&self, id: Uuid) -> Result<NotificationChannel, DbError>;

    /// Toggles the enabled status of a notification channel within a specific tenant.
    async fn toggle_enabled_for_tenant(
        &self,
        id: Uuid,
        tenant_id: Uuid,
    ) -> Result<NotificationChannel, DbError>;

    /// Lists enabled channels that are subscribed to a specific event type.
    async fn list_by_event(&self, event: &str) -> Result<Vec<NotificationChannel>, DbError>;

    /// Lists enabled channels that are subscribed to a specific event type within a tenant.
    async fn list_by_event_for_tenant(
        &self,
        event: &str,
        tenant_id: Uuid,
    ) -> Result<Vec<NotificationChannel>, DbError>;
}

/// SQLite implementation of NotificationChannelRepository.
#[cfg(feature = "database")]
pub struct SqliteNotificationChannelRepository {
    pool: sqlx::SqlitePool,
}

#[cfg(feature = "database")]
impl SqliteNotificationChannelRepository {
    pub fn new(pool: sqlx::SqlitePool) -> Self {
        Self { pool }
    }
}

#[cfg(feature = "database")]
#[async_trait]
impl NotificationChannelRepository for SqliteNotificationChannelRepository {
    async fn create(
        &self,
        tenant_id: Uuid,
        channel: &NotificationChannel,
    ) -> Result<NotificationChannel, DbError> {
        let id = channel.id.to_string();
        let tenant_id_str = tenant_id.to_string();
        let channel_type = channel.channel_type.as_db_str();
        let config = serde_json::to_string(&channel.config)?;
        let events = serde_json::to_string(&channel.events)?;
        let enabled = if channel.enabled { 1 } else { 0 };
        let created_at = channel.created_at.to_rfc3339();
        let updated_at = channel.updated_at.to_rfc3339();

        sqlx::query(
            r#"
            INSERT INTO notification_channels (id, tenant_id, name, channel_type, config, events, enabled, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&id)
        .bind(&tenant_id_str)
        .bind(&channel.name)
        .bind(channel_type)
        .bind(&config)
        .bind(&events)
        .bind(enabled)
        .bind(&created_at)
        .bind(&updated_at)
        .execute(&self.pool)
        .await?;

        Ok(channel.clone())
    }

    async fn get(&self, id: Uuid) -> Result<Option<NotificationChannel>, DbError> {
        let id_str = id.to_string();

        let row: Option<NotificationChannelRow> = sqlx::query_as(
            r#"SELECT id, tenant_id, name, channel_type, config, events, enabled, created_at, updated_at FROM notification_channels WHERE id = ?"#,
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
    ) -> Result<Option<NotificationChannel>, DbError> {
        let id_str = id.to_string();
        let tenant_id_str = tenant_id.to_string();

        let row: Option<NotificationChannelRow> = sqlx::query_as(
            r#"SELECT id, tenant_id, name, channel_type, config, events, enabled, created_at, updated_at FROM notification_channels WHERE id = ? AND tenant_id = ?"#,
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

    async fn list(&self) -> Result<Vec<NotificationChannel>, DbError> {
        let rows: Vec<NotificationChannelRow> = sqlx::query_as(
            r#"SELECT id, tenant_id, name, channel_type, config, events, enabled, created_at, updated_at FROM notification_channels ORDER BY name"#,
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into()).collect()
    }

    async fn list_for_tenant(&self, tenant_id: Uuid) -> Result<Vec<NotificationChannel>, DbError> {
        let tenant_id_str = tenant_id.to_string();

        let rows: Vec<NotificationChannelRow> = sqlx::query_as(
            r#"SELECT id, tenant_id, name, channel_type, config, events, enabled, created_at, updated_at FROM notification_channels WHERE tenant_id = ? ORDER BY name"#,
        )
        .bind(&tenant_id_str)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into()).collect()
    }

    async fn update(
        &self,
        id: Uuid,
        update: &NotificationChannelUpdate,
    ) -> Result<NotificationChannel, DbError> {
        let id_str = id.to_string();
        let now = Utc::now().to_rfc3339();

        // Build dynamic update query
        let mut set_clauses = vec!["updated_at = ?".to_string()];
        let mut values: Vec<String> = vec![now];

        if let Some(name) = &update.name {
            set_clauses.push("name = ?".to_string());
            values.push(name.clone());
        }

        if let Some(channel_type) = &update.channel_type {
            set_clauses.push("channel_type = ?".to_string());
            values.push(channel_type.as_db_str().to_string());
        }

        if let Some(config) = &update.config {
            set_clauses.push("config = ?".to_string());
            values.push(serde_json::to_string(config)?);
        }

        if let Some(events) = &update.events {
            set_clauses.push("events = ?".to_string());
            values.push(serde_json::to_string(events)?);
        }

        if let Some(enabled) = &update.enabled {
            set_clauses.push("enabled = ?".to_string());
            values.push(if *enabled {
                "1".to_string()
            } else {
                "0".to_string()
            });
        }

        let query = format!(
            "UPDATE notification_channels SET {} WHERE id = ?",
            set_clauses.join(", ")
        );

        let mut query_builder = sqlx::query(&query);

        for value in &values {
            query_builder = query_builder.bind(value);
        }

        query_builder = query_builder.bind(&id_str);
        query_builder.execute(&self.pool).await?;

        self.get(id).await?.ok_or_else(|| DbError::NotFound {
            entity: "NotificationChannel".to_string(),
            id: id.to_string(),
        })
    }

    async fn update_for_tenant(
        &self,
        id: Uuid,
        tenant_id: Uuid,
        update: &NotificationChannelUpdate,
    ) -> Result<NotificationChannel, DbError> {
        let id_str = id.to_string();
        let tenant_id_str = tenant_id.to_string();
        let now = Utc::now().to_rfc3339();

        // Build dynamic update query
        let mut set_clauses = vec!["updated_at = ?".to_string()];
        let mut values: Vec<String> = vec![now];

        if let Some(name) = &update.name {
            set_clauses.push("name = ?".to_string());
            values.push(name.clone());
        }

        if let Some(channel_type) = &update.channel_type {
            set_clauses.push("channel_type = ?".to_string());
            values.push(channel_type.as_db_str().to_string());
        }

        if let Some(config) = &update.config {
            set_clauses.push("config = ?".to_string());
            values.push(serde_json::to_string(config)?);
        }

        if let Some(events) = &update.events {
            set_clauses.push("events = ?".to_string());
            values.push(serde_json::to_string(events)?);
        }

        if let Some(enabled) = &update.enabled {
            set_clauses.push("enabled = ?".to_string());
            values.push(if *enabled {
                "1".to_string()
            } else {
                "0".to_string()
            });
        }

        let query = format!(
            "UPDATE notification_channels SET {} WHERE id = ? AND tenant_id = ?",
            set_clauses.join(", ")
        );

        let mut query_builder = sqlx::query(&query);

        for value in &values {
            query_builder = query_builder.bind(value);
        }

        query_builder = query_builder.bind(&id_str);
        query_builder = query_builder.bind(&tenant_id_str);
        query_builder.execute(&self.pool).await?;

        self.get_for_tenant(id, tenant_id)
            .await?
            .ok_or_else(|| DbError::NotFound {
                entity: "NotificationChannel".to_string(),
                id: id.to_string(),
            })
    }

    async fn delete(&self, id: Uuid) -> Result<bool, DbError> {
        let id_str = id.to_string();

        let result = sqlx::query("DELETE FROM notification_channels WHERE id = ?")
            .bind(&id_str)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    async fn delete_for_tenant(&self, id: Uuid, tenant_id: Uuid) -> Result<bool, DbError> {
        let id_str = id.to_string();
        let tenant_id_str = tenant_id.to_string();

        let result =
            sqlx::query("DELETE FROM notification_channels WHERE id = ? AND tenant_id = ?")
                .bind(&id_str)
                .bind(&tenant_id_str)
                .execute(&self.pool)
                .await?;

        Ok(result.rows_affected() > 0)
    }

    async fn toggle_enabled(&self, id: Uuid) -> Result<NotificationChannel, DbError> {
        let id_str = id.to_string();
        let now = Utc::now().to_rfc3339();

        sqlx::query(
            r#"UPDATE notification_channels SET enabled = NOT enabled, updated_at = ? WHERE id = ?"#,
        )
        .bind(&now)
        .bind(&id_str)
        .execute(&self.pool)
        .await?;

        self.get(id).await?.ok_or_else(|| DbError::NotFound {
            entity: "NotificationChannel".to_string(),
            id: id.to_string(),
        })
    }

    async fn toggle_enabled_for_tenant(
        &self,
        id: Uuid,
        tenant_id: Uuid,
    ) -> Result<NotificationChannel, DbError> {
        let id_str = id.to_string();
        let tenant_id_str = tenant_id.to_string();
        let now = Utc::now().to_rfc3339();

        sqlx::query(
            r#"UPDATE notification_channels SET enabled = NOT enabled, updated_at = ? WHERE id = ? AND tenant_id = ?"#,
        )
        .bind(&now)
        .bind(&id_str)
        .bind(&tenant_id_str)
        .execute(&self.pool)
        .await?;

        self.get_for_tenant(id, tenant_id)
            .await?
            .ok_or_else(|| DbError::NotFound {
                entity: "NotificationChannel".to_string(),
                id: id.to_string(),
            })
    }

    async fn list_by_event(&self, event: &str) -> Result<Vec<NotificationChannel>, DbError> {
        // SQLite uses json_each to search within the JSON array
        let rows: Vec<NotificationChannelRow> = sqlx::query_as(
            r#"
            SELECT id, tenant_id, name, channel_type, config, events, enabled, created_at, updated_at
            FROM notification_channels
            WHERE enabled = 1
              AND EXISTS (SELECT 1 FROM json_each(events) WHERE value = ?)
            ORDER BY name
            "#,
        )
        .bind(event)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into()).collect()
    }

    async fn list_by_event_for_tenant(
        &self,
        event: &str,
        tenant_id: Uuid,
    ) -> Result<Vec<NotificationChannel>, DbError> {
        let tenant_id_str = tenant_id.to_string();

        // SQLite uses json_each to search within the JSON array
        let rows: Vec<NotificationChannelRow> = sqlx::query_as(
            r#"
            SELECT id, tenant_id, name, channel_type, config, events, enabled, created_at, updated_at
            FROM notification_channels
            WHERE tenant_id = ?
              AND enabled = 1
              AND EXISTS (SELECT 1 FROM json_each(events) WHERE value = ?)
            ORDER BY name
            "#,
        )
        .bind(&tenant_id_str)
        .bind(event)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into()).collect()
    }
}

/// PostgreSQL implementation of NotificationChannelRepository.
#[cfg(feature = "database")]
pub struct PgNotificationChannelRepository {
    pool: sqlx::PgPool,
}

#[cfg(feature = "database")]
impl PgNotificationChannelRepository {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

#[cfg(feature = "database")]
#[async_trait]
impl NotificationChannelRepository for PgNotificationChannelRepository {
    async fn create(
        &self,
        tenant_id: Uuid,
        channel: &NotificationChannel,
    ) -> Result<NotificationChannel, DbError> {
        let channel_type = channel.channel_type.as_db_str();

        sqlx::query(
            r#"
            INSERT INTO notification_channels (id, tenant_id, name, channel_type, config, events, enabled, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
        )
        .bind(channel.id)
        .bind(tenant_id)
        .bind(&channel.name)
        .bind(channel_type)
        .bind(&channel.config)
        .bind(serde_json::to_value(&channel.events)?)
        .bind(channel.enabled)
        .bind(channel.created_at)
        .bind(channel.updated_at)
        .execute(&self.pool)
        .await?;

        Ok(channel.clone())
    }

    async fn get(&self, id: Uuid) -> Result<Option<NotificationChannel>, DbError> {
        let row: Option<PgNotificationChannelRow> = sqlx::query_as(
            r#"SELECT id, tenant_id, name, channel_type, config, events, enabled, created_at, updated_at FROM notification_channels WHERE id = $1"#,
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
    ) -> Result<Option<NotificationChannel>, DbError> {
        let row: Option<PgNotificationChannelRow> = sqlx::query_as(
            r#"SELECT id, tenant_id, name, channel_type, config, events, enabled, created_at, updated_at FROM notification_channels WHERE id = $1 AND tenant_id = $2"#,
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

    async fn list(&self) -> Result<Vec<NotificationChannel>, DbError> {
        let rows: Vec<PgNotificationChannelRow> = sqlx::query_as(
            r#"SELECT id, tenant_id, name, channel_type, config, events, enabled, created_at, updated_at FROM notification_channels ORDER BY name"#,
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into()).collect()
    }

    async fn list_for_tenant(&self, tenant_id: Uuid) -> Result<Vec<NotificationChannel>, DbError> {
        let rows: Vec<PgNotificationChannelRow> = sqlx::query_as(
            r#"SELECT id, tenant_id, name, channel_type, config, events, enabled, created_at, updated_at FROM notification_channels WHERE tenant_id = $1 ORDER BY name"#,
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into()).collect()
    }

    async fn update(
        &self,
        id: Uuid,
        update: &NotificationChannelUpdate,
    ) -> Result<NotificationChannel, DbError> {
        sqlx::query(
            r#"
            UPDATE notification_channels SET
                name = COALESCE($2, name),
                channel_type = COALESCE($3, channel_type),
                config = COALESCE($4, config),
                events = COALESCE($5, events),
                enabled = COALESCE($6, enabled),
                updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(&update.name)
        .bind(update.channel_type.as_ref().map(|ct| ct.as_db_str()))
        .bind(&update.config)
        .bind(
            update
                .events
                .as_ref()
                .and_then(|e| serde_json::to_value(e).ok()),
        )
        .bind(update.enabled)
        .execute(&self.pool)
        .await?;

        self.get(id).await?.ok_or_else(|| DbError::NotFound {
            entity: "NotificationChannel".to_string(),
            id: id.to_string(),
        })
    }

    async fn update_for_tenant(
        &self,
        id: Uuid,
        tenant_id: Uuid,
        update: &NotificationChannelUpdate,
    ) -> Result<NotificationChannel, DbError> {
        sqlx::query(
            r#"
            UPDATE notification_channels SET
                name = COALESCE($3, name),
                channel_type = COALESCE($4, channel_type),
                config = COALESCE($5, config),
                events = COALESCE($6, events),
                enabled = COALESCE($7, enabled),
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&update.name)
        .bind(update.channel_type.as_ref().map(|ct| ct.as_db_str()))
        .bind(&update.config)
        .bind(
            update
                .events
                .as_ref()
                .and_then(|e| serde_json::to_value(e).ok()),
        )
        .bind(update.enabled)
        .execute(&self.pool)
        .await?;

        self.get_for_tenant(id, tenant_id)
            .await?
            .ok_or_else(|| DbError::NotFound {
                entity: "NotificationChannel".to_string(),
                id: id.to_string(),
            })
    }

    async fn delete(&self, id: Uuid) -> Result<bool, DbError> {
        let result = sqlx::query("DELETE FROM notification_channels WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    async fn delete_for_tenant(&self, id: Uuid, tenant_id: Uuid) -> Result<bool, DbError> {
        let result =
            sqlx::query("DELETE FROM notification_channels WHERE id = $1 AND tenant_id = $2")
                .bind(id)
                .bind(tenant_id)
                .execute(&self.pool)
                .await?;

        Ok(result.rows_affected() > 0)
    }

    async fn toggle_enabled(&self, id: Uuid) -> Result<NotificationChannel, DbError> {
        sqlx::query(
            r#"UPDATE notification_channels SET enabled = NOT enabled, updated_at = NOW() WHERE id = $1"#,
        )
        .bind(id)
        .execute(&self.pool)
        .await?;

        self.get(id).await?.ok_or_else(|| DbError::NotFound {
            entity: "NotificationChannel".to_string(),
            id: id.to_string(),
        })
    }

    async fn toggle_enabled_for_tenant(
        &self,
        id: Uuid,
        tenant_id: Uuid,
    ) -> Result<NotificationChannel, DbError> {
        sqlx::query(
            r#"UPDATE notification_channels SET enabled = NOT enabled, updated_at = NOW() WHERE id = $1 AND tenant_id = $2"#,
        )
        .bind(id)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;

        self.get_for_tenant(id, tenant_id)
            .await?
            .ok_or_else(|| DbError::NotFound {
                entity: "NotificationChannel".to_string(),
                id: id.to_string(),
            })
    }

    async fn list_by_event(&self, event: &str) -> Result<Vec<NotificationChannel>, DbError> {
        // PostgreSQL uses JSONB containment operator to check if array contains the event
        let rows: Vec<PgNotificationChannelRow> = sqlx::query_as(
            r#"
            SELECT id, tenant_id, name, channel_type, config, events, enabled, created_at, updated_at
            FROM notification_channels
            WHERE enabled = true
              AND events @> $1::jsonb
            ORDER BY name
            "#,
        )
        .bind(serde_json::json!([event]))
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into()).collect()
    }

    async fn list_by_event_for_tenant(
        &self,
        event: &str,
        tenant_id: Uuid,
    ) -> Result<Vec<NotificationChannel>, DbError> {
        // PostgreSQL uses JSONB containment operator to check if array contains the event
        let rows: Vec<PgNotificationChannelRow> = sqlx::query_as(
            r#"
            SELECT id, tenant_id, name, channel_type, config, events, enabled, created_at, updated_at
            FROM notification_channels
            WHERE tenant_id = $1
              AND enabled = true
              AND events @> $2::jsonb
            ORDER BY name
            "#,
        )
        .bind(tenant_id)
        .bind(serde_json::json!([event]))
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into()).collect()
    }
}

/// Factory function to create the appropriate repository based on pool type.
#[cfg(feature = "database")]
pub fn create_notification_repository(pool: &DbPool) -> Box<dyn NotificationChannelRepository> {
    match pool {
        DbPool::Sqlite(pool) => Box::new(SqliteNotificationChannelRepository::new(pool.clone())),
        DbPool::Postgres(pool) => Box::new(PgNotificationChannelRepository::new(pool.clone())),
    }
}

// Helper structs for SQLx row mapping

#[cfg(feature = "database")]
#[derive(sqlx::FromRow)]
struct NotificationChannelRow {
    id: String,
    #[allow(dead_code)]
    tenant_id: String,
    name: String,
    channel_type: String,
    config: String,
    events: String,
    enabled: i32,
    created_at: String,
    updated_at: String,
}

#[cfg(feature = "database")]
impl TryFrom<NotificationChannelRow> for NotificationChannel {
    type Error = DbError;

    fn try_from(row: NotificationChannelRow) -> Result<Self, Self::Error> {
        let channel_type = ChannelType::from_db_str(&row.channel_type).ok_or_else(|| {
            DbError::Serialization(format!("Unknown channel type: {}", row.channel_type))
        })?;

        Ok(NotificationChannel {
            id: Uuid::parse_str(&row.id).map_err(|e| DbError::Serialization(e.to_string()))?,
            name: row.name,
            channel_type,
            config: serde_json::from_str(&row.config)?,
            events: serde_json::from_str(&row.events)?,
            enabled: row.enabled != 0,
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
struct PgNotificationChannelRow {
    id: Uuid,
    #[allow(dead_code)]
    tenant_id: Uuid,
    name: String,
    channel_type: String,
    config: serde_json::Value,
    events: serde_json::Value,
    enabled: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[cfg(feature = "database")]
impl TryFrom<PgNotificationChannelRow> for NotificationChannel {
    type Error = DbError;

    fn try_from(row: PgNotificationChannelRow) -> Result<Self, Self::Error> {
        let channel_type = ChannelType::from_db_str(&row.channel_type).ok_or_else(|| {
            DbError::Serialization(format!("Unknown channel type: {}", row.channel_type))
        })?;

        Ok(NotificationChannel {
            id: row.id,
            name: row.name,
            channel_type,
            config: row.config,
            events: serde_json::from_value(row.events)?,
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
    fn test_notification_channel_filter_default() {
        let filter = NotificationChannelFilter::default();
        assert!(filter.tenant_id.is_none());
        assert!(filter.enabled.is_none());
    }

    #[test]
    fn test_notification_channel_row_conversion() {
        let row = NotificationChannelRow {
            id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            tenant_id: "550e8400-e29b-41d4-a716-446655440001".to_string(),
            name: "Test Channel".to_string(),
            channel_type: "slack".to_string(),
            config: r#"{"webhook_url": "https://hooks.slack.com/test"}"#.to_string(),
            events: r#"["critical_incident", "action_required"]"#.to_string(),
            enabled: 1,
            created_at: "2024-01-30T12:00:00+00:00".to_string(),
            updated_at: "2024-01-30T12:00:00+00:00".to_string(),
        };

        let channel: NotificationChannel = row.try_into().unwrap();
        assert_eq!(channel.name, "Test Channel");
        assert_eq!(channel.channel_type, ChannelType::Slack);
        assert!(channel.enabled);
        assert_eq!(channel.events.len(), 2);
    }
}
