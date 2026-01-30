//! Settings repository for database operations.

use super::{DbError, DbPool};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// General application settings.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GeneralSettings {
    /// Organization name.
    pub org_name: String,
    /// Default timezone.
    pub timezone: String,
    /// Operation mode: assisted, supervised, or autonomous.
    pub mode: String,
}

/// Rate limit settings.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RateLimits {
    /// Maximum isolate host actions per hour.
    pub isolate_host_hour: u32,
    /// Maximum disable user actions per hour.
    pub disable_user_hour: u32,
    /// Maximum block IP actions per hour.
    pub block_ip_hour: u32,
}

/// Repository trait for settings persistence.
#[async_trait]
pub trait SettingsRepository: Send + Sync {
    /// Gets general settings.
    async fn get_general(&self) -> Result<GeneralSettings, DbError>;

    /// Saves general settings.
    async fn save_general(&self, settings: &GeneralSettings) -> Result<(), DbError>;

    /// Gets rate limit settings.
    async fn get_rate_limits(&self) -> Result<RateLimits, DbError>;

    /// Saves rate limit settings.
    async fn save_rate_limits(&self, limits: &RateLimits) -> Result<(), DbError>;

    /// Gets a raw setting value by key.
    async fn get_raw(&self, key: &str) -> Result<Option<String>, DbError>;

    /// Saves a raw setting value by key.
    async fn save_raw(&self, key: &str, value: &str) -> Result<(), DbError>;
}

/// SQLite implementation of SettingsRepository.
#[cfg(feature = "database")]
pub struct SqliteSettingsRepository {
    pool: sqlx::SqlitePool,
}

#[cfg(feature = "database")]
impl SqliteSettingsRepository {
    pub fn new(pool: sqlx::SqlitePool) -> Self {
        Self { pool }
    }
}

#[cfg(feature = "database")]
#[async_trait]
impl SettingsRepository for SqliteSettingsRepository {
    async fn get_general(&self) -> Result<GeneralSettings, DbError> {
        let row: Option<SettingsRow> =
            sqlx::query_as("SELECT key, value, updated_at FROM settings WHERE key = ?")
                .bind("general")
                .fetch_optional(&self.pool)
                .await?;

        match row {
            Some(row) => Ok(serde_json::from_str(&row.value)?),
            None => Ok(GeneralSettings::default()),
        }
    }

    async fn save_general(&self, settings: &GeneralSettings) -> Result<(), DbError> {
        let value = serde_json::to_string(settings)?;
        let now = Utc::now().to_rfc3339();

        sqlx::query(
            r#"
            INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
            "#,
        )
        .bind("general")
        .bind(&value)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_rate_limits(&self) -> Result<RateLimits, DbError> {
        let row: Option<SettingsRow> =
            sqlx::query_as("SELECT key, value, updated_at FROM settings WHERE key = ?")
                .bind("rate_limits")
                .fetch_optional(&self.pool)
                .await?;

        match row {
            Some(row) => Ok(serde_json::from_str(&row.value)?),
            None => Ok(RateLimits::default()),
        }
    }

    async fn save_rate_limits(&self, limits: &RateLimits) -> Result<(), DbError> {
        let value = serde_json::to_string(limits)?;
        let now = Utc::now().to_rfc3339();

        sqlx::query(
            r#"
            INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
            "#,
        )
        .bind("rate_limits")
        .bind(&value)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_raw(&self, key: &str) -> Result<Option<String>, DbError> {
        let row: Option<SettingsRow> =
            sqlx::query_as("SELECT key, value, updated_at FROM settings WHERE key = ?")
                .bind(key)
                .fetch_optional(&self.pool)
                .await?;

        Ok(row.map(|r| r.value))
    }

    async fn save_raw(&self, key: &str, value: &str) -> Result<(), DbError> {
        let now = Utc::now().to_rfc3339();

        sqlx::query(
            r#"
            INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
            "#,
        )
        .bind(key)
        .bind(value)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}

/// PostgreSQL implementation of SettingsRepository.
#[cfg(feature = "database")]
pub struct PgSettingsRepository {
    pool: sqlx::PgPool,
}

#[cfg(feature = "database")]
impl PgSettingsRepository {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

#[cfg(feature = "database")]
#[async_trait]
impl SettingsRepository for PgSettingsRepository {
    async fn get_general(&self) -> Result<GeneralSettings, DbError> {
        let row: Option<PgSettingsRow> =
            sqlx::query_as("SELECT key, value, updated_at FROM settings WHERE key = $1")
                .bind("general")
                .fetch_optional(&self.pool)
                .await?;

        match row {
            Some(row) => Ok(serde_json::from_value(row.value)?),
            None => Ok(GeneralSettings::default()),
        }
    }

    async fn save_general(&self, settings: &GeneralSettings) -> Result<(), DbError> {
        let value = serde_json::to_value(settings)?;

        sqlx::query(
            r#"
            INSERT INTO settings (key, value, updated_at) VALUES ($1, $2, NOW())
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = NOW()
            "#,
        )
        .bind("general")
        .bind(&value)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_rate_limits(&self) -> Result<RateLimits, DbError> {
        let row: Option<PgSettingsRow> =
            sqlx::query_as("SELECT key, value, updated_at FROM settings WHERE key = $1")
                .bind("rate_limits")
                .fetch_optional(&self.pool)
                .await?;

        match row {
            Some(row) => Ok(serde_json::from_value(row.value)?),
            None => Ok(RateLimits::default()),
        }
    }

    async fn save_rate_limits(&self, limits: &RateLimits) -> Result<(), DbError> {
        let value = serde_json::to_value(limits)?;

        sqlx::query(
            r#"
            INSERT INTO settings (key, value, updated_at) VALUES ($1, $2, NOW())
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = NOW()
            "#,
        )
        .bind("rate_limits")
        .bind(&value)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_raw(&self, key: &str) -> Result<Option<String>, DbError> {
        let row: Option<PgSettingsRow> =
            sqlx::query_as("SELECT key, value, updated_at FROM settings WHERE key = $1")
                .bind(key)
                .fetch_optional(&self.pool)
                .await?;

        Ok(row.map(|r| r.value.to_string()))
    }

    async fn save_raw(&self, key: &str, value: &str) -> Result<(), DbError> {
        let json_value: serde_json::Value = serde_json::from_str(value)
            .unwrap_or_else(|_| serde_json::Value::String(value.to_string()));

        sqlx::query(
            r#"
            INSERT INTO settings (key, value, updated_at) VALUES ($1, $2, NOW())
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = NOW()
            "#,
        )
        .bind(key)
        .bind(&json_value)
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}

/// Factory function to create the appropriate repository based on pool type.
#[cfg(feature = "database")]
pub fn create_settings_repository(pool: &DbPool) -> Box<dyn SettingsRepository> {
    match pool {
        DbPool::Sqlite(pool) => Box::new(SqliteSettingsRepository::new(pool.clone())),
        DbPool::Postgres(pool) => Box::new(PgSettingsRepository::new(pool.clone())),
    }
}

// Helper structs for SQLx row mapping

#[cfg(feature = "database")]
#[derive(sqlx::FromRow)]
struct SettingsRow {
    #[allow(dead_code)]
    key: String,
    value: String,
    #[allow(dead_code)]
    updated_at: String,
}

#[cfg(feature = "database")]
#[derive(sqlx::FromRow)]
struct PgSettingsRow {
    #[allow(dead_code)]
    key: String,
    value: serde_json::Value,
    #[allow(dead_code)]
    updated_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_general_settings_default() {
        let s = GeneralSettings::default();
        assert_eq!(s.org_name, "");
        assert_eq!(s.timezone, "");
        assert_eq!(s.mode, "");
    }

    #[test]
    fn test_rate_limits_default() {
        let r = RateLimits::default();
        assert_eq!(r.isolate_host_hour, 0);
        assert_eq!(r.disable_user_hour, 0);
        assert_eq!(r.block_ip_hour, 0);
    }

    #[test]
    fn test_general_settings_serialization() {
        let s = GeneralSettings {
            org_name: "Acme Corp".to_string(),
            timezone: "America/New_York".to_string(),
            mode: "supervised".to_string(),
        };
        let json = serde_json::to_string(&s).unwrap();
        let parsed: GeneralSettings = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.org_name, "Acme Corp");
        assert_eq!(parsed.timezone, "America/New_York");
        assert_eq!(parsed.mode, "supervised");
    }

    #[test]
    fn test_rate_limits_serialization() {
        let r = RateLimits {
            isolate_host_hour: 10,
            disable_user_hour: 5,
            block_ip_hour: 20,
        };
        let json = serde_json::to_string(&r).unwrap();
        let parsed: RateLimits = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.isolate_host_hour, 10);
        assert_eq!(parsed.disable_user_hour, 5);
        assert_eq!(parsed.block_ip_hour, 20);
    }
}
