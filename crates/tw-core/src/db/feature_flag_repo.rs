//! Feature flag repository for database operations.

use super::{DbError, DbPool};
use crate::features::{FeatureFlag, FeatureFlagError, FeatureFlagStore};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use uuid::Uuid;

/// Converts a database error to a FeatureFlagError.
#[allow(dead_code)]
fn db_to_flag_error(err: DbError) -> FeatureFlagError {
    FeatureFlagError::Storage(err.to_string())
}

/// Converts an sqlx error to a FeatureFlagError.
#[cfg(feature = "database")]
fn sqlx_to_flag_error(err: sqlx::Error) -> FeatureFlagError {
    FeatureFlagError::Storage(err.to_string())
}

// ============================================================================
// PostgreSQL Implementation
// ============================================================================

/// PostgreSQL implementation of FeatureFlagStore.
#[cfg(feature = "database")]
pub struct PostgresFeatureFlagStore {
    pool: sqlx::PgPool,
}

#[cfg(feature = "database")]
impl PostgresFeatureFlagStore {
    /// Creates a new PostgreSQL feature flag store.
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

#[cfg(feature = "database")]
#[derive(sqlx::FromRow)]
struct PgFeatureFlagRow {
    name: String,
    description: String,
    default_enabled: bool,
    tenant_overrides: serde_json::Value,
    percentage_rollout: Option<i16>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[cfg(feature = "database")]
impl TryFrom<PgFeatureFlagRow> for FeatureFlag {
    type Error = FeatureFlagError;

    fn try_from(row: PgFeatureFlagRow) -> Result<Self, Self::Error> {
        // Parse tenant_overrides from JSON
        let tenant_overrides: HashMap<Uuid, bool> = serde_json::from_value(row.tenant_overrides)
            .map_err(|e| {
                FeatureFlagError::Storage(format!("Failed to parse tenant_overrides: {}", e))
            })?;

        Ok(FeatureFlag {
            name: row.name,
            description: row.description,
            default_enabled: row.default_enabled,
            tenant_overrides,
            percentage_rollout: row.percentage_rollout.map(|p| p as u8),
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

#[cfg(feature = "database")]
#[async_trait]
impl FeatureFlagStore for PostgresFeatureFlagStore {
    async fn list(&self) -> Result<Vec<FeatureFlag>, FeatureFlagError> {
        let rows: Vec<PgFeatureFlagRow> = sqlx::query_as(
            r#"
            SELECT name, description, default_enabled, tenant_overrides,
                   percentage_rollout, created_at, updated_at
            FROM feature_flags
            ORDER BY name
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(sqlx_to_flag_error)?;

        rows.into_iter().map(|row| row.try_into()).collect()
    }

    async fn get(&self, name: &str) -> Result<Option<FeatureFlag>, FeatureFlagError> {
        let row: Option<PgFeatureFlagRow> = sqlx::query_as(
            r#"
            SELECT name, description, default_enabled, tenant_overrides,
                   percentage_rollout, created_at, updated_at
            FROM feature_flags
            WHERE name = $1
            "#,
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(sqlx_to_flag_error)?;

        match row {
            Some(r) => Ok(Some(r.try_into()?)),
            None => Ok(None),
        }
    }

    async fn upsert(&self, flag: &FeatureFlag) -> Result<(), FeatureFlagError> {
        let tenant_overrides = serde_json::to_value(&flag.tenant_overrides).map_err(|e| {
            FeatureFlagError::Storage(format!("Failed to serialize tenant_overrides: {}", e))
        })?;

        let percentage_rollout = flag.percentage_rollout.map(|p| p as i16);

        sqlx::query(
            r#"
            INSERT INTO feature_flags (name, description, default_enabled, tenant_overrides, percentage_rollout, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, NOW())
            ON CONFLICT (name) DO UPDATE SET
                description = EXCLUDED.description,
                default_enabled = EXCLUDED.default_enabled,
                tenant_overrides = EXCLUDED.tenant_overrides,
                percentage_rollout = EXCLUDED.percentage_rollout,
                updated_at = NOW()
            "#,
        )
        .bind(&flag.name)
        .bind(&flag.description)
        .bind(flag.default_enabled)
        .bind(&tenant_overrides)
        .bind(percentage_rollout)
        .bind(flag.created_at)
        .execute(&self.pool)
        .await
        .map_err(sqlx_to_flag_error)?;

        Ok(())
    }

    async fn delete(&self, name: &str) -> Result<bool, FeatureFlagError> {
        let result = sqlx::query("DELETE FROM feature_flags WHERE name = $1")
            .bind(name)
            .execute(&self.pool)
            .await
            .map_err(sqlx_to_flag_error)?;

        Ok(result.rows_affected() > 0)
    }
}

// ============================================================================
// SQLite Implementation
// ============================================================================

/// SQLite implementation of FeatureFlagStore.
#[cfg(feature = "database")]
pub struct SqliteFeatureFlagStore {
    pool: sqlx::SqlitePool,
}

#[cfg(feature = "database")]
impl SqliteFeatureFlagStore {
    /// Creates a new SQLite feature flag store.
    pub fn new(pool: sqlx::SqlitePool) -> Self {
        Self { pool }
    }
}

#[cfg(feature = "database")]
#[derive(sqlx::FromRow)]
struct SqliteFeatureFlagRow {
    name: String,
    description: String,
    default_enabled: i32, // SQLite stores booleans as integers
    tenant_overrides: String,
    percentage_rollout: Option<i32>,
    created_at: String,
    updated_at: String,
}

#[cfg(feature = "database")]
impl TryFrom<SqliteFeatureFlagRow> for FeatureFlag {
    type Error = FeatureFlagError;

    fn try_from(row: SqliteFeatureFlagRow) -> Result<Self, Self::Error> {
        // Parse tenant_overrides from JSON string
        let tenant_overrides: HashMap<Uuid, bool> = serde_json::from_str(&row.tenant_overrides)
            .map_err(|e| {
                FeatureFlagError::Storage(format!("Failed to parse tenant_overrides: {}", e))
            })?;

        // Parse timestamps
        let created_at = DateTime::parse_from_rfc3339(&row.created_at)
            .map(|dt| dt.with_timezone(&Utc))
            .or_else(|_| {
                // Try parsing SQLite datetime format
                chrono::NaiveDateTime::parse_from_str(&row.created_at, "%Y-%m-%d %H:%M:%S")
                    .map(|dt| dt.and_utc())
            })
            .map_err(|e| FeatureFlagError::Storage(format!("Failed to parse created_at: {}", e)))?;

        let updated_at = DateTime::parse_from_rfc3339(&row.updated_at)
            .map(|dt| dt.with_timezone(&Utc))
            .or_else(|_| {
                // Try parsing SQLite datetime format
                chrono::NaiveDateTime::parse_from_str(&row.updated_at, "%Y-%m-%d %H:%M:%S")
                    .map(|dt| dt.and_utc())
            })
            .map_err(|e| FeatureFlagError::Storage(format!("Failed to parse updated_at: {}", e)))?;

        Ok(FeatureFlag {
            name: row.name,
            description: row.description,
            default_enabled: row.default_enabled != 0,
            tenant_overrides,
            percentage_rollout: row.percentage_rollout.map(|p| p as u8),
            created_at,
            updated_at,
        })
    }
}

#[cfg(feature = "database")]
#[async_trait]
impl FeatureFlagStore for SqliteFeatureFlagStore {
    async fn list(&self) -> Result<Vec<FeatureFlag>, FeatureFlagError> {
        let rows: Vec<SqliteFeatureFlagRow> = sqlx::query_as(
            r#"
            SELECT name, description, default_enabled, tenant_overrides,
                   percentage_rollout, created_at, updated_at
            FROM feature_flags
            ORDER BY name
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(sqlx_to_flag_error)?;

        rows.into_iter().map(|row| row.try_into()).collect()
    }

    async fn get(&self, name: &str) -> Result<Option<FeatureFlag>, FeatureFlagError> {
        let row: Option<SqliteFeatureFlagRow> = sqlx::query_as(
            r#"
            SELECT name, description, default_enabled, tenant_overrides,
                   percentage_rollout, created_at, updated_at
            FROM feature_flags
            WHERE name = ?
            "#,
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(sqlx_to_flag_error)?;

        match row {
            Some(r) => Ok(Some(r.try_into()?)),
            None => Ok(None),
        }
    }

    async fn upsert(&self, flag: &FeatureFlag) -> Result<(), FeatureFlagError> {
        let tenant_overrides = serde_json::to_string(&flag.tenant_overrides).map_err(|e| {
            FeatureFlagError::Storage(format!("Failed to serialize tenant_overrides: {}", e))
        })?;

        let percentage_rollout = flag.percentage_rollout.map(|p| p as i32);
        let default_enabled = if flag.default_enabled { 1 } else { 0 };
        let now = Utc::now().to_rfc3339();

        sqlx::query(
            r#"
            INSERT INTO feature_flags (name, description, default_enabled, tenant_overrides, percentage_rollout, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (name) DO UPDATE SET
                description = excluded.description,
                default_enabled = excluded.default_enabled,
                tenant_overrides = excluded.tenant_overrides,
                percentage_rollout = excluded.percentage_rollout,
                updated_at = excluded.updated_at
            "#,
        )
        .bind(&flag.name)
        .bind(&flag.description)
        .bind(default_enabled)
        .bind(&tenant_overrides)
        .bind(percentage_rollout)
        .bind(flag.created_at.to_rfc3339())
        .bind(&now)
        .execute(&self.pool)
        .await
        .map_err(sqlx_to_flag_error)?;

        Ok(())
    }

    async fn delete(&self, name: &str) -> Result<bool, FeatureFlagError> {
        let result = sqlx::query("DELETE FROM feature_flags WHERE name = ?")
            .bind(name)
            .execute(&self.pool)
            .await
            .map_err(sqlx_to_flag_error)?;

        Ok(result.rows_affected() > 0)
    }
}

// ============================================================================
// Factory Function
// ============================================================================

/// Factory function to create the appropriate FeatureFlagStore based on pool type.
///
/// # Arguments
///
/// * `pool` - The database connection pool
///
/// # Returns
///
/// A boxed FeatureFlagStore implementation for the given pool type.
#[cfg(feature = "database")]
pub fn create_feature_flag_store(pool: &DbPool) -> Box<dyn FeatureFlagStore> {
    match pool {
        DbPool::Sqlite(pool) => Box::new(SqliteFeatureFlagStore::new(pool.clone())),
        DbPool::Postgres(pool) => Box::new(PostgresFeatureFlagStore::new(pool.clone())),
    }
}

#[cfg(not(feature = "database"))]
pub fn create_feature_flag_store(_pool: &DbPool) -> Box<dyn FeatureFlagStore> {
    panic!("Database support not enabled. Compile with --features database")
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_db_to_flag_error() {
        let db_err = DbError::Query("test error".to_string());
        let flag_err = db_to_flag_error(db_err);
        match flag_err {
            FeatureFlagError::Storage(msg) => assert!(msg.contains("test error")),
            _ => panic!("Expected Storage error"),
        }
    }

    #[cfg(feature = "database")]
    mod database_tests {
        use super::*;

        #[test]
        fn test_pg_row_conversion() {
            let row = PgFeatureFlagRow {
                name: "test_flag".to_string(),
                description: "Test description".to_string(),
                default_enabled: true,
                tenant_overrides: serde_json::json!({}),
                percentage_rollout: Some(50),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };

            let flag: FeatureFlag = row.try_into().unwrap();
            assert_eq!(flag.name, "test_flag");
            assert_eq!(flag.description, "Test description");
            assert!(flag.default_enabled);
            assert_eq!(flag.percentage_rollout, Some(50));
            assert!(flag.tenant_overrides.is_empty());
        }

        #[test]
        fn test_pg_row_conversion_with_tenant_overrides() {
            let tenant_id = Uuid::new_v4();
            let mut overrides = HashMap::new();
            overrides.insert(tenant_id.to_string(), true);

            let row = PgFeatureFlagRow {
                name: "test_flag".to_string(),
                description: "Test".to_string(),
                default_enabled: false,
                tenant_overrides: serde_json::to_value(overrides).unwrap(),
                percentage_rollout: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };

            let flag: FeatureFlag = row.try_into().unwrap();
            assert_eq!(flag.tenant_overrides.len(), 1);
            assert_eq!(flag.tenant_overrides.get(&tenant_id), Some(&true));
        }

        #[test]
        fn test_sqlite_row_conversion() {
            let now = Utc::now();
            let row = SqliteFeatureFlagRow {
                name: "test_flag".to_string(),
                description: "Test description".to_string(),
                default_enabled: 1,
                tenant_overrides: "{}".to_string(),
                percentage_rollout: Some(75),
                created_at: now.to_rfc3339(),
                updated_at: now.to_rfc3339(),
            };

            let flag: FeatureFlag = row.try_into().unwrap();
            assert_eq!(flag.name, "test_flag");
            assert_eq!(flag.description, "Test description");
            assert!(flag.default_enabled);
            assert_eq!(flag.percentage_rollout, Some(75));
        }

        #[test]
        fn test_sqlite_row_conversion_with_sqlite_datetime() {
            let row = SqliteFeatureFlagRow {
                name: "test_flag".to_string(),
                description: "Test".to_string(),
                default_enabled: 0,
                tenant_overrides: "{}".to_string(),
                percentage_rollout: None,
                created_at: "2024-02-10 12:30:45".to_string(),
                updated_at: "2024-02-10 12:30:45".to_string(),
            };

            let flag: FeatureFlag = row.try_into().unwrap();
            assert_eq!(flag.name, "test_flag");
            assert!(!flag.default_enabled);
        }
    }
}
