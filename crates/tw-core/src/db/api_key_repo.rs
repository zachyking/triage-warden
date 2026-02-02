//! API key repository for database operations.

use super::{DbError, DbPool};
use crate::auth::ApiKey;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Filter for listing API keys.
#[derive(Debug, Clone, Default)]
pub struct ApiKeyFilter {
    /// Filter by user ID.
    pub user_id: Option<Uuid>,
    /// Filter by active (non-expired) keys only.
    pub active_only: Option<bool>,
}

/// Repository trait for API key persistence.
#[async_trait]
pub trait ApiKeyRepository: Send + Sync {
    /// Creates a new API key.
    async fn create(&self, api_key: &ApiKey) -> Result<ApiKey, DbError>;

    /// Gets an API key by ID.
    async fn get(&self, id: Uuid) -> Result<Option<ApiKey>, DbError>;

    /// Gets an API key by its prefix (for lookup during authentication).
    async fn get_by_prefix(&self, prefix: &str) -> Result<Option<ApiKey>, DbError>;

    /// Lists API keys with optional filtering.
    async fn list(&self, filter: &ApiKeyFilter) -> Result<Vec<ApiKey>, DbError>;

    /// Lists API keys for a specific user.
    async fn list_by_user(&self, user_id: Uuid) -> Result<Vec<ApiKey>, DbError>;

    /// Updates the last_used_at timestamp.
    async fn update_last_used(&self, id: Uuid) -> Result<(), DbError>;

    /// Deletes an API key.
    async fn delete(&self, id: Uuid) -> Result<bool, DbError>;

    /// Deletes all API keys for a user.
    async fn delete_by_user(&self, user_id: Uuid) -> Result<u64, DbError>;

    /// Counts API keys matching a filter.
    async fn count(&self, filter: &ApiKeyFilter) -> Result<u64, DbError>;
}

/// SQLite implementation of ApiKeyRepository.
#[cfg(feature = "database")]
pub struct SqliteApiKeyRepository {
    pool: sqlx::SqlitePool,
}

#[cfg(feature = "database")]
impl SqliteApiKeyRepository {
    pub fn new(pool: sqlx::SqlitePool) -> Self {
        Self { pool }
    }
}

#[cfg(feature = "database")]
#[async_trait]
impl ApiKeyRepository for SqliteApiKeyRepository {
    async fn create(&self, api_key: &ApiKey) -> Result<ApiKey, DbError> {
        let id = api_key.id.to_string();
        let user_id = api_key.user_id.to_string();
        let scopes = serde_json::to_string(&api_key.scopes)
            .map_err(|e| DbError::Serialization(e.to_string()))?;
        let expires_at = api_key.expires_at.map(|t| t.to_rfc3339());
        let last_used_at = api_key.last_used_at.map(|t| t.to_rfc3339());
        let created_at = api_key.created_at.to_rfc3339();

        sqlx::query(
            r#"
            INSERT INTO api_keys (id, user_id, name, key_hash, key_prefix, scopes, expires_at, last_used_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&id)
        .bind(&user_id)
        .bind(&api_key.name)
        .bind(&api_key.key_hash)
        .bind(&api_key.key_prefix)
        .bind(&scopes)
        .bind(&expires_at)
        .bind(&last_used_at)
        .bind(&created_at)
        .execute(&self.pool)
        .await?;

        Ok(api_key.clone())
    }

    async fn get(&self, id: Uuid) -> Result<Option<ApiKey>, DbError> {
        let id_str = id.to_string();
        let row: Option<SqliteApiKeyRow> = sqlx::query_as(
            "SELECT id, user_id, name, key_hash, key_prefix, scopes, expires_at, last_used_at, created_at FROM api_keys WHERE id = ?",
        )
        .bind(&id_str)
        .fetch_optional(&self.pool)
        .await?;

        row.map(TryInto::try_into).transpose()
    }

    async fn get_by_prefix(&self, prefix: &str) -> Result<Option<ApiKey>, DbError> {
        let row: Option<SqliteApiKeyRow> = sqlx::query_as(
            "SELECT id, user_id, name, key_hash, key_prefix, scopes, expires_at, last_used_at, created_at FROM api_keys WHERE key_prefix = ?",
        )
        .bind(prefix)
        .fetch_optional(&self.pool)
        .await?;

        row.map(TryInto::try_into).transpose()
    }

    async fn list(&self, filter: &ApiKeyFilter) -> Result<Vec<ApiKey>, DbError> {
        let mut query = String::from(
            "SELECT id, user_id, name, key_hash, key_prefix, scopes, expires_at, last_used_at, created_at FROM api_keys WHERE 1=1",
        );
        let mut params: Vec<String> = Vec::new();

        if let Some(user_id) = &filter.user_id {
            query.push_str(" AND user_id = ?");
            params.push(user_id.to_string());
        }

        if let Some(true) = filter.active_only {
            query.push_str(" AND (expires_at IS NULL OR expires_at > ?)");
            params.push(Utc::now().to_rfc3339());
        }

        query.push_str(" ORDER BY created_at DESC");

        let mut sqlx_query = sqlx::query_as::<_, SqliteApiKeyRow>(&query);
        for param in params {
            sqlx_query = sqlx_query.bind(param);
        }

        let rows: Vec<SqliteApiKeyRow> = sqlx_query.fetch_all(&self.pool).await?;
        rows.into_iter().map(TryInto::try_into).collect()
    }

    async fn list_by_user(&self, user_id: Uuid) -> Result<Vec<ApiKey>, DbError> {
        self.list(&ApiKeyFilter {
            user_id: Some(user_id),
            active_only: None,
        })
        .await
    }

    async fn update_last_used(&self, id: Uuid) -> Result<(), DbError> {
        let now = Utc::now().to_rfc3339();

        sqlx::query("UPDATE api_keys SET last_used_at = ? WHERE id = ?")
            .bind(&now)
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn delete(&self, id: Uuid) -> Result<bool, DbError> {
        let result = sqlx::query("DELETE FROM api_keys WHERE id = ?")
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    async fn delete_by_user(&self, user_id: Uuid) -> Result<u64, DbError> {
        let result = sqlx::query("DELETE FROM api_keys WHERE user_id = ?")
            .bind(user_id.to_string())
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected())
    }

    async fn count(&self, filter: &ApiKeyFilter) -> Result<u64, DbError> {
        let mut query = String::from("SELECT COUNT(*) as count FROM api_keys WHERE 1=1");
        let mut params: Vec<String> = Vec::new();

        if let Some(user_id) = &filter.user_id {
            query.push_str(" AND user_id = ?");
            params.push(user_id.to_string());
        }

        if let Some(true) = filter.active_only {
            query.push_str(" AND (expires_at IS NULL OR expires_at > ?)");
            params.push(Utc::now().to_rfc3339());
        }

        let mut sqlx_query = sqlx::query_scalar::<_, i64>(&query);
        for param in params {
            sqlx_query = sqlx_query.bind(param);
        }

        let count: i64 = sqlx_query.fetch_one(&self.pool).await?;
        Ok(count as u64)
    }
}

/// PostgreSQL implementation of ApiKeyRepository.
#[cfg(feature = "database")]
pub struct PgApiKeyRepository {
    pool: sqlx::PgPool,
}

#[cfg(feature = "database")]
impl PgApiKeyRepository {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

#[cfg(feature = "database")]
#[async_trait]
impl ApiKeyRepository for PgApiKeyRepository {
    async fn create(&self, api_key: &ApiKey) -> Result<ApiKey, DbError> {
        let scopes = serde_json::to_value(&api_key.scopes)
            .map_err(|e| DbError::Serialization(e.to_string()))?;

        sqlx::query(
            r#"
            INSERT INTO api_keys (id, user_id, name, key_hash, key_prefix, scopes, expires_at, last_used_at, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
        )
        .bind(api_key.id)
        .bind(api_key.user_id)
        .bind(&api_key.name)
        .bind(&api_key.key_hash)
        .bind(&api_key.key_prefix)
        .bind(&scopes)
        .bind(api_key.expires_at)
        .bind(api_key.last_used_at)
        .bind(api_key.created_at)
        .execute(&self.pool)
        .await?;

        Ok(api_key.clone())
    }

    async fn get(&self, id: Uuid) -> Result<Option<ApiKey>, DbError> {
        let row: Option<PgApiKeyRow> = sqlx::query_as(
            "SELECT id, user_id, name, key_hash, key_prefix, scopes, expires_at, last_used_at, created_at FROM api_keys WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(TryInto::try_into).transpose()
    }

    async fn get_by_prefix(&self, prefix: &str) -> Result<Option<ApiKey>, DbError> {
        let row: Option<PgApiKeyRow> = sqlx::query_as(
            "SELECT id, user_id, name, key_hash, key_prefix, scopes, expires_at, last_used_at, created_at FROM api_keys WHERE key_prefix = $1",
        )
        .bind(prefix)
        .fetch_optional(&self.pool)
        .await?;

        row.map(TryInto::try_into).transpose()
    }

    async fn list(&self, filter: &ApiKeyFilter) -> Result<Vec<ApiKey>, DbError> {
        let rows: Vec<PgApiKeyRow> = if filter.user_id.is_some() || filter.active_only.is_some() {
            let mut conditions = vec!["1=1".to_string()];
            let mut param_idx = 1;

            if filter.user_id.is_some() {
                conditions.push(format!("user_id = ${}", param_idx));
                param_idx += 1;
            }

            if filter.active_only == Some(true) {
                conditions.push(format!(
                    "(expires_at IS NULL OR expires_at > ${})",
                    param_idx
                ));
            }

            let query = format!(
                "SELECT id, user_id, name, key_hash, key_prefix, scopes, expires_at, last_used_at, created_at FROM api_keys WHERE {} ORDER BY created_at DESC",
                conditions.join(" AND ")
            );

            let mut sqlx_query = sqlx::query_as::<_, PgApiKeyRow>(&query);

            if let Some(user_id) = filter.user_id {
                sqlx_query = sqlx_query.bind(user_id);
            }

            if filter.active_only == Some(true) {
                sqlx_query = sqlx_query.bind(Utc::now());
            }

            sqlx_query.fetch_all(&self.pool).await?
        } else {
            sqlx::query_as(
                "SELECT id, user_id, name, key_hash, key_prefix, scopes, expires_at, last_used_at, created_at FROM api_keys ORDER BY created_at DESC",
            )
            .fetch_all(&self.pool)
            .await?
        };

        rows.into_iter().map(TryInto::try_into).collect()
    }

    async fn list_by_user(&self, user_id: Uuid) -> Result<Vec<ApiKey>, DbError> {
        self.list(&ApiKeyFilter {
            user_id: Some(user_id),
            active_only: None,
        })
        .await
    }

    async fn update_last_used(&self, id: Uuid) -> Result<(), DbError> {
        sqlx::query("UPDATE api_keys SET last_used_at = NOW() WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn delete(&self, id: Uuid) -> Result<bool, DbError> {
        let result = sqlx::query("DELETE FROM api_keys WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    async fn delete_by_user(&self, user_id: Uuid) -> Result<u64, DbError> {
        let result = sqlx::query("DELETE FROM api_keys WHERE user_id = $1")
            .bind(user_id)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected())
    }

    async fn count(&self, filter: &ApiKeyFilter) -> Result<u64, DbError> {
        let count: i64 = if filter.user_id.is_some() || filter.active_only.is_some() {
            let mut conditions = vec!["1=1".to_string()];
            let mut param_idx = 1;

            if filter.user_id.is_some() {
                conditions.push(format!("user_id = ${}", param_idx));
                param_idx += 1;
            }

            if filter.active_only == Some(true) {
                conditions.push(format!(
                    "(expires_at IS NULL OR expires_at > ${})",
                    param_idx
                ));
            }

            let query = format!(
                "SELECT COUNT(*) FROM api_keys WHERE {}",
                conditions.join(" AND ")
            );

            let mut sqlx_query = sqlx::query_scalar::<_, i64>(&query);

            if let Some(user_id) = filter.user_id {
                sqlx_query = sqlx_query.bind(user_id);
            }

            if filter.active_only == Some(true) {
                sqlx_query = sqlx_query.bind(Utc::now());
            }

            sqlx_query.fetch_one(&self.pool).await?
        } else {
            sqlx::query_scalar("SELECT COUNT(*) FROM api_keys")
                .fetch_one(&self.pool)
                .await?
        };

        Ok(count as u64)
    }
}

/// Factory function to create the appropriate repository based on pool type.
#[cfg(feature = "database")]
pub fn create_api_key_repository(pool: &DbPool) -> Box<dyn ApiKeyRepository> {
    match pool {
        DbPool::Sqlite(pool) => Box::new(SqliteApiKeyRepository::new(pool.clone())),
        DbPool::Postgres(pool) => Box::new(PgApiKeyRepository::new(pool.clone())),
    }
}

// Helper structs for SQLx row mapping

#[cfg(feature = "database")]
#[derive(sqlx::FromRow)]
struct SqliteApiKeyRow {
    id: String,
    user_id: String,
    name: String,
    key_hash: String,
    key_prefix: String,
    scopes: String,
    expires_at: Option<String>,
    last_used_at: Option<String>,
    created_at: String,
}

#[cfg(feature = "database")]
impl TryFrom<SqliteApiKeyRow> for ApiKey {
    type Error = DbError;

    fn try_from(row: SqliteApiKeyRow) -> Result<Self, Self::Error> {
        let id = Uuid::parse_str(&row.id)
            .map_err(|e| DbError::Serialization(format!("Invalid UUID: {}", e)))?;

        let user_id = Uuid::parse_str(&row.user_id)
            .map_err(|e| DbError::Serialization(format!("Invalid user_id UUID: {}", e)))?;

        let scopes: Vec<String> = serde_json::from_str(&row.scopes)
            .map_err(|e| DbError::Serialization(format!("Invalid scopes JSON: {}", e)))?;

        let expires_at = row
            .expires_at
            .map(|s| DateTime::parse_from_rfc3339(&s))
            .transpose()
            .map_err(|e| DbError::Serialization(format!("Invalid expires_at timestamp: {}", e)))?
            .map(|dt| dt.with_timezone(&Utc));

        let last_used_at = row
            .last_used_at
            .map(|s| DateTime::parse_from_rfc3339(&s))
            .transpose()
            .map_err(|e| DbError::Serialization(format!("Invalid last_used_at timestamp: {}", e)))?
            .map(|dt| dt.with_timezone(&Utc));

        let created_at = DateTime::parse_from_rfc3339(&row.created_at)
            .map_err(|e| DbError::Serialization(format!("Invalid created_at timestamp: {}", e)))?
            .with_timezone(&Utc);

        Ok(ApiKey {
            id,
            user_id,
            name: row.name,
            key_hash: row.key_hash,
            key_prefix: row.key_prefix,
            scopes,
            expires_at,
            last_used_at,
            created_at,
        })
    }
}

#[cfg(feature = "database")]
#[derive(sqlx::FromRow)]
struct PgApiKeyRow {
    id: Uuid,
    user_id: Uuid,
    name: String,
    key_hash: String,
    key_prefix: String,
    scopes: serde_json::Value,
    expires_at: Option<DateTime<Utc>>,
    last_used_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

#[cfg(feature = "database")]
impl TryFrom<PgApiKeyRow> for ApiKey {
    type Error = DbError;

    fn try_from(row: PgApiKeyRow) -> Result<Self, Self::Error> {
        let scopes: Vec<String> = serde_json::from_value(row.scopes)
            .map_err(|e| DbError::Serialization(format!("Invalid scopes JSON: {}", e)))?;

        Ok(ApiKey {
            id: row.id,
            user_id: row.user_id,
            name: row.name,
            key_hash: row.key_hash,
            key_prefix: row.key_prefix,
            scopes,
            expires_at: row.expires_at,
            last_used_at: row.last_used_at,
            created_at: row.created_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_key_filter_default() {
        let filter = ApiKeyFilter::default();
        assert!(filter.user_id.is_none());
        assert!(filter.active_only.is_none());
    }
}
