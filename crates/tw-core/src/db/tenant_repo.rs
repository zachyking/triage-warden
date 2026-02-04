//! Tenant repository for database operations.
//!
//! This module provides the persistence layer for multi-tenant support.
//! Every tenant-scoped entity will reference tenants managed by this repository.

use super::{escape_like_pattern, DbError, DbPool};
use crate::tenant::{Tenant, TenantSettings, TenantStatus};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Filter criteria for listing tenants.
#[derive(Debug, Clone, Default)]
pub struct TenantFilter {
    /// Filter by tenant status.
    pub status: Option<TenantStatus>,
    /// Search by name or slug.
    pub search: Option<String>,
}

/// Partial update for a tenant.
#[derive(Debug, Clone, Default)]
pub struct TenantUpdate {
    /// New display name.
    pub name: Option<String>,
    /// New status.
    pub status: Option<TenantStatus>,
    /// New settings.
    pub settings: Option<TenantSettings>,
}

/// Repository trait for tenant persistence.
#[async_trait]
pub trait TenantRepository: Send + Sync {
    /// Creates a new tenant.
    async fn create(&self, tenant: &Tenant) -> Result<Tenant, DbError>;

    /// Gets a tenant by ID.
    async fn get(&self, id: Uuid) -> Result<Option<Tenant>, DbError>;

    /// Gets a tenant by slug.
    async fn get_by_slug(&self, slug: &str) -> Result<Option<Tenant>, DbError>;

    /// Lists tenants with optional filtering.
    async fn list(&self, filter: &TenantFilter) -> Result<Vec<Tenant>, DbError>;

    /// Updates a tenant.
    async fn update(&self, id: Uuid, update: &TenantUpdate) -> Result<Tenant, DbError>;

    /// Deletes a tenant.
    async fn delete(&self, id: Uuid) -> Result<bool, DbError>;

    /// Counts tenants matching a filter.
    async fn count(&self, filter: &TenantFilter) -> Result<u64, DbError>;

    /// Checks if any tenants exist.
    async fn any_exist(&self) -> Result<bool, DbError>;

    /// Gets the default tenant (slug = "default").
    async fn get_default(&self) -> Result<Option<Tenant>, DbError> {
        self.get_by_slug("default").await
    }
}

/// SQLite implementation of TenantRepository.
#[cfg(feature = "database")]
pub struct SqliteTenantRepository {
    pool: sqlx::SqlitePool,
}

#[cfg(feature = "database")]
impl SqliteTenantRepository {
    pub fn new(pool: sqlx::SqlitePool) -> Self {
        Self { pool }
    }
}

#[cfg(feature = "database")]
#[async_trait]
impl TenantRepository for SqliteTenantRepository {
    async fn create(&self, tenant: &Tenant) -> Result<Tenant, DbError> {
        let id = tenant.id.to_string();
        let status = tenant.status.as_db_str();
        let settings = serde_json::to_string(&tenant.settings)
            .map_err(|e| DbError::Serialization(format!("Failed to serialize settings: {}", e)))?;
        let created_at = tenant.created_at.to_rfc3339();
        let updated_at = tenant.updated_at.to_rfc3339();

        sqlx::query(
            r#"
            INSERT INTO tenants (id, name, slug, status, settings, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&id)
        .bind(&tenant.name)
        .bind(&tenant.slug)
        .bind(status)
        .bind(&settings)
        .bind(&created_at)
        .bind(&updated_at)
        .execute(&self.pool)
        .await?;

        Ok(tenant.clone())
    }

    async fn get(&self, id: Uuid) -> Result<Option<Tenant>, DbError> {
        let id_str = id.to_string();
        let row: Option<SqliteTenantRow> = sqlx::query_as(
            "SELECT id, name, slug, status, settings, created_at, updated_at FROM tenants WHERE id = ?",
        )
        .bind(&id_str)
        .fetch_optional(&self.pool)
        .await?;

        row.map(TryInto::try_into).transpose()
    }

    async fn get_by_slug(&self, slug: &str) -> Result<Option<Tenant>, DbError> {
        let row: Option<SqliteTenantRow> = sqlx::query_as(
            "SELECT id, name, slug, status, settings, created_at, updated_at FROM tenants WHERE slug = ?",
        )
        .bind(slug)
        .fetch_optional(&self.pool)
        .await?;

        row.map(TryInto::try_into).transpose()
    }

    async fn list(&self, filter: &TenantFilter) -> Result<Vec<Tenant>, DbError> {
        let mut query = String::from(
            "SELECT id, name, slug, status, settings, created_at, updated_at FROM tenants WHERE 1=1",
        );
        let mut params: Vec<String> = Vec::new();

        if let Some(status) = &filter.status {
            query.push_str(" AND status = ?");
            params.push(status.as_db_str().to_string());
        }

        if let Some(search) = &filter.search {
            query.push_str(" AND (name LIKE ? ESCAPE '\\' OR slug LIKE ? ESCAPE '\\')");
            let pattern = format!("%{}%", escape_like_pattern(search));
            params.push(pattern.clone());
            params.push(pattern);
        }

        query.push_str(" ORDER BY name ASC");

        let mut sqlx_query = sqlx::query_as::<_, SqliteTenantRow>(&query);
        for param in params {
            sqlx_query = sqlx_query.bind(param);
        }

        let rows: Vec<SqliteTenantRow> = sqlx_query.fetch_all(&self.pool).await?;

        rows.into_iter().map(TryInto::try_into).collect()
    }

    async fn update(&self, id: Uuid, update: &TenantUpdate) -> Result<Tenant, DbError> {
        let existing = self.get(id).await?.ok_or_else(|| DbError::NotFound {
            entity: "Tenant".to_string(),
            id: id.to_string(),
        })?;

        let name = update.name.as_ref().unwrap_or(&existing.name);
        let status = update.status.unwrap_or(existing.status);
        let settings = update.settings.as_ref().unwrap_or(&existing.settings);
        let settings_json = serde_json::to_string(settings)
            .map_err(|e| DbError::Serialization(format!("Failed to serialize settings: {}", e)))?;
        let updated_at = Utc::now().to_rfc3339();

        sqlx::query(
            r#"
            UPDATE tenants SET name = ?, status = ?, settings = ?, updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(name)
        .bind(status.as_db_str())
        .bind(&settings_json)
        .bind(&updated_at)
        .bind(id.to_string())
        .execute(&self.pool)
        .await?;

        self.get(id).await?.ok_or_else(|| DbError::NotFound {
            entity: "Tenant".to_string(),
            id: id.to_string(),
        })
    }

    async fn delete(&self, id: Uuid) -> Result<bool, DbError> {
        let result = sqlx::query("DELETE FROM tenants WHERE id = ?")
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    async fn count(&self, filter: &TenantFilter) -> Result<u64, DbError> {
        let mut query = String::from("SELECT COUNT(*) as count FROM tenants WHERE 1=1");
        let mut params: Vec<String> = Vec::new();

        if let Some(status) = &filter.status {
            query.push_str(" AND status = ?");
            params.push(status.as_db_str().to_string());
        }

        if let Some(search) = &filter.search {
            query.push_str(" AND (name LIKE ? ESCAPE '\\' OR slug LIKE ? ESCAPE '\\')");
            let pattern = format!("%{}%", escape_like_pattern(search));
            params.push(pattern.clone());
            params.push(pattern);
        }

        let mut sqlx_query = sqlx::query_scalar::<_, i64>(&query);
        for param in params {
            sqlx_query = sqlx_query.bind(param);
        }

        let count: i64 = sqlx_query.fetch_one(&self.pool).await?;
        Ok(count as u64)
    }

    async fn any_exist(&self) -> Result<bool, DbError> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tenants")
            .fetch_one(&self.pool)
            .await?;
        Ok(count > 0)
    }
}

/// PostgreSQL implementation of TenantRepository.
#[cfg(feature = "database")]
pub struct PgTenantRepository {
    pool: sqlx::PgPool,
}

#[cfg(feature = "database")]
impl PgTenantRepository {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

#[cfg(feature = "database")]
#[async_trait]
impl TenantRepository for PgTenantRepository {
    async fn create(&self, tenant: &Tenant) -> Result<Tenant, DbError> {
        let status = tenant.status.as_db_str();
        let settings = serde_json::to_value(&tenant.settings)
            .map_err(|e| DbError::Serialization(format!("Failed to serialize settings: {}", e)))?;

        sqlx::query(
            r#"
            INSERT INTO tenants (id, name, slug, status, settings, created_at, updated_at)
            VALUES ($1, $2, $3, $4::tenant_status, $5, $6, $7)
            "#,
        )
        .bind(tenant.id)
        .bind(&tenant.name)
        .bind(&tenant.slug)
        .bind(status)
        .bind(&settings)
        .bind(tenant.created_at)
        .bind(tenant.updated_at)
        .execute(&self.pool)
        .await?;

        Ok(tenant.clone())
    }

    async fn get(&self, id: Uuid) -> Result<Option<Tenant>, DbError> {
        let row: Option<PgTenantRow> = sqlx::query_as(
            "SELECT id, name, slug, status::text, settings, created_at, updated_at FROM tenants WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(TryInto::try_into).transpose()
    }

    async fn get_by_slug(&self, slug: &str) -> Result<Option<Tenant>, DbError> {
        let row: Option<PgTenantRow> = sqlx::query_as(
            "SELECT id, name, slug, status::text, settings, created_at, updated_at FROM tenants WHERE slug = $1",
        )
        .bind(slug)
        .fetch_optional(&self.pool)
        .await?;

        row.map(TryInto::try_into).transpose()
    }

    async fn list(&self, filter: &TenantFilter) -> Result<Vec<Tenant>, DbError> {
        let rows: Vec<PgTenantRow> = if filter.status.is_some() || filter.search.is_some() {
            let mut conditions = vec!["1=1".to_string()];
            let mut param_idx = 1;

            if filter.status.is_some() {
                conditions.push(format!("status = ${}::tenant_status", param_idx));
                param_idx += 1;
            }

            if filter.search.is_some() {
                conditions.push(format!(
                    "(name ILIKE ${} OR slug ILIKE ${})",
                    param_idx,
                    param_idx + 1
                ));
            }

            let query = format!(
                "SELECT id, name, slug, status::text, settings, created_at, updated_at FROM tenants WHERE {} ORDER BY name ASC",
                conditions.join(" AND ")
            );

            let mut sqlx_query = sqlx::query_as::<_, PgTenantRow>(&query);

            if let Some(status) = &filter.status {
                sqlx_query = sqlx_query.bind(status.as_db_str());
            }

            if let Some(search) = &filter.search {
                let pattern = format!("%{}%", escape_like_pattern(search));
                sqlx_query = sqlx_query.bind(pattern.clone());
                sqlx_query = sqlx_query.bind(pattern);
            }

            sqlx_query.fetch_all(&self.pool).await?
        } else {
            sqlx::query_as(
                "SELECT id, name, slug, status::text, settings, created_at, updated_at FROM tenants ORDER BY name ASC",
            )
            .fetch_all(&self.pool)
            .await?
        };

        rows.into_iter().map(TryInto::try_into).collect()
    }

    async fn update(&self, id: Uuid, update: &TenantUpdate) -> Result<Tenant, DbError> {
        let existing = self.get(id).await?.ok_or_else(|| DbError::NotFound {
            entity: "Tenant".to_string(),
            id: id.to_string(),
        })?;

        let name = update.name.as_ref().unwrap_or(&existing.name);
        let status = update.status.unwrap_or(existing.status);
        let settings = update.settings.as_ref().unwrap_or(&existing.settings);
        let settings_json = serde_json::to_value(settings)
            .map_err(|e| DbError::Serialization(format!("Failed to serialize settings: {}", e)))?;

        sqlx::query(
            r#"
            UPDATE tenants SET name = $1, status = $2::tenant_status, settings = $3, updated_at = NOW()
            WHERE id = $4
            "#,
        )
        .bind(name)
        .bind(status.as_db_str())
        .bind(&settings_json)
        .bind(id)
        .execute(&self.pool)
        .await?;

        self.get(id).await?.ok_or_else(|| DbError::NotFound {
            entity: "Tenant".to_string(),
            id: id.to_string(),
        })
    }

    async fn delete(&self, id: Uuid) -> Result<bool, DbError> {
        let result = sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    async fn count(&self, filter: &TenantFilter) -> Result<u64, DbError> {
        let count: i64 = if filter.status.is_some() || filter.search.is_some() {
            let mut conditions = vec!["1=1".to_string()];
            let mut param_idx = 1;

            if filter.status.is_some() {
                conditions.push(format!("status = ${}::tenant_status", param_idx));
                param_idx += 1;
            }

            if filter.search.is_some() {
                conditions.push(format!(
                    "(name ILIKE ${} OR slug ILIKE ${})",
                    param_idx,
                    param_idx + 1
                ));
            }

            let query = format!(
                "SELECT COUNT(*) FROM tenants WHERE {}",
                conditions.join(" AND ")
            );

            let mut sqlx_query = sqlx::query_scalar::<_, i64>(&query);

            if let Some(status) = &filter.status {
                sqlx_query = sqlx_query.bind(status.as_db_str());
            }

            if let Some(search) = &filter.search {
                let pattern = format!("%{}%", escape_like_pattern(search));
                sqlx_query = sqlx_query.bind(pattern.clone());
                sqlx_query = sqlx_query.bind(pattern);
            }

            sqlx_query.fetch_one(&self.pool).await?
        } else {
            sqlx::query_scalar("SELECT COUNT(*) FROM tenants")
                .fetch_one(&self.pool)
                .await?
        };

        Ok(count as u64)
    }

    async fn any_exist(&self) -> Result<bool, DbError> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tenants")
            .fetch_one(&self.pool)
            .await?;
        Ok(count > 0)
    }
}

/// Factory function to create the appropriate repository based on pool type.
#[cfg(feature = "database")]
pub fn create_tenant_repository(pool: &DbPool) -> Box<dyn TenantRepository> {
    match pool {
        DbPool::Sqlite(pool) => Box::new(SqliteTenantRepository::new(pool.clone())),
        DbPool::Postgres(pool) => Box::new(PgTenantRepository::new(pool.clone())),
    }
}

// Helper structs for SQLx row mapping

#[cfg(feature = "database")]
#[derive(sqlx::FromRow)]
struct SqliteTenantRow {
    id: String,
    name: String,
    slug: String,
    status: String,
    settings: String,
    created_at: String,
    updated_at: String,
}

#[cfg(feature = "database")]
impl TryFrom<SqliteTenantRow> for Tenant {
    type Error = DbError;

    fn try_from(row: SqliteTenantRow) -> Result<Self, Self::Error> {
        let id = Uuid::parse_str(&row.id)
            .map_err(|e| DbError::Serialization(format!("Invalid UUID: {}", e)))?;

        let status = match row.status.as_str() {
            "active" => TenantStatus::Active,
            "suspended" => TenantStatus::Suspended,
            "pending_deletion" => TenantStatus::PendingDeletion,
            _ => {
                return Err(DbError::Serialization(format!(
                    "Invalid tenant status: {}",
                    row.status
                )))
            }
        };

        let settings: TenantSettings = serde_json::from_str(&row.settings)
            .map_err(|e| DbError::Serialization(format!("Invalid settings JSON: {}", e)))?;

        let created_at = DateTime::parse_from_rfc3339(&row.created_at)
            .map_err(|e| DbError::Serialization(format!("Invalid timestamp: {}", e)))?
            .with_timezone(&Utc);

        let updated_at = DateTime::parse_from_rfc3339(&row.updated_at)
            .map_err(|e| DbError::Serialization(format!("Invalid timestamp: {}", e)))?
            .with_timezone(&Utc);

        Ok(Tenant {
            id,
            name: row.name,
            slug: row.slug,
            status,
            settings,
            created_at,
            updated_at,
        })
    }
}

#[cfg(feature = "database")]
#[derive(sqlx::FromRow)]
struct PgTenantRow {
    id: Uuid,
    name: String,
    slug: String,
    status: String,
    settings: serde_json::Value,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[cfg(feature = "database")]
impl TryFrom<PgTenantRow> for Tenant {
    type Error = DbError;

    fn try_from(row: PgTenantRow) -> Result<Self, Self::Error> {
        let status = match row.status.as_str() {
            "active" => TenantStatus::Active,
            "suspended" => TenantStatus::Suspended,
            "pending_deletion" => TenantStatus::PendingDeletion,
            _ => {
                return Err(DbError::Serialization(format!(
                    "Invalid tenant status: {}",
                    row.status
                )))
            }
        };

        let settings: TenantSettings = serde_json::from_value(row.settings)
            .map_err(|e| DbError::Serialization(format!("Invalid settings JSON: {}", e)))?;

        Ok(Tenant {
            id: row.id,
            name: row.name,
            slug: row.slug,
            status,
            settings,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tenant_filter_default() {
        let filter = TenantFilter::default();
        assert!(filter.status.is_none());
        assert!(filter.search.is_none());
    }

    #[test]
    fn test_tenant_update_default() {
        let update = TenantUpdate::default();
        assert!(update.name.is_none());
        assert!(update.status.is_none());
        assert!(update.settings.is_none());
    }
}
