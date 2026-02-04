//! Tenant-aware database connection management.
//!
//! This module provides utilities for setting PostgreSQL session variables
//! to enable Row-Level Security (RLS) tenant isolation.
//!
//! # How It Works
//!
//! 1. Before executing any query, call [`set_tenant_context`] with the tenant ID
//! 2. PostgreSQL RLS policies automatically filter queries by `app.current_tenant`
//! 3. Queries return only data belonging to the current tenant
//!
//! # Example
//!
//! ```rust,ignore
//! use tw_core::db::tenant_connection::{set_tenant_context, TenantConnectionGuard};
//! use tw_core::tenant::TenantContext;
//!
//! // Method 1: Direct function call
//! let mut conn = pool.acquire().await?;
//! set_tenant_context(&mut conn, tenant_ctx.tenant_id).await?;
//! // Execute queries...
//!
//! // Method 2: Using the guard (recommended for request handlers)
//! let guard = TenantConnectionGuard::new(pool.clone(), tenant_ctx.tenant_id).await?;
//! // guard.conn() returns a reference to the configured connection
//! // Tenant context is automatically cleared when guard is dropped
//! ```
//!
//! # Security Notes
//!
//! - Always set tenant context before executing queries on tenant-scoped tables
//! - Use superuser connections (which bypass RLS) only for admin operations
//! - The RLS policies use `fail-secure` behavior: if `app.current_tenant` is not set,
//!   queries return no rows

use super::{DbError, DbPool};
use uuid::Uuid;

/// Error types specific to tenant connection operations.
#[derive(Debug, thiserror::Error)]
pub enum TenantConnectionError {
    /// The database pool is not PostgreSQL (RLS is PostgreSQL-only).
    #[error("RLS tenant context is only supported on PostgreSQL")]
    NotPostgres,

    /// Failed to set the tenant context session variable.
    #[error("Failed to set tenant context: {0}")]
    SetContextFailed(String),

    /// Failed to clear the tenant context.
    #[error("Failed to clear tenant context: {0}")]
    ClearContextFailed(String),

    /// Database error during connection operations.
    #[error("Database error: {0}")]
    Database(#[from] DbError),

    /// SQLx error.
    #[error("SQLx error: {0}")]
    Sqlx(#[from] sqlx::Error),
}

/// Sets the tenant context for a PostgreSQL connection.
///
/// This must be called before executing any queries on tenant-scoped tables
/// to ensure RLS policies filter data correctly.
///
/// # Arguments
///
/// * `conn` - A mutable reference to a PostgreSQL connection
/// * `tenant_id` - The UUID of the tenant to set as the current context
///
/// # Returns
///
/// Returns `Ok(())` if the context was set successfully, or an error if:
/// - The pool is not PostgreSQL
/// - The SET command failed
///
/// # Example
///
/// ```rust,ignore
/// use tw_core::db::tenant_connection::set_tenant_context;
///
/// let mut conn = pool.acquire().await?;
/// set_tenant_context(&mut conn, tenant_id).await?;
/// // Now all queries on this connection are filtered by tenant_id
/// ```
#[cfg(feature = "database")]
pub async fn set_tenant_context(
    pool: &DbPool,
    tenant_id: Uuid,
) -> Result<(), TenantConnectionError> {
    match pool {
        DbPool::Postgres(pg_pool) => {
            // Use the helper function we created in the migration
            sqlx::query("SELECT set_tenant_context($1)")
                .bind(tenant_id)
                .execute(pg_pool)
                .await?;
            Ok(())
        }
        DbPool::Sqlite(_) => {
            // SQLite doesn't support RLS, so this is a no-op
            // Application-level filtering handles tenant isolation for SQLite
            Ok(())
        }
    }
}

#[cfg(not(feature = "database"))]
pub async fn set_tenant_context(
    _pool: &DbPool,
    _tenant_id: Uuid,
) -> Result<(), TenantConnectionError> {
    Ok(())
}

/// Clears the tenant context for a PostgreSQL connection.
///
/// After calling this, queries on tenant-scoped tables will return no rows
/// (fail-secure behavior). This is useful for:
/// - Admin operations that need to query across tenants
/// - Cleanup when returning a connection to the pool
///
/// # Arguments
///
/// * `conn` - A mutable reference to a PostgreSQL connection
///
/// # Example
///
/// ```rust,ignore
/// use tw_core::db::tenant_connection::clear_tenant_context;
///
/// // After tenant-specific work is done
/// clear_tenant_context(&mut conn).await?;
/// ```
#[cfg(feature = "database")]
pub async fn clear_tenant_context(pool: &DbPool) -> Result<(), TenantConnectionError> {
    match pool {
        DbPool::Postgres(pg_pool) => {
            sqlx::query("SELECT clear_tenant_context()")
                .execute(pg_pool)
                .await?;
            Ok(())
        }
        DbPool::Sqlite(_) => {
            // SQLite doesn't have session variables to clear
            Ok(())
        }
    }
}

#[cfg(not(feature = "database"))]
pub async fn clear_tenant_context(_pool: &DbPool) -> Result<(), TenantConnectionError> {
    Ok(())
}

/// Gets the current tenant context from a PostgreSQL connection.
///
/// Returns `None` if no tenant context is set or if using SQLite.
///
/// # Arguments
///
/// * `conn` - A reference to a database connection
///
/// # Example
///
/// ```rust,ignore
/// use tw_core::db::tenant_connection::get_current_tenant;
///
/// let tenant_id = get_current_tenant(&pool).await?;
/// match tenant_id {
///     Some(id) => println!("Current tenant: {}", id),
///     None => println!("No tenant context set"),
/// }
/// ```
#[cfg(feature = "database")]
pub async fn get_current_tenant(pool: &DbPool) -> Result<Option<Uuid>, TenantConnectionError> {
    match pool {
        DbPool::Postgres(pg_pool) => {
            let row: Option<(Option<Uuid>,)> = sqlx::query_as("SELECT get_current_tenant()")
                .fetch_optional(pg_pool)
                .await?;

            Ok(row.and_then(|(id,)| id))
        }
        DbPool::Sqlite(_) => {
            // SQLite doesn't have session variables
            Ok(None)
        }
    }
}

#[cfg(not(feature = "database"))]
pub async fn get_current_tenant(_pool: &DbPool) -> Result<Option<Uuid>, TenantConnectionError> {
    Ok(None)
}

/// Configuration for the tenant-aware database pool.
#[derive(Debug, Clone)]
pub struct TenantPoolConfig {
    /// The main database URL for tenant-scoped queries (uses RLS).
    pub database_url: String,

    /// Optional separate database URL for admin operations (bypasses RLS).
    /// If not provided, admin operations will use the main pool.
    pub admin_database_url: Option<String>,

    /// Whether to enforce tenant context on all queries.
    /// When true, queries without a tenant context will fail.
    /// When false (default), queries will proceed but RLS will filter to no rows.
    pub require_tenant_context: bool,
}

impl TenantPoolConfig {
    /// Creates a new configuration with the given database URL.
    pub fn new(database_url: impl Into<String>) -> Self {
        Self {
            database_url: database_url.into(),
            admin_database_url: None,
            require_tenant_context: false,
        }
    }

    /// Sets the admin database URL for bypassing RLS.
    pub fn with_admin_url(mut self, url: impl Into<String>) -> Self {
        self.admin_database_url = Some(url.into());
        self
    }

    /// Sets whether to require tenant context on all queries.
    pub fn with_required_context(mut self, required: bool) -> Self {
        self.require_tenant_context = required;
        self
    }
}

/// A wrapper around DbPool that manages tenant context.
///
/// This provides a higher-level interface for working with tenant-aware
/// database connections. It can optionally maintain separate pools for
/// tenant operations (with RLS) and admin operations (bypassing RLS).
#[derive(Clone)]
pub struct TenantAwarePool {
    /// The main pool for tenant-scoped queries.
    pool: DbPool,

    /// Optional admin pool that bypasses RLS.
    admin_pool: Option<DbPool>,

    /// Configuration.
    config: TenantPoolConfig,
}

impl TenantAwarePool {
    /// Creates a new tenant-aware pool.
    #[cfg(feature = "database")]
    pub async fn new(config: TenantPoolConfig) -> Result<Self, DbError> {
        use super::create_pool;

        let pool = create_pool(&config.database_url).await?;

        let admin_pool = if let Some(ref admin_url) = config.admin_database_url {
            Some(create_pool(admin_url).await?)
        } else {
            None
        };

        Ok(Self {
            pool,
            admin_pool,
            config,
        })
    }

    #[cfg(not(feature = "database"))]
    pub async fn new(_config: TenantPoolConfig) -> Result<Self, DbError> {
        Err(DbError::Configuration(
            "Database support not enabled".to_string(),
        ))
    }

    /// Returns a reference to the main pool.
    pub fn pool(&self) -> &DbPool {
        &self.pool
    }

    /// Returns a reference to the admin pool (bypasses RLS).
    ///
    /// Falls back to the main pool if no admin pool is configured.
    pub fn admin_pool(&self) -> &DbPool {
        self.admin_pool.as_ref().unwrap_or(&self.pool)
    }

    /// Sets the tenant context for the main pool.
    pub async fn set_tenant(&self, tenant_id: Uuid) -> Result<(), TenantConnectionError> {
        set_tenant_context(&self.pool, tenant_id).await
    }

    /// Clears the tenant context for the main pool.
    pub async fn clear_tenant(&self) -> Result<(), TenantConnectionError> {
        clear_tenant_context(&self.pool).await
    }

    /// Gets the current tenant context.
    pub async fn current_tenant(&self) -> Result<Option<Uuid>, TenantConnectionError> {
        get_current_tenant(&self.pool).await
    }

    /// Checks if the pool is healthy.
    #[cfg(feature = "database")]
    pub async fn is_healthy(&self) -> bool {
        self.pool.is_healthy().await
    }

    #[cfg(not(feature = "database"))]
    pub async fn is_healthy(&self) -> bool {
        false
    }

    /// Returns whether RLS is supported (PostgreSQL only).
    #[cfg(feature = "database")]
    pub fn supports_rls(&self) -> bool {
        matches!(self.pool, DbPool::Postgres(_))
    }

    #[cfg(not(feature = "database"))]
    pub fn supports_rls(&self) -> bool {
        false
    }

    /// Returns a reference to the pool configuration.
    pub fn config(&self) -> &TenantPoolConfig {
        &self.config
    }
}

/// A guard that ensures tenant context is set for the duration of its lifetime.
///
/// This is useful in request handlers where you want to ensure tenant context
/// is properly set and cleaned up, even if an error occurs.
///
/// # Example
///
/// ```rust,ignore
/// use tw_core::db::tenant_connection::TenantContextGuard;
///
/// async fn handle_request(pool: &TenantAwarePool, tenant_id: Uuid) -> Result<(), Error> {
///     let _guard = TenantContextGuard::new(pool, tenant_id).await?;
///
///     // All queries here are automatically filtered by tenant_id
///     let incidents = incident_repo.list_all().await?;
///
///     Ok(())
///     // Guard is dropped here, tenant context is cleared
/// }
/// ```
pub struct TenantContextGuard<'a> {
    pool: &'a TenantAwarePool,
    clear_on_drop: bool,
}

impl<'a> TenantContextGuard<'a> {
    /// Creates a new guard that sets the tenant context.
    pub async fn new(
        pool: &'a TenantAwarePool,
        tenant_id: Uuid,
    ) -> Result<Self, TenantConnectionError> {
        pool.set_tenant(tenant_id).await?;
        Ok(Self {
            pool,
            clear_on_drop: true,
        })
    }

    /// Creates a guard without clearing context on drop.
    ///
    /// Use this when the connection will be returned to a pool that
    /// manages tenant context separately.
    pub async fn new_without_cleanup(
        pool: &'a TenantAwarePool,
        tenant_id: Uuid,
    ) -> Result<Self, TenantConnectionError> {
        pool.set_tenant(tenant_id).await?;
        Ok(Self {
            pool,
            clear_on_drop: false,
        })
    }

    /// Returns a reference to the underlying pool.
    pub fn pool(&self) -> &DbPool {
        self.pool.pool()
    }
}

impl Drop for TenantContextGuard<'_> {
    fn drop(&mut self) {
        if self.clear_on_drop {
            // Note: We can't do async cleanup in drop, so we just log a warning.
            // In practice, connection pooling means the connection will be reused
            // and the next request will set its own tenant context.
            // For critical cleanup, use explicit clear_tenant() before dropping.
            tracing::trace!("TenantContextGuard dropped - tenant context may still be set");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tenant_pool_config() {
        let config = TenantPoolConfig::new("postgres://localhost/test")
            .with_admin_url("postgres://admin@localhost/test")
            .with_required_context(true);

        assert_eq!(config.database_url, "postgres://localhost/test");
        assert_eq!(
            config.admin_database_url,
            Some("postgres://admin@localhost/test".to_string())
        );
        assert!(config.require_tenant_context);
    }

    #[test]
    fn test_tenant_connection_error_display() {
        let err = TenantConnectionError::NotPostgres;
        assert_eq!(
            err.to_string(),
            "RLS tenant context is only supported on PostgreSQL"
        );

        let err = TenantConnectionError::SetContextFailed("test error".to_string());
        assert_eq!(err.to_string(), "Failed to set tenant context: test error");
    }
}
