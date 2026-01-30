//! Database connection pool management.

use super::DbError;
use std::time::Duration;

#[cfg(feature = "database")]
use sqlx::{Pool, Postgres, Sqlite};

/// Unified database pool that can work with SQLite or PostgreSQL.
#[cfg(feature = "database")]
pub enum DbPool {
    /// SQLite connection pool (for development/testing).
    Sqlite(Pool<Sqlite>),
    /// PostgreSQL connection pool (for production).
    Postgres(Pool<Postgres>),
}

#[cfg(not(feature = "database"))]
pub struct DbPool;

/// Options for creating a database connection pool.
#[derive(Debug, Clone)]
pub struct PoolOptions {
    /// Maximum number of connections in the pool.
    pub max_connections: u32,
    /// Minimum number of connections to maintain.
    pub min_connections: u32,
    /// Maximum time to wait for a connection.
    pub acquire_timeout: Duration,
    /// Maximum lifetime of a connection.
    pub max_lifetime: Option<Duration>,
    /// Idle timeout for connections.
    pub idle_timeout: Option<Duration>,
}

impl Default for PoolOptions {
    fn default() -> Self {
        Self {
            max_connections: 10,
            min_connections: 1,
            acquire_timeout: Duration::from_secs(30),
            max_lifetime: Some(Duration::from_secs(1800)), // 30 minutes
            idle_timeout: Some(Duration::from_secs(600)),  // 10 minutes
        }
    }
}

/// Creates a database connection pool from a database URL.
///
/// The URL scheme determines the database type:
/// - `sqlite://` or `sqlite:` for SQLite
/// - `postgres://` or `postgresql://` for PostgreSQL
///
/// # Arguments
/// * `database_url` - Database connection URL
///
/// # Returns
/// A database pool on success, or an error if connection fails.
#[cfg(feature = "database")]
pub async fn create_pool(database_url: &str) -> Result<DbPool, DbError> {
    create_pool_with_options(database_url, PoolOptions::default()).await
}

#[cfg(not(feature = "database"))]
pub async fn create_pool(_database_url: &str) -> Result<DbPool, DbError> {
    Err(DbError::Configuration(
        "Database support not enabled. Compile with --features database".to_string(),
    ))
}

/// Creates a database connection pool with custom options.
#[cfg(feature = "database")]
pub async fn create_pool_with_options(
    database_url: &str,
    options: PoolOptions,
) -> Result<DbPool, DbError> {
    use tracing::info;

    if database_url.starts_with("sqlite:") {
        info!("Creating SQLite connection pool");
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(options.max_connections)
            .min_connections(options.min_connections)
            .acquire_timeout(options.acquire_timeout)
            .max_lifetime(options.max_lifetime)
            .idle_timeout(options.idle_timeout)
            .connect(database_url)
            .await?;
        Ok(DbPool::Sqlite(pool))
    } else if database_url.starts_with("postgres://") || database_url.starts_with("postgresql://") {
        info!("Creating PostgreSQL connection pool");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(options.max_connections)
            .min_connections(options.min_connections)
            .acquire_timeout(options.acquire_timeout)
            .max_lifetime(options.max_lifetime)
            .idle_timeout(options.idle_timeout)
            .connect(database_url)
            .await?;
        Ok(DbPool::Postgres(pool))
    } else {
        Err(DbError::Configuration(format!(
            "Unsupported database URL scheme. Expected sqlite:// or postgres://, got: {}",
            database_url.split(':').next().unwrap_or("unknown")
        )))
    }
}

#[cfg(not(feature = "database"))]
pub async fn create_pool_with_options(
    _database_url: &str,
    _options: PoolOptions,
) -> Result<DbPool, DbError> {
    Err(DbError::Configuration(
        "Database support not enabled. Compile with --features database".to_string(),
    ))
}

#[cfg(feature = "database")]
impl DbPool {
    /// Returns the database type as a string.
    pub fn db_type(&self) -> &'static str {
        match self {
            DbPool::Sqlite(_) => "sqlite",
            DbPool::Postgres(_) => "postgres",
        }
    }

    /// Checks if the database connection is healthy.
    pub async fn is_healthy(&self) -> bool {
        match self {
            DbPool::Sqlite(pool) => sqlx::query("SELECT 1").fetch_one(pool).await.is_ok(),
            DbPool::Postgres(pool) => sqlx::query("SELECT 1").fetch_one(pool).await.is_ok(),
        }
    }

    /// Closes the connection pool.
    pub async fn close(&self) {
        match self {
            DbPool::Sqlite(pool) => pool.close().await,
            DbPool::Postgres(pool) => pool.close().await,
        }
    }

    /// Returns pool statistics.
    pub fn pool_size(&self) -> u32 {
        match self {
            DbPool::Sqlite(pool) => pool.size(),
            DbPool::Postgres(pool) => pool.size(),
        }
    }

    /// Returns number of idle connections.
    pub fn idle_connections(&self) -> usize {
        match self {
            DbPool::Sqlite(pool) => pool.num_idle(),
            DbPool::Postgres(pool) => pool.num_idle(),
        }
    }
}
