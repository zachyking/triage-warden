//! Database connection pool management.

use super::DbError;
use std::time::Duration;

/// Escapes special characters in a search pattern for use in SQL LIKE clauses.
///
/// SQL LIKE patterns use `%` for any sequence of characters and `_` for any
/// single character. If user input contains these characters, they should be
/// escaped to match literally.
///
/// # Characters escaped
///
/// - `%` -> `\%`
/// - `_` -> `\_`
/// - `[` -> `\[` (for databases that support bracket expressions)
/// - `]` -> `\]`
/// - `\` -> `\\`
///
/// # Example
///
/// ```
/// use tw_core::db::escape_like_pattern;
///
/// let user_input = "user_test%";
/// let escaped = escape_like_pattern(user_input);
/// assert_eq!(escaped, r"user\_test\%");
///
/// // Use in a LIKE query:
/// // WHERE username LIKE '%' || $1 || '%' ESCAPE '\'
/// ```
pub fn escape_like_pattern(pattern: &str) -> String {
    let mut escaped = String::with_capacity(pattern.len() * 2);
    for c in pattern.chars() {
        match c {
            '%' | '_' | '[' | ']' | '\\' => {
                escaped.push('\\');
                escaped.push(c);
            }
            _ => escaped.push(c),
        }
    }
    escaped
}

/// Creates a LIKE pattern that matches anywhere in the string.
///
/// Escapes the search term and wraps it with `%` wildcards.
///
/// # Example
///
/// ```
/// use tw_core::db::make_like_pattern;
///
/// let pattern = make_like_pattern("test_user");
/// assert_eq!(pattern, r"%test\_user%");
/// ```
pub fn make_like_pattern(search: &str) -> String {
    format!("%{}%", escape_like_pattern(search))
}

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
        // Parse from environment variables with production-ready defaults
        let max_connections = std::env::var("DATABASE_MAX_CONNECTIONS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(50); // Increased from 10 for production workloads

        let min_connections = std::env::var("DATABASE_MIN_CONNECTIONS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(5); // Increased from 1 to maintain warm connections

        let acquire_timeout_secs = std::env::var("DATABASE_ACQUIRE_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(30);

        Self {
            max_connections,
            min_connections,
            acquire_timeout: Duration::from_secs(acquire_timeout_secs),
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
impl Clone for DbPool {
    fn clone(&self) -> Self {
        match self {
            DbPool::Sqlite(pool) => DbPool::Sqlite(pool.clone()),
            DbPool::Postgres(pool) => DbPool::Postgres(pool.clone()),
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_like_pattern_no_special() {
        assert_eq!(escape_like_pattern("hello"), "hello");
        assert_eq!(escape_like_pattern("test123"), "test123");
        assert_eq!(escape_like_pattern(""), "");
    }

    #[test]
    fn test_escape_like_pattern_percent() {
        assert_eq!(escape_like_pattern("100%"), r"100\%");
        assert_eq!(escape_like_pattern("%test%"), r"\%test\%");
    }

    #[test]
    fn test_escape_like_pattern_underscore() {
        assert_eq!(escape_like_pattern("user_name"), r"user\_name");
        assert_eq!(escape_like_pattern("_private"), r"\_private");
    }

    #[test]
    fn test_escape_like_pattern_brackets() {
        assert_eq!(escape_like_pattern("[a-z]"), r"\[a-z\]");
    }

    #[test]
    fn test_escape_like_pattern_backslash() {
        assert_eq!(escape_like_pattern(r"c:\path"), r"c:\\path");
    }

    #[test]
    fn test_escape_like_pattern_mixed() {
        assert_eq!(
            escape_like_pattern("test_user%[admin]"),
            r"test\_user\%\[admin\]"
        );
    }

    #[test]
    fn test_make_like_pattern() {
        assert_eq!(make_like_pattern("test"), "%test%");
        assert_eq!(make_like_pattern("user_"), r"%user\_%");
        assert_eq!(make_like_pattern("100%"), r"%100\%%");
    }

    #[test]
    fn test_pool_options_default() {
        // Clear env vars to test defaults
        std::env::remove_var("DATABASE_MAX_CONNECTIONS");
        std::env::remove_var("DATABASE_MIN_CONNECTIONS");
        std::env::remove_var("DATABASE_ACQUIRE_TIMEOUT_SECS");

        let opts = PoolOptions::default();
        assert_eq!(opts.max_connections, 50);
        assert_eq!(opts.min_connections, 5);
    }
}
