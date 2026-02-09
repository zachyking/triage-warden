//! Database schema and migrations.

use super::{DbError, DbPool};

/// Runs database migrations.
#[cfg(feature = "database")]
pub async fn run_migrations(pool: &DbPool) -> Result<(), DbError> {
    use tracing::info;

    match pool {
        DbPool::Sqlite(pool) => {
            info!("Running SQLite migrations");
            sqlx::migrate!("src/db/migrations/sqlite").run(pool).await?;
        }
        DbPool::Postgres(pool) => {
            info!("Running PostgreSQL migrations");
            sqlx::migrate!("src/db/migrations/postgres")
                .run(pool)
                .await?;
        }
    }

    info!("Migrations completed successfully");
    Ok(())
}

#[cfg(not(feature = "database"))]
pub async fn run_migrations(_pool: &DbPool) -> Result<(), DbError> {
    Err(DbError::Configuration(
        "Database support not enabled".to_string(),
    ))
}
