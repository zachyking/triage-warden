//! Testcontainers support for integration tests.
//!
//! Provides container management for:
//! - PostgreSQL for database tests
//! - Redis for caching/session tests (future)
//!
//! Usage:
//! ```ignore
//! use crate::integration::testcontainers_support::*;
//!
//! #[tokio::test]
//! async fn test_with_postgres() {
//!     let pg = start_postgres().await;
//!     let pool = create_postgres_pool(&pg).await;
//!     // ... run tests
//! }
//! ```

use sqlx::PgPool;
use std::time::Duration;
use testcontainers::{
    core::{IntoContainerPort, WaitFor},
    runners::AsyncRunner,
    ContainerAsync, GenericImage, ImageExt,
};

/// PostgreSQL container configuration.
pub struct PostgresContainer {
    pub container: ContainerAsync<GenericImage>,
    pub host: String,
    pub port: u16,
    pub database: String,
    pub username: String,
    pub password: String,
}

impl PostgresContainer {
    /// Returns the connection URL for this container.
    pub fn connection_url(&self) -> String {
        format!(
            "postgres://{}:{}@{}:{}/{}",
            self.username, self.password, self.host, self.port, self.database
        )
    }
}

/// Starts a PostgreSQL container for testing.
///
/// The container is configured with:
/// - Database: triage_warden_test
/// - Username: test
/// - Password: test
pub async fn start_postgres() -> PostgresContainer {
    // Note: with_exposed_port must be called before ImageExt methods like with_env_var
    let image = GenericImage::new("postgres", "16-alpine")
        .with_exposed_port(5432.tcp())
        .with_wait_for(WaitFor::message_on_stderr(
            "database system is ready to accept connections",
        ))
        .with_env_var("POSTGRES_DB", "triage_warden_test")
        .with_env_var("POSTGRES_USER", "test")
        .with_env_var("POSTGRES_PASSWORD", "test");

    let container = AsyncRunner::start(image)
        .await
        .expect("Failed to start PostgreSQL container");

    // Wait a bit more for postgres to be fully ready
    tokio::time::sleep(Duration::from_secs(1)).await;

    let host = container.get_host().await.expect("Failed to get host");
    let port = container
        .get_host_port_ipv4(5432)
        .await
        .expect("Failed to get port");

    PostgresContainer {
        container,
        host: host.to_string(),
        port,
        database: "triage_warden_test".to_string(),
        username: "test".to_string(),
        password: "test".to_string(),
    }
}

/// Creates a PostgreSQL connection pool for the given container.
pub async fn create_postgres_pool(pg: &PostgresContainer) -> PgPool {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(&pg.connection_url())
        .await
        .expect("Failed to create PostgreSQL pool");

    // Run migrations
    run_postgres_migrations(&pool).await;

    pool
}

/// Helper to run SQL statements from a migration file.
async fn run_migration_file(pool: &PgPool, migration_sql: &str) {
    for raw_statement in migration_sql.split(';') {
        let lines: Vec<&str> = raw_statement
            .lines()
            .filter(|line| !line.trim().starts_with("--"))
            .collect();
        let statement = lines.join("\n");
        let statement = statement.trim();
        if statement.is_empty() {
            continue;
        }
        sqlx::query(statement)
            .execute(pool)
            .await
            .unwrap_or_else(|e| panic!("Failed to run migration: {} - Error: {}", statement, e));
    }
}

/// Runs all database migrations against a PostgreSQL database.
async fn run_postgres_migrations(pool: &PgPool) {
    // Run migrations in order (paths are relative to this file's location in tests/integration/)
    run_migration_file(
        pool,
        include_str!(
            "../../../tw-core/src/db/migrations/postgres/20240101_000001_initial_schema.sql"
        ),
    )
    .await;
    run_migration_file(
        pool,
        include_str!(
            "../../../tw-core/src/db/migrations/postgres/20240130_000001_create_playbooks.sql"
        ),
    )
    .await;
    run_migration_file(
        pool,
        include_str!(
            "../../../tw-core/src/db/migrations/postgres/20240130_000002_create_connectors.sql"
        ),
    )
    .await;
    run_migration_file(
        pool,
        include_str!(
            "../../../tw-core/src/db/migrations/postgres/20240130_000003_create_policies.sql"
        ),
    )
    .await;
    run_migration_file(pool, include_str!("../../../tw-core/src/db/migrations/postgres/20240130_000004_create_notification_channels.sql")).await;
    run_migration_file(
        pool,
        include_str!(
            "../../../tw-core/src/db/migrations/postgres/20240130_000005_create_settings.sql"
        ),
    )
    .await;
    run_migration_file(
        pool,
        include_str!(
            "../../../tw-core/src/db/migrations/postgres/20240201_000001_create_auth_tables.sql"
        ),
    )
    .await;
    run_migration_file(
        pool,
        include_str!(
            "../../../tw-core/src/db/migrations/postgres/20240210_000001_create_feature_flags.sql"
        ),
    )
    .await;

    // Run multi-tenancy migrations
    run_migration_file(
        pool,
        include_str!(
            "../../../tw-core/src/db/migrations/postgres/20240215_000001_create_tenants.sql"
        ),
    )
    .await;
    run_migration_file(pool, include_str!("../../../tw-core/src/db/migrations/postgres/20240215_000002_add_tenant_id_to_tables.sql")).await;
    run_migration_file(pool, include_str!("../../../tw-core/src/db/migrations/postgres/20240220_000001_add_tenant_id_to_tables.sql")).await;
    run_migration_file(
        pool,
        include_str!("../../../tw-core/src/db/migrations/postgres/20240220_000002_enable_rls.sql"),
    )
    .await;
    run_migration_file(
        pool,
        include_str!(
            "../../../tw-core/src/db/migrations/postgres/20240225_000001_add_optimized_indexes.sql"
        ),
    )
    .await;
}

/// Qdrant vector database container configuration.
/// Note: Using a custom image since testcontainers-modules doesn't have Qdrant yet.
pub struct QdrantContainer {
    pub container: ContainerAsync<GenericImage>,
    pub host: String,
    pub http_port: u16,
    pub grpc_port: u16,
}

impl QdrantContainer {
    /// Returns the HTTP URL for this container.
    pub fn http_url(&self) -> String {
        format!("http://{}:{}", self.host, self.http_port)
    }

    /// Returns the gRPC URL for this container.
    pub fn grpc_url(&self) -> String {
        format!("http://{}:{}", self.host, self.grpc_port)
    }
}

/// Starts a Qdrant container for testing.
pub async fn start_qdrant() -> QdrantContainer {
    // Note: with_exposed_port must be called before ImageExt methods
    let image = GenericImage::new("qdrant/qdrant", "v1.12.4")
        .with_exposed_port(6333.tcp())
        .with_exposed_port(6334.tcp())
        .with_wait_for(WaitFor::message_on_stdout("Qdrant gRPC listening on"));

    let container = AsyncRunner::start(image)
        .await
        .expect("Failed to start Qdrant container");

    // Wait for Qdrant to be fully ready
    tokio::time::sleep(Duration::from_secs(2)).await;

    let host = container.get_host().await.expect("Failed to get host");
    let http_port = container
        .get_host_port_ipv4(6333)
        .await
        .expect("Failed to get HTTP port");
    let grpc_port = container
        .get_host_port_ipv4(6334)
        .await
        .expect("Failed to get gRPC port");

    QdrantContainer {
        container,
        host: host.to_string(),
        http_port,
        grpc_port,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires Docker"]
    async fn test_postgres_container_starts() {
        let pg = start_postgres().await;
        assert!(!pg.connection_url().is_empty());

        let pool = create_postgres_pool(&pg).await;

        // Verify we can query the database
        let result: (i32,) = sqlx::query_as("SELECT 1")
            .fetch_one(&pool)
            .await
            .expect("Failed to query database");
        assert_eq!(result.0, 1);
    }

    #[tokio::test]
    #[ignore = "requires Docker"]
    async fn test_qdrant_container_starts() {
        let qdrant = start_qdrant().await;
        assert!(!qdrant.http_url().is_empty());
        assert!(!qdrant.grpc_url().is_empty());

        // Verify Qdrant is accessible via HTTP
        let client = reqwest::Client::new();
        let response = client
            .get(format!("{}/healthz", qdrant.http_url()))
            .send()
            .await
            .expect("Failed to connect to Qdrant");
        assert!(response.status().is_success());
    }
}
