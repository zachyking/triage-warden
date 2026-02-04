//! Common test utilities for integration tests.

use axum::{
    body::Body,
    http::{Method, StatusCode},
    Router,
};
use serde::de::DeserializeOwned;
use sqlx::SqlitePool;
use tower::ServiceExt;
use tw_api::{routes, state::AppState};
use tw_core::{db::DbPool, EventBus};
use uuid::Uuid;

/// Creates an in-memory SQLite database with all migrations applied.
pub async fn setup_test_db() -> SqlitePool {
    let unique_id = Uuid::new_v4();
    let db_url = format!(
        "sqlite:file:integration_test_{}?mode=memory&cache=shared",
        unique_id
    );

    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&db_url)
        .await
        .expect("Failed to create SQLite pool");

    run_migrations(&pool).await;
    pool
}

/// Runs all database migrations.
async fn run_migrations(pool: &SqlitePool) {
    sqlx::query(include_str!(
        "../../../../tw-core/src/db/migrations/sqlite/20240101_000001_initial_schema.sql"
    ))
    .execute(pool)
    .await
    .expect("Failed to run initial schema");

    sqlx::query(include_str!(
        "../../../../tw-core/src/db/migrations/sqlite/20240102_000001_create_playbooks.sql"
    ))
    .execute(pool)
    .await
    .expect("Failed to run playbooks migration");

    sqlx::query(include_str!(
        "../../../../tw-core/src/db/migrations/sqlite/20240103_000001_create_connectors.sql"
    ))
    .execute(pool)
    .await
    .expect("Failed to run connectors migration");

    sqlx::query(include_str!(
        "../../../../tw-core/src/db/migrations/sqlite/20240104_000001_create_policies.sql"
    ))
    .execute(pool)
    .await
    .expect("Failed to run policies migration");

    sqlx::query(include_str!(
        "../../../../tw-core/src/db/migrations/sqlite/20240105_000001_create_notification_channels.sql"
    ))
    .execute(pool)
    .await
    .expect("Failed to run notification channels migration");

    sqlx::query(include_str!(
        "../../../../tw-core/src/db/migrations/sqlite/20240106_000001_create_settings.sql"
    ))
    .execute(pool)
    .await
    .expect("Failed to run settings migration");

    sqlx::query(include_str!(
        "../../../../tw-core/src/db/migrations/sqlite/20240107_000001_create_auth_tables.sql"
    ))
    .execute(pool)
    .await
    .expect("Failed to run auth tables migration");

    // Multi-tenancy migrations
    for raw_statement in include_str!(
        "../../../../tw-core/src/db/migrations/sqlite/20240215_000001_create_tenants.sql"
    )
    .split(';')
    {
        let statement: String = raw_statement
            .lines()
            .filter(|line| !line.trim().starts_with("--"))
            .collect::<Vec<_>>()
            .join("\n");
        let statement = statement.trim();
        if statement.is_empty() {
            continue;
        }
        sqlx::query(statement)
            .execute(pool)
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "Failed to run tenants migration: {} - Error: {}",
                    statement, e
                )
            });
    }

    // Add tenant_id to all tables
    for raw_statement in include_str!(
        "../../../../tw-core/src/db/migrations/sqlite/20240215_000002_add_tenant_id_to_tables.sql"
    )
    .split(';')
    {
        let statement: String = raw_statement
            .lines()
            .filter(|line| !line.trim().starts_with("--"))
            .collect::<Vec<_>>()
            .join("\n");
        let statement = statement.trim();
        if statement.is_empty() {
            continue;
        }
        sqlx::query(statement)
            .execute(pool)
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "Failed to run tenant migration: {} - Error: {}",
                    statement, e
                )
            });
    }
}

/// Creates an AppState with test database.
pub async fn create_test_state() -> AppState {
    let pool = setup_test_db().await;
    let db = DbPool::Sqlite(pool);
    let event_bus = EventBus::new(100);
    AppState::new(db, event_bus)
}

/// Creates a test router (without authentication layer for health tests).
pub async fn create_test_router() -> (Router, AppState) {
    let state = create_test_state().await;
    let router = routes::create_router(state.clone());
    (router, state)
}

/// Helper to make GET requests.
pub fn get_request(uri: &str) -> axum::extract::Request<Body> {
    axum::extract::Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(Body::empty())
        .unwrap()
}

/// Sends request and parses JSON response.
pub async fn send_request<T: DeserializeOwned>(
    app: Router,
    request: axum::extract::Request<Body>,
) -> (StatusCode, T) {
    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let parsed: T = serde_json::from_slice(&body).unwrap_or_else(|e| {
        panic!(
            "Failed to parse response: {} - Body: {:?}",
            e,
            String::from_utf8_lossy(&body)
        )
    });
    (status, parsed)
}

/// Sends request and returns raw response body.
pub async fn send_request_raw(
    app: Router,
    request: axum::extract::Request<Body>,
) -> (StatusCode, String) {
    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&body).to_string())
}
