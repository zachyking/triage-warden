//! Shared test helpers for the tw-api crate.
//!
//! This module provides common test utilities for setting up test databases,
//! creating test state, and generating test entities. It consolidates patterns
//! used across multiple test modules to reduce duplication and ensure consistency.
//!
//! # Usage
//!
//! ```ignore
//! use crate::test_helpers::{setup_test_db, create_test_state, create_test_incident};
//!
//! #[tokio::test]
//! async fn my_test() {
//!     let state = create_test_state().await;
//!     let incident = create_test_incident(&state).await;
//!     // ... test logic
//! }
//! ```

use chrono::Utc;
use sqlx::SqlitePool;
use std::sync::Arc;
use uuid::Uuid;

use tw_core::auth::DEFAULT_TENANT_ID;
use tw_core::connector::{ConnectorConfig, ConnectorType};
use tw_core::db::{
    create_connector_repository, create_incident_repository, create_playbook_repository, DbPool,
};
use tw_core::incident::{Alert, AlertSource, Incident, Severity};
use tw_core::playbook::Playbook;
use tw_core::{EventBus, FeatureFlagStore, FeatureFlags, InMemoryFeatureFlagStore};

use crate::state::AppState;

// ============================================================================
// Database Setup
// ============================================================================

/// Creates an in-memory SQLite pool with full schema for testing.
///
/// Each call creates a completely isolated database with a unique identifier,
/// ensuring tests don't interfere with each other when run in parallel.
///
/// # Returns
///
/// A `SqlitePool` connected to a fresh in-memory database with all tables created.
///
/// # Panics
///
/// Panics if the database connection or schema creation fails.
///
/// # Example
///
/// ```ignore
/// let pool = setup_test_db().await;
/// // Use pool for direct database operations
/// ```
pub async fn setup_test_db() -> SqlitePool {
    // Use a unique UUID for complete database isolation
    let unique_id = Uuid::new_v4();
    let db_url = format!("sqlite:file:test_db_{}?mode=memory&cache=shared", unique_id);

    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&db_url)
        .await
        .expect("Failed to create SQLite pool");

    // Run all migrations to set up the complete schema
    run_migrations(&pool).await;

    pool
}

/// Creates an in-memory SQLite pool using a file-based approach for tests
/// that need persistent storage during the test lifecycle.
///
/// This is useful for tests that need to verify data persistence or
/// perform multiple operations that span router clones.
///
/// # Returns
///
/// A tuple of `(SqlitePool, PathBuf)` where PathBuf is the temp file path.
///
/// # Panics
///
/// Panics if the database connection or schema creation fails.
pub async fn setup_test_db_with_file() -> (SqlitePool, std::path::PathBuf) {
    let unique_id = Uuid::new_v4();
    let temp_dir = std::env::temp_dir();
    let db_path = temp_dir.join(format!("tw_api_test_{}.db", unique_id));
    let db_url = format!("sqlite:{}?mode=rwc", db_path.display());

    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&db_url)
        .await
        .expect("Failed to create SQLite pool");

    run_migrations(&pool).await;

    (pool, db_path)
}

/// Runs all database migrations on the provided pool.
///
/// This includes:
/// - Initial schema (incidents, audit_logs, actions)
/// - Playbooks table
/// - Connectors table
/// - Policies table
/// - Notification channels table
/// - Settings table
async fn run_migrations(pool: &SqlitePool) {
    // Initial schema with incidents, audit_logs, and actions
    sqlx::query(include_str!(
        "../../tw-core/src/db/migrations/sqlite/20240101_000001_initial_schema.sql"
    ))
    .execute(pool)
    .await
    .expect("Failed to run initial schema migration");

    // Playbooks table
    sqlx::query(include_str!(
        "../../tw-core/src/db/migrations/sqlite/20240102_000001_create_playbooks.sql"
    ))
    .execute(pool)
    .await
    .expect("Failed to run playbooks migration");

    // Connectors table
    sqlx::query(include_str!(
        "../../tw-core/src/db/migrations/sqlite/20240103_000001_create_connectors.sql"
    ))
    .execute(pool)
    .await
    .expect("Failed to run connectors migration");

    // Policies table
    sqlx::query(include_str!(
        "../../tw-core/src/db/migrations/sqlite/20240104_000001_create_policies.sql"
    ))
    .execute(pool)
    .await
    .expect("Failed to run policies migration");

    // Notification channels table
    sqlx::query(include_str!(
        "../../tw-core/src/db/migrations/sqlite/20240105_000001_create_notification_channels.sql"
    ))
    .execute(pool)
    .await
    .expect("Failed to run notification channels migration");

    // Settings table
    sqlx::query(include_str!(
        "../../tw-core/src/db/migrations/sqlite/20240106_000001_create_settings.sql"
    ))
    .execute(pool)
    .await
    .expect("Failed to run settings migration");

    // Feature flags table
    sqlx::query(include_str!(
        "../../tw-core/src/db/migrations/sqlite/20240210_000001_create_feature_flags.sql"
    ))
    .execute(pool)
    .await
    .expect("Failed to run feature flags migration");

    // Create tenants table for multi-tenancy
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS tenants (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            slug TEXT NOT NULL UNIQUE,
            settings TEXT NOT NULL DEFAULT '{}',
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        INSERT OR IGNORE INTO tenants (id, name, slug, settings, enabled, created_at, updated_at)
        VALUES ('00000000-0000-0000-0000-000000000001', 'Default', 'default', '{}', 1, datetime('now'), datetime('now'));
        "#,
    )
    .execute(pool)
    .await
    .expect("Failed to create tenants table");

    // Add tenant_id to all tables
    sqlx::query("ALTER TABLE incidents ADD COLUMN tenant_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants(id)")
        .execute(pool)
        .await
        .expect("Failed to add tenant_id to incidents");

    sqlx::query("ALTER TABLE audit_logs ADD COLUMN tenant_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants(id)")
        .execute(pool)
        .await
        .expect("Failed to add tenant_id to audit_logs");

    sqlx::query("ALTER TABLE actions ADD COLUMN tenant_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants(id)")
        .execute(pool)
        .await
        .expect("Failed to add tenant_id to actions");

    sqlx::query("ALTER TABLE playbooks ADD COLUMN tenant_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants(id)")
        .execute(pool)
        .await
        .expect("Failed to add tenant_id to playbooks");

    sqlx::query("ALTER TABLE connectors ADD COLUMN tenant_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants(id)")
        .execute(pool)
        .await
        .expect("Failed to add tenant_id to connectors");

    sqlx::query("ALTER TABLE policies ADD COLUMN tenant_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants(id)")
        .execute(pool)
        .await
        .expect("Failed to add tenant_id to policies");

    sqlx::query("ALTER TABLE notification_channels ADD COLUMN tenant_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants(id)")
        .execute(pool)
        .await
        .expect("Failed to add tenant_id to notification_channels");

    sqlx::query("ALTER TABLE settings ADD COLUMN tenant_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001'")
        .execute(pool)
        .await
        .expect("Failed to add tenant_id to settings");

    // Auth tables (users, sessions, api_keys)
    sqlx::query(include_str!(
        "../../tw-core/src/db/migrations/sqlite/20240107_000001_create_auth_tables.sql"
    ))
    .execute(pool)
    .await
    .expect("Failed to run auth tables migration");

    // Analyst feedback table
    sqlx::query(include_str!(
        "../../tw-core/src/db/migrations/sqlite/20240301_000001_create_analyst_feedback.sql"
    ))
    .execute(pool)
    .await
    .expect("Failed to run analyst feedback migration");
}

// ============================================================================
// State Creation
// ============================================================================

/// Creates default feature flags for testing.
///
/// This creates an in-memory feature flag store with no flags defined.
/// Tests that need specific flags should use `create_test_feature_flags_with`.
fn create_test_feature_flags() -> FeatureFlags {
    let store: Arc<dyn FeatureFlagStore> = Arc::new(InMemoryFeatureFlagStore::new());
    FeatureFlags::new(store)
}

/// Creates an `AppState` instance with a test database and EventBus.
///
/// This is the primary entry point for most tests. It sets up a complete
/// test environment with an isolated database and event bus.
///
/// # Returns
///
/// An `AppState` ready for use in tests.
///
/// # Example
///
/// ```ignore
/// let state = create_test_state().await;
/// let router = Router::new()
///     .nest("/api/incidents", routes::incidents::routes())
///     .with_state(state);
/// ```
pub async fn create_test_state() -> AppState {
    let pool = setup_test_db().await;
    let db = DbPool::Sqlite(pool);
    let event_bus = EventBus::new(100);
    let feature_flags = create_test_feature_flags();
    AppState::new(db, event_bus, feature_flags)
}

/// Creates an `AppState` from an existing SQLite pool.
///
/// Useful when you need direct access to the pool for database assertions
/// or when sharing a pool across multiple operations.
///
/// # Arguments
///
/// * `pool` - An existing SQLite pool with schema already created.
///
/// # Returns
///
/// An `AppState` using the provided pool.
pub fn create_test_state_from_pool(pool: SqlitePool) -> AppState {
    let db = DbPool::Sqlite(pool);
    let event_bus = EventBus::new(100);
    let feature_flags = create_test_feature_flags();
    AppState::new(db, event_bus, feature_flags)
}

/// Creates an `AppState` and returns both the state and the underlying pool.
///
/// This is useful when tests need both the state for API operations and
/// direct pool access for database assertions.
///
/// # Returns
///
/// A tuple of `(AppState, SqlitePool)`.
pub async fn create_test_state_with_pool() -> (AppState, SqlitePool) {
    let pool = setup_test_db().await;
    let db = DbPool::Sqlite(pool.clone());
    let event_bus = EventBus::new(100);
    let feature_flags = create_test_feature_flags();
    let state = AppState::new(db, event_bus, feature_flags);
    (state, pool)
}

// ============================================================================
// Test Entity Creation
// ============================================================================

/// Creates a test incident and saves it to the database.
///
/// The incident is created with:
/// - Source: EmailSecurity("M365")
/// - Alert type: "phishing"
/// - Severity: High
/// - Status: New
/// - Tags: ["phishing", "user-reported"]
///
/// # Arguments
///
/// * `state` - The AppState containing the database connection.
///
/// # Returns
///
/// The created `Incident` with its assigned ID.
///
/// # Panics
///
/// Panics if the incident cannot be created.
pub async fn create_test_incident(state: &AppState) -> Incident {
    let alert = Alert {
        id: format!("alert-{}", Uuid::new_v4()),
        source: AlertSource::EmailSecurity("M365".to_string()),
        alert_type: "phishing".to_string(),
        severity: Severity::High,
        title: "Suspected phishing email".to_string(),
        description: Some("User reported suspicious email".to_string()),
        data: serde_json::json!({
            "title": "Suspected phishing email",
            "alert_type": "phishing",
            "subject": "Urgent: Update your password",
            "sender": "attacker@malicious.com"
        }),
        timestamp: Utc::now(),
        tags: vec!["phishing".to_string(), "user-reported".to_string()],
    };

    let incident = Incident::from_alert(alert);
    let repo = create_incident_repository(&state.db);
    repo.create(&incident)
        .await
        .expect("Failed to create test incident");
    incident
}

/// Creates a test incident with custom parameters.
///
/// # Arguments
///
/// * `state` - The AppState containing the database connection.
/// * `severity` - The severity level for the incident.
/// * `alert_type` - The type of alert (e.g., "malware", "phishing").
/// * `source` - The alert source.
///
/// # Returns
///
/// The created `Incident` with its assigned ID.
pub async fn create_test_incident_with_params(
    state: &AppState,
    severity: Severity,
    alert_type: &str,
    source: AlertSource,
) -> Incident {
    let alert = Alert {
        id: format!("alert-{}", Uuid::new_v4()),
        source,
        alert_type: alert_type.to_string(),
        severity,
        title: format!("Test {} alert", alert_type),
        description: Some(format!("Test description for {}", alert_type)),
        data: serde_json::json!({
            "title": format!("Test {} alert", alert_type),
            "alert_type": alert_type,
        }),
        timestamp: Utc::now(),
        tags: vec![alert_type.to_string()],
    };

    let incident = Incident::from_alert(alert);
    let repo = create_incident_repository(&state.db);
    repo.create(&incident)
        .await
        .expect("Failed to create test incident");
    incident
}

/// Creates a test playbook and saves it to the database.
///
/// The playbook is created with:
/// - Name: Provided or "Test Playbook"
/// - Trigger type: "alert"
/// - Enabled: true
/// - No stages (empty)
///
/// # Arguments
///
/// * `state` - The AppState containing the database connection.
/// * `name` - The name for the playbook.
/// * `trigger_type` - The trigger type (e.g., "alert", "scheduled", "webhook").
///
/// # Returns
///
/// The created `Playbook` with its assigned ID.
///
/// # Panics
///
/// Panics if the playbook cannot be created.
pub async fn create_test_playbook(state: &AppState, name: &str, trigger_type: &str) -> Playbook {
    let playbook = Playbook::new(name, trigger_type);
    let repo = create_playbook_repository(&state.db);
    repo.create(DEFAULT_TENANT_ID, &playbook)
        .await
        .expect("Failed to create test playbook")
}

/// Creates a test playbook with a description.
///
/// # Arguments
///
/// * `state` - The AppState containing the database connection.
/// * `name` - The name for the playbook.
/// * `trigger_type` - The trigger type.
/// * `description` - The description for the playbook.
///
/// # Returns
///
/// The created `Playbook` with its assigned ID.
pub async fn create_test_playbook_with_description(
    state: &AppState,
    name: &str,
    trigger_type: &str,
    description: &str,
) -> Playbook {
    let playbook = Playbook::new(name, trigger_type).with_description(description);
    let repo = create_playbook_repository(&state.db);
    repo.create(DEFAULT_TENANT_ID, &playbook)
        .await
        .expect("Failed to create test playbook")
}

/// Creates a test connector and saves it to the database.
///
/// The connector is created with:
/// - Name: Provided or "Test Connector"
/// - Type: Provided (e.g., VirusTotal, Jira)
/// - Status: Unknown (default)
/// - Enabled: true
///
/// # Arguments
///
/// * `state` - The AppState containing the database connection.
/// * `name` - The name for the connector.
/// * `connector_type` - The type of connector.
/// * `config` - The configuration JSON for the connector.
///
/// # Returns
///
/// The created `ConnectorConfig` with its assigned ID.
///
/// # Panics
///
/// Panics if the connector cannot be created.
pub async fn create_test_connector(
    state: &AppState,
    name: &str,
    connector_type: ConnectorType,
    config: serde_json::Value,
) -> ConnectorConfig {
    let connector = ConnectorConfig::new(name.to_string(), connector_type, config);
    let repo = create_connector_repository(&state.db);
    repo.create(&connector)
        .await
        .expect("Failed to create test connector")
}

/// Creates a test VirusTotal connector with default configuration.
///
/// # Arguments
///
/// * `state` - The AppState containing the database connection.
/// * `name` - The name for the connector.
///
/// # Returns
///
/// The created `ConnectorConfig`.
pub async fn create_test_virustotal_connector(state: &AppState, name: &str) -> ConnectorConfig {
    create_test_connector(
        state,
        name,
        ConnectorType::VirusTotal,
        serde_json::json!({
            "api_key": "test-api-key-12345"
        }),
    )
    .await
}

/// Creates a test Jira connector with default configuration.
///
/// # Arguments
///
/// * `state` - The AppState containing the database connection.
/// * `name` - The name for the connector.
///
/// # Returns
///
/// The created `ConnectorConfig`.
pub async fn create_test_jira_connector(state: &AppState, name: &str) -> ConnectorConfig {
    create_test_connector(
        state,
        name,
        ConnectorType::Jira,
        serde_json::json!({
            "base_url": "https://example.atlassian.net",
            "api_token": "test-token-12345",
            "project_key": "SEC"
        }),
    )
    .await
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Extracts the pool from an AppState for direct database operations.
///
/// # Arguments
///
/// * `state` - The AppState to extract the pool from.
///
/// # Returns
///
/// A reference to the underlying `SqlitePool`.
///
/// # Panics
///
/// Panics if the AppState doesn't contain a SQLite pool.
pub fn get_pool_from_state(state: &AppState) -> &SqlitePool {
    match &*state.db {
        DbPool::Sqlite(pool) => pool,
        #[allow(unreachable_patterns)]
        _ => panic!("Expected SQLite pool in test state"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tw_core::incident::IncidentStatus;

    #[tokio::test]
    async fn test_setup_test_db_creates_tables() {
        let pool = setup_test_db().await;

        // Verify incidents table exists
        let result =
            sqlx::query("SELECT name FROM sqlite_master WHERE type='table' AND name='incidents'")
                .fetch_optional(&pool)
                .await
                .expect("Query failed");
        assert!(result.is_some(), "incidents table should exist");

        // Verify playbooks table exists
        let result =
            sqlx::query("SELECT name FROM sqlite_master WHERE type='table' AND name='playbooks'")
                .fetch_optional(&pool)
                .await
                .expect("Query failed");
        assert!(result.is_some(), "playbooks table should exist");

        // Verify connectors table exists
        let result =
            sqlx::query("SELECT name FROM sqlite_master WHERE type='table' AND name='connectors'")
                .fetch_optional(&pool)
                .await
                .expect("Query failed");
        assert!(result.is_some(), "connectors table should exist");
    }

    #[tokio::test]
    async fn test_create_test_state_returns_valid_state() {
        let state = create_test_state().await;

        // Verify we can use the state
        let repo = create_incident_repository(&state.db);
        let filter = tw_core::db::IncidentFilter::default();
        let pagination = tw_core::db::Pagination {
            page: 1,
            per_page: 10,
        };

        let incidents = repo
            .list(&filter, &pagination)
            .await
            .expect("Failed to list incidents");
        assert!(
            incidents.is_empty(),
            "Fresh database should have no incidents"
        );
    }

    #[tokio::test]
    async fn test_create_test_incident() {
        let state = create_test_state().await;
        let incident = create_test_incident(&state).await;

        assert_eq!(incident.status, IncidentStatus::New);
        assert_eq!(incident.severity, Severity::High);
        assert!(incident.tags.contains(&"phishing".to_string()));

        // Verify it was saved
        let repo = create_incident_repository(&state.db);
        let retrieved = repo.get(incident.id).await.expect("Query failed");
        assert!(retrieved.is_some());
    }

    #[tokio::test]
    async fn test_create_test_playbook() {
        let state = create_test_state().await;
        let playbook = create_test_playbook(&state, "Test Playbook", "alert").await;

        assert_eq!(playbook.name, "Test Playbook");
        assert_eq!(playbook.trigger_type, "alert");
        assert!(playbook.enabled);

        // Verify it was saved
        let repo = create_playbook_repository(&state.db);
        let retrieved = repo.get(playbook.id).await.expect("Query failed");
        assert!(retrieved.is_some());
    }

    #[tokio::test]
    async fn test_create_test_connector() {
        let state = create_test_state().await;
        let connector = create_test_virustotal_connector(&state, "Test VT").await;

        assert_eq!(connector.name, "Test VT");
        assert_eq!(connector.connector_type, ConnectorType::VirusTotal);
        assert!(connector.enabled);

        // Verify it was saved
        let repo = create_connector_repository(&state.db);
        let retrieved = repo.get(connector.id).await.expect("Query failed");
        assert!(retrieved.is_some());
    }

    #[tokio::test]
    async fn test_database_isolation() {
        // Create two separate states
        let state1 = create_test_state().await;
        let state2 = create_test_state().await;

        // Create an incident in state1
        let _incident = create_test_incident(&state1).await;

        // Verify state2 doesn't see the incident
        let repo = create_incident_repository(&state2.db);
        let filter = tw_core::db::IncidentFilter::default();
        let pagination = tw_core::db::Pagination {
            page: 1,
            per_page: 10,
        };

        let incidents = repo
            .list(&filter, &pagination)
            .await
            .expect("Failed to list incidents");
        assert!(
            incidents.is_empty(),
            "State2 should not see incidents from state1"
        );
    }
}
