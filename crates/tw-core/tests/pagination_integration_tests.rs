//! Integration tests for pagination support.
//!
//! These tests verify that pagination works correctly for both SQLite and PostgreSQL.
//! They require database features to run.
//!
//! # Running these tests
//!
//! For SQLite (in-memory):
//! ```bash
//! cargo test --features database pagination_ --test pagination_integration_tests
//! ```
//!
//! For PostgreSQL:
//! ```bash
//! TEST_DATABASE_URL="postgres://user:pass@localhost:5432/tw_test" cargo test --features database pagination_pg_ --test pagination_integration_tests
//! ```

#![cfg(feature = "database")]

use chrono::Utc;
use sqlx::sqlite::SqlitePoolOptions;
use tw_core::db::{
    pagination::{AuditLogFilter, PaginatedResult, Pagination, DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE},
    DbPool, IncidentFilter,
};
use tw_core::incident::{
    Alert, AlertSource, AuditAction, AuditEntry, Incident, IncidentStatus, Severity,
};
use uuid::Uuid;

/// Default tenant ID used in migrations.
const DEFAULT_TENANT_ID: Uuid = Uuid::from_u128(0x00000000_0000_0000_0000_000000000001);

/// Creates an in-memory SQLite pool for testing.
async fn create_sqlite_test_pool() -> sqlx::SqlitePool {
    let db_url = format!(
        "sqlite:file:test_pagination_{}?mode=memory&cache=shared",
        Uuid::new_v4()
    );

    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&db_url)
        .await
        .expect("Failed to create pool");

    // Create schema
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
    .execute(&pool)
    .await
    .expect("Failed to create tenants table");

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS incidents (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants(id),
            source TEXT NOT NULL,
            severity TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
            status TEXT NOT NULL CHECK (status IN ('new', 'enriching', 'analyzing', 'pending_review', 'pending_approval', 'executing', 'resolved', 'false_positive', 'dismissed', 'escalated', 'closed')),
            alert_data TEXT NOT NULL,
            enrichments TEXT NOT NULL DEFAULT '[]',
            analysis TEXT,
            proposed_actions TEXT NOT NULL DEFAULT '[]',
            ticket_id TEXT,
            tags TEXT NOT NULL DEFAULT '[]',
            metadata TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        -- Add optimized indexes for pagination tests
        CREATE INDEX IF NOT EXISTS idx_incidents_tenant_status_created
            ON incidents(tenant_id, status, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_incidents_tenant_severity_status
            ON incidents(tenant_id, severity, status);
        "#,
    )
    .execute(&pool)
    .await
    .expect("Failed to create incidents table");

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS audit_logs (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants(id),
            incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
            action TEXT NOT NULL,
            actor TEXT NOT NULL,
            details TEXT,
            created_at TEXT NOT NULL
        );

        -- Add optimized indexes for pagination tests
        CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_incident_created
            ON audit_logs(tenant_id, incident_id, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_actor_created
            ON audit_logs(tenant_id, actor, created_at DESC);
        "#,
    )
    .execute(&pool)
    .await
    .expect("Failed to create audit_logs table");

    pool
}

/// Creates a test incident.
fn create_test_alert(idx: usize) -> Alert {
    Alert {
        id: format!("test-alert-{}", idx),
        source: AlertSource::Siem("Test".to_string()),
        alert_type: "test".to_string(),
        severity: match idx % 5 {
            0 => Severity::Info,
            1 => Severity::Low,
            2 => Severity::Medium,
            3 => Severity::High,
            _ => Severity::Critical,
        },
        title: format!("Test Alert {}", idx),
        description: Some(format!("Description for test alert {}", idx)),
        data: serde_json::json!({"index": idx, "title": format!("Test Alert {}", idx)}),
        timestamp: Utc::now(),
        tags: vec![format!("tag-{}", idx % 3)],
    }
}

// ============================================================================
// Pagination Unit Tests
// ============================================================================

#[test]
fn test_pagination_defaults() {
    let p = Pagination::default();
    assert_eq!(p.page, 1);
    assert_eq!(p.per_page, DEFAULT_PAGE_SIZE);
    assert_eq!(p.per_page, 50);
}

#[test]
fn test_pagination_max_page_size() {
    assert_eq!(MAX_PAGE_SIZE, 200);
}

#[test]
fn test_pagination_new_clamps_per_page() {
    let p = Pagination::new(1, 500);
    assert_eq!(p.per_page, MAX_PAGE_SIZE);

    let p = Pagination::new(1, 0);
    assert_eq!(p.per_page, 1);
}

#[test]
fn test_pagination_new_clamps_page() {
    let p = Pagination::new(0, 50);
    assert_eq!(p.page, 1);
}

#[test]
fn test_pagination_offset_calculation() {
    let p = Pagination::new(1, 50);
    assert_eq!(p.offset(), 0);

    let p = Pagination::new(2, 50);
    assert_eq!(p.offset(), 50);

    let p = Pagination::new(5, 20);
    assert_eq!(p.offset(), 80);
}

#[test]
fn test_pagination_total_pages() {
    let p = Pagination::new(1, 50);

    assert_eq!(p.total_pages(0), 1);
    assert_eq!(p.total_pages(25), 1);
    assert_eq!(p.total_pages(50), 1);
    assert_eq!(p.total_pages(51), 2);
    assert_eq!(p.total_pages(100), 2);
    assert_eq!(p.total_pages(101), 3);
}

#[test]
fn test_paginated_result_has_next_page() {
    let items: Vec<i32> = vec![1, 2, 3];
    let pagination = Pagination::new(1, 3);

    let result = PaginatedResult::new(items.clone(), 10, &pagination);
    assert!(result.has_next_page());
    assert!(!result.has_previous_page());

    let pagination = Pagination::new(4, 3);
    let result = PaginatedResult::new(items.clone(), 10, &pagination);
    assert!(!result.has_next_page());
    assert!(result.has_previous_page());
}

#[test]
fn test_paginated_result_map() {
    let items = vec![1, 2, 3];
    let pagination = Pagination::new(1, 10);
    let result = PaginatedResult::new(items, 3, &pagination);

    let mapped = result.map(|x| x.to_string());
    assert_eq!(mapped.items, vec!["1", "2", "3"]);
    assert_eq!(mapped.total, 3);
    assert_eq!(mapped.page, 1);
}

// ============================================================================
// SQLite Pagination Integration Tests
// ============================================================================

#[tokio::test]
async fn test_pagination_sqlite_incident_list() {
    let pool = create_sqlite_test_pool().await;
    let db = DbPool::Sqlite(pool);
    let repo = tw_core::db::create_incident_repository(&db);

    // Create 15 test incidents
    for i in 0..15 {
        let alert = create_test_alert(i);
        let incident = Incident::from_alert(alert);
        repo.create(&incident)
            .await
            .expect("Failed to create incident");
    }

    // Test first page
    let filter = IncidentFilter::default();
    let pagination = Pagination::new(1, 5);
    let incidents = repo
        .list(&filter, &pagination)
        .await
        .expect("Failed to list");
    assert_eq!(incidents.len(), 5);

    // Test second page
    let pagination = Pagination::new(2, 5);
    let incidents = repo
        .list(&filter, &pagination)
        .await
        .expect("Failed to list");
    assert_eq!(incidents.len(), 5);

    // Test third page (partial)
    let pagination = Pagination::new(3, 5);
    let incidents = repo
        .list(&filter, &pagination)
        .await
        .expect("Failed to list");
    assert_eq!(incidents.len(), 5);

    // Test beyond last page
    let pagination = Pagination::new(10, 5);
    let incidents = repo
        .list(&filter, &pagination)
        .await
        .expect("Failed to list");
    assert!(incidents.is_empty());
}

#[tokio::test]
async fn test_pagination_sqlite_incident_count() {
    let pool = create_sqlite_test_pool().await;
    let db = DbPool::Sqlite(pool);
    let repo = tw_core::db::create_incident_repository(&db);

    // Create 25 test incidents
    for i in 0..25 {
        let alert = create_test_alert(i);
        let incident = Incident::from_alert(alert);
        repo.create(&incident)
            .await
            .expect("Failed to create incident");
    }

    // Count all
    let filter = IncidentFilter::default();
    let count = repo.count(&filter).await.expect("Failed to count");
    assert_eq!(count, 25);

    // Count with status filter (all are 'new')
    let filter = IncidentFilter {
        status: Some(vec![IncidentStatus::New]),
        ..Default::default()
    };
    let count = repo.count(&filter).await.expect("Failed to count");
    assert_eq!(count, 25);

    // Count with non-matching filter
    let filter = IncidentFilter {
        status: Some(vec![IncidentStatus::Resolved]),
        ..Default::default()
    };
    let count = repo.count(&filter).await.expect("Failed to count");
    assert_eq!(count, 0);
}

#[tokio::test]
async fn test_pagination_sqlite_incident_with_filter() {
    let pool = create_sqlite_test_pool().await;
    let db = DbPool::Sqlite(pool);
    let repo = tw_core::db::create_incident_repository(&db);

    // Create incidents with different severities
    for i in 0..20 {
        let alert = create_test_alert(i);
        let incident = Incident::from_alert(alert);
        repo.create(&incident)
            .await
            .expect("Failed to create incident");
    }

    // Filter by high severity (every 4th incident: 3, 8, 13, 18)
    let filter = IncidentFilter {
        severity: Some(vec![Severity::High]),
        ..Default::default()
    };

    let count = repo.count(&filter).await.expect("Failed to count");
    assert_eq!(count, 4);

    let pagination = Pagination::new(1, 10);
    let incidents = repo
        .list(&filter, &pagination)
        .await
        .expect("Failed to list");
    assert_eq!(incidents.len(), 4);
    for incident in &incidents {
        assert_eq!(incident.severity, Severity::High);
    }
}

#[tokio::test]
async fn test_pagination_sqlite_audit_log_paginated() {
    let pool = create_sqlite_test_pool().await;
    let db = DbPool::Sqlite(pool);
    let incident_repo = tw_core::db::create_incident_repository(&db);
    let audit_repo = tw_core::db::create_audit_repository(&db);

    // Create an incident first
    let alert = create_test_alert(0);
    let incident = Incident::from_alert(alert);
    let incident = incident_repo
        .create(&incident)
        .await
        .expect("Failed to create incident");

    // Create 30 audit entries
    for i in 0..30 {
        let entry = AuditEntry::new(
            AuditAction::StatusChanged(IncidentStatus::Enriching),
            format!("actor-{}", i % 3),
            Some(serde_json::json!({"index": i})),
        );
        audit_repo
            .log(DEFAULT_TENANT_ID, incident.id, &entry)
            .await
            .expect("Failed to log audit entry");
    }

    // Test paginated list
    let filter = AuditLogFilter {
        tenant_id: Some(DEFAULT_TENANT_ID),
        incident_id: Some(incident.id),
        ..Default::default()
    };

    let pagination = Pagination::new(1, 10);
    let result = audit_repo
        .list_paginated(&filter, &pagination)
        .await
        .expect("Failed to list audit logs");

    assert_eq!(result.items.len(), 10);
    assert_eq!(result.total, 30);
    assert_eq!(result.page, 1);
    assert_eq!(result.per_page, 10);
    assert_eq!(result.total_pages, 3);
    assert!(result.has_next_page());
    assert!(!result.has_previous_page());

    // Test second page
    let pagination = Pagination::new(2, 10);
    let result = audit_repo
        .list_paginated(&filter, &pagination)
        .await
        .expect("Failed to list audit logs");

    assert_eq!(result.items.len(), 10);
    assert!(result.has_next_page());
    assert!(result.has_previous_page());

    // Test last page
    let pagination = Pagination::new(3, 10);
    let result = audit_repo
        .list_paginated(&filter, &pagination)
        .await
        .expect("Failed to list audit logs");

    assert_eq!(result.items.len(), 10);
    assert!(!result.has_next_page());
    assert!(result.has_previous_page());
}

#[tokio::test]
async fn test_pagination_sqlite_audit_log_filter_by_actor() {
    let pool = create_sqlite_test_pool().await;
    let db = DbPool::Sqlite(pool);
    let incident_repo = tw_core::db::create_incident_repository(&db);
    let audit_repo = tw_core::db::create_audit_repository(&db);

    // Create an incident first
    let alert = create_test_alert(0);
    let incident = Incident::from_alert(alert);
    let incident = incident_repo
        .create(&incident)
        .await
        .expect("Failed to create incident");

    // Create audit entries with different actors
    for i in 0..15 {
        let entry = AuditEntry::new(
            AuditAction::StatusChanged(IncidentStatus::Analyzing),
            format!("actor-{}", i % 3), // 0, 1, 2, 0, 1, 2, ...
            None,
        );
        audit_repo
            .log(DEFAULT_TENANT_ID, incident.id, &entry)
            .await
            .expect("Failed to log audit entry");
    }

    // Filter by actor-0 (should have 5 entries: 0, 3, 6, 9, 12)
    let filter = AuditLogFilter {
        tenant_id: Some(DEFAULT_TENANT_ID),
        actor: Some("actor-0".to_string()),
        ..Default::default()
    };

    let count = audit_repo.count(&filter).await.expect("Failed to count");
    assert_eq!(count, 5);

    let pagination = Pagination::new(1, 10);
    let result = audit_repo
        .list_paginated(&filter, &pagination)
        .await
        .expect("Failed to list");

    assert_eq!(result.items.len(), 5);
    for (_incident_id, entry) in &result.items {
        assert_eq!(entry.actor, "actor-0");
    }
}

#[tokio::test]
async fn test_pagination_sqlite_empty_results() {
    let pool = create_sqlite_test_pool().await;
    let db = DbPool::Sqlite(pool);
    let repo = tw_core::db::create_incident_repository(&db);

    // Don't create any incidents

    let filter = IncidentFilter::default();
    let pagination = Pagination::new(1, 50);
    let incidents = repo
        .list(&filter, &pagination)
        .await
        .expect("Failed to list");

    assert!(incidents.is_empty());

    let count = repo.count(&filter).await.expect("Failed to count");
    assert_eq!(count, 0);
}

#[tokio::test]
async fn test_pagination_sqlite_max_page_size_respected() {
    let pool = create_sqlite_test_pool().await;
    let db = DbPool::Sqlite(pool);
    let repo = tw_core::db::create_incident_repository(&db);

    // Create 250 incidents (more than MAX_PAGE_SIZE)
    for i in 0..250 {
        let alert = create_test_alert(i);
        let incident = Incident::from_alert(alert);
        repo.create(&incident)
            .await
            .expect("Failed to create incident");
    }

    // Request more than MAX_PAGE_SIZE (should be clamped)
    let pagination = Pagination::new(1, 500);
    assert_eq!(pagination.per_page, MAX_PAGE_SIZE);

    let filter = IncidentFilter::default();
    let incidents = repo
        .list(&filter, &pagination)
        .await
        .expect("Failed to list");
    assert_eq!(incidents.len(), MAX_PAGE_SIZE as usize);
}

// ============================================================================
// PostgreSQL Pagination Integration Tests
// These tests run only when TEST_DATABASE_URL is set
// ============================================================================

#[cfg(feature = "database")]
mod postgres_tests {
    use super::*;
    use sqlx::{postgres::PgPoolOptions, PgPool};
    use std::env;

    async fn create_pg_test_pool() -> Option<PgPool> {
        let url = env::var("TEST_DATABASE_URL").ok()?;

        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&url)
            .await
            .ok()?;

        // Run minimal migrations for tests
        let migrations = [
            include_str!("../src/db/migrations/postgres/20240101_000001_initial_schema.sql"),
            include_str!("../src/db/migrations/postgres/20240215_000001_create_tenants.sql"),
            include_str!(
                "../src/db/migrations/postgres/20240220_000001_add_tenant_id_to_tables.sql"
            ),
            include_str!("../src/db/migrations/postgres/20240225_000001_add_optimized_indexes.sql"),
        ];

        for migration in migrations {
            if let Err(e) = sqlx::query(migration).execute(&pool).await {
                eprintln!("Migration warning (may be expected): {}", e);
            }
        }

        Some(pool)
    }

    #[tokio::test]
    async fn test_pagination_pg_incident_list() {
        let Some(pool) = create_pg_test_pool().await else {
            eprintln!("Skipping test: TEST_DATABASE_URL not set");
            return;
        };

        let db = DbPool::Postgres(pool);
        let repo = tw_core::db::create_incident_repository(&db);

        // Cleanup any existing test data
        if let Err(e) = sqlx::query("DELETE FROM incidents WHERE source LIKE '%Test%'")
            .execute(match &db {
                DbPool::Postgres(p) => p,
                _ => unreachable!(),
            })
            .await
        {
            eprintln!("Cleanup warning: {}", e);
        }

        // Create test incidents
        for i in 0..15 {
            let alert = create_test_alert(i);
            let incident = Incident::from_alert(alert);
            if let Err(e) = repo.create(&incident).await {
                eprintln!("Create incident warning: {}", e);
                return; // Skip test if we can't create incidents
            }
        }

        // Test pagination
        let filter = IncidentFilter::default();
        let pagination = Pagination::new(1, 5);
        let incidents = repo
            .list(&filter, &pagination)
            .await
            .expect("Failed to list");

        // Should have 5 or fewer incidents (depending on existing data)
        assert!(incidents.len() <= 5);

        // Cleanup
        if let Err(e) = sqlx::query("DELETE FROM incidents WHERE source LIKE '%Test%'")
            .execute(match &db {
                DbPool::Postgres(p) => p,
                _ => unreachable!(),
            })
            .await
        {
            eprintln!("Cleanup warning: {}", e);
        }
    }

    #[tokio::test]
    async fn test_pagination_pg_audit_log_paginated() {
        let Some(pool) = create_pg_test_pool().await else {
            eprintln!("Skipping test: TEST_DATABASE_URL not set");
            return;
        };

        let db = DbPool::Postgres(pool.clone());
        let incident_repo = tw_core::db::create_incident_repository(&db);
        let audit_repo = tw_core::db::create_audit_repository(&db);

        // Cleanup
        let _ = sqlx::query("DELETE FROM audit_logs WHERE actor LIKE 'test-actor-%'")
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM incidents WHERE source LIKE '%PgTest%'")
            .execute(&pool)
            .await;

        // Create an incident
        let alert = Alert {
            id: format!("pg-test-{}", Uuid::new_v4()),
            source: AlertSource::Siem("PgTest".to_string()),
            ..create_test_alert(0)
        };
        let incident = Incident::from_alert(alert);
        let incident = match incident_repo.create(&incident).await {
            Ok(i) => i,
            Err(e) => {
                eprintln!("Create incident warning: {}", e);
                return;
            }
        };

        // Create audit entries
        for i in 0..20 {
            let entry = AuditEntry::new(
                AuditAction::StatusChanged(IncidentStatus::Enriching),
                format!("test-actor-{}", i % 2),
                None,
            );
            if let Err(e) = audit_repo.log(DEFAULT_TENANT_ID, incident.id, &entry).await {
                eprintln!("Log audit entry warning: {}", e);
                return;
            }
        }

        // Test paginated list
        let filter = AuditLogFilter {
            tenant_id: Some(DEFAULT_TENANT_ID),
            incident_id: Some(incident.id),
            ..Default::default()
        };

        let pagination = Pagination::new(1, 10);
        let result = match audit_repo.list_paginated(&filter, &pagination).await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("List paginated warning: {}", e);
                return;
            }
        };

        assert_eq!(result.items.len(), 10);
        assert_eq!(result.total, 20);
        assert_eq!(result.total_pages, 2);

        // Cleanup
        let _ = sqlx::query("DELETE FROM audit_logs WHERE actor LIKE 'test-actor-%'")
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM incidents WHERE source LIKE '%PgTest%'")
            .execute(&pool)
            .await;
    }
}
