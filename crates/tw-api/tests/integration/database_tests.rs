//! Database integration tests using testcontainers.
//!
//! These tests run against a real PostgreSQL database in Docker.
//! They verify that database operations work correctly with the actual
//! PostgreSQL database instead of SQLite in-memory.

use super::testcontainers_support::{create_postgres_pool, start_postgres};
use serial_test::serial;
use sqlx::Row;
use uuid::Uuid;

/// Test that incidents can be created and retrieved from PostgreSQL.
#[tokio::test]
#[serial]
#[ignore = "requires Docker"]
async fn test_incident_crud_postgres() {
    let pg = start_postgres().await;
    let pool = create_postgres_pool(&pg).await;

    // Create a tenant first (required for foreign key constraint)
    let tenant_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO tenants (id, name, slug, status, created_at, updated_at)
        VALUES ($1, 'Test Tenant', 'test-tenant', 'active', NOW(), NOW())
        "#,
    )
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("Failed to create tenant");

    // Create an incident
    let incident_id = Uuid::new_v4();
    let alert_json = serde_json::json!({
        "type": "email_security",
        "subject": "Test Alert",
        "sender": "test@example.com"
    });

    sqlx::query(
        r#"
        INSERT INTO incidents (id, tenant_id, alert_type, alert_data, status, created_at, updated_at)
        VALUES ($1, $2, 'email_security', $3, 'pending', NOW(), NOW())
        "#,
    )
    .bind(incident_id)
    .bind(tenant_id)
    .bind(&alert_json)
    .execute(&pool)
    .await
    .expect("Failed to create incident");

    // Retrieve the incident
    let row = sqlx::query("SELECT id, alert_type, status FROM incidents WHERE id = $1")
        .bind(incident_id)
        .fetch_one(&pool)
        .await
        .expect("Failed to fetch incident");

    assert_eq!(row.get::<Uuid, _>("id"), incident_id);
    assert_eq!(row.get::<String, _>("alert_type"), "email_security");
    assert_eq!(row.get::<String, _>("status"), "pending");
}

/// Test that playbooks can be stored and retrieved from PostgreSQL.
#[tokio::test]
#[serial]
#[ignore = "requires Docker"]
async fn test_playbook_crud_postgres() {
    let pg = start_postgres().await;
    let pool = create_postgres_pool(&pg).await;

    // Create a tenant
    let tenant_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO tenants (id, name, slug, status, created_at, updated_at)
        VALUES ($1, 'Test Tenant', 'test-tenant-pb', 'active', NOW(), NOW())
        "#,
    )
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("Failed to create tenant");

    // Create a playbook
    let playbook_id = Uuid::new_v4();
    let playbook_yaml = r#"
name: Test Playbook
description: A test playbook for integration testing
alert_types:
  - email_security
steps:
  - name: Check sender reputation
    tool: lookup_domain
    "#;

    sqlx::query(
        r#"
        INSERT INTO playbooks (id, tenant_id, name, description, alert_types, playbook_yaml, enabled, created_at, updated_at)
        VALUES ($1, $2, 'Test Playbook', 'A test playbook', ARRAY['email_security']::text[], $3, true, NOW(), NOW())
        "#,
    )
    .bind(playbook_id)
    .bind(tenant_id)
    .bind(playbook_yaml)
    .execute(&pool)
    .await
    .expect("Failed to create playbook");

    // Retrieve the playbook
    let row = sqlx::query("SELECT id, name, enabled FROM playbooks WHERE id = $1")
        .bind(playbook_id)
        .fetch_one(&pool)
        .await
        .expect("Failed to fetch playbook");

    assert_eq!(row.get::<Uuid, _>("id"), playbook_id);
    assert_eq!(row.get::<String, _>("name"), "Test Playbook");
    assert!(row.get::<bool, _>("enabled"));
}

/// Test multi-tenancy isolation in PostgreSQL.
#[tokio::test]
#[serial]
#[ignore = "requires Docker"]
async fn test_multi_tenancy_isolation_postgres() {
    let pg = start_postgres().await;
    let pool = create_postgres_pool(&pg).await;

    // Create two tenants
    let tenant_a = Uuid::new_v4();
    let tenant_b = Uuid::new_v4();

    for (id, slug) in [(tenant_a, "tenant-a"), (tenant_b, "tenant-b")] {
        sqlx::query(
            r#"
            INSERT INTO tenants (id, name, slug, status, created_at, updated_at)
            VALUES ($1, $2, $3, 'active', NOW(), NOW())
            "#,
        )
        .bind(id)
        .bind(format!("Tenant {}", slug))
        .bind(slug)
        .execute(&pool)
        .await
        .expect("Failed to create tenant");
    }

    // Create incidents for each tenant
    let incident_a = Uuid::new_v4();
    let incident_b = Uuid::new_v4();

    sqlx::query(
        r#"
        INSERT INTO incidents (id, tenant_id, alert_type, alert_data, status, created_at, updated_at)
        VALUES ($1, $2, 'edr_detection', '{}', 'pending', NOW(), NOW())
        "#,
    )
    .bind(incident_a)
    .bind(tenant_a)
    .execute(&pool)
    .await
    .expect("Failed to create incident A");

    sqlx::query(
        r#"
        INSERT INTO incidents (id, tenant_id, alert_type, alert_data, status, created_at, updated_at)
        VALUES ($1, $2, 'authentication', '{}', 'pending', NOW(), NOW())
        "#,
    )
    .bind(incident_b)
    .bind(tenant_b)
    .execute(&pool)
    .await
    .expect("Failed to create incident B");

    // Verify tenant A can only see their incidents
    let count_a: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM incidents WHERE tenant_id = $1")
        .bind(tenant_a)
        .fetch_one(&pool)
        .await
        .expect("Failed to count incidents for tenant A");
    assert_eq!(count_a.0, 1);

    // Verify tenant B can only see their incidents
    let count_b: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM incidents WHERE tenant_id = $1")
        .bind(tenant_b)
        .fetch_one(&pool)
        .await
        .expect("Failed to count incidents for tenant B");
    assert_eq!(count_b.0, 1);

    // Verify total incidents
    let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM incidents")
        .fetch_one(&pool)
        .await
        .expect("Failed to count total incidents");
    assert_eq!(total.0, 2);
}

/// Test connector configuration storage in PostgreSQL.
#[tokio::test]
#[serial]
#[ignore = "requires Docker"]
async fn test_connector_config_postgres() {
    let pg = start_postgres().await;
    let pool = create_postgres_pool(&pg).await;

    // Create a tenant
    let tenant_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO tenants (id, name, slug, status, created_at, updated_at)
        VALUES ($1, 'Test Tenant', 'test-tenant-conn', 'active', NOW(), NOW())
        "#,
    )
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("Failed to create tenant");

    // Create a connector configuration
    let connector_id = Uuid::new_v4();
    let config_json = serde_json::json!({
        "api_url": "https://api.example.com",
        "timeout_seconds": 30
    });

    sqlx::query(
        r#"
        INSERT INTO connectors (id, tenant_id, connector_type, name, config, enabled, created_at, updated_at)
        VALUES ($1, $2, 'threat_intel', 'VirusTotal', $3, true, NOW(), NOW())
        "#,
    )
    .bind(connector_id)
    .bind(tenant_id)
    .bind(&config_json)
    .execute(&pool)
    .await
    .expect("Failed to create connector");

    // Retrieve and verify
    let row = sqlx::query("SELECT connector_type, name, enabled FROM connectors WHERE id = $1")
        .bind(connector_id)
        .fetch_one(&pool)
        .await
        .expect("Failed to fetch connector");

    assert_eq!(row.get::<String, _>("connector_type"), "threat_intel");
    assert_eq!(row.get::<String, _>("name"), "VirusTotal");
    assert!(row.get::<bool, _>("enabled"));
}

/// Test that feedback can be stored and aggregated in PostgreSQL.
#[tokio::test]
#[serial]
#[ignore = "requires Docker"]
async fn test_feedback_aggregation_postgres() {
    let pg = start_postgres().await;
    let pool = create_postgres_pool(&pg).await;

    // Create tenant and incident first
    let tenant_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO tenants (id, name, slug, status, created_at, updated_at)
        VALUES ($1, 'Test Tenant', 'test-tenant-fb', 'active', NOW(), NOW())
        "#,
    )
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("Failed to create tenant");

    // Check if analyst_feedback table exists (may be created by separate migration)
    let table_exists: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS (
            SELECT FROM information_schema.tables
            WHERE table_name = 'analyst_feedback'
        )
        "#,
    )
    .fetch_one(&pool)
    .await
    .unwrap_or(false);

    if !table_exists {
        // Skip test if feedback table doesn't exist yet
        println!("Skipping feedback test - analyst_feedback table not found");
        return;
    }

    // Create incident
    let incident_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO incidents (id, tenant_id, alert_type, alert_data, status, created_at, updated_at)
        VALUES ($1, $2, 'email_security', '{}', 'completed', NOW(), NOW())
        "#,
    )
    .bind(incident_id)
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("Failed to create incident");

    // Insert feedback
    sqlx::query(
        r#"
        INSERT INTO analyst_feedback (id, incident_id, analyst_id, verdict_correct, confidence_appropriate, notes, created_at)
        VALUES ($1, $2, 'analyst-1', true, true, 'Good analysis', NOW())
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(incident_id)
    .execute(&pool)
    .await
    .expect("Failed to create feedback");

    // Query feedback count
    let count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM analyst_feedback WHERE incident_id = $1")
            .bind(incident_id)
            .fetch_one(&pool)
            .await
            .expect("Failed to count feedback");

    assert_eq!(count.0, 1);
}
