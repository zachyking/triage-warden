//! Settings web handler tests for Triage Warden.
//!
//! This module contains tests for the settings page and related endpoints.

use super::*;
use crate::auth::test_helpers::{inject_test_user, TestUser};
use axum::{
    body::Body,
    http::{Request, StatusCode},
    middleware,
};
use tower::ServiceExt;
use tw_core::db::DbPool;
use tw_core::EventBus;

/// Sets up a test app with an in-memory SQLite database.
async fn setup_test_app() -> Router {
    let db_url = format!(
        "sqlite:file:test_settings_{}?mode=memory&cache=shared",
        uuid::Uuid::new_v4()
    );

    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&db_url)
        .await
        .expect("Failed to create pool");

    // Run migrations to set up the schema
    sqlx::query(include_str!(
        "../../../tw-core/src/db/migrations/sqlite/20240101_000001_initial_schema.sql"
    ))
    .execute(&pool)
    .await
    .expect("Failed to run initial schema");

    sqlx::query(include_str!(
        "../../../tw-core/src/db/migrations/sqlite/20240102_000001_create_playbooks.sql"
    ))
    .execute(&pool)
    .await
    .expect("Failed to run playbooks schema");

    sqlx::query(include_str!(
        "../../../tw-core/src/db/migrations/sqlite/20240103_000001_create_connectors.sql"
    ))
    .execute(&pool)
    .await
    .expect("Failed to run connectors schema");

    sqlx::query(include_str!(
        "../../../tw-core/src/db/migrations/sqlite/20240104_000001_create_policies.sql"
    ))
    .execute(&pool)
    .await
    .expect("Failed to run policies schema");

    sqlx::query(include_str!(
        "../../../tw-core/src/db/migrations/sqlite/20240105_000001_create_notification_channels.sql"
    ))
    .execute(&pool)
    .await
    .expect("Failed to run notification channels schema");

    sqlx::query(include_str!(
        "../../../tw-core/src/db/migrations/sqlite/20240106_000001_create_settings.sql"
    ))
    .execute(&pool)
    .await
    .expect("Failed to run settings schema");

    let db = DbPool::Sqlite(pool);
    let event_bus = EventBus::new(100);
    let state = AppState::new(db, event_bus);

    // Add test user middleware to bypass authentication
    create_web_router(state).layer(middleware::from_fn(move |req, next| {
        inject_test_user(TestUser::admin(), req, next)
    }))
}

/// Sets up a test app and returns both the router and state for additional DB operations.
async fn setup_test_app_with_state() -> (Router, AppState) {
    let db_url = format!(
        "sqlite:file:test_settings_state_{}?mode=memory&cache=shared",
        uuid::Uuid::new_v4()
    );

    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&db_url)
        .await
        .expect("Failed to create pool");

    // Run migrations
    sqlx::query(include_str!(
        "../../../tw-core/src/db/migrations/sqlite/20240101_000001_initial_schema.sql"
    ))
    .execute(&pool)
    .await
    .expect("Failed to run initial schema");

    sqlx::query(include_str!(
        "../../../tw-core/src/db/migrations/sqlite/20240102_000001_create_playbooks.sql"
    ))
    .execute(&pool)
    .await
    .expect("Failed to run playbooks schema");

    sqlx::query(include_str!(
        "../../../tw-core/src/db/migrations/sqlite/20240103_000001_create_connectors.sql"
    ))
    .execute(&pool)
    .await
    .expect("Failed to run connectors schema");

    sqlx::query(include_str!(
        "../../../tw-core/src/db/migrations/sqlite/20240104_000001_create_policies.sql"
    ))
    .execute(&pool)
    .await
    .expect("Failed to run policies schema");

    sqlx::query(include_str!(
        "../../../tw-core/src/db/migrations/sqlite/20240105_000001_create_notification_channels.sql"
    ))
    .execute(&pool)
    .await
    .expect("Failed to run notification channels schema");

    sqlx::query(include_str!(
        "../../../tw-core/src/db/migrations/sqlite/20240106_000001_create_settings.sql"
    ))
    .execute(&pool)
    .await
    .expect("Failed to run settings schema");

    let db = DbPool::Sqlite(pool);
    let event_bus = EventBus::new(100);
    let state = AppState::new(db, event_bus);
    // Add test user middleware to bypass authentication
    let router = create_web_router(state.clone()).layer(middleware::from_fn(move |req, next| {
        inject_test_user(TestUser::admin(), req, next)
    }));
    (router, state)
}

// ==============================================
// Settings Page Tests
// ==============================================

#[tokio::test]
async fn test_settings_returns_general_tab_by_default() {
    let app = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/settings")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();

    assert!(
        body_str.contains("Settings"),
        "Settings page should contain 'Settings' title"
    );
    assert!(
        body_str.contains("General"),
        "Settings page should contain 'General' tab"
    );
}

#[tokio::test]
async fn test_settings_connectors_tab() {
    let app = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/settings?tab=connectors")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();

    assert!(
        body_str.contains("Connectors"),
        "Settings page should contain 'Connectors' tab"
    );
    assert!(
        body_str.contains("Add Connector") || body_str.contains("add-connector"),
        "Connectors tab should contain add connector functionality"
    );
}

#[tokio::test]
async fn test_settings_policies_tab() {
    let app = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/settings?tab=policies")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();

    assert!(
        body_str.contains("Policies"),
        "Settings page should contain 'Policies' tab"
    );
    assert!(
        body_str.contains("Add Policy") || body_str.contains("add-policy"),
        "Policies tab should contain add policy functionality"
    );
}

#[tokio::test]
async fn test_settings_notifications_tab() {
    let app = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/settings?tab=notifications")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();

    assert!(
        body_str.contains("Notifications"),
        "Settings page should contain 'Notifications' tab"
    );
    assert!(
        body_str.contains("Add Notification") || body_str.contains("add-notification"),
        "Notifications tab should contain add notification functionality"
    );
}

// ==============================================
// Settings Modal Endpoints Tests
// ==============================================

#[tokio::test]
async fn test_modal_add_connector_returns_html_partial() {
    let app = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/web/modals/add-connector")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let content_type = response
        .headers()
        .get("content-type")
        .expect("Content-Type header should be present");
    assert!(
        content_type.to_str().unwrap().contains("text/html"),
        "Modal should return HTML content type"
    );
}

#[tokio::test]
async fn test_modal_add_policy_returns_html_partial() {
    let app = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/web/modals/add-policy")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let content_type = response
        .headers()
        .get("content-type")
        .expect("Content-Type header should be present");
    assert!(
        content_type.to_str().unwrap().contains("text/html"),
        "Modal should return HTML content type"
    );
}

#[tokio::test]
async fn test_modal_add_notification_returns_html_partial() {
    let app = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/web/modals/add-notification")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let content_type = response
        .headers()
        .get("content-type")
        .expect("Content-Type header should be present");
    assert!(
        content_type.to_str().unwrap().contains("text/html"),
        "Modal should return HTML content type"
    );
}

// ==============================================
// Settings Partials Endpoints Tests
// ==============================================

#[tokio::test]
async fn test_partials_connectors_returns_html() {
    let app = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/web/partials/connectors")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let content_type = response
        .headers()
        .get("content-type")
        .expect("Content-Type header should be present");
    assert!(
        content_type.to_str().unwrap().contains("text/html"),
        "Connectors partial should return HTML content type"
    );
}

#[tokio::test]
async fn test_partials_policies_returns_html() {
    let app = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/web/partials/policies")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let content_type = response
        .headers()
        .get("content-type")
        .expect("Content-Type header should be present");
    assert!(
        content_type.to_str().unwrap().contains("text/html"),
        "Policies partial should return HTML content type"
    );
}

#[tokio::test]
async fn test_partials_notifications_returns_html() {
    let app = setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/web/partials/notifications")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let content_type = response
        .headers()
        .get("content-type")
        .expect("Content-Type header should be present");
    assert!(
        content_type.to_str().unwrap().contains("text/html"),
        "Notifications partial should return HTML content type"
    );
}

// ==============================================
// Edit Modal Tests (require existing entities)
// ==============================================

#[tokio::test]
async fn test_modal_edit_connector_nonexistent_returns_empty() {
    let app = setup_test_app().await;

    let nonexistent_id = Uuid::new_v4();

    let response = app
        .oneshot(
            Request::builder()
                .uri(&format!("/web/modals/edit-connector/{}", nonexistent_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();

    assert!(
        body_str.is_empty(),
        "Edit modal for nonexistent connector should return empty response"
    );
}

#[tokio::test]
async fn test_modal_edit_policy_nonexistent_returns_empty() {
    let app = setup_test_app().await;

    let nonexistent_id = Uuid::new_v4();

    let response = app
        .oneshot(
            Request::builder()
                .uri(&format!("/web/modals/edit-policy/{}", nonexistent_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();

    assert!(
        body_str.is_empty(),
        "Edit modal for nonexistent policy should return empty response"
    );
}

#[tokio::test]
async fn test_modal_edit_notification_nonexistent_returns_empty() {
    let app = setup_test_app().await;

    let nonexistent_id = Uuid::new_v4();

    let response = app
        .oneshot(
            Request::builder()
                .uri(&format!("/web/modals/edit-notification/{}", nonexistent_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();

    assert!(
        body_str.is_empty(),
        "Edit modal for nonexistent notification should return empty response"
    );
}

// ==============================================
// Partials with Data Tests
// ==============================================

#[tokio::test]
async fn test_partials_connectors_with_data() {
    let (app, state) = setup_test_app_with_state().await;

    // Create a connector in the database using the repository
    let connector_repo = tw_core::db::create_connector_repository(&state.db);
    let connector = tw_core::connector::ConnectorConfig::new(
        "VirusTotal Connector".to_string(),
        tw_core::connector::ConnectorType::VirusTotal,
        serde_json::json!({"api_key": "test_key"}),
    );
    connector_repo
        .create(&connector)
        .await
        .expect("Failed to create test connector");

    let response = app
        .oneshot(
            Request::builder()
                .uri("/web/partials/connectors")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();

    assert!(
        body_str.contains("VirusTotal Connector"),
        "Connectors partial should contain the created connector name"
    );
}

#[tokio::test]
async fn test_partials_policies_with_data() {
    let (app, state) = setup_test_app_with_state().await;

    // Create a policy in the database using the repository
    let policy_repo = tw_core::db::create_policy_repository(&state.db);
    let policy = tw_core::policy::Policy::new(
        "Critical Alert Policy".to_string(),
        "severity == 'critical'".to_string(),
        tw_core::policy::PolicyAction::RequireApproval,
    )
    .with_approval_level(tw_core::policy::ApprovalLevel::Manager);

    policy_repo
        .create(&policy)
        .await
        .expect("Failed to create test policy");

    let response = app
        .oneshot(
            Request::builder()
                .uri("/web/partials/policies")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();

    assert!(
        body_str.contains("Critical Alert Policy"),
        "Policies partial should contain the created policy name"
    );
}

#[tokio::test]
async fn test_partials_notifications_with_data() {
    let (app, state) = setup_test_app_with_state().await;

    // Create a notification channel in the database using the repository
    let notification_repo = tw_core::db::create_notification_repository(&state.db);
    let channel = tw_core::notification::NotificationChannel::new(
        "Security Alerts Slack".to_string(),
        tw_core::notification::ChannelType::Slack,
        serde_json::json!({"webhook_url": "https://hooks.slack.com/test"}),
        vec!["critical_incident".to_string()],
    );

    notification_repo
        .create(&channel)
        .await
        .expect("Failed to create test notification channel");

    let response = app
        .oneshot(
            Request::builder()
                .uri("/web/partials/notifications")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();

    assert!(
        body_str.contains("Security Alerts Slack"),
        "Notifications partial should contain the created channel name"
    );
}

#[tokio::test]
async fn test_modal_edit_connector_with_existing_entity() {
    let (app, state) = setup_test_app_with_state().await;

    // Create a connector in the database
    let connector_repo = tw_core::db::create_connector_repository(&state.db);
    let connector = tw_core::connector::ConnectorConfig::new(
        "Test Connector".to_string(),
        tw_core::connector::ConnectorType::VirusTotal,
        serde_json::json!({"api_key": "test_key"}),
    );
    let created = connector_repo
        .create(&connector)
        .await
        .expect("Failed to create test connector");

    let response = app
        .oneshot(
            Request::builder()
                .uri(&format!("/web/modals/edit-connector/{}", created.id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();

    assert!(
        body_str.contains("Test Connector")
            || body_str.contains("modal")
            || body_str.contains("form"),
        "Edit connector modal should contain the connector name or modal/form elements"
    );
}

#[tokio::test]
async fn test_modal_edit_policy_with_existing_entity() {
    let (app, state) = setup_test_app_with_state().await;

    // Create a policy in the database
    let policy_repo = tw_core::db::create_policy_repository(&state.db);
    let policy = tw_core::policy::Policy::new(
        "Test Policy".to_string(),
        "severity == 'critical'".to_string(),
        tw_core::policy::PolicyAction::RequireApproval,
    );
    let created = policy_repo
        .create(&policy)
        .await
        .expect("Failed to create test policy");

    let response = app
        .oneshot(
            Request::builder()
                .uri(&format!("/web/modals/edit-policy/{}", created.id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();

    assert!(
        body_str.contains("Test Policy") || body_str.contains("modal") || body_str.contains("form"),
        "Edit policy modal should contain the policy name or modal/form elements"
    );
}

#[tokio::test]
async fn test_modal_edit_notification_with_existing_entity() {
    let (app, state) = setup_test_app_with_state().await;

    // Create a notification channel in the database
    let notification_repo = tw_core::db::create_notification_repository(&state.db);
    let channel = tw_core::notification::NotificationChannel::new(
        "Test Channel".to_string(),
        tw_core::notification::ChannelType::Slack,
        serde_json::json!({"webhook_url": "https://example.com/webhook"}),
        vec!["critical_incident".to_string()],
    );
    let created = notification_repo
        .create(&channel)
        .await
        .expect("Failed to create test notification channel");

    let response = app
        .oneshot(
            Request::builder()
                .uri(&format!("/web/modals/edit-notification/{}", created.id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();

    assert!(
        body_str.contains("Test Channel")
            || body_str.contains("modal")
            || body_str.contains("form"),
        "Edit notification modal should contain the channel name or modal/form elements"
    );
}
