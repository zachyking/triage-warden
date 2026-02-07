//! Authentication and authorization tests.
//!
//! These tests verify that protected endpoints properly reject
//! unauthenticated requests and enforce role-based access control.

use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
};
use tower::ServiceExt;

use super::common::{create_test_router, send_request_raw};

/// Helper to create a request without authentication.
fn unauthenticated_request(method: Method, uri: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("Content-Type", "application/json")
        .body(Body::empty())
        .unwrap()
}

/// Helper to create a POST request with body.
fn post_request(uri: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header("Content-Type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

// ============================================================
// Incidents Endpoint Auth Tests
// ============================================================

#[tokio::test]
async fn test_list_incidents_requires_auth() {
    let (app, _state) = create_test_router().await;

    let request = unauthenticated_request(Method::GET, "/api/v1/incidents");
    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_get_incident_requires_auth() {
    let (app, _state) = create_test_router().await;

    let request = unauthenticated_request(
        Method::GET,
        "/api/v1/incidents/550e8400-e29b-41d4-a716-446655440000",
    );
    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_execute_action_requires_auth() {
    let (app, _state) = create_test_router().await;

    let request = post_request(
        "/api/v1/incidents/550e8400-e29b-41d4-a716-446655440000/actions",
        r#"{"action_type":"lookup","target":{"type":"ip","value":"1.2.3.4"},"reason":"test"}"#,
    );
    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// ============================================================
// Settings Endpoint Auth Tests (Admin Only)
// ============================================================

#[tokio::test]
async fn test_get_settings_requires_auth() {
    let (app, _state) = create_test_router().await;

    let request = unauthenticated_request(Method::GET, "/api/v1/settings/general");
    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_save_settings_requires_auth() {
    let (app, _state) = create_test_router().await;

    let request = post_request(
        "/api/v1/settings/general",
        r#"{"org_name":"Test","timezone":"UTC","mode":"supervised"}"#,
    );
    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_get_rate_limits_requires_auth() {
    let (app, _state) = create_test_router().await;

    let request = unauthenticated_request(Method::GET, "/api/v1/settings/rate-limits");
    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_get_llm_settings_requires_auth() {
    let (app, _state) = create_test_router().await;

    let request = unauthenticated_request(Method::GET, "/api/v1/settings/llm");
    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// ============================================================
// Connectors Endpoint Auth Tests
// ============================================================

#[tokio::test]
async fn test_list_connectors_requires_auth() {
    let (app, _state) = create_test_router().await;

    let request = unauthenticated_request(Method::GET, "/api/v1/connectors");
    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_create_connector_requires_auth() {
    let (app, _state) = create_test_router().await;

    let request = post_request(
        "/api/v1/connectors",
        r#"{"name":"Test","connector_type":"virus_total","config":{}}"#,
    );
    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_delete_connector_requires_auth() {
    let (app, _state) = create_test_router().await;

    let request = unauthenticated_request(
        Method::DELETE,
        "/api/v1/connectors/550e8400-e29b-41d4-a716-446655440000",
    );
    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// ============================================================
// Playbooks Endpoint Auth Tests
// ============================================================

#[tokio::test]
async fn test_list_playbooks_requires_auth() {
    let (app, _state) = create_test_router().await;

    let request = unauthenticated_request(Method::GET, "/api/v1/playbooks");
    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_create_playbook_requires_auth() {
    let (app, _state) = create_test_router().await;

    let request = post_request(
        "/api/v1/playbooks",
        r#"{"name":"Test Playbook","trigger_type":"manual"}"#,
    );
    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_delete_playbook_requires_auth() {
    let (app, _state) = create_test_router().await;

    let request = unauthenticated_request(
        Method::DELETE,
        "/api/v1/playbooks/550e8400-e29b-41d4-a716-446655440000",
    );
    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// ============================================================
// Kill Switch Endpoint Auth Tests
// ============================================================

// Note: GET /kill-switch (status) is intentionally public for monitoring
// Only activation/deactivation require admin auth
#[tokio::test]
async fn test_kill_switch_status_is_public() {
    let (app, _state) = create_test_router().await;

    let request = unauthenticated_request(Method::GET, "/api/v1/kill-switch");
    let response = app.oneshot(request).await.unwrap();

    // Kill switch status is publicly accessible for health monitoring
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_activate_kill_switch_requires_auth() {
    let (app, _state) = create_test_router().await;

    let request = post_request(
        "/api/v1/kill-switch/activate",
        r#"{"reason":"test activation"}"#,
    );
    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// ============================================================
// Users Endpoint Auth Tests (Admin Only)
// ============================================================

#[tokio::test]
async fn test_list_users_requires_auth() {
    let (app, _state) = create_test_router().await;

    let request = unauthenticated_request(Method::GET, "/api/v1/admin/users");
    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_create_user_requires_auth() {
    let (app, _state) = create_test_router().await;

    let request = post_request(
        "/api/v1/admin/users",
        r#"{"email":"test@example.com","username":"testuser","password":"password123","role":"analyst"}"#,
    );
    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// ============================================================
// API Keys Endpoint Auth Tests
// ============================================================

#[tokio::test]
async fn test_list_api_keys_requires_auth() {
    let (app, _state) = create_test_router().await;

    let request = unauthenticated_request(Method::GET, "/api/v1/api-keys");
    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_create_api_key_requires_auth() {
    let (app, _state) = create_test_router().await;

    let request = post_request("/api/v1/api-keys", r#"{"name":"Test Key"}"#);
    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// ============================================================
// Policies Endpoint Tests
// ============================================================

#[tokio::test]
async fn test_list_policies_requires_auth() {
    let (app, _state) = create_test_router().await;

    let request = unauthenticated_request(Method::GET, "/api/v1/policies");
    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// ============================================================
// Notifications Endpoint Tests
// ============================================================

#[tokio::test]
async fn test_list_notification_channels_requires_auth() {
    let (app, _state) = create_test_router().await;

    let request = unauthenticated_request(Method::GET, "/api/v1/notifications");
    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// ============================================================
// Public Endpoints (No Auth Required)
// ============================================================

#[tokio::test]
async fn test_health_no_auth_required() {
    let (app, _state) = create_test_router().await;

    let request = unauthenticated_request(Method::GET, "/health");
    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_liveness_no_auth_required() {
    let (app, _state) = create_test_router().await;

    let request = unauthenticated_request(Method::GET, "/live");
    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_readiness_no_auth_required() {
    let (app, _state) = create_test_router().await;

    let request = unauthenticated_request(Method::GET, "/ready");
    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

// Note: Login page test is not included because it requires template rendering
// which is not available in the minimal test router setup. The login page
// is tested manually or in end-to-end tests.

// ============================================================
// Error Response Format Tests
// ============================================================

#[tokio::test]
async fn test_unauthorized_returns_json_error() {
    let (app, _state) = create_test_router().await;

    let request = unauthenticated_request(Method::GET, "/api/v1/incidents");
    let (status, body) = send_request_raw(app, request).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Verify it's valid JSON with error structure
    let error: serde_json::Value = serde_json::from_str(&body).expect("Response should be JSON");
    assert!(error.get("code").is_some(), "Error should have code field");
    assert!(
        error.get("message").is_some(),
        "Error should have message field"
    );
}
