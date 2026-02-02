//! Health check endpoint integration tests.

use axum::http::StatusCode;
use serde_json::Value;
use tower::ServiceExt;

use super::common::{create_test_router, get_request, send_request, send_request_raw};

/// Tests that the basic health endpoint returns healthy status.
#[tokio::test]
async fn test_health_endpoint_returns_ok() {
    let (app, _state) = create_test_router().await;

    let (status, body) = send_request_raw(app, get_request("/health")).await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("healthy") || body.contains("ok"),
        "Health endpoint should indicate healthy status"
    );
}

/// Tests that the live endpoint returns success.
#[tokio::test]
async fn test_live_endpoint_returns_ok() {
    let (app, _state) = create_test_router().await;

    let (status, _body) = send_request_raw(app, get_request("/live")).await;

    assert_eq!(status, StatusCode::OK);
}

/// Tests that the ready endpoint returns success when database is connected.
#[tokio::test]
async fn test_ready_endpoint_returns_ok() {
    let (app, _state) = create_test_router().await;

    let (status, _body) = send_request_raw(app, get_request("/ready")).await;

    assert_eq!(status, StatusCode::OK);
}

/// Tests that the detailed health endpoint returns component statuses.
#[tokio::test]
async fn test_detailed_health_returns_components() {
    let (app, _state) = create_test_router().await;

    let (status, body): (StatusCode, Value) =
        send_request(app, get_request("/health/detailed")).await;

    assert_eq!(status, StatusCode::OK);

    // Check that it has the expected structure
    assert!(body.get("status").is_some(), "Should have status field");
    assert!(
        body.get("components").is_some() || body.get("database").is_some(),
        "Should have components or database field"
    );
}

/// Tests that health check works without authentication.
#[tokio::test]
async fn test_health_endpoints_no_auth_required() {
    // All health endpoints should work without authentication
    let endpoints = ["/health", "/live", "/ready", "/health/detailed"];

    for endpoint in endpoints {
        let (app, _) = create_test_router().await;
        let (status, _) = send_request_raw(app, get_request(endpoint)).await;

        assert!(
            status == StatusCode::OK || status == StatusCode::SERVICE_UNAVAILABLE,
            "Health endpoint {} should return OK or SERVICE_UNAVAILABLE, got {:?}",
            endpoint,
            status
        );
    }
}

/// Tests that the health endpoint returns JSON content.
#[tokio::test]
async fn test_health_returns_json() {
    let (app, _state) = create_test_router().await;

    let response = ServiceExt::<axum::extract::Request<axum::body::Body>>::oneshot(
        app,
        get_request("/health"),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|h: &axum::http::HeaderValue| h.to_str().ok());

    // Health endpoint should return JSON
    let has_json = content_type
        .map(|ct: &str| ct.contains("json"))
        .unwrap_or(false);
    assert!(has_json, "Health endpoint should return JSON content type");
}

/// Tests that the detailed health shows database as healthy.
#[tokio::test]
async fn test_database_health_status() {
    let (app, _state) = create_test_router().await;

    let (status, body): (StatusCode, Value) =
        send_request(app, get_request("/health/detailed")).await;

    assert_eq!(status, StatusCode::OK);

    // Check database status if present
    if let Some(components) = body.get("components") {
        if let Some(db_status) = components.get("database") {
            // Database should be healthy/connected
            let status_str = db_status
                .get("status")
                .or_else(|| db_status.get("healthy"))
                .and_then(|s| {
                    if s.is_boolean() {
                        Some(s.as_bool().unwrap().to_string())
                    } else {
                        s.as_str().map(|s| s.to_string())
                    }
                });

            if let Some(s) = status_str {
                assert!(
                    s == "healthy" || s == "connected" || s == "true",
                    "Database should be healthy, got: {}",
                    s
                );
            }
        }
    }
}

/// Tests that kill switch status is included in detailed health.
#[tokio::test]
async fn test_kill_switch_in_health() {
    let (app, _state) = create_test_router().await;

    let (status, body): (StatusCode, Value) =
        send_request(app, get_request("/health/detailed")).await;

    assert_eq!(status, StatusCode::OK);

    // Check for kill switch status
    if let Some(components) = body.get("components") {
        if let Some(kill_switch) = components.get("kill_switch") {
            // Kill switch should show as inactive initially
            let active = kill_switch
                .get("active")
                .and_then(|a| a.as_bool())
                .unwrap_or(true);

            assert!(!active, "Kill switch should be inactive by default");
        }
    }
}
