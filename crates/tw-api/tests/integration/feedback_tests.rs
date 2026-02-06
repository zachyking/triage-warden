//! Feedback API endpoint integration tests.
//!
//! These tests verify the feedback endpoints enforce authentication,
//! return correct status codes, and follow the API contract.

use axum::http::{Method, StatusCode};
use tower::ServiceExt;

use super::common::{
    create_test_router, delete_request, get_request, post_json_request, put_json_request,
    send_request_raw,
};

// ============================================================================
// Authentication Enforcement Tests
// ============================================================================

/// Feedback listing requires authentication.
#[tokio::test]
async fn test_list_feedback_requires_auth() {
    let (app, _state) = create_test_router().await;

    let request = get_request("/api/v1/feedback");
    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// Getting a specific feedback entry requires authentication.
#[tokio::test]
async fn test_get_feedback_requires_auth() {
    let (app, _state) = create_test_router().await;

    let request = get_request("/api/v1/feedback/550e8400-e29b-41d4-a716-446655440000");
    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// Updating feedback requires authentication.
#[tokio::test]
async fn test_update_feedback_requires_auth() {
    let (app, _state) = create_test_router().await;

    let request = put_json_request(
        "/api/v1/feedback/550e8400-e29b-41d4-a716-446655440000",
        r#"{"notes": "updated"}"#,
    );
    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// Deleting feedback requires authentication.
#[tokio::test]
async fn test_delete_feedback_requires_auth() {
    let (app, _state) = create_test_router().await;

    let request = delete_request("/api/v1/feedback/550e8400-e29b-41d4-a716-446655440000");
    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// Creating feedback for an incident requires authentication.
#[tokio::test]
async fn test_create_feedback_for_incident_requires_auth() {
    let (app, _state) = create_test_router().await;

    let request = post_json_request(
        "/api/v1/incidents/550e8400-e29b-41d4-a716-446655440000/feedback",
        r#"{"feedback_type": "correct"}"#,
    );
    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// Getting feedback for an incident requires authentication.
#[tokio::test]
async fn test_get_feedback_for_incident_requires_auth() {
    let (app, _state) = create_test_router().await;

    let request = get_request("/api/v1/incidents/550e8400-e29b-41d4-a716-446655440000/feedback");
    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// ============================================================================
// Analytics Endpoints Auth Tests
// ============================================================================

/// Feedback stats require authentication.
#[tokio::test]
async fn test_feedback_stats_requires_auth() {
    let (app, _state) = create_test_router().await;

    let request = get_request("/api/v1/feedback/stats");
    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// Accuracy by verdict requires authentication.
#[tokio::test]
async fn test_accuracy_by_verdict_requires_auth() {
    let (app, _state) = create_test_router().await;

    let request = get_request("/api/v1/feedback/accuracy/by-verdict");
    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// Accuracy by type requires authentication.
#[tokio::test]
async fn test_accuracy_by_type_requires_auth() {
    let (app, _state) = create_test_router().await;

    let request = get_request("/api/v1/feedback/accuracy/by-type");
    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// Accuracy trends require authentication.
#[tokio::test]
async fn test_accuracy_trends_requires_auth() {
    let (app, _state) = create_test_router().await;

    let request = get_request("/api/v1/feedback/trends");
    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// ============================================================================
// Error Response Format Tests
// ============================================================================

/// Unauthenticated feedback requests return JSON error.
#[tokio::test]
async fn test_feedback_unauthorized_returns_json_error() {
    let (app, _state) = create_test_router().await;

    let request = get_request("/api/v1/feedback");
    let (status, body) = send_request_raw(app, request).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Verify it's valid JSON with error structure
    let error: serde_json::Value = serde_json::from_str(&body).expect("Response should be JSON");
    assert!(error.get("code").is_some(), "Error should have code field");
    assert!(
        error.get("message").is_some(),
        "Error should have message field"
    );
    assert_eq!(
        error["code"].as_str().unwrap(),
        "UNAUTHORIZED",
        "Error code should be UNAUTHORIZED"
    );
}

/// Unauthenticated incident feedback request returns JSON error.
#[tokio::test]
async fn test_incident_feedback_unauthorized_returns_json_error() {
    let (app, _state) = create_test_router().await;

    let request = post_json_request(
        "/api/v1/incidents/550e8400-e29b-41d4-a716-446655440000/feedback",
        r#"{"feedback_type": "correct"}"#,
    );
    let (status, body) = send_request_raw(app, request).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let error: serde_json::Value = serde_json::from_str(&body).expect("Response should be JSON");
    assert_eq!(
        error["code"].as_str().unwrap(),
        "UNAUTHORIZED",
        "Error code should be UNAUTHORIZED"
    );
}

// ============================================================================
// Route Existence Tests (verify endpoints are mounted)
// ============================================================================

/// Verify that /api/feedback routes exist (not 404).
/// Unauthenticated requests should return 401, not 404.
#[tokio::test]
async fn test_feedback_routes_exist() {
    let endpoints = [
        ("/api/v1/feedback", Method::GET),
        ("/api/v1/feedback/stats", Method::GET),
        ("/api/v1/feedback/accuracy/by-verdict", Method::GET),
        ("/api/v1/feedback/accuracy/by-type", Method::GET),
        ("/api/v1/feedback/trends", Method::GET),
    ];

    for (endpoint, method) in endpoints {
        let (app, _) = create_test_router().await;

        let request = axum::extract::Request::builder()
            .method(method.clone())
            .uri(endpoint)
            .body(axum::body::Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_ne!(
            response.status(),
            StatusCode::NOT_FOUND,
            "Endpoint {} {:?} should exist (not 404), got {:?}",
            endpoint,
            method,
            response.status()
        );
    }
}

/// Verify that legacy /api/feedback routes also exist.
#[tokio::test]
async fn test_feedback_legacy_routes_exist() {
    let (app, _state) = create_test_router().await;

    let request = get_request("/api/feedback");
    let response = app.oneshot(request).await.unwrap();

    // Should get 401 (unauthorized), not 404 (not found)
    assert_ne!(
        response.status(),
        StatusCode::NOT_FOUND,
        "Legacy /api/feedback route should exist"
    );
}

/// Verify that incident feedback routes exist.
#[tokio::test]
async fn test_incident_feedback_routes_exist() {
    let uuid = "550e8400-e29b-41d4-a716-446655440000";

    let endpoints = [
        (format!("/api/v1/incidents/{}/feedback", uuid), Method::GET),
        (format!("/api/v1/incidents/{}/feedback", uuid), Method::POST),
    ];

    for (endpoint, method) in endpoints {
        let (app, _) = create_test_router().await;

        let body = if method == Method::POST {
            axum::body::Body::from(r#"{"feedback_type":"correct"}"#)
        } else {
            axum::body::Body::empty()
        };

        let mut builder = axum::extract::Request::builder()
            .method(method.clone())
            .uri(&endpoint);

        if method == Method::POST {
            builder = builder.header("Content-Type", "application/json");
        }

        let request = builder.body(body).unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_ne!(
            response.status(),
            StatusCode::NOT_FOUND,
            "Endpoint {} {:?} should exist (not 404), got {:?}",
            endpoint,
            method,
            response.status()
        );
    }
}
