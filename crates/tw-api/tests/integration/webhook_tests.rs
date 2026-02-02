//! Webhook ingestion integration tests.

use axum::{
    body::Body,
    http::{Method, StatusCode},
};
use serde_json::{json, Value};

use super::common::{create_test_router, send_request, send_request_raw};

/// Helper to create a POST request with JSON body.
fn post_json_request(uri: &str, body: &Value) -> axum::extract::Request<Body> {
    axum::extract::Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap()
}

/// Test that the webhook endpoint accepts a valid alert payload.
#[tokio::test]
async fn test_webhook_accepts_valid_alert() {
    // This test runs in dev mode without signature validation
    std::env::set_var("TW_WEBHOOK_REQUIRE_SIGNATURE", "false");
    std::env::remove_var("TW_ENV");

    let (app, _state) = create_test_router().await;

    let payload = json!({
        "source": "splunk",
        "alert_type": "malware_detected",
        "title": "Malware Detected on Workstation",
        "severity": "high",
        "description": "Ransomware activity detected",
        "data": {
            "hostname": "workstation-001",
            "file_hash": "abc123"
        }
    });

    let request = post_json_request("/api/webhooks/alerts", &payload);
    let (status, body): (StatusCode, Value) = send_request(app, request).await;

    // Should return 202 Accepted
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "Webhook should accept valid alert"
    );

    // Response should indicate acceptance
    assert_eq!(body.get("accepted"), Some(&json!(true)));
    assert!(body.get("incident_id").is_some());

    // Cleanup
    std::env::remove_var("TW_WEBHOOK_REQUIRE_SIGNATURE");
}

/// Test that webhook rejects malformed JSON.
#[tokio::test]
async fn test_webhook_rejects_malformed_json() {
    std::env::set_var("TW_WEBHOOK_REQUIRE_SIGNATURE", "false");
    std::env::remove_var("TW_ENV");

    let (app, _state) = create_test_router().await;

    let request = axum::extract::Request::builder()
        .method(Method::POST)
        .uri("/api/webhooks/alerts")
        .header("Content-Type", "application/json")
        .body(Body::from("not valid json"))
        .unwrap();

    let (status, _body) = send_request_raw(app, request).await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Webhook should reject malformed JSON"
    );

    std::env::remove_var("TW_WEBHOOK_REQUIRE_SIGNATURE");
}

/// Test that webhook validates required fields.
#[tokio::test]
async fn test_webhook_validates_required_fields() {
    std::env::set_var("TW_WEBHOOK_REQUIRE_SIGNATURE", "false");
    std::env::remove_var("TW_ENV");

    let (app, _state) = create_test_router().await;

    // Missing required 'source' field
    let payload = json!({
        "alert_type": "malware_detected",
        "title": "Test Alert",
        "data": {}
    });

    let request = post_json_request("/api/webhooks/alerts", &payload);
    let (status, _body) = send_request_raw(app, request).await;

    // Should return bad request due to missing required field
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::UNPROCESSABLE_ENTITY,
        "Webhook should reject missing required fields"
    );

    std::env::remove_var("TW_WEBHOOK_REQUIRE_SIGNATURE");
}

/// Test that webhook with source path parameter overrides body source.
#[tokio::test]
async fn test_webhook_source_path_parameter() {
    std::env::set_var("TW_WEBHOOK_REQUIRE_SIGNATURE", "false");
    std::env::remove_var("TW_ENV");

    let (app, _state) = create_test_router().await;

    let payload = json!({
        "source": "body_source",
        "alert_type": "phishing",
        "title": "Phishing Email Detected",
        "data": {}
    });

    // Use path parameter source
    let request = post_json_request("/api/webhooks/alerts/crowdstrike", &payload);
    let (status, body): (StatusCode, Value) = send_request(app, request).await;

    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(body.get("accepted"), Some(&json!(true)));

    std::env::remove_var("TW_WEBHOOK_REQUIRE_SIGNATURE");
}

/// Test that webhook creates an incident in the database.
#[tokio::test]
async fn test_webhook_creates_incident() {
    std::env::set_var("TW_WEBHOOK_REQUIRE_SIGNATURE", "false");
    std::env::remove_var("TW_ENV");

    let (app, state) = create_test_router().await;

    let payload = json!({
        "source": "sentinelone",
        "alert_type": "suspicious_behavior",
        "title": "Suspicious Process Execution",
        "severity": "critical",
        "data": {
            "process": "powershell.exe",
            "command_line": "-enc base64string"
        }
    });

    let request = post_json_request("/api/webhooks/alerts", &payload);
    let (status, body): (StatusCode, Value) = send_request(app, request).await;

    assert_eq!(status, StatusCode::ACCEPTED);

    // Get the created incident ID
    let incident_id = body
        .get("incident_id")
        .and_then(|v| v.as_str())
        .expect("Should have incident_id");

    // Verify incident exists in database
    use tw_core::db::create_incident_repository;
    let repo = create_incident_repository(&state.db);
    let incident = repo
        .get(uuid::Uuid::parse_str(incident_id).unwrap())
        .await
        .expect("DB query should succeed");

    assert!(incident.is_some(), "Incident should exist in database");

    std::env::remove_var("TW_WEBHOOK_REQUIRE_SIGNATURE");
}

/// Test multiple webhooks can be processed.
#[tokio::test]
async fn test_multiple_webhook_alerts() {
    std::env::set_var("TW_WEBHOOK_REQUIRE_SIGNATURE", "false");
    std::env::remove_var("TW_ENV");

    for i in 0..3 {
        let (app, _state) = create_test_router().await;

        let payload = json!({
            "source": "test",
            "alert_type": format!("test_type_{}", i),
            "title": format!("Test Alert {}", i),
            "data": {"index": i}
        });

        let request = post_json_request("/api/webhooks/alerts", &payload);
        let (status, _body): (StatusCode, Value) = send_request(app, request).await;

        assert_eq!(status, StatusCode::ACCEPTED);
    }

    std::env::remove_var("TW_WEBHOOK_REQUIRE_SIGNATURE");
}
