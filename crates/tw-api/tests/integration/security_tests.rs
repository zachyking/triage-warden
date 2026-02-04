//! Security integration tests for Triage Warden API.
//!
//! These tests verify that security fixes are working correctly:
//! - Security headers (HSTS, CSP, etc.)
//! - Request ID generation
//! - Event handling for critical events

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
};
use std::sync::Arc;
use tower::ServiceExt;
use tw_api::server::{ApiServer, ApiServerConfig};
use tw_api::state::AppState;
use tw_core::{db::DbPool, EventBus, FeatureFlagStore, FeatureFlags, InMemoryFeatureFlagStore};

use super::common::setup_test_db;

/// Creates an AppState with test database and full server (including middleware).
async fn create_test_state() -> AppState {
    let pool = setup_test_db().await;
    let db = DbPool::Sqlite(pool);
    let event_bus = EventBus::new(100);
    let store: Arc<dyn FeatureFlagStore> = Arc::new(InMemoryFeatureFlagStore::new());
    let feature_flags = FeatureFlags::new(store);
    AppState::new(db, event_bus, feature_flags)
}

/// Helper to create a GET request.
fn get_request(uri: &str) -> Request<Body> {
    Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(Body::empty())
        .unwrap()
}

// ============================================================
// Security Headers Tests
// ============================================================

#[tokio::test]
async fn test_security_headers_present() {
    let state = create_test_state().await;
    let server = ApiServer::new(state, ApiServerConfig::default());
    let app = server.router();

    let request = get_request("/health");
    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Check X-Content-Type-Options
    assert_eq!(
        response
            .headers()
            .get(header::X_CONTENT_TYPE_OPTIONS)
            .map(|v| v.to_str().unwrap()),
        Some("nosniff"),
        "X-Content-Type-Options header missing or incorrect"
    );

    // Check X-Frame-Options
    assert_eq!(
        response
            .headers()
            .get(header::X_FRAME_OPTIONS)
            .map(|v| v.to_str().unwrap()),
        Some("DENY"),
        "X-Frame-Options header missing or incorrect"
    );

    // Check X-XSS-Protection
    assert_eq!(
        response
            .headers()
            .get("X-XSS-Protection")
            .map(|v| v.to_str().unwrap()),
        Some("1; mode=block"),
        "X-XSS-Protection header missing or incorrect"
    );

    // Check Cache-Control
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .map(|v| v.to_str().unwrap()),
        Some("no-store"),
        "Cache-Control header missing or incorrect"
    );

    // Check HSTS
    let hsts = response
        .headers()
        .get(header::STRICT_TRANSPORT_SECURITY)
        .map(|v| v.to_str().unwrap());
    assert!(hsts.is_some(), "Strict-Transport-Security header missing");
    assert!(
        hsts.unwrap().contains("max-age=31536000"),
        "HSTS max-age should be at least 1 year"
    );
    assert!(
        hsts.unwrap().contains("includeSubDomains"),
        "HSTS should include subdomains"
    );

    // Check CSP
    let csp = response
        .headers()
        .get(header::CONTENT_SECURITY_POLICY)
        .map(|v| v.to_str().unwrap());
    assert!(csp.is_some(), "Content-Security-Policy header missing");
    let csp = csp.unwrap();
    assert!(
        csp.contains("default-src 'self'"),
        "CSP should have restrictive default-src"
    );
    assert!(
        csp.contains("frame-ancestors 'none'"),
        "CSP should prevent framing"
    );

    // Check Referrer-Policy
    assert_eq!(
        response
            .headers()
            .get("Referrer-Policy")
            .map(|v| v.to_str().unwrap()),
        Some("strict-origin-when-cross-origin"),
        "Referrer-Policy header missing or incorrect"
    );

    // Check Permissions-Policy
    let permissions = response
        .headers()
        .get("Permissions-Policy")
        .map(|v| v.to_str().unwrap());
    assert!(permissions.is_some(), "Permissions-Policy header missing");
    assert!(
        permissions.unwrap().contains("geolocation=()"),
        "Permissions-Policy should disable geolocation"
    );
}

#[tokio::test]
async fn test_request_id_header() {
    let state = create_test_state().await;
    let server = ApiServer::new(state, ApiServerConfig::default());
    let app = server.router();

    let request = get_request("/health");
    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Check X-Request-Id is present in response
    let request_id = response.headers().get("X-Request-Id");
    assert!(
        request_id.is_some(),
        "X-Request-Id header should be present in response"
    );

    // Verify it's a valid UUID-like format
    let id = request_id.unwrap().to_str().unwrap();
    assert!(
        id.len() >= 32,
        "Request ID should be at least 32 characters (UUID format)"
    );
}

#[tokio::test]
async fn test_request_id_forwarded() {
    let state = create_test_state().await;
    let server = ApiServer::new(state, ApiServerConfig::default());
    let app = server.router();

    // Send request with custom request ID
    let custom_id = "custom-request-id-12345";
    let request = Request::builder()
        .method(Method::GET)
        .uri("/health")
        .header("X-Request-Id", custom_id)
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Check that the same request ID is returned
    let returned_id = response
        .headers()
        .get("X-Request-Id")
        .map(|v| v.to_str().unwrap());
    assert_eq!(
        returned_id,
        Some(custom_id),
        "Request ID should be forwarded from request"
    );
}

// ============================================================
// Critical Event Handling Tests
// ============================================================

#[cfg(test)]
mod event_tests {
    use tw_core::events::TriageEvent;
    use tw_core::incident::{Alert, AlertSource, Severity};

    #[test]
    fn test_kill_switch_is_critical() {
        let event = TriageEvent::KillSwitchActivated {
            reason: "test".to_string(),
            activated_by: "admin".to_string(),
        };
        assert!(
            event.is_critical(),
            "KillSwitchActivated should be critical"
        );
    }

    #[test]
    fn test_non_recoverable_error_is_critical() {
        let event = TriageEvent::SystemError {
            incident_id: None,
            error: "fatal error".to_string(),
            recoverable: false,
        };
        assert!(
            event.is_critical(),
            "Non-recoverable SystemError should be critical"
        );
    }

    #[test]
    fn test_recoverable_error_not_critical() {
        let event = TriageEvent::SystemError {
            incident_id: None,
            error: "transient error".to_string(),
            recoverable: true,
        };
        assert!(
            !event.is_critical(),
            "Recoverable SystemError should not be critical"
        );
    }

    #[test]
    fn test_escalation_is_critical() {
        let event = TriageEvent::IncidentEscalated {
            incident_id: uuid::Uuid::new_v4(),
            escalation_level: 3,
            reason: "test".to_string(),
        };
        assert!(event.is_critical(), "IncidentEscalated should be critical");
    }

    #[test]
    fn test_normal_events_not_critical() {
        let event = TriageEvent::AlertReceived(Alert {
            id: "test".to_string(),
            source: AlertSource::Siem("test".to_string()),
            alert_type: "test".to_string(),
            severity: Severity::Low,
            title: "Test".to_string(),
            description: None,
            data: serde_json::json!({}),
            timestamp: chrono::Utc::now(),
            tags: vec![],
        });
        assert!(!event.is_critical(), "AlertReceived should not be critical");
    }
}

// ============================================================
// Event Bus Dropped Event Tracking Test
// ============================================================

#[cfg(test)]
mod event_bus_tests {
    use tw_core::EventBus;

    #[test]
    fn test_dropped_event_counter_starts_at_zero() {
        let event_bus = EventBus::new(100);
        assert_eq!(
            event_bus.dropped_event_count(),
            0,
            "Dropped event count should start at zero"
        );
    }
}
