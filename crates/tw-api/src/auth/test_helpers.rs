//! Test helpers for authentication.
//!
//! Provides utilities for testing authenticated endpoints without
//! setting up full session infrastructure.

use axum::{extract::Request, middleware::Next, response::Response};
use tw_core::{
    auth::{Role, DEFAULT_TENANT_ID},
    User,
};
use uuid::Uuid;

/// Extension type for injecting a test user into requests.
#[derive(Clone)]
pub struct TestUser(pub User);

impl TestUser {
    /// Creates a default admin test user.
    pub fn admin() -> Self {
        TestUser(User {
            id: Uuid::new_v4(),
            tenant_id: DEFAULT_TENANT_ID,
            email: "admin@test.local".to_string(),
            username: "test_admin".to_string(),
            password_hash: "not_used".to_string(),
            role: Role::Admin,
            display_name: Some("Test Admin".to_string()),
            enabled: true,
            last_login_at: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        })
    }

    /// Creates a default analyst test user.
    pub fn analyst() -> Self {
        TestUser(User {
            id: Uuid::new_v4(),
            tenant_id: DEFAULT_TENANT_ID,
            email: "analyst@test.local".to_string(),
            username: "test_analyst".to_string(),
            password_hash: "not_used".to_string(),
            role: Role::Analyst,
            display_name: Some("Test Analyst".to_string()),
            enabled: true,
            last_login_at: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        })
    }

    /// Creates a default viewer test user.
    pub fn viewer() -> Self {
        TestUser(User {
            id: Uuid::new_v4(),
            tenant_id: DEFAULT_TENANT_ID,
            email: "viewer@test.local".to_string(),
            username: "test_viewer".to_string(),
            password_hash: "not_used".to_string(),
            role: Role::Viewer,
            display_name: Some("Test Viewer".to_string()),
            enabled: true,
            last_login_at: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        })
    }
}

/// Middleware that injects a test user into the request extensions.
///
/// Use this in tests to bypass session-based authentication.
///
/// # Example
///
/// ```ignore
/// use axum::{Router, middleware};
/// use crate::auth::test_helpers::{TestUser, inject_test_user};
///
/// let router = Router::new()
///     .route("/protected", get(handler))
///     .layer(middleware::from_fn_with_state(
///         TestUser::admin(),
///         inject_test_user
///     ));
/// ```
pub async fn inject_test_user(test_user: TestUser, mut request: Request, next: Next) -> Response {
    request.extensions_mut().insert(test_user);
    next.run(request).await
}
