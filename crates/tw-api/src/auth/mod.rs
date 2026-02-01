//! Authentication and authorization for the API.
//!
//! This module provides:
//! - Session-based authentication for web dashboard
//! - API key authentication for programmatic access
//! - Role-based access control extractors
//! - CSRF protection for forms

pub mod csrf;
pub mod extractors;

pub use csrf::{generate_csrf_token, validate_csrf_token, CsrfToken};
pub use extractors::{AuthenticatedUser, OptionalUser, RequireAdmin, RequireAnalyst};

use tower_sessions::Session;
use tw_core::auth::SessionData;

/// Session key for storing user data.
pub const SESSION_USER_KEY: &str = "user";

/// Gets the session data from the session.
pub async fn get_session_data(session: &Session) -> Option<SessionData> {
    session
        .get::<SessionData>(SESSION_USER_KEY)
        .await
        .ok()
        .flatten()
}

/// Stores session data in the session.
pub async fn set_session_data(
    session: &Session,
    data: SessionData,
) -> Result<(), tower_sessions::session::Error> {
    session.insert(SESSION_USER_KEY, data).await
}

/// Clears the session (logout).
pub async fn clear_session(session: &Session) -> Result<(), tower_sessions::session::Error> {
    session.flush().await
}
