//! Authentication routes for login and logout.

use axum::{
    extract::{ConnectInfo, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    Form, Router,
};
use serde::Deserialize;
use std::net::SocketAddr;
use tower_sessions::Session;
use tracing::{info, warn};
use tw_core::{auth::SessionData, db::create_user_repository, verify_password};

use crate::auth::{clear_session, set_session_data, validate_csrf_token};
use crate::rate_limit::RateLimitError;
use crate::state::AppState;
use crate::web::HtmlTemplate;

use askama::Template;

/// Login page template.
#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginTemplate {
    pub error: Option<String>,
    pub csrf_token: String,
}

/// Login form data.
#[derive(Debug, Deserialize)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
    pub csrf_token: String,
}

/// Creates the auth routes.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/login", get(login_page))
        .route("/login", post(login_submit))
        .route("/logout", post(logout))
}

/// Renders the login page.
async fn login_page(session: Session) -> impl IntoResponse {
    // Generate a CSRF token for the form
    let csrf_token = crate::auth::generate_csrf_token();

    // Store it in the session (we'll use a simple key for unauthenticated sessions)
    let _ = session.insert("login_csrf", &csrf_token).await;

    HtmlTemplate(LoginTemplate {
        error: None,
        csrf_token,
    })
}

/// Handles login form submission.
async fn login_submit(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    session: Session,
    Form(form): Form<LoginForm>,
) -> Response {
    let client_ip = addr.ip();

    // Check rate limits first (before any other validation)
    if let Err(e) = state.login_rate_limiter.check(client_ip) {
        warn!(
            ip = %client_ip,
            username = %form.username,
            "Login rate limited"
        );
        return match e {
            RateLimitError::PerIpLimitExceeded => {
                render_rate_limit_error(
                    "Too many login attempts. Please wait a minute and try again.".to_string(),
                    &session,
                )
                .await
            }
            RateLimitError::GlobalLimitExceeded => {
                render_rate_limit_error(
                    "Server is experiencing high traffic. Please try again later.".to_string(),
                    &session,
                )
                .await
            }
        };
    }

    // Validate CSRF token
    let stored_csrf: Option<String> = session.get("login_csrf").await.ok().flatten();
    if let Some(stored) = &stored_csrf {
        if !validate_csrf_token(&form.csrf_token, stored) {
            warn!("CSRF validation failed for login attempt");
            return render_login_error("Invalid request. Please try again.".to_string(), &session)
                .await;
        }
    } else {
        return render_login_error(
            "Session expired. Please refresh and try again.".to_string(),
            &session,
        )
        .await;
    }

    // Clear the login CSRF token
    let _ = session.remove::<String>("login_csrf").await;

    // Look up the user
    let user_repo = create_user_repository(&state.db);
    let user = match user_repo.get_by_username(&form.username).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            // Also try email
            match user_repo.get_by_email(&form.username).await {
                Ok(Some(user)) => user,
                Ok(None) => {
                    warn!(
                        ip = %client_ip,
                        username = %form.username,
                        "Login attempt for unknown user"
                    );
                    return render_login_error(
                        "Invalid username or password.".to_string(),
                        &session,
                    )
                    .await;
                }
                Err(e) => {
                    warn!("Database error during login: {}", e);
                    return render_login_error(
                        "An error occurred. Please try again.".to_string(),
                        &session,
                    )
                    .await;
                }
            }
        }
        Err(e) => {
            warn!("Database error during login: {}", e);
            return render_login_error(
                "An error occurred. Please try again.".to_string(),
                &session,
            )
            .await;
        }
    };

    // Check if account is enabled
    if !user.enabled {
        warn!(
            ip = %client_ip,
            username = %user.username,
            "Login attempt for disabled account"
        );
        return render_login_error("This account has been disabled.".to_string(), &session).await;
    }

    // Verify password
    match verify_password(&form.password, &user.password_hash) {
        Ok(true) => {
            // Password is correct
        }
        Ok(false) => {
            warn!(
                ip = %client_ip,
                username = %user.username,
                "Invalid password"
            );
            return render_login_error("Invalid username or password.".to_string(), &session).await;
        }
        Err(e) => {
            warn!("Password verification error: {}", e);
            return render_login_error(
                "An error occurred. Please try again.".to_string(),
                &session,
            )
            .await;
        }
    }

    // ============================================
    // SESSION FIXATION PREVENTION
    // ============================================
    // Regenerate session ID after successful authentication to prevent
    // session fixation attacks. This ensures any pre-authentication
    // session ID is invalidated.
    if let Err(e) = session.cycle_id().await {
        warn!("Failed to regenerate session ID: {}", e);
        // Continue anyway - this is a defense-in-depth measure
    }

    // Create session data
    let session_data = SessionData::new(&user);

    // Store session data
    if let Err(e) = set_session_data(&session, session_data).await {
        warn!("Failed to store session data: {}", e);
        return render_login_error("An error occurred. Please try again.".to_string(), &session)
            .await;
    }

    // Update last login timestamp
    let _ = user_repo.update_last_login(user.id).await;

    info!(
        ip = %client_ip,
        username = %user.username,
        role = %user.role,
        "User logged in successfully"
    );

    // Redirect to dashboard
    Redirect::to("/").into_response()
}

/// Handles logout.
async fn logout(session: Session) -> impl IntoResponse {
    if let Err(e) = clear_session(&session).await {
        warn!("Error clearing session during logout: {}", e);
    }

    info!("User logged out");

    Redirect::to("/login")
}

/// Helper to render login page with error.
async fn render_login_error(error: String, session: &Session) -> Response {
    let csrf_token = crate::auth::generate_csrf_token();
    let _ = session.insert("login_csrf", &csrf_token).await;

    HtmlTemplate(LoginTemplate {
        error: Some(error),
        csrf_token,
    })
    .into_response()
}

/// Helper to render login page with rate limit error (returns 429 status).
async fn render_rate_limit_error(error: String, session: &Session) -> Response {
    let csrf_token = crate::auth::generate_csrf_token();
    let _ = session.insert("login_csrf", &csrf_token).await;

    let body = HtmlTemplate(LoginTemplate {
        error: Some(error),
        csrf_token,
    })
    .into_response();

    // Return 429 Too Many Requests status
    (StatusCode::TOO_MANY_REQUESTS, body).into_response()
}
