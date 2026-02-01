//! Axum extractors for authentication and authorization.

use axum::{
    async_trait,
    extract::{FromRef, FromRequestParts},
    http::{header::AUTHORIZATION, request::Parts},
};
use tower_sessions::Session;
use tw_core::{
    auth::{Role, SessionData},
    db::{create_user_repository, DbPool},
    User,
};

use crate::error::ApiError;
use crate::state::AppState;

use super::get_session_data;

/// Extractor for authenticated users.
///
/// This extractor will:
/// 1. Check for a valid session with user data
/// 2. If no session, check for an API key in the Authorization header
/// 3. Return 401 Unauthorized if neither is present
///
/// # Example
///
/// ```ignore
/// async fn protected_endpoint(
///     AuthenticatedUser(user): AuthenticatedUser,
/// ) -> impl IntoResponse {
///     format!("Hello, {}!", user.username)
/// }
/// ```
pub struct AuthenticatedUser(pub User);

#[async_trait]
impl<S> FromRequestParts<S> for AuthenticatedUser
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);

        // First, try session-based auth
        if let Ok(session) = Session::from_request_parts(parts, state).await {
            if let Some(session_data) = get_session_data(&session).await {
                // Load full user from database to get current state
                let user_repo = create_user_repository(&app_state.db);
                if let Ok(Some(user)) = user_repo.get(session_data.user_id).await {
                    if !user.enabled {
                        return Err(ApiError::AccountDisabled);
                    }
                    return Ok(AuthenticatedUser(user));
                }
            }
        }

        // Try API key auth from Authorization header
        if let Some(auth_header) = parts.headers.get(AUTHORIZATION) {
            if let Ok(auth_str) = auth_header.to_str() {
                if let Some(token) = auth_str.strip_prefix("Bearer ") {
                    if let Some(user) = validate_api_key(&app_state.db, token).await? {
                        if !user.enabled {
                            return Err(ApiError::AccountDisabled);
                        }
                        return Ok(AuthenticatedUser(user));
                    }
                }
            }
        }

        Err(ApiError::Unauthorized(
            "Authentication required".to_string(),
        ))
    }
}

/// Extractor for optional authentication.
///
/// This extractor will try to get the current user but never fails.
/// Returns `None` if not authenticated.
///
/// # Example
///
/// ```ignore
/// async fn public_endpoint(
///     OptionalUser(user): OptionalUser,
/// ) -> impl IntoResponse {
///     if let Some(user) = user {
///         format!("Hello, {}!", user.username)
///     } else {
///         "Hello, guest!".to_string()
///     }
/// }
/// ```
pub struct OptionalUser(pub Option<User>);

#[async_trait]
impl<S> FromRequestParts<S> for OptionalUser
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);

        // Try session-based auth
        if let Ok(session) = Session::from_request_parts(parts, state).await {
            if let Some(session_data) = get_session_data(&session).await {
                let user_repo = create_user_repository(&app_state.db);
                if let Ok(Some(user)) = user_repo.get(session_data.user_id).await {
                    if user.enabled {
                        return Ok(OptionalUser(Some(user)));
                    }
                }
            }
        }

        // Try API key auth
        if let Some(auth_header) = parts.headers.get(AUTHORIZATION) {
            if let Ok(auth_str) = auth_header.to_str() {
                if let Some(token) = auth_str.strip_prefix("Bearer ") {
                    if let Ok(Some(user)) = validate_api_key(&app_state.db, token).await {
                        if user.enabled {
                            return Ok(OptionalUser(Some(user)));
                        }
                    }
                }
            }
        }

        Ok(OptionalUser(None))
    }
}

/// Extractor that requires admin role.
///
/// Returns 403 Forbidden if the user is not an admin.
///
/// # Example
///
/// ```ignore
/// async fn admin_endpoint(
///     RequireAdmin(user): RequireAdmin,
/// ) -> impl IntoResponse {
///     format!("Admin {} accessing admin panel", user.username)
/// }
/// ```
pub struct RequireAdmin(pub User);

#[async_trait]
impl<S> FromRequestParts<S> for RequireAdmin
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let AuthenticatedUser(user) = AuthenticatedUser::from_request_parts(parts, state).await?;

        if !user.has_permission(Role::Admin) {
            return Err(ApiError::Forbidden("Admin access required".to_string()));
        }

        Ok(RequireAdmin(user))
    }
}

/// Extractor that requires at least analyst role.
///
/// Returns 403 Forbidden if the user is only a viewer.
///
/// # Example
///
/// ```ignore
/// async fn analyst_endpoint(
///     RequireAnalyst(user): RequireAnalyst,
/// ) -> impl IntoResponse {
///     format!("Analyst {} can approve actions", user.username)
/// }
/// ```
pub struct RequireAnalyst(pub User);

#[async_trait]
impl<S> FromRequestParts<S> for RequireAnalyst
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let AuthenticatedUser(user) = AuthenticatedUser::from_request_parts(parts, state).await?;

        if !user.has_permission(Role::Analyst) {
            return Err(ApiError::Forbidden("Analyst access required".to_string()));
        }

        Ok(RequireAnalyst(user))
    }
}

/// Validates an API key and returns the associated user.
async fn validate_api_key(_db: &DbPool, token: &str) -> Result<Option<User>, ApiError> {
    // API keys have format: tw_<prefix>_<secret>
    // We lookup by prefix and then verify the full key
    if !token.starts_with("tw_") {
        return Ok(None);
    }

    let parts: Vec<&str> = token.splitn(3, '_').collect();
    if parts.len() != 3 {
        return Ok(None);
    }

    let key_prefix = format!("tw_{}", parts[1]);

    // For now, we don't have ApiKeyRepository implemented
    // This would query the api_keys table, verify the hash, and return the user
    // TODO: Implement ApiKeyRepository and complete this function

    // Placeholder: API key validation not yet implemented
    tracing::debug!("API key validation attempted with prefix: {}", key_prefix);
    Ok(None)
}

/// Extractor for session data without loading full user.
///
/// Useful for lightweight checks or getting CSRF token.
pub struct CurrentSession(pub SessionData);

#[async_trait]
impl<S> FromRequestParts<S> for CurrentSession
where
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let session = Session::from_request_parts(parts, state)
            .await
            .map_err(|_| ApiError::SessionExpired)?;

        let session_data = get_session_data(&session)
            .await
            .ok_or(ApiError::SessionExpired)?;

        Ok(CurrentSession(session_data))
    }
}
