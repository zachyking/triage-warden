//! Axum extractors for authentication and authorization.

use axum::{
    async_trait,
    extract::{FromRef, FromRequestParts},
    http::{header::AUTHORIZATION, request::Parts},
};
use tower_sessions::Session;
use tracing::{debug, warn};
use tw_core::{
    auth::{ApiKey, Role, SessionData},
    db::{create_api_key_repository, create_user_repository, DbPool},
    tenant::TenantContext,
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
        // In tests, check for injected test user first
        #[cfg(test)]
        {
            if let Some(test_user) = parts.extensions.get::<super::test_helpers::TestUser>() {
                return Ok(AuthenticatedUser(test_user.0.clone()));
            }
        }

        let app_state = AppState::from_ref(state);
        let requested_tenant_id = parts.extensions.get::<TenantContext>().map(|t| t.tenant_id);

        // First, try session-based auth
        if let Ok(session) = Session::from_request_parts(parts, state).await {
            if let Some(session_data) = get_session_data(&session).await {
                // Load full user from database to get current state
                let user_repo = create_user_repository(&app_state.db);
                if let Ok(Some(user)) = user_repo.get(session_data.user_id).await {
                    if !user.enabled {
                        return Err(ApiError::AccountDisabled);
                    }
                    enforce_tenant_membership(requested_tenant_id, &user)?;
                    // Store session auth context for scope checking
                    parts
                        .extensions
                        .insert(SessionAuthContext { role: user.role });
                    return Ok(AuthenticatedUser(user));
                }
            }
        }

        // Try API key auth from Authorization header
        if let Some(auth_header) = parts.headers.get(AUTHORIZATION) {
            if let Ok(auth_str) = auth_header.to_str() {
                if let Some(token) = auth_str.strip_prefix("Bearer ") {
                    if let Some(validated) = validate_api_key(&app_state.db, token).await? {
                        if !validated.user.enabled {
                            return Err(ApiError::AccountDisabled);
                        }
                        enforce_tenant_membership(requested_tenant_id, &validated.user)?;
                        // Store the validated API key in request extensions for scope checking
                        parts.extensions.insert(validated.api_key.clone());
                        return Ok(AuthenticatedUser(validated.user));
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
        let requested_tenant_id = parts.extensions.get::<TenantContext>().map(|t| t.tenant_id);

        // Try session-based auth
        if let Ok(session) = Session::from_request_parts(parts, state).await {
            if let Some(session_data) = get_session_data(&session).await {
                let user_repo = create_user_repository(&app_state.db);
                if let Ok(Some(user)) = user_repo.get(session_data.user_id).await {
                    if user.enabled
                        && requested_tenant_id
                            .map(|tenant_id| user.tenant_id == tenant_id)
                            .unwrap_or(true)
                    {
                        return Ok(OptionalUser(Some(user)));
                    }
                }
            }
        }

        // Try API key auth
        if let Some(auth_header) = parts.headers.get(AUTHORIZATION) {
            if let Ok(auth_str) = auth_header.to_str() {
                if let Some(token) = auth_str.strip_prefix("Bearer ") {
                    if let Ok(Some(validated)) = validate_api_key(&app_state.db, token).await {
                        if validated.user.enabled
                            && requested_tenant_id
                                .map(|tenant_id| validated.user.tenant_id == tenant_id)
                                .unwrap_or(true)
                        {
                            parts.extensions.insert(validated.api_key.clone());
                            return Ok(OptionalUser(Some(validated.user)));
                        }
                    }
                }
            }
        }

        Ok(OptionalUser(None))
    }
}

fn enforce_tenant_membership(
    requested_tenant_id: Option<uuid::Uuid>,
    user: &User,
) -> Result<(), ApiError> {
    if let Some(tenant_id) = requested_tenant_id {
        if user.tenant_id != tenant_id {
            warn!(
                user_id = %user.id,
                user_tenant_id = %user.tenant_id,
                requested_tenant_id = %tenant_id,
                "Authenticated user does not belong to requested tenant"
            );
            return Err(ApiError::Forbidden("Tenant access denied".to_string()));
        }
    }

    Ok(())
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

/// Result of API key validation, including the key and user.
pub struct ValidatedApiKey {
    /// The validated API key.
    pub api_key: ApiKey,
    /// The user who owns this key.
    pub user: User,
}

/// Validates an API key and returns the associated user.
///
/// # API Key Format
///
/// API keys have the format: `tw_<prefix>_<secret>`
/// - `tw_` - Static prefix identifying Triage Warden keys
/// - `<prefix>` - 6-character identifier for key lookup
/// - `<secret>` - 32-character secret for verification
///
/// # Validation Steps
///
/// 1. Parse and validate key format
/// 2. Look up key by prefix in database
/// 3. Verify full key hash matches
/// 4. Check expiration
/// 5. Load the owning user
/// 6. Update last_used_at timestamp
async fn validate_api_key(db: &DbPool, token: &str) -> Result<Option<ValidatedApiKey>, ApiError> {
    // API keys have format: tw_<prefix>_<secret>
    // We lookup by prefix and then verify the full key
    if !token.starts_with("tw_") {
        debug!("API key rejected: doesn't start with 'tw_'");
        return Ok(None);
    }

    let parts: Vec<&str> = token.splitn(3, '_').collect();
    if parts.len() != 3 {
        debug!("API key rejected: invalid format (expected tw_<prefix>_<secret>)");
        return Ok(None);
    }

    let key_prefix = format!("tw_{}", parts[1]);
    debug!(prefix = %key_prefix, "Looking up API key by prefix");

    // Look up the API key by prefix
    let api_key_repo = create_api_key_repository(db);
    let api_key = match api_key_repo.get_by_prefix(&key_prefix).await {
        Ok(Some(key)) => key,
        Ok(None) => {
            debug!(prefix = %key_prefix, "API key not found");
            return Ok(None);
        }
        Err(e) => {
            warn!(error = %e, "Database error looking up API key");
            return Err(ApiError::Internal("Database error".to_string()));
        }
    };

    // Verify the full key hash
    if !api_key.verify(token) {
        warn!(prefix = %key_prefix, "API key hash verification failed");
        return Ok(None);
    }

    // Check expiration
    if api_key.is_expired() {
        debug!(
            prefix = %key_prefix,
            expires_at = ?api_key.expires_at,
            "API key has expired"
        );
        return Err(ApiError::Unauthorized("API key has expired".to_string()));
    }

    // Load the user who owns this key
    let user_repo = create_user_repository(db);
    let user = match user_repo.get(api_key.user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            warn!(
                user_id = %api_key.user_id,
                prefix = %key_prefix,
                "API key owner not found"
            );
            return Err(ApiError::Unauthorized(
                "API key owner not found".to_string(),
            ));
        }
        Err(e) => {
            warn!(error = %e, "Database error loading API key owner");
            return Err(ApiError::Internal("Database error".to_string()));
        }
    };

    // Update last_used_at timestamp (fire-and-forget, don't block on it)
    let api_key_id = api_key.id;
    let db_clone = db.clone();
    tokio::spawn(async move {
        let repo = create_api_key_repository(&db_clone);
        if let Err(e) = repo.update_last_used(api_key_id).await {
            warn!(error = %e, "Failed to update API key last_used_at");
        }
    });

    debug!(
        prefix = %key_prefix,
        user_id = %user.id,
        username = %user.username,
        "API key validated successfully"
    );

    Ok(Some(ValidatedApiKey { api_key, user }))
}

/// Standard API key scopes.
pub mod scopes {
    /// Scope for incident-related operations (read, update, execute actions).
    pub const INCIDENTS: &str = "incidents";
    /// Scope for connector-related operations (read, configure, test).
    pub const CONNECTORS: &str = "connectors";
    /// Scope for admin operations (user management, settings).
    pub const ADMIN: &str = "admin";
    /// Scope for read-only operations.
    pub const READ: &str = "read";
    /// Scope for write operations.
    pub const WRITE: &str = "write";
    /// Scope for webhook operations.
    pub const WEBHOOKS: &str = "webhooks";
    /// Wildcard scope - grants all permissions.
    pub const ALL: &str = "*";
}

/// Context for session-based authentication.
///
/// Stored in request extensions to enable scope validation for session users.
#[derive(Debug, Clone)]
pub struct SessionAuthContext {
    /// The role of the authenticated session user.
    pub role: Role,
}

/// Maps a user role to its equivalent set of API scopes.
///
/// This ensures session-based authentication respects the same scope
/// restrictions as API key authentication.
///
/// # Scope Mapping
///
/// - **Admin**: All scopes (`*`) - full access to everything
/// - **Analyst**: `read`, `write`, `incidents`, `connectors`, `webhooks` - operational access
/// - **Viewer**: `read` only - read-only access to dashboards and incidents
pub fn scopes_for_role(role: &Role) -> &'static [&'static str] {
    match role {
        Role::Admin => &[scopes::ALL],
        Role::Analyst => &[
            scopes::READ,
            scopes::WRITE,
            scopes::INCIDENTS,
            scopes::CONNECTORS,
            scopes::WEBHOOKS,
        ],
        Role::Viewer => &[scopes::READ],
    }
}

/// Checks if a role has a specific scope.
///
/// Returns true if the role's equivalent scope set includes the required scope
/// or the wildcard scope (`*`).
pub fn role_has_scope(role: &Role, required_scope: &str) -> bool {
    let role_scopes = scopes_for_role(role);
    role_scopes.contains(&scopes::ALL) || role_scopes.contains(&required_scope)
}

/// Macro to create scope-specific extractors.
///
/// This generates extractor types that check for specific API key scopes.
/// Session-based authentication is validated against role-based equivalent scopes.
///
/// # Scope Validation
///
/// - **API Key Auth**: Checks if the API key has the required scope or wildcard (`*`)
/// - **Session Auth**: Maps user role to equivalent scopes and validates:
///   - Admin role has all scopes
///   - Analyst role has read, write, incidents, connectors, webhooks
///   - Viewer role has read-only scope
macro_rules! define_scope_extractor {
    ($name:ident, $scope:expr, $doc:literal) => {
        #[doc = $doc]
        pub struct $name(pub User);

        #[async_trait]
        impl<S> FromRequestParts<S> for $name
        where
            AppState: FromRef<S>,
            S: Send + Sync,
        {
            type Rejection = ApiError;

            async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
                let AuthenticatedUser(user) = AuthenticatedUser::from_request_parts(parts, state).await?;

                // Check API key scopes if authenticated via API key
                if let Some(api_key) = parts.extensions.get::<ApiKey>() {
                    if !api_key.has_scope($scope) {
                        warn!(
                            scope = $scope,
                            key_prefix = %api_key.key_prefix,
                            key_scopes = ?api_key.scopes,
                            "API key missing required scope"
                        );
                        return Err(ApiError::Forbidden(format!(
                            "API key does not have required scope: {}",
                            $scope
                        )));
                    }
                }
                // Check session-based auth scopes based on user role
                else if let Some(session_ctx) = parts.extensions.get::<SessionAuthContext>() {
                    if !role_has_scope(&session_ctx.role, $scope) {
                        warn!(
                            scope = $scope,
                            role = ?session_ctx.role,
                            "Session user role does not have required scope"
                        );
                        return Err(ApiError::Forbidden(format!(
                            "Insufficient permissions: {} scope required",
                            $scope
                        )));
                    }
                }
                // Fallback: check user role directly (defensive)
                else if !role_has_scope(&user.role, $scope) {
                    warn!(
                        scope = $scope,
                        role = ?user.role,
                        "User role does not have required scope"
                    );
                    return Err(ApiError::Forbidden(format!(
                        "Insufficient permissions: {} scope required",
                        $scope
                    )));
                }

                Ok($name(user))
            }
        }
    };
}

// Define scope-specific extractors
define_scope_extractor!(
    RequireIncidentsScope,
    scopes::INCIDENTS,
    "Extractor that requires the 'incidents' API key scope."
);

define_scope_extractor!(
    RequireConnectorsScope,
    scopes::CONNECTORS,
    "Extractor that requires the 'connectors' API key scope."
);

define_scope_extractor!(
    RequireAdminScope,
    scopes::ADMIN,
    "Extractor that requires the 'admin' API key scope."
);

define_scope_extractor!(
    RequireReadScope,
    scopes::READ,
    "Extractor that requires the 'read' API key scope."
);

define_scope_extractor!(
    RequireWriteScope,
    scopes::WRITE,
    "Extractor that requires the 'write' API key scope."
);

define_scope_extractor!(
    RequireWebhooksScope,
    scopes::WEBHOOKS,
    "Extractor that requires the 'webhooks' API key scope."
);

/// Helper function to check if the current auth context has a required scope.
///
/// This function validates scopes for both API key and session-based authentication:
/// - For API keys: Checks if the key has the required scope or wildcard
/// - For sessions: Maps user role to equivalent scopes and validates
///
/// Returns Ok if:
/// - API key has the required scope (or wildcard `*`)
/// - Session user's role grants the required scope
///
/// Returns Err(403 Forbidden) if the scope is insufficient.
pub fn check_scope(parts: &Parts, required_scope: &str) -> Result<(), ApiError> {
    // Check API key scopes
    if let Some(api_key) = parts.extensions.get::<ApiKey>() {
        if !api_key.has_scope(required_scope) {
            return Err(ApiError::Forbidden(format!(
                "API key does not have required scope: {}",
                required_scope
            )));
        }
        return Ok(());
    }

    // Check session-based auth scopes
    if let Some(session_ctx) = parts.extensions.get::<SessionAuthContext>() {
        if !role_has_scope(&session_ctx.role, required_scope) {
            return Err(ApiError::Forbidden(format!(
                "Insufficient permissions: {} scope required",
                required_scope
            )));
        }
        return Ok(());
    }

    // No auth context found - this shouldn't happen if AuthenticatedUser was used
    Err(ApiError::Forbidden(format!(
        "Unable to verify scope: {}",
        required_scope
    )))
}

/// Helper function to check if an API key (if present) has a required scope.
///
/// **DEPRECATED**: Use `check_scope` instead, which validates both API key and session scopes.
///
/// Returns Ok if:
/// - No API key is present (session auth - WARNING: this bypasses scope checks!)
/// - API key has the required scope
#[deprecated(
    since = "0.2.0",
    note = "Use check_scope() instead, which validates both API key and session scopes"
)]
pub fn check_api_key_scope(parts: &Parts, required_scope: &str) -> Result<(), ApiError> {
    if let Some(api_key) = parts.extensions.get::<ApiKey>() {
        if !api_key.has_scope(required_scope) {
            return Err(ApiError::Forbidden(format!(
                "API key does not have required scope: {}",
                required_scope
            )));
        }
    }
    Ok(())
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
