//! Authentication and authorization types for Triage Warden.
//!
//! This module provides core authentication types including:
//! - User and Role definitions
//! - API key management
//! - Session data structures
//! - Password hashing utilities
//! - Fine-grained permissions for workflow authorization
//! - Authorization context for action execution

pub mod password;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

/// Fine-grained permissions for workflow and action authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    /// Read incidents and their data.
    ReadIncidents,
    /// Write/modify incidents (status changes, add enrichments, etc.).
    WriteIncidents,
    /// Approve proposed actions for execution.
    ApproveActions,
    /// Execute approved actions.
    ExecuteActions,
    /// Manage playbooks (create, update, delete).
    ManagePlaybooks,
    /// Manage policies (create, update, delete).
    ManagePolicies,
    /// Manage users (create, update, delete).
    ManageUsers,
    /// Manage connectors (create, update, delete).
    ManageConnectors,
    /// Manage system settings.
    ManageSettings,
    /// Activate/deactivate kill switch.
    ManageKillSwitch,
}

impl Permission {
    /// Returns all available permissions.
    pub fn all() -> HashSet<Permission> {
        HashSet::from([
            Permission::ReadIncidents,
            Permission::WriteIncidents,
            Permission::ApproveActions,
            Permission::ExecuteActions,
            Permission::ManagePlaybooks,
            Permission::ManagePolicies,
            Permission::ManageUsers,
            Permission::ManageConnectors,
            Permission::ManageSettings,
            Permission::ManageKillSwitch,
        ])
    }

    /// Returns the permission name as a string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Permission::ReadIncidents => "read_incidents",
            Permission::WriteIncidents => "write_incidents",
            Permission::ApproveActions => "approve_actions",
            Permission::ExecuteActions => "execute_actions",
            Permission::ManagePlaybooks => "manage_playbooks",
            Permission::ManagePolicies => "manage_policies",
            Permission::ManageUsers => "manage_users",
            Permission::ManageConnectors => "manage_connectors",
            Permission::ManageSettings => "manage_settings",
            Permission::ManageKillSwitch => "manage_kill_switch",
        }
    }
}

impl fmt::Display for Permission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Authorization context for workflow operations.
///
/// This struct carries identity and permission information through
/// workflow transitions, enabling fine-grained access control and
/// comprehensive audit logging.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationContext {
    /// Unique identifier of the actor (user or service).
    pub actor_id: Uuid,
    /// Human-readable actor name for audit logs.
    pub actor_name: String,
    /// The actor's role.
    pub role: Role,
    /// Explicit permissions granted to this actor.
    pub permissions: HashSet<Permission>,
    /// Session or request ID for tracing.
    pub session_id: Option<String>,
    /// IP address of the request origin (for audit).
    pub ip_address: Option<String>,
}

impl AuthorizationContext {
    /// Creates a new authorization context from a user.
    pub fn from_user(user: &User) -> Self {
        Self {
            actor_id: user.id,
            actor_name: user.display().to_string(),
            role: user.role,
            permissions: Self::permissions_for_role(user.role),
            session_id: None,
            ip_address: None,
        }
    }

    /// Creates a system context for automated operations.
    pub fn system() -> Self {
        Self {
            actor_id: Uuid::nil(),
            actor_name: "system".to_string(),
            role: Role::Admin,
            permissions: Permission::all(),
            session_id: None,
            ip_address: None,
        }
    }

    /// Creates an authorization context with explicit permissions.
    pub fn with_permissions(
        actor_id: Uuid,
        actor_name: impl Into<String>,
        role: Role,
        permissions: HashSet<Permission>,
    ) -> Self {
        Self {
            actor_id,
            actor_name: actor_name.into(),
            role,
            permissions,
            session_id: None,
            ip_address: None,
        }
    }

    /// Adds session tracking information.
    pub fn with_session(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    /// Adds IP address for audit purposes.
    pub fn with_ip_address(mut self, ip: impl Into<String>) -> Self {
        self.ip_address = Some(ip.into());
        self
    }

    /// Returns the permissions for a given role.
    pub fn permissions_for_role(role: Role) -> HashSet<Permission> {
        match role {
            Role::Admin => Permission::all(),
            Role::Analyst => HashSet::from([
                Permission::ReadIncidents,
                Permission::WriteIncidents,
                Permission::ApproveActions,
                Permission::ExecuteActions,
            ]),
            Role::Viewer => HashSet::from([Permission::ReadIncidents]),
        }
    }

    /// Checks if this context has a specific permission.
    pub fn has_permission(&self, permission: Permission) -> bool {
        self.permissions.contains(&permission)
    }

    /// Checks if this context has all of the specified permissions.
    pub fn has_all_permissions(&self, permissions: &[Permission]) -> bool {
        permissions.iter().all(|p| self.permissions.contains(p))
    }

    /// Checks if this context has any of the specified permissions.
    pub fn has_any_permission(&self, permissions: &[Permission]) -> bool {
        permissions.iter().any(|p| self.permissions.contains(p))
    }

    /// Returns the actor identity string for audit logging.
    pub fn audit_identity(&self) -> String {
        format!("{}:{}", self.actor_id, self.actor_name)
    }

    /// Validates that this context has permission to execute actions.
    ///
    /// Returns an error if the `ExecuteActions` permission is missing.
    pub fn validate_execute_permission(&self) -> Result<(), AuthorizationError> {
        if !self.has_permission(Permission::ExecuteActions) {
            return Err(AuthorizationError::InsufficientPermissions {
                actor_id: self.actor_id,
                actor_name: self.actor_name.clone(),
                required: Permission::ExecuteActions,
                role: self.role,
            });
        }
        Ok(())
    }

    /// Validates that this context has permission for destructive actions.
    ///
    /// Destructive actions require both `ExecuteActions` and `ApproveActions` permissions.
    pub fn validate_destructive_permission(&self) -> Result<(), AuthorizationError> {
        self.validate_execute_permission()?;
        if !self.has_permission(Permission::ApproveActions) {
            return Err(AuthorizationError::InsufficientPermissions {
                actor_id: self.actor_id,
                actor_name: self.actor_name.clone(),
                required: Permission::ApproveActions,
                role: self.role,
            });
        }
        Ok(())
    }
}

/// Errors that can occur during authorization checks.
#[derive(Debug, Clone)]
pub enum AuthorizationError {
    /// The actor lacks a required permission.
    InsufficientPermissions {
        actor_id: Uuid,
        actor_name: String,
        required: Permission,
        role: Role,
    },
    /// No authorization context was provided.
    MissingContext,
    /// The authorization context is invalid.
    InvalidContext(String),
}

impl std::fmt::Display for AuthorizationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthorizationError::InsufficientPermissions {
                actor_name,
                required,
                role,
                ..
            } => {
                write!(
                    f,
                    "User '{}' (role: {}) lacks required permission: {:?}",
                    actor_name, role, required
                )
            }
            AuthorizationError::MissingContext => {
                write!(f, "No authorization context provided")
            }
            AuthorizationError::InvalidContext(msg) => {
                write!(f, "Invalid authorization context: {}", msg)
            }
        }
    }
}

impl std::error::Error for AuthorizationError {}

/// List of action names considered destructive and requiring approval permission.
pub const DESTRUCTIVE_ACTIONS: &[&str] = &[
    "isolate_host",
    "disable_user",
    "block_sender",
    "quarantine_email",
];

/// Checks if an action is considered destructive (requires approval permission).
pub fn is_destructive_action(action_name: &str) -> bool {
    DESTRUCTIVE_ACTIONS.contains(&action_name)
}

/// User role for role-based access control.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Full system access, can manage users and all settings.
    Admin,
    /// Can view and act on incidents, approve actions.
    Analyst,
    /// Read-only access to dashboards and incidents.
    #[default]
    Viewer,
}

impl Role {
    /// Returns the role name as a string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::Analyst => "analyst",
            Role::Viewer => "viewer",
        }
    }

    /// Returns true if this role has at least the permissions of the given role.
    pub fn has_permission(&self, required: Role) -> bool {
        match (self, required) {
            // Admin has all permissions
            (Role::Admin, _) => true,
            // Analyst has analyst and viewer permissions
            (Role::Analyst, Role::Analyst | Role::Viewer) => true,
            // Viewer only has viewer permissions
            (Role::Viewer, Role::Viewer) => true,
            _ => false,
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for Role {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "admin" => Ok(Role::Admin),
            "analyst" => Ok(Role::Analyst),
            "viewer" => Ok(Role::Viewer),
            _ => Err(()),
        }
    }
}

/// A user in the system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    /// Unique identifier.
    pub id: Uuid,
    /// Email address (unique).
    pub email: String,
    /// Username for login (unique).
    pub username: String,
    /// Argon2 password hash.
    #[serde(skip_serializing)]
    pub password_hash: String,
    /// User role.
    pub role: Role,
    /// Display name (optional).
    pub display_name: Option<String>,
    /// Whether the account is enabled.
    pub enabled: bool,
    /// Last login timestamp.
    pub last_login_at: Option<DateTime<Utc>>,
    /// Account creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
}

impl User {
    /// Creates a new user with the given details.
    pub fn new(
        email: impl Into<String>,
        username: impl Into<String>,
        password_hash: impl Into<String>,
        role: Role,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            email: email.into(),
            username: username.into(),
            password_hash: password_hash.into(),
            role,
            display_name: None,
            enabled: true,
            last_login_at: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Returns the display name, falling back to username.
    pub fn display(&self) -> &str {
        self.display_name.as_deref().unwrap_or(&self.username)
    }

    /// Returns true if the user has at least the given role's permissions.
    pub fn has_permission(&self, required: Role) -> bool {
        self.role.has_permission(required)
    }

    /// Returns true if the user is an admin.
    pub fn is_admin(&self) -> bool {
        self.role == Role::Admin
    }
}

/// Update fields for a user.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UserUpdate {
    pub email: Option<String>,
    pub username: Option<String>,
    pub role: Option<Role>,
    pub display_name: Option<Option<String>>,
    pub enabled: Option<bool>,
}

/// Filter for listing users.
#[derive(Debug, Clone, Default)]
pub struct UserFilter {
    pub role: Option<Role>,
    pub enabled: Option<bool>,
    pub search: Option<String>,
}

/// An API key for programmatic access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    /// Unique identifier.
    pub id: Uuid,
    /// User who owns this key.
    pub user_id: Uuid,
    /// Descriptive name for the key.
    pub name: String,
    /// SHA-256 hash of the full key.
    #[serde(skip_serializing)]
    pub key_hash: String,
    /// Prefix of the key for identification (e.g., "tw_abc123").
    pub key_prefix: String,
    /// Scopes/permissions for this key.
    pub scopes: Vec<String>,
    /// Expiration timestamp (optional).
    pub expires_at: Option<DateTime<Utc>>,
    /// Last time this key was used.
    pub last_used_at: Option<DateTime<Utc>>,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
}

impl ApiKey {
    /// Character set for API key generation (alphanumeric, 62 chars for more entropy).
    const CHARSET: &'static [u8] =
        b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    /// Creates a new API key. Returns the key struct and the raw key value.
    pub fn new(user_id: Uuid, name: impl Into<String>, scopes: Vec<String>) -> (Self, String) {
        use rand::rngs::OsRng;
        use rand::Rng;
        use sha2::{Digest, Sha256};

        // Generate a random key: tw_<prefix>_<secret>
        // Uses OsRng for cryptographically secure random number generation
        let prefix: String = (0..6)
            .map(|_| Self::CHARSET[OsRng.gen_range(0..Self::CHARSET.len())] as char)
            .collect();
        let secret: String = (0..32)
            .map(|_| Self::CHARSET[OsRng.gen_range(0..Self::CHARSET.len())] as char)
            .collect();

        let raw_key = format!("tw_{}_{}", prefix, secret);
        let key_prefix = format!("tw_{}", prefix);

        // Hash the full key
        let mut hasher = Sha256::new();
        hasher.update(raw_key.as_bytes());
        let key_hash = hex::encode(hasher.finalize());

        let api_key = Self {
            id: Uuid::new_v4(),
            user_id,
            name: name.into(),
            key_hash,
            key_prefix,
            scopes,
            expires_at: None,
            last_used_at: None,
            created_at: Utc::now(),
        };

        (api_key, raw_key)
    }

    /// Verifies that a raw key matches this API key's hash.
    pub fn verify(&self, raw_key: &str) -> bool {
        use sha2::{Digest, Sha256};
        use subtle::ConstantTimeEq;

        let mut hasher = Sha256::new();
        hasher.update(raw_key.as_bytes());
        let computed = hex::encode(hasher.finalize());

        computed.as_bytes().ct_eq(self.key_hash.as_bytes()).into()
    }

    /// Returns true if this key has expired.
    pub fn is_expired(&self) -> bool {
        self.expires_at.map(|exp| exp < Utc::now()).unwrap_or(false)
    }

    /// Returns true if this key has the given scope.
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope || s == "*")
    }
}

/// Session data stored for authenticated users.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionData {
    /// User ID.
    pub user_id: Uuid,
    /// Username (for display).
    pub username: String,
    /// User role.
    pub role: Role,
    /// CSRF token for form protection.
    pub csrf_token: String,
}

impl SessionData {
    /// Creates new session data with a fresh CSRF token.
    pub fn new(user: &User) -> Self {
        use rand::rngs::OsRng;
        use rand::Rng;

        // Use OsRng for cryptographically secure CSRF token generation
        let csrf_token: String = (0..32)
            .map(|_| {
                const CHARSET: &[u8] =
                    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
                CHARSET[OsRng.gen_range(0..CHARSET.len())] as char
            })
            .collect();

        Self {
            user_id: user.id,
            username: user.username.clone(),
            role: user.role,
            csrf_token,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role_permissions() {
        assert!(Role::Admin.has_permission(Role::Admin));
        assert!(Role::Admin.has_permission(Role::Analyst));
        assert!(Role::Admin.has_permission(Role::Viewer));

        assert!(!Role::Analyst.has_permission(Role::Admin));
        assert!(Role::Analyst.has_permission(Role::Analyst));
        assert!(Role::Analyst.has_permission(Role::Viewer));

        assert!(!Role::Viewer.has_permission(Role::Admin));
        assert!(!Role::Viewer.has_permission(Role::Analyst));
        assert!(Role::Viewer.has_permission(Role::Viewer));
    }

    #[test]
    fn test_role_from_str() {
        assert_eq!("admin".parse::<Role>(), Ok(Role::Admin));
        assert_eq!("ADMIN".parse::<Role>(), Ok(Role::Admin));
        assert_eq!("analyst".parse::<Role>(), Ok(Role::Analyst));
        assert_eq!("viewer".parse::<Role>(), Ok(Role::Viewer));
        assert!("unknown".parse::<Role>().is_err());
    }

    #[test]
    fn test_user_display() {
        let mut user = User::new("test@example.com", "testuser", "hash", Role::Viewer);
        assert_eq!(user.display(), "testuser");

        user.display_name = Some("Test User".to_string());
        assert_eq!(user.display(), "Test User");
    }

    #[test]
    fn test_api_key_creation_and_verify() {
        let user_id = Uuid::new_v4();
        let (api_key, raw_key) = ApiKey::new(user_id, "Test Key", vec!["read".to_string()]);

        assert!(raw_key.starts_with("tw_"));
        assert!(api_key.verify(&raw_key));
        assert!(!api_key.verify("wrong_key"));
    }

    #[test]
    fn test_api_key_expiry() {
        let user_id = Uuid::new_v4();
        let (mut api_key, _) = ApiKey::new(user_id, "Test Key", vec![]);

        assert!(!api_key.is_expired());

        api_key.expires_at = Some(Utc::now() - chrono::Duration::hours(1));
        assert!(api_key.is_expired());
    }

    #[test]
    fn test_api_key_scopes() {
        let user_id = Uuid::new_v4();
        let (api_key, _) = ApiKey::new(
            user_id,
            "Test Key",
            vec!["read".to_string(), "write".to_string()],
        );

        assert!(api_key.has_scope("read"));
        assert!(api_key.has_scope("write"));
        assert!(!api_key.has_scope("admin"));
    }

    #[test]
    fn test_wildcard_scope() {
        let user_id = Uuid::new_v4();
        let (api_key, _) = ApiKey::new(user_id, "Test Key", vec!["*".to_string()]);

        assert!(api_key.has_scope("read"));
        assert!(api_key.has_scope("write"));
        assert!(api_key.has_scope("anything"));
    }

    #[test]
    fn test_permission_enum() {
        let all_perms = Permission::all();
        assert!(all_perms.contains(&Permission::ReadIncidents));
        assert!(all_perms.contains(&Permission::WriteIncidents));
        assert!(all_perms.contains(&Permission::ApproveActions));
        assert!(all_perms.contains(&Permission::ExecuteActions));
        assert_eq!(all_perms.len(), 10);
    }

    #[test]
    fn test_authorization_context_from_user() {
        let user = User::new("test@example.com", "testuser", "hash", Role::Analyst);
        let ctx = AuthorizationContext::from_user(&user);

        assert_eq!(ctx.actor_id, user.id);
        assert_eq!(ctx.actor_name, "testuser");
        assert_eq!(ctx.role, Role::Analyst);
        assert!(ctx.has_permission(Permission::ReadIncidents));
        assert!(ctx.has_permission(Permission::WriteIncidents));
        assert!(ctx.has_permission(Permission::ApproveActions));
        assert!(!ctx.has_permission(Permission::ManageUsers));
    }

    #[test]
    fn test_authorization_context_system() {
        let ctx = AuthorizationContext::system();

        assert_eq!(ctx.actor_id, Uuid::nil());
        assert_eq!(ctx.actor_name, "system");
        assert_eq!(ctx.role, Role::Admin);
        // System context has all permissions
        assert!(ctx.has_permission(Permission::ManageUsers));
        assert!(ctx.has_permission(Permission::ManageKillSwitch));
    }

    #[test]
    fn test_authorization_context_viewer_permissions() {
        let user = User::new("viewer@example.com", "viewer", "hash", Role::Viewer);
        let ctx = AuthorizationContext::from_user(&user);

        assert!(ctx.has_permission(Permission::ReadIncidents));
        assert!(!ctx.has_permission(Permission::WriteIncidents));
        assert!(!ctx.has_permission(Permission::ApproveActions));
        assert!(!ctx.has_permission(Permission::ExecuteActions));
    }

    #[test]
    fn test_authorization_context_with_session_and_ip() {
        let user = User::new("test@example.com", "testuser", "hash", Role::Analyst);
        let ctx = AuthorizationContext::from_user(&user)
            .with_session("session-123")
            .with_ip_address("192.168.1.100");

        assert_eq!(ctx.session_id, Some("session-123".to_string()));
        assert_eq!(ctx.ip_address, Some("192.168.1.100".to_string()));
    }

    #[test]
    fn test_authorization_context_has_all_permissions() {
        let user = User::new("admin@example.com", "admin", "hash", Role::Admin);
        let ctx = AuthorizationContext::from_user(&user);

        assert!(ctx.has_all_permissions(&[
            Permission::ReadIncidents,
            Permission::WriteIncidents,
            Permission::ManageUsers
        ]));

        let viewer = User::new("viewer@example.com", "viewer", "hash", Role::Viewer);
        let viewer_ctx = AuthorizationContext::from_user(&viewer);
        assert!(!viewer_ctx
            .has_all_permissions(&[Permission::ReadIncidents, Permission::WriteIncidents,]));
    }

    #[test]
    fn test_authorization_context_has_any_permission() {
        let viewer = User::new("viewer@example.com", "viewer", "hash", Role::Viewer);
        let ctx = AuthorizationContext::from_user(&viewer);

        assert!(ctx.has_any_permission(&[Permission::ReadIncidents, Permission::WriteIncidents,]));
        assert!(!ctx.has_any_permission(&[Permission::ManageUsers, Permission::ManageSettings,]));
    }

    #[test]
    fn test_audit_identity() {
        let user = User::new("test@example.com", "testuser", "hash", Role::Analyst);
        let ctx = AuthorizationContext::from_user(&user);

        let identity = ctx.audit_identity();
        assert!(identity.contains(&user.id.to_string()));
        assert!(identity.contains("testuser"));
    }
}
