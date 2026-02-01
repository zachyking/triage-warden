//! Authentication and authorization types for Triage Warden.
//!
//! This module provides core authentication types including:
//! - User and Role definitions
//! - API key management
//! - Session data structures
//! - Password hashing utilities

pub mod password;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

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
    /// Creates a new API key. Returns the key struct and the raw key value.
    pub fn new(user_id: Uuid, name: impl Into<String>, scopes: Vec<String>) -> (Self, String) {
        use rand::Rng;
        use sha2::{Digest, Sha256};

        // Generate a random key: tw_<prefix>_<secret>
        let mut rng = rand::thread_rng();
        let prefix: String = (0..6)
            .map(|_| {
                let idx = rng.gen_range(0..36);
                if idx < 10 {
                    (b'0' + idx) as char
                } else {
                    (b'a' + idx - 10) as char
                }
            })
            .collect();
        let secret: String = (0..32)
            .map(|_| {
                let idx = rng.gen_range(0..36);
                if idx < 10 {
                    (b'0' + idx) as char
                } else {
                    (b'a' + idx - 10) as char
                }
            })
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
        use rand::Rng;

        let csrf_token: String = rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(32)
            .map(char::from)
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
}
