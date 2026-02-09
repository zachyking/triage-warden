//! Just-in-time user provisioning for federated authentication.
//!
//! This module creates or updates local users from IdP claims and applies
//! tenant-scoped role mapping rules.

use crate::error::ApiError;
use chrono::Utc;
use rand::rngs::OsRng;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, warn};
use tw_core::auth::{Role, User, UserUpdate, DEFAULT_TENANT_ID};
use tw_core::db::{create_user_repository, DbPool};
use tw_core::hash_password;
use uuid::Uuid;

/// Normalized SSO claim set used for JIT provisioning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoClaims {
    /// Stable subject identifier from IdP.
    pub subject: String,
    /// User email.
    pub email: String,
    /// Optional display name.
    pub display_name: Option<String>,
    /// Group memberships from IdP.
    pub groups: Vec<String>,
    /// Role labels from IdP.
    pub roles: Vec<String>,
    /// Optional tenant identifier from IdP claim.
    pub tenant_id: Option<Uuid>,
    /// Whether the account is active at the IdP.
    pub active: bool,
    /// Whether MFA assurance is present.
    pub mfa_verified: bool,
    /// Optional IdP session id for coordinated logout.
    pub session_id: Option<String>,
}

impl SsoClaims {
    /// Returns a canonical principal string for audit events.
    pub fn principal(&self) -> String {
        format!("{} ({})", self.email, self.subject)
    }
}

/// JIT provisioning service.
#[derive(Debug, Clone)]
pub struct UserProvisioner {
    role_mapping: HashMap<String, Role>,
    default_role: Role,
    allow_auto_create: bool,
}

impl Default for UserProvisioner {
    fn default() -> Self {
        Self::from_env()
    }
}

impl UserProvisioner {
    /// Creates a provisioner from environment configuration.
    ///
    /// Supported environment variables:
    /// - `TW_SSO_ROLE_MAPPING`: `group_or_role=internal_role,...`
    /// - `TW_SSO_DEFAULT_ROLE`: `viewer|analyst|admin`
    /// - `TW_SSO_AUTO_CREATE_USERS`: `true|false` (default `true`)
    pub fn from_env() -> Self {
        let default_role = std::env::var("TW_SSO_DEFAULT_ROLE")
            .ok()
            .and_then(|value| parse_role(&value))
            .unwrap_or(Role::Viewer);

        let allow_auto_create = std::env::var("TW_SSO_AUTO_CREATE_USERS")
            .ok()
            .map(|value| matches!(value.to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
            .unwrap_or(true);

        let role_mapping =
            parse_role_mapping(&std::env::var("TW_SSO_ROLE_MAPPING").unwrap_or_else(|_| {
                "soc_admin=admin,soc_analyst=analyst,soc_viewer=viewer".into()
            }));

        Self {
            role_mapping,
            default_role,
            allow_auto_create,
        }
    }

    /// Resolves role from IdP groups/roles according to configured mapping.
    pub fn determine_role(&self, claims: &SsoClaims) -> Role {
        for external in claims.groups.iter().chain(claims.roles.iter()) {
            if let Some(mapped) = self.role_mapping.get(&external.to_lowercase()) {
                return *mapped;
            }
        }
        self.default_role
    }

    /// Creates or updates a user record from SSO claims.
    pub async fn provision_from_claims(
        &self,
        db: &DbPool,
        claims: &SsoClaims,
    ) -> Result<User, ApiError> {
        let tenant_id = claims.tenant_id.unwrap_or(DEFAULT_TENANT_ID);
        let user_repo = create_user_repository(db);
        let role = self.determine_role(claims);

        if let Some(mut existing) = user_repo
            .get_by_email_for_tenant(&claims.email, tenant_id)
            .await
            .map_err(|e| ApiError::Database(e.to_string()))?
        {
            let update = UserUpdate {
                email: Some(claims.email.clone()),
                username: None,
                role: Some(role),
                display_name: Some(claims.display_name.clone()),
                enabled: Some(claims.active),
            };

            existing = user_repo
                .update_for_tenant(existing.id, tenant_id, &update)
                .await
                .map_err(|e| ApiError::Database(e.to_string()))?;

            info!(
                user_id = %existing.id,
                tenant_id = %tenant_id,
                role = %existing.role,
                active = claims.active,
                "Updated existing user from SSO claims"
            );
            return Ok(existing);
        }

        if !self.allow_auto_create {
            warn!(
                email = %claims.email,
                tenant_id = %tenant_id,
                "SSO auto-provisioning disabled; rejecting unknown principal"
            );
            return Err(ApiError::Unauthorized(
                "User is not provisioned for this tenant".to_string(),
            ));
        }

        if !claims.active {
            return Err(ApiError::Unauthorized(
                "Identity provider account is not active".to_string(),
            ));
        }

        let username = self
            .generate_unique_username(db, tenant_id, &claims.email)
            .await?;
        let password_hash = generate_random_password_hash().map_err(|e| {
            ApiError::Internal(format!("failed to generate bootstrap credential: {e}"))
        })?;

        let mut user =
            User::new_for_tenant(tenant_id, &claims.email, username, password_hash, role);
        user.display_name = claims.display_name.clone();
        user.enabled = true;
        user.created_at = Utc::now();
        user.updated_at = user.created_at;

        let created = user_repo
            .create(&user)
            .await
            .map_err(|e| ApiError::Database(e.to_string()))?;

        info!(
            user_id = %created.id,
            tenant_id = %tenant_id,
            role = %created.role,
            principal = %claims.principal(),
            "Provisioned new SSO user"
        );

        Ok(created)
    }

    /// Disables local account when IdP marks principal inactive.
    pub async fn deprovision_if_inactive(
        &self,
        db: &DbPool,
        claims: &SsoClaims,
    ) -> Result<(), ApiError> {
        if claims.active {
            return Ok(());
        }

        let tenant_id = claims.tenant_id.unwrap_or(DEFAULT_TENANT_ID);
        let user_repo = create_user_repository(db);

        if let Some(user) = user_repo
            .get_by_email_for_tenant(&claims.email, tenant_id)
            .await
            .map_err(|e| ApiError::Database(e.to_string()))?
        {
            if user.enabled {
                let update = UserUpdate {
                    email: None,
                    username: None,
                    role: None,
                    display_name: None,
                    enabled: Some(false),
                };
                user_repo
                    .update_for_tenant(user.id, tenant_id, &update)
                    .await
                    .map_err(|e| ApiError::Database(e.to_string()))?;
                info!(
                    user_id = %user.id,
                    tenant_id = %tenant_id,
                    "Deprovisioned inactive SSO user"
                );
            }
        }

        Ok(())
    }

    async fn generate_unique_username(
        &self,
        db: &DbPool,
        tenant_id: Uuid,
        email: &str,
    ) -> Result<String, ApiError> {
        let base = sanitize_username(email);
        let user_repo = create_user_repository(db);

        if user_repo
            .get_by_username_for_tenant(&base, tenant_id)
            .await
            .map_err(|e| ApiError::Database(e.to_string()))?
            .is_none()
        {
            return Ok(base);
        }

        for suffix in 1..10_000u32 {
            let candidate = format!("{base}{suffix}");
            if user_repo
                .get_by_username_for_tenant(&candidate, tenant_id)
                .await
                .map_err(|e| ApiError::Database(e.to_string()))?
                .is_none()
            {
                return Ok(candidate);
            }
        }

        Err(ApiError::Internal(
            "unable to allocate unique username for SSO principal".to_string(),
        ))
    }
}

fn sanitize_username(email: &str) -> String {
    let local = email.split('@').next().unwrap_or("user");
    let mut normalized = String::with_capacity(local.len());
    for c in local.chars() {
        if c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' {
            normalized.push(c.to_ascii_lowercase());
        }
    }

    if normalized.is_empty() {
        "user".to_string()
    } else {
        normalized
    }
}

fn generate_random_password_hash() -> Result<String, tw_core::auth::password::PasswordError> {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut secret = String::with_capacity(40);
    for _ in 0..40 {
        let idx = OsRng.gen_range(0..CHARSET.len());
        secret.push(CHARSET[idx] as char);
    }
    hash_password(&secret)
}

fn parse_role_mapping(value: &str) -> HashMap<String, Role> {
    let mut mapping = HashMap::new();
    for raw_entry in value.split(',') {
        let entry = raw_entry.trim();
        if entry.is_empty() {
            continue;
        }

        let Some((external, role_str)) = entry.split_once('=') else {
            continue;
        };
        if let Some(role) = parse_role(role_str) {
            mapping.insert(external.trim().to_lowercase(), role);
        }
    }
    mapping
}

fn parse_role(value: &str) -> Option<Role> {
    match value.trim().to_ascii_lowercase().as_str() {
        "admin" | "super_admin" | "tenant_admin" => Some(Role::Admin),
        "analyst" | "soc_manager" | "senior_analyst" => Some(Role::Analyst),
        "viewer" | "readonly" | "read_only" => Some(Role::Viewer),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_determine_role_prefers_mapping() {
        let provisioner = UserProvisioner {
            role_mapping: HashMap::from([
                ("grp-admin".to_string(), Role::Admin),
                ("grp-analyst".to_string(), Role::Analyst),
            ]),
            default_role: Role::Viewer,
            allow_auto_create: true,
        };

        let claims = SsoClaims {
            subject: "sub-1".to_string(),
            email: "user@example.com".to_string(),
            display_name: None,
            groups: vec!["grp-analyst".to_string()],
            roles: vec![],
            tenant_id: None,
            active: true,
            mfa_verified: true,
            session_id: None,
        };

        assert_eq!(provisioner.determine_role(&claims), Role::Analyst);
    }

    #[test]
    fn test_sanitize_username() {
        assert_eq!(
            sanitize_username("Alice.SOC+prod@example.com"),
            "alice.socprod"
        );
        assert_eq!(sanitize_username("@example.com"), "user");
    }

    #[test]
    fn test_parse_role_mapping() {
        let map = parse_role_mapping("idp-admin=admin,idp-ro=viewer,idp-bad=unknown");
        assert_eq!(map.get("idp-admin"), Some(&Role::Admin));
        assert_eq!(map.get("idp-ro"), Some(&Role::Viewer));
        assert!(!map.contains_key("idp-bad"));
    }
}
