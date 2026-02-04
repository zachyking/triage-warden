//! Multi-tenant support for Triage Warden.
//!
//! This module provides tenant isolation primitives including:
//! - `Tenant`: The tenant entity with configuration and metadata
//! - `TenantContext`: Lightweight request-scoped tenant context
//! - `TenantSettings`: Per-tenant configuration (LLM, limits, features)
//! - `TenantStatus`: Tenant lifecycle states
//!
//! # Example
//!
//! ```rust
//! use tw_core::tenant::{Tenant, TenantContext, TenantSettings, TenantStatus};
//! use std::sync::Arc;
//!
//! // Create a new tenant
//! let tenant = Tenant::new("acme-corp", "Acme Corporation").unwrap();
//!
//! // Create a request-scoped context (cheap to clone)
//! let ctx = TenantContext::from_tenant(&tenant);
//!
//! // Pass context through request handlers
//! assert_eq!(ctx.tenant_slug, "acme-corp");
//! ```

mod types;

pub use types::{TenantSettings, TenantStatus};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;

/// Errors that can occur during tenant operations.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum TenantError {
    /// Slug validation failed.
    #[error("Invalid tenant slug: {0}")]
    InvalidSlug(String),

    /// Tenant not found.
    #[error("Tenant not found: {0}")]
    NotFound(Uuid),

    /// Tenant is not in an operational state.
    #[error("Tenant is not operational (status: {0})")]
    NotOperational(TenantStatus),
}

/// Validates a tenant slug according to the following rules:
/// - Lowercase alphanumeric characters and hyphens only
/// - Must be 3-63 characters long
/// - Must start with a letter
/// - Cannot end with a hyphen
/// - No consecutive hyphens
fn validate_slug(slug: &str) -> Result<(), TenantError> {
    // Length check: 3-63 characters
    if slug.len() < 3 || slug.len() > 63 {
        return Err(TenantError::InvalidSlug(format!(
            "Slug must be between 3 and 63 characters, got {}",
            slug.len()
        )));
    }

    // Must start with a letter
    let first_char = slug.chars().next().unwrap();
    if !first_char.is_ascii_lowercase() {
        return Err(TenantError::InvalidSlug(
            "Slug must start with a lowercase letter".to_string(),
        ));
    }

    // Cannot end with a hyphen
    if slug.ends_with('-') {
        return Err(TenantError::InvalidSlug(
            "Slug cannot end with a hyphen".to_string(),
        ));
    }

    // Check all characters and consecutive hyphens
    let mut prev_hyphen = false;
    for ch in slug.chars() {
        if ch == '-' {
            if prev_hyphen {
                return Err(TenantError::InvalidSlug(
                    "Slug cannot contain consecutive hyphens".to_string(),
                ));
            }
            prev_hyphen = true;
        } else if ch.is_ascii_lowercase() || ch.is_ascii_digit() {
            prev_hyphen = false;
        } else {
            return Err(TenantError::InvalidSlug(format!(
                "Slug contains invalid character '{}'. Only lowercase letters, digits, and hyphens are allowed",
                ch
            )));
        }
    }

    Ok(())
}

/// Represents a tenant in the multi-tenant system.
///
/// A tenant is an isolated organization with its own:
/// - Users and permissions
/// - Incidents and alerts
/// - Configuration and settings
/// - Feature flag overrides
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tenant {
    /// Unique identifier for this tenant.
    pub id: Uuid,

    /// Display name of the tenant/organization.
    pub name: String,

    /// URL-safe identifier used for subdomains and routing.
    /// Must be lowercase alphanumeric with hyphens, 3-63 chars, starting with a letter.
    pub slug: String,

    /// Current lifecycle status of the tenant.
    pub status: TenantStatus,

    /// Tenant-specific configuration settings.
    pub settings: TenantSettings,

    /// Timestamp when the tenant was created.
    pub created_at: DateTime<Utc>,

    /// Timestamp of the last update.
    pub updated_at: DateTime<Utc>,
}

impl Tenant {
    /// Creates a new tenant with the given slug and name.
    ///
    /// The slug will be validated according to these rules:
    /// - Lowercase alphanumeric characters and hyphens only
    /// - Must be 3-63 characters long
    /// - Must start with a letter
    /// - Cannot end with a hyphen
    /// - No consecutive hyphens
    ///
    /// # Errors
    ///
    /// Returns `TenantError::InvalidSlug` if the slug doesn't meet the requirements.
    pub fn new(slug: &str, name: &str) -> Result<Self, TenantError> {
        validate_slug(slug)?;

        let now = Utc::now();
        Ok(Self {
            id: Uuid::new_v4(),
            name: name.to_string(),
            slug: slug.to_string(),
            status: TenantStatus::Active,
            settings: TenantSettings::default(),
            created_at: now,
            updated_at: now,
        })
    }

    /// Creates a new tenant with a specific ID (for deserialization/testing).
    pub fn with_id(id: Uuid, slug: &str, name: &str) -> Result<Self, TenantError> {
        validate_slug(slug)?;

        let now = Utc::now();
        Ok(Self {
            id,
            name: name.to_string(),
            slug: slug.to_string(),
            status: TenantStatus::Active,
            settings: TenantSettings::default(),
            created_at: now,
            updated_at: now,
        })
    }

    /// Returns true if the tenant is in an operational state.
    pub fn is_operational(&self) -> bool {
        self.status.is_operational()
    }

    /// Updates the tenant settings.
    pub fn update_settings(&mut self, settings: TenantSettings) {
        self.settings = settings;
        self.updated_at = Utc::now();
    }

    /// Updates the tenant status.
    pub fn update_status(&mut self, status: TenantStatus) {
        self.status = status;
        self.updated_at = Utc::now();
    }
}

/// Request-scoped tenant context.
///
/// This is a lightweight structure designed to be passed through request
/// handlers and service calls. It contains the essential tenant information
/// needed for most operations.
///
/// The `settings` field uses `Arc` to make cloning cheap - the actual
/// settings data is shared rather than copied.
///
/// # Example
///
/// ```rust
/// use tw_core::tenant::{Tenant, TenantContext};
///
/// let tenant = Tenant::new("my-org", "My Organization").unwrap();
/// let ctx = TenantContext::from_tenant(&tenant);
///
/// // Clone is cheap - just Arc reference counting
/// let ctx2 = ctx.clone();
/// assert_eq!(ctx.tenant_id, ctx2.tenant_id);
/// ```
#[derive(Debug, Clone)]
pub struct TenantContext {
    /// The tenant's unique identifier.
    pub tenant_id: Uuid,

    /// The tenant's URL-safe slug.
    pub tenant_slug: String,

    /// Shared reference to tenant settings (cheap to clone).
    pub settings: Arc<TenantSettings>,
}

impl TenantContext {
    /// Creates a new tenant context from a tenant entity.
    pub fn from_tenant(tenant: &Tenant) -> Self {
        Self {
            tenant_id: tenant.id,
            tenant_slug: tenant.slug.clone(),
            settings: Arc::new(tenant.settings.clone()),
        }
    }

    /// Creates a new tenant context with explicit values.
    pub fn new(tenant_id: Uuid, tenant_slug: String, settings: Arc<TenantSettings>) -> Self {
        Self {
            tenant_id,
            tenant_slug,
            settings,
        }
    }

    /// Returns the default operation mode for this tenant.
    pub fn operation_mode(&self) -> crate::orchestrator::OperationMode {
        self.settings.default_operation_mode
    }

    /// Returns the concurrency limit for this tenant.
    pub fn concurrency_limit(&self) -> u32 {
        self.settings.concurrency_limit
    }

    /// Checks if a feature is explicitly overridden for this tenant.
    pub fn get_feature_override(&self, feature: &str) -> Option<bool> {
        self.settings.feature_overrides.get(feature).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orchestrator::OperationMode;

    #[test]
    fn test_tenant_creation() {
        let tenant = Tenant::new("acme-corp", "Acme Corporation").unwrap();
        assert_eq!(tenant.slug, "acme-corp");
        assert_eq!(tenant.name, "Acme Corporation");
        assert_eq!(tenant.status, TenantStatus::Active);
        assert!(tenant.is_operational());
    }

    #[test]
    fn test_tenant_with_id() {
        let id = Uuid::new_v4();
        let tenant = Tenant::with_id(id, "test-tenant", "Test Tenant").unwrap();
        assert_eq!(tenant.id, id);
        assert_eq!(tenant.slug, "test-tenant");
    }

    #[test]
    fn test_slug_validation_valid() {
        // Valid slugs
        assert!(validate_slug("abc").is_ok());
        assert!(validate_slug("my-tenant").is_ok());
        assert!(validate_slug("tenant123").is_ok());
        assert!(validate_slug("a-b-c").is_ok());
        assert!(validate_slug("org-name-with-numbers-123").is_ok());
        // 63 character slug
        assert!(validate_slug("a".repeat(63).as_str()).is_ok());
    }

    #[test]
    fn test_slug_validation_invalid_length() {
        // Too short
        assert!(validate_slug("ab").is_err());
        // Too long (64 characters)
        assert!(validate_slug(&"a".repeat(64)).is_err());
    }

    #[test]
    fn test_slug_validation_must_start_with_letter() {
        assert!(validate_slug("1tenant").is_err());
        assert!(validate_slug("-tenant").is_err());
    }

    #[test]
    fn test_slug_validation_cannot_end_with_hyphen() {
        assert!(validate_slug("tenant-").is_err());
    }

    #[test]
    fn test_slug_validation_no_consecutive_hyphens() {
        assert!(validate_slug("my--tenant").is_err());
    }

    #[test]
    fn test_slug_validation_lowercase_only() {
        assert!(validate_slug("MyTenant").is_err());
        assert!(validate_slug("TENANT").is_err());
    }

    #[test]
    fn test_slug_validation_no_special_chars() {
        assert!(validate_slug("my_tenant").is_err());
        assert!(validate_slug("my.tenant").is_err());
        assert!(validate_slug("my@tenant").is_err());
    }

    #[test]
    fn test_tenant_context_from_tenant() {
        let tenant = Tenant::new("test-org", "Test Organization").unwrap();
        let ctx = TenantContext::from_tenant(&tenant);

        assert_eq!(ctx.tenant_id, tenant.id);
        assert_eq!(ctx.tenant_slug, tenant.slug);
        assert_eq!(ctx.operation_mode(), OperationMode::Assisted);
        assert_eq!(ctx.concurrency_limit(), 10);
    }

    #[test]
    fn test_tenant_context_clone_is_cheap() {
        let tenant = Tenant::new("test-org", "Test Organization").unwrap();
        let ctx1 = TenantContext::from_tenant(&tenant);
        let ctx2 = ctx1.clone();

        // Both contexts share the same Arc<TenantSettings>
        assert!(Arc::ptr_eq(&ctx1.settings, &ctx2.settings));
    }

    #[test]
    fn test_tenant_context_feature_override() {
        let mut tenant = Tenant::new("test-org", "Test Organization").unwrap();
        tenant
            .settings
            .feature_overrides
            .insert("beta_feature".to_string(), true);
        tenant
            .settings
            .feature_overrides
            .insert("deprecated_feature".to_string(), false);

        let ctx = TenantContext::from_tenant(&tenant);

        assert_eq!(ctx.get_feature_override("beta_feature"), Some(true));
        assert_eq!(ctx.get_feature_override("deprecated_feature"), Some(false));
        assert_eq!(ctx.get_feature_override("unknown_feature"), None);
    }

    #[test]
    fn test_tenant_update_settings() {
        let mut tenant = Tenant::new("test-org", "Test Organization").unwrap();
        let original_updated_at = tenant.updated_at;

        // Small delay to ensure timestamp changes
        std::thread::sleep(std::time::Duration::from_millis(10));

        let mut new_settings = TenantSettings::default();
        new_settings.concurrency_limit = 50;
        tenant.update_settings(new_settings);

        assert_eq!(tenant.settings.concurrency_limit, 50);
        assert!(tenant.updated_at > original_updated_at);
    }

    #[test]
    fn test_tenant_update_status() {
        let mut tenant = Tenant::new("test-org", "Test Organization").unwrap();
        assert!(tenant.is_operational());

        tenant.update_status(TenantStatus::Suspended);
        assert_eq!(tenant.status, TenantStatus::Suspended);
        assert!(!tenant.is_operational());

        tenant.update_status(TenantStatus::PendingDeletion);
        assert_eq!(tenant.status, TenantStatus::PendingDeletion);
        assert!(!tenant.is_operational());
    }

    #[test]
    fn test_tenant_serialization() {
        let tenant = Tenant::new("test-org", "Test Organization").unwrap();
        let json = serde_json::to_string(&tenant).unwrap();
        let parsed: Tenant = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.id, tenant.id);
        assert_eq!(parsed.slug, tenant.slug);
        assert_eq!(parsed.name, tenant.name);
        assert_eq!(parsed.status, tenant.status);
    }
}
