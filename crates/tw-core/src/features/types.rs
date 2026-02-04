//! Feature flag types and storage trait.
//!
//! This module defines the core types for the feature flag system:
//! - `FeatureFlag`: The feature flag entity
//! - `FeatureFlagStore`: Persistence abstraction
//! - `FeatureFlagError`: Error types

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use uuid::Uuid;

/// Errors that can occur during feature flag operations.
#[derive(Error, Debug, Clone)]
pub enum FeatureFlagError {
    /// Feature flag not found.
    #[error("Feature flag not found: {0}")]
    NotFound(String),

    /// Storage operation failed.
    #[error("Storage error: {0}")]
    Storage(String),

    /// Invalid percentage rollout value.
    #[error("Invalid percentage: {0}. Must be between 0 and 100.")]
    InvalidPercentage(u8),
}

/// A feature flag for controlling feature availability.
///
/// Feature flags support:
/// - Global default state (enabled/disabled)
/// - Per-tenant overrides
/// - Percentage-based rollouts (deterministic per tenant)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureFlag {
    /// Unique name identifier for the flag (e.g., "new_dashboard", "beta_ai_model").
    pub name: String,

    /// Human-readable description of what this flag controls.
    pub description: String,

    /// Whether the flag is enabled by default when no overrides apply.
    pub default_enabled: bool,

    /// Per-tenant overrides. Key is tenant ID, value is enabled/disabled.
    pub tenant_overrides: HashMap<Uuid, bool>,

    /// Optional percentage rollout (0-100).
    /// When set, the flag is enabled for this percentage of tenants
    /// (determined by hashing tenant_id + flag_name).
    /// Tenant overrides take precedence over percentage rollout.
    pub percentage_rollout: Option<u8>,

    /// Timestamp when the flag was created.
    pub created_at: DateTime<Utc>,

    /// Timestamp of the last update.
    pub updated_at: DateTime<Utc>,
}

impl FeatureFlag {
    /// Creates a new feature flag with the given name and default state.
    ///
    /// # Errors
    ///
    /// Returns `FeatureFlagError::InvalidPercentage` if `percentage_rollout` is > 100.
    pub fn new(
        name: &str,
        description: &str,
        default_enabled: bool,
        percentage_rollout: Option<u8>,
    ) -> Result<Self, FeatureFlagError> {
        if let Some(pct) = percentage_rollout {
            if pct > 100 {
                return Err(FeatureFlagError::InvalidPercentage(pct));
            }
        }

        let now = Utc::now();
        Ok(Self {
            name: name.to_string(),
            description: description.to_string(),
            default_enabled,
            tenant_overrides: HashMap::new(),
            percentage_rollout,
            created_at: now,
            updated_at: now,
        })
    }

    /// Sets a tenant-specific override for this flag.
    pub fn set_tenant_override(&mut self, tenant_id: Uuid, enabled: bool) {
        self.tenant_overrides.insert(tenant_id, enabled);
        self.updated_at = Utc::now();
    }

    /// Removes a tenant-specific override for this flag.
    pub fn remove_tenant_override(&mut self, tenant_id: &Uuid) -> bool {
        let removed = self.tenant_overrides.remove(tenant_id).is_some();
        if removed {
            self.updated_at = Utc::now();
        }
        removed
    }

    /// Sets the percentage rollout for this flag.
    ///
    /// # Errors
    ///
    /// Returns `FeatureFlagError::InvalidPercentage` if `percentage` is > 100.
    pub fn set_percentage_rollout(
        &mut self,
        percentage: Option<u8>,
    ) -> Result<(), FeatureFlagError> {
        if let Some(pct) = percentage {
            if pct > 100 {
                return Err(FeatureFlagError::InvalidPercentage(pct));
            }
        }
        self.percentage_rollout = percentage;
        self.updated_at = Utc::now();
        Ok(())
    }

    /// Returns true if the flag has any tenant overrides.
    pub fn has_overrides(&self) -> bool {
        !self.tenant_overrides.is_empty()
    }
}

/// Persistence abstraction for feature flags.
///
/// Implementations can store flags in various backends:
/// - Database (SQLite, PostgreSQL)
/// - Configuration files
/// - Remote services (LaunchDarkly, etc.)
#[async_trait]
pub trait FeatureFlagStore: Send + Sync + 'static {
    /// Lists all feature flags.
    async fn list(&self) -> Result<Vec<FeatureFlag>, FeatureFlagError>;

    /// Gets a feature flag by name.
    async fn get(&self, name: &str) -> Result<Option<FeatureFlag>, FeatureFlagError>;

    /// Creates or updates a feature flag.
    async fn upsert(&self, flag: &FeatureFlag) -> Result<(), FeatureFlagError>;

    /// Deletes a feature flag by name.
    /// Returns true if the flag existed and was deleted.
    async fn delete(&self, name: &str) -> Result<bool, FeatureFlagError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feature_flag_creation() {
        let flag =
            FeatureFlag::new("new_feature", "A new feature for testing", false, None).unwrap();

        assert_eq!(flag.name, "new_feature");
        assert_eq!(flag.description, "A new feature for testing");
        assert!(!flag.default_enabled);
        assert!(flag.percentage_rollout.is_none());
        assert!(flag.tenant_overrides.is_empty());
    }

    #[test]
    fn test_feature_flag_with_percentage() {
        let flag = FeatureFlag::new(
            "gradual_rollout",
            "Feature with gradual rollout",
            false,
            Some(50),
        )
        .unwrap();

        assert_eq!(flag.percentage_rollout, Some(50));
    }

    #[test]
    fn test_feature_flag_invalid_percentage() {
        let result = FeatureFlag::new("invalid", "Invalid percentage", false, Some(101));

        assert!(matches!(
            result,
            Err(FeatureFlagError::InvalidPercentage(101))
        ));
    }

    #[test]
    fn test_feature_flag_tenant_override() {
        let mut flag = FeatureFlag::new("beta_feature", "Beta feature", false, None).unwrap();

        let tenant_id = Uuid::new_v4();
        flag.set_tenant_override(tenant_id, true);

        assert!(flag.has_overrides());
        assert_eq!(flag.tenant_overrides.get(&tenant_id), Some(&true));
    }

    #[test]
    fn test_feature_flag_remove_tenant_override() {
        let mut flag = FeatureFlag::new("beta_feature", "Beta feature", false, None).unwrap();

        let tenant_id = Uuid::new_v4();
        flag.set_tenant_override(tenant_id, true);
        assert!(flag.has_overrides());

        let removed = flag.remove_tenant_override(&tenant_id);
        assert!(removed);
        assert!(!flag.has_overrides());

        // Removing again should return false
        let removed_again = flag.remove_tenant_override(&tenant_id);
        assert!(!removed_again);
    }

    #[test]
    fn test_feature_flag_set_percentage_rollout() {
        let mut flag = FeatureFlag::new("gradual", "Gradual rollout", false, None).unwrap();

        assert!(flag.percentage_rollout.is_none());

        flag.set_percentage_rollout(Some(25)).unwrap();
        assert_eq!(flag.percentage_rollout, Some(25));

        flag.set_percentage_rollout(Some(100)).unwrap();
        assert_eq!(flag.percentage_rollout, Some(100));

        flag.set_percentage_rollout(None).unwrap();
        assert!(flag.percentage_rollout.is_none());
    }

    #[test]
    fn test_feature_flag_set_invalid_percentage_rollout() {
        let mut flag = FeatureFlag::new("gradual", "Gradual rollout", false, None).unwrap();

        let result = flag.set_percentage_rollout(Some(150));
        assert!(matches!(
            result,
            Err(FeatureFlagError::InvalidPercentage(150))
        ));
    }

    #[test]
    fn test_feature_flag_serialization() {
        let mut flag =
            FeatureFlag::new("serializable", "A serializable flag", true, Some(75)).unwrap();

        let tenant_id = Uuid::new_v4();
        flag.set_tenant_override(tenant_id, false);

        let json = serde_json::to_string(&flag).unwrap();
        let parsed: FeatureFlag = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.name, flag.name);
        assert_eq!(parsed.description, flag.description);
        assert_eq!(parsed.default_enabled, flag.default_enabled);
        assert_eq!(parsed.percentage_rollout, flag.percentage_rollout);
        assert_eq!(parsed.tenant_overrides.get(&tenant_id), Some(&false));
    }

    #[test]
    fn test_feature_flag_error_display() {
        let not_found = FeatureFlagError::NotFound("missing_flag".to_string());
        assert!(not_found.to_string().contains("missing_flag"));

        let storage = FeatureFlagError::Storage("connection failed".to_string());
        assert!(storage.to_string().contains("connection failed"));

        let invalid_pct = FeatureFlagError::InvalidPercentage(150);
        assert!(invalid_pct.to_string().contains("150"));
    }
}
