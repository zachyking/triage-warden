//! Tenant settings and status types.
//!
//! This module defines the tenant configuration and lifecycle status types
//! used for multi-tenant isolation in Triage Warden.

use crate::orchestrator::OperationMode;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Status of a tenant in the system lifecycle.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum TenantStatus {
    /// Tenant is active and operational.
    #[default]
    Active,
    /// Tenant is suspended (e.g., billing issue, policy violation).
    /// No operations are permitted except read-only access.
    Suspended,
    /// Tenant is pending deletion.
    /// Data retention period before permanent removal.
    PendingDeletion,
}

impl TenantStatus {
    /// Returns the database-compatible string representation (snake_case).
    pub fn as_db_str(&self) -> &'static str {
        match self {
            TenantStatus::Active => "active",
            TenantStatus::Suspended => "suspended",
            TenantStatus::PendingDeletion => "pending_deletion",
        }
    }

    /// Returns true if the tenant can perform operations.
    pub fn is_operational(&self) -> bool {
        matches!(self, TenantStatus::Active)
    }
}

impl std::fmt::Display for TenantStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TenantStatus::Active => write!(f, "Active"),
            TenantStatus::Suspended => write!(f, "Suspended"),
            TenantStatus::PendingDeletion => write!(f, "Pending Deletion"),
        }
    }
}

/// Configuration settings for a tenant.
///
/// These settings control the tenant's LLM provider, operation mode,
/// concurrency limits, and feature flag overrides.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantSettings {
    /// LLM provider name (e.g., "openai", "anthropic", "azure").
    /// If None, uses the system default.
    pub llm_provider: Option<String>,

    /// Reference to the tenant's LLM API key in the secrets store.
    /// This is NOT the actual key - it's a reference/path to retrieve it.
    pub llm_api_key_ref: Option<String>,

    /// Default operation mode for this tenant.
    /// Controls the level of automation for incident triage.
    pub default_operation_mode: OperationMode,

    /// Maximum concurrent incident processing limit for this tenant.
    /// Prevents resource exhaustion in multi-tenant environments.
    pub concurrency_limit: u32,

    /// Per-tenant feature flag overrides.
    /// Keys are feature flag names, values indicate enabled/disabled.
    /// These override the global feature flag settings.
    pub feature_overrides: HashMap<String, bool>,
}

impl Default for TenantSettings {
    fn default() -> Self {
        Self {
            llm_provider: None,
            llm_api_key_ref: None,
            default_operation_mode: OperationMode::Assisted,
            concurrency_limit: 10,
            feature_overrides: HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tenant_status_default() {
        let status = TenantStatus::default();
        assert_eq!(status, TenantStatus::Active);
    }

    #[test]
    fn test_tenant_status_is_operational() {
        assert!(TenantStatus::Active.is_operational());
        assert!(!TenantStatus::Suspended.is_operational());
        assert!(!TenantStatus::PendingDeletion.is_operational());
    }

    #[test]
    fn test_tenant_status_as_db_str() {
        assert_eq!(TenantStatus::Active.as_db_str(), "active");
        assert_eq!(TenantStatus::Suspended.as_db_str(), "suspended");
        assert_eq!(
            TenantStatus::PendingDeletion.as_db_str(),
            "pending_deletion"
        );
    }

    #[test]
    fn test_tenant_status_display() {
        assert_eq!(TenantStatus::Active.to_string(), "Active");
        assert_eq!(TenantStatus::Suspended.to_string(), "Suspended");
        assert_eq!(
            TenantStatus::PendingDeletion.to_string(),
            "Pending Deletion"
        );
    }

    #[test]
    fn test_tenant_settings_default() {
        let settings = TenantSettings::default();
        assert!(settings.llm_provider.is_none());
        assert!(settings.llm_api_key_ref.is_none());
        assert_eq!(settings.default_operation_mode, OperationMode::Assisted);
        assert_eq!(settings.concurrency_limit, 10);
        assert!(settings.feature_overrides.is_empty());
    }

    #[test]
    fn test_tenant_settings_serialization() {
        let mut settings = TenantSettings::default();
        settings.llm_provider = Some("anthropic".to_string());
        settings.concurrency_limit = 20;
        settings
            .feature_overrides
            .insert("new_ui".to_string(), true);

        let json = serde_json::to_string(&settings).unwrap();
        let parsed: TenantSettings = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.llm_provider, Some("anthropic".to_string()));
        assert_eq!(parsed.concurrency_limit, 20);
        assert_eq!(parsed.feature_overrides.get("new_ui"), Some(&true));
    }

    #[test]
    fn test_tenant_status_serialization() {
        let statuses = [
            TenantStatus::Active,
            TenantStatus::Suspended,
            TenantStatus::PendingDeletion,
        ];

        for status in statuses {
            let json = serde_json::to_string(&status).unwrap();
            let parsed: TenantStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, status);
        }
    }
}
