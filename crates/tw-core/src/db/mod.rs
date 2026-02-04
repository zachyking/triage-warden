//! Database layer for Triage Warden.
//!
//! This module provides persistence for incidents, audit logs, policies, and actions
//! using SQLx with support for both SQLite (development) and PostgreSQL (production).

mod error;
pub mod mocks;
mod pool;
pub mod retry;
mod schema;

pub mod api_key_repo;
pub mod audit_repo;
pub mod connector_repo;
pub mod feature_flag_repo;
pub mod incident_repo;
pub mod metrics_repo;
pub mod notification_repo;
pub mod playbook_repo;
pub mod policy_repo;
pub mod seed;
pub mod settings_repo;
pub mod user_repo;

pub use error::DbError;
pub use pool::{
    create_pool, create_pool_with_options, escape_like_pattern, make_like_pattern, DbPool,
    PoolOptions,
};
pub use retry::{is_transient_error, with_retry, RetryConfig};
pub use schema::run_migrations;

// Re-export repository traits and types
pub use api_key_repo::{ApiKeyFilter, ApiKeyRepository};
pub use audit_repo::AuditRepository;
pub use connector_repo::{ConnectorRepository, ConnectorUpdate};
pub use incident_repo::{IncidentFilter, IncidentRepository, IncidentUpdate, Pagination};
pub use metrics_repo::{
    ActionMetricsData, IncidentMetricsData, MetricsRepository, PerformanceMetricsData,
};
pub use notification_repo::NotificationChannelRepository;
pub use playbook_repo::{PlaybookFilter, PlaybookRepository, PlaybookUpdate};
pub use policy_repo::{PolicyRepository, PolicyUpdate};
pub use settings_repo::{GeneralSettings, LlmSettings, RateLimits, SettingsRepository};
pub use user_repo::UserRepository;

// Re-export factory functions
pub use api_key_repo::create_api_key_repository;
pub use audit_repo::create_audit_repository;
pub use connector_repo::create_connector_repository;
pub use incident_repo::create_incident_repository;
pub use metrics_repo::create_metrics_repository;
pub use notification_repo::create_notification_repository;
pub use playbook_repo::create_playbook_repository;
pub use policy_repo::create_policy_repository;
pub use settings_repo::create_settings_repository;
pub use user_repo::create_user_repository;

pub use feature_flag_repo::create_feature_flag_store;

pub use seed::ensure_admin_user;
