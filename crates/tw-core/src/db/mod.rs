//! Database layer for Triage Warden.
//!
//! This module provides persistence for incidents, audit logs, policies, and actions
//! using SQLx with support for both SQLite (development) and PostgreSQL (production).

mod error;
mod pool;
mod schema;

pub mod audit_repo;
pub mod connector_repo;
pub mod incident_repo;
pub mod notification_repo;
pub mod playbook_repo;
pub mod policy_repo;
pub mod settings_repo;

pub use error::DbError;
pub use pool::{create_pool, create_pool_with_options, DbPool, PoolOptions};
pub use schema::run_migrations;

// Re-export repository traits and types
pub use audit_repo::AuditRepository;
pub use connector_repo::{ConnectorRepository, ConnectorUpdate};
pub use incident_repo::{IncidentFilter, IncidentRepository, IncidentUpdate, Pagination};
pub use notification_repo::NotificationChannelRepository;
pub use playbook_repo::{PlaybookFilter, PlaybookRepository, PlaybookUpdate};
pub use policy_repo::{PolicyRepository, PolicyUpdate};
pub use settings_repo::{GeneralSettings, RateLimits, SettingsRepository};

// Re-export factory functions
pub use audit_repo::create_audit_repository;
pub use connector_repo::create_connector_repository;
pub use incident_repo::create_incident_repository;
pub use notification_repo::create_notification_repository;
pub use playbook_repo::create_playbook_repository;
pub use policy_repo::create_policy_repository;
pub use settings_repo::create_settings_repository;
