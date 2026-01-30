//! Database layer for Triage Warden.
//!
//! This module provides persistence for incidents, audit logs, and actions
//! using SQLx with support for both SQLite (development) and PostgreSQL (production).

mod error;
mod pool;
mod schema;

pub mod audit_repo;
pub mod incident_repo;

pub use error::DbError;
pub use pool::{create_pool, create_pool_with_options, DbPool, PoolOptions};
pub use schema::run_migrations;

// Re-export repository traits and types
pub use audit_repo::AuditRepository;
pub use incident_repo::{IncidentFilter, IncidentRepository, IncidentUpdate, Pagination};

// Re-export factory functions
pub use audit_repo::create_audit_repository;
pub use incident_repo::create_incident_repository;
