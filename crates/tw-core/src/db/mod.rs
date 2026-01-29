//! Database layer for Triage Warden.
//!
//! This module provides persistence for incidents, audit logs, and actions
//! using SQLx with support for both SQLite (development) and PostgreSQL (production).

mod error;
mod pool;
mod schema;

pub mod incident_repo;
pub mod audit_repo;

pub use error::DbError;
pub use pool::{DbPool, create_pool, create_pool_with_options, PoolOptions};
pub use schema::run_migrations;

// Re-export repository traits and types
pub use incident_repo::{IncidentRepository, IncidentFilter, IncidentUpdate, Pagination};
pub use audit_repo::AuditRepository;

// Re-export factory functions
pub use incident_repo::create_incident_repository;
pub use audit_repo::create_audit_repository;
