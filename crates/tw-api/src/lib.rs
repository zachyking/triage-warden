//! # tw-api
//!
//! REST API server for Triage Warden.
//!
//! This crate provides the HTTP API for incident management, webhook ingestion,
//! and real-time updates via WebSocket.

pub mod auth;
pub mod dto;
pub mod error;
pub mod middleware;
pub mod rate_limit;
pub mod routes;
pub mod server;
pub mod state;
pub mod web;
pub mod webhooks;

/// Test helpers module providing common utilities for testing.
///
/// This module is only compiled in test mode and provides:
/// - `setup_test_db()` - Creates in-memory SQLite pool with full schema
/// - `create_test_state()` - Creates AppState with test database and EventBus
/// - `create_test_incident()` - Helper to create test incidents
/// - `create_test_playbook()` - Helper to create test playbooks
/// - `create_test_connector()` - Helper to create test connectors
#[cfg(test)]
pub mod test_helpers;

pub use error::ApiError;
pub use server::{ApiServer, ApiServerConfig};
pub use state::AppState;
