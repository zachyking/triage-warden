//! # tw-api
//!
//! REST API server for Triage Warden.
//!
//! This crate provides the HTTP API for incident management, webhook ingestion,
//! and real-time updates via WebSocket.

pub mod dto;
pub mod error;
pub mod middleware;
pub mod routes;
pub mod server;
pub mod state;
pub mod web;
pub mod webhooks;

pub use error::ApiError;
pub use server::{ApiServer, ApiServerConfig};
pub use state::AppState;
