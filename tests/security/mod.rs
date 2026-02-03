//! Security Integration Tests
//!
//! This module contains all security-related integration tests organized into:
//! - `auth` - Authentication and authorization tests
//! - `injection` - Injection prevention tests
//! - `safety` - Safety controls tests (rate limiting, kill switch, etc.)

pub mod auth;
pub mod injection;
pub mod safety;
