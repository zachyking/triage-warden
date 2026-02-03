//! Safety controls integration tests.
//!
//! This module contains comprehensive integration tests for Triage Warden's
//! safety controls including:
//!
//! - Global and webhook rate limiting
//! - Rate limiter memory bounds (LRU eviction)
//! - Kill switch immediate effect
//! - Rollback data integrity (HMAC signing)
//! - Credential zeroization

pub mod rate_limiting_tests;
pub mod kill_switch_tests;
pub mod rollback_integrity_tests;
pub mod credential_zeroization_tests;
