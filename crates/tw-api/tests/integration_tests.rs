//! Integration tests for Triage Warden API.
//!
//! These tests verify end-to-end functionality of the API endpoints.
//! Note: Tests for authenticated endpoints are in the crate's unit tests
//! where the test helper middleware can be properly applied.

mod integration;

pub use integration::common;
pub use integration::health_tests;
