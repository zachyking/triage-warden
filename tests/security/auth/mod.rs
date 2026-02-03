//! Comprehensive authentication and authorization integration tests.
//!
//! This module tests the security controls for:
//! - Unauthorized action execution is blocked
//! - Workflow transition authorization
//! - API key scope enforcement
//! - Session scope enforcement
//! - Force flag removal verification
//! - Escalation privilege checks

mod action_authorization_tests;
mod api_key_scope_tests;
mod escalation_privilege_tests;
mod force_flag_tests;
mod session_scope_tests;
mod workflow_authorization_tests;
