//! Injection Prevention Integration Tests
//!
//! This module contains comprehensive tests for various injection attack vectors:
//! - JQL injection (Jira)
//! - OData injection (M365)
//! - FQL injection (CrowdStrike)
//! - ReDoS pattern detection
//! - Email header injection

pub mod jql_injection_tests;
pub mod odata_injection_tests;
pub mod fql_injection_tests;
pub mod redos_tests;
pub mod email_header_injection_tests;
