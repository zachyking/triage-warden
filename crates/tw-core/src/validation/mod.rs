//! Input validation types for Triage Warden.
//!
//! This module provides validated types that ensure input data
//! conforms to expected formats and is safe from injection attacks.
//!
//! # Available Types
//!
//! - [`ValidatedHostname`] - RFC 1035 compliant hostname validation
//! - [`ValidatedEmail`] - RFC 5321 compliant email address validation
//!
//! # Security
//!
//! All validated types in this module are designed with security in mind:
//! - Input is validated before acceptance
//! - Shell metacharacters and injection patterns are rejected
//! - Inputs are normalized where appropriate (e.g., lowercase for hostnames and emails)

pub mod email;
mod hostname;

pub use email::{
    validate_email, validate_email_with_options, EmailValidationError, EmailValidationOptions,
    ValidatedEmail,
};
pub use hostname::{HostnameValidationError, ValidatedHostname};
