//! Automated Threat Hunting subsystem (Stage 5.1).
//!
//! This module provides the core data structures and logic for proactive
//! threat hunting, including hunt definitions, execution, findings, and
//! a library of built-in hunting queries.

mod executor;
mod hunt;
mod queries;

pub use executor::*;
pub use hunt::*;
pub use queries::*;
