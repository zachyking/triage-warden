//! # tw-observability
//!
//! Logging, metrics, and audit infrastructure for Triage Warden.
//!
//! This crate provides structured logging with tracing, metrics collection,
//! and audit trail functionality.

pub mod audit;
pub mod logging;
pub mod metrics;

pub use audit::{AuditLog, AuditLogEntry};
pub use logging::init_logging;
pub use metrics::{MetricsCollector, KPIs};
