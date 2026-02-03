//! # tw-observability
//!
//! Logging, metrics, and audit infrastructure for Triage Warden.
//!
//! This crate provides structured logging with tracing, metrics collection,
//! and audit trail functionality.
//!
//! ## Action Audit Logging
//!
//! The audit module includes comprehensive action audit logging with:
//! - Detailed actor identity tracking
//! - Automatic masking of sensitive parameters
//! - Structured JSON format for log aggregation
//! - Correlation IDs for linking related audit entries

pub mod audit;
pub mod logging;
pub mod metrics;

pub use audit::{
    mask_sensitive_parameters, ActionAuditEntry, ActionAuditEntryBuilder, ActionAuditLog,
    ActionAuditResult, AuditEventType, AuditLog, AuditLogEntry, AuditResult,
};
pub use logging::init_logging;
pub use metrics::{KPIs, MetricsCollector};
