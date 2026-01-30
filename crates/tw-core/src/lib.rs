//! # tw-core
//!
//! Core orchestrator and data models for Triage Warden.
//!
//! This crate provides the central orchestration loop, incident data models,
//! workflow state machine, and event bus for the Triage Warden system.

pub mod events;
pub mod incident;
pub mod orchestrator;
pub mod workflow;

#[cfg(feature = "database")]
pub mod db;

pub use events::{EventBus, TriageEvent};
pub use incident::{
    Alert, AlertSource, AuditEntry, Enrichment, Incident, IncidentStatus, ProposedAction, Severity,
    TriageAnalysis,
};
pub use orchestrator::Orchestrator;
pub use workflow::{WorkflowEngine, WorkflowState, WorkflowTransition};
