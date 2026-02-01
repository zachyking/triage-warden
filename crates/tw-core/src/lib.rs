//! # tw-core
//!
//! Core orchestrator and data models for Triage Warden.
//!
//! This crate provides the central orchestration loop, incident data models,
//! workflow state machine, and event bus for the Triage Warden system.

pub mod auth;
pub mod connector;
pub mod events;
pub mod incident;
pub mod notification;
pub mod orchestrator;
pub mod playbook;
pub mod policy;
pub mod workflow;

#[cfg(feature = "database")]
pub mod db;

pub use connector::{ConnectorConfig, ConnectorStatus, ConnectorType};
pub use events::{EventBus, TriageEvent};
pub use incident::{
    Alert, AlertSource, AuditEntry, Enrichment, Incident, IncidentStatus, ProposedAction, Severity,
    TriageAnalysis,
};
pub use notification::{
    ChannelType, NotificationChannel, NotificationChannelUpdate, NOTIFICATION_EVENTS,
};
pub use orchestrator::Orchestrator;
pub use playbook::{Playbook, PlaybookStage, PlaybookStep};
pub use policy::{ApprovalLevel, Policy, PolicyAction};
pub use workflow::{WorkflowEngine, WorkflowState, WorkflowTransition};

// Auth exports
pub use auth::password::{
    hash_password, validate_password_strength, verify_password, PasswordError,
};
pub use auth::{ApiKey, Role, SessionData, User, UserFilter, UserUpdate};
