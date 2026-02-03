//! # tw-actions
//!
//! Action plugins for Triage Warden.
//!
//! This crate provides the action registry and implementations for
//! automated response actions like host isolation, user disabling, etc.
//!
//! ## Action Types
//!
//! ### Response Actions
//! - `isolate_host` - Isolates a host from the network using EDR
//! - `disable_user` - Disables a user account in the identity provider
//! - `create_ticket` - Creates a ticket in the ticketing system
//! - `block_sender` - Blocks a sender in the email gateway
//! - `quarantine_email` - Quarantines an email message
//! - `notify_user` - Notifies a user about a security event
//! - `notify_reporter` - Sends status update to the incident reporter
//! - `escalate` - Routes incident to appropriate approval level
//!
//! ### Analysis Actions
//! - `parse_email` - Parses email content and extracts indicators
//! - `check_email_authentication` - Checks email authentication (SPF/DKIM/DMARC)
//! - `run_triage_agent` - Triggers the AI triage workflow for an incident
//!
//! ### Lookup/Enrichment Actions
//! - `lookup_sender_reputation` - Queries sender domain/IP reputation
//! - `lookup_urls` - Checks URLs against threat intelligence
//! - `lookup_attachments` - Checks attachment hashes against threat intelligence
//!
//! ### Tuning/Learning Actions
//! - `log_false_positive` - Records a false positive for tuning/learning

pub mod block_sender;
pub mod check_email_authentication;
pub mod create_ticket;
pub mod disable_user;
pub mod email_sanitizer;
pub mod escalate;
pub mod isolate_host;
pub mod log_false_positive;
pub mod lookup_attachments;
pub mod lookup_sender_reputation;
pub mod lookup_urls;
pub mod notify_reporter;
pub mod notify_user;
pub mod parse_email;
pub mod quarantine_email;
pub mod registry;
pub mod run_triage_agent;

pub use block_sender::BlockSenderAction;
pub use check_email_authentication::CheckEmailAuthenticationAction;
pub use create_ticket::CreateTicketAction;
pub use disable_user::DisableUserAction;
pub use email_sanitizer::{
    sanitize_body, sanitize_email, sanitize_subject, EmailSanitizationError, SanitizedEmail,
};
pub use escalate::{EscalateAction, EscalationLevel, EscalationRecord};
pub use isolate_host::IsolateHostAction;
pub use log_false_positive::{FalsePositiveRecord, LogFalsePositiveAction};
pub use lookup_attachments::{AttachmentInput, AttachmentLookupResult, LookupAttachmentsAction};
pub use lookup_sender_reputation::LookupSenderReputationAction;
pub use lookup_urls::{LookupUrlsAction, UrlLookupResult};
pub use notify_reporter::{IncidentStatus, NotifyReporterAction};
pub use notify_user::NotifyUserAction;
pub use parse_email::ParseEmailAction;
pub use quarantine_email::QuarantineEmailAction;
pub use registry::{Action, ActionContext, ActionError, ActionRegistry, ActionResult, Permission};
pub use run_triage_agent::{AgentConfig, RunTriageAgentAction, TriageResult};
