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
//!
//! ### Analysis Actions
//! - `parse_email` - Parses email content and extracts indicators
//! - `check_email_authentication` - Checks email authentication (SPF/DKIM/DMARC)
//!
//! ### Lookup/Enrichment Actions
//! - `lookup_sender_reputation` - Queries sender domain/IP reputation
//! - `lookup_urls` - Checks URLs against threat intelligence
//! - `lookup_attachments` - Checks attachment hashes against threat intelligence

pub mod block_sender;
pub mod check_email_authentication;
pub mod create_ticket;
pub mod disable_user;
pub mod isolate_host;
pub mod lookup_attachments;
pub mod lookup_sender_reputation;
pub mod lookup_urls;
pub mod notify_user;
pub mod parse_email;
pub mod quarantine_email;
pub mod registry;

pub use block_sender::BlockSenderAction;
pub use check_email_authentication::CheckEmailAuthenticationAction;
pub use create_ticket::CreateTicketAction;
pub use disable_user::DisableUserAction;
pub use isolate_host::IsolateHostAction;
pub use lookup_attachments::{AttachmentInput, AttachmentLookupResult, LookupAttachmentsAction};
pub use lookup_sender_reputation::LookupSenderReputationAction;
pub use lookup_urls::{LookupUrlsAction, UrlLookupResult};
pub use notify_user::NotifyUserAction;
pub use parse_email::ParseEmailAction;
pub use quarantine_email::QuarantineEmailAction;
pub use registry::{Action, ActionContext, ActionError, ActionRegistry, ActionResult};
