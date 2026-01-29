//! # tw-actions
//!
//! Action plugins for Triage Warden.
//!
//! This crate provides the action registry and implementations for
//! automated response actions like host isolation, user disabling, etc.

pub mod create_ticket;
pub mod disable_user;
pub mod isolate_host;
pub mod registry;

pub use create_ticket::CreateTicketAction;
pub use disable_user::DisableUserAction;
pub use isolate_host::IsolateHostAction;
pub use registry::{Action, ActionError, ActionRegistry, ActionResult};
