//! Webhook processing utilities.

mod generic;
mod signature;

pub use generic::normalize_alert;
pub use signature::validate_signature;
