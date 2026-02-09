//! Compliance-oriented immutable audit primitives.

pub mod chain;
pub mod immutable;

pub use chain::{verify_chain, ChainVerificationError};
pub use immutable::{AuditActor, AuditEventType, AuditOutcome, AuditResource, ImmutableAuditLog};
