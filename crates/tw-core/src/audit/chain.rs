//! Chain verification helpers for immutable audit logs.

use crate::audit::immutable::ImmutableAuditLog;
use thiserror::Error;

/// Errors from chain verification.
#[derive(Debug, Error)]
pub enum ChainVerificationError {
    #[error("audit chain is empty")]
    Empty,
    #[error("genesis entry is invalid")]
    InvalidGenesis,
    #[error("invalid link between sequence {previous} and {current}")]
    InvalidLink { previous: u64, current: u64 },
}

/// Verifies a sequence of immutable audit entries.
pub fn verify_chain(entries: &[ImmutableAuditLog]) -> Result<(), ChainVerificationError> {
    if entries.is_empty() {
        return Err(ChainVerificationError::Empty);
    }
    let first = &entries[0];
    if first.sequence != 1 || first.previous_hash != "GENESIS" || first.compute_hash() != first.hash
    {
        return Err(ChainVerificationError::InvalidGenesis);
    }

    for window in entries.windows(2) {
        let previous = &window[0];
        let current = &window[1];
        if !current.verify_chain(previous) {
            return Err(ChainVerificationError::InvalidLink {
                previous: previous.sequence,
                current: current.sequence,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::immutable::{AuditActor, AuditEventType, AuditOutcome, AuditResource};

    #[test]
    fn test_verify_chain_happy_path() {
        let first = ImmutableAuditLog::new(
            None,
            AuditEventType::SystemStarted,
            AuditActor {
                id: "system".to_string(),
                kind: "service".to_string(),
            },
            AuditResource {
                kind: "service".to_string(),
                id: None,
            },
            "start",
            AuditOutcome::Success,
            serde_json::json!({}),
        );
        let second = ImmutableAuditLog::new(
            Some(&first),
            AuditEventType::SystemStopped,
            AuditActor {
                id: "system".to_string(),
                kind: "service".to_string(),
            },
            AuditResource {
                kind: "service".to_string(),
                id: None,
            },
            "stop",
            AuditOutcome::Success,
            serde_json::json!({}),
        );
        assert!(verify_chain(&[first, second]).is_ok());
    }
}
