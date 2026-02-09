//! Tamper-evident immutable audit log entries.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Security-relevant audit event types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    LoginSuccess,
    LoginFailure,
    Logout,
    SessionExpired,
    MfaChallenge,
    PermissionGranted,
    PermissionDenied,
    RoleAssigned,
    RoleRevoked,
    IncidentViewed,
    IncidentExported,
    ReportGenerated,
    BulkExport,
    SettingChanged,
    ConnectorConfigured,
    PlaybookModified,
    PolicyUpdated,
    ActionRequested,
    ActionApproved,
    ActionRejected,
    ActionExecuted,
    ActionFailed,
    ActionRolledBack,
    AiAnalysisRequested,
    AiRecommendation,
    AiFeedbackProvided,
    SystemStarted,
    SystemStopped,
    KillSwitchActivated,
    GuardrailTriggered,
    Custom(String),
}

/// Actor representation for immutable audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditActor {
    pub id: String,
    pub kind: String,
}

/// Resource representation for immutable audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditResource {
    pub kind: String,
    pub id: Option<String>,
}

/// Outcome for immutable audit entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    Success,
    Failure,
    Denied,
}

/// Immutable, hash-chained audit event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ImmutableAuditLog {
    pub id: Uuid,
    pub sequence: u64,
    pub timestamp: DateTime<Utc>,
    pub event_type: AuditEventType,
    pub actor: AuditActor,
    pub resource: AuditResource,
    pub action: String,
    pub outcome: AuditOutcome,
    pub details: serde_json::Value,
    pub previous_hash: String,
    pub hash: String,
}

/// Payload fields for creating immutable audit entries.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ImmutableAuditPayload {
    pub event_type: AuditEventType,
    pub actor: AuditActor,
    pub resource: AuditResource,
    pub action: String,
    pub outcome: AuditOutcome,
    pub details: serde_json::Value,
}

impl ImmutableAuditPayload {
    /// Creates an immutable audit payload.
    pub fn new(
        event_type: AuditEventType,
        actor: AuditActor,
        resource: AuditResource,
        action: impl Into<String>,
        outcome: AuditOutcome,
        details: serde_json::Value,
    ) -> Self {
        Self {
            event_type,
            actor,
            resource,
            action: action.into(),
            outcome,
            details,
        }
    }
}

impl ImmutableAuditLog {
    /// Creates a new entry chained to the previous hash.
    pub fn new(
        previous: Option<&ImmutableAuditLog>,
        event_type: AuditEventType,
        actor: AuditActor,
        resource: AuditResource,
        action: impl Into<String>,
        outcome: AuditOutcome,
        details: serde_json::Value,
    ) -> Self {
        Self::from_seed(
            Uuid::new_v4(),
            Utc::now(),
            previous,
            ImmutableAuditPayload::new(event_type, actor, resource, action, outcome, details),
        )
    }

    /// Creates a deterministic entry from explicit id/timestamp seed.
    pub fn from_seed(
        id: Uuid,
        timestamp: DateTime<Utc>,
        previous: Option<&ImmutableAuditLog>,
        payload: ImmutableAuditPayload,
    ) -> Self {
        let sequence = previous.map(|p| p.sequence + 1).unwrap_or(1);
        let previous_hash = previous
            .map(|p| p.hash.clone())
            .unwrap_or_else(|| "GENESIS".to_string());

        let mut entry = Self {
            id,
            sequence,
            timestamp,
            event_type: payload.event_type,
            actor: payload.actor,
            resource: payload.resource,
            action: payload.action,
            outcome: payload.outcome,
            details: payload.details,
            previous_hash,
            hash: String::new(),
        };
        entry.hash = entry.compute_hash();
        entry
    }

    /// Computes deterministic entry hash.
    pub fn compute_hash(&self) -> String {
        let payload = serde_json::json!({
            "id": self.id,
            "sequence": self.sequence,
            "timestamp": self.timestamp.to_rfc3339(),
            "event_type": self.event_type,
            "actor": self.actor,
            "resource": self.resource,
            "action": self.action,
            "outcome": self.outcome,
            "details": self.details,
            "previous_hash": self.previous_hash,
        });
        let serialized = serde_json::to_vec(&payload).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(serialized);
        hex::encode(hasher.finalize())
    }

    /// Validates continuity and content hash against previous entry.
    pub fn verify_chain(&self, previous: &ImmutableAuditLog) -> bool {
        self.previous_hash == previous.hash
            && self.sequence == previous.sequence + 1
            && self.compute_hash() == self.hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_verification() {
        let first = ImmutableAuditLog::new(
            None,
            AuditEventType::LoginSuccess,
            AuditActor {
                id: "u1".to_string(),
                kind: "user".to_string(),
            },
            AuditResource {
                kind: "session".to_string(),
                id: Some("s1".to_string()),
            },
            "login",
            AuditOutcome::Success,
            serde_json::json!({}),
        );
        let second = ImmutableAuditLog::new(
            Some(&first),
            AuditEventType::ActionExecuted,
            AuditActor {
                id: "u1".to_string(),
                kind: "user".to_string(),
            },
            AuditResource {
                kind: "incident".to_string(),
                id: Some("i1".to_string()),
            },
            "execute",
            AuditOutcome::Success,
            serde_json::json!({}),
        );

        assert!(second.verify_chain(&first));
    }
}
