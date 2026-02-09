//! Rollback tracking models for reversible actions.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Rollback status for an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackStatus {
    Available,
    Executed,
    Expired,
    Failed,
}

/// Rollback metadata for an executed action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionRollbackInfo {
    pub action_id: Uuid,
    pub is_reversible: bool,
    pub rollback_action: Option<String>,
    pub rollback_payload: Option<serde_json::Value>,
    pub rollback_deadline: Option<DateTime<Utc>>,
    pub rollback_status: RollbackStatus,
}

impl ActionRollbackInfo {
    /// Creates rollback metadata for a reversible action.
    pub fn reversible(
        action_id: Uuid,
        rollback_action: impl Into<String>,
        rollback_payload: serde_json::Value,
        rollback_deadline: Option<DateTime<Utc>>,
    ) -> Self {
        Self {
            action_id,
            is_reversible: true,
            rollback_action: Some(rollback_action.into()),
            rollback_payload: Some(rollback_payload),
            rollback_deadline,
            rollback_status: RollbackStatus::Available,
        }
    }
}

/// In-memory rollback registry.
#[derive(Debug, Default)]
pub struct RollbackRegistry {
    entries: HashMap<Uuid, ActionRollbackInfo>,
}

impl RollbackRegistry {
    /// Inserts or updates rollback metadata.
    pub fn upsert(&mut self, info: ActionRollbackInfo) {
        self.entries.insert(info.action_id, info);
    }

    /// Gets rollback metadata by action id.
    pub fn get(&self, action_id: Uuid) -> Option<&ActionRollbackInfo> {
        self.entries.get(&action_id)
    }

    /// Marks rollback status for an action.
    pub fn mark_status(&mut self, action_id: Uuid, status: RollbackStatus) -> bool {
        if let Some(info) = self.entries.get_mut(&action_id) {
            info.rollback_status = status;
            return true;
        }
        false
    }

    /// Lists all rollback metadata.
    pub fn list(&self) -> Vec<ActionRollbackInfo> {
        self.entries.values().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_updates_status() {
        let mut registry = RollbackRegistry::default();
        let action_id = Uuid::new_v4();
        registry.upsert(ActionRollbackInfo::reversible(
            action_id,
            "unisolate_host",
            serde_json::json!({"host": "srv-1"}),
            None,
        ));
        assert!(registry.mark_status(action_id, RollbackStatus::Executed));
        assert_eq!(
            registry.get(action_id).map(|v| v.rollback_status),
            Some(RollbackStatus::Executed)
        );
    }
}
