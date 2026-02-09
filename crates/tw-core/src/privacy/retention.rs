//! Retention policy models and evaluation helpers.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Data class subject to retention controls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataType {
    AiPrompt,
    AiResponse,
    AiFullTranscript,
    AuditEvent,
    IncidentExport,
    EvidencePackage,
    SessionRecord,
}

/// Deletion behavior when retention window expires.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeletionStrategy {
    HardDelete,
    Anonymize,
    Archive,
}

/// Retention rule.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RetentionPolicy {
    pub data_type: DataType,
    pub retention_days: u32,
    pub deletion_strategy: DeletionStrategy,
}

/// Evaluation result for a specific data record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RetentionDecision {
    pub expired: bool,
    pub delete_after: DateTime<Utc>,
    pub strategy: DeletionStrategy,
}

/// Metadata for a record evaluated by retention cleanup.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RetentionRecord {
    pub record_id: String,
    pub data_type: DataType,
    pub created_at: DateTime<Utc>,
}

/// Cleanup action decision for a specific record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RetentionCleanupAction {
    pub record_id: String,
    pub data_type: DataType,
    pub expired: bool,
    pub delete_after: DateTime<Utc>,
    pub strategy: DeletionStrategy,
}

/// Cleanup planning output.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RetentionCleanupReport {
    pub evaluated: usize,
    pub expired: usize,
    pub actions: Vec<RetentionCleanupAction>,
}

/// Retention manager containing tenant policy set.
#[derive(Debug, Clone)]
pub struct RetentionManager {
    policies: HashMap<DataType, RetentionPolicy>,
}

impl Default for RetentionManager {
    fn default() -> Self {
        let defaults = vec![
            RetentionPolicy {
                data_type: DataType::AiPrompt,
                retention_days: 30,
                deletion_strategy: DeletionStrategy::Anonymize,
            },
            RetentionPolicy {
                data_type: DataType::AiResponse,
                retention_days: 30,
                deletion_strategy: DeletionStrategy::Anonymize,
            },
            RetentionPolicy {
                data_type: DataType::AiFullTranscript,
                retention_days: 7,
                deletion_strategy: DeletionStrategy::HardDelete,
            },
            RetentionPolicy {
                data_type: DataType::AuditEvent,
                retention_days: 365,
                deletion_strategy: DeletionStrategy::Archive,
            },
            RetentionPolicy {
                data_type: DataType::IncidentExport,
                retention_days: 90,
                deletion_strategy: DeletionStrategy::HardDelete,
            },
            RetentionPolicy {
                data_type: DataType::EvidencePackage,
                retention_days: 365,
                deletion_strategy: DeletionStrategy::Archive,
            },
            RetentionPolicy {
                data_type: DataType::SessionRecord,
                retention_days: 30,
                deletion_strategy: DeletionStrategy::HardDelete,
            },
        ];

        let mut policies = HashMap::new();
        for policy in defaults {
            policies.insert(policy.data_type, policy);
        }
        Self { policies }
    }
}

impl RetentionManager {
    /// Creates manager from explicit policy list.
    pub fn new(policies: Vec<RetentionPolicy>) -> Self {
        let mut map = HashMap::new();
        for policy in policies {
            map.insert(policy.data_type, policy);
        }
        Self { policies: map }
    }

    /// Sets or replaces a policy.
    pub fn set_policy(&mut self, policy: RetentionPolicy) {
        self.policies.insert(policy.data_type, policy);
    }

    /// Gets policy for a data type.
    pub fn policy_for(&self, data_type: DataType) -> Option<&RetentionPolicy> {
        self.policies.get(&data_type)
    }

    /// Returns all policies in deterministic order.
    pub fn all_policies(&self) -> Vec<RetentionPolicy> {
        let mut values: Vec<_> = self.policies.values().cloned().collect();
        values.sort_by_key(|p| p.data_type as u8);
        values
    }

    /// Evaluates retention status for a record.
    pub fn evaluate(
        &self,
        data_type: DataType,
        created_at: DateTime<Utc>,
    ) -> Option<RetentionDecision> {
        self.evaluate_at(data_type, created_at, Utc::now())
    }

    /// Evaluates retention status for a record using explicit reference time.
    pub fn evaluate_at(
        &self,
        data_type: DataType,
        created_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Option<RetentionDecision> {
        let policy = self.policy_for(data_type)?;
        let delete_after = created_at + Duration::days(policy.retention_days as i64);
        Some(RetentionDecision {
            expired: now >= delete_after,
            delete_after,
            strategy: policy.deletion_strategy,
        })
    }

    /// Creates a cleanup plan for multiple records.
    pub fn plan_cleanup(
        &self,
        records: &[RetentionRecord],
        now: DateTime<Utc>,
    ) -> RetentionCleanupReport {
        let mut actions = Vec::with_capacity(records.len());
        let mut expired = 0usize;

        for record in records {
            if let Some(decision) = self.evaluate_at(record.data_type, record.created_at, now) {
                if decision.expired {
                    expired += 1;
                }
                actions.push(RetentionCleanupAction {
                    record_id: record.record_id.clone(),
                    data_type: record.data_type,
                    expired: decision.expired,
                    delete_after: decision.delete_after,
                    strategy: decision.strategy,
                });
            }
        }

        RetentionCleanupReport {
            evaluated: actions.len(),
            expired,
            actions,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_policy_exists() {
        let manager = RetentionManager::default();
        assert!(manager.policy_for(DataType::AiPrompt).is_some());
    }

    #[test]
    fn test_retention_evaluation() {
        let manager = RetentionManager::default();
        let created = Utc::now() - Duration::days(40);
        let decision = manager
            .evaluate(DataType::AiPrompt, created)
            .expect("policy exists");
        assert!(decision.expired);
    }

    #[test]
    fn test_cleanup_planning() {
        let manager = RetentionManager::default();
        let now = Utc::now();
        let records = vec![
            RetentionRecord {
                record_id: "r1".to_string(),
                data_type: DataType::AiPrompt,
                created_at: now - Duration::days(90),
            },
            RetentionRecord {
                record_id: "r2".to_string(),
                data_type: DataType::AuditEvent,
                created_at: now - Duration::days(10),
            },
        ];

        let report = manager.plan_cleanup(&records, now);
        assert_eq!(report.evaluated, 2);
        assert_eq!(report.expired, 1);
        assert!(report
            .actions
            .iter()
            .any(|a| a.record_id == "r1" && a.expired));
    }
}
