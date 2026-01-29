//! Audit logging for Triage Warden.
//!
//! This module provides audit trail functionality for compliance and forensics.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;
use uuid::Uuid;

/// An entry in the audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    /// Unique entry ID.
    pub id: Uuid,
    /// Timestamp.
    pub timestamp: DateTime<Utc>,
    /// Event type.
    pub event_type: AuditEventType,
    /// Actor (user or system component).
    pub actor: String,
    /// Incident ID (if applicable).
    pub incident_id: Option<Uuid>,
    /// Action ID (if applicable).
    pub action_id: Option<Uuid>,
    /// Description of the event.
    pub description: String,
    /// Additional details.
    pub details: serde_json::Value,
    /// Result/outcome.
    pub result: AuditResult,
}

/// Types of auditable events.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    /// System startup/shutdown.
    SystemLifecycle,
    /// Configuration change.
    ConfigChange,
    /// Incident created.
    IncidentCreated,
    /// Incident status changed.
    IncidentStatusChanged,
    /// Analysis completed.
    AnalysisCompleted,
    /// Action proposed.
    ActionProposed,
    /// Action approved.
    ActionApproved,
    /// Action denied.
    ActionDenied,
    /// Action executed.
    ActionExecuted,
    /// Action failed.
    ActionFailed,
    /// Action rolled back.
    ActionRolledBack,
    /// Policy evaluated.
    PolicyEvaluated,
    /// Approval request created.
    ApprovalRequested,
    /// Approval decision made.
    ApprovalDecision,
    /// Kill switch activated.
    KillSwitchActivated,
    /// Kill switch deactivated.
    KillSwitchDeactivated,
    /// User login.
    UserLogin,
    /// User logout.
    UserLogout,
    /// API access.
    ApiAccess,
    /// Data export.
    DataExport,
    /// Custom event.
    Custom(String),
}

/// Result of an audited operation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditResult {
    Success,
    Failure(String),
    Denied(String),
    Pending,
}

/// Audit log with in-memory storage and optional persistence.
pub struct AuditLog {
    /// In-memory log entries.
    entries: Arc<RwLock<VecDeque<AuditLogEntry>>>,
    /// Maximum entries to keep in memory.
    max_entries: usize,
    /// Whether to also log to tracing.
    log_to_tracing: bool,
}

impl AuditLog {
    /// Creates a new audit log.
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: Arc::new(RwLock::new(VecDeque::with_capacity(max_entries))),
            max_entries,
            log_to_tracing: true,
        }
    }

    /// Creates an audit log without tracing output.
    pub fn without_tracing(max_entries: usize) -> Self {
        Self {
            entries: Arc::new(RwLock::new(VecDeque::with_capacity(max_entries))),
            max_entries,
            log_to_tracing: false,
        }
    }

    /// Logs an audit entry.
    pub async fn log(&self, entry: AuditLogEntry) {
        if self.log_to_tracing {
            info!(
                event_type = ?entry.event_type,
                actor = %entry.actor,
                incident_id = ?entry.incident_id,
                result = ?entry.result,
                "Audit: {}",
                entry.description
            );
        }

        let mut entries = self.entries.write().await;
        if entries.len() >= self.max_entries {
            entries.pop_front();
        }
        entries.push_back(entry);
    }

    /// Logs an event with builder pattern.
    pub async fn log_event(
        &self,
        event_type: AuditEventType,
        actor: &str,
        description: &str,
        result: AuditResult,
    ) {
        let entry = AuditLogEntry {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_type,
            actor: actor.to_string(),
            incident_id: None,
            action_id: None,
            description: description.to_string(),
            details: serde_json::json!({}),
            result,
        };
        self.log(entry).await;
    }

    /// Logs an incident event.
    pub async fn log_incident_event(
        &self,
        event_type: AuditEventType,
        actor: &str,
        incident_id: Uuid,
        description: &str,
        details: serde_json::Value,
        result: AuditResult,
    ) {
        let entry = AuditLogEntry {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_type,
            actor: actor.to_string(),
            incident_id: Some(incident_id),
            action_id: None,
            description: description.to_string(),
            details,
            result,
        };
        self.log(entry).await;
    }

    /// Logs an action event.
    pub async fn log_action_event(
        &self,
        event_type: AuditEventType,
        actor: &str,
        incident_id: Uuid,
        action_id: Uuid,
        description: &str,
        details: serde_json::Value,
        result: AuditResult,
    ) {
        let entry = AuditLogEntry {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_type,
            actor: actor.to_string(),
            incident_id: Some(incident_id),
            action_id: Some(action_id),
            description: description.to_string(),
            details,
            result,
        };
        self.log(entry).await;
    }

    /// Gets all entries.
    pub async fn get_entries(&self) -> Vec<AuditLogEntry> {
        let entries = self.entries.read().await;
        entries.iter().cloned().collect()
    }

    /// Gets entries for a specific incident.
    pub async fn get_incident_entries(&self, incident_id: Uuid) -> Vec<AuditLogEntry> {
        let entries = self.entries.read().await;
        entries
            .iter()
            .filter(|e| e.incident_id == Some(incident_id))
            .cloned()
            .collect()
    }

    /// Gets entries by event type.
    pub async fn get_entries_by_type(&self, event_type: AuditEventType) -> Vec<AuditLogEntry> {
        let entries = self.entries.read().await;
        entries
            .iter()
            .filter(|e| e.event_type == event_type)
            .cloned()
            .collect()
    }

    /// Gets entries within a time range.
    pub async fn get_entries_in_range(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Vec<AuditLogEntry> {
        let entries = self.entries.read().await;
        entries
            .iter()
            .filter(|e| e.timestamp >= start && e.timestamp <= end)
            .cloned()
            .collect()
    }

    /// Gets entries by actor.
    pub async fn get_entries_by_actor(&self, actor: &str) -> Vec<AuditLogEntry> {
        let entries = self.entries.read().await;
        entries
            .iter()
            .filter(|e| e.actor == actor)
            .cloned()
            .collect()
    }

    /// Exports entries as JSON.
    pub async fn export_json(&self) -> String {
        let entries = self.get_entries().await;
        serde_json::to_string_pretty(&entries).unwrap_or_else(|_| "[]".to_string())
    }

    /// Gets the number of entries.
    pub async fn len(&self) -> usize {
        self.entries.read().await.len()
    }

    /// Checks if the audit log is empty.
    pub async fn is_empty(&self) -> bool {
        self.entries.read().await.is_empty()
    }

    /// Clears all entries.
    pub async fn clear(&self) {
        self.entries.write().await.clear();
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new(10000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_log_event() {
        let audit_log = AuditLog::without_tracing(100);

        audit_log
            .log_event(
                AuditEventType::SystemLifecycle,
                "system",
                "System started",
                AuditResult::Success,
            )
            .await;

        let entries = audit_log.get_entries().await;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].event_type, AuditEventType::SystemLifecycle);
    }

    #[tokio::test]
    async fn test_incident_event() {
        let audit_log = AuditLog::without_tracing(100);
        let incident_id = Uuid::new_v4();

        audit_log
            .log_incident_event(
                AuditEventType::IncidentCreated,
                "ai",
                incident_id,
                "Incident created from alert",
                serde_json::json!({"severity": "high"}),
                AuditResult::Success,
            )
            .await;

        let entries = audit_log.get_incident_entries(incident_id).await;
        assert_eq!(entries.len(), 1);
    }

    #[tokio::test]
    async fn test_max_entries() {
        let audit_log = AuditLog::without_tracing(5);

        for i in 0..10 {
            audit_log
                .log_event(
                    AuditEventType::Custom(format!("event-{}", i)),
                    "test",
                    &format!("Event {}", i),
                    AuditResult::Success,
                )
                .await;
        }

        assert_eq!(audit_log.len().await, 5);

        // First events should have been evicted
        let entries = audit_log.get_entries().await;
        assert!(matches!(
            &entries[0].event_type,
            AuditEventType::Custom(s) if s == "event-5"
        ));
    }

    #[tokio::test]
    async fn test_get_by_actor() {
        let audit_log = AuditLog::without_tracing(100);

        audit_log
            .log_event(
                AuditEventType::ActionApproved,
                "analyst@company.com",
                "Action approved",
                AuditResult::Success,
            )
            .await;

        audit_log
            .log_event(
                AuditEventType::ActionExecuted,
                "system",
                "Action executed",
                AuditResult::Success,
            )
            .await;

        let analyst_entries = audit_log.get_entries_by_actor("analyst@company.com").await;
        assert_eq!(analyst_entries.len(), 1);

        let system_entries = audit_log.get_entries_by_actor("system").await;
        assert_eq!(system_entries.len(), 1);
    }

    #[tokio::test]
    async fn test_export_json() {
        let audit_log = AuditLog::without_tracing(100);

        audit_log
            .log_event(
                AuditEventType::SystemLifecycle,
                "system",
                "Test event",
                AuditResult::Success,
            )
            .await;

        let json = audit_log.export_json().await;
        assert!(json.contains("SystemLifecycle") || json.contains("system_lifecycle"));
    }
}
