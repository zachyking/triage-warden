//! Shift handoff report generation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A shift handoff report summarizing the state for the next analyst.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShiftHandoff {
    /// Unique handoff report identifier.
    pub id: Uuid,
    /// Start of the shift being handed off.
    pub shift_start: DateTime<Utc>,
    /// End of the shift being handed off.
    pub shift_end: DateTime<Utc>,
    /// ID of the analyst handing off.
    pub analyst_id: Uuid,
    /// Name of the analyst handing off.
    pub analyst_name: String,
    /// Open incidents that need attention.
    pub open_incidents: Vec<IncidentSummary>,
    /// Pending actions awaiting execution or approval.
    pub pending_actions: Vec<ActionSummary>,
    /// Notable events during the shift.
    pub notable_events: Vec<String>,
    /// Recommendations for the incoming analyst.
    pub recommendations: Vec<String>,
    /// When this report was generated.
    pub created_at: DateTime<Utc>,
}

impl ShiftHandoff {
    /// Creates a new shift handoff report.
    pub fn new(
        shift_start: DateTime<Utc>,
        shift_end: DateTime<Utc>,
        analyst_id: Uuid,
        analyst_name: String,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            shift_start,
            shift_end,
            analyst_id,
            analyst_name,
            open_incidents: Vec::new(),
            pending_actions: Vec::new(),
            notable_events: Vec::new(),
            recommendations: Vec::new(),
            created_at: Utc::now(),
        }
    }

    /// Adds an open incident summary.
    pub fn add_incident(&mut self, summary: IncidentSummary) {
        self.open_incidents.push(summary);
    }

    /// Adds a pending action summary.
    pub fn add_action(&mut self, summary: ActionSummary) {
        self.pending_actions.push(summary);
    }

    /// Adds a notable event description.
    pub fn add_notable_event(&mut self, event: String) {
        self.notable_events.push(event);
    }

    /// Adds a recommendation.
    pub fn add_recommendation(&mut self, recommendation: String) {
        self.recommendations.push(recommendation);
    }

    /// Returns the total number of items needing attention.
    pub fn items_needing_attention(&self) -> usize {
        self.open_incidents.len() + self.pending_actions.len()
    }
}

/// Summary of an open incident for handoff reports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentSummary {
    /// Incident ID.
    pub id: Uuid,
    /// Incident title.
    pub title: String,
    /// Current severity.
    pub severity: String,
    /// Current status.
    pub status: String,
    /// Who it is assigned to (if anyone).
    pub assigned_to: Option<String>,
    /// When it was last updated.
    pub last_updated: DateTime<Utc>,
}

/// Summary of a pending action for handoff reports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionSummary {
    /// Action ID.
    pub id: Uuid,
    /// Action description.
    pub description: String,
    /// Current status.
    pub status: String,
    /// Related incident ID.
    pub incident_id: Uuid,
}

/// Request to generate a shift handoff report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShiftHandoffRequest {
    /// Start of the shift.
    pub shift_start: DateTime<Utc>,
    /// End of the shift.
    pub shift_end: DateTime<Utc>,
    /// Optional notes from the analyst.
    pub notes: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_incident_summary() -> IncidentSummary {
        IncidentSummary {
            id: Uuid::new_v4(),
            title: "Suspicious login from unusual location".to_string(),
            severity: "high".to_string(),
            status: "investigating".to_string(),
            assigned_to: Some("Alice".to_string()),
            last_updated: Utc::now(),
        }
    }

    fn sample_action_summary() -> ActionSummary {
        ActionSummary {
            id: Uuid::new_v4(),
            description: "Block IP 10.0.0.1".to_string(),
            status: "pending_approval".to_string(),
            incident_id: Uuid::new_v4(),
        }
    }

    #[test]
    fn test_handoff_creation() {
        let analyst_id = Uuid::new_v4();
        let start = Utc::now() - chrono::Duration::hours(8);
        let end = Utc::now();

        let handoff = ShiftHandoff::new(start, end, analyst_id, "Alice".to_string());

        assert_eq!(handoff.analyst_id, analyst_id);
        assert_eq!(handoff.analyst_name, "Alice");
        assert!(handoff.open_incidents.is_empty());
        assert!(handoff.pending_actions.is_empty());
        assert!(handoff.notable_events.is_empty());
        assert!(handoff.recommendations.is_empty());
    }

    #[test]
    fn test_add_incident() {
        let mut handoff = ShiftHandoff::new(
            Utc::now() - chrono::Duration::hours(8),
            Utc::now(),
            Uuid::new_v4(),
            "Bob".to_string(),
        );

        handoff.add_incident(sample_incident_summary());
        assert_eq!(handoff.open_incidents.len(), 1);
        assert_eq!(
            handoff.open_incidents[0].title,
            "Suspicious login from unusual location"
        );
    }

    #[test]
    fn test_add_action() {
        let mut handoff = ShiftHandoff::new(
            Utc::now() - chrono::Duration::hours(8),
            Utc::now(),
            Uuid::new_v4(),
            "Carol".to_string(),
        );

        handoff.add_action(sample_action_summary());
        assert_eq!(handoff.pending_actions.len(), 1);
    }

    #[test]
    fn test_add_notable_event() {
        let mut handoff = ShiftHandoff::new(
            Utc::now() - chrono::Duration::hours(8),
            Utc::now(),
            Uuid::new_v4(),
            "Dave".to_string(),
        );

        handoff.add_notable_event("Phishing campaign targeting finance team".to_string());
        handoff.add_notable_event("New CVE published affecting our web servers".to_string());
        assert_eq!(handoff.notable_events.len(), 2);
    }

    #[test]
    fn test_add_recommendation() {
        let mut handoff = ShiftHandoff::new(
            Utc::now() - chrono::Duration::hours(8),
            Utc::now(),
            Uuid::new_v4(),
            "Eve".to_string(),
        );

        handoff.add_recommendation("Monitor INC-2045 closely for lateral movement".to_string());
        assert_eq!(handoff.recommendations.len(), 1);
    }

    #[test]
    fn test_items_needing_attention() {
        let mut handoff = ShiftHandoff::new(
            Utc::now() - chrono::Duration::hours(8),
            Utc::now(),
            Uuid::new_v4(),
            "Frank".to_string(),
        );

        assert_eq!(handoff.items_needing_attention(), 0);

        handoff.add_incident(sample_incident_summary());
        handoff.add_incident(sample_incident_summary());
        handoff.add_action(sample_action_summary());

        assert_eq!(handoff.items_needing_attention(), 3);
    }

    #[test]
    fn test_handoff_serialization_roundtrip() {
        let mut handoff = ShiftHandoff::new(
            Utc::now() - chrono::Duration::hours(8),
            Utc::now(),
            Uuid::new_v4(),
            "Grace".to_string(),
        );
        handoff.add_incident(sample_incident_summary());
        handoff.add_action(sample_action_summary());
        handoff.add_notable_event("Test event".to_string());
        handoff.add_recommendation("Test recommendation".to_string());

        let json = serde_json::to_string(&handoff).unwrap();
        let deserialized: ShiftHandoff = serde_json::from_str(&json).unwrap();

        assert_eq!(handoff.id, deserialized.id);
        assert_eq!(handoff.analyst_name, deserialized.analyst_name);
        assert_eq!(
            handoff.open_incidents.len(),
            deserialized.open_incidents.len()
        );
        assert_eq!(
            handoff.pending_actions.len(),
            deserialized.pending_actions.len()
        );
        assert_eq!(
            handoff.notable_events.len(),
            deserialized.notable_events.len()
        );
    }

    #[test]
    fn test_handoff_request_deserialization() {
        let json = r#"{
            "shift_start": "2025-01-15T08:00:00Z",
            "shift_end": "2025-01-15T16:00:00Z",
            "notes": "Quiet shift overall"
        }"#;

        let request: ShiftHandoffRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.notes, Some("Quiet shift overall".to_string()));
    }

    #[test]
    fn test_handoff_request_without_notes() {
        let json = r#"{
            "shift_start": "2025-01-15T08:00:00Z",
            "shift_end": "2025-01-15T16:00:00Z"
        }"#;

        let request: ShiftHandoffRequest = serde_json::from_str(json).unwrap();
        assert!(request.notes.is_none());
    }
}
