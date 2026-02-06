//! Real-time event types for live updates.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::comment::IncidentComment;

/// Events pushed to connected clients for real-time updates.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RealtimeEvent {
    /// An incident's fields were updated.
    IncidentUpdated {
        /// Incident ID.
        id: Uuid,
        /// List of changed fields.
        changes: Vec<FieldChange>,
    },
    /// An incident was assigned to a user.
    IncidentAssigned {
        /// Incident ID.
        id: Uuid,
        /// New assignee user ID.
        assignee_id: Uuid,
    },
    /// A comment was added to an incident.
    CommentAdded {
        /// Incident ID.
        incident_id: Uuid,
        /// The new comment.
        comment: IncidentComment,
    },
    /// An action's status changed.
    ActionStatusChanged {
        /// Action ID.
        action_id: Uuid,
        /// New status string.
        status: String,
    },
    /// A new incident was created.
    NewIncident {
        /// Incident ID.
        id: Uuid,
        /// Severity string.
        severity: String,
        /// Incident title.
        title: String,
    },
}

/// Describes a change to a single field on an incident.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FieldChange {
    /// Name of the field that changed.
    pub field_name: String,
    /// Previous value (None if the field was unset).
    pub old_value: Option<serde_json::Value>,
    /// New value (None if the field was cleared).
    pub new_value: Option<serde_json::Value>,
}

impl FieldChange {
    /// Creates a new field change record.
    pub fn new(
        field_name: String,
        old_value: Option<serde_json::Value>,
        new_value: Option<serde_json::Value>,
    ) -> Self {
        Self {
            field_name,
            old_value,
            new_value,
        }
    }
}

/// A user's subscription to real-time events with optional filters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealtimeSubscription {
    /// The subscribing user's ID.
    pub user_id: Uuid,
    /// Filters to narrow which events the user receives.
    pub filters: SubscriptionFilter,
}

/// Filters applied to a real-time subscription.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SubscriptionFilter {
    /// Only receive events for these specific incidents.
    pub incident_ids: Option<Vec<Uuid>>,
    /// Only receive events for incidents with these severities.
    pub severities: Option<Vec<String>>,
    /// Only receive events for incidents assigned to the subscribing user.
    #[serde(default)]
    pub assigned_to_me: bool,
}

impl SubscriptionFilter {
    /// Returns true if the filter matches the given event.
    pub fn matches(&self, event: &RealtimeEvent, user_id: Uuid) -> bool {
        match event {
            RealtimeEvent::IncidentUpdated { id, .. }
            | RealtimeEvent::IncidentAssigned { id, .. } => {
                self.matches_incident_id(*id) && self.matches_assignment(event, user_id)
            }
            RealtimeEvent::CommentAdded { incident_id, .. } => {
                self.matches_incident_id(*incident_id)
            }
            RealtimeEvent::ActionStatusChanged { .. } => true,
            RealtimeEvent::NewIncident { id, severity, .. } => {
                self.matches_incident_id(*id) && self.matches_severity(severity)
            }
        }
    }

    fn matches_incident_id(&self, id: Uuid) -> bool {
        match &self.incident_ids {
            Some(ids) => ids.contains(&id),
            None => true,
        }
    }

    fn matches_severity(&self, severity: &str) -> bool {
        match &self.severities {
            Some(sevs) => sevs.iter().any(|s| s.eq_ignore_ascii_case(severity)),
            None => true,
        }
    }

    fn matches_assignment(&self, event: &RealtimeEvent, user_id: Uuid) -> bool {
        if !self.assigned_to_me {
            return true;
        }
        // For assigned_to_me filter, check if the incident is being assigned to this user
        if let RealtimeEvent::IncidentAssigned { assignee_id, .. } = event {
            return *assignee_id == user_id;
        }
        // For other events, we can't determine assignment from the event alone,
        // so we pass through (external filtering needed).
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_change_creation() {
        let change = FieldChange::new(
            "severity".to_string(),
            Some(serde_json::json!("medium")),
            Some(serde_json::json!("high")),
        );
        assert_eq!(change.field_name, "severity");
        assert_eq!(change.old_value, Some(serde_json::json!("medium")));
        assert_eq!(change.new_value, Some(serde_json::json!("high")));
    }

    #[test]
    fn test_realtime_event_serialization_incident_updated() {
        let event = RealtimeEvent::IncidentUpdated {
            id: Uuid::nil(),
            changes: vec![FieldChange::new(
                "status".to_string(),
                Some(serde_json::json!("open")),
                Some(serde_json::json!("investigating")),
            )],
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"type\":\"incident_updated\""));

        let deserialized: RealtimeEvent = serde_json::from_str(&json).unwrap();
        if let RealtimeEvent::IncidentUpdated { changes, .. } = deserialized {
            assert_eq!(changes.len(), 1);
            assert_eq!(changes[0].field_name, "status");
        } else {
            panic!("Wrong event type after deserialization");
        }
    }

    #[test]
    fn test_realtime_event_serialization_new_incident() {
        let event = RealtimeEvent::NewIncident {
            id: Uuid::nil(),
            severity: "critical".to_string(),
            title: "Ransomware detected".to_string(),
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"type\":\"new_incident\""));
        assert!(json.contains("Ransomware detected"));
    }

    #[test]
    fn test_realtime_event_serialization_assigned() {
        let event = RealtimeEvent::IncidentAssigned {
            id: Uuid::nil(),
            assignee_id: Uuid::nil(),
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"type\":\"incident_assigned\""));
    }

    #[test]
    fn test_realtime_event_serialization_action_status() {
        let event = RealtimeEvent::ActionStatusChanged {
            action_id: Uuid::nil(),
            status: "completed".to_string(),
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"type\":\"action_status_changed\""));
    }

    #[test]
    fn test_filter_no_filters_matches_everything() {
        let filter = SubscriptionFilter::default();
        let user_id = Uuid::new_v4();

        let event = RealtimeEvent::NewIncident {
            id: Uuid::new_v4(),
            severity: "low".to_string(),
            title: "Test".to_string(),
        };
        assert!(filter.matches(&event, user_id));
    }

    #[test]
    fn test_filter_by_incident_id() {
        let target_id = Uuid::new_v4();
        let other_id = Uuid::new_v4();
        let filter = SubscriptionFilter {
            incident_ids: Some(vec![target_id]),
            ..Default::default()
        };

        let user_id = Uuid::new_v4();

        let matching = RealtimeEvent::IncidentUpdated {
            id: target_id,
            changes: vec![],
        };
        assert!(filter.matches(&matching, user_id));

        let non_matching = RealtimeEvent::IncidentUpdated {
            id: other_id,
            changes: vec![],
        };
        assert!(!filter.matches(&non_matching, user_id));
    }

    #[test]
    fn test_filter_by_severity() {
        let filter = SubscriptionFilter {
            severities: Some(vec!["critical".to_string(), "high".to_string()]),
            ..Default::default()
        };

        let user_id = Uuid::new_v4();

        let critical = RealtimeEvent::NewIncident {
            id: Uuid::new_v4(),
            severity: "Critical".to_string(),
            title: "Test".to_string(),
        };
        assert!(filter.matches(&critical, user_id));

        let low = RealtimeEvent::NewIncident {
            id: Uuid::new_v4(),
            severity: "low".to_string(),
            title: "Test".to_string(),
        };
        assert!(!filter.matches(&low, user_id));
    }

    #[test]
    fn test_filter_assigned_to_me() {
        let my_id = Uuid::new_v4();
        let other_id = Uuid::new_v4();
        let filter = SubscriptionFilter {
            assigned_to_me: true,
            ..Default::default()
        };

        let assigned_to_me = RealtimeEvent::IncidentAssigned {
            id: Uuid::new_v4(),
            assignee_id: my_id,
        };
        assert!(filter.matches(&assigned_to_me, my_id));

        let assigned_to_other = RealtimeEvent::IncidentAssigned {
            id: Uuid::new_v4(),
            assignee_id: other_id,
        };
        assert!(!filter.matches(&assigned_to_other, my_id));
    }

    #[test]
    fn test_subscription_serialization() {
        let sub = RealtimeSubscription {
            user_id: Uuid::new_v4(),
            filters: SubscriptionFilter {
                incident_ids: None,
                severities: Some(vec!["critical".to_string()]),
                assigned_to_me: true,
            },
        };

        let json = serde_json::to_string(&sub).unwrap();
        let deserialized: RealtimeSubscription = serde_json::from_str(&json).unwrap();
        assert_eq!(sub.user_id, deserialized.user_id);
        assert!(deserialized.filters.assigned_to_me);
    }
}
