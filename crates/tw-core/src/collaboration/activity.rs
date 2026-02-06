//! Activity feed for incident audit trails.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A single entry in the activity feed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityEntry {
    /// Unique activity entry identifier.
    pub id: Uuid,
    /// When the activity occurred.
    pub timestamp: DateTime<Utc>,
    /// The user who performed the action (None for system actions).
    pub actor_id: Option<Uuid>,
    /// Display name of the actor.
    pub actor_name: Option<String>,
    /// Type of activity.
    pub activity_type: ActivityType,
    /// The incident this activity relates to (if applicable).
    pub incident_id: Option<Uuid>,
    /// Human-readable description of the activity.
    pub description: String,
    /// Additional structured metadata about the activity.
    pub metadata: Option<serde_json::Value>,
}

impl ActivityEntry {
    /// Creates a new activity entry.
    pub fn new(activity_type: ActivityType, description: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            actor_id: None,
            actor_name: None,
            activity_type,
            incident_id: None,
            description,
            metadata: None,
        }
    }

    /// Sets the actor for this activity.
    pub fn with_actor(mut self, actor_id: Uuid, actor_name: String) -> Self {
        self.actor_id = Some(actor_id);
        self.actor_name = Some(actor_name);
        self
    }

    /// Sets the incident for this activity.
    pub fn with_incident(mut self, incident_id: Uuid) -> Self {
        self.incident_id = Some(incident_id);
        self
    }

    /// Sets additional metadata.
    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = Some(metadata);
        self
    }
}

/// Types of activities tracked in the feed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivityType {
    /// A new incident was created.
    IncidentCreated,
    /// An incident was updated (fields changed).
    IncidentUpdated,
    /// An incident was assigned or reassigned.
    IncidentAssigned,
    /// A comment was added to an incident.
    CommentAdded,
    /// An action was executed on an incident.
    ActionExecuted,
    /// The verdict was changed.
    VerdictChanged,
    /// The severity was changed.
    SeverityChanged,
    /// The status was changed.
    StatusChanged,
}

impl std::fmt::Display for ActivityType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ActivityType::IncidentCreated => write!(f, "incident_created"),
            ActivityType::IncidentUpdated => write!(f, "incident_updated"),
            ActivityType::IncidentAssigned => write!(f, "incident_assigned"),
            ActivityType::CommentAdded => write!(f, "comment_added"),
            ActivityType::ActionExecuted => write!(f, "action_executed"),
            ActivityType::VerdictChanged => write!(f, "verdict_changed"),
            ActivityType::SeverityChanged => write!(f, "severity_changed"),
            ActivityType::StatusChanged => write!(f, "status_changed"),
        }
    }
}

/// Filter criteria for querying the activity feed.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ActivityFilter {
    /// Filter by activity types.
    pub activity_types: Option<Vec<ActivityType>>,
    /// Filter by actor ID.
    pub actor_id: Option<Uuid>,
    /// Filter by incident ID.
    pub incident_id: Option<Uuid>,
    /// Only return activities after this timestamp.
    pub since: Option<DateTime<Utc>>,
    /// Maximum number of entries to return.
    pub limit: Option<u32>,
    /// Number of entries to skip.
    pub offset: Option<u32>,
}

impl ActivityFilter {
    /// Returns true if the given activity entry matches this filter.
    pub fn matches(&self, entry: &ActivityEntry) -> bool {
        if let Some(types) = &self.activity_types {
            if !types.contains(&entry.activity_type) {
                return false;
            }
        }
        if let Some(actor_id) = self.actor_id {
            if entry.actor_id != Some(actor_id) {
                return false;
            }
        }
        if let Some(incident_id) = self.incident_id {
            if entry.incident_id != Some(incident_id) {
                return false;
            }
        }
        if let Some(since) = self.since {
            if entry.timestamp < since {
                return false;
            }
        }
        true
    }

    /// Applies limit and offset to a list of entries.
    pub fn paginate<'a>(&self, entries: &'a [ActivityEntry]) -> &'a [ActivityEntry] {
        let offset = self.offset.unwrap_or(0) as usize;
        let limit = self.limit.unwrap_or(50) as usize;

        if offset >= entries.len() {
            return &[];
        }

        let end = (offset + limit).min(entries.len());
        &entries[offset..end]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_activity_entry_creation() {
        let entry = ActivityEntry::new(
            ActivityType::IncidentCreated,
            "New incident created from CrowdStrike alert".to_string(),
        );

        assert_eq!(entry.activity_type, ActivityType::IncidentCreated);
        assert!(entry.actor_id.is_none());
        assert!(entry.incident_id.is_none());
        assert!(entry.metadata.is_none());
    }

    #[test]
    fn test_activity_entry_with_actor() {
        let actor_id = Uuid::new_v4();
        let entry = ActivityEntry::new(ActivityType::CommentAdded, "Comment added".to_string())
            .with_actor(actor_id, "Alice".to_string());

        assert_eq!(entry.actor_id, Some(actor_id));
        assert_eq!(entry.actor_name, Some("Alice".to_string()));
    }

    #[test]
    fn test_activity_entry_with_incident() {
        let incident_id = Uuid::new_v4();
        let entry = ActivityEntry::new(
            ActivityType::SeverityChanged,
            "Severity escalated to critical".to_string(),
        )
        .with_incident(incident_id);

        assert_eq!(entry.incident_id, Some(incident_id));
    }

    #[test]
    fn test_activity_entry_with_metadata() {
        let entry = ActivityEntry::new(ActivityType::VerdictChanged, "Verdict changed".to_string())
            .with_metadata(serde_json::json!({
                "old_verdict": "false_positive",
                "new_verdict": "true_positive"
            }));

        assert!(entry.metadata.is_some());
    }

    #[test]
    fn test_activity_type_display() {
        assert_eq!(
            ActivityType::IncidentCreated.to_string(),
            "incident_created"
        );
        assert_eq!(ActivityType::CommentAdded.to_string(), "comment_added");
        assert_eq!(ActivityType::ActionExecuted.to_string(), "action_executed");
        assert_eq!(ActivityType::VerdictChanged.to_string(), "verdict_changed");
        assert_eq!(ActivityType::StatusChanged.to_string(), "status_changed");
    }

    #[test]
    fn test_activity_type_serialization() {
        let json = serde_json::to_string(&ActivityType::SeverityChanged).unwrap();
        assert_eq!(json, "\"severity_changed\"");

        let deserialized: ActivityType = serde_json::from_str("\"severity_changed\"").unwrap();
        assert_eq!(deserialized, ActivityType::SeverityChanged);
    }

    #[test]
    fn test_filter_by_activity_type() {
        let entry = ActivityEntry::new(ActivityType::CommentAdded, "Comment".to_string());

        let matching = ActivityFilter {
            activity_types: Some(vec![
                ActivityType::CommentAdded,
                ActivityType::IncidentCreated,
            ]),
            ..Default::default()
        };
        assert!(matching.matches(&entry));

        let non_matching = ActivityFilter {
            activity_types: Some(vec![ActivityType::SeverityChanged]),
            ..Default::default()
        };
        assert!(!non_matching.matches(&entry));
    }

    #[test]
    fn test_filter_by_actor() {
        let actor_id = Uuid::new_v4();
        let entry = ActivityEntry::new(ActivityType::CommentAdded, "Comment".to_string())
            .with_actor(actor_id, "Alice".to_string());

        let matching = ActivityFilter {
            actor_id: Some(actor_id),
            ..Default::default()
        };
        assert!(matching.matches(&entry));

        let non_matching = ActivityFilter {
            actor_id: Some(Uuid::new_v4()),
            ..Default::default()
        };
        assert!(!non_matching.matches(&entry));
    }

    #[test]
    fn test_filter_by_incident() {
        let incident_id = Uuid::new_v4();
        let entry = ActivityEntry::new(ActivityType::IncidentUpdated, "Updated".to_string())
            .with_incident(incident_id);

        let matching = ActivityFilter {
            incident_id: Some(incident_id),
            ..Default::default()
        };
        assert!(matching.matches(&entry));

        let non_matching = ActivityFilter {
            incident_id: Some(Uuid::new_v4()),
            ..Default::default()
        };
        assert!(!non_matching.matches(&entry));
    }

    #[test]
    fn test_filter_by_since() {
        let entry = ActivityEntry::new(ActivityType::IncidentCreated, "Created".to_string());

        // Entry was just created, so "since an hour ago" should match
        let matching = ActivityFilter {
            since: Some(Utc::now() - chrono::Duration::hours(1)),
            ..Default::default()
        };
        assert!(matching.matches(&entry));

        // "Since the future" should not match
        let non_matching = ActivityFilter {
            since: Some(Utc::now() + chrono::Duration::hours(1)),
            ..Default::default()
        };
        assert!(!non_matching.matches(&entry));
    }

    #[test]
    fn test_filter_no_filters_matches_all() {
        let entry = ActivityEntry::new(ActivityType::ActionExecuted, "Action executed".to_string());

        let filter = ActivityFilter::default();
        assert!(filter.matches(&entry));
    }

    #[test]
    fn test_paginate() {
        let entries: Vec<ActivityEntry> = (0..10)
            .map(|i| ActivityEntry::new(ActivityType::IncidentCreated, format!("Entry {}", i)))
            .collect();

        let filter = ActivityFilter {
            limit: Some(3),
            offset: Some(2),
            ..Default::default()
        };

        let result = filter.paginate(&entries);
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn test_paginate_offset_beyond_end() {
        let entries: Vec<ActivityEntry> = (0..3)
            .map(|i| ActivityEntry::new(ActivityType::IncidentCreated, format!("Entry {}", i)))
            .collect();

        let filter = ActivityFilter {
            offset: Some(100),
            ..Default::default()
        };

        let result = filter.paginate(&entries);
        assert!(result.is_empty());
    }

    #[test]
    fn test_activity_entry_serialization_roundtrip() {
        let entry = ActivityEntry::new(
            ActivityType::SeverityChanged,
            "Severity changed from medium to high".to_string(),
        )
        .with_actor(Uuid::new_v4(), "Bob".to_string())
        .with_incident(Uuid::new_v4())
        .with_metadata(serde_json::json!({"old": "medium", "new": "high"}));

        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: ActivityEntry = serde_json::from_str(&json).unwrap();

        assert_eq!(entry.id, deserialized.id);
        assert_eq!(entry.activity_type, deserialized.activity_type);
        assert_eq!(entry.description, deserialized.description);
        assert_eq!(entry.actor_name, deserialized.actor_name);
    }
}
