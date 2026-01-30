//! Notification channel data structures.
//!
//! This module defines the types for configuring notification channels
//! that can receive alerts about incidents, actions, and system events.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The type of notification channel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChannelType {
    /// Slack webhook or bot integration.
    Slack,
    /// Microsoft Teams webhook.
    Teams,
    /// Email notifications.
    Email,
    /// PagerDuty integration for incident escalation.
    PagerDuty,
    /// Generic webhook for custom integrations.
    Webhook,
}

impl ChannelType {
    /// Returns the database string representation.
    pub fn as_db_str(&self) -> &'static str {
        match self {
            ChannelType::Slack => "slack",
            ChannelType::Teams => "teams",
            ChannelType::Email => "email",
            ChannelType::PagerDuty => "pagerduty",
            ChannelType::Webhook => "webhook",
        }
    }

    /// Parses a channel type from a database string.
    pub fn from_db_str(s: &str) -> Option<Self> {
        match s {
            "slack" => Some(ChannelType::Slack),
            "teams" => Some(ChannelType::Teams),
            "email" => Some(ChannelType::Email),
            "pagerduty" => Some(ChannelType::PagerDuty),
            "webhook" => Some(ChannelType::Webhook),
            _ => None,
        }
    }
}

/// A notification channel configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationChannel {
    /// Unique identifier for the channel.
    pub id: Uuid,
    /// Human-readable name for the channel.
    pub name: String,
    /// The type of notification channel.
    pub channel_type: ChannelType,
    /// Channel-specific configuration (webhook_url, api_token, channel, etc.).
    pub config: serde_json::Value,
    /// Event types that trigger notifications on this channel.
    pub events: Vec<String>,
    /// Whether the channel is currently enabled.
    pub enabled: bool,
    /// When the channel was created.
    pub created_at: DateTime<Utc>,
    /// When the channel was last updated.
    pub updated_at: DateTime<Utc>,
}

impl NotificationChannel {
    /// Creates a new notification channel with the given parameters.
    pub fn new(
        name: String,
        channel_type: ChannelType,
        config: serde_json::Value,
        events: Vec<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            name,
            channel_type,
            config,
            events,
            enabled: true,
            created_at: now,
            updated_at: now,
        }
    }

    /// Checks if this channel should receive notifications for the given event type.
    pub fn handles_event(&self, event: &str) -> bool {
        self.enabled && self.events.iter().any(|e| e == event)
    }
}

/// Event types that can trigger notifications.
pub const NOTIFICATION_EVENTS: &[&str] = &[
    "critical_incident",
    "action_required",
    "action_executed",
    "incident_resolved",
    "system_health",
    "policy_violation",
];

/// Partial update for a notification channel.
#[derive(Debug, Clone, Default)]
pub struct NotificationChannelUpdate {
    /// Updated name.
    pub name: Option<String>,
    /// Updated channel type.
    pub channel_type: Option<ChannelType>,
    /// Updated configuration.
    pub config: Option<serde_json::Value>,
    /// Updated event list.
    pub events: Option<Vec<String>>,
    /// Updated enabled status.
    pub enabled: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_type_db_str() {
        assert_eq!(ChannelType::Slack.as_db_str(), "slack");
        assert_eq!(ChannelType::Teams.as_db_str(), "teams");
        assert_eq!(ChannelType::Email.as_db_str(), "email");
        assert_eq!(ChannelType::PagerDuty.as_db_str(), "pagerduty");
        assert_eq!(ChannelType::Webhook.as_db_str(), "webhook");
    }

    #[test]
    fn test_channel_type_from_db_str() {
        assert_eq!(ChannelType::from_db_str("slack"), Some(ChannelType::Slack));
        assert_eq!(ChannelType::from_db_str("teams"), Some(ChannelType::Teams));
        assert_eq!(ChannelType::from_db_str("email"), Some(ChannelType::Email));
        assert_eq!(
            ChannelType::from_db_str("pagerduty"),
            Some(ChannelType::PagerDuty)
        );
        assert_eq!(
            ChannelType::from_db_str("webhook"),
            Some(ChannelType::Webhook)
        );
        assert_eq!(ChannelType::from_db_str("unknown"), None);
    }

    #[test]
    fn test_handles_event() {
        let channel = NotificationChannel::new(
            "test".to_string(),
            ChannelType::Slack,
            serde_json::json!({}),
            vec![
                "critical_incident".to_string(),
                "action_required".to_string(),
            ],
        );

        assert!(channel.handles_event("critical_incident"));
        assert!(channel.handles_event("action_required"));
        assert!(!channel.handles_event("incident_resolved"));
    }

    #[test]
    fn test_handles_event_disabled() {
        let mut channel = NotificationChannel::new(
            "test".to_string(),
            ChannelType::Slack,
            serde_json::json!({}),
            vec!["critical_incident".to_string()],
        );
        channel.enabled = false;

        assert!(!channel.handles_event("critical_incident"));
    }
}
