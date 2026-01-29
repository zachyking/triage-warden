//! Slack notification channel for Triage Warden.
//!
//! This module provides Slack webhook integration for sending notifications.

use super::{Notification, NotificationError, NotificationPriority, NotificationType, Notifier};
use async_trait::async_trait;
use serde::Serialize;
use tracing::{debug, error, instrument};

/// A notifier that sends messages to Slack via webhook.
pub struct SlackNotifier {
    /// The Slack webhook URL.
    webhook_url: String,
    /// Optional channel override (if webhook allows it).
    channel: Option<String>,
    /// HTTP client for sending requests.
    #[cfg(not(test))]
    client: reqwest::Client,
}

impl SlackNotifier {
    /// Creates a new Slack notifier.
    pub fn new(webhook_url: impl Into<String>) -> Result<Self, NotificationError> {
        let url = webhook_url.into();
        if url.is_empty() {
            return Err(NotificationError::InvalidConfig(
                "Slack webhook URL cannot be empty".to_string(),
            ));
        }

        Ok(Self {
            webhook_url: url,
            channel: None,
            #[cfg(not(test))]
            client: reqwest::Client::new(),
        })
    }

    /// Sets the channel override.
    pub fn with_channel(mut self, channel: impl Into<String>) -> Self {
        self.channel = Some(channel.into());
        self
    }

    /// Formats a notification as Slack blocks.
    fn format_message(&self, notification: &Notification) -> SlackMessage {
        let color = notification.priority.color();
        let type_emoji = match notification.notification_type {
            NotificationType::ApprovalRequired => ":ballot_box_with_check:",
            NotificationType::Escalation => ":arrow_up:",
            NotificationType::Alert => ":warning:",
            NotificationType::Info => ":information_source:",
        };

        let priority_emoji = match notification.priority {
            NotificationPriority::Low => ":white_circle:",
            NotificationPriority::Normal => ":large_blue_circle:",
            NotificationPriority::High => ":large_orange_circle:",
            NotificationPriority::Urgent => ":red_circle:",
        };

        let header = format!(
            "{} {} | {} {}",
            type_emoji,
            notification.notification_type,
            priority_emoji,
            notification.priority
        );

        let mut fields = vec![
            SlackField {
                title: "Notification ID".to_string(),
                value: notification.id.to_string(),
                short: true,
            },
            SlackField {
                title: "Created".to_string(),
                value: notification.created_at.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
                short: true,
            },
        ];

        // Add metadata as fields
        for (key, value) in &notification.metadata {
            fields.push(SlackField {
                title: key.clone(),
                value: value.clone(),
                short: true,
            });
        }

        let attachments = vec![SlackAttachment {
            color: color.to_string(),
            title: notification.title.clone(),
            text: notification.message.clone(),
            fields,
            footer: Some("Triage Warden".to_string()),
            ts: Some(notification.created_at.timestamp()),
        }];

        SlackMessage {
            channel: self.channel.clone(),
            text: header,
            attachments,
        }
    }

    /// Sends the message to Slack (actual HTTP call).
    #[cfg(not(test))]
    async fn send_to_slack(&self, message: &SlackMessage) -> Result<(), NotificationError> {
        let response = self
            .client
            .post(&self.webhook_url)
            .json(message)
            .send()
            .await
            .map_err(|e| NotificationError::SendFailed(format!("HTTP request failed: {}", e)))?;

        if response.status().is_success() {
            Ok(())
        } else if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            Err(NotificationError::RateLimited(
                "Slack rate limit exceeded".to_string(),
            ))
        } else {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "Unable to read response body".to_string());
            Err(NotificationError::SendFailed(format!(
                "Slack returned {}: {}",
                status, body
            )))
        }
    }

    /// Mock send for testing.
    #[cfg(test)]
    async fn send_to_slack(&self, _message: &SlackMessage) -> Result<(), NotificationError> {
        // In tests, we just verify the message was formatted correctly
        Ok(())
    }
}

#[async_trait]
impl Notifier for SlackNotifier {
    #[instrument(skip(self, notification), fields(webhook_url = %self.webhook_url, channel = ?self.channel))]
    async fn send(&self, notification: &Notification) -> Result<(), NotificationError> {
        let message = self.format_message(notification);
        debug!(
            notification_id = %notification.id,
            "Sending notification to Slack"
        );

        match self.send_to_slack(&message).await {
            Ok(()) => {
                debug!(
                    notification_id = %notification.id,
                    "Successfully sent notification to Slack"
                );
                Ok(())
            }
            Err(e) => {
                error!(
                    notification_id = %notification.id,
                    error = %e,
                    "Failed to send notification to Slack"
                );
                Err(e)
            }
        }
    }

    fn name(&self) -> &str {
        "slack"
    }
}

/// Slack message payload.
#[derive(Debug, Serialize)]
struct SlackMessage {
    #[serde(skip_serializing_if = "Option::is_none")]
    channel: Option<String>,
    text: String,
    attachments: Vec<SlackAttachment>,
}

/// Slack attachment.
#[derive(Debug, Serialize)]
struct SlackAttachment {
    color: String,
    title: String,
    text: String,
    fields: Vec<SlackField>,
    #[serde(skip_serializing_if = "Option::is_none")]
    footer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ts: Option<i64>,
}

/// Slack field within an attachment.
#[derive(Debug, Serialize)]
struct SlackField {
    title: String,
    value: String,
    short: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slack_notifier_creation() {
        let notifier = SlackNotifier::new("https://hooks.slack.com/services/xxx/yyy/zzz");
        assert!(notifier.is_ok());
        let notifier = notifier.unwrap();
        assert_eq!(notifier.name(), "slack");
    }

    #[test]
    fn test_slack_notifier_empty_url() {
        let result = SlackNotifier::new("");
        assert!(result.is_err());
        if let Err(NotificationError::InvalidConfig(msg)) = result {
            assert!(msg.contains("cannot be empty"));
        } else {
            panic!("Expected InvalidConfig error");
        }
    }

    #[test]
    fn test_slack_notifier_with_channel() {
        let notifier = SlackNotifier::new("https://hooks.slack.com/services/xxx/yyy/zzz")
            .unwrap()
            .with_channel("#alerts");

        assert_eq!(notifier.channel, Some("#alerts".to_string()));
    }

    #[test]
    fn test_message_formatting() {
        let notifier = SlackNotifier::new("https://hooks.slack.com/test")
            .unwrap()
            .with_channel("#test");

        let notification = Notification::alert(
            "Security Alert",
            "Suspicious activity detected on server-001",
            NotificationPriority::High,
        )
        .with_metadata("incident_id", "INC-12345")
        .with_metadata("source", "SIEM");

        let message = notifier.format_message(&notification);

        assert_eq!(message.channel, Some("#test".to_string()));
        assert!(message.text.contains("Alert"));
        assert!(message.text.contains("High"));
        assert_eq!(message.attachments.len(), 1);

        let attachment = &message.attachments[0];
        assert_eq!(attachment.title, "Security Alert");
        assert_eq!(
            attachment.text,
            "Suspicious activity detected on server-001"
        );
        assert_eq!(attachment.color, NotificationPriority::High.color());

        // Check fields include metadata
        let field_titles: Vec<&str> = attachment.fields.iter().map(|f| f.title.as_str()).collect();
        assert!(field_titles.contains(&"incident_id"));
        assert!(field_titles.contains(&"source"));
        assert!(field_titles.contains(&"Notification ID"));
        assert!(field_titles.contains(&"Created"));
    }

    #[test]
    fn test_approval_required_formatting() {
        let notifier = SlackNotifier::new("https://hooks.slack.com/test").unwrap();

        let notification = Notification::approval_required(
            "Approval Needed",
            "Please review action",
            NotificationPriority::Normal,
        );

        let message = notifier.format_message(&notification);

        assert!(message.text.contains("Approval Required"));
        assert!(message.text.contains(":ballot_box_with_check:"));
    }

    #[test]
    fn test_escalation_formatting() {
        let notifier = SlackNotifier::new("https://hooks.slack.com/test").unwrap();

        let notification = Notification::escalation(
            "Escalation",
            "Issue escalated to manager",
            NotificationPriority::Urgent,
        );

        let message = notifier.format_message(&notification);

        assert!(message.text.contains("Escalation"));
        assert!(message.text.contains(":arrow_up:"));
        assert!(message.text.contains("Urgent"));
        assert!(message.text.contains(":red_circle:"));
    }

    #[test]
    fn test_info_formatting() {
        let notifier = SlackNotifier::new("https://hooks.slack.com/test").unwrap();

        let notification = Notification::info("Information", "System status update");

        let message = notifier.format_message(&notification);

        assert!(message.text.contains("Info"));
        assert!(message.text.contains(":information_source:"));
        assert!(message.text.contains(":white_circle:")); // Low priority
    }

    #[tokio::test]
    async fn test_send_notification() {
        let notifier = SlackNotifier::new("https://hooks.slack.com/test").unwrap();
        let notification = Notification::info("Test", "Test message");

        // In test mode, this should succeed without making HTTP calls
        let result = notifier.send(&notification).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_message_serialization() {
        let notifier = SlackNotifier::new("https://hooks.slack.com/test").unwrap();
        let notification = Notification::alert("Test", "Message", NotificationPriority::Normal);

        let message = notifier.format_message(&notification);
        let json = serde_json::to_string(&message);

        assert!(json.is_ok());
        let json_str = json.unwrap();
        assert!(json_str.contains("\"text\":"));
        assert!(json_str.contains("\"attachments\":"));
        assert!(json_str.contains("\"color\":"));
    }
}
