//! Generic webhook notification channel for Triage Warden.
//!
//! This module provides a generic HTTP webhook integration for sending notifications
//! to arbitrary endpoints.

use super::{Notification, NotificationError, Notifier};
use async_trait::async_trait;
use serde::Serialize;
use std::collections::HashMap;
use tracing::{debug, error, instrument};

/// A notifier that sends JSON payloads to a webhook URL.
pub struct WebhookNotifier {
    /// The webhook URL to send notifications to.
    url: String,
    /// Additional headers to include in the request.
    headers: HashMap<String, String>,
    /// HTTP client for sending requests.
    #[cfg(not(test))]
    client: reqwest::Client,
}

impl WebhookNotifier {
    /// Creates a new webhook notifier.
    pub fn new(url: impl Into<String>) -> Result<Self, NotificationError> {
        let url = url.into();
        if url.is_empty() {
            return Err(NotificationError::InvalidConfig(
                "Webhook URL cannot be empty".to_string(),
            ));
        }

        Ok(Self {
            url,
            headers: HashMap::new(),
            #[cfg(not(test))]
            client: reqwest::Client::new(),
        })
    }

    /// Adds a header to be included in webhook requests.
    pub fn with_header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(key.into(), value.into());
        self
    }

    /// Sets multiple headers at once.
    pub fn with_headers(mut self, headers: HashMap<String, String>) -> Self {
        self.headers.extend(headers);
        self
    }

    /// Adds an authorization header with a bearer token.
    pub fn with_bearer_token(self, token: impl Into<String>) -> Self {
        self.with_header("Authorization", format!("Bearer {}", token.into()))
    }

    /// Adds an API key header.
    pub fn with_api_key(self, key_name: impl Into<String>, key_value: impl Into<String>) -> Self {
        self.with_header(key_name, key_value)
    }

    /// Creates the JSON payload for a notification.
    fn create_payload(&self, notification: &Notification) -> WebhookPayload {
        WebhookPayload {
            id: notification.id.to_string(),
            notification_type: format!("{:?}", notification.notification_type).to_lowercase(),
            title: notification.title.clone(),
            message: notification.message.clone(),
            priority: format!("{:?}", notification.priority).to_lowercase(),
            metadata: notification.metadata.clone(),
            created_at: notification.created_at.to_rfc3339(),
        }
    }

    /// Sends the payload to the webhook URL (actual HTTP call).
    #[cfg(not(test))]
    async fn send_to_webhook(&self, payload: &WebhookPayload) -> Result<(), NotificationError> {
        let mut request = self.client.post(&self.url).json(payload);

        // Add custom headers
        for (key, value) in &self.headers {
            request = request.header(key.as_str(), value.as_str());
        }

        let response = request
            .send()
            .await
            .map_err(|e| NotificationError::SendFailed(format!("HTTP request failed: {}", e)))?;

        if response.status().is_success() {
            Ok(())
        } else if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            Err(NotificationError::RateLimited(
                "Webhook rate limit exceeded".to_string(),
            ))
        } else {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "Unable to read response body".to_string());
            Err(NotificationError::SendFailed(format!(
                "Webhook returned {}: {}",
                status, body
            )))
        }
    }

    /// Mock send for testing.
    #[cfg(test)]
    async fn send_to_webhook(&self, _payload: &WebhookPayload) -> Result<(), NotificationError> {
        // In tests, we just verify the payload was created correctly
        Ok(())
    }
}

#[async_trait]
impl Notifier for WebhookNotifier {
    #[instrument(skip(self, notification), fields(url = %self.url))]
    async fn send(&self, notification: &Notification) -> Result<(), NotificationError> {
        let payload = self.create_payload(notification);
        debug!(
            notification_id = %notification.id,
            "Sending notification to webhook"
        );

        match self.send_to_webhook(&payload).await {
            Ok(()) => {
                debug!(
                    notification_id = %notification.id,
                    "Successfully sent notification to webhook"
                );
                Ok(())
            }
            Err(e) => {
                error!(
                    notification_id = %notification.id,
                    error = %e,
                    "Failed to send notification to webhook"
                );
                Err(e)
            }
        }
    }

    fn name(&self) -> &str {
        "webhook"
    }
}

/// The JSON payload sent to webhook endpoints.
#[derive(Debug, Serialize)]
pub struct WebhookPayload {
    /// Notification ID.
    pub id: String,
    /// Type of notification.
    pub notification_type: String,
    /// Title of the notification.
    pub title: String,
    /// Message body.
    pub message: String,
    /// Priority level.
    pub priority: String,
    /// Additional metadata.
    pub metadata: HashMap<String, String>,
    /// ISO 8601 timestamp of when the notification was created.
    pub created_at: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notifications::NotificationPriority;

    #[test]
    fn test_webhook_notifier_creation() {
        let notifier = WebhookNotifier::new("https://example.com/webhook");
        assert!(notifier.is_ok());
        let notifier = notifier.unwrap();
        assert_eq!(notifier.name(), "webhook");
    }

    #[test]
    fn test_webhook_notifier_empty_url() {
        let result = WebhookNotifier::new("");
        assert!(result.is_err());
        if let Err(NotificationError::InvalidConfig(msg)) = result {
            assert!(msg.contains("cannot be empty"));
        } else {
            panic!("Expected InvalidConfig error");
        }
    }

    #[test]
    fn test_with_header() {
        let notifier = WebhookNotifier::new("https://example.com/webhook")
            .unwrap()
            .with_header("X-Custom-Header", "custom-value");

        assert_eq!(
            notifier.headers.get("X-Custom-Header"),
            Some(&"custom-value".to_string())
        );
    }

    #[test]
    fn test_with_headers() {
        let mut headers = HashMap::new();
        headers.insert("X-Header-1".to_string(), "value1".to_string());
        headers.insert("X-Header-2".to_string(), "value2".to_string());

        let notifier = WebhookNotifier::new("https://example.com/webhook")
            .unwrap()
            .with_headers(headers);

        assert_eq!(notifier.headers.len(), 2);
        assert_eq!(
            notifier.headers.get("X-Header-1"),
            Some(&"value1".to_string())
        );
        assert_eq!(
            notifier.headers.get("X-Header-2"),
            Some(&"value2".to_string())
        );
    }

    #[test]
    fn test_with_bearer_token() {
        let notifier = WebhookNotifier::new("https://example.com/webhook")
            .unwrap()
            .with_bearer_token("my-secret-token");

        assert_eq!(
            notifier.headers.get("Authorization"),
            Some(&"Bearer my-secret-token".to_string())
        );
    }

    #[test]
    fn test_with_api_key() {
        let notifier = WebhookNotifier::new("https://example.com/webhook")
            .unwrap()
            .with_api_key("X-API-Key", "secret-key");

        assert_eq!(
            notifier.headers.get("X-API-Key"),
            Some(&"secret-key".to_string())
        );
    }

    #[test]
    fn test_payload_creation() {
        let notifier = WebhookNotifier::new("https://example.com/webhook").unwrap();

        let notification = Notification::alert(
            "Security Alert",
            "Suspicious activity detected",
            NotificationPriority::High,
        )
        .with_metadata("incident_id", "INC-12345")
        .with_metadata("severity", "critical");

        let payload = notifier.create_payload(&notification);

        assert_eq!(payload.id, notification.id.to_string());
        assert_eq!(payload.notification_type, "alert");
        assert_eq!(payload.title, "Security Alert");
        assert_eq!(payload.message, "Suspicious activity detected");
        assert_eq!(payload.priority, "high");
        assert_eq!(payload.metadata.len(), 2);
        assert_eq!(
            payload.metadata.get("incident_id"),
            Some(&"INC-12345".to_string())
        );
    }

    #[test]
    fn test_payload_notification_types() {
        let notifier = WebhookNotifier::new("https://example.com/webhook").unwrap();

        let approval = Notification::approval_required("Test", "Msg", NotificationPriority::Normal);
        let payload = notifier.create_payload(&approval);
        assert_eq!(payload.notification_type, "approvalrequired");

        let escalation = Notification::escalation("Test", "Msg", NotificationPriority::High);
        let payload = notifier.create_payload(&escalation);
        assert_eq!(payload.notification_type, "escalation");

        let info = Notification::info("Test", "Msg");
        let payload = notifier.create_payload(&info);
        assert_eq!(payload.notification_type, "info");
    }

    #[test]
    fn test_payload_priorities() {
        let notifier = WebhookNotifier::new("https://example.com/webhook").unwrap();

        let low = Notification::alert("Test", "Msg", NotificationPriority::Low);
        assert_eq!(notifier.create_payload(&low).priority, "low");

        let normal = Notification::alert("Test", "Msg", NotificationPriority::Normal);
        assert_eq!(notifier.create_payload(&normal).priority, "normal");

        let high = Notification::alert("Test", "Msg", NotificationPriority::High);
        assert_eq!(notifier.create_payload(&high).priority, "high");

        let urgent = Notification::alert("Test", "Msg", NotificationPriority::Urgent);
        assert_eq!(notifier.create_payload(&urgent).priority, "urgent");
    }

    #[tokio::test]
    async fn test_send_notification() {
        let notifier = WebhookNotifier::new("https://example.com/webhook").unwrap();
        let notification = Notification::info("Test", "Test message");

        // In test mode, this should succeed without making HTTP calls
        let result = notifier.send(&notification).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_payload_serialization() {
        let notifier = WebhookNotifier::new("https://example.com/webhook").unwrap();
        let notification = Notification::alert("Test", "Message", NotificationPriority::Normal)
            .with_metadata("key", "value");

        let payload = notifier.create_payload(&notification);
        let json = serde_json::to_string(&payload);

        assert!(json.is_ok());
        let json_str = json.unwrap();
        assert!(json_str.contains("\"id\":"));
        assert!(json_str.contains("\"notification_type\":\"alert\""));
        assert!(json_str.contains("\"title\":\"Test\""));
        assert!(json_str.contains("\"message\":\"Message\""));
        assert!(json_str.contains("\"priority\":\"normal\""));
        assert!(json_str.contains("\"metadata\":"));
        assert!(json_str.contains("\"created_at\":"));
    }

    #[test]
    fn test_payload_created_at_format() {
        let notifier = WebhookNotifier::new("https://example.com/webhook").unwrap();
        let notification = Notification::info("Test", "Message");

        let payload = notifier.create_payload(&notification);

        // Should be RFC 3339 format
        assert!(payload.created_at.contains("T"));
        assert!(payload.created_at.ends_with("+00:00") || payload.created_at.ends_with("Z"));
    }

    #[test]
    fn test_chained_configuration() {
        let notifier = WebhookNotifier::new("https://example.com/webhook")
            .unwrap()
            .with_bearer_token("token")
            .with_header("X-Custom", "value")
            .with_api_key("X-API-Key", "key");

        assert_eq!(notifier.headers.len(), 3);
        assert!(notifier.headers.contains_key("Authorization"));
        assert!(notifier.headers.contains_key("X-Custom"));
        assert!(notifier.headers.contains_key("X-API-Key"));
    }
}
