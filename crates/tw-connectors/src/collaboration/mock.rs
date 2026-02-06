//! Mock collaboration connector for testing.
//!
//! Records all sent messages for test verification without making real API calls.

use crate::traits::{ConnectorError, ConnectorHealth, ConnectorResult};
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::RwLock;

/// A recorded message sent through the mock connector.
#[derive(Debug, Clone)]
pub struct RecordedMessage {
    /// Target channel or recipient.
    pub channel: String,
    /// Message text content.
    pub text: String,
    /// Whether this was a rich/block message.
    pub is_rich: bool,
    /// Timestamp when the message was recorded.
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Mock collaboration connector for testing notification delivery.
pub struct MockCollaborationConnector {
    name: String,
    messages: Arc<RwLock<Vec<RecordedMessage>>>,
    should_fail: Arc<RwLock<bool>>,
}

impl MockCollaborationConnector {
    /// Creates a new mock collaboration connector.
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            messages: Arc::new(RwLock::new(Vec::new())),
            should_fail: Arc::new(RwLock::new(false)),
        }
    }

    /// Sends a message to a channel (records it for test verification).
    pub async fn send_message(&self, channel: &str, text: &str) -> ConnectorResult<()> {
        let should_fail = *self.should_fail.read().await;
        if should_fail {
            return Err(ConnectorError::RequestFailed("Mock failure".to_string()));
        }

        let mut messages = self.messages.write().await;
        messages.push(RecordedMessage {
            channel: channel.to_string(),
            text: text.to_string(),
            is_rich: false,
            timestamp: chrono::Utc::now(),
        });
        Ok(())
    }

    /// Sends a rich message (records it for test verification).
    pub async fn send_rich_message(&self, channel: &str, text: &str) -> ConnectorResult<()> {
        let should_fail = *self.should_fail.read().await;
        if should_fail {
            return Err(ConnectorError::RequestFailed("Mock failure".to_string()));
        }

        let mut messages = self.messages.write().await;
        messages.push(RecordedMessage {
            channel: channel.to_string(),
            text: text.to_string(),
            is_rich: true,
            timestamp: chrono::Utc::now(),
        });
        Ok(())
    }

    /// Sets whether the connector should fail on the next call.
    pub async fn set_should_fail(&self, should_fail: bool) {
        let mut sf = self.should_fail.write().await;
        *sf = should_fail;
    }

    /// Gets all recorded messages.
    pub async fn get_messages(&self) -> Vec<RecordedMessage> {
        let messages = self.messages.read().await;
        messages.clone()
    }

    /// Gets messages for a specific channel.
    pub async fn get_channel_messages(&self, channel: &str) -> Vec<RecordedMessage> {
        let messages = self.messages.read().await;
        messages
            .iter()
            .filter(|m| m.channel == channel)
            .cloned()
            .collect()
    }

    /// Clears all recorded messages.
    pub async fn clear(&self) {
        let mut messages = self.messages.write().await;
        messages.clear();
    }

    /// Returns the total number of messages sent.
    pub async fn message_count(&self) -> usize {
        let messages = self.messages.read().await;
        messages.len()
    }
}

#[async_trait]
impl crate::traits::Connector for MockCollaborationConnector {
    fn name(&self) -> &str {
        &self.name
    }

    fn connector_type(&self) -> &str {
        "collaboration"
    }

    async fn health_check(&self) -> ConnectorResult<ConnectorHealth> {
        let should_fail = *self.should_fail.read().await;
        if should_fail {
            Ok(ConnectorHealth::Unhealthy("Mock failure mode".to_string()))
        } else {
            Ok(ConnectorHealth::Healthy)
        }
    }

    async fn test_connection(&self) -> ConnectorResult<bool> {
        let should_fail = *self.should_fail.read().await;
        Ok(!should_fail)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::Connector;

    #[tokio::test]
    async fn test_send_message() {
        let connector = MockCollaborationConnector::new("test-slack");
        connector
            .send_message("#security", "Test alert")
            .await
            .unwrap();

        let messages = connector.get_messages().await;
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].channel, "#security");
        assert_eq!(messages[0].text, "Test alert");
        assert!(!messages[0].is_rich);
    }

    #[tokio::test]
    async fn test_send_rich_message() {
        let connector = MockCollaborationConnector::new("test-teams");
        connector
            .send_rich_message("#incidents", "Rich notification")
            .await
            .unwrap();

        let messages = connector.get_messages().await;
        assert_eq!(messages.len(), 1);
        assert!(messages[0].is_rich);
    }

    #[tokio::test]
    async fn test_failure_mode() {
        let connector = MockCollaborationConnector::new("test");
        connector.set_should_fail(true).await;

        let result = connector.send_message("#test", "Should fail").await;
        assert!(result.is_err());

        // No messages should be recorded
        assert_eq!(connector.message_count().await, 0);
    }

    #[tokio::test]
    async fn test_channel_filtering() {
        let connector = MockCollaborationConnector::new("test");
        connector
            .send_message("#security", "Security alert")
            .await
            .unwrap();
        connector
            .send_message("#general", "General message")
            .await
            .unwrap();
        connector
            .send_message("#security", "Another alert")
            .await
            .unwrap();

        let security_messages = connector.get_channel_messages("#security").await;
        assert_eq!(security_messages.len(), 2);

        let general_messages = connector.get_channel_messages("#general").await;
        assert_eq!(general_messages.len(), 1);
    }

    #[tokio::test]
    async fn test_clear() {
        let connector = MockCollaborationConnector::new("test");
        connector.send_message("#test", "Message 1").await.unwrap();
        connector.send_message("#test", "Message 2").await.unwrap();

        assert_eq!(connector.message_count().await, 2);

        connector.clear().await;
        assert_eq!(connector.message_count().await, 0);
    }

    #[tokio::test]
    async fn test_health_check() {
        let connector = MockCollaborationConnector::new("test");

        let health = connector.health_check().await.unwrap();
        assert!(matches!(health, ConnectorHealth::Healthy));

        connector.set_should_fail(true).await;
        let health = connector.health_check().await.unwrap();
        assert!(matches!(health, ConnectorHealth::Unhealthy(_)));
    }

    #[tokio::test]
    async fn test_connector_metadata() {
        let connector = MockCollaborationConnector::new("test-collab");
        assert_eq!(connector.name(), "test-collab");
        assert_eq!(connector.connector_type(), "collaboration");
    }

    #[tokio::test]
    async fn test_test_connection() {
        let connector = MockCollaborationConnector::new("test");

        assert!(connector.test_connection().await.unwrap());

        connector.set_should_fail(true).await;
        assert!(!connector.test_connection().await.unwrap());
    }
}
