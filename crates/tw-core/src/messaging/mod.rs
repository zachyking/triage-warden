//! Message queue abstraction for distributed processing.
//!
//! This module provides a trait-based abstraction over message queues, enabling
//! Triage Warden to swap between different message queue implementations (Redis
//! Streams, RabbitMQ, Kafka) without changing application code.
//!
//! # Architecture
//!
//! The [`MessageQueue`] trait is the cornerstone of distributed processing in
//! Triage Warden. All orchestrator instances communicate through this interface,
//! enabling horizontal scaling and fault tolerance.
//!
//! ```text
//! ┌─────────────────┐     ┌─────────────────┐
//! │  Orchestrator 1 │────▶│                 │
//! └─────────────────┘     │  MessageQueue   │
//!                         │  (Redis/RabbitMQ│────▶ Consumers
//! ┌─────────────────┐     │   /Kafka)       │
//! │  Orchestrator 2 │────▶│                 │
//! └─────────────────┘     └─────────────────┘
//! ```
//!
//! # Consumer Groups
//!
//! Messages are delivered to consumer groups, not individual consumers. All
//! subscribers in the same group share the message load - each message is
//! processed by exactly one consumer in the group. This enables:
//!
//! - **Load balancing**: Work is distributed across consumers
//! - **Fault tolerance**: If one consumer fails, others continue processing
//! - **Exactly-once semantics**: Messages are acknowledged after processing
//!
//! # Message Acknowledgment
//!
//! Messages must be explicitly acknowledged after successful processing:
//!
//! ```ignore
//! let mut subscription = queue.subscribe("alerts", "worker-group").await?;
//! while let Some(message) = subscription.recv().await {
//!     match process_alert(&message).await {
//!         Ok(_) => {
//!             queue.acknowledge("alerts", &message.id).await?;
//!         }
//!         Err(e) => {
//!             // Message will be redelivered after visibility timeout
//!             tracing::error!("Failed to process alert: {}", e);
//!         }
//!     }
//! }
//! ```
//!
//! # Example Usage
//!
//! ```ignore
//! use tw_core::messaging::{MessageQueue, MockMessageQueue};
//!
//! // Create a mock queue for testing
//! let queue = MockMessageQueue::new();
//!
//! // Publish a message
//! let payload = serde_json::to_vec(&event)?;
//! let msg_id = queue.publish("triage.alerts", &payload).await?;
//!
//! // Subscribe to messages
//! let mut subscription = queue.subscribe("triage.alerts", "analyzer").await?;
//! if let Some(msg) = subscription.recv().await {
//!     // Process message
//!     queue.acknowledge("triage.alerts", &msg.id).await?;
//! }
//!
//! // Check health
//! let health = queue.health_check().await?;
//! assert!(health.connected);
//! ```
//!
//! # Implementations
//!
//! - [`MockMessageQueue`]: In-memory implementation for testing
//! - Future: `RedisMessageQueue`, `RabbitMQMessageQueue`, `KafkaMessageQueue`

pub mod error;
pub mod mock;
pub mod types;

pub use error::{MessageQueueError, MessageQueueResult};
pub use mock::MockMessageQueue;
pub use types::{Message, MessageId, QueueHealth, SubscribeOptions, Subscription};

use async_trait::async_trait;

/// A trait for message queue implementations.
///
/// This trait defines the interface for publishing messages, subscribing to
/// topics, acknowledging message processing, and checking queue health.
///
/// # Implementation Requirements
///
/// Implementations must be:
/// - **Thread-safe**: The trait requires `Send + Sync`
/// - **Async**: All methods are async
/// - **Statically sized**: Required for `Arc<dyn MessageQueue>`
///
/// # Topic Naming
///
/// Topics should follow a hierarchical naming convention:
/// - `triage.alerts` - New alerts from sources
/// - `triage.enrichment` - Enrichment requests/results
/// - `triage.analysis` - AI analysis tasks
/// - `triage.actions` - Proposed/executed actions
///
/// # Error Handling
///
/// All methods return [`Result`] with [`MessageQueueError`]. Implementations
/// should:
/// - Return `Connection` errors for network failures
/// - Return `Timeout` errors for operations that exceed configured timeouts
/// - Return `Serialization` errors for malformed data
/// - Return appropriate specific errors for other failure modes
///
/// # Example Implementation
///
/// See [`MockMessageQueue`] for a reference implementation using Tokio channels.
#[async_trait]
pub trait MessageQueue: Send + Sync + 'static {
    /// Publishes a message to the specified topic.
    ///
    /// # Arguments
    ///
    /// * `topic` - The topic/stream to publish to (e.g., "triage.alerts")
    /// * `message` - The message payload as raw bytes
    ///
    /// # Returns
    ///
    /// Returns the unique [`MessageId`] assigned to the published message.
    /// This ID can be used for acknowledgment or message tracking.
    ///
    /// # Errors
    ///
    /// - [`MessageQueueError::Connection`] - Failed to connect to the queue
    /// - [`MessageQueueError::Timeout`] - Operation timed out
    /// - [`MessageQueueError::InvalidTopic`] - Topic name is invalid
    /// - [`MessageQueueError::Serialization`] - Message too large or invalid
    ///
    /// # Example
    ///
    /// ```ignore
    /// let event = TriageEvent::AlertReceived(alert);
    /// let payload = serde_json::to_vec(&event)?;
    /// let msg_id = queue.publish("triage.alerts", &payload).await?;
    /// tracing::info!("Published message {}", msg_id);
    /// ```
    async fn publish(&self, topic: &str, message: &[u8]) -> Result<MessageId, MessageQueueError>;

    /// Subscribes to a topic as part of a consumer group.
    ///
    /// Returns a [`Subscription`] that provides a channel for receiving messages.
    /// Messages are load-balanced across all consumers in the same group.
    ///
    /// # Arguments
    ///
    /// * `topic` - The topic/stream to subscribe to
    /// * `group` - The consumer group name (e.g., "worker-1", "analyzer")
    ///
    /// # Consumer Group Semantics
    ///
    /// - All consumers in the same group share the message load
    /// - Each message is delivered to exactly one consumer per group
    /// - Different groups receive all messages independently
    ///
    /// # Returns
    ///
    /// Returns a [`Subscription`] with a receiver channel for incoming messages.
    ///
    /// # Errors
    ///
    /// - [`MessageQueueError::Connection`] - Failed to connect to the queue
    /// - [`MessageQueueError::InvalidTopic`] - Topic doesn't exist
    /// - [`MessageQueueError::InvalidGroup`] - Group name is invalid
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut subscription = queue.subscribe("triage.alerts", "analyzer").await?;
    /// while let Some(message) = subscription.recv().await {
    ///     process_message(&message)?;
    ///     queue.acknowledge("triage.alerts", &message.id).await?;
    /// }
    /// ```
    async fn subscribe(&self, topic: &str, group: &str) -> Result<Subscription, MessageQueueError>;

    /// Subscribes to a topic with advanced configuration options.
    ///
    /// This method allows configuring batch size, visibility timeout, and other
    /// advanced options that affect message delivery behavior.
    ///
    /// # Arguments
    ///
    /// * `topic` - The topic/stream to subscribe to
    /// * `group` - The consumer group name
    /// * `options` - Configuration options for the subscription
    ///
    /// # Default Implementation
    ///
    /// The default implementation ignores options and calls [`subscribe`](Self::subscribe).
    /// Implementations should override this to support advanced options.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let options = SubscribeOptions::new()
    ///     .with_batch_size(20)
    ///     .with_visibility_timeout(60);
    ///
    /// let subscription = queue.subscribe_with_options(
    ///     "triage.alerts",
    ///     "analyzer",
    ///     options
    /// ).await?;
    /// ```
    async fn subscribe_with_options(
        &self,
        topic: &str,
        group: &str,
        _options: SubscribeOptions,
    ) -> Result<Subscription, MessageQueueError> {
        // Default implementation ignores options
        self.subscribe(topic, group).await
    }

    /// Acknowledges successful processing of a message.
    ///
    /// Messages must be acknowledged to prevent redelivery. Unacknowledged
    /// messages will be redelivered to another consumer after the visibility
    /// timeout expires.
    ///
    /// # Arguments
    ///
    /// * `topic` - The topic the message was received from
    /// * `message_id` - The ID of the message to acknowledge
    ///
    /// # Errors
    ///
    /// - [`MessageQueueError::Connection`] - Failed to connect to the queue
    /// - [`MessageQueueError::MessageNotFound`] - Message doesn't exist or already acknowledged
    /// - [`MessageQueueError::InvalidTopic`] - Topic doesn't exist
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Process the message first
    /// match process_message(&message).await {
    ///     Ok(_) => {
    ///         // Only acknowledge on success
    ///         queue.acknowledge("triage.alerts", &message.id).await?;
    ///     }
    ///     Err(e) => {
    ///         // Don't acknowledge - message will be redelivered
    ///         tracing::error!("Processing failed: {}", e);
    ///     }
    /// }
    /// ```
    async fn acknowledge(
        &self,
        topic: &str,
        message_id: &MessageId,
    ) -> Result<(), MessageQueueError>;

    /// Checks the health of the message queue connection.
    ///
    /// Returns metrics about the queue connection and pending messages.
    /// Use this for health checks, monitoring, and alerting.
    ///
    /// # Returns
    ///
    /// Returns a [`QueueHealth`] struct with:
    /// - `connected`: Whether the connection is active
    /// - `pending_messages`: Number of unprocessed messages
    /// - `consumer_count`: Number of active consumers
    ///
    /// # Errors
    ///
    /// - [`MessageQueueError::Connection`] - Failed to connect to the queue
    /// - [`MessageQueueError::Timeout`] - Health check timed out
    ///
    /// # Example
    ///
    /// ```ignore
    /// let health = queue.health_check().await?;
    /// if !health.connected {
    ///     tracing::error!("Message queue disconnected!");
    /// }
    /// if health.pending_messages > 1000 {
    ///     tracing::warn!("High message backlog: {}", health.pending_messages);
    /// }
    /// ```
    async fn health_check(&self) -> Result<QueueHealth, MessageQueueError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_queue_basic_operations() {
        let queue = MockMessageQueue::new();

        // Test health check on new queue
        let health = queue.health_check().await.unwrap();
        assert!(health.connected);
        assert_eq!(health.pending_messages, 0);
    }

    #[tokio::test]
    async fn test_mock_queue_publish_subscribe() {
        let queue = MockMessageQueue::new();

        // Subscribe first
        let mut subscription = queue.subscribe("test-topic", "test-group").await.unwrap();

        // Publish a message
        let payload = b"hello world";
        let msg_id = queue.publish("test-topic", payload).await.unwrap();

        // Receive the message
        let message = subscription.recv().await.unwrap();
        assert_eq!(message.id, msg_id);
        assert_eq!(message.payload, payload);
        assert_eq!(message.topic, "test-topic");

        // Acknowledge
        queue.acknowledge("test-topic", &message.id).await.unwrap();
    }

    #[tokio::test]
    async fn test_mock_queue_multiple_subscribers() {
        let queue = MockMessageQueue::new();

        // Two subscribers in different groups should both receive the message
        let mut sub1 = queue.subscribe("test-topic", "group1").await.unwrap();
        let mut sub2 = queue.subscribe("test-topic", "group2").await.unwrap();

        // Publish a message
        let payload = b"broadcast";
        queue.publish("test-topic", payload).await.unwrap();

        // Both should receive it
        let msg1 = sub1.recv().await.unwrap();
        let msg2 = sub2.recv().await.unwrap();

        assert_eq!(msg1.payload, payload);
        assert_eq!(msg2.payload, payload);
    }
}
