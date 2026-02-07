//! Message types for the message queue abstraction.
//!
//! This module defines the core types used by the [`MessageQueue`](super::MessageQueue) trait
//! for distributed message passing between orchestrator instances.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

/// Unique identifier for a message in the queue.
///
/// The format of the underlying string is implementation-specific:
/// - Redis Streams: `<timestamp>-<sequence>` (e.g., "1234567890123-0")
/// - RabbitMQ: delivery tag or message ID
/// - Kafka: `<partition>-<offset>` (e.g., "0-42")
///
/// # Examples
///
/// ```
/// use tw_core::messaging::MessageId;
///
/// let id = MessageId::new("1234567890123-0".to_string());
/// assert_eq!(id.as_str(), "1234567890123-0");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MessageId(pub String);

impl MessageId {
    /// Creates a new `MessageId` from a string.
    pub fn new(id: String) -> Self {
        Self(id)
    }

    /// Returns the underlying string representation.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the `MessageId` and returns the underlying string.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl std::fmt::Display for MessageId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for MessageId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for MessageId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

/// A message received from the queue.
///
/// Messages are the fundamental unit of communication between distributed
/// orchestrator instances. Each message has a unique ID, belongs to a topic,
/// and carries an arbitrary binary payload (typically serialized JSON).
///
/// # Serialization
///
/// The `payload` field contains raw bytes. Applications typically serialize
/// domain events using serde_json before publishing:
///
/// ```ignore
/// let event = TriageEvent::AlertReceived(alert);
/// let payload = serde_json::to_vec(&event)?;
/// queue.publish("triage.alerts", &payload).await?;
/// ```
///
/// # Acknowledgment
///
/// Messages must be acknowledged after successful processing to prevent
/// redelivery. Unacknowledged messages will be redelivered after the
/// visibility timeout (implementation-specific).
#[derive(Debug, Clone)]
pub struct Message {
    /// Unique identifier for this message.
    pub id: MessageId,
    /// The topic this message was published to.
    pub topic: String,
    /// The message payload as raw bytes.
    ///
    /// Typically contains serialized JSON data. Use `serde_json::from_slice`
    /// to deserialize into your domain types.
    pub payload: Vec<u8>,
    /// Timestamp when the message was published.
    ///
    /// Set by the message queue implementation at publish time.
    pub timestamp: DateTime<Utc>,
}

impl Message {
    /// Creates a new message.
    pub fn new(id: MessageId, topic: String, payload: Vec<u8>, timestamp: DateTime<Utc>) -> Self {
        Self {
            id,
            topic,
            payload,
            timestamp,
        }
    }

    /// Attempts to deserialize the payload as JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if the payload is not valid JSON or doesn't match
    /// the expected type `T`.
    pub fn deserialize<T: for<'de> Deserialize<'de>>(&self) -> Result<T, serde_json::Error> {
        serde_json::from_slice(&self.payload)
    }
}

/// A subscription to a message queue topic.
///
/// Subscriptions provide an async channel for receiving messages from a topic.
/// When a subscription is dropped, the underlying resources are cleaned up
/// automatically (unsubscription from the queue, channel closure).
///
/// # Consumer Groups
///
/// Subscriptions are always associated with a consumer group. Messages are
/// load-balanced across all consumers in the same group, ensuring each message
/// is processed exactly once per group.
///
/// # Example
///
/// ```ignore
/// let subscription = queue.subscribe("triage.alerts", "worker-group").await?;
/// while let Some(message) = subscription.receiver.recv().await {
///     // Process the message
///     process_message(&message)?;
///     // Acknowledge after successful processing
///     queue.acknowledge("triage.alerts", &message.id).await?;
/// }
/// ```
///
/// # Drop Behavior
///
/// When the `Subscription` is dropped, the receiver channel is closed and
/// no further messages will be delivered. Implementations should ensure that
/// any pending unacknowledged messages are returned to the queue for redelivery.
pub struct Subscription {
    /// The channel receiver for incoming messages.
    ///
    /// Messages are delivered asynchronously. Use `recv().await` to receive
    /// the next message, or `try_recv()` for non-blocking access.
    pub receiver: mpsc::Receiver<Message>,
}

impl Subscription {
    /// Creates a new subscription with the given receiver.
    pub fn new(receiver: mpsc::Receiver<Message>) -> Self {
        Self { receiver }
    }

    /// Receives the next message from the subscription.
    ///
    /// Returns `None` when the subscription is closed or the underlying
    /// queue connection is lost.
    pub async fn recv(&mut self) -> Option<Message> {
        self.receiver.recv().await
    }

    /// Attempts to receive a message without blocking.
    ///
    /// Returns `Ok(message)` if a message is available, `Err(TryRecvError::Empty)`
    /// if no message is ready, or `Err(TryRecvError::Disconnected)` if the
    /// subscription is closed.
    pub fn try_recv(&mut self) -> Result<Message, mpsc::error::TryRecvError> {
        self.receiver.try_recv()
    }
}

impl std::fmt::Debug for Subscription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Subscription")
            .field("receiver", &"<mpsc::Receiver>")
            .finish()
    }
}

/// Health status of the message queue.
///
/// Used by the `health_check` method to report the current state of the
/// message queue connection and provide metrics for monitoring.
///
/// # Example
///
/// ```ignore
/// let health = queue.health_check().await?;
/// if !health.connected {
///     tracing::error!("Message queue disconnected!");
///     // Trigger reconnection or alert
/// }
/// metrics::gauge!("mq_pending_messages").set(health.pending_messages as f64);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueHealth {
    /// Whether the queue connection is active.
    ///
    /// `false` indicates a connection failure or timeout. Operations may
    /// fail until the connection is restored.
    pub connected: bool,
    /// Number of messages waiting to be processed.
    ///
    /// High values may indicate consumer lag or processing bottlenecks.
    pub pending_messages: u64,
    /// Number of active consumers subscribed to the queue.
    ///
    /// Used for load balancing decisions and capacity planning.
    pub consumer_count: u32,
}

impl QueueHealth {
    /// Creates a new `QueueHealth` instance.
    pub fn new(connected: bool, pending_messages: u64, consumer_count: u32) -> Self {
        Self {
            connected,
            pending_messages,
            consumer_count,
        }
    }

    /// Creates a healthy status with the given metrics.
    pub fn healthy(pending_messages: u64, consumer_count: u32) -> Self {
        Self::new(true, pending_messages, consumer_count)
    }

    /// Creates a disconnected status.
    pub fn disconnected() -> Self {
        Self::new(false, 0, 0)
    }

    /// Returns `true` if the queue is healthy (connected with reasonable lag).
    ///
    /// A queue is considered healthy if:
    /// - It is connected
    /// - Pending messages are below 10,000 (configurable threshold)
    pub fn is_healthy(&self) -> bool {
        self.connected && self.pending_messages < 10_000
    }
}

impl Default for QueueHealth {
    fn default() -> Self {
        Self::disconnected()
    }
}

/// Options for subscribing to a topic.
///
/// This struct is used with the `subscribe_with_options` method to configure
/// advanced subscription behavior such as batch size and visibility timeout.
///
/// # Notes
///
/// `batch_size` and `buffer_size` are currently honored by queue implementations
/// that support configurable subscription behavior (for example Redis streams).
/// `visibility_timeout_secs` is accepted here for API consistency and is
/// applied by backends that implement visibility semantics.
#[derive(Debug, Clone, Default)]
pub struct SubscribeOptions {
    /// Maximum number of messages to buffer before backpressure.
    ///
    /// Defaults to 100 if not specified.
    pub buffer_size: Option<usize>,

    /// Visibility timeout in seconds.
    ///
    /// Messages not acknowledged within this time will be redelivered.
    /// Defaults to 30 seconds if not specified.
    pub visibility_timeout_secs: Option<u64>,

    /// Maximum number of messages to fetch in a single poll.
    ///
    /// Larger batch sizes improve throughput but increase memory usage.
    /// Defaults to 10 if not specified.
    pub batch_size: Option<usize>,
}

impl SubscribeOptions {
    /// Creates a new `SubscribeOptions` with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the buffer size.
    pub fn with_buffer_size(mut self, size: usize) -> Self {
        self.buffer_size = Some(size);
        self
    }

    /// Sets the visibility timeout in seconds.
    pub fn with_visibility_timeout(mut self, timeout_secs: u64) -> Self {
        self.visibility_timeout_secs = Some(timeout_secs);
        self
    }

    /// Sets the batch size.
    pub fn with_batch_size(mut self, size: usize) -> Self {
        self.batch_size = Some(size);
        self
    }

    /// Returns the buffer size, defaulting to 100.
    pub fn buffer_size_or_default(&self) -> usize {
        self.buffer_size.unwrap_or(100)
    }

    /// Returns the visibility timeout in seconds, defaulting to 30.
    pub fn visibility_timeout_or_default(&self) -> u64 {
        self.visibility_timeout_secs.unwrap_or(30)
    }

    /// Returns the batch size, defaulting to 10.
    pub fn batch_size_or_default(&self) -> usize {
        self.batch_size.unwrap_or(10)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_id_creation() {
        let id = MessageId::new("test-123".to_string());
        assert_eq!(id.as_str(), "test-123");
        assert_eq!(id.to_string(), "test-123");
    }

    #[test]
    fn test_message_id_from_string() {
        let id: MessageId = "test-456".into();
        assert_eq!(id.as_str(), "test-456");
    }

    #[test]
    fn test_message_deserialization() {
        #[derive(Debug, Deserialize, PartialEq)]
        struct TestPayload {
            value: i32,
        }

        let payload = serde_json::to_vec(&serde_json::json!({"value": 42})).unwrap();
        let message = Message::new(
            MessageId::new("1".to_string()),
            "test".to_string(),
            payload,
            Utc::now(),
        );

        let result: TestPayload = message.deserialize().unwrap();
        assert_eq!(result.value, 42);
    }

    #[test]
    fn test_queue_health() {
        let health = QueueHealth::healthy(100, 5);
        assert!(health.connected);
        assert!(health.is_healthy());

        let unhealthy = QueueHealth::disconnected();
        assert!(!unhealthy.connected);
        assert!(!unhealthy.is_healthy());

        // High pending messages makes it unhealthy
        let lagging = QueueHealth::healthy(15_000, 5);
        assert!(lagging.connected);
        assert!(!lagging.is_healthy());
    }

    #[test]
    fn test_subscribe_options() {
        let opts = SubscribeOptions::new()
            .with_buffer_size(200)
            .with_visibility_timeout(60)
            .with_batch_size(20);

        assert_eq!(opts.buffer_size_or_default(), 200);
        assert_eq!(opts.visibility_timeout_or_default(), 60);
        assert_eq!(opts.batch_size_or_default(), 20);
    }

    #[test]
    fn test_subscribe_options_defaults() {
        let opts = SubscribeOptions::new();
        assert_eq!(opts.buffer_size_or_default(), 100);
        assert_eq!(opts.visibility_timeout_or_default(), 30);
        assert_eq!(opts.batch_size_or_default(), 10);
    }
}
