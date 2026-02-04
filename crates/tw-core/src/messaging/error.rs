//! Error types for the message queue abstraction.
//!
//! This module defines the error types returned by [`MessageQueue`](super::MessageQueue)
//! operations.

use thiserror::Error;

/// Errors that can occur in message queue operations.
///
/// This enum covers the common failure modes across different message queue
/// implementations (Redis Streams, RabbitMQ, Kafka, etc.).
///
/// # Error Handling
///
/// Most errors are transient and can be retried:
/// - [`Connection`](Self::Connection): Retry with exponential backoff
/// - [`Timeout`](Self::Timeout): Retry, possibly with a longer timeout
/// - [`SubscriptionClosed`](Self::SubscriptionClosed): Re-subscribe
///
/// Permanent errors that should not be retried:
/// - [`Serialization`](Self::Serialization): Fix the data format
/// - [`InvalidTopic`](Self::InvalidTopic): Fix the topic name
///
/// # Example
///
/// ```ignore
/// match queue.publish("topic", &payload).await {
///     Ok(id) => info!("Published message {}", id),
///     Err(MessageQueueError::Connection(e)) => {
///         warn!("Connection error, retrying: {}", e);
///         // Retry logic here
///     }
///     Err(e) => error!("Permanent error: {}", e),
/// }
/// ```
#[derive(Error, Debug, Clone)]
pub enum MessageQueueError {
    /// Failed to connect to or communicate with the message queue.
    ///
    /// This error indicates a network-level failure such as:
    /// - DNS resolution failure
    /// - TCP connection refused
    /// - TLS handshake failure
    /// - Connection dropped mid-operation
    ///
    /// This is typically a transient error that can be retried.
    #[error("Connection error: {0}")]
    Connection(String),

    /// Operation timed out waiting for a response.
    ///
    /// This can occur when:
    /// - The queue server is overloaded
    /// - Network latency is high
    /// - The operation is taking too long (e.g., large message)
    ///
    /// Consider retrying with exponential backoff or increasing the timeout.
    #[error("Operation timed out: {0}")]
    Timeout(String),

    /// Failed to serialize or deserialize a message.
    ///
    /// This error indicates a data format issue:
    /// - Invalid JSON payload
    /// - Payload too large
    /// - Encoding mismatch
    ///
    /// This is typically a permanent error that requires fixing the data.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// The subscription has been closed.
    ///
    /// This occurs when:
    /// - The subscription was explicitly closed
    /// - The consumer was removed from the group
    /// - The queue server terminated the connection
    ///
    /// Re-subscribe to continue receiving messages.
    #[error("Subscription closed: {0}")]
    SubscriptionClosed(String),

    /// The specified topic or queue does not exist or is invalid.
    ///
    /// This can occur when:
    /// - The topic name contains invalid characters
    /// - The topic doesn't exist and auto-creation is disabled
    /// - Insufficient permissions to access the topic
    #[error("Invalid topic: {0}")]
    InvalidTopic(String),

    /// The specified message ID was not found.
    ///
    /// This occurs when trying to acknowledge or query a message
    /// that doesn't exist, has already been acknowledged, or has expired.
    #[error("Message not found: {0}")]
    MessageNotFound(String),

    /// The consumer group does not exist or is invalid.
    ///
    /// This can occur when:
    /// - The group name contains invalid characters
    /// - The group was deleted while the consumer was subscribed
    #[error("Invalid consumer group: {0}")]
    InvalidGroup(String),

    /// An unknown or unexpected error occurred.
    ///
    /// This is a catch-all for errors that don't fit other categories.
    /// The inner string contains additional context about the failure.
    ///
    /// Check logs for more details when encountering this error.
    #[error("Unknown error: {0}")]
    Unknown(String),
}

impl MessageQueueError {
    /// Creates a new connection error.
    pub fn connection(msg: impl Into<String>) -> Self {
        Self::Connection(msg.into())
    }

    /// Creates a new timeout error.
    pub fn timeout(msg: impl Into<String>) -> Self {
        Self::Timeout(msg.into())
    }

    /// Creates a new serialization error.
    pub fn serialization(msg: impl Into<String>) -> Self {
        Self::Serialization(msg.into())
    }

    /// Creates a new subscription closed error.
    pub fn subscription_closed(msg: impl Into<String>) -> Self {
        Self::SubscriptionClosed(msg.into())
    }

    /// Creates a new invalid topic error.
    pub fn invalid_topic(msg: impl Into<String>) -> Self {
        Self::InvalidTopic(msg.into())
    }

    /// Creates a new message not found error.
    pub fn message_not_found(msg: impl Into<String>) -> Self {
        Self::MessageNotFound(msg.into())
    }

    /// Creates a new invalid group error.
    pub fn invalid_group(msg: impl Into<String>) -> Self {
        Self::InvalidGroup(msg.into())
    }

    /// Creates a new unknown error.
    pub fn unknown(msg: impl Into<String>) -> Self {
        Self::Unknown(msg.into())
    }

    /// Returns `true` if this error is transient and the operation can be retried.
    ///
    /// # Transient Errors
    ///
    /// - [`Connection`](Self::Connection)
    /// - [`Timeout`](Self::Timeout)
    /// - [`SubscriptionClosed`](Self::SubscriptionClosed)
    ///
    /// # Permanent Errors
    ///
    /// - [`Serialization`](Self::Serialization)
    /// - [`InvalidTopic`](Self::InvalidTopic)
    /// - [`MessageNotFound`](Self::MessageNotFound)
    /// - [`InvalidGroup`](Self::InvalidGroup)
    /// - [`Unknown`](Self::Unknown)
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            Self::Connection(_) | Self::Timeout(_) | Self::SubscriptionClosed(_)
        )
    }

    /// Returns `true` if this error indicates the operation should be retried.
    ///
    /// Alias for [`is_transient`](Self::is_transient).
    pub fn should_retry(&self) -> bool {
        self.is_transient()
    }

    /// Returns the error kind as a static string for logging/metrics.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Connection(_) => "connection",
            Self::Timeout(_) => "timeout",
            Self::Serialization(_) => "serialization",
            Self::SubscriptionClosed(_) => "subscription_closed",
            Self::InvalidTopic(_) => "invalid_topic",
            Self::MessageNotFound(_) => "message_not_found",
            Self::InvalidGroup(_) => "invalid_group",
            Self::Unknown(_) => "unknown",
        }
    }
}

/// Result type for message queue operations.
pub type MessageQueueResult<T> = Result<T, MessageQueueError>;

impl From<serde_json::Error> for MessageQueueError {
    fn from(err: serde_json::Error) -> Self {
        Self::Serialization(err.to_string())
    }
}

impl From<std::io::Error> for MessageQueueError {
    fn from(err: std::io::Error) -> Self {
        match err.kind() {
            std::io::ErrorKind::TimedOut => Self::Timeout(err.to_string()),
            std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::NotConnected => Self::Connection(err.to_string()),
            _ => Self::Unknown(err.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_creation() {
        let err = MessageQueueError::connection("failed to connect");
        assert!(matches!(err, MessageQueueError::Connection(_)));
        assert_eq!(err.to_string(), "Connection error: failed to connect");
    }

    #[test]
    fn test_transient_errors() {
        assert!(MessageQueueError::connection("test").is_transient());
        assert!(MessageQueueError::timeout("test").is_transient());
        assert!(MessageQueueError::subscription_closed("test").is_transient());

        assert!(!MessageQueueError::serialization("test").is_transient());
        assert!(!MessageQueueError::invalid_topic("test").is_transient());
        assert!(!MessageQueueError::unknown("test").is_transient());
    }

    #[test]
    fn test_error_kind() {
        assert_eq!(MessageQueueError::connection("test").kind(), "connection");
        assert_eq!(MessageQueueError::timeout("test").kind(), "timeout");
        assert_eq!(
            MessageQueueError::serialization("test").kind(),
            "serialization"
        );
    }

    #[test]
    fn test_from_serde_error() {
        let json_err = serde_json::from_str::<i32>("invalid").unwrap_err();
        let mq_err: MessageQueueError = json_err.into();
        assert!(matches!(mq_err, MessageQueueError::Serialization(_)));
    }
}
