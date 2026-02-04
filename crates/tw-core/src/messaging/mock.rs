//! Mock implementation of the MessageQueue trait for testing.
//!
//! This module provides [`MockMessageQueue`], an in-memory message queue
//! implementation using Tokio broadcast channels. It's designed for:
//!
//! - Unit tests that need a functional message queue
//! - Integration tests without external dependencies
//! - Local development without running Redis/RabbitMQ/Kafka
//!
//! # Behavior
//!
//! The mock queue provides the following semantics:
//!
//! - **Publish**: Messages are broadcast to all subscribers on the topic
//! - **Subscribe**: Creates a new receiver for the topic's broadcast channel
//! - **Acknowledge**: Tracks acknowledged messages (no redelivery in mock)
//! - **Health Check**: Always returns healthy status
//!
//! # Limitations
//!
//! This mock does not implement:
//! - Message persistence (messages are lost on drop)
//! - Consumer group load balancing (all subscribers receive all messages)
//! - Message redelivery on failed acknowledgment
//! - Visibility timeouts
//!
//! Use a real message queue implementation for production.

use async_trait::async_trait;
use chrono::Utc;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc, RwLock};
use tracing::{debug, trace};

use super::error::MessageQueueError;
use super::types::{Message, MessageId, QueueHealth, Subscription};
use super::MessageQueue;

/// Default broadcast channel capacity.
const DEFAULT_CHANNEL_CAPACITY: usize = 1024;

/// Default subscription buffer size.
const DEFAULT_SUBSCRIPTION_BUFFER: usize = 100;

/// In-memory mock implementation of [`MessageQueue`] for testing.
///
/// Uses Tokio broadcast channels to distribute messages to subscribers.
/// Each topic has its own broadcast channel, and subscribers receive
/// messages through a bridged mpsc channel.
///
/// # Thread Safety
///
/// `MockMessageQueue` is `Send + Sync` and can be safely shared across
/// tasks using `Arc<MockMessageQueue>`.
///
/// # Example
///
/// ```
/// use tw_core::messaging::{MessageQueue, MockMessageQueue};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let queue = MockMessageQueue::new();
///
/// // Subscribe to a topic
/// let mut subscription = queue.subscribe("events", "worker").await?;
///
/// // Publish a message
/// queue.publish("events", b"hello").await?;
///
/// // Receive the message
/// let msg = subscription.recv().await.unwrap();
/// assert_eq!(msg.payload, b"hello");
///
/// // Acknowledge it
/// queue.acknowledge("events", &msg.id).await?;
/// # Ok(())
/// # }
/// ```
pub struct MockMessageQueue {
    /// Broadcast senders for each topic.
    topics: Arc<RwLock<HashMap<String, broadcast::Sender<Message>>>>,
    /// Counter for generating unique message IDs.
    message_counter: AtomicU64,
    /// Set of acknowledged message IDs per topic.
    acknowledged: Arc<RwLock<HashMap<String, HashSet<MessageId>>>>,
    /// Number of active subscribers per topic.
    subscriber_counts: Arc<RwLock<HashMap<String, u32>>>,
    /// Channel capacity for new topics.
    channel_capacity: usize,
}

impl MockMessageQueue {
    /// Creates a new `MockMessageQueue` with default capacity.
    ///
    /// The default broadcast channel capacity is 1024 messages per topic.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CHANNEL_CAPACITY)
    }

    /// Creates a new `MockMessageQueue` with the specified channel capacity.
    ///
    /// # Arguments
    ///
    /// * `capacity` - Maximum number of messages buffered in each topic's channel
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            topics: Arc::new(RwLock::new(HashMap::new())),
            message_counter: AtomicU64::new(0),
            acknowledged: Arc::new(RwLock::new(HashMap::new())),
            subscriber_counts: Arc::new(RwLock::new(HashMap::new())),
            channel_capacity: capacity,
        }
    }

    /// Gets or creates a broadcast sender for the given topic.
    async fn get_or_create_topic(&self, topic: &str) -> broadcast::Sender<Message> {
        let mut topics = self.topics.write().await;
        if let Some(sender) = topics.get(topic) {
            sender.clone()
        } else {
            let (tx, _) = broadcast::channel(self.channel_capacity);
            topics.insert(topic.to_string(), tx.clone());
            tx
        }
    }

    /// Generates a unique message ID.
    fn next_message_id(&self) -> MessageId {
        let id = self.message_counter.fetch_add(1, Ordering::SeqCst);
        MessageId::new(format!("mock-{}-{}", Utc::now().timestamp_millis(), id))
    }

    /// Returns the total number of messages published across all topics.
    ///
    /// This is useful for testing to verify expected publish counts.
    /// Note: This is a global counter, not per-topic.
    pub fn total_published_count(&self) -> u64 {
        self.message_counter.load(Ordering::SeqCst)
    }

    /// Returns whether a message has been acknowledged.
    ///
    /// This is useful for testing to verify acknowledgment behavior.
    pub async fn is_acknowledged(&self, topic: &str, message_id: &MessageId) -> bool {
        let acknowledged = self.acknowledged.read().await;
        acknowledged
            .get(topic)
            .map(|set| set.contains(message_id))
            .unwrap_or(false)
    }

    /// Returns the number of acknowledged messages for a topic.
    pub async fn acknowledged_count(&self, topic: &str) -> usize {
        let acknowledged = self.acknowledged.read().await;
        acknowledged.get(topic).map(|set| set.len()).unwrap_or(0)
    }

    /// Clears all topics and resets the queue state.
    ///
    /// This is useful for test cleanup between test cases.
    pub async fn clear(&self) {
        let mut topics = self.topics.write().await;
        let mut acknowledged = self.acknowledged.write().await;
        let mut counts = self.subscriber_counts.write().await;

        topics.clear();
        acknowledged.clear();
        counts.clear();
    }
}

impl Default for MockMessageQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for MockMessageQueue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockMessageQueue")
            .field("channel_capacity", &self.channel_capacity)
            .field("message_counter", &self.message_counter)
            .finish()
    }
}

#[async_trait]
impl MessageQueue for MockMessageQueue {
    async fn publish(&self, topic: &str, message: &[u8]) -> Result<MessageId, MessageQueueError> {
        let sender = self.get_or_create_topic(topic).await;
        let message_id = self.next_message_id();

        let msg = Message {
            id: message_id.clone(),
            topic: topic.to_string(),
            payload: message.to_vec(),
            timestamp: Utc::now(),
        };

        // Send to broadcast channel
        // We ignore the result because having no receivers is valid
        match sender.send(msg) {
            Ok(count) => {
                trace!(
                    topic = topic,
                    message_id = %message_id,
                    receivers = count,
                    "Published message"
                );
            }
            Err(_) => {
                // No receivers, but that's okay - message is still "published"
                trace!(
                    topic = topic,
                    message_id = %message_id,
                    "Published message (no receivers)"
                );
            }
        }

        Ok(message_id)
    }

    async fn subscribe(&self, topic: &str, group: &str) -> Result<Subscription, MessageQueueError> {
        let sender = self.get_or_create_topic(topic).await;
        let mut broadcast_rx = sender.subscribe();

        // Create an mpsc channel to bridge from broadcast to Subscription
        let (mpsc_tx, mpsc_rx) = mpsc::channel(DEFAULT_SUBSCRIPTION_BUFFER);

        // Track subscriber count
        {
            let mut counts = self.subscriber_counts.write().await;
            *counts.entry(topic.to_string()).or_insert(0) += 1;
        }

        // Clone for the spawned task
        let topic_name = topic.to_string();
        let group_name = group.to_string();
        let counts = Arc::clone(&self.subscriber_counts);

        // Spawn a task to bridge broadcast messages to the mpsc channel
        tokio::spawn(async move {
            loop {
                match broadcast_rx.recv().await {
                    Ok(message) => {
                        trace!(
                            topic = %topic_name,
                            group = %group_name,
                            message_id = %message.id,
                            "Forwarding message to subscriber"
                        );
                        if mpsc_tx.send(message).await.is_err() {
                            // Receiver dropped, exit the loop
                            debug!(
                                topic = %topic_name,
                                group = %group_name,
                                "Subscriber channel closed, stopping forward task"
                            );
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        debug!(
                            topic = %topic_name,
                            group = %group_name,
                            "Broadcast channel closed"
                        );
                        break;
                    }
                    Err(broadcast::error::RecvError::Lagged(count)) => {
                        debug!(
                            topic = %topic_name,
                            group = %group_name,
                            lagged = count,
                            "Subscriber lagged behind, some messages dropped"
                        );
                        // Continue receiving - we've lost some messages but can continue
                    }
                }
            }

            // Decrement subscriber count when task exits
            let mut counts = counts.write().await;
            if let Some(count) = counts.get_mut(&topic_name) {
                *count = count.saturating_sub(1);
            }
        });

        debug!(topic = topic, group = group, "Created subscription");

        Ok(Subscription::new(mpsc_rx))
    }

    async fn acknowledge(
        &self,
        topic: &str,
        message_id: &MessageId,
    ) -> Result<(), MessageQueueError> {
        let mut acknowledged = self.acknowledged.write().await;
        let topic_acks = acknowledged
            .entry(topic.to_string())
            .or_insert_with(HashSet::new);

        if topic_acks.insert(message_id.clone()) {
            trace!(
                topic = topic,
                message_id = %message_id,
                "Acknowledged message"
            );
            Ok(())
        } else {
            // Already acknowledged - this is not an error in the mock
            trace!(
                topic = topic,
                message_id = %message_id,
                "Message already acknowledged"
            );
            Ok(())
        }
    }

    async fn health_check(&self) -> Result<QueueHealth, MessageQueueError> {
        let counts = self.subscriber_counts.read().await;

        // Sum up all subscriber counts
        let total_consumers: u32 = counts.values().sum();

        // For the mock, pending messages is always 0 since broadcast doesn't buffer
        Ok(QueueHealth {
            connected: true,
            pending_messages: 0,
            consumer_count: total_consumers,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_mock_queue_creation() {
        let queue = MockMessageQueue::new();
        let health = queue.health_check().await.unwrap();
        assert!(health.connected);
        assert_eq!(health.consumer_count, 0);
    }

    #[tokio::test]
    async fn test_publish_without_subscribers() {
        let queue = MockMessageQueue::new();
        let result = queue.publish("test-topic", b"hello").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_publish_and_subscribe() {
        let queue = MockMessageQueue::new();

        // Subscribe first
        let mut subscription = queue.subscribe("test-topic", "test-group").await.unwrap();

        // Give the subscription task time to start
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Publish
        let payload = b"test message";
        let msg_id = queue.publish("test-topic", payload).await.unwrap();

        // Receive with timeout
        let msg = tokio::time::timeout(Duration::from_secs(1), subscription.recv())
            .await
            .expect("Timeout waiting for message")
            .expect("No message received");

        assert_eq!(msg.id, msg_id);
        assert_eq!(msg.payload, payload);
        assert_eq!(msg.topic, "test-topic");
    }

    #[tokio::test]
    async fn test_acknowledgment() {
        let queue = MockMessageQueue::new();
        let mut subscription = queue.subscribe("test-topic", "test-group").await.unwrap();

        tokio::time::sleep(Duration::from_millis(10)).await;

        queue.publish("test-topic", b"hello").await.unwrap();

        let msg = tokio::time::timeout(Duration::from_secs(1), subscription.recv())
            .await
            .expect("Timeout")
            .expect("No message");

        // Acknowledge
        queue
            .acknowledge("test-topic", &msg.id)
            .await
            .expect("Acknowledge failed");

        // Verify it's acknowledged
        assert!(queue.is_acknowledged("test-topic", &msg.id).await);
        assert_eq!(queue.acknowledged_count("test-topic").await, 1);
    }

    #[tokio::test]
    async fn test_multiple_subscribers_same_group() {
        let queue = MockMessageQueue::new();

        // In the mock, all subscribers receive all messages (no load balancing)
        let mut sub1 = queue.subscribe("test-topic", "group").await.unwrap();
        let mut sub2 = queue.subscribe("test-topic", "group").await.unwrap();

        tokio::time::sleep(Duration::from_millis(10)).await;

        queue.publish("test-topic", b"message").await.unwrap();

        // Both should receive it (mock limitation)
        let msg1 = tokio::time::timeout(Duration::from_secs(1), sub1.recv())
            .await
            .expect("Timeout")
            .expect("No message");
        let msg2 = tokio::time::timeout(Duration::from_secs(1), sub2.recv())
            .await
            .expect("Timeout")
            .expect("No message");

        assert_eq!(msg1.payload, msg2.payload);
    }

    #[tokio::test]
    async fn test_multiple_subscribers_different_groups() {
        let queue = MockMessageQueue::new();

        let mut sub1 = queue.subscribe("test-topic", "group1").await.unwrap();
        let mut sub2 = queue.subscribe("test-topic", "group2").await.unwrap();

        tokio::time::sleep(Duration::from_millis(10)).await;

        queue.publish("test-topic", b"broadcast").await.unwrap();

        // Both groups should receive the message
        let msg1 = tokio::time::timeout(Duration::from_secs(1), sub1.recv())
            .await
            .expect("Timeout")
            .expect("No message");
        let msg2 = tokio::time::timeout(Duration::from_secs(1), sub2.recv())
            .await
            .expect("Timeout")
            .expect("No message");

        assert_eq!(msg1.payload, b"broadcast");
        assert_eq!(msg2.payload, b"broadcast");
    }

    #[tokio::test]
    async fn test_multiple_topics() {
        let queue = MockMessageQueue::new();

        let mut sub_alerts = queue.subscribe("alerts", "worker").await.unwrap();
        let mut sub_events = queue.subscribe("events", "worker").await.unwrap();

        tokio::time::sleep(Duration::from_millis(10)).await;

        queue.publish("alerts", b"alert message").await.unwrap();
        queue.publish("events", b"event message").await.unwrap();

        let alert = tokio::time::timeout(Duration::from_secs(1), sub_alerts.recv())
            .await
            .expect("Timeout")
            .expect("No message");
        let event = tokio::time::timeout(Duration::from_secs(1), sub_events.recv())
            .await
            .expect("Timeout")
            .expect("No message");

        assert_eq!(alert.payload, b"alert message");
        assert_eq!(alert.topic, "alerts");
        assert_eq!(event.payload, b"event message");
        assert_eq!(event.topic, "events");
    }

    #[tokio::test]
    async fn test_subscriber_count_tracking() {
        let queue = MockMessageQueue::new();

        let health1 = queue.health_check().await.unwrap();
        assert_eq!(health1.consumer_count, 0);

        let _sub1 = queue.subscribe("test", "group1").await.unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;

        let health2 = queue.health_check().await.unwrap();
        assert_eq!(health2.consumer_count, 1);

        let _sub2 = queue.subscribe("test", "group2").await.unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;

        let health3 = queue.health_check().await.unwrap();
        assert_eq!(health3.consumer_count, 2);
    }

    #[tokio::test]
    async fn test_clear() {
        let queue = MockMessageQueue::new();

        queue.publish("test", b"message").await.unwrap();
        let mut sub = queue.subscribe("test", "group").await.unwrap();

        tokio::time::sleep(Duration::from_millis(10)).await;

        queue.publish("test", b"after sub").await.unwrap();
        let msg = tokio::time::timeout(Duration::from_secs(1), sub.recv())
            .await
            .expect("Timeout")
            .expect("No message");
        queue.acknowledge("test", &msg.id).await.unwrap();

        assert_eq!(queue.acknowledged_count("test").await, 1);

        queue.clear().await;

        assert_eq!(queue.acknowledged_count("test").await, 0);
    }

    #[tokio::test]
    async fn test_message_deserialization() {
        let queue = MockMessageQueue::new();
        let mut sub = queue.subscribe("test", "group").await.unwrap();

        tokio::time::sleep(Duration::from_millis(10)).await;

        #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
        struct TestEvent {
            name: String,
            value: i32,
        }

        let event = TestEvent {
            name: "test".to_string(),
            value: 42,
        };
        let payload = serde_json::to_vec(&event).unwrap();

        queue.publish("test", &payload).await.unwrap();

        let msg = tokio::time::timeout(Duration::from_secs(1), sub.recv())
            .await
            .expect("Timeout")
            .expect("No message");

        let received: TestEvent = msg.deserialize().unwrap();
        assert_eq!(received, event);
    }

    #[tokio::test]
    async fn test_unique_message_ids() {
        let queue = MockMessageQueue::new();

        let id1 = queue.publish("test", b"msg1").await.unwrap();
        let id2 = queue.publish("test", b"msg2").await.unwrap();
        let id3 = queue.publish("test", b"msg3").await.unwrap();

        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
        assert_ne!(id1, id3);
    }
}
