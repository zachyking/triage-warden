//! Redis Streams implementation of the MessageQueue trait.
//!
//! This module provides [`RedisMessageQueue`], a production-ready message queue
//! implementation using Redis Streams. It supports:
//!
//! - Consumer groups for load-balanced message delivery
//! - Connection pooling with `deadpool-redis`
//! - Automatic stream/group creation
//! - Message acknowledgment with XACK
//! - Configurable stream trimming with MAXLEN
//!
//! # Redis Streams Concepts
//!
//! Redis Streams provide a log-based data structure similar to Kafka:
//!
//! - **Stream**: An append-only log of messages (like a Kafka topic)
//! - **Consumer Group**: A named group of consumers sharing message load
//! - **Consumer**: An individual instance reading from a group
//! - **Message ID**: Timestamp-based ID (e.g., "1234567890123-0")
//!
//! # Example
//!
//! ```ignore
//! use tw_core::messaging::{MessageQueue, RedisMessageQueue, RedisMessageQueueConfig};
//!
//! let config = RedisMessageQueueConfig::new("redis://localhost:6379");
//! let queue = RedisMessageQueue::new(config, "instance-1").await?;
//!
//! // Publish a message
//! let msg_id = queue.publish("triage.alerts", b"alert data").await?;
//!
//! // Subscribe to the stream
//! let mut subscription = queue.subscribe("triage.alerts", "workers").await?;
//! while let Some(msg) = subscription.recv().await {
//!     process_alert(&msg)?;
//!     queue.acknowledge("triage.alerts", &msg.id).await?;
//! }
//! ```

use async_trait::async_trait;
use chrono::{DateTime, TimeZone, Utc};
use deadpool_redis::{Config as PoolConfig, Pool, Runtime};
use redis::streams::{StreamReadOptions, StreamReadReply};
use redis::{AsyncCommands, RedisError};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, trace, warn};

use super::error::MessageQueueError;
use super::types::{Message, MessageId, QueueHealth, SubscribeOptions, Subscription};
use super::MessageQueue;

/// Configuration for the Redis Streams message queue.
///
/// # Example
///
/// ```ignore
/// let config = RedisMessageQueueConfig::new("redis://localhost:6379")
///     .with_max_connections(20)
///     .with_stream_max_len(100_000)
///     .with_block_ms(5000)
///     .with_batch_size(10);
/// ```
#[derive(Debug, Clone)]
pub struct RedisMessageQueueConfig {
    /// Redis connection URL (e.g., "redis://localhost:6379")
    pub url: String,
    /// Maximum number of connections in the pool
    pub max_connections: u32,
    /// Maximum stream length (MAXLEN for XADD) to prevent unbounded growth
    pub stream_max_len: usize,
    /// Block time in milliseconds for XREADGROUP (0 = non-blocking)
    pub block_ms: u64,
    /// Number of messages to fetch in each XREADGROUP call
    pub batch_size: usize,
    /// Prefix for consumer names
    pub consumer_prefix: String,
    /// Timeout for reconnection attempts in milliseconds
    pub reconnect_timeout_ms: u64,
}

impl RedisMessageQueueConfig {
    /// Creates a new configuration with the given Redis URL.
    ///
    /// Uses sensible defaults for production:
    /// - 10 max connections
    /// - 100,000 max stream length
    /// - 5 second block time
    /// - 10 messages per batch
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            max_connections: 10,
            stream_max_len: 100_000,
            block_ms: 5000,
            batch_size: 10,
            consumer_prefix: "tw-consumer".to_string(),
            reconnect_timeout_ms: 30_000,
        }
    }

    /// Sets the maximum number of connections in the pool.
    pub fn with_max_connections(mut self, max: u32) -> Self {
        self.max_connections = max;
        self
    }

    /// Sets the maximum stream length for XADD MAXLEN.
    pub fn with_stream_max_len(mut self, max_len: usize) -> Self {
        self.stream_max_len = max_len;
        self
    }

    /// Sets the block time in milliseconds for XREADGROUP.
    pub fn with_block_ms(mut self, ms: u64) -> Self {
        self.block_ms = ms;
        self
    }

    /// Sets the batch size for XREADGROUP.
    pub fn with_batch_size(mut self, size: usize) -> Self {
        self.batch_size = size;
        self
    }

    /// Sets the consumer name prefix.
    pub fn with_consumer_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.consumer_prefix = prefix.into();
        self
    }
}

impl Default for RedisMessageQueueConfig {
    fn default() -> Self {
        Self::new("redis://localhost:6379")
    }
}

/// Tracks active subscriptions for a topic.
struct SubscriptionHandle {
    /// Group name this subscription belongs to
    group: String,
    /// Consumer name within the group
    consumer: String,
    /// Sender to signal shutdown (kept for future graceful shutdown support)
    #[allow(dead_code)]
    shutdown_tx: mpsc::Sender<()>,
}

/// Redis Streams implementation of [`MessageQueue`].
///
/// Provides a production-ready message queue using Redis Streams with:
/// - Connection pooling via `deadpool-redis`
/// - Consumer groups for load-balanced delivery
/// - Automatic stream and group creation
/// - Message acknowledgment
///
/// # Thread Safety
///
/// `RedisMessageQueue` is `Send + Sync` and can be safely shared across
/// tasks using `Arc<RedisMessageQueue>`.
pub struct RedisMessageQueue {
    /// Connection pool
    pool: Pool,
    /// Unique identifier for this instance
    instance_id: String,
    /// Configuration
    config: RedisMessageQueueConfig,
    /// Active subscriptions (topic -> handles)
    subscriptions: Arc<RwLock<HashMap<String, Vec<SubscriptionHandle>>>>,
}

impl RedisMessageQueue {
    /// Creates a new `RedisMessageQueue` with the given configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration for Redis connection and behavior
    /// * `instance_id` - Unique identifier for this orchestrator instance
    ///
    /// # Errors
    ///
    /// Returns an error if the connection pool cannot be created.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let config = RedisMessageQueueConfig::new("redis://localhost:6379");
    /// let queue = RedisMessageQueue::new(config, "orchestrator-1").await?;
    /// ```
    pub async fn new(
        config: RedisMessageQueueConfig,
        instance_id: impl Into<String>,
    ) -> Result<Self, MessageQueueError> {
        let instance_id = instance_id.into();

        // Create deadpool configuration
        let pool_config = PoolConfig::from_url(&config.url);
        let pool = pool_config
            .builder()
            .map_err(|e| {
                MessageQueueError::connection(format!("Failed to create pool builder: {e}"))
            })?
            .max_size(config.max_connections as usize)
            .runtime(Runtime::Tokio1)
            .build()
            .map_err(|e| MessageQueueError::connection(format!("Failed to build pool: {e}")))?;

        // Verify connectivity
        let mut conn = pool
            .get()
            .await
            .map_err(|e| MessageQueueError::connection(format!("Failed to get connection: {e}")))?;

        redis::cmd("PING")
            .query_async::<String>(&mut *conn)
            .await
            .map_err(|e| MessageQueueError::connection(format!("Redis PING failed: {e}")))?;

        info!(
            instance_id = %instance_id,
            url = %config.url,
            max_connections = config.max_connections,
            "Connected to Redis"
        );

        Ok(Self {
            pool,
            instance_id,
            config,
            subscriptions: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Returns the consumer name for this instance within a group.
    fn consumer_name(&self, group: &str) -> String {
        format!(
            "{}-{}-{}",
            self.config.consumer_prefix, group, self.instance_id
        )
    }

    /// Ensures a consumer group exists for the given stream.
    ///
    /// Creates the stream and group if they don't exist, using MKSTREAM.
    /// Handles BUSYGROUP error gracefully (group already exists).
    async fn ensure_consumer_group(
        &self,
        stream: &str,
        group: &str,
    ) -> Result<(), MessageQueueError> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| MessageQueueError::connection(format!("Pool error: {e}")))?;

        // XGROUP CREATE <stream> <group> $ MKSTREAM
        // $ means start reading from new messages only
        let result: Result<String, RedisError> = redis::cmd("XGROUP")
            .arg("CREATE")
            .arg(stream)
            .arg(group)
            .arg("$")
            .arg("MKSTREAM")
            .query_async(&mut *conn)
            .await;

        match result {
            Ok(_) => {
                info!(stream = stream, group = group, "Created consumer group");
                Ok(())
            }
            Err(e) => {
                let err_msg = e.to_string();
                // BUSYGROUP means the group already exists - that's fine
                if err_msg.contains("BUSYGROUP") {
                    debug!(
                        stream = stream,
                        group = group,
                        "Consumer group already exists"
                    );
                    Ok(())
                } else {
                    Err(MessageQueueError::connection(format!(
                        "Failed to create consumer group: {e}"
                    )))
                }
            }
        }
    }

    /// Parses a Redis stream message ID into a timestamp.
    fn parse_timestamp(id: &str) -> DateTime<Utc> {
        // Redis stream IDs are in the format "<timestamp_ms>-<sequence>"
        if let Some(ts_str) = id.split('-').next() {
            if let Ok(ts_ms) = ts_str.parse::<i64>() {
                if let Some(dt) = Utc.timestamp_millis_opt(ts_ms).single() {
                    return dt;
                }
            }
        }
        // Fallback to current time if parsing fails
        Utc::now()
    }

    /// Claims stale pending messages that haven't been processed.
    ///
    /// This is useful at startup to reclaim messages from crashed consumers.
    ///
    /// # Arguments
    ///
    /// * `stream` - The stream name
    /// * `group` - The consumer group name
    /// * `min_idle_ms` - Minimum idle time in milliseconds before claiming
    /// * `count` - Maximum number of messages to claim
    ///
    /// # Returns
    ///
    /// Returns the number of messages claimed.
    pub async fn claim_stale_messages(
        &self,
        stream: &str,
        group: &str,
        min_idle_ms: u64,
        count: usize,
    ) -> Result<usize, MessageQueueError> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| MessageQueueError::connection(format!("Pool error: {e}")))?;

        let consumer = self.consumer_name(group);

        // First, get pending messages with XPENDING
        let pending: Vec<(String, String, u64, u64)> = redis::cmd("XPENDING")
            .arg(stream)
            .arg(group)
            .arg("-") // start
            .arg("+") // end
            .arg(count)
            .query_async(&mut *conn)
            .await
            .map_err(|e| MessageQueueError::connection(format!("XPENDING failed: {e}")))?;

        if pending.is_empty() {
            return Ok(0);
        }

        // Collect message IDs that have been idle long enough
        let stale_ids: Vec<&str> = pending
            .iter()
            .filter(|(_, _, idle, _)| *idle >= min_idle_ms)
            .map(|(id, _, _, _)| id.as_str())
            .collect();

        if stale_ids.is_empty() {
            return Ok(0);
        }

        // XCLAIM to take ownership of these messages
        let mut cmd = redis::cmd("XCLAIM");
        cmd.arg(stream).arg(group).arg(&consumer).arg(min_idle_ms);

        for id in &stale_ids {
            cmd.arg(*id);
        }

        // XCLAIM returns stream entries, we just parse the raw response to count
        let claimed: redis::Value = cmd
            .query_async(&mut *conn)
            .await
            .map_err(|e| MessageQueueError::connection(format!("XCLAIM failed: {e}")))?;

        // Count the claimed messages from the response
        let claimed_count = match claimed {
            redis::Value::Array(arr) => arr.len(),
            _ => 0,
        };
        if claimed_count > 0 {
            info!(
                stream = stream,
                group = group,
                consumer = consumer,
                claimed_count = claimed_count,
                "Claimed stale messages"
            );
        }

        Ok(claimed_count)
    }

    /// Gets the number of pending messages for a stream/group.
    ///
    /// This is useful for monitoring and can be called to check backlog.
    #[allow(dead_code)]
    pub async fn get_pending_count(
        &self,
        stream: &str,
        group: &str,
    ) -> Result<u64, MessageQueueError> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| MessageQueueError::connection(format!("Pool error: {e}")))?;

        // XPENDING returns summary: [count, first_id, last_id, [[consumer, count], ...]]
        let result: redis::Value = redis::cmd("XPENDING")
            .arg(stream)
            .arg(group)
            .query_async(&mut *conn)
            .await
            .map_err(|e| {
                // NOGROUP error means the group doesn't exist yet
                if e.to_string().contains("NOGROUP") {
                    return MessageQueueError::invalid_group(format!(
                        "Consumer group '{group}' doesn't exist for stream '{stream}'"
                    ));
                }
                MessageQueueError::connection(format!("XPENDING failed: {e}"))
            })?;

        // Parse the response
        match result {
            redis::Value::Array(ref arr) if !arr.is_empty() => {
                if let redis::Value::Int(count) = &arr[0] {
                    return Ok(*count as u64);
                }
            }
            redis::Value::Nil => return Ok(0),
            _ => {}
        }

        Ok(0)
    }
}

impl std::fmt::Debug for RedisMessageQueue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisMessageQueue")
            .field("instance_id", &self.instance_id)
            .field("url", &self.config.url)
            .field("max_connections", &self.config.max_connections)
            .finish()
    }
}

#[async_trait]
impl MessageQueue for RedisMessageQueue {
    async fn publish(&self, topic: &str, message: &[u8]) -> Result<MessageId, MessageQueueError> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| MessageQueueError::connection(format!("Pool error: {e}")))?;

        // XADD with MAXLEN to prevent unbounded growth
        // Use approximate (~) trimming for better performance
        let msg_id: String = redis::cmd("XADD")
            .arg(topic)
            .arg("MAXLEN")
            .arg("~")
            .arg(self.config.stream_max_len)
            .arg("*") // Auto-generate message ID
            .arg("payload")
            .arg(message)
            .query_async(&mut *conn)
            .await
            .map_err(|e| MessageQueueError::connection(format!("XADD failed: {e}")))?;

        trace!(
            topic = topic,
            message_id = %msg_id,
            payload_len = message.len(),
            "Published message"
        );

        Ok(MessageId::new(msg_id))
    }

    async fn subscribe(&self, topic: &str, group: &str) -> Result<Subscription, MessageQueueError> {
        // Ensure the consumer group exists
        self.ensure_consumer_group(topic, group).await?;

        let consumer = self.consumer_name(group);

        // Create channel for delivering messages to the subscriber
        let (msg_tx, msg_rx) = mpsc::channel(self.config.batch_size * 2);
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);

        // Clone what we need for the background task
        let pool = self.pool.clone();
        let topic_owned = topic.to_string();
        let group_owned = group.to_string();
        let consumer_clone = consumer.clone();
        let block_ms = self.config.block_ms;
        let batch_size = self.config.batch_size;

        // Track the subscription
        {
            let mut subs = self.subscriptions.write().await;
            subs.entry(topic_owned.clone())
                .or_insert_with(Vec::new)
                .push(SubscriptionHandle {
                    group: group_owned.clone(),
                    consumer: consumer.clone(),
                    shutdown_tx: shutdown_tx.clone(),
                });
        }

        let subscriptions = Arc::clone(&self.subscriptions);

        // Spawn background task to read from Redis and forward to channel
        tokio::spawn(async move {
            let topic = topic_owned;
            let group = group_owned;
            info!(
                topic = %topic,
                group = %group,
                consumer = %consumer_clone,
                "Starting subscription task"
            );

            loop {
                // Check for shutdown signal
                if shutdown_rx.try_recv().is_ok() {
                    debug!(topic = %topic, group = %group, "Subscription shutdown requested");
                    break;
                }

                // Get connection from pool
                let mut conn = match pool.get().await {
                    Ok(conn) => conn,
                    Err(e) => {
                        error!(error = %e, "Failed to get connection from pool");
                        tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
                        continue;
                    }
                };

                // XREADGROUP GROUP <group> <consumer> BLOCK <ms> COUNT <n> STREAMS <stream> >
                let opts = StreamReadOptions::default()
                    .group(&group, &consumer_clone)
                    .block(block_ms as usize)
                    .count(batch_size);

                let result: Result<StreamReadReply, RedisError> =
                    conn.xread_options(&[&topic], &[">"], &opts).await;

                match result {
                    Ok(reply) => {
                        for stream_key in reply.keys {
                            for stream_id in stream_key.ids {
                                // Extract payload from the message
                                let payload: Vec<u8> = stream_id
                                    .map
                                    .get("payload")
                                    .and_then(|v| match v {
                                        redis::Value::BulkString(bytes) => Some(bytes.clone()),
                                        redis::Value::SimpleString(s) => {
                                            Some(s.as_bytes().to_vec())
                                        }
                                        _ => None,
                                    })
                                    .unwrap_or_default();

                                let message = Message {
                                    id: MessageId::new(stream_id.id.clone()),
                                    topic: topic.clone(),
                                    payload,
                                    timestamp: Self::parse_timestamp(&stream_id.id),
                                };

                                trace!(
                                    topic = %topic,
                                    message_id = %message.id,
                                    "Received message"
                                );

                                if msg_tx.send(message).await.is_err() {
                                    debug!(topic = %topic, "Subscriber channel closed");
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        let err_str = e.to_string();
                        if err_str.contains("NOGROUP") {
                            // Group was deleted, try to recreate
                            warn!(topic = %topic, group = %group, "Consumer group not found, will retry");
                            tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
                        } else {
                            error!(error = %e, "XREADGROUP error");
                            tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
                        }
                    }
                }
            }

            // Remove subscription handle on exit
            let mut subs = subscriptions.write().await;
            if let Some(handles) = subs.get_mut(&topic) {
                handles.retain(|h| h.consumer != consumer_clone);
                if handles.is_empty() {
                    subs.remove(&topic);
                }
            }

            info!(topic = %topic, group = %group, "Subscription task ended");
        });

        debug!(
            topic = topic,
            group = group,
            consumer = consumer,
            "Created subscription"
        );

        Ok(Subscription::new(msg_rx))
    }

    async fn subscribe_with_options(
        &self,
        topic: &str,
        group: &str,
        options: SubscribeOptions,
    ) -> Result<Subscription, MessageQueueError> {
        // For Redis Streams, we use the options to configure batch size
        // The visibility timeout is handled by XCLAIM for stale messages

        // Ensure the consumer group exists
        self.ensure_consumer_group(topic, group).await?;

        let consumer = self.consumer_name(group);
        let batch_size = options.batch_size_or_default();
        let buffer_size = options.buffer_size_or_default();

        // Create channel for delivering messages to the subscriber
        let (msg_tx, msg_rx) = mpsc::channel(buffer_size);
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);

        // Clone what we need for the background task
        let pool = self.pool.clone();
        let topic_owned = topic.to_string();
        let group_owned = group.to_string();
        let consumer_clone = consumer.clone();
        let block_ms = self.config.block_ms;

        // Track the subscription
        {
            let mut subs = self.subscriptions.write().await;
            subs.entry(topic_owned.clone())
                .or_insert_with(Vec::new)
                .push(SubscriptionHandle {
                    group: group_owned.clone(),
                    consumer: consumer.clone(),
                    shutdown_tx: shutdown_tx.clone(),
                });
        }

        let subscriptions = Arc::clone(&self.subscriptions);

        // Spawn background task to read from Redis and forward to channel
        tokio::spawn(async move {
            let topic = topic_owned;
            let group = group_owned;
            info!(
                topic = %topic,
                group = %group,
                consumer = %consumer_clone,
                batch_size = batch_size,
                buffer_size = buffer_size,
                "Starting subscription task with options"
            );

            loop {
                // Check for shutdown signal
                if shutdown_rx.try_recv().is_ok() {
                    debug!(topic = %topic, group = %group, "Subscription shutdown requested");
                    break;
                }

                // Get connection from pool
                let mut conn = match pool.get().await {
                    Ok(conn) => conn,
                    Err(e) => {
                        error!(error = %e, "Failed to get connection from pool");
                        tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
                        continue;
                    }
                };

                // XREADGROUP with configured batch size
                let opts = StreamReadOptions::default()
                    .group(&group, &consumer_clone)
                    .block(block_ms as usize)
                    .count(batch_size);

                let result: Result<StreamReadReply, RedisError> =
                    conn.xread_options(&[&topic], &[">"], &opts).await;

                match result {
                    Ok(reply) => {
                        for stream_key in reply.keys {
                            for stream_id in stream_key.ids {
                                let payload: Vec<u8> = stream_id
                                    .map
                                    .get("payload")
                                    .and_then(|v| match v {
                                        redis::Value::BulkString(bytes) => Some(bytes.clone()),
                                        redis::Value::SimpleString(s) => {
                                            Some(s.as_bytes().to_vec())
                                        }
                                        _ => None,
                                    })
                                    .unwrap_or_default();

                                let message = Message {
                                    id: MessageId::new(stream_id.id.clone()),
                                    topic: topic.clone(),
                                    payload,
                                    timestamp: Self::parse_timestamp(&stream_id.id),
                                };

                                if msg_tx.send(message).await.is_err() {
                                    debug!(topic = %topic, "Subscriber channel closed");
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        let err_str = e.to_string();
                        if err_str.contains("NOGROUP") {
                            warn!(topic = %topic, group = %group, "Consumer group not found, will retry");
                            tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
                        } else {
                            error!(error = %e, "XREADGROUP error");
                            tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
                        }
                    }
                }
            }

            // Remove subscription handle on exit
            let mut subs = subscriptions.write().await;
            if let Some(handles) = subs.get_mut(&topic) {
                handles.retain(|h| h.consumer != consumer_clone);
                if handles.is_empty() {
                    subs.remove(&topic);
                }
            }

            info!(topic = %topic, group = %group, "Subscription task ended");
        });

        debug!(
            topic = topic,
            group = group,
            consumer = consumer,
            "Created subscription with options"
        );

        Ok(Subscription::new(msg_rx))
    }

    async fn acknowledge(
        &self,
        topic: &str,
        message_id: &MessageId,
    ) -> Result<(), MessageQueueError> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| MessageQueueError::connection(format!("Pool error: {e}")))?;

        // We need to get the group name from active subscriptions
        // For now, we'll try to acknowledge for all known groups on this topic
        let groups: Vec<String> = {
            let subs = self.subscriptions.read().await;
            subs.get(topic)
                .map(|handles| handles.iter().map(|h| h.group.clone()).collect())
                .unwrap_or_default()
        };

        if groups.is_empty() {
            // Try to get groups from Redis XINFO
            let info_result: Result<Vec<HashMap<String, redis::Value>>, RedisError> =
                redis::cmd("XINFO")
                    .arg("GROUPS")
                    .arg(topic)
                    .query_async(&mut *conn)
                    .await;

            match info_result {
                Ok(groups_info) => {
                    for group_info in groups_info {
                        if let Some(redis::Value::BulkString(name)) = group_info.get("name") {
                            let group_name = String::from_utf8_lossy(name);
                            let ack_result: Result<i64, RedisError> = redis::cmd("XACK")
                                .arg(topic)
                                .arg(group_name.as_ref())
                                .arg(message_id.as_str())
                                .query_async(&mut *conn)
                                .await;

                            match ack_result {
                                Ok(count) if count > 0 => {
                                    trace!(
                                        topic = topic,
                                        group = %group_name,
                                        message_id = %message_id,
                                        "Acknowledged message"
                                    );
                                    return Ok(());
                                }
                                Ok(_) => continue, // Message not in this group
                                Err(e) => {
                                    warn!(error = %e, "XACK failed for group {}", group_name);
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    return Err(MessageQueueError::connection(format!(
                        "Failed to get stream groups: {e}"
                    )));
                }
            }

            // No group acknowledged the message
            return Err(MessageQueueError::message_not_found(format!(
                "Message {} not found in any consumer group for topic {}",
                message_id, topic
            )));
        }

        // Acknowledge for each known group
        let mut acknowledged = false;
        for group in &groups {
            let ack_result: Result<i64, RedisError> = redis::cmd("XACK")
                .arg(topic)
                .arg(group)
                .arg(message_id.as_str())
                .query_async(&mut *conn)
                .await;

            match ack_result {
                Ok(count) if count > 0 => {
                    trace!(
                        topic = topic,
                        group = group,
                        message_id = %message_id,
                        "Acknowledged message"
                    );
                    acknowledged = true;
                }
                Ok(_) => {
                    // Message was not pending in this group (already ack'd or not delivered)
                    debug!(
                        topic = topic,
                        group = group,
                        message_id = %message_id,
                        "Message not pending in group"
                    );
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        topic = topic,
                        group = group,
                        message_id = %message_id,
                        "XACK failed"
                    );
                }
            }
        }

        if acknowledged {
            Ok(())
        } else {
            // Message wasn't pending - might have been already acknowledged
            // This is not necessarily an error
            debug!(
                topic = topic,
                message_id = %message_id,
                "Message not pending in any group (may have been already acknowledged)"
            );
            Ok(())
        }
    }

    async fn health_check(&self) -> Result<QueueHealth, MessageQueueError> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| MessageQueueError::connection(format!("Pool error: {e}")))?;

        // Test connectivity with PING
        let pong: String = redis::cmd("PING")
            .query_async(&mut *conn)
            .await
            .map_err(|e| MessageQueueError::connection(format!("PING failed: {e}")))?;

        if pong != "PONG" {
            return Ok(QueueHealth::disconnected());
        }

        // Count active consumers from tracked subscriptions
        let consumer_count: u32 = {
            let subs = self.subscriptions.read().await;
            subs.values().map(|v| v.len() as u32).sum()
        };

        // For pending messages, we'd need to sum across all streams/groups
        // This is expensive, so we return 0 for basic health check
        // Use get_pending_count for specific stream/group if needed
        let pending_messages = 0;

        Ok(QueueHealth::healthy(pending_messages, consumer_count))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = RedisMessageQueueConfig::default();
        assert_eq!(config.url, "redis://localhost:6379");
        assert_eq!(config.max_connections, 10);
        assert_eq!(config.stream_max_len, 100_000);
        assert_eq!(config.block_ms, 5000);
        assert_eq!(config.batch_size, 10);
    }

    #[test]
    fn test_config_builder() {
        let config = RedisMessageQueueConfig::new("redis://custom:6380")
            .with_max_connections(20)
            .with_stream_max_len(50_000)
            .with_block_ms(1000)
            .with_batch_size(5)
            .with_consumer_prefix("my-app");

        assert_eq!(config.url, "redis://custom:6380");
        assert_eq!(config.max_connections, 20);
        assert_eq!(config.stream_max_len, 50_000);
        assert_eq!(config.block_ms, 1000);
        assert_eq!(config.batch_size, 5);
        assert_eq!(config.consumer_prefix, "my-app");
    }

    #[test]
    fn test_parse_timestamp() {
        // Valid Redis stream ID
        let ts = RedisMessageQueue::parse_timestamp("1706745600000-0");
        assert!(ts.timestamp_millis() > 0);

        // Invalid format falls back to now
        let ts_invalid = RedisMessageQueue::parse_timestamp("invalid");
        let now = Utc::now();
        assert!((ts_invalid.timestamp_millis() - now.timestamp_millis()).abs() < 1000);
    }

    // Integration tests that require a running Redis instance
    // Run with: cargo test --features redis-streams -- --ignored

    #[tokio::test]
    #[ignore = "Requires running Redis instance"]
    async fn test_redis_connection() {
        let config = RedisMessageQueueConfig::new("redis://localhost:6379");
        let queue = RedisMessageQueue::new(config, "test-instance").await;
        assert!(queue.is_ok());
    }

    #[tokio::test]
    #[ignore = "Requires running Redis instance"]
    async fn test_redis_publish_subscribe() {
        let config = RedisMessageQueueConfig::new("redis://localhost:6379").with_block_ms(100);
        let queue = RedisMessageQueue::new(config, "test-instance")
            .await
            .expect("Failed to connect to Redis");

        // Subscribe first
        let mut subscription = queue
            .subscribe("test-stream", "test-group")
            .await
            .expect("Failed to subscribe");

        // Give the subscription time to set up
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Publish a message
        let payload = b"hello redis streams";
        let msg_id = queue
            .publish("test-stream", payload)
            .await
            .expect("Failed to publish");

        // Receive the message
        let msg = tokio::time::timeout(tokio::time::Duration::from_secs(5), subscription.recv())
            .await
            .expect("Timeout waiting for message")
            .expect("No message received");

        assert_eq!(msg.id, msg_id);
        assert_eq!(msg.payload, payload);
        assert_eq!(msg.topic, "test-stream");

        // Acknowledge
        queue
            .acknowledge("test-stream", &msg.id)
            .await
            .expect("Failed to acknowledge");
    }

    #[tokio::test]
    #[ignore = "Requires running Redis instance"]
    async fn test_redis_health_check() {
        let config = RedisMessageQueueConfig::new("redis://localhost:6379");
        let queue = RedisMessageQueue::new(config, "test-instance")
            .await
            .expect("Failed to connect to Redis");

        let health = queue.health_check().await.expect("Health check failed");
        assert!(health.connected);
    }

    #[tokio::test]
    #[ignore = "Requires running Redis instance"]
    async fn test_redis_consumer_groups() {
        let config = RedisMessageQueueConfig::new("redis://localhost:6379").with_block_ms(100);
        let queue = RedisMessageQueue::new(config, "test-instance")
            .await
            .expect("Failed to connect to Redis");

        // Create two consumers in different groups
        let mut sub1 = queue
            .subscribe("multi-group-stream", "group1")
            .await
            .expect("Failed to subscribe to group1");

        let mut sub2 = queue
            .subscribe("multi-group-stream", "group2")
            .await
            .expect("Failed to subscribe to group2");

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Publish a message
        queue
            .publish("multi-group-stream", b"broadcast message")
            .await
            .expect("Failed to publish");

        // Both groups should receive the message
        let msg1 = tokio::time::timeout(tokio::time::Duration::from_secs(5), sub1.recv())
            .await
            .expect("Timeout on group1")
            .expect("No message for group1");

        let msg2 = tokio::time::timeout(tokio::time::Duration::from_secs(5), sub2.recv())
            .await
            .expect("Timeout on group2")
            .expect("No message for group2");

        assert_eq!(msg1.payload, msg2.payload);
    }
}
