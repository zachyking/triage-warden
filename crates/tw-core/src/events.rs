//! Event bus for Triage Warden.
//!
//! This module provides an asynchronous event bus using Tokio channels
//! for communication between components in the triage system.
//!
//! ## Distributed Mode
//!
//! When the `distributed_queue` feature flag is enabled and a [`MessageQueue`]
//! is configured, the event bus will publish events to both the local broadcast
//! channel AND the distributed message queue. This enables horizontal scaling
//! of the orchestrator across multiple instances.
//!
//! ```text
//! ┌─────────────┐    ┌─────────────┐    ┌─────────────────┐
//! │  Publisher  │───▶│  EventBus   │───▶│ Local Broadcast │
//! └─────────────┘    │             │    └─────────────────┘
//!                    │             │    ┌─────────────────┐
//!                    │             │───▶│  MessageQueue   │
//!                    └─────────────┘    │  (distributed)  │
//!                                       └─────────────────┘
//! ```
//!
//! ## Consumer Groups
//!
//! When subscribing via message queue, each orchestrator instance joins a
//! consumer group named `tw-orchestrator-{instance_id}`. This ensures that
//! each event is processed by only one instance in the cluster.
//!
//! ## Idempotency
//!
//! Events include an `event_id` for deduplication tracking. Consumers should
//! track processed event IDs to handle at-least-once delivery semantics.

use crate::features::FeatureFlags;
use crate::incident::{
    ActionType, Alert, Enrichment, IncidentStatus, ProposedAction, TriageAnalysis,
};
use crate::messaging::{MessageQueue, MessageQueueError};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::{broadcast, mpsc, RwLock};
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

/// The default topic for triage events in the distributed queue.
pub const TRIAGE_EVENTS_TOPIC: &str = "triage.events";

/// Schema version for event serialization (for future compatibility).
pub const EVENT_SCHEMA_VERSION: u8 = 1;

/// Errors that can occur in the event bus.
#[derive(Error, Debug)]
pub enum EventBusError {
    #[error("Failed to send event: {0}")]
    SendError(String),

    #[error("Failed to receive event: {0}")]
    ReceiveError(String),

    #[error("Channel closed")]
    ChannelClosed,

    #[error("Subscriber not found: {0}")]
    SubscriberNotFound(String),

    #[error("Message queue error: {0}")]
    MessageQueueError(#[from] MessageQueueError),

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Envelope wrapping a TriageEvent for distributed queue transport.
///
/// This struct provides:
/// - Unique event ID for deduplication tracking
/// - Schema version for forward/backward compatibility
/// - Timestamp for ordering and debugging
/// - Source instance ID for tracing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEnvelope {
    /// Unique identifier for this event (for deduplication).
    pub event_id: Uuid,
    /// Schema version for forward compatibility.
    pub schema_version: u8,
    /// Timestamp when the event was created.
    pub timestamp: DateTime<Utc>,
    /// Source instance ID that published the event.
    pub source_instance: Option<String>,
    /// The wrapped event.
    pub event: TriageEvent,
}

impl EventEnvelope {
    /// Creates a new event envelope with a generated event ID.
    pub fn new(event: TriageEvent) -> Self {
        Self {
            event_id: Uuid::new_v4(),
            schema_version: EVENT_SCHEMA_VERSION,
            timestamp: Utc::now(),
            source_instance: None,
            event,
        }
    }

    /// Creates a new event envelope with a specific source instance.
    pub fn with_source(event: TriageEvent, source_instance: String) -> Self {
        Self {
            event_id: Uuid::new_v4(),
            schema_version: EVENT_SCHEMA_VERSION,
            timestamp: Utc::now(),
            source_instance: Some(source_instance),
            event,
        }
    }

    /// Serializes the envelope to JSON bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, EventBusError> {
        serde_json::to_vec(self).map_err(|e| EventBusError::SerializationError(e.to_string()))
    }

    /// Deserializes an envelope from JSON bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EventBusError> {
        serde_json::from_slice(bytes).map_err(|e| EventBusError::SerializationError(e.to_string()))
    }
}

/// Events that flow through the triage system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TriageEvent {
    /// A new alert has been received.
    AlertReceived(Alert),

    /// An incident has been created from an alert.
    IncidentCreated { incident_id: Uuid, alert_id: String },

    /// Enrichment has been completed for an incident.
    EnrichmentComplete {
        incident_id: Uuid,
        enrichment: Enrichment,
    },

    /// All enrichments are complete, ready for analysis.
    EnrichmentPhaseComplete { incident_id: Uuid },

    /// AI analysis has been completed.
    AnalysisComplete {
        incident_id: Uuid,
        analysis: TriageAnalysis,
    },

    /// Actions have been proposed.
    ActionsProposed {
        incident_id: Uuid,
        actions: Vec<ProposedAction>,
    },

    /// An action has been approved.
    ActionApproved {
        incident_id: Uuid,
        action_id: Uuid,
        approved_by: String,
    },

    /// An action has been denied.
    ActionDenied {
        incident_id: Uuid,
        action_id: Uuid,
        denied_by: String,
        reason: String,
    },

    /// An action has been executed.
    ActionExecuted {
        incident_id: Uuid,
        action_id: Uuid,
        action_type: ActionType,
        result: ActionResult,
    },

    /// Incident status has changed.
    StatusChanged {
        incident_id: Uuid,
        old_status: IncidentStatus,
        new_status: IncidentStatus,
    },

    /// A ticket has been created.
    TicketCreated {
        incident_id: Uuid,
        ticket_id: String,
        ticket_url: Option<String>,
    },

    /// Incident has been escalated.
    IncidentEscalated {
        incident_id: Uuid,
        escalation_level: u8,
        reason: String,
    },

    /// Incident has been resolved.
    IncidentResolved {
        incident_id: Uuid,
        resolution: Resolution,
    },

    /// Enrichment has been requested (re-enrichment).
    EnrichmentRequested { incident_id: Uuid },

    /// System error occurred.
    SystemError {
        incident_id: Option<Uuid>,
        error: String,
        recoverable: bool,
    },

    /// Kill switch activated - stop all automation.
    KillSwitchActivated {
        reason: String,
        activated_by: String,
    },

    /// Analyst feedback has been received on an incident.
    FeedbackReceived {
        incident_id: Uuid,
        feedback_id: Uuid,
        feedback_type: String,
        is_correction: bool,
    },
}

impl TriageEvent {
    /// Returns true if this is a critical event that must not be dropped.
    /// Critical events are always delivered, even if it means blocking.
    pub fn is_critical(&self) -> bool {
        matches!(
            self,
            TriageEvent::KillSwitchActivated { .. }
                | TriageEvent::SystemError {
                    recoverable: false,
                    ..
                }
                | TriageEvent::IncidentEscalated { .. }
        )
    }
}

/// Result of an action execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResult {
    /// Whether the action succeeded.
    pub success: bool,
    /// Result message.
    pub message: String,
    /// Additional data from the action.
    pub data: Option<serde_json::Value>,
    /// Error details if failed.
    pub error: Option<String>,
}

/// Resolution details for a closed incident.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resolution {
    /// Type of resolution.
    pub resolution_type: ResolutionType,
    /// Summary of resolution.
    pub summary: String,
    /// Actions taken.
    pub actions_taken: Vec<String>,
    /// Lessons learned (optional).
    pub lessons_learned: Option<String>,
}

/// Types of incident resolutions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionType {
    /// Confirmed as true positive and remediated.
    Remediated,
    /// Confirmed as false positive.
    FalsePositive,
    /// Benign true positive (e.g., authorized pen test).
    BenignTruePositive,
    /// Duplicate of another incident.
    Duplicate,
    /// No longer relevant.
    Stale,
}

/// Type alias for event subscribers.
type EventSubscriber = mpsc::Sender<TriageEvent>;

/// Metrics for the event bus.
#[derive(Debug, Default)]
pub struct EventBusMetrics {
    /// Total events published (broadcast only).
    pub events_published_broadcast: AtomicU64,
    /// Total events published to message queue.
    pub events_published_queue: AtomicU64,
    /// Events consumed from message queue.
    pub events_consumed_queue: AtomicU64,
    /// Queue publish failures.
    pub queue_publish_failures: AtomicU64,
    /// Queue connection failures (fallback to broadcast).
    pub queue_fallback_count: AtomicU64,
    /// Processing lag (last known pending messages in queue).
    pub processing_lag: AtomicU64,
}

impl EventBusMetrics {
    /// Records a broadcast publish.
    pub fn record_broadcast_publish(&self) {
        self.events_published_broadcast
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Records a queue publish.
    pub fn record_queue_publish(&self) {
        self.events_published_queue.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a queue consumption.
    pub fn record_queue_consume(&self) {
        self.events_consumed_queue.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a queue publish failure.
    pub fn record_queue_failure(&self) {
        self.queue_publish_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a fallback to broadcast.
    pub fn record_fallback(&self) {
        self.queue_fallback_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Updates the processing lag.
    pub fn set_processing_lag(&self, lag: u64) {
        self.processing_lag.store(lag, Ordering::Relaxed);
    }

    /// Returns a snapshot of all metrics.
    pub fn snapshot(&self) -> EventBusMetricsSnapshot {
        EventBusMetricsSnapshot {
            events_published_broadcast: self.events_published_broadcast.load(Ordering::Relaxed),
            events_published_queue: self.events_published_queue.load(Ordering::Relaxed),
            events_consumed_queue: self.events_consumed_queue.load(Ordering::Relaxed),
            queue_publish_failures: self.queue_publish_failures.load(Ordering::Relaxed),
            queue_fallback_count: self.queue_fallback_count.load(Ordering::Relaxed),
            processing_lag: self.processing_lag.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of event bus metrics.
#[derive(Debug, Clone, Default)]
pub struct EventBusMetricsSnapshot {
    pub events_published_broadcast: u64,
    pub events_published_queue: u64,
    pub events_consumed_queue: u64,
    pub queue_publish_failures: u64,
    pub queue_fallback_count: u64,
    pub processing_lag: u64,
}

/// Central event bus for the triage system.
///
/// The event bus supports two modes:
/// 1. **Local mode** (default): Uses Tokio broadcast channels for in-process communication.
/// 2. **Distributed mode**: Uses both broadcast channels AND a MessageQueue for cross-instance communication.
///
/// The mode is controlled by the `distributed_queue` feature flag.
pub struct EventBus {
    /// Broadcast channel for all events.
    broadcast_tx: broadcast::Sender<TriageEvent>,
    /// Named subscribers for specific event handling.
    subscribers: Arc<RwLock<HashMap<String, EventSubscriber>>>,
    /// Event history buffer size.
    history_size: usize,
    /// Recent event history.
    history: Arc<RwLock<Vec<TriageEvent>>>,
    /// Counter for dropped events (non-critical only).
    dropped_events: AtomicU64,
    /// Optional message queue for distributed mode.
    message_queue: Option<Arc<dyn MessageQueue>>,
    /// Feature flags service for checking distributed_queue flag.
    feature_flags: Option<Arc<FeatureFlags>>,
    /// Instance ID for consumer group naming.
    instance_id: String,
    /// Metrics for monitoring.
    metrics: Arc<EventBusMetrics>,
}

impl EventBus {
    /// Creates a new event bus with the specified broadcast capacity.
    pub fn new(capacity: usize) -> Self {
        let (broadcast_tx, _) = broadcast::channel(capacity);
        Self {
            broadcast_tx,
            subscribers: Arc::new(RwLock::new(HashMap::new())),
            history_size: 1000,
            history: Arc::new(RwLock::new(Vec::with_capacity(1000))),
            dropped_events: AtomicU64::new(0),
            message_queue: None,
            feature_flags: None,
            instance_id: crate::leadership::default_instance_id(),
            metrics: Arc::new(EventBusMetrics::default()),
        }
    }

    /// Creates a new event bus with custom history size.
    pub fn with_history_size(capacity: usize, history_size: usize) -> Self {
        let (broadcast_tx, _) = broadcast::channel(capacity);
        Self {
            broadcast_tx,
            subscribers: Arc::new(RwLock::new(HashMap::new())),
            history_size,
            history: Arc::new(RwLock::new(Vec::with_capacity(history_size))),
            dropped_events: AtomicU64::new(0),
            message_queue: None,
            feature_flags: None,
            instance_id: crate::leadership::default_instance_id(),
            metrics: Arc::new(EventBusMetrics::default()),
        }
    }

    /// Creates an event bus builder for advanced configuration.
    pub fn builder(capacity: usize) -> EventBusBuilder {
        EventBusBuilder::new(capacity)
    }

    /// Returns the number of dropped events since the bus was created.
    pub fn dropped_event_count(&self) -> u64 {
        self.dropped_events.load(Ordering::Relaxed)
    }

    /// Returns whether distributed queue mode is enabled.
    ///
    /// This returns true only if:
    /// 1. A message queue is configured, AND
    /// 2. The `distributed_queue` feature flag is enabled (or no feature flags service is configured)
    pub fn is_distributed_mode(&self) -> bool {
        if self.message_queue.is_none() {
            return false;
        }

        // If feature flags are configured, check the distributed_queue flag
        if let Some(ref flags) = self.feature_flags {
            return flags.is_enabled("distributed_queue", None);
        }

        // If no feature flags, default to enabled when queue is present
        true
    }

    /// Returns the instance ID used for consumer group naming.
    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    /// Returns the consumer group name for this instance.
    ///
    /// The naming convention is: `tw-orchestrator-{instance_id}`
    pub fn consumer_group(&self) -> String {
        format!("tw-orchestrator-{}", self.instance_id)
    }

    /// Returns a reference to the metrics.
    pub fn metrics(&self) -> &EventBusMetrics {
        &self.metrics
    }

    /// Returns a snapshot of the current metrics.
    pub fn metrics_snapshot(&self) -> EventBusMetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Publishes an event to all subscribers.
    ///
    /// In distributed mode, the event is published to both:
    /// 1. The local broadcast channel (for in-process subscribers)
    /// 2. The message queue (for distributed subscribers)
    ///
    /// If the message queue is unavailable, the event is still published to
    /// the local broadcast channel (graceful degradation).
    #[instrument(skip(self), fields(event_type = ?std::mem::discriminant(&event)))]
    pub async fn publish(&self, event: TriageEvent) -> Result<(), EventBusError> {
        debug!("Publishing event: {:?}", event);

        // Add to history
        {
            let mut history = self.history.write().await;
            if history.len() >= self.history_size {
                history.remove(0);
            }
            history.push(event.clone());
        }

        // Broadcast to all receivers (always happens)
        match self.broadcast_tx.send(event.clone()) {
            Ok(count) => {
                debug!("Event broadcast to {} receivers", count);
                self.metrics.record_broadcast_publish();
            }
            Err(_) => {
                // No receivers is okay - events still go to history
                debug!("No broadcast receivers for event");
                self.metrics.record_broadcast_publish();
            }
        }

        // Publish to message queue if distributed mode is enabled
        if self.is_distributed_mode() {
            if let Some(ref queue) = self.message_queue {
                let envelope = EventEnvelope::with_source(event.clone(), self.instance_id.clone());
                match envelope.to_bytes() {
                    Ok(payload) => {
                        match queue.publish(TRIAGE_EVENTS_TOPIC, &payload).await {
                            Ok(msg_id) => {
                                debug!("Event published to message queue with ID: {}", msg_id);
                                self.metrics.record_queue_publish();
                                metrics::counter!("event_bus_queue_publish").increment(1);
                            }
                            Err(e) => {
                                // Log the error but don't fail - graceful degradation
                                warn!(
                                    "Failed to publish event to message queue: {}. Falling back to broadcast only.",
                                    e
                                );
                                self.metrics.record_queue_failure();
                                self.metrics.record_fallback();
                                metrics::counter!("event_bus_queue_failures").increment(1);
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to serialize event envelope: {}", e);
                        self.metrics.record_queue_failure();
                    }
                }
            }
        }

        // Send to named subscribers with special handling for critical events
        let subscribers = self.subscribers.read().await;
        let is_critical = event.is_critical();

        for (name, tx) in subscribers.iter() {
            if is_critical {
                // Critical events must be delivered - use blocking send with timeout
                match tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    tx.send(event.clone()),
                )
                .await
                {
                    Ok(Ok(())) => {
                        debug!("Critical event delivered to subscriber {}", name);
                    }
                    Ok(Err(_)) => {
                        // Channel closed - subscriber is gone
                        error!(
                            "Failed to deliver critical event to subscriber {}: channel closed",
                            name
                        );
                    }
                    Err(_) => {
                        // Timeout - subscriber is too slow for critical events
                        error!(
                            "Timeout delivering critical event to subscriber {} - subscriber may be stalled",
                            name
                        );
                    }
                }
            } else {
                // Non-critical events use try_send - drop if channel is full
                if let Err(e) = tx.try_send(event.clone()) {
                    let dropped = self.dropped_events.fetch_add(1, Ordering::Relaxed) + 1;
                    // Log every 100 dropped events to avoid log spam
                    if dropped % 100 == 1 {
                        warn!(
                            "Event dropped for subscriber {} (total dropped: {}): {}",
                            name, dropped, e
                        );
                    }
                }
            }
        }

        Ok(())
    }

    /// Subscribes to the broadcast channel.
    pub fn subscribe_broadcast(&self) -> broadcast::Receiver<TriageEvent> {
        self.broadcast_tx.subscribe()
    }

    /// Registers a named subscriber with a dedicated channel.
    pub async fn register_subscriber(
        &self,
        name: &str,
        buffer_size: usize,
    ) -> mpsc::Receiver<TriageEvent> {
        let (tx, rx) = mpsc::channel(buffer_size);
        let mut subscribers = self.subscribers.write().await;
        subscribers.insert(name.to_string(), tx);
        info!("Registered subscriber: {}", name);
        rx
    }

    /// Unregisters a named subscriber.
    pub async fn unregister_subscriber(&self, name: &str) -> Result<(), EventBusError> {
        let mut subscribers = self.subscribers.write().await;
        if subscribers.remove(name).is_some() {
            info!("Unregistered subscriber: {}", name);
            Ok(())
        } else {
            Err(EventBusError::SubscriberNotFound(name.to_string()))
        }
    }

    /// Gets recent event history.
    pub async fn get_history(&self, limit: Option<usize>) -> Vec<TriageEvent> {
        let history = self.history.read().await;
        match limit {
            Some(n) => history.iter().rev().take(n).cloned().collect(),
            None => history.clone(),
        }
    }

    /// Gets events for a specific incident.
    pub async fn get_incident_events(&self, incident_id: Uuid) -> Vec<TriageEvent> {
        let history = self.history.read().await;
        history
            .iter()
            .filter(|event| event.incident_id() == Some(incident_id))
            .cloned()
            .collect()
    }

    /// Gets the number of active subscribers.
    pub async fn subscriber_count(&self) -> usize {
        self.subscribers.read().await.len() + self.broadcast_tx.receiver_count()
    }

    /// Subscribes to events via the distributed message queue.
    ///
    /// This method returns a channel that receives events from the message queue.
    /// Events are automatically deserialized from the queue format.
    ///
    /// The consumer group is named `tw-orchestrator-{instance_id}` to ensure
    /// load balancing across orchestrator instances.
    ///
    /// Returns `None` if distributed mode is not enabled or no message queue is configured.
    pub async fn subscribe_distributed(&self) -> Option<mpsc::Receiver<EventEnvelope>> {
        if !self.is_distributed_mode() {
            debug!("Distributed mode not enabled, cannot create distributed subscription");
            return None;
        }

        let queue = self.message_queue.as_ref()?;
        let consumer_group = self.consumer_group();

        match queue.subscribe(TRIAGE_EVENTS_TOPIC, &consumer_group).await {
            Ok(mut subscription) => {
                // Create a channel to bridge the subscription
                let (tx, rx) = mpsc::channel::<EventEnvelope>(1024);
                let metrics = Arc::clone(&self.metrics);
                let queue_clone = Arc::clone(queue);

                // Spawn a task to process messages from the queue
                tokio::spawn(async move {
                    while let Some(message) = subscription.recv().await {
                        match EventEnvelope::from_bytes(&message.payload) {
                            Ok(envelope) => {
                                metrics.record_queue_consume();
                                metrics::counter!("event_bus_queue_consume").increment(1);

                                if tx.send(envelope).await.is_err() {
                                    debug!("Distributed subscription receiver dropped");
                                    break;
                                }

                                // Acknowledge the message after successful send
                                if let Err(e) = queue_clone
                                    .acknowledge(TRIAGE_EVENTS_TOPIC, &message.id)
                                    .await
                                {
                                    warn!("Failed to acknowledge message {}: {}", message.id, e);
                                }
                            }
                            Err(e) => {
                                error!("Failed to deserialize event envelope from queue: {}", e);
                                // Still acknowledge to prevent infinite redelivery of bad messages
                                let _ = queue_clone
                                    .acknowledge(TRIAGE_EVENTS_TOPIC, &message.id)
                                    .await;
                            }
                        }
                    }
                    debug!("Distributed subscription task ended");
                });

                info!(
                    "Created distributed subscription with consumer group: {}",
                    consumer_group
                );
                Some(rx)
            }
            Err(e) => {
                error!("Failed to create distributed subscription: {}", e);
                None
            }
        }
    }

    /// Performs a health check on the message queue (if configured).
    ///
    /// Returns `None` if no message queue is configured.
    /// Updates the processing lag metric with the pending message count.
    pub async fn queue_health_check(
        &self,
    ) -> Option<Result<crate::messaging::QueueHealth, EventBusError>> {
        let queue = self.message_queue.as_ref()?;

        match queue.health_check().await {
            Ok(health) => {
                self.metrics.set_processing_lag(health.pending_messages);
                metrics::gauge!("event_bus_processing_lag").set(health.pending_messages as f64);
                Some(Ok(health))
            }
            Err(e) => Some(Err(EventBusError::MessageQueueError(e))),
        }
    }

    /// Publishes an event with fallback logging and metrics on failure.
    ///
    /// This method is intended for fire-and-forget scenarios where event
    /// delivery failures should be logged but not propagate as errors.
    /// It logs any failures at ERROR level and increments a failure counter.
    #[instrument(skip(self), fields(event_type = ?std::mem::discriminant(&event)))]
    pub async fn publish_with_fallback(&self, event: TriageEvent) {
        if let Err(e) = self.publish(event).await {
            tracing::error!(error = %e, "Event publish failed");
            metrics::counter!("event_bus_publish_failures").increment(1);
        }
    }
}

impl TriageEvent {
    /// Extracts the incident ID from an event if applicable.
    pub fn incident_id(&self) -> Option<Uuid> {
        match self {
            TriageEvent::AlertReceived(_) => None,
            TriageEvent::IncidentCreated { incident_id, .. } => Some(*incident_id),
            TriageEvent::EnrichmentComplete { incident_id, .. } => Some(*incident_id),
            TriageEvent::EnrichmentPhaseComplete { incident_id } => Some(*incident_id),
            TriageEvent::AnalysisComplete { incident_id, .. } => Some(*incident_id),
            TriageEvent::ActionsProposed { incident_id, .. } => Some(*incident_id),
            TriageEvent::ActionApproved { incident_id, .. } => Some(*incident_id),
            TriageEvent::ActionDenied { incident_id, .. } => Some(*incident_id),
            TriageEvent::ActionExecuted { incident_id, .. } => Some(*incident_id),
            TriageEvent::StatusChanged { incident_id, .. } => Some(*incident_id),
            TriageEvent::TicketCreated { incident_id, .. } => Some(*incident_id),
            TriageEvent::IncidentEscalated { incident_id, .. } => Some(*incident_id),
            TriageEvent::IncidentResolved { incident_id, .. } => Some(*incident_id),
            TriageEvent::EnrichmentRequested { incident_id } => Some(*incident_id),
            TriageEvent::SystemError { incident_id, .. } => *incident_id,
            TriageEvent::KillSwitchActivated { .. } => None,
            TriageEvent::FeedbackReceived { incident_id, .. } => Some(*incident_id),
        }
    }

    /// Returns the event type as a string for logging/metrics.
    pub fn event_type(&self) -> &'static str {
        match self {
            TriageEvent::AlertReceived(_) => "alert_received",
            TriageEvent::IncidentCreated { .. } => "incident_created",
            TriageEvent::EnrichmentComplete { .. } => "enrichment_complete",
            TriageEvent::EnrichmentPhaseComplete { .. } => "enrichment_phase_complete",
            TriageEvent::AnalysisComplete { .. } => "analysis_complete",
            TriageEvent::ActionsProposed { .. } => "actions_proposed",
            TriageEvent::ActionApproved { .. } => "action_approved",
            TriageEvent::ActionDenied { .. } => "action_denied",
            TriageEvent::ActionExecuted { .. } => "action_executed",
            TriageEvent::StatusChanged { .. } => "status_changed",
            TriageEvent::TicketCreated { .. } => "ticket_created",
            TriageEvent::IncidentEscalated { .. } => "incident_escalated",
            TriageEvent::IncidentResolved { .. } => "incident_resolved",
            TriageEvent::EnrichmentRequested { .. } => "enrichment_requested",
            TriageEvent::SystemError { .. } => "system_error",
            TriageEvent::KillSwitchActivated { .. } => "kill_switch_activated",
            TriageEvent::FeedbackReceived { .. } => "feedback_received",
        }
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new(1024)
    }
}

/// Builder for creating an EventBus with advanced configuration.
///
/// # Example
///
/// ```ignore
/// use tw_core::events::EventBus;
/// use tw_core::messaging::MockMessageQueue;
/// use std::sync::Arc;
///
/// let queue = Arc::new(MockMessageQueue::new());
/// let event_bus = EventBus::builder(1024)
///     .with_message_queue(queue)
///     .with_instance_id("orchestrator-1")
///     .with_history_size(500)
///     .build();
/// ```
pub struct EventBusBuilder {
    capacity: usize,
    history_size: usize,
    message_queue: Option<Arc<dyn MessageQueue>>,
    feature_flags: Option<Arc<FeatureFlags>>,
    instance_id: Option<String>,
}

impl EventBusBuilder {
    /// Creates a new builder with the specified broadcast capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            history_size: 1000,
            message_queue: None,
            feature_flags: None,
            instance_id: None,
        }
    }

    /// Sets the event history size.
    pub fn with_history_size(mut self, size: usize) -> Self {
        self.history_size = size;
        self
    }

    /// Sets the message queue for distributed mode.
    pub fn with_message_queue(mut self, queue: Arc<dyn MessageQueue>) -> Self {
        self.message_queue = Some(queue);
        self
    }

    /// Sets the feature flags service for checking the `distributed_queue` flag.
    pub fn with_feature_flags(mut self, flags: Arc<FeatureFlags>) -> Self {
        self.feature_flags = Some(flags);
        self
    }

    /// Sets the instance ID for consumer group naming.
    ///
    /// If not set, a default instance ID is generated.
    pub fn with_instance_id(mut self, id: impl Into<String>) -> Self {
        self.instance_id = Some(id.into());
        self
    }

    /// Builds the EventBus.
    pub fn build(self) -> EventBus {
        let (broadcast_tx, _) = broadcast::channel(self.capacity);

        EventBus {
            broadcast_tx,
            subscribers: Arc::new(RwLock::new(HashMap::new())),
            history_size: self.history_size,
            history: Arc::new(RwLock::new(Vec::with_capacity(self.history_size))),
            dropped_events: AtomicU64::new(0),
            message_queue: self.message_queue,
            feature_flags: self.feature_flags,
            instance_id: self
                .instance_id
                .unwrap_or_else(crate::leadership::default_instance_id),
            metrics: Arc::new(EventBusMetrics::default()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::FeatureFlagStore;
    use crate::incident::{AlertSource, Severity};
    use chrono::Utc;

    fn create_test_alert() -> Alert {
        Alert {
            id: "test-alert-1".to_string(),
            source: AlertSource::EmailSecurity("M365".to_string()),
            alert_type: "phishing".to_string(),
            severity: Severity::High,
            title: "Test alert".to_string(),
            description: None,
            data: serde_json::json!({}),
            timestamp: Utc::now(),
            tags: vec![],
        }
    }

    #[tokio::test]
    async fn test_event_bus_publish() {
        let bus = EventBus::new(100);
        let event = TriageEvent::AlertReceived(create_test_alert());

        let result = bus.publish(event).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_event_bus_broadcast() {
        let bus = EventBus::new(100);
        let mut rx = bus.subscribe_broadcast();

        let event = TriageEvent::AlertReceived(create_test_alert());
        bus.publish(event.clone()).await.unwrap();

        let received = rx.recv().await.unwrap();
        assert_eq!(received.event_type(), "alert_received");
    }

    #[tokio::test]
    async fn test_named_subscriber() {
        let bus = EventBus::new(100);
        let mut rx = bus.register_subscriber("test_subscriber", 10).await;

        let event = TriageEvent::AlertReceived(create_test_alert());
        bus.publish(event).await.unwrap();

        let received = rx.recv().await.unwrap();
        assert_eq!(received.event_type(), "alert_received");
    }

    #[tokio::test]
    async fn test_event_history() {
        let bus = EventBus::with_history_size(100, 10);

        for i in 0..5 {
            let mut alert = create_test_alert();
            alert.id = format!("alert-{}", i);
            bus.publish(TriageEvent::AlertReceived(alert))
                .await
                .unwrap();
        }

        let history = bus.get_history(None).await;
        assert_eq!(history.len(), 5);

        let limited = bus.get_history(Some(3)).await;
        assert_eq!(limited.len(), 3);
    }

    #[tokio::test]
    async fn test_incident_id_extraction() {
        let incident_id = Uuid::new_v4();

        let event = TriageEvent::IncidentCreated {
            incident_id,
            alert_id: "test".to_string(),
        };
        assert_eq!(event.incident_id(), Some(incident_id));

        let event = TriageEvent::AlertReceived(create_test_alert());
        assert_eq!(event.incident_id(), None);
    }

    // ============================================================
    // Event Envelope Tests
    // ============================================================

    #[test]
    fn test_event_envelope_creation() {
        let event = TriageEvent::AlertReceived(create_test_alert());
        let envelope = EventEnvelope::new(event.clone());

        assert_eq!(envelope.schema_version, EVENT_SCHEMA_VERSION);
        assert!(envelope.source_instance.is_none());
        assert!(envelope.event_id != Uuid::nil());
    }

    #[test]
    fn test_event_envelope_with_source() {
        let event = TriageEvent::AlertReceived(create_test_alert());
        let envelope = EventEnvelope::with_source(event, "instance-1".to_string());

        assert_eq!(envelope.source_instance, Some("instance-1".to_string()));
    }

    #[test]
    fn test_event_envelope_serialization() {
        let event = TriageEvent::AlertReceived(create_test_alert());
        let envelope = EventEnvelope::new(event);

        let bytes = envelope.to_bytes().unwrap();
        let deserialized = EventEnvelope::from_bytes(&bytes).unwrap();

        assert_eq!(deserialized.event_id, envelope.event_id);
        assert_eq!(deserialized.schema_version, envelope.schema_version);
        assert_eq!(deserialized.event.event_type(), "alert_received");
    }

    #[test]
    fn test_event_envelope_unique_ids() {
        let event = TriageEvent::AlertReceived(create_test_alert());
        let envelope1 = EventEnvelope::new(event.clone());
        let envelope2 = EventEnvelope::new(event);

        assert_ne!(envelope1.event_id, envelope2.event_id);
    }

    // ============================================================
    // EventBus Builder Tests
    // ============================================================

    #[test]
    fn test_event_bus_builder() {
        let bus = EventBus::builder(512)
            .with_history_size(500)
            .with_instance_id("test-instance")
            .build();

        assert_eq!(bus.instance_id(), "test-instance");
        assert_eq!(bus.consumer_group(), "tw-orchestrator-test-instance");
    }

    #[tokio::test]
    async fn test_event_bus_builder_with_mock_queue() {
        use crate::messaging::MockMessageQueue;

        let queue: Arc<dyn MessageQueue> = Arc::new(MockMessageQueue::new());
        let bus = EventBus::builder(512)
            .with_message_queue(queue)
            .with_instance_id("test-instance")
            .build();

        assert!(bus.is_distributed_mode());
    }

    #[test]
    fn test_event_bus_not_distributed_without_queue() {
        let bus = EventBus::new(100);
        assert!(!bus.is_distributed_mode());
    }

    // ============================================================
    // Distributed Mode Tests
    // ============================================================

    #[tokio::test]
    async fn test_distributed_mode_publish() {
        use crate::messaging::MockMessageQueue;

        let mock_queue = Arc::new(MockMessageQueue::new());
        let queue: Arc<dyn MessageQueue> = Arc::clone(&mock_queue) as Arc<dyn MessageQueue>;
        let bus = EventBus::builder(512)
            .with_message_queue(queue)
            .with_instance_id("test-instance")
            .build();

        // Subscribe to the queue first
        let mut sub = mock_queue
            .subscribe(TRIAGE_EVENTS_TOPIC, "test-consumer")
            .await
            .unwrap();

        // Give subscription time to set up
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        // Publish an event
        let event = TriageEvent::AlertReceived(create_test_alert());
        bus.publish(event).await.unwrap();

        // Should receive from queue
        let msg = tokio::time::timeout(std::time::Duration::from_secs(1), sub.recv())
            .await
            .expect("Timeout")
            .expect("No message");

        let envelope = EventEnvelope::from_bytes(&msg.payload).unwrap();
        assert_eq!(envelope.event.event_type(), "alert_received");
        assert_eq!(envelope.source_instance, Some("test-instance".to_string()));
    }

    #[tokio::test]
    async fn test_distributed_mode_metrics() {
        use crate::messaging::MockMessageQueue;

        let queue: Arc<dyn MessageQueue> = Arc::new(MockMessageQueue::new());
        let bus = EventBus::builder(512)
            .with_message_queue(queue)
            .with_instance_id("test-instance")
            .build();

        let event = TriageEvent::AlertReceived(create_test_alert());
        bus.publish(event).await.unwrap();

        let metrics = bus.metrics_snapshot();
        assert_eq!(metrics.events_published_broadcast, 1);
        assert_eq!(metrics.events_published_queue, 1);
    }

    #[tokio::test]
    async fn test_broadcast_only_mode_metrics() {
        let bus = EventBus::new(100);

        let event = TriageEvent::AlertReceived(create_test_alert());
        bus.publish(event).await.unwrap();

        let metrics = bus.metrics_snapshot();
        assert_eq!(metrics.events_published_broadcast, 1);
        assert_eq!(metrics.events_published_queue, 0);
    }

    #[tokio::test]
    async fn test_subscribe_distributed_returns_none_without_queue() {
        let bus = EventBus::new(100);

        let subscription = bus.subscribe_distributed().await;
        assert!(subscription.is_none());
    }

    #[tokio::test]
    async fn test_subscribe_distributed_with_queue() {
        use crate::messaging::MockMessageQueue;

        let queue: Arc<dyn MessageQueue> = Arc::new(MockMessageQueue::new());
        let bus = EventBus::builder(512)
            .with_message_queue(queue)
            .with_instance_id("test-instance")
            .build();

        let subscription = bus.subscribe_distributed().await;
        assert!(subscription.is_some());
    }

    #[tokio::test]
    async fn test_queue_health_check() {
        use crate::messaging::MockMessageQueue;

        let queue: Arc<dyn MessageQueue> = Arc::new(MockMessageQueue::new());
        let bus = EventBus::builder(512)
            .with_message_queue(queue)
            .with_instance_id("test-instance")
            .build();

        let health = bus.queue_health_check().await;
        assert!(health.is_some());
        let health = health.unwrap().unwrap();
        assert!(health.connected);
    }

    #[tokio::test]
    async fn test_queue_health_check_none_without_queue() {
        let bus = EventBus::new(100);

        let health = bus.queue_health_check().await;
        assert!(health.is_none());
    }

    // ============================================================
    // Feature Flag Integration Tests
    // ============================================================

    #[tokio::test]
    async fn test_distributed_mode_disabled_by_feature_flag() {
        use crate::features::{FeatureFlag, FeatureFlags, InMemoryFeatureFlagStore};
        use crate::messaging::MockMessageQueue;

        // Create feature flags with distributed_queue disabled
        let store: Arc<dyn FeatureFlagStore> = Arc::new(InMemoryFeatureFlagStore::new());
        let flag =
            FeatureFlag::new("distributed_queue", "Enable distributed queue", false, None).unwrap();
        store.upsert(&flag).await.unwrap();

        let flags = Arc::new(FeatureFlags::new(Arc::clone(&store)));
        flags.refresh().await.unwrap();

        let queue: Arc<dyn MessageQueue> = Arc::new(MockMessageQueue::new());
        let bus = EventBus::builder(512)
            .with_message_queue(queue)
            .with_feature_flags(flags)
            .with_instance_id("test-instance")
            .build();

        // Even with queue, distributed mode should be off
        assert!(!bus.is_distributed_mode());
    }

    #[tokio::test]
    async fn test_distributed_mode_enabled_by_feature_flag() {
        use crate::features::{FeatureFlag, FeatureFlags, InMemoryFeatureFlagStore};
        use crate::messaging::MockMessageQueue;

        // Create feature flags with distributed_queue enabled
        let store: Arc<dyn FeatureFlagStore> = Arc::new(InMemoryFeatureFlagStore::new());
        let flag =
            FeatureFlag::new("distributed_queue", "Enable distributed queue", true, None).unwrap();
        store.upsert(&flag).await.unwrap();

        let flags = Arc::new(FeatureFlags::new(Arc::clone(&store)));
        flags.refresh().await.unwrap();

        let queue: Arc<dyn MessageQueue> = Arc::new(MockMessageQueue::new());
        let bus = EventBus::builder(512)
            .with_message_queue(queue)
            .with_feature_flags(flags)
            .with_instance_id("test-instance")
            .build();

        assert!(bus.is_distributed_mode());
    }

    // ============================================================
    // Consumer Group Naming Tests
    // ============================================================

    #[test]
    fn test_consumer_group_naming() {
        let bus = EventBus::builder(100)
            .with_instance_id("my-orchestrator-pod-abc123")
            .build();

        assert_eq!(
            bus.consumer_group(),
            "tw-orchestrator-my-orchestrator-pod-abc123"
        );
    }

    #[test]
    fn test_consumer_group_default_instance_id() {
        let bus = EventBus::new(100);

        let group = bus.consumer_group();
        assert!(group.starts_with("tw-orchestrator-"));
        // Default instance ID should be a hostname-based identifier
        assert!(group.len() > "tw-orchestrator-".len());
    }

    // ============================================================
    // Backward Compatibility Tests
    // ============================================================

    #[tokio::test]
    async fn test_backward_compatibility_broadcast() {
        // Existing code using EventBus should still work
        let bus = EventBus::new(100);
        let mut rx = bus.subscribe_broadcast();

        let event = TriageEvent::AlertReceived(create_test_alert());
        bus.publish(event).await.unwrap();

        let received = rx.recv().await.unwrap();
        assert_eq!(received.event_type(), "alert_received");
    }

    #[tokio::test]
    async fn test_backward_compatibility_named_subscriber() {
        // Existing code using named subscribers should still work
        let bus = EventBus::new(100);
        let mut rx = bus.register_subscriber("legacy_subscriber", 10).await;

        let event = TriageEvent::AlertReceived(create_test_alert());
        bus.publish(event).await.unwrap();

        let received = rx.recv().await.unwrap();
        assert_eq!(received.event_type(), "alert_received");
    }

    #[tokio::test]
    async fn test_backward_compatibility_history() {
        // Existing code using history should still work
        let bus = EventBus::with_history_size(100, 10);

        for i in 0..5 {
            let mut alert = create_test_alert();
            alert.id = format!("compat-alert-{}", i);
            bus.publish(TriageEvent::AlertReceived(alert))
                .await
                .unwrap();
        }

        let history = bus.get_history(None).await;
        assert_eq!(history.len(), 5);
    }

    // ============================================================
    // Error Handling Tests
    // ============================================================

    #[test]
    fn test_event_bus_error_from_message_queue_error() {
        use crate::messaging::MessageQueueError;

        let mq_error = MessageQueueError::connection("connection failed");
        let bus_error: EventBusError = mq_error.into();

        assert!(matches!(bus_error, EventBusError::MessageQueueError(_)));
    }

    #[test]
    fn test_event_envelope_deserialization_error() {
        let invalid_bytes = b"not valid json";
        let result = EventEnvelope::from_bytes(invalid_bytes);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            EventBusError::SerializationError(_)
        ));
    }

    // ============================================================
    // Metrics Tests
    // ============================================================

    #[test]
    fn test_metrics_snapshot() {
        let metrics = EventBusMetrics::default();

        metrics.record_broadcast_publish();
        metrics.record_broadcast_publish();
        metrics.record_queue_publish();
        metrics.record_queue_consume();
        metrics.record_queue_failure();
        metrics.record_fallback();
        metrics.set_processing_lag(42);

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.events_published_broadcast, 2);
        assert_eq!(snapshot.events_published_queue, 1);
        assert_eq!(snapshot.events_consumed_queue, 1);
        assert_eq!(snapshot.queue_publish_failures, 1);
        assert_eq!(snapshot.queue_fallback_count, 1);
        assert_eq!(snapshot.processing_lag, 42);
    }
}
