//! Event bus for Triage Warden.
//!
//! This module provides an asynchronous event bus using Tokio channels
//! for communication between components in the triage system.

use crate::incident::{
    ActionType, Alert, Enrichment, IncidentStatus, ProposedAction, TriageAnalysis,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::{broadcast, mpsc, RwLock};
use tracing::{debug, info, instrument, warn};
use uuid::Uuid;

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
}

/// Events that flow through the triage system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TriageEvent {
    /// A new alert has been received.
    AlertReceived(Alert),

    /// An incident has been created from an alert.
    IncidentCreated {
        incident_id: Uuid,
        alert_id: String,
    },

    /// Enrichment has been completed for an incident.
    EnrichmentComplete {
        incident_id: Uuid,
        enrichment: Enrichment,
    },

    /// All enrichments are complete, ready for analysis.
    EnrichmentPhaseComplete {
        incident_id: Uuid,
    },

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

/// Central event bus for the triage system.
pub struct EventBus {
    /// Broadcast channel for all events.
    broadcast_tx: broadcast::Sender<TriageEvent>,
    /// Named subscribers for specific event handling.
    subscribers: Arc<RwLock<HashMap<String, EventSubscriber>>>,
    /// Event history buffer size.
    history_size: usize,
    /// Recent event history.
    history: Arc<RwLock<Vec<TriageEvent>>>,
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
        }
    }

    /// Publishes an event to all subscribers.
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

        // Broadcast to all receivers
        match self.broadcast_tx.send(event.clone()) {
            Ok(count) => {
                debug!("Event broadcast to {} receivers", count);
            }
            Err(_) => {
                // No receivers is okay - events still go to history
                debug!("No broadcast receivers for event");
            }
        }

        // Send to named subscribers
        let subscribers = self.subscribers.read().await;
        for (name, tx) in subscribers.iter() {
            if let Err(e) = tx.try_send(event.clone()) {
                warn!("Failed to send event to subscriber {}: {}", name, e);
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
            TriageEvent::SystemError { incident_id, .. } => *incident_id,
            TriageEvent::KillSwitchActivated { .. } => None,
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
            TriageEvent::SystemError { .. } => "system_error",
            TriageEvent::KillSwitchActivated { .. } => "kill_switch_activated",
        }
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new(1024)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
            bus.publish(TriageEvent::AlertReceived(alert)).await.unwrap();
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
}
