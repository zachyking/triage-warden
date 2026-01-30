//! Central orchestrator for Triage Warden.
//!
//! The orchestrator manages the main agent loop, coordinating between
//! connectors, the policy engine, AI analysis, and action execution.

use crate::events::{EventBus, TriageEvent};
use crate::incident::{Alert, Incident, IncidentStatus};
use crate::workflow::{WorkflowEngine, WorkflowError};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

/// Errors that can occur in the orchestrator.
#[derive(Error, Debug)]
pub enum OrchestratorError {
    #[error("Incident not found: {0}")]
    IncidentNotFound(Uuid),

    #[error("Workflow error: {0}")]
    WorkflowError(#[from] WorkflowError),

    #[error("Event bus error: {0}")]
    EventBusError(#[from] crate::events::EventBusError),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Connector error: {0}")]
    ConnectorError(String),

    #[error("Policy violation: {0}")]
    PolicyViolation(String),

    #[error("Kill switch activated: {0}")]
    KillSwitchActivated(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

/// Operation mode for the orchestrator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OperationMode {
    /// AI observes and suggests only - no automated actions.
    Assisted,
    /// Low-risk actions are automated, high-risk requires approval.
    #[default]
    Supervised,
    /// Full automation for configured incident types.
    Autonomous,
}

/// Configuration for the orchestrator.
#[derive(Debug, Clone)]
pub struct OrchestratorConfig {
    /// Operation mode.
    pub mode: OperationMode,
    /// Maximum concurrent incidents to process.
    pub max_concurrent_incidents: usize,
    /// Timeout for enrichment phase (seconds).
    pub enrichment_timeout_secs: u64,
    /// Timeout for analysis phase (seconds).
    pub analysis_timeout_secs: u64,
    /// Whether to auto-create tickets.
    pub auto_create_tickets: bool,
    /// Whether the kill switch is enabled.
    pub kill_switch_enabled: bool,
}

impl Default for OrchestratorConfig {
    fn default() -> Self {
        Self {
            mode: OperationMode::Supervised,
            max_concurrent_incidents: 50,
            enrichment_timeout_secs: 60,
            analysis_timeout_secs: 120,
            auto_create_tickets: true,
            kill_switch_enabled: false,
        }
    }
}

/// Statistics for the orchestrator.
#[derive(Debug, Clone, Default)]
pub struct OrchestratorStats {
    /// Total alerts received.
    pub alerts_received: u64,
    /// Total incidents created.
    pub incidents_created: u64,
    /// Incidents currently being processed.
    pub incidents_in_progress: u64,
    /// Incidents resolved.
    pub incidents_resolved: u64,
    /// Incidents marked as false positive.
    pub incidents_false_positive: u64,
    /// Actions executed.
    pub actions_executed: u64,
    /// Actions denied.
    pub actions_denied: u64,
    /// Errors encountered.
    pub errors: u64,
}

/// The central orchestrator that coordinates all triage activities.
pub struct Orchestrator {
    /// Configuration.
    config: Arc<RwLock<OrchestratorConfig>>,
    /// Event bus for inter-component communication.
    event_bus: Arc<EventBus>,
    /// Workflow engine for state management.
    workflow_engine: Arc<RwLock<WorkflowEngine>>,
    /// Active incidents being processed.
    incidents: Arc<RwLock<HashMap<Uuid, Incident>>>,
    /// Statistics.
    stats: Arc<RwLock<OrchestratorStats>>,
    /// Whether the orchestrator is running.
    running: Arc<RwLock<bool>>,
}

impl Orchestrator {
    /// Creates a new orchestrator with default configuration.
    pub fn new() -> Self {
        Self::with_config(OrchestratorConfig::default())
    }

    /// Creates a new orchestrator with the specified configuration.
    pub fn with_config(config: OrchestratorConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            event_bus: Arc::new(EventBus::new(1024)),
            workflow_engine: Arc::new(RwLock::new(WorkflowEngine::new())),
            incidents: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(OrchestratorStats::default())),
            running: Arc::new(RwLock::new(false)),
        }
    }

    /// Gets a reference to the event bus.
    pub fn event_bus(&self) -> Arc<EventBus> {
        Arc::clone(&self.event_bus)
    }

    /// Gets the current operation mode.
    pub async fn operation_mode(&self) -> OperationMode {
        self.config.read().await.mode
    }

    /// Sets the operation mode.
    pub async fn set_operation_mode(&self, mode: OperationMode) {
        let mut config = self.config.write().await;
        info!(
            "Changing operation mode from {:?} to {:?}",
            config.mode, mode
        );
        config.mode = mode;
    }

    /// Checks if the kill switch is activated.
    pub async fn is_kill_switch_active(&self) -> bool {
        self.config.read().await.kill_switch_enabled
    }

    /// Activates the kill switch.
    #[instrument(skip(self))]
    pub async fn activate_kill_switch(&self, reason: &str, activated_by: &str) {
        let mut config = self.config.write().await;
        config.kill_switch_enabled = true;
        error!("Kill switch activated by {}: {}", activated_by, reason);

        // Publish kill switch event
        let _ = self
            .event_bus
            .publish(TriageEvent::KillSwitchActivated {
                reason: reason.to_string(),
                activated_by: activated_by.to_string(),
            })
            .await;
    }

    /// Deactivates the kill switch.
    #[instrument(skip(self))]
    pub async fn deactivate_kill_switch(&self, deactivated_by: &str) {
        let mut config = self.config.write().await;
        config.kill_switch_enabled = false;
        warn!("Kill switch deactivated by {}", deactivated_by);
    }

    /// Processes an incoming alert.
    #[instrument(skip(self, alert), fields(alert_id = %alert.id))]
    pub async fn process_alert(&self, alert: Alert) -> Result<Uuid, OrchestratorError> {
        // Check kill switch
        if self.is_kill_switch_active().await {
            return Err(OrchestratorError::KillSwitchActivated(
                "Cannot process alerts while kill switch is active".to_string(),
            ));
        }

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.alerts_received += 1;
        }

        // Publish alert received event
        self.event_bus
            .publish(TriageEvent::AlertReceived(alert.clone()))
            .await?;

        // Create incident from alert
        let incident = Incident::from_alert(alert.clone());
        let incident_id = incident.id;

        info!(
            "Created incident {} from alert {} (severity: {})",
            incident_id, alert.id, incident.severity
        );

        // Register workflow
        {
            let mut workflow_engine = self.workflow_engine.write().await;
            workflow_engine.register_workflow(&incident);
        }

        // Store incident
        {
            let mut incidents = self.incidents.write().await;
            incidents.insert(incident_id, incident);
        }

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.incidents_created += 1;
            stats.incidents_in_progress += 1;
        }

        // Publish incident created event
        self.event_bus
            .publish(TriageEvent::IncidentCreated {
                incident_id,
                alert_id: alert.id,
            })
            .await?;

        Ok(incident_id)
    }

    /// Gets an incident by ID.
    pub async fn get_incident(&self, id: Uuid) -> Option<Incident> {
        let incidents = self.incidents.read().await;
        incidents.get(&id).cloned()
    }

    /// Gets all active incidents.
    pub async fn get_active_incidents(&self) -> Vec<Incident> {
        let incidents = self.incidents.read().await;
        incidents.values().cloned().collect()
    }

    /// Gets incidents by status.
    pub async fn get_incidents_by_status(&self, status: IncidentStatus) -> Vec<Incident> {
        let incidents = self.incidents.read().await;
        incidents
            .values()
            .filter(|i| i.status == status)
            .cloned()
            .collect()
    }

    /// Transitions an incident to a new status.
    #[instrument(skip(self), fields(incident_id = %incident_id))]
    pub async fn transition_incident(
        &self,
        incident_id: Uuid,
        new_status: IncidentStatus,
    ) -> Result<(), OrchestratorError> {
        // Check kill switch for certain transitions
        if self.is_kill_switch_active().await && new_status == IncidentStatus::Executing {
            return Err(OrchestratorError::KillSwitchActivated(
                "Cannot execute actions while kill switch is active".to_string(),
            ));
        }

        let old_status;
        let transition_actions;

        // Get incident and perform transition
        {
            let mut incidents = self.incidents.write().await;
            let incident = incidents
                .get_mut(&incident_id)
                .ok_or(OrchestratorError::IncidentNotFound(incident_id))?;

            old_status = incident.status.clone();

            let mut workflow_engine = self.workflow_engine.write().await;
            transition_actions = workflow_engine.transition(incident, new_status.clone())?;
        }

        // Publish status changed event
        self.event_bus
            .publish(TriageEvent::StatusChanged {
                incident_id,
                old_status: old_status.clone(),
                new_status: new_status.clone(),
            })
            .await?;

        // Execute transition actions
        for action in transition_actions {
            debug!("Executing transition action: {:?}", action);
            // In a full implementation, these would trigger actual actions
        }

        // Update stats for terminal states
        {
            let mut stats = self.stats.write().await;
            match new_status {
                IncidentStatus::Resolved => {
                    stats.incidents_in_progress = stats.incidents_in_progress.saturating_sub(1);
                    stats.incidents_resolved += 1;
                }
                IncidentStatus::FalsePositive => {
                    stats.incidents_in_progress = stats.incidents_in_progress.saturating_sub(1);
                    stats.incidents_false_positive += 1;
                }
                IncidentStatus::Closed => {
                    stats.incidents_in_progress = stats.incidents_in_progress.saturating_sub(1);
                }
                _ => {}
            }
        }

        info!(
            "Transitioned incident {} from {:?} to {:?}",
            incident_id, old_status, new_status
        );

        Ok(())
    }

    /// Updates an incident.
    pub async fn update_incident<F>(&self, incident_id: Uuid, f: F) -> Result<(), OrchestratorError>
    where
        F: FnOnce(&mut Incident),
    {
        let mut incidents = self.incidents.write().await;
        let incident = incidents
            .get_mut(&incident_id)
            .ok_or(OrchestratorError::IncidentNotFound(incident_id))?;

        f(incident);
        Ok(())
    }

    /// Gets the current statistics.
    pub async fn stats(&self) -> OrchestratorStats {
        self.stats.read().await.clone()
    }

    /// Checks if the orchestrator is running.
    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }

    /// Starts the orchestrator.
    #[instrument(skip(self))]
    pub async fn start(&self) -> Result<(), OrchestratorError> {
        let mut running = self.running.write().await;
        if *running {
            return Ok(());
        }
        *running = true;
        info!("Orchestrator started");
        Ok(())
    }

    /// Stops the orchestrator.
    #[instrument(skip(self))]
    pub async fn stop(&self) -> Result<(), OrchestratorError> {
        let mut running = self.running.write().await;
        *running = false;
        info!("Orchestrator stopped");
        Ok(())
    }

    /// Gets the workflow state for an incident.
    pub async fn get_workflow_state(
        &self,
        incident_id: Uuid,
    ) -> Option<crate::workflow::WorkflowState> {
        let engine = self.workflow_engine.read().await;
        engine.get_workflow(incident_id).cloned()
    }

    /// Gets the count of incidents by status.
    pub async fn get_incident_counts(&self) -> HashMap<IncidentStatus, usize> {
        let incidents = self.incidents.read().await;
        let mut counts: HashMap<IncidentStatus, usize> = HashMap::new();

        for incident in incidents.values() {
            *counts.entry(incident.status.clone()).or_insert(0) += 1;
        }

        counts
    }
}

impl Default for Orchestrator {
    fn default() -> Self {
        Self::new()
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
            title: "Test phishing alert".to_string(),
            description: Some("Suspicious email detected".to_string()),
            data: serde_json::json!({"subject": "Urgent: Password reset"}),
            timestamp: Utc::now(),
            tags: vec!["phishing".to_string()],
        }
    }

    #[tokio::test]
    async fn test_orchestrator_creation() {
        let orchestrator = Orchestrator::new();
        assert!(!orchestrator.is_running().await);
        assert_eq!(
            orchestrator.operation_mode().await,
            OperationMode::Supervised
        );
    }

    #[tokio::test]
    async fn test_process_alert() {
        let orchestrator = Orchestrator::new();
        let alert = create_test_alert();

        let incident_id = orchestrator.process_alert(alert).await.unwrap();

        let incident = orchestrator.get_incident(incident_id).await.unwrap();
        assert_eq!(incident.status, IncidentStatus::New);
        assert_eq!(incident.severity, Severity::High);
    }

    #[tokio::test]
    async fn test_transition_incident() {
        let orchestrator = Orchestrator::new();
        let alert = create_test_alert();

        let incident_id = orchestrator.process_alert(alert).await.unwrap();

        // Transition to Enriching
        orchestrator
            .transition_incident(incident_id, IncidentStatus::Enriching)
            .await
            .unwrap();

        let incident = orchestrator.get_incident(incident_id).await.unwrap();
        assert_eq!(incident.status, IncidentStatus::Enriching);
    }

    #[tokio::test]
    async fn test_kill_switch() {
        let orchestrator = Orchestrator::new();

        // Activate kill switch
        orchestrator.activate_kill_switch("Test", "test_user").await;

        assert!(orchestrator.is_kill_switch_active().await);

        // Should not be able to process alerts
        let alert = create_test_alert();
        let result = orchestrator.process_alert(alert).await;
        assert!(matches!(
            result,
            Err(OrchestratorError::KillSwitchActivated(_))
        ));

        // Deactivate and try again
        orchestrator.deactivate_kill_switch("test_user").await;
        assert!(!orchestrator.is_kill_switch_active().await);

        let alert = create_test_alert();
        let result = orchestrator.process_alert(alert).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_stats() {
        let orchestrator = Orchestrator::new();

        let alert1 = create_test_alert();
        let mut alert2 = create_test_alert();
        alert2.id = "test-alert-2".to_string();

        orchestrator.process_alert(alert1).await.unwrap();
        orchestrator.process_alert(alert2).await.unwrap();

        let stats = orchestrator.stats().await;
        assert_eq!(stats.alerts_received, 2);
        assert_eq!(stats.incidents_created, 2);
        assert_eq!(stats.incidents_in_progress, 2);
    }

    #[tokio::test]
    async fn test_operation_mode() {
        let orchestrator = Orchestrator::new();

        assert_eq!(
            orchestrator.operation_mode().await,
            OperationMode::Supervised
        );

        orchestrator
            .set_operation_mode(OperationMode::Assisted)
            .await;
        assert_eq!(orchestrator.operation_mode().await, OperationMode::Assisted);

        orchestrator
            .set_operation_mode(OperationMode::Autonomous)
            .await;
        assert_eq!(
            orchestrator.operation_mode().await,
            OperationMode::Autonomous
        );
    }

    #[tokio::test]
    async fn test_get_incidents_by_status() {
        let orchestrator = Orchestrator::new();

        let alert1 = create_test_alert();
        let mut alert2 = create_test_alert();
        alert2.id = "test-alert-2".to_string();

        let id1 = orchestrator.process_alert(alert1).await.unwrap();
        let _id2 = orchestrator.process_alert(alert2).await.unwrap();

        // Transition one to Enriching
        orchestrator
            .transition_incident(id1, IncidentStatus::Enriching)
            .await
            .unwrap();

        let new_incidents = orchestrator
            .get_incidents_by_status(IncidentStatus::New)
            .await;
        assert_eq!(new_incidents.len(), 1);

        let enriching_incidents = orchestrator
            .get_incidents_by_status(IncidentStatus::Enriching)
            .await;
        assert_eq!(enriching_incidents.len(), 1);
    }
}
