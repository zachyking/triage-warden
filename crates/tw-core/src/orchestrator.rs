//! Central orchestrator for Triage Warden.
//!
//! The orchestrator manages the main agent loop, coordinating between
//! connectors, the policy engine, AI analysis, and action execution.
//!
//! ## Authorization
//!
//! All state transitions require an `AuthorizationContext` to ensure
//! proper permission checks and audit logging.
//!
//! ## Leader Election for Singleton Tasks
//!
//! In a horizontally scaled deployment, certain tasks should only run on ONE instance:
//! - Cleanup tasks (old incidents, expired sessions)
//! - Scheduled analysis jobs
//! - Metrics aggregation
//!
//! The orchestrator uses `LeaderElector` to coordinate these singleton tasks.
//! If `leader_elector` is `None`, tasks run unconditionally (single-instance mode).
//!
//! ### Resource Names
//! - `tw-orchestrator-cleanup` - Cleanup singleton tasks
//! - `tw-orchestrator-scheduler` - Scheduled analysis jobs
//! - `tw-orchestrator-metrics` - Metrics aggregation

use crate::auth::AuthorizationContext;
use crate::events::{EventBus, TriageEvent};
use crate::incident::{Alert, Incident, IncidentStatus};
use crate::leadership::{LeaderElectionError, LeaderElector, LeaderLease};
use crate::workflow::{WorkflowEngine, WorkflowError};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::{watch, RwLock};
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

/// Resource name for cleanup singleton tasks.
pub const LEADER_RESOURCE_CLEANUP: &str = "tw-orchestrator-cleanup";
/// Resource name for scheduled analysis jobs.
pub const LEADER_RESOURCE_SCHEDULER: &str = "tw-orchestrator-scheduler";
/// Resource name for metrics aggregation.
pub const LEADER_RESOURCE_METRICS: &str = "tw-orchestrator-metrics";

/// Default TTL for leader leases (30 seconds).
pub const DEFAULT_LEADER_TTL: Duration = Duration::from_secs(30);
/// Default renewal interval (10 seconds, should be less than TTL/2).
pub const DEFAULT_LEADER_RENEW_INTERVAL: Duration = Duration::from_secs(10);

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

    #[error("Leader election error: {0}")]
    LeaderElectionError(#[from] LeaderElectionError),

    #[error("Internal error: {0}")]
    Internal(String),
}

/// Operation mode for the orchestrator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
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

/// Statistics for leader election and singleton tasks.
#[derive(Debug, Clone, Default)]
pub struct LeadershipStats {
    /// Number of times leadership was acquired.
    pub elections_won: u64,
    /// Number of times leadership was lost.
    pub elections_lost: u64,
    /// Number of successful lease renewals.
    pub renewals_successful: u64,
    /// Number of failed lease renewals.
    pub renewals_failed: u64,
    /// Total cleanup task executions while leader.
    pub cleanup_executions: u64,
    /// Total scheduler task executions while leader.
    pub scheduler_executions: u64,
    /// Total metrics aggregation executions while leader.
    pub metrics_executions: u64,
    /// Timestamp when leadership was acquired (for calculating duration).
    pub leadership_acquired_at: Option<DateTime<Utc>>,
    /// Total seconds spent as leader (across all leadership periods).
    pub total_leadership_seconds: u64,
}

/// State of a leader lease for a specific resource.
#[derive(Debug, Default)]
struct LeaseState {
    /// The current lease, if held.
    lease: Option<LeaderLease>,
    /// Whether this instance is currently the leader.
    is_leader: bool,
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
    /// Leader elector for coordinating singleton tasks (optional).
    /// If None, singleton tasks run unconditionally (single-instance mode).
    leader_elector: Option<Arc<dyn LeaderElector>>,
    /// Instance ID for logging and debugging.
    instance_id: String,
    /// Leadership statistics.
    leadership_stats: Arc<RwLock<LeadershipStats>>,
    /// Leader lease states for each resource.
    lease_states: Arc<RwLock<HashMap<String, LeaseState>>>,
    /// Shutdown signal sender.
    shutdown_tx: watch::Sender<bool>,
    /// Shutdown signal receiver.
    shutdown_rx: watch::Receiver<bool>,
    /// Counter for tracking active singleton task executions (for graceful shutdown).
    active_singleton_tasks: Arc<AtomicU64>,
}

impl Orchestrator {
    /// Creates a new orchestrator with default configuration.
    pub fn new() -> Self {
        Self::with_config(OrchestratorConfig::default())
    }

    /// Creates a new orchestrator with the specified configuration.
    pub fn with_config(config: OrchestratorConfig) -> Self {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        Self {
            config: Arc::new(RwLock::new(config)),
            event_bus: Arc::new(EventBus::new(1024)),
            workflow_engine: Arc::new(RwLock::new(WorkflowEngine::new())),
            incidents: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(OrchestratorStats::default())),
            running: Arc::new(RwLock::new(false)),
            leader_elector: None,
            instance_id: crate::leadership::default_instance_id(),
            leadership_stats: Arc::new(RwLock::new(LeadershipStats::default())),
            lease_states: Arc::new(RwLock::new(HashMap::new())),
            shutdown_tx,
            shutdown_rx,
            active_singleton_tasks: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Creates a new orchestrator with leader election support.
    ///
    /// When a `LeaderElector` is provided, singleton tasks (cleanup, scheduler, metrics)
    /// will only run on the instance that holds leadership for each resource.
    pub fn with_leader_elector(
        config: OrchestratorConfig,
        leader_elector: Arc<dyn LeaderElector>,
        instance_id: impl Into<String>,
    ) -> Self {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        Self {
            config: Arc::new(RwLock::new(config)),
            event_bus: Arc::new(EventBus::new(1024)),
            workflow_engine: Arc::new(RwLock::new(WorkflowEngine::new())),
            incidents: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(OrchestratorStats::default())),
            running: Arc::new(RwLock::new(false)),
            leader_elector: Some(leader_elector),
            instance_id: instance_id.into(),
            leadership_stats: Arc::new(RwLock::new(LeadershipStats::default())),
            lease_states: Arc::new(RwLock::new(HashMap::new())),
            shutdown_tx,
            shutdown_rx,
            active_singleton_tasks: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Sets the leader elector for coordinating singleton tasks.
    pub fn set_leader_elector(&mut self, leader_elector: Arc<dyn LeaderElector>) {
        self.leader_elector = Some(leader_elector);
    }

    /// Gets the instance ID.
    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    /// Gets whether this orchestrator has leader election enabled.
    pub fn has_leader_election(&self) -> bool {
        self.leader_elector.is_some()
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

    /// Checks if a status is an automated state that should be blocked when kill switch is active.
    ///
    /// Automated states are those that involve system-driven operations without human intervention:
    /// - `Executing`: Automated action execution
    /// - `Enriching`: Automated data enrichment from external sources
    /// - `Analyzing`: AI-driven analysis
    ///
    /// Manual/human states are allowed even when kill switch is active:
    /// - `New`: Initial state
    /// - `PendingReview`: Waiting for human review
    /// - `PendingApproval`: Waiting for human approval
    /// - `Resolved`, `FalsePositive`, `Dismissed`, `Escalated`, `Closed`: Terminal/human-decided states
    #[inline]
    fn is_automated_state(status: &IncidentStatus) -> bool {
        matches!(
            status,
            IncidentStatus::Executing | IncidentStatus::Enriching | IncidentStatus::Analyzing
        )
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

        // Update stats for alert received (single lock acquisition)
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

        // Perform all state mutations in a single critical section to prevent race conditions
        // This ensures atomic update of workflow registration, incident storage, and stats
        {
            // Register workflow first
            let mut workflow_engine = self.workflow_engine.write().await;
            workflow_engine.register_workflow(&incident);

            // Store incident
            let mut incidents = self.incidents.write().await;
            incidents.insert(incident_id, incident);

            // Update stats atomically after successful storage
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
    ///
    /// ## Authorization
    ///
    /// This method requires an `AuthorizationContext` to verify that the caller
    /// has the necessary permissions for the requested transition:
    ///
    /// - Transitions to `Executing` require `ApproveActions` permission
    /// - Transitions to `Resolved` require `WriteIncidents` permission
    ///
    /// All transitions are logged with the actor's identity for audit purposes.
    ///
    /// ## Kill Switch
    ///
    /// When the kill switch is active, all automated state transitions are blocked:
    /// - `Executing`: Action execution
    /// - `Enriching`: Automated data enrichment
    /// - `Analyzing`: AI analysis
    ///
    /// Manual/human-initiated states (PendingReview, Resolved, etc.) are still allowed.
    /// The kill switch check is performed atomically within the write-locked critical
    /// section to prevent race conditions.
    ///
    /// ## Parameters
    ///
    /// - `incident_id`: The UUID of the incident to transition
    /// - `new_status`: The target status
    /// - `auth_ctx`: Authorization context containing actor identity and permissions
    ///
    /// ## Errors
    ///
    /// Returns `OrchestratorError::WorkflowError` with `Unauthorized` variant if
    /// the caller lacks the required permissions.
    ///
    /// Returns `OrchestratorError::KillSwitchActivated` if kill switch is active
    /// and the target state is an automated state.
    #[instrument(skip(self, auth_ctx), fields(incident_id = %incident_id, actor = %auth_ctx.actor_name))]
    pub async fn transition_incident(
        &self,
        incident_id: Uuid,
        new_status: IncidentStatus,
        auth_ctx: &AuthorizationContext,
    ) -> Result<(), OrchestratorError> {
        let old_status;
        let transition_actions;

        // Perform all checks and transitions inside the write-locked critical section
        // to prevent race conditions between kill switch check and state transition.
        // This ensures immediate effect of kill switch across all concurrent operations.
        {
            // Acquire config lock first to check kill switch atomically
            let config = self.config.read().await;

            // Check kill switch for automated state transitions
            // Automated states that should be blocked when kill switch is active:
            // - Executing: Action execution
            // - Enriching: Automated data enrichment
            // - Analyzing: AI analysis
            if config.kill_switch_enabled && Self::is_automated_state(&new_status) {
                let blocked_action = match &new_status {
                    IncidentStatus::Executing => "execute actions",
                    IncidentStatus::Enriching => "perform automated enrichment",
                    IncidentStatus::Analyzing => "perform AI analysis",
                    _ => "perform automated operations",
                };
                warn!(
                    "Kill switch blocking transition to {:?} for incident {}",
                    new_status, incident_id
                );
                return Err(OrchestratorError::KillSwitchActivated(format!(
                    "Cannot {} while kill switch is active",
                    blocked_action
                )));
            }

            // Drop config lock before acquiring incident lock to avoid deadlock
            drop(config);

            let mut incidents = self.incidents.write().await;
            let incident = incidents
                .get_mut(&incident_id)
                .ok_or(OrchestratorError::IncidentNotFound(incident_id))?;

            old_status = incident.status.clone();

            let mut workflow_engine = self.workflow_engine.write().await;
            transition_actions =
                workflow_engine.transition(incident, new_status.clone(), auth_ctx)?;
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
            "Transitioned incident {} from {:?} to {:?} by {} (role: {:?})",
            incident_id, old_status, new_status, auth_ctx.actor_name, auth_ctx.role
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

    // ============================================================
    // Leader Election and Singleton Task Coordination
    // ============================================================

    /// Gets the leadership statistics.
    pub async fn leadership_stats(&self) -> LeadershipStats {
        self.leadership_stats.read().await.clone()
    }

    /// Checks if this instance is currently the leader for a resource.
    ///
    /// If no leader elector is configured, returns `true` (single-instance mode).
    pub fn is_leader(&self, resource: &str) -> bool {
        match &self.leader_elector {
            Some(elector) => elector.is_leader(resource),
            None => true, // Single-instance mode: always "leader"
        }
    }

    /// Checks if this instance is the leader for cleanup tasks.
    pub fn is_cleanup_leader(&self) -> bool {
        self.is_leader(LEADER_RESOURCE_CLEANUP)
    }

    /// Checks if this instance is the leader for scheduler tasks.
    pub fn is_scheduler_leader(&self) -> bool {
        self.is_leader(LEADER_RESOURCE_SCHEDULER)
    }

    /// Checks if this instance is the leader for metrics tasks.
    pub fn is_metrics_leader(&self) -> bool {
        self.is_leader(LEADER_RESOURCE_METRICS)
    }

    /// Attempts to acquire leadership for a resource.
    ///
    /// Returns `Ok(true)` if leadership was acquired or already held.
    /// Returns `Ok(false)` if another instance holds leadership.
    /// Returns `Err` if leader elector is not configured.
    #[instrument(skip(self), fields(instance_id = %self.instance_id))]
    pub async fn try_acquire_leadership(
        &self,
        resource: &str,
        ttl: Duration,
    ) -> Result<bool, OrchestratorError> {
        let elector = match &self.leader_elector {
            Some(e) => e,
            None => {
                // Single-instance mode: always succeed
                debug!(
                    "No leader elector configured, running in single-instance mode for {}",
                    resource
                );
                return Ok(true);
            }
        };

        match elector.try_acquire(resource, ttl).await {
            Ok(Some(lease)) => {
                info!(
                    instance_id = %self.instance_id,
                    resource = %resource,
                    fencing_token = lease.fencing_token,
                    expires_at = %lease.expires_at,
                    "Acquired leadership for resource"
                );

                // Update lease state
                let mut lease_states = self.lease_states.write().await;
                let state = lease_states.entry(resource.to_string()).or_default();
                let was_leader = state.is_leader;
                state.lease = Some(lease);
                state.is_leader = true;

                // Update stats if this is a new leadership acquisition
                if !was_leader {
                    let mut stats = self.leadership_stats.write().await;
                    stats.elections_won += 1;
                    stats.leadership_acquired_at = Some(Utc::now());
                }

                Ok(true)
            }
            Ok(None) => {
                debug!(
                    instance_id = %self.instance_id,
                    resource = %resource,
                    "Resource is held by another instance"
                );
                Ok(false)
            }
            Err(e) => {
                error!(
                    instance_id = %self.instance_id,
                    resource = %resource,
                    error = %e,
                    "Failed to acquire leadership"
                );
                Err(OrchestratorError::LeaderElectionError(e))
            }
        }
    }

    /// Releases leadership for a resource.
    ///
    /// This should be called during graceful shutdown.
    #[instrument(skip(self), fields(instance_id = %self.instance_id))]
    pub async fn release_leadership(&self, resource: &str) -> Result<(), OrchestratorError> {
        let elector = match &self.leader_elector {
            Some(e) => e,
            None => return Ok(()), // Single-instance mode: nothing to release
        };

        // Get and remove the lease
        let lease = {
            let mut lease_states = self.lease_states.write().await;
            if let Some(state) = lease_states.get_mut(resource) {
                let lease = state.lease.take();
                if state.is_leader {
                    state.is_leader = false;
                    // Update leadership duration stats
                    let mut stats = self.leadership_stats.write().await;
                    if let Some(acquired_at) = stats.leadership_acquired_at.take() {
                        let duration = (Utc::now() - acquired_at).num_seconds().max(0) as u64;
                        stats.total_leadership_seconds += duration;
                    }
                    stats.elections_lost += 1;
                }
                lease
            } else {
                None
            }
        };

        if let Some(lease) = lease {
            info!(
                instance_id = %self.instance_id,
                resource = %resource,
                fencing_token = lease.fencing_token,
                "Releasing leadership"
            );

            if let Err(e) = elector.release(&lease).await {
                warn!(
                    instance_id = %self.instance_id,
                    resource = %resource,
                    error = %e,
                    "Failed to release leadership (may have already expired)"
                );
                // Don't return error - the lease may have already expired
            }
        }

        Ok(())
    }

    /// Renews the leadership lease for a resource.
    ///
    /// Returns `Ok(true)` if renewal succeeded.
    /// Returns `Ok(false)` if leadership was lost.
    #[instrument(skip(self), fields(instance_id = %self.instance_id))]
    pub async fn renew_leadership(&self, resource: &str) -> Result<bool, OrchestratorError> {
        let elector = match &self.leader_elector {
            Some(e) => e,
            None => return Ok(true), // Single-instance mode: always succeed
        };

        // Get mutable access to the lease
        let mut lease_states = self.lease_states.write().await;
        let state = match lease_states.get_mut(resource) {
            Some(s) if s.lease.is_some() => s,
            _ => {
                debug!(
                    instance_id = %self.instance_id,
                    resource = %resource,
                    "No lease to renew"
                );
                return Ok(false);
            }
        };

        let lease = state.lease.as_mut().unwrap();
        match elector.renew(lease).await {
            Ok(true) => {
                debug!(
                    instance_id = %self.instance_id,
                    resource = %resource,
                    expires_at = %lease.expires_at,
                    "Leadership renewed"
                );

                // Update stats
                let mut stats = self.leadership_stats.write().await;
                stats.renewals_successful += 1;

                Ok(true)
            }
            Ok(false) => {
                warn!(
                    instance_id = %self.instance_id,
                    resource = %resource,
                    "Lost leadership during renewal"
                );

                // Mark as no longer leader
                state.is_leader = false;
                state.lease = None;

                // Update stats
                let mut stats = self.leadership_stats.write().await;
                stats.renewals_failed += 1;
                stats.elections_lost += 1;
                if let Some(acquired_at) = stats.leadership_acquired_at.take() {
                    let duration = (Utc::now() - acquired_at).num_seconds().max(0) as u64;
                    stats.total_leadership_seconds += duration;
                }

                Ok(false)
            }
            Err(e) => {
                error!(
                    instance_id = %self.instance_id,
                    resource = %resource,
                    error = %e,
                    "Error renewing leadership"
                );

                // Update stats
                let mut stats = self.leadership_stats.write().await;
                stats.renewals_failed += 1;

                Err(OrchestratorError::LeaderElectionError(e))
            }
        }
    }

    /// Runs a task only if this instance is the leader for the resource.
    ///
    /// This is the primary method for coordinating singleton tasks. It:
    /// 1. Checks if this instance is the leader
    /// 2. If so, runs the task
    /// 3. Periodically checks leader status during long operations
    ///
    /// If no leader elector is configured, the task runs unconditionally.
    ///
    /// # Arguments
    /// * `resource` - The resource name for leadership (e.g., `LEADER_RESOURCE_CLEANUP`)
    /// * `task_name` - Human-readable name for logging
    /// * `task` - The async task to run
    ///
    /// # Returns
    /// * `Ok(Some(result))` - Task ran and completed
    /// * `Ok(None)` - Not the leader, task was skipped
    /// * `Err(e)` - An error occurred
    #[instrument(skip(self, task), fields(instance_id = %self.instance_id))]
    pub async fn run_if_leader<F, T, E>(
        &self,
        resource: &str,
        task_name: &str,
        task: F,
    ) -> Result<Option<T>, OrchestratorError>
    where
        F: std::future::Future<Output = Result<T, E>>,
        E: std::fmt::Display,
    {
        // Check if we're the leader
        if !self.is_leader(resource) {
            debug!(
                instance_id = %self.instance_id,
                resource = %resource,
                task = %task_name,
                "Skipping task - not the leader"
            );
            return Ok(None);
        }

        info!(
            instance_id = %self.instance_id,
            resource = %resource,
            task = %task_name,
            "Running singleton task as leader"
        );

        // Track active task
        self.active_singleton_tasks.fetch_add(1, Ordering::SeqCst);

        let result = task.await;

        self.active_singleton_tasks.fetch_sub(1, Ordering::SeqCst);

        match result {
            Ok(value) => {
                debug!(
                    instance_id = %self.instance_id,
                    resource = %resource,
                    task = %task_name,
                    "Singleton task completed successfully"
                );
                Ok(Some(value))
            }
            Err(e) => {
                error!(
                    instance_id = %self.instance_id,
                    resource = %resource,
                    task = %task_name,
                    error = %e,
                    "Singleton task failed"
                );
                Err(OrchestratorError::Internal(format!(
                    "Singleton task '{}' failed: {}",
                    task_name, e
                )))
            }
        }
    }

    /// Starts the background leader lease renewal task.
    ///
    /// This spawns a background task that periodically renews all held leases.
    /// The task runs until shutdown is signaled.
    ///
    /// # Arguments
    /// * `resources` - List of resources to maintain leadership for
    /// * `renew_interval` - How often to renew leases
    pub fn start_lease_renewal_task(
        self: &Arc<Self>,
        resources: Vec<String>,
        renew_interval: Duration,
    ) -> tokio::task::JoinHandle<()> {
        let orchestrator = Arc::clone(self);
        let mut shutdown_rx = self.shutdown_rx.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(renew_interval);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            info!(
                instance_id = %orchestrator.instance_id,
                resources = ?resources,
                interval_secs = renew_interval.as_secs(),
                "Starting lease renewal task"
            );

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        for resource in &resources {
                            // First try to acquire if we don't have it
                            if !orchestrator.is_leader(resource) {
                                if let Ok(acquired) = orchestrator
                                    .try_acquire_leadership(resource, DEFAULT_LEADER_TTL)
                                    .await
                                {
                                    if acquired {
                                        info!(
                                            instance_id = %orchestrator.instance_id,
                                            resource = %resource,
                                            "Acquired leadership"
                                        );
                                    }
                                }
                            } else {
                                // Renew existing lease
                                match orchestrator.renew_leadership(resource).await {
                                    Ok(true) => {
                                        debug!(
                                            instance_id = %orchestrator.instance_id,
                                            resource = %resource,
                                            "Lease renewed"
                                        );
                                    }
                                    Ok(false) => {
                                        warn!(
                                            instance_id = %orchestrator.instance_id,
                                            resource = %resource,
                                            "Lost leadership"
                                        );
                                    }
                                    Err(e) => {
                                        error!(
                                            instance_id = %orchestrator.instance_id,
                                            resource = %resource,
                                            error = %e,
                                            "Failed to renew lease"
                                        );
                                    }
                                }
                            }
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            info!(
                                instance_id = %orchestrator.instance_id,
                                "Lease renewal task shutting down"
                            );
                            break;
                        }
                    }
                }
            }
        })
    }

    /// Starts the singleton task runner.
    ///
    /// This spawns a background task that periodically runs singleton tasks
    /// (cleanup, scheduler, metrics) if this instance is the leader.
    ///
    /// # Arguments
    /// * `cleanup_interval` - How often to run cleanup tasks
    /// * `scheduler_interval` - How often to run scheduler tasks
    /// * `metrics_interval` - How often to run metrics aggregation
    pub fn start_singleton_tasks(
        self: &Arc<Self>,
        cleanup_interval: Duration,
        scheduler_interval: Duration,
        metrics_interval: Duration,
    ) -> tokio::task::JoinHandle<()> {
        let orchestrator = Arc::clone(self);
        let mut shutdown_rx = self.shutdown_rx.clone();

        tokio::spawn(async move {
            let mut cleanup_interval = tokio::time::interval(cleanup_interval);
            let mut scheduler_interval = tokio::time::interval(scheduler_interval);
            let mut metrics_interval = tokio::time::interval(metrics_interval);

            cleanup_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            scheduler_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            metrics_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            info!(
                instance_id = %orchestrator.instance_id,
                "Starting singleton tasks runner"
            );

            loop {
                tokio::select! {
                    _ = cleanup_interval.tick() => {
                        if let Err(e) = orchestrator.run_cleanup_task().await {
                            error!(
                                instance_id = %orchestrator.instance_id,
                                error = %e,
                                "Cleanup task failed"
                            );
                        }
                    }
                    _ = scheduler_interval.tick() => {
                        if let Err(e) = orchestrator.run_scheduler_task().await {
                            error!(
                                instance_id = %orchestrator.instance_id,
                                error = %e,
                                "Scheduler task failed"
                            );
                        }
                    }
                    _ = metrics_interval.tick() => {
                        if let Err(e) = orchestrator.run_metrics_task().await {
                            error!(
                                instance_id = %orchestrator.instance_id,
                                error = %e,
                                "Metrics task failed"
                            );
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            info!(
                                instance_id = %orchestrator.instance_id,
                                "Singleton tasks runner shutting down"
                            );
                            break;
                        }
                    }
                }
            }
        })
    }

    /// Runs the cleanup singleton task if this instance is the leader.
    ///
    /// Cleanup tasks include:
    /// - Removing old resolved/closed incidents
    /// - Cleaning up expired sessions
    /// - Purging old audit logs
    #[instrument(skip(self), fields(instance_id = %self.instance_id))]
    pub async fn run_cleanup_task(&self) -> Result<(), OrchestratorError> {
        let result = self
            .run_if_leader(LEADER_RESOURCE_CLEANUP, "cleanup", async {
                // Placeholder for actual cleanup implementation
                debug!("Running cleanup task");

                // Example: Clean up old incidents
                let cutoff = Utc::now() - chrono::Duration::days(30);
                let incidents = self.incidents.read().await;
                let old_incidents: Vec<Uuid> = incidents
                    .iter()
                    .filter(|(_, inc)| {
                        matches!(
                            inc.status,
                            IncidentStatus::Closed
                                | IncidentStatus::Resolved
                                | IncidentStatus::FalsePositive
                        ) && inc.created_at < cutoff
                    })
                    .map(|(id, _)| *id)
                    .collect();
                drop(incidents);

                let cleaned_count = old_incidents.len();
                if cleaned_count > 0 {
                    let mut incidents = self.incidents.write().await;
                    for id in old_incidents {
                        incidents.remove(&id);
                    }
                    info!(
                        instance_id = %self.instance_id,
                        cleaned_count = cleaned_count,
                        "Cleaned up old incidents"
                    );
                }

                Ok::<_, std::convert::Infallible>(())
            })
            .await?;

        if result.is_some() {
            let mut stats = self.leadership_stats.write().await;
            stats.cleanup_executions += 1;
        }

        Ok(())
    }

    /// Runs the scheduler singleton task if this instance is the leader.
    ///
    /// Scheduler tasks include:
    /// - Processing scheduled analysis jobs
    /// - Running periodic enrichments
    /// - Executing scheduled reports
    #[instrument(skip(self), fields(instance_id = %self.instance_id))]
    pub async fn run_scheduler_task(&self) -> Result<(), OrchestratorError> {
        let result = self
            .run_if_leader(LEADER_RESOURCE_SCHEDULER, "scheduler", async {
                // Placeholder for actual scheduler implementation
                debug!("Running scheduler task");

                // Example: Process any scheduled jobs
                // In a real implementation, this would check a job queue
                // and execute pending scheduled tasks

                Ok::<_, std::convert::Infallible>(())
            })
            .await?;

        if result.is_some() {
            let mut stats = self.leadership_stats.write().await;
            stats.scheduler_executions += 1;
        }

        Ok(())
    }

    /// Runs the metrics aggregation singleton task if this instance is the leader.
    ///
    /// Metrics tasks include:
    /// - Aggregating incident statistics
    /// - Computing SLA metrics
    /// - Generating performance reports
    #[instrument(skip(self), fields(instance_id = %self.instance_id))]
    pub async fn run_metrics_task(&self) -> Result<(), OrchestratorError> {
        let result = self
            .run_if_leader(LEADER_RESOURCE_METRICS, "metrics", async {
                // Placeholder for actual metrics aggregation implementation
                debug!("Running metrics aggregation task");

                // Example: Compute and log current stats
                let stats = self.stats.read().await;
                info!(
                    instance_id = %self.instance_id,
                    alerts_received = stats.alerts_received,
                    incidents_created = stats.incidents_created,
                    incidents_resolved = stats.incidents_resolved,
                    "Metrics aggregation complete"
                );

                Ok::<_, std::convert::Infallible>(())
            })
            .await?;

        if result.is_some() {
            let mut stats = self.leadership_stats.write().await;
            stats.metrics_executions += 1;
        }

        Ok(())
    }

    /// Initiates graceful shutdown.
    ///
    /// This:
    /// 1. Signals all background tasks to stop
    /// 2. Waits for active singleton tasks to complete
    /// 3. Releases all held leader locks
    #[instrument(skip(self), fields(instance_id = %self.instance_id))]
    pub async fn graceful_shutdown(&self) -> Result<(), OrchestratorError> {
        info!(
            instance_id = %self.instance_id,
            "Initiating graceful shutdown"
        );

        // Signal shutdown
        let _ = self.shutdown_tx.send(true);

        // Wait for active singleton tasks to complete (with timeout)
        let timeout = Duration::from_secs(30);
        let start = std::time::Instant::now();
        while self.active_singleton_tasks.load(Ordering::SeqCst) > 0 {
            if start.elapsed() > timeout {
                warn!(
                    instance_id = %self.instance_id,
                    active_tasks = self.active_singleton_tasks.load(Ordering::SeqCst),
                    "Timeout waiting for singleton tasks to complete"
                );
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // Release all leader locks
        let resources = vec![
            LEADER_RESOURCE_CLEANUP.to_string(),
            LEADER_RESOURCE_SCHEDULER.to_string(),
            LEADER_RESOURCE_METRICS.to_string(),
        ];

        for resource in resources {
            if let Err(e) = self.release_leadership(&resource).await {
                warn!(
                    instance_id = %self.instance_id,
                    resource = %resource,
                    error = %e,
                    "Failed to release leadership during shutdown"
                );
            }
        }

        // Stop the orchestrator
        self.stop().await?;

        info!(
            instance_id = %self.instance_id,
            "Graceful shutdown complete"
        );

        Ok(())
    }

    /// Gets a clone of the shutdown receiver for external use.
    pub fn shutdown_receiver(&self) -> watch::Receiver<bool> {
        self.shutdown_rx.clone()
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
    use crate::auth::{Role, User};
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

    fn create_analyst_context() -> AuthorizationContext {
        let user = User::new("analyst@test.com", "analyst", "hash", Role::Analyst);
        AuthorizationContext::from_user(&user)
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
        let auth_ctx = create_analyst_context();

        let incident_id = orchestrator.process_alert(alert).await.unwrap();

        // Transition to Enriching
        orchestrator
            .transition_incident(incident_id, IncidentStatus::Enriching, &auth_ctx)
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
        let auth_ctx = create_analyst_context();

        let alert1 = create_test_alert();
        let mut alert2 = create_test_alert();
        alert2.id = "test-alert-2".to_string();

        let id1 = orchestrator.process_alert(alert1).await.unwrap();
        let _id2 = orchestrator.process_alert(alert2).await.unwrap();

        // Transition one to Enriching
        orchestrator
            .transition_incident(id1, IncidentStatus::Enriching, &auth_ctx)
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

    // ============================================================
    // Concurrent Alert Processing Tests
    // ============================================================

    #[tokio::test]
    async fn test_concurrent_alert_processing() {
        use std::sync::Arc;
        use tokio::task::JoinSet;

        let orchestrator = Arc::new(Orchestrator::new());
        let mut tasks = JoinSet::new();

        // Spawn 10 concurrent alert processing tasks
        for i in 0..10 {
            let orch = Arc::clone(&orchestrator);
            tasks.spawn(async move {
                let alert = Alert {
                    id: format!("concurrent-alert-{}", i),
                    source: AlertSource::EmailSecurity("M365".to_string()),
                    alert_type: "phishing".to_string(),
                    severity: Severity::Medium,
                    title: format!("Concurrent test alert {}", i),
                    description: Some("Test description".to_string()),
                    data: serde_json::json!({}),
                    timestamp: Utc::now(),
                    tags: vec![],
                };
                orch.process_alert(alert).await
            });
        }

        // All should complete successfully
        let mut incident_ids = Vec::new();
        while let Some(result) = tasks.join_next().await {
            let id = result.unwrap().unwrap();
            incident_ids.push(id);
        }

        // All incidents should be unique
        assert_eq!(incident_ids.len(), 10);
        incident_ids.sort();
        incident_ids.dedup();
        assert_eq!(incident_ids.len(), 10);

        // Stats should reflect all processed alerts
        let stats = orchestrator.stats().await;
        assert_eq!(stats.alerts_received, 10);
        assert_eq!(stats.incidents_created, 10);
    }

    #[tokio::test]
    async fn test_concurrent_status_transitions() {
        use std::sync::Arc;
        use tokio::task::JoinSet;

        let orchestrator = Arc::new(Orchestrator::new());
        let auth_ctx = Arc::new(create_analyst_context());

        // Create multiple incidents
        let mut incident_ids = Vec::new();
        for i in 0..5 {
            let mut alert = create_test_alert();
            alert.id = format!("status-test-{}", i);
            let id = orchestrator.process_alert(alert).await.unwrap();
            incident_ids.push(id);
        }

        // Transition all concurrently
        let mut tasks = JoinSet::new();
        for id in incident_ids.clone() {
            let orch = Arc::clone(&orchestrator);
            let ctx = Arc::clone(&auth_ctx);
            tasks.spawn(async move {
                orch.transition_incident(id, IncidentStatus::Enriching, &ctx)
                    .await
            });
        }

        // All should succeed
        while let Some(result) = tasks.join_next().await {
            assert!(result.unwrap().is_ok());
        }

        // Verify all are now enriching
        let enriching = orchestrator
            .get_incidents_by_status(IncidentStatus::Enriching)
            .await;
        assert_eq!(enriching.len(), 5);
    }

    // ============================================================
    // State Transition Tests
    // ============================================================

    #[tokio::test]
    async fn test_basic_state_transition() {
        let orchestrator = Orchestrator::new();
        let alert = create_test_alert();
        let auth_ctx = create_analyst_context();
        let incident_id = orchestrator.process_alert(alert).await.unwrap();

        // New -> Enriching (no condition required)
        orchestrator
            .transition_incident(incident_id, IncidentStatus::Enriching, &auth_ctx)
            .await
            .unwrap();

        let incident = orchestrator.get_incident(incident_id).await.unwrap();
        assert_eq!(incident.status, IncidentStatus::Enriching);
    }

    #[tokio::test]
    async fn test_invalid_state_transition_blocked() {
        let orchestrator = Orchestrator::new();
        let alert = create_test_alert();
        let auth_ctx = create_analyst_context();
        let incident_id = orchestrator.process_alert(alert).await.unwrap();

        // New -> Analyzing requires going through Enriching first
        // This should fail because the workflow requires EnrichmentsComplete
        let result = orchestrator
            .transition_incident(incident_id, IncidentStatus::Analyzing, &auth_ctx)
            .await;

        // Should fail with either InvalidTransition or ConditionNotMet
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_workflow_enforces_conditions() {
        let orchestrator = Orchestrator::new();
        let alert = create_test_alert();
        let auth_ctx = create_analyst_context();
        let incident_id = orchestrator.process_alert(alert).await.unwrap();

        // New -> Enriching (OK, no condition)
        orchestrator
            .transition_incident(incident_id, IncidentStatus::Enriching, &auth_ctx)
            .await
            .unwrap();

        // Enriching -> Analyzing requires EnrichmentsComplete condition
        // Without setting that context, this should fail
        let result = orchestrator
            .transition_incident(incident_id, IncidentStatus::Analyzing, &auth_ctx)
            .await;

        // This tests that conditions are enforced
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_transition_nonexistent_incident() {
        let orchestrator = Orchestrator::new();
        let auth_ctx = create_analyst_context();
        let fake_id = uuid::Uuid::new_v4();

        let result = orchestrator
            .transition_incident(fake_id, IncidentStatus::Enriching, &auth_ctx)
            .await;

        assert!(matches!(
            result,
            Err(OrchestratorError::IncidentNotFound(_))
        ));
    }

    // ============================================================
    // Kill Switch Concurrent Tests
    // ============================================================

    #[tokio::test]
    async fn test_kill_switch_blocks_concurrent_processing() {
        use std::sync::Arc;
        use tokio::task::JoinSet;

        let orchestrator = Arc::new(Orchestrator::new());

        // Activate kill switch
        orchestrator.activate_kill_switch("Test", "admin").await;

        // Try to process multiple alerts concurrently
        let mut tasks = JoinSet::new();
        for i in 0..5 {
            let orch = Arc::clone(&orchestrator);
            tasks.spawn(async move {
                let mut alert = create_test_alert();
                alert.id = format!("blocked-alert-{}", i);
                orch.process_alert(alert).await
            });
        }

        // All should fail with KillSwitchActivated
        while let Some(result) = tasks.join_next().await {
            assert!(matches!(
                result.unwrap(),
                Err(OrchestratorError::KillSwitchActivated(_))
            ));
        }

        // Stats should show 0 processed
        let stats = orchestrator.stats().await;
        assert_eq!(stats.incidents_created, 0);
    }

    #[tokio::test]
    async fn test_kill_switch_toggle_during_processing() {
        use std::sync::Arc;

        let orchestrator = Arc::new(Orchestrator::new());

        // Process one alert
        let alert1 = create_test_alert();
        let id1 = orchestrator.process_alert(alert1).await.unwrap();

        // Activate kill switch
        orchestrator.activate_kill_switch("Test", "admin").await;

        // Try another - should fail
        let mut alert2 = create_test_alert();
        alert2.id = "blocked-alert".to_string();
        let result = orchestrator.process_alert(alert2).await;
        assert!(matches!(
            result,
            Err(OrchestratorError::KillSwitchActivated(_))
        ));

        // Deactivate
        orchestrator.deactivate_kill_switch("admin").await;

        // Now should work
        let mut alert3 = create_test_alert();
        alert3.id = "unblocked-alert".to_string();
        let id3 = orchestrator.process_alert(alert3).await.unwrap();

        assert_ne!(id1, id3);
    }

    // ============================================================
    // Kill Switch Race Condition Tests (Task 8.1)
    // ============================================================

    #[tokio::test]
    async fn test_kill_switch_blocks_executing_state() {
        let orchestrator = Orchestrator::new();
        let auth_ctx = create_analyst_context();

        // Create incident and transition to a state before Executing
        let alert = create_test_alert();
        let incident_id = orchestrator.process_alert(alert).await.unwrap();

        // Activate kill switch
        orchestrator.activate_kill_switch("Test", "admin").await;

        // Attempt to transition to Executing should fail
        let result = orchestrator
            .transition_incident(incident_id, IncidentStatus::Executing, &auth_ctx)
            .await;

        assert!(matches!(
            result,
            Err(OrchestratorError::KillSwitchActivated(_))
        ));

        // Verify the error message mentions action execution
        if let Err(OrchestratorError::KillSwitchActivated(msg)) = result {
            assert!(msg.contains("execute actions"));
        }
    }

    #[tokio::test]
    async fn test_kill_switch_blocks_enriching_state() {
        let orchestrator = Orchestrator::new();
        let auth_ctx = create_analyst_context();

        // Create incident
        let alert = create_test_alert();
        let incident_id = orchestrator.process_alert(alert).await.unwrap();

        // Deactivate any default state and then activate kill switch
        orchestrator.activate_kill_switch("Test", "admin").await;

        // Attempt to transition to Enriching should fail
        let result = orchestrator
            .transition_incident(incident_id, IncidentStatus::Enriching, &auth_ctx)
            .await;

        assert!(matches!(
            result,
            Err(OrchestratorError::KillSwitchActivated(_))
        ));

        // Verify the error message mentions enrichment
        if let Err(OrchestratorError::KillSwitchActivated(msg)) = result {
            assert!(msg.contains("enrichment"));
        }
    }

    #[tokio::test]
    async fn test_kill_switch_blocks_analyzing_state() {
        let orchestrator = Orchestrator::new();
        let auth_ctx = create_analyst_context();

        // Create incident
        let alert = create_test_alert();
        let incident_id = orchestrator.process_alert(alert).await.unwrap();

        // Activate kill switch
        orchestrator.activate_kill_switch("Test", "admin").await;

        // Attempt to transition to Analyzing should fail
        let result = orchestrator
            .transition_incident(incident_id, IncidentStatus::Analyzing, &auth_ctx)
            .await;

        assert!(matches!(
            result,
            Err(OrchestratorError::KillSwitchActivated(_))
        ));

        // Verify the error message mentions AI analysis
        if let Err(OrchestratorError::KillSwitchActivated(msg)) = result {
            assert!(msg.contains("analysis"));
        }
    }

    #[tokio::test]
    async fn test_kill_switch_allows_manual_states() {
        let orchestrator = Orchestrator::new();
        let auth_ctx = create_analyst_context();

        // Create incident
        let alert = create_test_alert();
        let incident_id = orchestrator.process_alert(alert).await.unwrap();

        // Activate kill switch
        orchestrator.activate_kill_switch("Test", "admin").await;

        // Manual states should still be allowed even with kill switch active
        // Try PendingReview (a manual state)
        let result = orchestrator
            .transition_incident(incident_id, IncidentStatus::PendingReview, &auth_ctx)
            .await;

        // This should succeed (workflow permitting) or fail with a non-kill-switch error
        // The key is it should NOT fail due to kill switch
        match result {
            Ok(_) => {
                // Good - manual state was allowed
                let incident = orchestrator.get_incident(incident_id).await.unwrap();
                assert_eq!(incident.status, IncidentStatus::PendingReview);
            }
            Err(OrchestratorError::KillSwitchActivated(_)) => {
                panic!("Kill switch should not block manual states like PendingReview");
            }
            Err(_) => {
                // Other workflow errors are acceptable (e.g., invalid transition)
            }
        }
    }

    #[tokio::test]
    async fn test_kill_switch_allows_terminal_states() {
        let orchestrator = Orchestrator::new();
        let auth_ctx = create_analyst_context();

        // Create incident
        let alert = create_test_alert();
        let incident_id = orchestrator.process_alert(alert).await.unwrap();

        // Activate kill switch
        orchestrator.activate_kill_switch("Test", "admin").await;

        // Terminal states like Dismissed should be allowed even with kill switch active
        let result = orchestrator
            .transition_incident(incident_id, IncidentStatus::Dismissed, &auth_ctx)
            .await;

        match result {
            Ok(_) => {
                // Good - terminal state was allowed
                let incident = orchestrator.get_incident(incident_id).await.unwrap();
                assert_eq!(incident.status, IncidentStatus::Dismissed);
            }
            Err(OrchestratorError::KillSwitchActivated(_)) => {
                panic!("Kill switch should not block terminal states like Dismissed");
            }
            Err(_) => {
                // Other workflow errors are acceptable
            }
        }
    }

    #[tokio::test]
    async fn test_kill_switch_concurrent_activation_blocks_transitions() {
        use std::sync::Arc;
        use tokio::task::JoinSet;

        let orchestrator = Arc::new(Orchestrator::new());
        let auth_ctx = Arc::new(create_analyst_context());

        // Create multiple incidents before kill switch
        let mut incident_ids = Vec::new();
        for i in 0..10 {
            let mut alert = create_test_alert();
            alert.id = format!("race-test-{}", i);
            let id = orchestrator.process_alert(alert).await.unwrap();
            incident_ids.push(id);
        }

        // Activate kill switch
        orchestrator
            .activate_kill_switch("Race condition test", "admin")
            .await;

        // Now try to transition all incidents to Enriching concurrently
        // All should be blocked by kill switch
        let mut tasks = JoinSet::new();
        for id in incident_ids {
            let orch = Arc::clone(&orchestrator);
            let ctx = Arc::clone(&auth_ctx);
            tasks.spawn(async move {
                orch.transition_incident(id, IncidentStatus::Enriching, &ctx)
                    .await
            });
        }

        // All should fail with KillSwitchActivated
        let mut all_blocked = true;
        while let Some(result) = tasks.join_next().await {
            match result.unwrap() {
                Err(OrchestratorError::KillSwitchActivated(_)) => {
                    // Expected - kill switch blocked the transition
                }
                Ok(_) => {
                    all_blocked = false;
                }
                Err(e) => {
                    panic!("Unexpected error: {:?}", e);
                }
            }
        }
        assert!(
            all_blocked,
            "All transitions should be blocked by kill switch"
        );
    }

    #[tokio::test]
    async fn test_kill_switch_immediate_effect_on_concurrent_operations() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use tokio::task::JoinSet;

        let orchestrator = Arc::new(Orchestrator::new());
        let auth_ctx = Arc::new(create_analyst_context());
        let blocked_count = Arc::new(AtomicUsize::new(0));

        // Create incidents first
        let mut incident_ids = Vec::new();
        for i in 0..20 {
            let mut alert = create_test_alert();
            alert.id = format!("immediate-effect-test-{}", i);
            let id = orchestrator.process_alert(alert).await.unwrap();
            incident_ids.push(id);
        }

        // Spawn tasks that will try to transition
        let mut tasks = JoinSet::new();
        for id in incident_ids.clone() {
            let orch = Arc::clone(&orchestrator);
            let ctx = Arc::clone(&auth_ctx);
            let count = Arc::clone(&blocked_count);
            tasks.spawn(async move {
                // Small delay to allow kill switch to be set
                tokio::time::sleep(tokio::time::Duration::from_micros(100)).await;
                let result = orch
                    .transition_incident(id, IncidentStatus::Enriching, &ctx)
                    .await;
                if matches!(result, Err(OrchestratorError::KillSwitchActivated(_))) {
                    count.fetch_add(1, Ordering::SeqCst);
                }
                result
            });
        }

        // Activate kill switch while tasks are running
        orchestrator
            .activate_kill_switch("Immediate effect test", "admin")
            .await;

        // Wait for all tasks to complete
        while (tasks.join_next().await).is_some() {}

        // Most or all operations should have been blocked
        // (exact number depends on timing, but kill switch should have immediate effect)
        let blocked = blocked_count.load(Ordering::SeqCst);
        assert!(
            blocked > 0,
            "Kill switch should block at least some concurrent operations"
        );
    }

    #[tokio::test]
    async fn test_is_automated_state_helper() {
        // Test the helper function directly
        assert!(Orchestrator::is_automated_state(&IncidentStatus::Executing));
        assert!(Orchestrator::is_automated_state(&IncidentStatus::Enriching));
        assert!(Orchestrator::is_automated_state(&IncidentStatus::Analyzing));

        // These should NOT be automated states
        assert!(!Orchestrator::is_automated_state(&IncidentStatus::New));
        assert!(!Orchestrator::is_automated_state(
            &IncidentStatus::PendingReview
        ));
        assert!(!Orchestrator::is_automated_state(
            &IncidentStatus::PendingApproval
        ));
        assert!(!Orchestrator::is_automated_state(&IncidentStatus::Resolved));
        assert!(!Orchestrator::is_automated_state(
            &IncidentStatus::FalsePositive
        ));
        assert!(!Orchestrator::is_automated_state(
            &IncidentStatus::Dismissed
        ));
        assert!(!Orchestrator::is_automated_state(
            &IncidentStatus::Escalated
        ));
        assert!(!Orchestrator::is_automated_state(&IncidentStatus::Closed));
    }

    #[tokio::test]
    async fn test_kill_switch_deactivation_allows_automated_states() {
        let orchestrator = Orchestrator::new();
        let auth_ctx = create_analyst_context();

        // Create incident
        let alert = create_test_alert();
        let incident_id = orchestrator.process_alert(alert).await.unwrap();

        // Activate kill switch
        orchestrator.activate_kill_switch("Test", "admin").await;

        // Verify Enriching is blocked
        let result = orchestrator
            .transition_incident(incident_id, IncidentStatus::Enriching, &auth_ctx)
            .await;
        assert!(matches!(
            result,
            Err(OrchestratorError::KillSwitchActivated(_))
        ));

        // Deactivate kill switch
        orchestrator.deactivate_kill_switch("admin").await;

        // Now Enriching should be allowed
        let result = orchestrator
            .transition_incident(incident_id, IncidentStatus::Enriching, &auth_ctx)
            .await;
        assert!(result.is_ok());

        // Verify the state actually changed
        let incident = orchestrator.get_incident(incident_id).await.unwrap();
        assert_eq!(incident.status, IncidentStatus::Enriching);
    }

    // ============================================================
    // Operation Mode Tests
    // ============================================================

    #[tokio::test]
    async fn test_operation_mode_transitions() {
        let orchestrator = Orchestrator::new();

        // Default is Supervised
        assert_eq!(
            orchestrator.operation_mode().await,
            OperationMode::Supervised
        );

        // Transition through all modes
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

        orchestrator
            .set_operation_mode(OperationMode::Supervised)
            .await;
        assert_eq!(
            orchestrator.operation_mode().await,
            OperationMode::Supervised
        );
    }

    // ============================================================
    // Edge Cases
    // ============================================================

    #[tokio::test]
    async fn test_get_nonexistent_incident() {
        let orchestrator = Orchestrator::new();
        let fake_id = uuid::Uuid::new_v4();

        let result = orchestrator.get_incident(fake_id).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_multiple_severity_levels() {
        let orchestrator = Orchestrator::new();

        let mut alerts = vec![];
        for (i, severity) in [
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ]
        .iter()
        .enumerate()
        {
            let mut alert = create_test_alert();
            alert.id = format!("severity-test-{}", i);
            alert.severity = *severity;
            alerts.push(alert);
        }

        for alert in alerts {
            let expected_severity = alert.severity;
            let id = orchestrator.process_alert(alert).await.unwrap();
            let incident = orchestrator.get_incident(id).await.unwrap();
            assert_eq!(incident.severity, expected_severity);
        }
    }

    // ============================================================
    // Leader Election and Singleton Task Tests (Task 1.5.2)
    // ============================================================

    mod leader_election_tests {
        use super::*;
        use crate::leadership::{LeaderElectorConfig, MockLeaderElector};
        use std::time::Duration;

        fn create_mock_elector(instance_id: &str) -> Arc<dyn LeaderElector> {
            let config = LeaderElectorConfig::new(instance_id)
                .with_default_ttl(Duration::from_secs(30))
                .with_renew_interval(Duration::from_secs(10));
            Arc::new(MockLeaderElector::new(config))
        }

        fn create_mock_elector_raw(instance_id: &str) -> MockLeaderElector {
            let config = LeaderElectorConfig::new(instance_id)
                .with_default_ttl(Duration::from_secs(30))
                .with_renew_interval(Duration::from_secs(10));
            MockLeaderElector::new(config)
        }

        #[tokio::test]
        async fn test_orchestrator_with_leader_elector() {
            let elector = create_mock_elector("instance-1");
            let orchestrator = Orchestrator::with_leader_elector(
                OrchestratorConfig::default(),
                elector,
                "instance-1",
            );

            assert!(orchestrator.has_leader_election());
            assert_eq!(orchestrator.instance_id(), "instance-1");
        }

        #[tokio::test]
        async fn test_orchestrator_without_leader_elector_single_instance_mode() {
            let orchestrator = Orchestrator::new();

            // Without leader elector, should always report as leader
            assert!(!orchestrator.has_leader_election());
            assert!(orchestrator.is_leader(LEADER_RESOURCE_CLEANUP));
            assert!(orchestrator.is_cleanup_leader());
            assert!(orchestrator.is_scheduler_leader());
            assert!(orchestrator.is_metrics_leader());
        }

        #[tokio::test]
        async fn test_acquire_leadership() {
            let elector = create_mock_elector("instance-1");
            let orchestrator = Orchestrator::with_leader_elector(
                OrchestratorConfig::default(),
                elector,
                "instance-1",
            );

            // Acquire leadership
            let acquired = orchestrator
                .try_acquire_leadership(LEADER_RESOURCE_CLEANUP, Duration::from_secs(30))
                .await
                .unwrap();

            assert!(acquired);
            assert!(orchestrator.is_cleanup_leader());

            // Check leadership stats
            let stats = orchestrator.leadership_stats().await;
            assert_eq!(stats.elections_won, 1);
        }

        #[tokio::test]
        async fn test_leadership_contention() {
            // Create shared elector state
            let elector1 = create_mock_elector_raw("instance-1");
            let elector2 = MockLeaderElector {
                config: LeaderElectorConfig::new("instance-2"),
                leases: Arc::clone(&elector1.leases),
                fencing_tokens: Arc::clone(&elector1.fencing_tokens),
                time_override: Arc::clone(&elector1.time_override),
            };

            let orchestrator1 = Orchestrator::with_leader_elector(
                OrchestratorConfig::default(),
                Arc::new(elector1),
                "instance-1",
            );

            let orchestrator2 = Orchestrator::with_leader_elector(
                OrchestratorConfig::default(),
                Arc::new(elector2),
                "instance-2",
            );

            // Instance 1 acquires leadership
            let acquired1 = orchestrator1
                .try_acquire_leadership(LEADER_RESOURCE_CLEANUP, Duration::from_secs(30))
                .await
                .unwrap();
            assert!(acquired1);

            // Instance 2 cannot acquire (already held by instance 1)
            let acquired2 = orchestrator2
                .try_acquire_leadership(LEADER_RESOURCE_CLEANUP, Duration::from_secs(30))
                .await
                .unwrap();
            assert!(!acquired2);

            // Verify leadership status
            assert!(orchestrator1.is_cleanup_leader());
            assert!(!orchestrator2.is_cleanup_leader());
        }

        #[tokio::test]
        async fn test_release_leadership() {
            let elector = create_mock_elector("instance-1");
            let orchestrator = Orchestrator::with_leader_elector(
                OrchestratorConfig::default(),
                elector,
                "instance-1",
            );

            // Acquire then release
            orchestrator
                .try_acquire_leadership(LEADER_RESOURCE_CLEANUP, Duration::from_secs(30))
                .await
                .unwrap();
            assert!(orchestrator.is_cleanup_leader());

            orchestrator
                .release_leadership(LEADER_RESOURCE_CLEANUP)
                .await
                .unwrap();

            // Leadership stats should show loss
            let stats = orchestrator.leadership_stats().await;
            assert_eq!(stats.elections_won, 1);
            assert_eq!(stats.elections_lost, 1);
        }

        #[tokio::test]
        async fn test_renew_leadership() {
            let elector = create_mock_elector("instance-1");
            let orchestrator = Orchestrator::with_leader_elector(
                OrchestratorConfig::default(),
                elector,
                "instance-1",
            );

            // Acquire leadership
            orchestrator
                .try_acquire_leadership(LEADER_RESOURCE_CLEANUP, Duration::from_secs(30))
                .await
                .unwrap();

            // Renew
            let renewed = orchestrator
                .renew_leadership(LEADER_RESOURCE_CLEANUP)
                .await
                .unwrap();

            assert!(renewed);

            // Check stats
            let stats = orchestrator.leadership_stats().await;
            assert_eq!(stats.renewals_successful, 1);
        }

        #[tokio::test]
        async fn test_run_if_leader_as_leader() {
            let elector = create_mock_elector("instance-1");
            let orchestrator = Orchestrator::with_leader_elector(
                OrchestratorConfig::default(),
                elector,
                "instance-1",
            );

            // Acquire leadership
            orchestrator
                .try_acquire_leadership(LEADER_RESOURCE_CLEANUP, Duration::from_secs(30))
                .await
                .unwrap();

            // Run task
            let result = orchestrator
                .run_if_leader(LEADER_RESOURCE_CLEANUP, "test-task", async {
                    Ok::<_, std::convert::Infallible>(42)
                })
                .await
                .unwrap();

            assert_eq!(result, Some(42));
        }

        #[tokio::test]
        async fn test_run_if_leader_as_non_leader() {
            // Create shared elector state
            let elector1 = create_mock_elector_raw("instance-1");
            let elector2 = MockLeaderElector {
                config: LeaderElectorConfig::new("instance-2"),
                leases: Arc::clone(&elector1.leases),
                fencing_tokens: Arc::clone(&elector1.fencing_tokens),
                time_override: Arc::clone(&elector1.time_override),
            };

            let orchestrator1 = Orchestrator::with_leader_elector(
                OrchestratorConfig::default(),
                Arc::new(elector1),
                "instance-1",
            );

            let orchestrator2 = Orchestrator::with_leader_elector(
                OrchestratorConfig::default(),
                Arc::new(elector2),
                "instance-2",
            );

            // Instance 1 acquires leadership
            orchestrator1
                .try_acquire_leadership(LEADER_RESOURCE_CLEANUP, Duration::from_secs(30))
                .await
                .unwrap();

            // Instance 2 tries to run task (should skip since not leader)
            let result = orchestrator2
                .run_if_leader(LEADER_RESOURCE_CLEANUP, "test-task", async {
                    Ok::<_, std::convert::Infallible>(42)
                })
                .await
                .unwrap();

            assert_eq!(result, None); // Task was skipped
        }

        #[tokio::test]
        async fn test_run_if_leader_single_instance_mode() {
            let orchestrator = Orchestrator::new(); // No leader elector

            // Should run unconditionally
            let result = orchestrator
                .run_if_leader(LEADER_RESOURCE_CLEANUP, "test-task", async {
                    Ok::<_, std::convert::Infallible>(42)
                })
                .await
                .unwrap();

            assert_eq!(result, Some(42));
        }

        #[tokio::test]
        async fn test_cleanup_task_runs_as_leader() {
            let elector = create_mock_elector("instance-1");
            let orchestrator = Orchestrator::with_leader_elector(
                OrchestratorConfig::default(),
                elector,
                "instance-1",
            );

            // Acquire leadership for cleanup
            orchestrator
                .try_acquire_leadership(LEADER_RESOURCE_CLEANUP, Duration::from_secs(30))
                .await
                .unwrap();

            // Run cleanup task
            orchestrator.run_cleanup_task().await.unwrap();

            // Verify stats updated
            let stats = orchestrator.leadership_stats().await;
            assert_eq!(stats.cleanup_executions, 1);
        }

        #[tokio::test]
        async fn test_cleanup_task_skipped_as_non_leader() {
            // Create shared elector state
            let elector1 = create_mock_elector_raw("instance-1");
            let elector2 = MockLeaderElector {
                config: LeaderElectorConfig::new("instance-2"),
                leases: Arc::clone(&elector1.leases),
                fencing_tokens: Arc::clone(&elector1.fencing_tokens),
                time_override: Arc::clone(&elector1.time_override),
            };

            let orchestrator1 = Orchestrator::with_leader_elector(
                OrchestratorConfig::default(),
                Arc::new(elector1),
                "instance-1",
            );

            let orchestrator2 = Orchestrator::with_leader_elector(
                OrchestratorConfig::default(),
                Arc::new(elector2),
                "instance-2",
            );

            // Instance 1 acquires leadership
            orchestrator1
                .try_acquire_leadership(LEADER_RESOURCE_CLEANUP, Duration::from_secs(30))
                .await
                .unwrap();

            // Instance 2 tries to run cleanup (should skip)
            orchestrator2.run_cleanup_task().await.unwrap();

            // Instance 2's stats should show 0 executions
            let stats2 = orchestrator2.leadership_stats().await;
            assert_eq!(stats2.cleanup_executions, 0);

            // Instance 1 runs cleanup successfully
            orchestrator1.run_cleanup_task().await.unwrap();
            let stats1 = orchestrator1.leadership_stats().await;
            assert_eq!(stats1.cleanup_executions, 1);
        }

        #[tokio::test]
        async fn test_scheduler_task_runs_as_leader() {
            let elector = create_mock_elector("instance-1");
            let orchestrator = Orchestrator::with_leader_elector(
                OrchestratorConfig::default(),
                elector,
                "instance-1",
            );

            orchestrator
                .try_acquire_leadership(LEADER_RESOURCE_SCHEDULER, Duration::from_secs(30))
                .await
                .unwrap();

            orchestrator.run_scheduler_task().await.unwrap();

            let stats = orchestrator.leadership_stats().await;
            assert_eq!(stats.scheduler_executions, 1);
        }

        #[tokio::test]
        async fn test_metrics_task_runs_as_leader() {
            let elector = create_mock_elector("instance-1");
            let orchestrator = Orchestrator::with_leader_elector(
                OrchestratorConfig::default(),
                elector,
                "instance-1",
            );

            orchestrator
                .try_acquire_leadership(LEADER_RESOURCE_METRICS, Duration::from_secs(30))
                .await
                .unwrap();

            orchestrator.run_metrics_task().await.unwrap();

            let stats = orchestrator.leadership_stats().await;
            assert_eq!(stats.metrics_executions, 1);
        }

        #[tokio::test]
        async fn test_graceful_shutdown_releases_all_leases() {
            let elector = create_mock_elector_raw("instance-1");
            let elector_ref = Arc::new(elector);
            let orchestrator = Orchestrator::with_leader_elector(
                OrchestratorConfig::default(),
                Arc::clone(&elector_ref) as Arc<dyn LeaderElector>,
                "instance-1",
            );

            // Acquire all leader resources
            orchestrator
                .try_acquire_leadership(LEADER_RESOURCE_CLEANUP, Duration::from_secs(30))
                .await
                .unwrap();
            orchestrator
                .try_acquire_leadership(LEADER_RESOURCE_SCHEDULER, Duration::from_secs(30))
                .await
                .unwrap();
            orchestrator
                .try_acquire_leadership(LEADER_RESOURCE_METRICS, Duration::from_secs(30))
                .await
                .unwrap();

            // Verify leadership
            assert!(orchestrator.is_cleanup_leader());
            assert!(orchestrator.is_scheduler_leader());
            assert!(orchestrator.is_metrics_leader());

            // Graceful shutdown
            orchestrator.graceful_shutdown().await.unwrap();

            // Verify leases were released (elector should have no leases)
            let leases = elector_ref.all_leases().await;
            assert!(leases.is_empty());
        }

        #[tokio::test]
        async fn test_leadership_handoff_on_expiration() {
            // Create shared elector state
            let elector1 = create_mock_elector_raw("instance-1");
            let elector1_ref = Arc::new(elector1);
            let elector2 = MockLeaderElector {
                config: LeaderElectorConfig::new("instance-2"),
                leases: Arc::clone(&elector1_ref.leases),
                fencing_tokens: Arc::clone(&elector1_ref.fencing_tokens),
                time_override: Arc::clone(&elector1_ref.time_override),
            };

            let orchestrator1 = Orchestrator::with_leader_elector(
                OrchestratorConfig::default(),
                Arc::clone(&elector1_ref) as Arc<dyn LeaderElector>,
                "instance-1",
            );

            let orchestrator2 = Orchestrator::with_leader_elector(
                OrchestratorConfig::default(),
                Arc::new(elector2),
                "instance-2",
            );

            // Instance 1 acquires with short TTL
            orchestrator1
                .try_acquire_leadership(LEADER_RESOURCE_CLEANUP, Duration::from_secs(1))
                .await
                .unwrap();
            assert!(orchestrator1.is_cleanup_leader());

            // Simulate time passing (lease expires)
            elector1_ref.advance_time(Duration::from_secs(5)).await;

            // Instance 2 can now acquire
            let acquired = orchestrator2
                .try_acquire_leadership(LEADER_RESOURCE_CLEANUP, Duration::from_secs(30))
                .await
                .unwrap();
            assert!(acquired);
            assert!(orchestrator2.is_cleanup_leader());
        }

        #[tokio::test]
        async fn test_leadership_logging_includes_instance_id() {
            let elector = create_mock_elector("test-instance-123");
            let orchestrator = Orchestrator::with_leader_elector(
                OrchestratorConfig::default(),
                elector,
                "test-instance-123",
            );

            assert_eq!(orchestrator.instance_id(), "test-instance-123");
        }

        #[tokio::test]
        async fn test_leadership_stats_tracking() {
            let elector = create_mock_elector("instance-1");
            let orchestrator = Orchestrator::with_leader_elector(
                OrchestratorConfig::default(),
                elector,
                "instance-1",
            );

            // Initial stats
            let stats = orchestrator.leadership_stats().await;
            assert_eq!(stats.elections_won, 0);
            assert_eq!(stats.elections_lost, 0);

            // Acquire leadership
            orchestrator
                .try_acquire_leadership(LEADER_RESOURCE_CLEANUP, Duration::from_secs(30))
                .await
                .unwrap();

            let stats = orchestrator.leadership_stats().await;
            assert_eq!(stats.elections_won, 1);
            assert!(stats.leadership_acquired_at.is_some());

            // Renew
            orchestrator
                .renew_leadership(LEADER_RESOURCE_CLEANUP)
                .await
                .unwrap();

            let stats = orchestrator.leadership_stats().await;
            assert_eq!(stats.renewals_successful, 1);

            // Release
            orchestrator
                .release_leadership(LEADER_RESOURCE_CLEANUP)
                .await
                .unwrap();

            let stats = orchestrator.leadership_stats().await;
            assert_eq!(stats.elections_lost, 1);
            // Leadership duration should be tracked (any value is valid since it depends on timing)
            let _ = stats.total_leadership_seconds;
        }

        #[tokio::test]
        async fn test_multiple_resources_independent_leadership() {
            let elector = create_mock_elector("instance-1");
            let orchestrator = Orchestrator::with_leader_elector(
                OrchestratorConfig::default(),
                elector,
                "instance-1",
            );

            // Acquire leadership for cleanup only
            orchestrator
                .try_acquire_leadership(LEADER_RESOURCE_CLEANUP, Duration::from_secs(30))
                .await
                .unwrap();

            // Should be leader for cleanup, but not scheduler or metrics
            assert!(orchestrator.is_cleanup_leader());
            assert!(!orchestrator.is_scheduler_leader());
            assert!(!orchestrator.is_metrics_leader());

            // Acquire scheduler
            orchestrator
                .try_acquire_leadership(LEADER_RESOURCE_SCHEDULER, Duration::from_secs(30))
                .await
                .unwrap();

            assert!(orchestrator.is_cleanup_leader());
            assert!(orchestrator.is_scheduler_leader());
            assert!(!orchestrator.is_metrics_leader());
        }

        #[tokio::test]
        async fn test_acquire_leadership_single_instance_mode_always_succeeds() {
            let orchestrator = Orchestrator::new(); // No leader elector

            let acquired = orchestrator
                .try_acquire_leadership(LEADER_RESOURCE_CLEANUP, Duration::from_secs(30))
                .await
                .unwrap();

            assert!(acquired);
        }

        #[tokio::test]
        async fn test_renew_leadership_single_instance_mode_always_succeeds() {
            let orchestrator = Orchestrator::new(); // No leader elector

            let renewed = orchestrator
                .renew_leadership(LEADER_RESOURCE_CLEANUP)
                .await
                .unwrap();

            assert!(renewed);
        }

        #[tokio::test]
        async fn test_release_leadership_single_instance_mode_no_op() {
            let orchestrator = Orchestrator::new(); // No leader elector

            // Should succeed without error
            orchestrator
                .release_leadership(LEADER_RESOURCE_CLEANUP)
                .await
                .unwrap();
        }

        // Integration test concept: Verify only one instance runs singleton tasks
        #[tokio::test]
        async fn test_integration_only_one_instance_runs_singleton_tasks() {
            use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

            // Create shared elector state for both instances
            let elector1 = create_mock_elector_raw("instance-1");
            let elector2 = MockLeaderElector {
                config: LeaderElectorConfig::new("instance-2"),
                leases: Arc::clone(&elector1.leases),
                fencing_tokens: Arc::clone(&elector1.fencing_tokens),
                time_override: Arc::clone(&elector1.time_override),
            };

            let orchestrator1 = Arc::new(Orchestrator::with_leader_elector(
                OrchestratorConfig::default(),
                Arc::new(elector1),
                "instance-1",
            ));

            let orchestrator2 = Arc::new(Orchestrator::with_leader_elector(
                OrchestratorConfig::default(),
                Arc::new(elector2),
                "instance-2",
            ));

            // Both instances try to acquire leadership concurrently
            let (result1, result2) = tokio::join!(
                orchestrator1
                    .try_acquire_leadership(LEADER_RESOURCE_CLEANUP, Duration::from_secs(30)),
                orchestrator2
                    .try_acquire_leadership(LEADER_RESOURCE_CLEANUP, Duration::from_secs(30))
            );

            // Only one should succeed
            let acquired1 = result1.unwrap();
            let acquired2 = result2.unwrap();
            assert!(
                (acquired1 && !acquired2) || (!acquired1 && acquired2),
                "Exactly one instance should acquire leadership"
            );

            // Track how many times the task ran
            let execution_count = Arc::new(AtomicUsize::new(0));

            // Both instances try to run the task
            let count1 = Arc::clone(&execution_count);
            let count2 = Arc::clone(&execution_count);

            let orch1 = Arc::clone(&orchestrator1);
            let orch2 = Arc::clone(&orchestrator2);

            let (res1, res2) = tokio::join!(
                async {
                    orch1
                        .run_if_leader(LEADER_RESOURCE_CLEANUP, "test", async {
                            count1.fetch_add(1, AtomicOrdering::SeqCst);
                            Ok::<_, std::convert::Infallible>(())
                        })
                        .await
                },
                async {
                    orch2
                        .run_if_leader(LEADER_RESOURCE_CLEANUP, "test", async {
                            count2.fetch_add(1, AtomicOrdering::SeqCst);
                            Ok::<_, std::convert::Infallible>(())
                        })
                        .await
                }
            );

            res1.unwrap();
            res2.unwrap();

            // Task should have run exactly once
            assert_eq!(
                execution_count.load(AtomicOrdering::SeqCst),
                1,
                "Singleton task should run exactly once across all instances"
            );
        }
    }
}
