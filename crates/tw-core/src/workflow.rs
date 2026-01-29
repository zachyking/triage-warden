//! Workflow state machine for Triage Warden.
//!
//! This module implements the workflow state machine that manages the
//! progression of incidents through the triage process.

use crate::incident::{Incident, IncidentStatus};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use tracing::{debug, info, instrument, warn};
use uuid::Uuid;

/// Errors that can occur in workflow processing.
#[derive(Error, Debug)]
pub enum WorkflowError {
    #[error("Invalid state transition from {from:?} to {to:?}")]
    InvalidTransition {
        from: IncidentStatus,
        to: IncidentStatus,
    },

    #[error("Workflow not found: {0}")]
    WorkflowNotFound(Uuid),

    #[error("Condition not met: {0}")]
    ConditionNotMet(String),

    #[error("Playbook not found: {0}")]
    PlaybookNotFound(String),

    #[error("Step execution failed: {0}")]
    StepExecutionFailed(String),
}

/// Represents a state transition in the workflow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowTransition {
    /// Source state.
    pub from: IncidentStatus,
    /// Target state.
    pub to: IncidentStatus,
    /// Condition that must be met for this transition.
    pub condition: Option<TransitionCondition>,
    /// Actions to execute on transition.
    pub actions: Vec<TransitionAction>,
}

/// Conditions that can gate state transitions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionCondition {
    /// All enrichments must be complete.
    EnrichmentsComplete,
    /// Analysis must be complete.
    AnalysisComplete,
    /// All proposed actions must be reviewed.
    ActionsReviewed,
    /// All approved actions must be executed.
    ActionsExecuted,
    /// Manual approval required.
    ManualApproval,
    /// Confidence threshold must be met.
    ConfidenceThreshold(f64),
    /// Custom condition.
    Custom(String),
}

/// Actions to execute during a state transition.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionAction {
    /// Send a notification.
    SendNotification { template: String },
    /// Create a ticket.
    CreateTicket,
    /// Update the ticket.
    UpdateTicket { status: String },
    /// Log an audit entry.
    AuditLog { message: String },
    /// Run a playbook step.
    RunPlaybookStep { step_name: String },
}

/// Current state of a workflow execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowState {
    /// Incident ID this workflow is for.
    pub incident_id: Uuid,
    /// Current status.
    pub current_status: IncidentStatus,
    /// Playbook being executed (if any).
    pub playbook: Option<String>,
    /// Current step in the playbook.
    pub current_step: Option<String>,
    /// Steps that have been completed.
    pub completed_steps: Vec<String>,
    /// Variables/context for the workflow.
    pub context: HashMap<String, serde_json::Value>,
    /// Whether the workflow is paused.
    pub paused: bool,
    /// Reason for pause (if paused).
    pub pause_reason: Option<String>,
}

impl WorkflowState {
    /// Creates a new workflow state for an incident.
    pub fn new(incident_id: Uuid) -> Self {
        Self {
            incident_id,
            current_status: IncidentStatus::New,
            playbook: None,
            current_step: None,
            completed_steps: Vec::new(),
            context: HashMap::new(),
            paused: false,
            pause_reason: None,
        }
    }

    /// Creates a workflow state with a specific playbook.
    pub fn with_playbook(incident_id: Uuid, playbook: &str) -> Self {
        Self {
            incident_id,
            current_status: IncidentStatus::New,
            playbook: Some(playbook.to_string()),
            current_step: None,
            completed_steps: Vec::new(),
            context: HashMap::new(),
            paused: false,
            pause_reason: None,
        }
    }

    /// Sets a context variable.
    pub fn set_context(&mut self, key: &str, value: serde_json::Value) {
        self.context.insert(key.to_string(), value);
    }

    /// Gets a context variable.
    pub fn get_context(&self, key: &str) -> Option<&serde_json::Value> {
        self.context.get(key)
    }

    /// Marks a step as completed.
    pub fn complete_step(&mut self, step: &str) {
        self.completed_steps.push(step.to_string());
        self.current_step = None;
    }

    /// Pauses the workflow.
    pub fn pause(&mut self, reason: &str) {
        self.paused = true;
        self.pause_reason = Some(reason.to_string());
    }

    /// Resumes the workflow.
    pub fn resume(&mut self) {
        self.paused = false;
        self.pause_reason = None;
    }
}

/// The workflow engine manages state transitions and playbook execution.
pub struct WorkflowEngine {
    /// Valid state transitions.
    transitions: Vec<WorkflowTransition>,
    /// Active workflow states by incident ID.
    active_workflows: HashMap<Uuid, WorkflowState>,
}

impl WorkflowEngine {
    /// Creates a new workflow engine with default transitions.
    pub fn new() -> Self {
        Self {
            transitions: Self::default_transitions(),
            active_workflows: HashMap::new(),
        }
    }

    /// Returns the default state transition rules.
    fn default_transitions() -> Vec<WorkflowTransition> {
        vec![
            // New -> Enriching
            WorkflowTransition {
                from: IncidentStatus::New,
                to: IncidentStatus::Enriching,
                condition: None,
                actions: vec![TransitionAction::AuditLog {
                    message: "Starting enrichment phase".to_string(),
                }],
            },
            // Enriching -> Analyzing
            WorkflowTransition {
                from: IncidentStatus::Enriching,
                to: IncidentStatus::Analyzing,
                condition: Some(TransitionCondition::EnrichmentsComplete),
                actions: vec![TransitionAction::AuditLog {
                    message: "Starting AI analysis".to_string(),
                }],
            },
            // Analyzing -> PendingReview
            WorkflowTransition {
                from: IncidentStatus::Analyzing,
                to: IncidentStatus::PendingReview,
                condition: Some(TransitionCondition::AnalysisComplete),
                actions: vec![
                    TransitionAction::CreateTicket,
                    TransitionAction::SendNotification {
                        template: "analysis_complete".to_string(),
                    },
                ],
            },
            // PendingReview -> PendingApproval
            WorkflowTransition {
                from: IncidentStatus::PendingReview,
                to: IncidentStatus::PendingApproval,
                condition: None,
                actions: vec![TransitionAction::SendNotification {
                    template: "approval_required".to_string(),
                }],
            },
            // PendingApproval -> Executing
            WorkflowTransition {
                from: IncidentStatus::PendingApproval,
                to: IncidentStatus::Executing,
                condition: Some(TransitionCondition::ActionsReviewed),
                actions: vec![TransitionAction::AuditLog {
                    message: "Executing approved actions".to_string(),
                }],
            },
            // Executing -> Resolved
            WorkflowTransition {
                from: IncidentStatus::Executing,
                to: IncidentStatus::Resolved,
                condition: Some(TransitionCondition::ActionsExecuted),
                actions: vec![
                    TransitionAction::UpdateTicket {
                        status: "resolved".to_string(),
                    },
                    TransitionAction::SendNotification {
                        template: "incident_resolved".to_string(),
                    },
                ],
            },
            // Any -> FalsePositive
            WorkflowTransition {
                from: IncidentStatus::PendingReview,
                to: IncidentStatus::FalsePositive,
                condition: None,
                actions: vec![
                    TransitionAction::UpdateTicket {
                        status: "false_positive".to_string(),
                    },
                    TransitionAction::AuditLog {
                        message: "Marked as false positive".to_string(),
                    },
                ],
            },
            // Any -> Escalated
            WorkflowTransition {
                from: IncidentStatus::PendingReview,
                to: IncidentStatus::Escalated,
                condition: None,
                actions: vec![
                    TransitionAction::UpdateTicket {
                        status: "escalated".to_string(),
                    },
                    TransitionAction::SendNotification {
                        template: "incident_escalated".to_string(),
                    },
                ],
            },
        ]
    }

    /// Registers a new workflow for an incident.
    #[instrument(skip(self))]
    pub fn register_workflow(&mut self, incident: &Incident) -> WorkflowState {
        let state = WorkflowState::new(incident.id);
        self.active_workflows.insert(incident.id, state.clone());
        info!("Registered workflow for incident {}", incident.id);
        state
    }

    /// Registers a workflow with a specific playbook.
    #[instrument(skip(self))]
    pub fn register_workflow_with_playbook(
        &mut self,
        incident: &Incident,
        playbook: &str,
    ) -> WorkflowState {
        let state = WorkflowState::with_playbook(incident.id, playbook);
        self.active_workflows.insert(incident.id, state.clone());
        info!(
            "Registered workflow for incident {} with playbook {}",
            incident.id, playbook
        );
        state
    }

    /// Gets the current workflow state for an incident.
    pub fn get_workflow(&self, incident_id: Uuid) -> Option<&WorkflowState> {
        self.active_workflows.get(&incident_id)
    }

    /// Gets a mutable reference to the workflow state.
    pub fn get_workflow_mut(&mut self, incident_id: Uuid) -> Option<&mut WorkflowState> {
        self.active_workflows.get_mut(&incident_id)
    }

    /// Checks if a state transition is valid.
    pub fn can_transition(
        &self,
        from: &IncidentStatus,
        to: &IncidentStatus,
    ) -> Option<&WorkflowTransition> {
        self.transitions
            .iter()
            .find(|t| &t.from == from && &t.to == to)
    }

    /// Attempts to transition an incident to a new state.
    #[instrument(skip(self, incident))]
    pub fn transition(
        &mut self,
        incident: &mut Incident,
        to: IncidentStatus,
    ) -> Result<Vec<TransitionAction>, WorkflowError> {
        let from = incident.status.clone();

        // Check if transition is valid
        let transition = self
            .can_transition(&from, &to)
            .ok_or(WorkflowError::InvalidTransition {
                from: from.clone(),
                to: to.clone(),
            })?
            .clone();

        // Check condition if present
        if let Some(ref condition) = transition.condition {
            if !self.evaluate_condition(condition, incident)? {
                return Err(WorkflowError::ConditionNotMet(format!("{:?}", condition)));
            }
        }

        // Update incident status
        incident.update_status(to.clone(), "workflow_engine");

        // Update workflow state
        if let Some(state) = self.active_workflows.get_mut(&incident.id) {
            state.current_status = to.clone();
        }

        info!(
            "Transitioned incident {} from {:?} to {:?}",
            incident.id, from, to
        );

        Ok(transition.actions)
    }

    /// Evaluates a transition condition.
    fn evaluate_condition(
        &self,
        condition: &TransitionCondition,
        incident: &Incident,
    ) -> Result<bool, WorkflowError> {
        match condition {
            TransitionCondition::EnrichmentsComplete => {
                // For now, consider complete if we have at least one enrichment
                // In production, this would check against expected enrichments
                Ok(!incident.enrichments.is_empty())
            }
            TransitionCondition::AnalysisComplete => Ok(incident.analysis.is_some()),
            TransitionCondition::ActionsReviewed => {
                // All proposed actions must have a status other than Pending
                Ok(incident
                    .proposed_actions
                    .iter()
                    .all(|a| a.approval_status != crate::incident::ApprovalStatus::Pending))
            }
            TransitionCondition::ActionsExecuted => {
                // All approved actions must be executed
                Ok(incident.proposed_actions.iter().all(|a| {
                    a.approval_status == crate::incident::ApprovalStatus::Executed
                        || a.approval_status == crate::incident::ApprovalStatus::Denied
                        || a.approval_status == crate::incident::ApprovalStatus::Failed
                }))
            }
            TransitionCondition::ManualApproval => {
                // This would check an approval flag set externally
                debug!("Manual approval check - requires external approval");
                Ok(false)
            }
            TransitionCondition::ConfidenceThreshold(threshold) => {
                if let Some(ref analysis) = incident.analysis {
                    Ok(analysis.confidence >= *threshold)
                } else {
                    Ok(false)
                }
            }
            TransitionCondition::Custom(name) => {
                warn!("Custom condition '{}' not implemented", name);
                Ok(false)
            }
        }
    }

    /// Gets all possible next states from the current state.
    pub fn get_possible_transitions(&self, from: &IncidentStatus) -> Vec<&WorkflowTransition> {
        self.transitions.iter().filter(|t| &t.from == from).collect()
    }

    /// Removes a completed workflow.
    pub fn remove_workflow(&mut self, incident_id: Uuid) -> Option<WorkflowState> {
        self.active_workflows.remove(&incident_id)
    }

    /// Gets the count of active workflows.
    pub fn active_workflow_count(&self) -> usize {
        self.active_workflows.len()
    }

    /// Gets all active workflows.
    pub fn get_all_workflows(&self) -> &HashMap<Uuid, WorkflowState> {
        &self.active_workflows
    }
}

impl Default for WorkflowEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::incident::{Alert, AlertSource, Enrichment, EnrichmentType, Severity};
    use chrono::Utc;

    fn create_test_incident() -> Incident {
        let alert = Alert {
            id: "test-alert".to_string(),
            source: AlertSource::EmailSecurity("Test".to_string()),
            alert_type: "phishing".to_string(),
            severity: Severity::High,
            title: "Test alert".to_string(),
            description: None,
            data: serde_json::json!({}),
            timestamp: Utc::now(),
            tags: vec![],
        };
        Incident::from_alert(alert)
    }

    #[test]
    fn test_workflow_registration() {
        let mut engine = WorkflowEngine::new();
        let incident = create_test_incident();

        let state = engine.register_workflow(&incident);
        assert_eq!(state.current_status, IncidentStatus::New);
        assert!(engine.get_workflow(incident.id).is_some());
    }

    #[test]
    fn test_valid_transition() {
        let mut engine = WorkflowEngine::new();
        let mut incident = create_test_incident();
        engine.register_workflow(&incident);

        // New -> Enriching should succeed
        let result = engine.transition(&mut incident, IncidentStatus::Enriching);
        assert!(result.is_ok());
        assert_eq!(incident.status, IncidentStatus::Enriching);
    }

    #[test]
    fn test_invalid_transition() {
        let mut engine = WorkflowEngine::new();
        let mut incident = create_test_incident();
        engine.register_workflow(&incident);

        // New -> Resolved should fail (not a valid direct transition)
        let result = engine.transition(&mut incident, IncidentStatus::Resolved);
        assert!(result.is_err());
    }

    #[test]
    fn test_condition_not_met() {
        let mut engine = WorkflowEngine::new();
        let mut incident = create_test_incident();
        engine.register_workflow(&incident);

        // Transition to Enriching first
        engine
            .transition(&mut incident, IncidentStatus::Enriching)
            .unwrap();

        // Enriching -> Analyzing should fail without enrichments
        let result = engine.transition(&mut incident, IncidentStatus::Analyzing);
        assert!(matches!(result, Err(WorkflowError::ConditionNotMet(_))));
    }

    #[test]
    fn test_condition_met() {
        let mut engine = WorkflowEngine::new();
        let mut incident = create_test_incident();
        engine.register_workflow(&incident);

        // Transition to Enriching
        engine
            .transition(&mut incident, IncidentStatus::Enriching)
            .unwrap();

        // Add an enrichment
        incident.add_enrichment(Enrichment {
            enrichment_type: EnrichmentType::ThreatIntel,
            source: "test".to_string(),
            data: serde_json::json!({}),
            timestamp: Utc::now(),
            ttl_seconds: None,
        });

        // Now Enriching -> Analyzing should succeed
        let result = engine.transition(&mut incident, IncidentStatus::Analyzing);
        assert!(result.is_ok());
    }

    #[test]
    fn test_workflow_state_context() {
        let mut state = WorkflowState::new(Uuid::new_v4());

        state.set_context("key1", serde_json::json!("value1"));
        assert_eq!(
            state.get_context("key1"),
            Some(&serde_json::json!("value1"))
        );

        state.set_context("key2", serde_json::json!(42));
        assert_eq!(state.get_context("key2"), Some(&serde_json::json!(42)));
    }

    #[test]
    fn test_workflow_pause_resume() {
        let mut state = WorkflowState::new(Uuid::new_v4());

        assert!(!state.paused);
        state.pause("Waiting for approval");
        assert!(state.paused);
        assert_eq!(state.pause_reason, Some("Waiting for approval".to_string()));

        state.resume();
        assert!(!state.paused);
        assert!(state.pause_reason.is_none());
    }
}
