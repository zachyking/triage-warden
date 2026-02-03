//! Workflow state machine for Triage Warden.
//!
//! This module implements the workflow state machine that manages the
//! progression of incidents through the triage process.
//!
//! ## Authorization
//!
//! Workflow transitions require appropriate permissions:
//! - Transitions to `Executing` require `ApproveActions` permission
//! - Transitions to `Resolved` require `WriteIncidents` permission
//! - All state transitions are logged with actor identity
//!
//! ## Manual Approval
//!
//! Some transitions require manual approval before proceeding. The approval
//! workflow:
//! 1. Request approval via `request_manual_approval()`
//! 2. Approver grants/denies via `grant_approval()` or `deny_approval()`
//! 3. Transition condition checks approval state
//! 4. Stale approvals timeout after configured duration

use crate::auth::{AuthorizationContext, Permission};
use crate::incident::{Incident, IncidentStatus};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use tracing::{debug, info, instrument, warn};
use uuid::Uuid;

/// Default timeout for manual approvals (24 hours).
pub const DEFAULT_APPROVAL_TIMEOUT_HOURS: i64 = 24;

/// Status of a manual approval request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ManualApprovalStatus {
    /// Approval has been requested and is pending.
    Pending,
    /// Approval was granted.
    Approved,
    /// Approval was denied.
    Denied,
    /// Approval request timed out.
    TimedOut,
}

/// Represents a manual approval request for a workflow transition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManualApprovalRequest {
    /// Unique identifier for this approval request.
    pub id: Uuid,
    /// The incident this approval is for.
    pub incident_id: Uuid,
    /// The transition that requires approval.
    pub transition_to: IncidentStatus,
    /// Current status of the approval.
    pub status: ManualApprovalStatus,
    /// Who requested the approval.
    pub requested_by: String,
    /// When the approval was requested.
    pub requested_at: DateTime<Utc>,
    /// When the approval expires (becomes stale).
    pub expires_at: DateTime<Utc>,
    /// Who made the approval decision (if any).
    pub decided_by: Option<String>,
    /// When the decision was made.
    pub decided_at: Option<DateTime<Utc>>,
    /// Reason for the decision.
    pub decision_reason: Option<String>,
}

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

    #[error("Unauthorized: {action} requires {required_permission} permission (actor: {actor})")]
    Unauthorized {
        /// The action that was attempted.
        action: String,
        /// The permission that was required.
        required_permission: String,
        /// The actor who attempted the action.
        actor: String,
    },

    #[error("Approval not found: {0}")]
    ApprovalNotFound(Uuid),

    #[error("Approval already decided: {0}")]
    ApprovalAlreadyDecided(Uuid),

    #[error("Approval request expired at {0}")]
    ApprovalExpired(DateTime<Utc>),

    #[error("Manual approval required for transition to {0:?}")]
    ManualApprovalRequired(IncidentStatus),

    #[error("Manual approval was denied: {0}")]
    ManualApprovalDenied(String),
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
    /// Manual approval requests for this workflow.
    pub approval_requests: Vec<ManualApprovalRequest>,
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
            approval_requests: Vec::new(),
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
            approval_requests: Vec::new(),
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

    /// Creates a new manual approval request for a transition.
    ///
    /// Returns the approval request ID.
    pub fn request_approval(
        &mut self,
        transition_to: IncidentStatus,
        requested_by: &str,
        timeout_hours: Option<i64>,
    ) -> Uuid {
        let now = Utc::now();
        let timeout = timeout_hours.unwrap_or(DEFAULT_APPROVAL_TIMEOUT_HOURS);
        let expires_at = now + Duration::hours(timeout);

        let request = ManualApprovalRequest {
            id: Uuid::new_v4(),
            incident_id: self.incident_id,
            transition_to: transition_to.clone(),
            status: ManualApprovalStatus::Pending,
            requested_by: requested_by.to_string(),
            requested_at: now,
            expires_at,
            decided_by: None,
            decided_at: None,
            decision_reason: None,
        };

        let id = request.id;
        self.approval_requests.push(request);

        // Pause the workflow while waiting for approval
        self.pause("Waiting for manual approval");

        info!(
            "Manual approval requested for incident {} to transition to {:?}, expires at {}",
            self.incident_id, transition_to, expires_at
        );

        id
    }

    /// Gets a pending approval request for a specific transition.
    pub fn get_pending_approval(
        &self,
        transition_to: &IncidentStatus,
    ) -> Option<&ManualApprovalRequest> {
        self.approval_requests.iter().find(|r| {
            r.transition_to == *transition_to && r.status == ManualApprovalStatus::Pending
        })
    }

    /// Gets an approval request by ID.
    pub fn get_approval(&self, approval_id: Uuid) -> Option<&ManualApprovalRequest> {
        self.approval_requests.iter().find(|r| r.id == approval_id)
    }

    /// Gets a mutable approval request by ID.
    fn get_approval_mut(&mut self, approval_id: Uuid) -> Option<&mut ManualApprovalRequest> {
        self.approval_requests
            .iter_mut()
            .find(|r| r.id == approval_id)
    }

    /// Checks if a transition has been approved.
    ///
    /// Returns:
    /// - `Ok(true)` if the transition is approved
    /// - `Ok(false)` if no approval exists or it's still pending
    /// - `Err(WorkflowError::ManualApprovalDenied)` if denied
    /// - `Err(WorkflowError::ApprovalExpired)` if timed out
    pub fn check_approval_status(
        &self,
        transition_to: &IncidentStatus,
    ) -> Result<bool, WorkflowError> {
        // Find the most recent approval request for this transition
        let request = self
            .approval_requests
            .iter()
            .filter(|r| r.transition_to == *transition_to)
            .max_by_key(|r| r.requested_at);

        match request {
            None => {
                debug!(
                    "No approval request found for transition to {:?}",
                    transition_to
                );
                Ok(false)
            }
            Some(req) => {
                // Check for timeout first
                if req.status == ManualApprovalStatus::Pending && Utc::now() > req.expires_at {
                    debug!(
                        "Approval request {} has expired (expired at {})",
                        req.id, req.expires_at
                    );
                    return Err(WorkflowError::ApprovalExpired(req.expires_at));
                }

                match req.status {
                    ManualApprovalStatus::Approved => {
                        debug!("Approval {} is granted", req.id);
                        Ok(true)
                    }
                    ManualApprovalStatus::Pending => {
                        debug!("Approval {} is still pending", req.id);
                        Ok(false)
                    }
                    ManualApprovalStatus::Denied => {
                        let reason = req
                            .decision_reason
                            .clone()
                            .unwrap_or_else(|| "No reason provided".to_string());
                        Err(WorkflowError::ManualApprovalDenied(reason))
                    }
                    ManualApprovalStatus::TimedOut => {
                        Err(WorkflowError::ApprovalExpired(req.expires_at))
                    }
                }
            }
        }
    }

    /// Processes stale approvals and marks them as timed out.
    ///
    /// Returns the number of approvals that were marked as timed out.
    pub fn process_stale_approvals(&mut self) -> usize {
        let now = Utc::now();
        let mut count = 0;

        for request in &mut self.approval_requests {
            if request.status == ManualApprovalStatus::Pending && now > request.expires_at {
                request.status = ManualApprovalStatus::TimedOut;
                request.decided_at = Some(now);
                request.decision_reason = Some("Approval request timed out".to_string());
                count += 1;
                warn!(
                    "Approval request {} for incident {} timed out",
                    request.id, request.incident_id
                );
            }
        }

        count
    }

    /// Checks if there are any pending approval requests.
    pub fn has_pending_approvals(&self) -> bool {
        self.approval_requests
            .iter()
            .any(|r| r.status == ManualApprovalStatus::Pending && Utc::now() <= r.expires_at)
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
    ///
    /// ## Authorization Requirements
    ///
    /// - Transitions to `Executing` require `ApproveActions` permission
    /// - Transitions to `Resolved` require `WriteIncidents` permission
    /// - All transitions are logged with actor identity for audit purposes
    ///
    /// ## Parameters
    ///
    /// - `incident`: The incident to transition
    /// - `to`: The target status
    /// - `auth_ctx`: Authorization context containing actor identity and permissions
    ///
    /// ## Returns
    ///
    /// Returns the list of transition actions to execute on success, or a
    /// `WorkflowError::Unauthorized` if the actor lacks required permissions.
    #[instrument(skip(self, incident, auth_ctx), fields(actor = %auth_ctx.actor_name))]
    pub fn transition(
        &mut self,
        incident: &mut Incident,
        to: IncidentStatus,
        auth_ctx: &AuthorizationContext,
    ) -> Result<Vec<TransitionAction>, WorkflowError> {
        let from = incident.status.clone();

        // Check authorization for sensitive transitions
        self.check_transition_authorization(&to, auth_ctx)?;

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
            if !self.evaluate_condition(condition, incident, &to)? {
                return Err(WorkflowError::ConditionNotMet(format!("{:?}", condition)));
            }
        }

        // Update incident status with actor identity for audit trail
        incident.update_status(to.clone(), &auth_ctx.audit_identity());

        // Update workflow state
        if let Some(state) = self.active_workflows.get_mut(&incident.id) {
            state.current_status = to.clone();
        }

        info!(
            "Transitioned incident {} from {:?} to {:?} by {} (role: {:?})",
            incident.id, from, to, auth_ctx.actor_name, auth_ctx.role
        );

        Ok(transition.actions)
    }

    /// Checks if the given authorization context has permission for the transition.
    ///
    /// ## Permission Requirements
    ///
    /// - `Executing`: Requires `ApproveActions` - allows execution of approved actions
    /// - `Resolved`: Requires `WriteIncidents` - allows marking incidents as resolved
    fn check_transition_authorization(
        &self,
        to: &IncidentStatus,
        auth_ctx: &AuthorizationContext,
    ) -> Result<(), WorkflowError> {
        let required_permission = match to {
            IncidentStatus::Executing => Some(Permission::ApproveActions),
            IncidentStatus::Resolved => Some(Permission::WriteIncidents),
            _ => None,
        };

        if let Some(permission) = required_permission {
            if !auth_ctx.has_permission(permission) {
                warn!(
                    "Authorization denied: actor {} (role: {:?}) attempted transition to {:?} without {} permission",
                    auth_ctx.actor_name, auth_ctx.role, to, permission
                );
                return Err(WorkflowError::Unauthorized {
                    action: format!("transition to {:?}", to),
                    required_permission: permission.to_string(),
                    actor: auth_ctx.audit_identity(),
                });
            }
        }

        Ok(())
    }

    /// Evaluates a transition condition.
    ///
    /// For `ManualApproval` conditions, this checks the workflow's approval state:
    /// - If approved: returns `Ok(true)` allowing the transition
    /// - If pending: returns `Ok(false)` blocking the transition
    /// - If denied or expired: returns an appropriate error
    fn evaluate_condition(
        &self,
        condition: &TransitionCondition,
        incident: &Incident,
        target_status: &IncidentStatus,
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
                // Check the workflow's approval state for this transition
                if let Some(state) = self.active_workflows.get(&incident.id) {
                    // Process any stale approvals first (check without mutating)
                    // The actual timeout processing happens in process_stale_approvals()
                    match state.check_approval_status(target_status) {
                        Ok(approved) => {
                            if approved {
                                debug!(
                                    "Manual approval granted for incident {} to {:?}",
                                    incident.id, target_status
                                );
                                Ok(true)
                            } else {
                                debug!(
                                    "Manual approval pending or not requested for incident {} to {:?}",
                                    incident.id, target_status
                                );
                                Ok(false)
                            }
                        }
                        Err(e) => {
                            warn!(
                                "Manual approval check failed for incident {}: {}",
                                incident.id, e
                            );
                            Err(e)
                        }
                    }
                } else {
                    // No workflow state found - approval not requested
                    debug!(
                        "No workflow state for incident {} - manual approval required",
                        incident.id
                    );
                    Ok(false)
                }
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
        self.transitions
            .iter()
            .filter(|t| &t.from == from)
            .collect()
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

    /// Requests manual approval for a workflow transition.
    ///
    /// This creates an approval request that must be granted before the
    /// transition can proceed. The workflow will be paused until approval
    /// is granted or denied.
    ///
    /// ## Parameters
    ///
    /// - `incident_id`: The incident requiring approval
    /// - `transition_to`: The target status for the transition
    /// - `auth_ctx`: Authorization context of the requester
    /// - `timeout_hours`: Optional custom timeout (defaults to 24 hours)
    ///
    /// ## Returns
    ///
    /// Returns the approval request ID on success.
    #[instrument(skip(self, auth_ctx), fields(actor = %auth_ctx.actor_name))]
    pub fn request_manual_approval(
        &mut self,
        incident_id: Uuid,
        transition_to: IncidentStatus,
        auth_ctx: &AuthorizationContext,
        timeout_hours: Option<i64>,
    ) -> Result<Uuid, WorkflowError> {
        let state = self
            .active_workflows
            .get_mut(&incident_id)
            .ok_or(WorkflowError::WorkflowNotFound(incident_id))?;

        let approval_id = state.request_approval(
            transition_to.clone(),
            &auth_ctx.audit_identity(),
            timeout_hours,
        );

        info!(
            "Manual approval {} requested by {} for incident {} to transition to {:?}",
            approval_id, auth_ctx.actor_name, incident_id, transition_to
        );

        Ok(approval_id)
    }

    /// Grants a manual approval request.
    ///
    /// ## Authorization
    ///
    /// The actor must have the `ApproveActions` permission to grant approvals.
    ///
    /// ## Parameters
    ///
    /// - `incident_id`: The incident with the approval request
    /// - `approval_id`: The specific approval request ID
    /// - `auth_ctx`: Authorization context of the approver
    /// - `reason`: Optional reason for granting approval
    #[instrument(skip(self, auth_ctx), fields(actor = %auth_ctx.actor_name))]
    pub fn grant_approval(
        &mut self,
        incident_id: Uuid,
        approval_id: Uuid,
        auth_ctx: &AuthorizationContext,
        reason: Option<String>,
    ) -> Result<(), WorkflowError> {
        // Check authorization
        if !auth_ctx.has_permission(Permission::ApproveActions) {
            return Err(WorkflowError::Unauthorized {
                action: "grant approval".to_string(),
                required_permission: Permission::ApproveActions.to_string(),
                actor: auth_ctx.audit_identity(),
            });
        }

        let state = self
            .active_workflows
            .get_mut(&incident_id)
            .ok_or(WorkflowError::WorkflowNotFound(incident_id))?;

        let request = state
            .get_approval_mut(approval_id)
            .ok_or(WorkflowError::ApprovalNotFound(approval_id))?;

        // Check if already decided
        if request.status != ManualApprovalStatus::Pending {
            return Err(WorkflowError::ApprovalAlreadyDecided(approval_id));
        }

        // Check if expired
        let now = Utc::now();
        if now > request.expires_at {
            request.status = ManualApprovalStatus::TimedOut;
            request.decided_at = Some(now);
            return Err(WorkflowError::ApprovalExpired(request.expires_at));
        }

        // Grant the approval
        request.status = ManualApprovalStatus::Approved;
        request.decided_by = Some(auth_ctx.audit_identity());
        request.decided_at = Some(now);
        request.decision_reason = reason.clone();

        // Resume the workflow if no other pending approvals
        if !state.has_pending_approvals() {
            state.resume();
        }

        info!(
            "Approval {} granted by {} for incident {}: {:?}",
            approval_id, auth_ctx.actor_name, incident_id, reason
        );

        Ok(())
    }

    /// Denies a manual approval request.
    ///
    /// ## Authorization
    ///
    /// The actor must have the `ApproveActions` permission to deny approvals.
    ///
    /// ## Parameters
    ///
    /// - `incident_id`: The incident with the approval request
    /// - `approval_id`: The specific approval request ID
    /// - `auth_ctx`: Authorization context of the denier
    /// - `reason`: Reason for denying (required)
    #[instrument(skip(self, auth_ctx), fields(actor = %auth_ctx.actor_name))]
    pub fn deny_approval(
        &mut self,
        incident_id: Uuid,
        approval_id: Uuid,
        auth_ctx: &AuthorizationContext,
        reason: String,
    ) -> Result<(), WorkflowError> {
        // Check authorization
        if !auth_ctx.has_permission(Permission::ApproveActions) {
            return Err(WorkflowError::Unauthorized {
                action: "deny approval".to_string(),
                required_permission: Permission::ApproveActions.to_string(),
                actor: auth_ctx.audit_identity(),
            });
        }

        let state = self
            .active_workflows
            .get_mut(&incident_id)
            .ok_or(WorkflowError::WorkflowNotFound(incident_id))?;

        let request = state
            .get_approval_mut(approval_id)
            .ok_or(WorkflowError::ApprovalNotFound(approval_id))?;

        // Check if already decided
        if request.status != ManualApprovalStatus::Pending {
            return Err(WorkflowError::ApprovalAlreadyDecided(approval_id));
        }

        // Deny the approval
        let now = Utc::now();
        request.status = ManualApprovalStatus::Denied;
        request.decided_by = Some(auth_ctx.audit_identity());
        request.decided_at = Some(now);
        request.decision_reason = Some(reason.clone());

        // Resume workflow (it will fail on next transition attempt due to denial)
        state.resume();

        warn!(
            "Approval {} denied by {} for incident {}: {}",
            approval_id, auth_ctx.actor_name, incident_id, reason
        );

        Ok(())
    }

    /// Processes all stale approval requests across all workflows.
    ///
    /// This should be called periodically to mark expired approvals as timed out.
    ///
    /// ## Returns
    ///
    /// Returns the total number of approvals that were marked as timed out.
    pub fn process_all_stale_approvals(&mut self) -> usize {
        let mut total = 0;
        for state in self.active_workflows.values_mut() {
            total += state.process_stale_approvals();
        }
        if total > 0 {
            info!("Processed {} stale approval requests", total);
        }
        total
    }

    /// Gets all pending approval requests across all workflows.
    pub fn get_all_pending_approvals(&self) -> Vec<&ManualApprovalRequest> {
        let now = Utc::now();
        self.active_workflows
            .values()
            .flat_map(|state| {
                state
                    .approval_requests
                    .iter()
                    .filter(|r| r.status == ManualApprovalStatus::Pending && now <= r.expires_at)
            })
            .collect()
    }

    /// Gets pending approval requests for a specific incident.
    pub fn get_pending_approvals_for_incident(
        &self,
        incident_id: Uuid,
    ) -> Result<Vec<&ManualApprovalRequest>, WorkflowError> {
        let state = self
            .active_workflows
            .get(&incident_id)
            .ok_or(WorkflowError::WorkflowNotFound(incident_id))?;

        let now = Utc::now();
        Ok(state
            .approval_requests
            .iter()
            .filter(|r| r.status == ManualApprovalStatus::Pending && now <= r.expires_at)
            .collect())
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
    use crate::auth::{Role, User};
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

    fn create_analyst_context() -> AuthorizationContext {
        let user = User::new("analyst@test.com", "analyst", "hash", Role::Analyst);
        AuthorizationContext::from_user(&user)
    }

    fn create_viewer_context() -> AuthorizationContext {
        let user = User::new("viewer@test.com", "viewer", "hash", Role::Viewer);
        AuthorizationContext::from_user(&user)
    }

    fn create_admin_context() -> AuthorizationContext {
        let user = User::new("admin@test.com", "admin", "hash", Role::Admin);
        AuthorizationContext::from_user(&user)
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
        let auth_ctx = create_analyst_context();
        engine.register_workflow(&incident);

        // New -> Enriching should succeed
        let result = engine.transition(&mut incident, IncidentStatus::Enriching, &auth_ctx);
        assert!(result.is_ok());
        assert_eq!(incident.status, IncidentStatus::Enriching);
    }

    #[test]
    fn test_invalid_transition() {
        let mut engine = WorkflowEngine::new();
        let mut incident = create_test_incident();
        let auth_ctx = create_analyst_context();
        engine.register_workflow(&incident);

        // New -> Resolved should fail (not a valid direct transition)
        let result = engine.transition(&mut incident, IncidentStatus::Resolved, &auth_ctx);
        assert!(result.is_err());
    }

    #[test]
    fn test_condition_not_met() {
        let mut engine = WorkflowEngine::new();
        let mut incident = create_test_incident();
        let auth_ctx = create_analyst_context();
        engine.register_workflow(&incident);

        // Transition to Enriching first
        engine
            .transition(&mut incident, IncidentStatus::Enriching, &auth_ctx)
            .unwrap();

        // Enriching -> Analyzing should fail without enrichments
        let result = engine.transition(&mut incident, IncidentStatus::Analyzing, &auth_ctx);
        assert!(matches!(result, Err(WorkflowError::ConditionNotMet(_))));
    }

    #[test]
    fn test_condition_met() {
        let mut engine = WorkflowEngine::new();
        let mut incident = create_test_incident();
        let auth_ctx = create_analyst_context();
        engine.register_workflow(&incident);

        // Transition to Enriching
        engine
            .transition(&mut incident, IncidentStatus::Enriching, &auth_ctx)
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
        let result = engine.transition(&mut incident, IncidentStatus::Analyzing, &auth_ctx);
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

    // ============================================================
    // Authorization Tests
    // ============================================================

    #[test]
    fn test_transition_to_executing_requires_approve_actions() {
        let mut engine = WorkflowEngine::new();
        let mut incident = create_test_incident();
        let viewer_ctx = create_viewer_context();
        let analyst_ctx = create_analyst_context();
        engine.register_workflow(&incident);

        // Setup: Get to PendingApproval state
        engine
            .transition(&mut incident, IncidentStatus::Enriching, &analyst_ctx)
            .unwrap();
        incident.add_enrichment(Enrichment {
            enrichment_type: EnrichmentType::ThreatIntel,
            source: "test".to_string(),
            data: serde_json::json!({}),
            timestamp: Utc::now(),
            ttl_seconds: None,
        });
        engine
            .transition(&mut incident, IncidentStatus::Analyzing, &analyst_ctx)
            .unwrap();
        incident.set_analysis(crate::incident::TriageAnalysis {
            verdict: crate::incident::TriageVerdict::TruePositive,
            confidence: 0.9,
            summary: "Test".to_string(),
            reasoning: "Test".to_string(),
            mitre_techniques: vec![],
            iocs: vec![],
            recommendations: vec![],
            risk_score: 80,
            analyzed_by: "test".to_string(),
            timestamp: Utc::now(),
        });
        engine
            .transition(&mut incident, IncidentStatus::PendingReview, &analyst_ctx)
            .unwrap();
        engine
            .transition(&mut incident, IncidentStatus::PendingApproval, &analyst_ctx)
            .unwrap();

        // Mark all actions as reviewed (empty list means all reviewed)
        // Viewer should NOT be able to transition to Executing
        let result = engine.transition(&mut incident, IncidentStatus::Executing, &viewer_ctx);
        assert!(matches!(result, Err(WorkflowError::Unauthorized { .. })));

        // Analyst SHOULD be able to transition to Executing (has ApproveActions permission)
        let result = engine.transition(&mut incident, IncidentStatus::Executing, &analyst_ctx);
        assert!(result.is_ok());
    }

    #[test]
    fn test_transition_to_resolved_requires_write_incidents() {
        let mut engine = WorkflowEngine::new();
        let mut incident = create_test_incident();
        let viewer_ctx = create_viewer_context();
        let analyst_ctx = create_analyst_context();
        engine.register_workflow(&incident);

        // Setup: Get to Executing state (using analyst who has permissions)
        engine
            .transition(&mut incident, IncidentStatus::Enriching, &analyst_ctx)
            .unwrap();
        incident.add_enrichment(Enrichment {
            enrichment_type: EnrichmentType::ThreatIntel,
            source: "test".to_string(),
            data: serde_json::json!({}),
            timestamp: Utc::now(),
            ttl_seconds: None,
        });
        engine
            .transition(&mut incident, IncidentStatus::Analyzing, &analyst_ctx)
            .unwrap();
        incident.set_analysis(crate::incident::TriageAnalysis {
            verdict: crate::incident::TriageVerdict::TruePositive,
            confidence: 0.9,
            summary: "Test".to_string(),
            reasoning: "Test".to_string(),
            mitre_techniques: vec![],
            iocs: vec![],
            recommendations: vec![],
            risk_score: 80,
            analyzed_by: "test".to_string(),
            timestamp: Utc::now(),
        });
        engine
            .transition(&mut incident, IncidentStatus::PendingReview, &analyst_ctx)
            .unwrap();
        engine
            .transition(&mut incident, IncidentStatus::PendingApproval, &analyst_ctx)
            .unwrap();
        engine
            .transition(&mut incident, IncidentStatus::Executing, &analyst_ctx)
            .unwrap();

        // Viewer should NOT be able to transition to Resolved
        let result = engine.transition(&mut incident, IncidentStatus::Resolved, &viewer_ctx);
        assert!(matches!(result, Err(WorkflowError::Unauthorized { .. })));

        // Analyst SHOULD be able to transition to Resolved (has WriteIncidents permission)
        let result = engine.transition(&mut incident, IncidentStatus::Resolved, &analyst_ctx);
        assert!(result.is_ok());
    }

    #[test]
    fn test_admin_can_perform_all_transitions() {
        let mut engine = WorkflowEngine::new();
        let mut incident = create_test_incident();
        let admin_ctx = create_admin_context();
        engine.register_workflow(&incident);

        // Admin should be able to do all transitions
        engine
            .transition(&mut incident, IncidentStatus::Enriching, &admin_ctx)
            .unwrap();
        incident.add_enrichment(Enrichment {
            enrichment_type: EnrichmentType::ThreatIntel,
            source: "test".to_string(),
            data: serde_json::json!({}),
            timestamp: Utc::now(),
            ttl_seconds: None,
        });
        engine
            .transition(&mut incident, IncidentStatus::Analyzing, &admin_ctx)
            .unwrap();
        incident.set_analysis(crate::incident::TriageAnalysis {
            verdict: crate::incident::TriageVerdict::TruePositive,
            confidence: 0.9,
            summary: "Test".to_string(),
            reasoning: "Test".to_string(),
            mitre_techniques: vec![],
            iocs: vec![],
            recommendations: vec![],
            risk_score: 80,
            analyzed_by: "test".to_string(),
            timestamp: Utc::now(),
        });
        engine
            .transition(&mut incident, IncidentStatus::PendingReview, &admin_ctx)
            .unwrap();
        engine
            .transition(&mut incident, IncidentStatus::PendingApproval, &admin_ctx)
            .unwrap();
        engine
            .transition(&mut incident, IncidentStatus::Executing, &admin_ctx)
            .unwrap();
        engine
            .transition(&mut incident, IncidentStatus::Resolved, &admin_ctx)
            .unwrap();

        assert_eq!(incident.status, IncidentStatus::Resolved);
    }

    #[test]
    fn test_system_context_can_perform_all_transitions() {
        let mut engine = WorkflowEngine::new();
        let mut incident = create_test_incident();
        let system_ctx = AuthorizationContext::system();
        engine.register_workflow(&incident);

        // System context should be able to do all transitions
        let result = engine.transition(&mut incident, IncidentStatus::Enriching, &system_ctx);
        assert!(result.is_ok());
        assert_eq!(incident.status, IncidentStatus::Enriching);
    }

    #[test]
    fn test_audit_log_includes_actor_identity() {
        let mut engine = WorkflowEngine::new();
        let mut incident = create_test_incident();
        let analyst_ctx = create_analyst_context();
        engine.register_workflow(&incident);

        let initial_audit_count = incident.audit_log.len();

        // Perform transition
        engine
            .transition(&mut incident, IncidentStatus::Enriching, &analyst_ctx)
            .unwrap();

        // Check that audit log was updated with actor identity
        assert!(incident.audit_log.len() > initial_audit_count);
        let last_entry = incident.audit_log.last().unwrap();
        assert!(last_entry.actor.contains("analyst"));
    }

    #[test]
    fn test_unauthorized_error_contains_useful_info() {
        let mut engine = WorkflowEngine::new();
        let mut incident = create_test_incident();
        let viewer_ctx = create_viewer_context();
        let analyst_ctx = create_analyst_context();
        engine.register_workflow(&incident);

        // Setup: Get to PendingApproval state
        engine
            .transition(&mut incident, IncidentStatus::Enriching, &analyst_ctx)
            .unwrap();
        incident.add_enrichment(Enrichment {
            enrichment_type: EnrichmentType::ThreatIntel,
            source: "test".to_string(),
            data: serde_json::json!({}),
            timestamp: Utc::now(),
            ttl_seconds: None,
        });
        engine
            .transition(&mut incident, IncidentStatus::Analyzing, &analyst_ctx)
            .unwrap();
        incident.set_analysis(crate::incident::TriageAnalysis {
            verdict: crate::incident::TriageVerdict::TruePositive,
            confidence: 0.9,
            summary: "Test".to_string(),
            reasoning: "Test".to_string(),
            mitre_techniques: vec![],
            iocs: vec![],
            recommendations: vec![],
            risk_score: 80,
            analyzed_by: "test".to_string(),
            timestamp: Utc::now(),
        });
        engine
            .transition(&mut incident, IncidentStatus::PendingReview, &analyst_ctx)
            .unwrap();
        engine
            .transition(&mut incident, IncidentStatus::PendingApproval, &analyst_ctx)
            .unwrap();

        // Try unauthorized transition
        let result = engine.transition(&mut incident, IncidentStatus::Executing, &viewer_ctx);

        match result {
            Err(WorkflowError::Unauthorized {
                action,
                required_permission,
                actor,
            }) => {
                assert!(action.contains("Executing"));
                assert!(required_permission.contains("approve_actions"));
                assert!(actor.contains("viewer"));
            }
            _ => panic!("Expected Unauthorized error"),
        }
    }

    // ============================================================
    // Manual Approval Tests
    // ============================================================

    #[test]
    fn test_request_manual_approval() {
        let mut engine = WorkflowEngine::new();
        let incident = create_test_incident();
        let analyst_ctx = create_analyst_context();
        engine.register_workflow(&incident);

        // Request manual approval
        let approval_id = engine
            .request_manual_approval(
                incident.id,
                IncidentStatus::Executing,
                &analyst_ctx,
                None, // Use default timeout
            )
            .unwrap();

        // Verify approval request was created
        let state = engine.get_workflow(incident.id).unwrap();
        assert!(state.paused);
        assert_eq!(state.approval_requests.len(), 1);

        let request = &state.approval_requests[0];
        assert_eq!(request.id, approval_id);
        assert_eq!(request.status, ManualApprovalStatus::Pending);
        assert_eq!(request.transition_to, IncidentStatus::Executing);
        assert!(request.requested_by.contains("analyst"));
    }

    #[test]
    fn test_grant_approval() {
        let mut engine = WorkflowEngine::new();
        let incident = create_test_incident();
        let analyst_ctx = create_analyst_context();
        let admin_ctx = create_admin_context();
        engine.register_workflow(&incident);

        // Request manual approval
        let approval_id = engine
            .request_manual_approval(incident.id, IncidentStatus::Executing, &analyst_ctx, None)
            .unwrap();

        // Grant approval (admin has ApproveActions permission)
        let result = engine.grant_approval(
            incident.id,
            approval_id,
            &admin_ctx,
            Some("Approved after review".to_string()),
        );
        assert!(result.is_ok());

        // Verify approval status
        let state = engine.get_workflow(incident.id).unwrap();
        let request = state.get_approval(approval_id).unwrap();
        assert_eq!(request.status, ManualApprovalStatus::Approved);
        assert!(request.decided_by.as_ref().unwrap().contains("admin"));
        assert!(request.decided_at.is_some());
        assert_eq!(
            request.decision_reason,
            Some("Approved after review".to_string())
        );

        // Workflow should be resumed
        assert!(!state.paused);
    }

    #[test]
    fn test_deny_approval() {
        let mut engine = WorkflowEngine::new();
        let incident = create_test_incident();
        let analyst_ctx = create_analyst_context();
        engine.register_workflow(&incident);

        // Request and deny approval
        let approval_id = engine
            .request_manual_approval(incident.id, IncidentStatus::Executing, &analyst_ctx, None)
            .unwrap();

        let result = engine.deny_approval(
            incident.id,
            approval_id,
            &analyst_ctx,
            "Risk too high".to_string(),
        );
        assert!(result.is_ok());

        // Verify denial
        let state = engine.get_workflow(incident.id).unwrap();
        let request = state.get_approval(approval_id).unwrap();
        assert_eq!(request.status, ManualApprovalStatus::Denied);
        assert_eq!(request.decision_reason, Some("Risk too high".to_string()));
    }

    #[test]
    fn test_viewer_cannot_grant_approval() {
        let mut engine = WorkflowEngine::new();
        let incident = create_test_incident();
        let analyst_ctx = create_analyst_context();
        let viewer_ctx = create_viewer_context();
        engine.register_workflow(&incident);

        let approval_id = engine
            .request_manual_approval(incident.id, IncidentStatus::Executing, &analyst_ctx, None)
            .unwrap();

        // Viewer should not be able to grant approval
        let result = engine.grant_approval(incident.id, approval_id, &viewer_ctx, None);
        assert!(matches!(result, Err(WorkflowError::Unauthorized { .. })));

        // Approval should still be pending
        let state = engine.get_workflow(incident.id).unwrap();
        let request = state.get_approval(approval_id).unwrap();
        assert_eq!(request.status, ManualApprovalStatus::Pending);
    }

    #[test]
    fn test_approval_blocks_transition_until_granted() {
        let mut engine = WorkflowEngine::new();
        let mut incident = create_test_incident();
        let analyst_ctx = create_analyst_context();

        // Add a transition that requires manual approval
        engine.transitions.push(WorkflowTransition {
            from: IncidentStatus::New,
            to: IncidentStatus::PendingReview,
            condition: Some(TransitionCondition::ManualApproval),
            actions: vec![],
        });

        engine.register_workflow(&incident);

        // Transition should fail without approval
        let result = engine.transition(&mut incident, IncidentStatus::PendingReview, &analyst_ctx);
        assert!(matches!(result, Err(WorkflowError::ConditionNotMet(_))));

        // Request approval
        let approval_id = engine
            .request_manual_approval(
                incident.id,
                IncidentStatus::PendingReview,
                &analyst_ctx,
                None,
            )
            .unwrap();

        // Transition should still fail (pending)
        let result = engine.transition(&mut incident, IncidentStatus::PendingReview, &analyst_ctx);
        assert!(matches!(result, Err(WorkflowError::ConditionNotMet(_))));

        // Grant approval
        engine
            .grant_approval(incident.id, approval_id, &analyst_ctx, None)
            .unwrap();

        // Now transition should succeed
        let result = engine.transition(&mut incident, IncidentStatus::PendingReview, &analyst_ctx);
        assert!(result.is_ok());
        assert_eq!(incident.status, IncidentStatus::PendingReview);
    }

    #[test]
    fn test_denied_approval_causes_transition_error() {
        let mut engine = WorkflowEngine::new();
        let mut incident = create_test_incident();
        let analyst_ctx = create_analyst_context();

        // Add a transition that requires manual approval
        engine.transitions.push(WorkflowTransition {
            from: IncidentStatus::New,
            to: IncidentStatus::PendingReview,
            condition: Some(TransitionCondition::ManualApproval),
            actions: vec![],
        });

        engine.register_workflow(&incident);

        // Request and deny approval
        let approval_id = engine
            .request_manual_approval(
                incident.id,
                IncidentStatus::PendingReview,
                &analyst_ctx,
                None,
            )
            .unwrap();

        engine
            .deny_approval(
                incident.id,
                approval_id,
                &analyst_ctx,
                "Denied for testing".to_string(),
            )
            .unwrap();

        // Transition should fail with denial error
        let result = engine.transition(&mut incident, IncidentStatus::PendingReview, &analyst_ctx);
        assert!(matches!(
            result,
            Err(WorkflowError::ManualApprovalDenied(_))
        ));
    }

    #[test]
    fn test_approval_timeout() {
        let mut state = WorkflowState::new(Uuid::new_v4());

        // Create an already-expired approval request manually
        let now = Utc::now();
        let request = ManualApprovalRequest {
            id: Uuid::new_v4(),
            incident_id: state.incident_id,
            transition_to: IncidentStatus::Executing,
            status: ManualApprovalStatus::Pending,
            requested_by: "test".to_string(),
            requested_at: now - Duration::hours(25),
            expires_at: now - Duration::hours(1), // Already expired
            decided_by: None,
            decided_at: None,
            decision_reason: None,
        };
        state.approval_requests.push(request);

        // Check approval status should return expired error
        let result = state.check_approval_status(&IncidentStatus::Executing);
        assert!(matches!(result, Err(WorkflowError::ApprovalExpired(_))));
    }

    #[test]
    fn test_process_stale_approvals() {
        let mut engine = WorkflowEngine::new();
        let incident = create_test_incident();
        engine.register_workflow(&incident);

        // Manually add an expired approval request
        let now = Utc::now();
        let state = engine.get_workflow_mut(incident.id).unwrap();
        state.approval_requests.push(ManualApprovalRequest {
            id: Uuid::new_v4(),
            incident_id: incident.id,
            transition_to: IncidentStatus::Executing,
            status: ManualApprovalStatus::Pending,
            requested_by: "test".to_string(),
            requested_at: now - Duration::hours(25),
            expires_at: now - Duration::hours(1),
            decided_by: None,
            decided_at: None,
            decision_reason: None,
        });

        // Process stale approvals
        let count = engine.process_all_stale_approvals();
        assert_eq!(count, 1);

        // Verify the approval was marked as timed out
        let state = engine.get_workflow(incident.id).unwrap();
        assert_eq!(
            state.approval_requests[0].status,
            ManualApprovalStatus::TimedOut
        );
    }

    #[test]
    fn test_cannot_grant_already_decided_approval() {
        let mut engine = WorkflowEngine::new();
        let incident = create_test_incident();
        let analyst_ctx = create_analyst_context();
        engine.register_workflow(&incident);

        let approval_id = engine
            .request_manual_approval(incident.id, IncidentStatus::Executing, &analyst_ctx, None)
            .unwrap();

        // Grant approval first time
        engine
            .grant_approval(incident.id, approval_id, &analyst_ctx, None)
            .unwrap();

        // Trying to grant again should fail
        let result = engine.grant_approval(incident.id, approval_id, &analyst_ctx, None);
        assert!(matches!(
            result,
            Err(WorkflowError::ApprovalAlreadyDecided(_))
        ));
    }

    #[test]
    fn test_get_all_pending_approvals() {
        let mut engine = WorkflowEngine::new();
        let incident1 = create_test_incident();
        let incident2 = create_test_incident();
        let analyst_ctx = create_analyst_context();

        engine.register_workflow(&incident1);
        engine.register_workflow(&incident2);

        // Request approvals for both incidents
        engine
            .request_manual_approval(incident1.id, IncidentStatus::Executing, &analyst_ctx, None)
            .unwrap();
        engine
            .request_manual_approval(
                incident2.id,
                IncidentStatus::PendingReview,
                &analyst_ctx,
                None,
            )
            .unwrap();

        // Get all pending approvals
        let pending = engine.get_all_pending_approvals();
        assert_eq!(pending.len(), 2);
    }

    #[test]
    fn test_custom_approval_timeout() {
        let mut engine = WorkflowEngine::new();
        let incident = create_test_incident();
        let analyst_ctx = create_analyst_context();
        engine.register_workflow(&incident);

        // Request approval with custom 1-hour timeout
        engine
            .request_manual_approval(
                incident.id,
                IncidentStatus::Executing,
                &analyst_ctx,
                Some(1),
            )
            .unwrap();

        let state = engine.get_workflow(incident.id).unwrap();
        let request = &state.approval_requests[0];

        // Verify custom timeout was set (approximately 1 hour from now)
        let time_diff = request.expires_at - request.requested_at;
        assert!(time_diff >= Duration::minutes(59));
        assert!(time_diff <= Duration::minutes(61));
    }

    #[test]
    fn test_workflow_state_has_pending_approvals() {
        let mut state = WorkflowState::new(Uuid::new_v4());

        // Initially no pending approvals
        assert!(!state.has_pending_approvals());

        // Request approval
        state.request_approval(IncidentStatus::Executing, "test", None);

        // Now should have pending approvals
        assert!(state.has_pending_approvals());
    }

    #[test]
    fn test_approval_request_not_found() {
        let mut engine = WorkflowEngine::new();
        let incident = create_test_incident();
        let analyst_ctx = create_analyst_context();
        engine.register_workflow(&incident);

        // Try to grant non-existent approval
        let result = engine.grant_approval(incident.id, Uuid::new_v4(), &analyst_ctx, None);
        assert!(matches!(result, Err(WorkflowError::ApprovalNotFound(_))));
    }

    #[test]
    fn test_workflow_not_found_for_approval() {
        let mut engine = WorkflowEngine::new();
        let analyst_ctx = create_analyst_context();

        // Try to request approval for non-existent workflow
        let result = engine.request_manual_approval(
            Uuid::new_v4(),
            IncidentStatus::Executing,
            &analyst_ctx,
            None,
        );
        assert!(matches!(result, Err(WorkflowError::WorkflowNotFound(_))));
    }
}
