//! # tw-policy
//!
//! Policy engine and guardrails for Triage Warden.
//!
//! This crate provides the policy evaluation engine, rule definitions,
//! approval workflows, and data sanitization for controlling automated actions.

pub mod approval;
pub mod approval_manager;
pub mod config;
pub mod engine;
pub mod escalation;
pub mod kill_switch;
pub mod mode;
pub mod notifications;
pub mod rules;
pub mod sanitization;

pub use approval::{ApprovalLevel, ApprovalRequest, ApprovalWorkflow};
pub use approval_manager::{
    ApprovalError as ApprovalManagerError, ApprovalManager,
    ApprovalRequest as ManagedApprovalRequest, ApprovalStatus as ManagedApprovalStatus,
};
pub use config::{load_guardrails, ConfigError, GuardrailsConfig};
pub use engine::{PolicyDecision, PolicyEngine};
pub use escalation::{
    EscalationAction, EscalationCondition, EscalationManager, EscalationRule, FalsePositiveStats,
    IncidentContext,
};
pub use kill_switch::{
    KillSwitch, KillSwitchActive, KillSwitchError, KillSwitchEvent, KillSwitchStatus,
};
pub use mode::{ActionRisk, ModeChange, ModeManager, OperationMode};
pub use notifications::{
    CompositeNotifier, LogNotifier, Notification, NotificationError, NotificationPriority,
    NotificationType, Notifier, SlackNotifier, WebhookNotifier,
};
pub use rules::{PolicyRule, RuleCondition, RuleEffect};
pub use sanitization::{SanitizationError, SanitizationResult, Sanitizer};
