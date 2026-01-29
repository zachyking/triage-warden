//! # tw-policy
//!
//! Policy engine and guardrails for Triage Warden.
//!
//! This crate provides the policy evaluation engine, rule definitions,
//! approval workflows, and data sanitization for controlling automated actions.

pub mod approval;
pub mod config;
pub mod engine;
pub mod rules;
pub mod sanitization;

pub use approval::{ApprovalLevel, ApprovalRequest, ApprovalWorkflow};
pub use config::{load_guardrails, ConfigError, GuardrailsConfig};
pub use engine::{PolicyDecision, PolicyEngine};
pub use rules::{PolicyRule, RuleCondition, RuleEffect};
pub use sanitization::{SanitizationError, SanitizationResult, Sanitizer};
