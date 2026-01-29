//! # tw-policy
//!
//! Policy engine and guardrails for Triage Warden.
//!
//! This crate provides the policy evaluation engine, rule definitions,
//! and approval workflows for controlling automated actions.

pub mod approval;
pub mod engine;
pub mod rules;

pub use approval::{ApprovalLevel, ApprovalRequest, ApprovalWorkflow};
pub use engine::{PolicyDecision, PolicyEngine};
pub use rules::{PolicyRule, RuleCondition, RuleEffect};
