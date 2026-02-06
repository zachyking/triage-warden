//! Notification rules engine for Triage Warden.
//!
//! This module extends the base notification channel system with a rules engine
//! that evaluates events against configurable conditions and dispatches
//! notifications to the appropriate channels.

pub mod rules;

pub use rules::{
    ChannelConfig, ConditionOperator, NotificationCondition, NotificationEngine,
    NotificationHistory, NotificationRule, NotificationTrigger, ThrottleConfig,
};
