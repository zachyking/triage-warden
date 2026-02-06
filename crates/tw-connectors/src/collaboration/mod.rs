//! Collaboration tool connectors (Slack, Microsoft Teams).
//!
//! This module provides connectors for sending notifications and interactive
//! messages to collaboration platforms used by security teams.

pub mod mock;
pub mod slack;
pub mod teams;

pub use mock::MockCollaborationConnector;
pub use slack::{SlackConfig, SlackConnector};
pub use teams::{TeamsConfig, TeamsConnector};
