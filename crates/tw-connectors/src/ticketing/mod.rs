//! Ticketing system connectors.

pub mod jira;
pub mod mock;

pub use jira::{JiraConfig, JiraConnector};
pub use mock::MockTicketingConnector;
