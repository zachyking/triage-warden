//! Ticketing system connectors.

pub mod jira;
pub mod mock;

pub use jira::JiraConnector;
pub use mock::MockTicketingConnector;
