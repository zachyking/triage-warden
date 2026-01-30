//! SIEM connectors.

pub mod mock;
pub mod splunk;

pub use mock::MockSIEMConnector;
pub use splunk::{SplunkConfig, SplunkConnector};
