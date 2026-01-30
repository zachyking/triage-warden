//! EDR connectors.

pub mod crowdstrike;
pub mod mock;

pub use crowdstrike::{CrowdStrikeConfig, CrowdStrikeConnector};
pub use mock::MockEDRConnector;
