//! EDR connectors.

pub mod carbon_black;
pub mod crowdstrike;
pub mod defender_endpoint;
pub mod mock;
pub mod sentinelone;

pub use carbon_black::{CarbonBlackConfig, CarbonBlackConnector};
pub use crowdstrike::{CrowdStrikeConfig, CrowdStrikeConnector};
pub use defender_endpoint::{DefenderEndpointConfig, DefenderEndpointConnector};
pub use mock::MockEDRConnector;
pub use sentinelone::{SentinelOneConfig, SentinelOneConnector};
