//! Email gateway connectors.

pub mod m365;
pub mod mock;

pub use m365::{M365Config, M365Connector};
pub use mock::MockEmailGatewayConnector;
