//! Identity provider connectors.

pub mod auth0;
pub mod duo;
pub mod mock;
pub mod okta;

pub use auth0::{Auth0Config, Auth0Connector};
pub use duo::{DuoConfig, DuoConnector};
pub use mock::MockIdentityConnector;
pub use okta::{OktaConfig, OktaConnector};
