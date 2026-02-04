//! Mock implementations of repository traits for testing.
//!
//! These mocks use in-memory storage and do not require a database connection.
//! They are useful for unit testing route handlers, services, and other components
//! that depend on repositories.

mod api_key_repo;
mod connector_repo;
mod incident_repo;
mod tenant_repo;
mod user_repo;

pub use api_key_repo::MockApiKeyRepository;
pub use connector_repo::MockConnectorRepository;
pub use incident_repo::MockIncidentRepository;
pub use tenant_repo::MockTenantRepository;
pub use user_repo::MockUserRepository;
