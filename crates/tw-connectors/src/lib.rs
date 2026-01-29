//! # tw-connectors
//!
//! Integration connectors for SIEM, EDR, ticketing, and threat intel systems.
//!
//! This crate provides the trait definitions and implementations for connecting
//! to external security tools and services.

pub mod edr;
pub mod http;
pub mod siem;
pub mod threat_intel;
pub mod ticketing;
pub mod traits;

pub use traits::{
    Connector, ConnectorConfig, ConnectorError, ConnectorHealth, ConnectorResult, CreateTicketRequest,
    EDRConnector, SIEMConnector, ThreatIntelConnector, TicketPriority, TicketingConnector,
    UpdateTicketRequest, Ticket,
};
