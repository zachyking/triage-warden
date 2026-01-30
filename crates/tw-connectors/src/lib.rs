//! # tw-connectors
//!
//! Integration connectors for SIEM, EDR, ticketing, email gateway, and threat intel systems.
//!
//! This crate provides the trait definitions and implementations for connecting
//! to external security tools and services.

pub mod edr;
pub mod email;
pub mod http;
pub mod siem;
pub mod threat_intel;
pub mod ticketing;
pub mod traits;

// Re-export traits
pub use traits::{
    Connector, ConnectorConfig, ConnectorError, ConnectorHealth, ConnectorResult,
    // Ticketing
    CreateTicketRequest, Ticket, TicketPriority, TicketingConnector, UpdateTicketRequest,
    // Threat Intel
    ThreatIntelConnector, ThreatIntelResult, ThreatVerdict, IndicatorType,
    // SIEM
    SIEMConnector, SIEMAlert, SIEMEvent, SearchResults, TimeRange,
    // EDR
    EDRConnector, HostInfo, HostStatus, Detection, ActionResult,
    // Email Gateway
    EmailGatewayConnector, EmailMessage, EmailSearchQuery, EmailAttachment,
    EmailThreatData, ThreatAssessment,
};

// Re-export connector implementations
pub use edr::{CrowdStrikeConfig, CrowdStrikeConnector, MockEDRConnector};
pub use email::{M365Config, M365Connector};
pub use siem::{MockSIEMConnector, SplunkConfig, SplunkConnector};
pub use threat_intel::{MockThreatIntelConnector, VirusTotalConfig, VirusTotalConnector};
pub use ticketing::{JiraConfig, JiraConnector, MockTicketingConnector};
