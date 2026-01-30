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
    ActionResult,
    Connector,
    ConnectorConfig,
    ConnectorError,
    ConnectorHealth,
    ConnectorResult,
    // Ticketing
    CreateTicketRequest,
    Detection,
    // EDR
    EDRConnector,
    EmailAttachment,
    // Email Gateway
    EmailGatewayConnector,
    EmailMessage,
    EmailSearchQuery,
    EmailThreatData,
    HostInfo,
    HostStatus,
    IndicatorType,
    SIEMAlert,
    // SIEM
    SIEMConnector,
    SIEMEvent,
    SearchResults,
    ThreatAssessment,
    // Threat Intel
    ThreatIntelConnector,
    ThreatIntelResult,
    ThreatVerdict,
    Ticket,
    TicketPriority,
    TicketingConnector,
    TimeRange,
    UpdateTicketRequest,
};

// Re-export connector implementations
pub use edr::{CrowdStrikeConfig, CrowdStrikeConnector, MockEDRConnector};
pub use email::{M365Config, M365Connector};
pub use siem::{MockSIEMConnector, SplunkConfig, SplunkConnector};
pub use threat_intel::{MockThreatIntelConnector, VirusTotalConfig, VirusTotalConnector};
pub use ticketing::{JiraConfig, JiraConnector, MockTicketingConnector};
