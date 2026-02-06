//! # tw-connectors
//!
//! Integration connectors for SIEM, EDR, ticketing, email gateway, threat intel,
//! and cloud security systems.
//!
//! This crate provides the trait definitions and implementations for connecting
//! to external security tools and services.

pub mod asm;
pub mod cloud;
pub mod collaboration;
pub mod edr;
pub mod email;
pub mod http;
pub mod identity;
pub mod itsm;
pub mod network;
pub mod sandbox;
pub mod secure_string;
pub mod siem;
pub mod testing;
pub mod threat_intel;
pub mod ticketing;
pub mod traits;
pub mod vulnerability;

// Re-export SecureString at the crate root
pub use secure_string::SecureString;

// Re-export traits
pub use traits::{
    // Response actions
    Action,
    ActionExecutor,
    ActionResult,
    ActionType,
    // Alert source
    AlertSource,
    // Auth
    AuthConfig,
    // Identity
    AuthLogEntry,
    // CMDB
    CMDBAsset,
    ConnectionTestResult,
    Connector,
    ConnectorCategory,
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
    // Enrichment
    Enricher,
    EnrichmentResult,
    HostInfo,
    HostStatus,
    // ITSM
    ITSMConnector,
    ITSMIncident,
    IdentityConnector,
    IdentityUser,
    IndicatorType,
    // IOC types
    Ioc,
    IocType,
    // Network Security
    NetworkEvent,
    NetworkSecurityConnector,
    // On-call
    OnCallInfo,
    // Raw alerts
    RawAlert,
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
pub use edr::{
    CarbonBlackConfig, CarbonBlackConnector, CrowdStrikeConfig, CrowdStrikeConnector,
    DefenderEndpointConfig, DefenderEndpointConnector, MockEDRConnector, SentinelOneConfig,
    SentinelOneConnector,
};
pub use email::{M365Config, M365Connector, MockEmailGatewayConnector};
pub use identity::{
    Auth0Config, Auth0Connector, DuoConfig, DuoConnector, MockIdentityConnector, OktaConfig,
    OktaConnector,
};
pub use itsm::{
    MockITSMConnector, OpsgenieConfig, OpsgenieConnector, PagerDutyConfig, PagerDutyConnector,
    ServiceNowConfig, ServiceNowConnector,
};
pub use network::{
    MockNetworkConnector, PaloAltoConfig, PaloAltoConnector, UmbrellaConfig, UmbrellaConnector,
    ZscalerConfig, ZscalerConnector,
};
pub use sandbox::{
    MalwareSandbox, MockSandboxConnector, SandboxReport, SandboxVerdict, SubmissionId,
    SubmissionOptions,
};
pub use siem::{
    ChronicleConfig, ChronicleConnector, ElasticConfig, ElasticConnector, MockSIEMConnector,
    QRadarConfig, QRadarConnector, SplunkConfig, SplunkConnector,
};
pub use threat_intel::{
    AbusechConfig, AbusechConnector, AggregatedIntelResult, AggregatorConfig, AlienVaultConfig,
    AlienVaultConnector, GreyNoiseConfig, GreyNoiseConnector, MispConfig, MispConnector,
    MockThreatIntelConnector, ShodanConfig, ShodanConnector, ThreatIntelAggregator,
    VirusTotalConfig, VirusTotalConnector, XForceConfig, XForceConnector,
};
pub use ticketing::{JiraConfig, JiraConnector, MockTicketingConnector};

// Re-export cloud connectors
pub use cloud::{
    aws::{CloudTrailConnector, GuardDutyConnector, SecurityHubConnector},
    azure::{DefenderConnector, EntraIdConnector, SentinelConnector},
    gcp::SCCConnector,
    mock::MockCloudConnector,
};

// Re-export collaboration connectors
pub use collaboration::{
    MockCollaborationConnector, SlackConfig, SlackConnector, TeamsConfig, TeamsConnector,
};

// Re-export vulnerability scanner connectors
pub use vulnerability::{
    qualys::QualysConnector, rapid7::Rapid7Connector, tenable::TenableConnector,
};
pub use vulnerability::{
    MockVulnerabilityScanner, ScanResult, ScanStatus, VulnSeverity, VulnStatus, Vulnerability,
    VulnerabilityScanner,
};

// Re-export ASM connectors
pub use asm::{censys::CensysConnector, scorecard::ScorecardConnector};
pub use asm::{AttackSurfaceMonitor, ExposureType, ExternalExposure, MockAsmProvider};
