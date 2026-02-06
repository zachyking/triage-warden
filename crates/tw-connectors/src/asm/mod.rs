//! Attack Surface Management (ASM) connectors.
//!
//! This module provides integrations with external attack surface monitoring
//! platforms (Censys, SecurityScorecard) for identifying exposed assets and risks.

pub mod censys;
pub mod mock;
pub mod scorecard;

pub use self::mock::MockAsmProvider;

use crate::{Connector, ConnectorResult};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Trait for attack surface monitoring connectors.
#[async_trait]
pub trait AttackSurfaceMonitor: Connector {
    /// Gets external exposures for a domain.
    async fn get_exposures(&self, domain: &str) -> ConnectorResult<Vec<ExternalExposure>>;

    /// Gets exposures associated with a specific asset.
    async fn get_asset_exposure(&self, asset_id: &str) -> ConnectorResult<Vec<ExternalExposure>>;

    /// Gets a risk score for a domain (0.0 - 100.0).
    async fn get_risk_score(&self, domain: &str) -> ConnectorResult<Option<f32>>;
}

/// An external exposure detected by ASM monitoring.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExternalExposure {
    /// Unique identifier for this exposure.
    pub id: Uuid,
    /// Identifier of the exposed asset (IP, hostname, etc.).
    pub asset_identifier: String,
    /// Type and details of the exposure.
    pub exposure_type: ExposureType,
    /// Risk score for this specific exposure (0.0 - 100.0).
    pub risk_score: f32,
    /// Additional details as structured data.
    pub details: serde_json::Value,
    /// When this exposure was first detected.
    pub first_seen: DateTime<Utc>,
    /// When this exposure was last confirmed.
    pub last_seen: DateTime<Utc>,
}

/// Types of external exposure.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ExposureType {
    /// An open network port with an identified service.
    OpenPort { port: u16, service: String },
    /// A TLS certificate that has expired.
    ExpiredCertificate {
        domain: String,
        expiry: DateTime<Utc>,
    },
    /// A weak or deprecated TLS cipher in use.
    WeakCipher { domain: String, cipher: String },
    /// A publicly accessible service that may be unintended.
    ExposedService { service: String, version: String },
    /// A DNS misconfiguration or issue.
    DnsIssue { issue_type: String },
    /// A missing or misconfigured HTTP security header.
    MisconfiguredHeader { header: String, issue: String },
}

impl std::fmt::Display for ExposureType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExposureType::OpenPort { port, service } => {
                write!(f, "Open port {}:{}", port, service)
            }
            ExposureType::ExpiredCertificate { domain, .. } => {
                write!(f, "Expired certificate for {}", domain)
            }
            ExposureType::WeakCipher { domain, cipher } => {
                write!(f, "Weak cipher {} on {}", cipher, domain)
            }
            ExposureType::ExposedService { service, version } => {
                write!(f, "Exposed {} v{}", service, version)
            }
            ExposureType::DnsIssue { issue_type } => {
                write!(f, "DNS issue: {}", issue_type)
            }
            ExposureType::MisconfiguredHeader { header, issue } => {
                write!(f, "Header {} misconfigured: {}", header, issue)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_external_exposure_serialization() {
        let now = Utc::now();
        let exposure = ExternalExposure {
            id: Uuid::new_v4(),
            asset_identifier: "192.168.1.100".to_string(),
            exposure_type: ExposureType::OpenPort {
                port: 443,
                service: "https".to_string(),
            },
            risk_score: 25.0,
            details: serde_json::json!({"banner": "nginx/1.18"}),
            first_seen: now,
            last_seen: now,
        };

        let json = serde_json::to_string(&exposure).unwrap();
        let deserialized: ExternalExposure = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.asset_identifier, "192.168.1.100");
        assert_eq!(deserialized.risk_score, 25.0);
    }

    #[test]
    fn test_exposure_type_variants() {
        let types = vec![
            ExposureType::OpenPort {
                port: 22,
                service: "ssh".to_string(),
            },
            ExposureType::ExpiredCertificate {
                domain: "example.com".to_string(),
                expiry: Utc::now(),
            },
            ExposureType::WeakCipher {
                domain: "example.com".to_string(),
                cipher: "TLS_RSA_WITH_RC4_128_SHA".to_string(),
            },
            ExposureType::ExposedService {
                service: "elasticsearch".to_string(),
                version: "7.10".to_string(),
            },
            ExposureType::DnsIssue {
                issue_type: "missing_spf".to_string(),
            },
            ExposureType::MisconfiguredHeader {
                header: "X-Frame-Options".to_string(),
                issue: "missing".to_string(),
            },
        ];

        for exposure_type in types {
            let json = serde_json::to_string(&exposure_type).unwrap();
            let deserialized: ExposureType = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, exposure_type);
        }
    }

    #[test]
    fn test_exposure_type_display() {
        let open_port = ExposureType::OpenPort {
            port: 22,
            service: "ssh".to_string(),
        };
        assert_eq!(format!("{}", open_port), "Open port 22:ssh");

        let expired = ExposureType::ExpiredCertificate {
            domain: "example.com".to_string(),
            expiry: Utc::now(),
        };
        assert!(format!("{}", expired).contains("Expired certificate"));

        let weak = ExposureType::WeakCipher {
            domain: "example.com".to_string(),
            cipher: "RC4".to_string(),
        };
        assert!(format!("{}", weak).contains("Weak cipher RC4"));

        let dns = ExposureType::DnsIssue {
            issue_type: "missing_spf".to_string(),
        };
        assert!(format!("{}", dns).contains("DNS issue"));

        let header = ExposureType::MisconfiguredHeader {
            header: "CSP".to_string(),
            issue: "too permissive".to_string(),
        };
        assert!(format!("{}", header).contains("CSP misconfigured"));
    }

    #[test]
    fn test_exposure_risk_score_range() {
        let now = Utc::now();
        let low_risk = ExternalExposure {
            id: Uuid::new_v4(),
            asset_identifier: "10.0.0.1".to_string(),
            exposure_type: ExposureType::DnsIssue {
                issue_type: "info".to_string(),
            },
            risk_score: 0.0,
            details: serde_json::Value::Null,
            first_seen: now,
            last_seen: now,
        };
        assert_eq!(low_risk.risk_score, 0.0);

        let high_risk = ExternalExposure {
            id: Uuid::new_v4(),
            asset_identifier: "10.0.0.2".to_string(),
            exposure_type: ExposureType::ExposedService {
                service: "database".to_string(),
                version: "5.7".to_string(),
            },
            risk_score: 100.0,
            details: serde_json::Value::Null,
            first_seen: now,
            last_seen: now,
        };
        assert_eq!(high_risk.risk_score, 100.0);
    }
}
