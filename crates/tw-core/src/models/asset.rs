//! Asset data model for the Asset & Identity Context Store.
//!
//! Assets represent infrastructure components (servers, workstations, cloud resources, etc.)
//! that are tracked for enrichment during incident triage.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Represents an infrastructure asset tracked in the context store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Asset {
    /// Unique identifier for this asset.
    pub id: Uuid,
    /// Tenant that owns this asset.
    pub tenant_id: Uuid,
    /// Type of asset.
    pub asset_type: AssetType,
    /// Identifiers used to match this asset (hostname, IP, MAC, etc.).
    pub identifiers: Vec<AssetIdentifier>,
    /// Human-readable name for the asset.
    pub name: String,
    /// Business criticality level.
    pub criticality: Criticality,
    /// Owner of the asset (references an Identity).
    pub owner: Option<Uuid>,
    /// Team responsible for the asset.
    pub team: Option<String>,
    /// Deployment environment.
    pub environment: Environment,
    /// Arbitrary tags for categorization.
    pub tags: HashMap<String, String>,
    /// Timestamp of last activity or heartbeat.
    pub last_seen: DateTime<Utc>,
    /// Names of connectors that have reported this asset.
    pub source_connectors: Vec<String>,
    /// Additional metadata.
    pub metadata: serde_json::Value,
    /// Timestamp when the asset was first created.
    pub created_at: DateTime<Utc>,
    /// Timestamp of the last update.
    pub updated_at: DateTime<Utc>,
}

impl Asset {
    /// Creates a new asset with required fields.
    pub fn new(
        tenant_id: Uuid,
        name: String,
        asset_type: AssetType,
        criticality: Criticality,
        environment: Environment,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            tenant_id,
            asset_type,
            identifiers: Vec::new(),
            name,
            criticality,
            owner: None,
            team: None,
            environment,
            tags: HashMap::new(),
            last_seen: now,
            source_connectors: Vec::new(),
            metadata: serde_json::Value::Null,
            created_at: now,
            updated_at: now,
        }
    }

    /// Adds an identifier to the asset.
    pub fn add_identifier(&mut self, identifier: AssetIdentifier) {
        self.identifiers.push(identifier);
        self.updated_at = Utc::now();
    }

    /// Checks whether this asset matches a given identifier value.
    pub fn matches_identifier(&self, identifier_type: &IdentifierType, value: &str) -> bool {
        self.identifiers
            .iter()
            .any(|id| &id.identifier_type == identifier_type && id.value == value)
    }

    /// Updates the last_seen timestamp.
    pub fn touch(&mut self) {
        self.last_seen = Utc::now();
        self.updated_at = Utc::now();
    }
}

/// Classification of the asset type.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AssetType {
    /// Physical or virtual server.
    Server,
    /// End-user workstation or laptop.
    Workstation,
    /// Mobile device (phone, tablet).
    MobileDevice,
    /// Network equipment (router, switch, firewall).
    NetworkDevice,
    /// Cloud virtual machine or compute instance.
    CloudInstance,
    /// Container or Kubernetes pod.
    Container,
    /// Database server or managed database service.
    Database,
    /// Application or service.
    Application,
    /// IoT or OT device.
    IotDevice,
    /// Custom asset type.
    Custom(String),
}

impl std::fmt::Display for AssetType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AssetType::Server => write!(f, "Server"),
            AssetType::Workstation => write!(f, "Workstation"),
            AssetType::MobileDevice => write!(f, "Mobile Device"),
            AssetType::NetworkDevice => write!(f, "Network Device"),
            AssetType::CloudInstance => write!(f, "Cloud Instance"),
            AssetType::Container => write!(f, "Container"),
            AssetType::Database => write!(f, "Database"),
            AssetType::Application => write!(f, "Application"),
            AssetType::IotDevice => write!(f, "IoT Device"),
            AssetType::Custom(name) => write!(f, "Custom: {}", name),
        }
    }
}

/// An identifier that can be used to look up an asset.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AssetIdentifier {
    /// Type of identifier.
    pub identifier_type: IdentifierType,
    /// Identifier value.
    pub value: String,
    /// Confidence in this identifier mapping (0.0 - 1.0).
    pub confidence: f64,
    /// Source that provided this identifier.
    pub source: String,
}

impl AssetIdentifier {
    /// Creates a new asset identifier.
    pub fn new(identifier_type: IdentifierType, value: String, source: String) -> Self {
        Self {
            identifier_type,
            value,
            confidence: 1.0,
            source,
        }
    }

    /// Creates a new identifier with a specific confidence.
    pub fn with_confidence(mut self, confidence: f64) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }
}

/// Types of identifiers used to match assets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum IdentifierType {
    /// Hostname.
    Hostname,
    /// IPv4 address.
    Ipv4,
    /// IPv6 address.
    Ipv6,
    /// MAC address.
    MacAddress,
    /// Fully Qualified Domain Name.
    Fqdn,
    /// Cloud instance ID (e.g., i-0123456789abcdef0).
    CloudInstanceId,
    /// Cloud resource ARN.
    CloudArn,
    /// Serial number.
    SerialNumber,
    /// Custom identifier type.
    Custom(String),
}

impl std::fmt::Display for IdentifierType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IdentifierType::Hostname => write!(f, "Hostname"),
            IdentifierType::Ipv4 => write!(f, "IPv4"),
            IdentifierType::Ipv6 => write!(f, "IPv6"),
            IdentifierType::MacAddress => write!(f, "MAC Address"),
            IdentifierType::Fqdn => write!(f, "FQDN"),
            IdentifierType::CloudInstanceId => write!(f, "Cloud Instance ID"),
            IdentifierType::CloudArn => write!(f, "Cloud ARN"),
            IdentifierType::SerialNumber => write!(f, "Serial Number"),
            IdentifierType::Custom(name) => write!(f, "Custom: {}", name),
        }
    }
}

/// Business criticality level of an asset.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Criticality {
    /// Low criticality - minimal business impact.
    Low,
    /// Medium criticality.
    Medium,
    /// High criticality - significant business impact.
    High,
    /// Critical - essential business service.
    Critical,
}

impl std::fmt::Display for Criticality {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Criticality::Low => write!(f, "Low"),
            Criticality::Medium => write!(f, "Medium"),
            Criticality::High => write!(f, "High"),
            Criticality::Critical => write!(f, "Critical"),
        }
    }
}

/// Deployment environment of an asset.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Environment {
    /// Production environment.
    Production,
    /// Staging / pre-production.
    Staging,
    /// Development environment.
    Development,
    /// Testing / QA.
    Testing,
    /// Custom environment label.
    Custom(String),
}

impl std::fmt::Display for Environment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Environment::Production => write!(f, "Production"),
            Environment::Staging => write!(f, "Staging"),
            Environment::Development => write!(f, "Development"),
            Environment::Testing => write!(f, "Testing"),
            Environment::Custom(name) => write!(f, "Custom: {}", name),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_asset_creation() {
        let tenant_id = Uuid::new_v4();
        let asset = Asset::new(
            tenant_id,
            "web-server-01".to_string(),
            AssetType::Server,
            Criticality::High,
            Environment::Production,
        );

        assert!(!asset.id.is_nil());
        assert_eq!(asset.tenant_id, tenant_id);
        assert_eq!(asset.name, "web-server-01");
        assert_eq!(asset.asset_type, AssetType::Server);
        assert_eq!(asset.criticality, Criticality::High);
        assert_eq!(asset.environment, Environment::Production);
        assert!(asset.identifiers.is_empty());
        assert!(asset.owner.is_none());
    }

    #[test]
    fn test_asset_add_identifier() {
        let mut asset = Asset::new(
            Uuid::new_v4(),
            "ws-001".to_string(),
            AssetType::Workstation,
            Criticality::Medium,
            Environment::Production,
        );

        asset.add_identifier(AssetIdentifier::new(
            IdentifierType::Hostname,
            "ws-001.corp.local".to_string(),
            "edr".to_string(),
        ));

        assert_eq!(asset.identifiers.len(), 1);
        assert!(asset.matches_identifier(&IdentifierType::Hostname, "ws-001.corp.local"));
        assert!(!asset.matches_identifier(&IdentifierType::Hostname, "ws-002.corp.local"));
    }

    #[test]
    fn test_asset_identifier_confidence() {
        let id = AssetIdentifier::new(
            IdentifierType::Ipv4,
            "192.168.1.100".to_string(),
            "dhcp".to_string(),
        )
        .with_confidence(0.8);

        assert_eq!(id.confidence, 0.8);

        // Test clamping
        let id2 = AssetIdentifier::new(
            IdentifierType::Ipv4,
            "10.0.0.1".to_string(),
            "scanner".to_string(),
        )
        .with_confidence(1.5);

        assert_eq!(id2.confidence, 1.0);
    }

    #[test]
    fn test_criticality_ordering() {
        assert!(Criticality::Critical > Criticality::High);
        assert!(Criticality::High > Criticality::Medium);
        assert!(Criticality::Medium > Criticality::Low);
    }

    #[test]
    fn test_asset_type_display() {
        assert_eq!(format!("{}", AssetType::Server), "Server");
        assert_eq!(format!("{}", AssetType::Workstation), "Workstation");
        assert_eq!(format!("{}", AssetType::CloudInstance), "Cloud Instance");
        assert_eq!(
            format!("{}", AssetType::Custom("Printer".to_string())),
            "Custom: Printer"
        );
    }

    #[test]
    fn test_asset_serialization() {
        let mut asset = Asset::new(
            Uuid::new_v4(),
            "db-prod-01".to_string(),
            AssetType::Database,
            Criticality::Critical,
            Environment::Production,
        );
        asset.add_identifier(AssetIdentifier::new(
            IdentifierType::Hostname,
            "db-prod-01.internal".to_string(),
            "cmdb".to_string(),
        ));

        let json = serde_json::to_string(&asset).unwrap();
        let deserialized: Asset = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.id, asset.id);
        assert_eq!(deserialized.name, "db-prod-01");
        assert_eq!(deserialized.asset_type, AssetType::Database);
        assert_eq!(deserialized.criticality, Criticality::Critical);
        assert_eq!(deserialized.identifiers.len(), 1);
    }

    #[test]
    fn test_environment_display() {
        assert_eq!(format!("{}", Environment::Production), "Production");
        assert_eq!(format!("{}", Environment::Staging), "Staging");
        assert_eq!(format!("{}", Environment::Development), "Development");
        assert_eq!(format!("{}", Environment::Testing), "Testing");
    }

    #[test]
    fn test_identifier_type_display() {
        assert_eq!(format!("{}", IdentifierType::Hostname), "Hostname");
        assert_eq!(format!("{}", IdentifierType::Ipv4), "IPv4");
        assert_eq!(format!("{}", IdentifierType::CloudArn), "Cloud ARN");
    }

    #[test]
    fn test_asset_touch() {
        let mut asset = Asset::new(
            Uuid::new_v4(),
            "test".to_string(),
            AssetType::Server,
            Criticality::Low,
            Environment::Testing,
        );
        let before = asset.last_seen;
        std::thread::sleep(std::time::Duration::from_millis(10));
        asset.touch();
        assert!(asset.last_seen >= before);
    }
}
