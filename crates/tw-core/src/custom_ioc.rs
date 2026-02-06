//! Custom IoC (Indicator of Compromise) management.
//!
//! Provides models for managing organization-specific IoCs including
//! allow/block lists, custom threat indicators, and bulk import support.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Type of IoC indicator.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum IocType {
    Ipv4,
    Ipv6,
    Domain,
    Url,
    Md5,
    Sha1,
    Sha256,
    Email,
    FileName,
    RegistryKey,
    Mutex,
    UserAgent,
    JA3,
    Custom(String),
}

impl std::fmt::Display for IocType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IocType::Ipv4 => write!(f, "ipv4"),
            IocType::Ipv6 => write!(f, "ipv6"),
            IocType::Domain => write!(f, "domain"),
            IocType::Url => write!(f, "url"),
            IocType::Md5 => write!(f, "md5"),
            IocType::Sha1 => write!(f, "sha1"),
            IocType::Sha256 => write!(f, "sha256"),
            IocType::Email => write!(f, "email"),
            IocType::FileName => write!(f, "file_name"),
            IocType::RegistryKey => write!(f, "registry_key"),
            IocType::Mutex => write!(f, "mutex"),
            IocType::UserAgent => write!(f, "user_agent"),
            IocType::JA3 => write!(f, "ja3"),
            IocType::Custom(s) => write!(f, "custom:{}", s),
        }
    }
}

/// Classification of an IoC.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IocClassification {
    /// Known malicious indicator.
    Malicious,
    /// Suspicious indicator requiring investigation.
    Suspicious,
    /// Known benign/allowed indicator.
    Benign,
    /// Blocked indicator (organizational policy).
    Blocked,
    /// Informational only.
    Informational,
}

/// A custom IoC managed by the organization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomIoc {
    /// Unique identifier.
    pub id: Uuid,
    /// Tenant that owns this IoC.
    pub tenant_id: Uuid,
    /// Type of the IoC.
    pub ioc_type: IocType,
    /// The IoC value (e.g., IP address, domain, hash).
    pub value: String,
    /// Classification of the IoC.
    pub classification: IocClassification,
    /// Source of the IoC (e.g., "internal-investigation", "threat-feed").
    pub source: String,
    /// Confidence score (0.0 - 1.0).
    pub confidence: f32,
    /// Tags for categorization.
    pub tags: Vec<String>,
    /// Expiration date (None = no expiration).
    pub expiration: Option<DateTime<Utc>>,
    /// Additional context/notes.
    pub context: Option<String>,
    /// User who created the IoC.
    pub created_by: Option<Uuid>,
    /// When the IoC was created.
    pub created_at: DateTime<Utc>,
    /// When the IoC was last updated.
    pub updated_at: DateTime<Utc>,
}

impl CustomIoc {
    /// Creates a new custom IoC.
    pub fn new(
        tenant_id: Uuid,
        ioc_type: IocType,
        value: String,
        classification: IocClassification,
        source: String,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            tenant_id,
            ioc_type,
            value,
            classification,
            source,
            confidence: 0.5,
            tags: Vec::new(),
            expiration: None,
            context: None,
            created_by: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Checks if this IoC has expired.
    pub fn is_expired(&self) -> bool {
        self.expiration.map(|exp| Utc::now() > exp).unwrap_or(false)
    }

    /// Checks if this IoC is active (not expired).
    pub fn is_active(&self) -> bool {
        !self.is_expired()
    }
}

/// Request to create a new custom IoC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateIocRequest {
    pub ioc_type: IocType,
    pub value: String,
    pub classification: IocClassification,
    pub source: String,
    pub confidence: Option<f32>,
    pub tags: Option<Vec<String>>,
    pub expiration: Option<DateTime<Utc>>,
    pub context: Option<String>,
}

/// Request to update a custom IoC.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateIocRequest {
    pub classification: Option<IocClassification>,
    pub confidence: Option<f32>,
    pub tags: Option<Vec<String>>,
    pub expiration: Option<Option<DateTime<Utc>>>,
    pub context: Option<String>,
}

/// Search parameters for IoCs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocSearchParams {
    /// Filter by IoC type.
    pub ioc_type: Option<IocType>,
    /// Search by value (exact or partial match).
    pub value: Option<String>,
    /// Filter by classification.
    pub classification: Option<IocClassification>,
    /// Filter by tag.
    pub tag: Option<String>,
    /// Include expired IoCs.
    #[serde(default)]
    pub include_expired: bool,
    /// Maximum results.
    #[serde(default = "default_limit")]
    pub limit: usize,
    /// Offset for pagination.
    #[serde(default)]
    pub offset: usize,
}

fn default_limit() -> usize {
    100
}

impl Default for IocSearchParams {
    fn default() -> Self {
        Self {
            ioc_type: None,
            value: None,
            classification: None,
            tag: None,
            include_expired: false,
            limit: default_limit(),
            offset: 0,
        }
    }
}

/// An IoC list (allow list, block list, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocList {
    /// Unique identifier.
    pub id: Uuid,
    /// Tenant that owns this list.
    pub tenant_id: Uuid,
    /// Name of the list.
    pub name: String,
    /// Description.
    pub description: Option<String>,
    /// Type of list.
    pub list_type: IocListType,
    /// Number of entries.
    pub entry_count: u64,
    /// When the list was created.
    pub created_at: DateTime<Utc>,
    /// When the list was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Type of IoC list.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IocListType {
    /// Allow list (known good indicators).
    AllowList,
    /// Block list (known bad indicators).
    BlockList,
    /// Watch list (indicators to monitor).
    WatchList,
    /// Custom list.
    Custom(String),
}

/// Bulk import result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkImportResult {
    /// Number of IoCs successfully imported.
    pub imported: u64,
    /// Number of IoCs that failed to import.
    pub failed: u64,
    /// Number of duplicate IoCs skipped.
    pub duplicates: u64,
    /// Errors encountered during import.
    pub errors: Vec<BulkImportError>,
}

/// Error from bulk import.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkImportError {
    /// Line number in the import file.
    pub line: u64,
    /// The value that failed.
    pub value: String,
    /// Error message.
    pub error: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_custom_ioc() {
        let tenant_id = Uuid::new_v4();
        let ioc = CustomIoc::new(
            tenant_id,
            IocType::Ipv4,
            "192.168.1.100".to_string(),
            IocClassification::Malicious,
            "manual".to_string(),
        );

        assert_eq!(ioc.tenant_id, tenant_id);
        assert_eq!(ioc.ioc_type, IocType::Ipv4);
        assert_eq!(ioc.value, "192.168.1.100");
        assert_eq!(ioc.classification, IocClassification::Malicious);
        assert!(ioc.is_active());
        assert!(!ioc.is_expired());
    }

    #[test]
    fn test_ioc_expiration() {
        let mut ioc = CustomIoc::new(
            Uuid::new_v4(),
            IocType::Domain,
            "test.com".to_string(),
            IocClassification::Suspicious,
            "test".to_string(),
        );

        // Not expired
        assert!(!ioc.is_expired());

        // Set to past time
        ioc.expiration = Some(Utc::now() - chrono::Duration::hours(1));
        assert!(ioc.is_expired());
        assert!(!ioc.is_active());

        // Set to future time
        ioc.expiration = Some(Utc::now() + chrono::Duration::hours(1));
        assert!(!ioc.is_expired());
        assert!(ioc.is_active());
    }

    #[test]
    fn test_ioc_type_display() {
        assert_eq!(IocType::Ipv4.to_string(), "ipv4");
        assert_eq!(IocType::Sha256.to_string(), "sha256");
        assert_eq!(
            IocType::Custom("yara_rule".to_string()).to_string(),
            "custom:yara_rule"
        );
    }

    #[test]
    fn test_ioc_classification_serialization() {
        let json = serde_json::to_string(&IocClassification::Malicious).unwrap();
        assert_eq!(json, "\"malicious\"");

        let parsed: IocClassification = serde_json::from_str("\"benign\"").unwrap();
        assert_eq!(parsed, IocClassification::Benign);
    }

    #[test]
    fn test_ioc_list_type_serialization() {
        let json = serde_json::to_string(&IocListType::AllowList).unwrap();
        assert_eq!(json, "\"allow_list\"");

        let json = serde_json::to_string(&IocListType::BlockList).unwrap();
        assert_eq!(json, "\"block_list\"");
    }

    #[test]
    fn test_search_params_defaults() {
        let params = IocSearchParams::default();
        assert_eq!(params.limit, 100);
        assert_eq!(params.offset, 0);
        assert!(!params.include_expired);
    }

    #[test]
    fn test_bulk_import_result() {
        let result = BulkImportResult {
            imported: 100,
            failed: 2,
            duplicates: 5,
            errors: vec![BulkImportError {
                line: 42,
                value: "invalid-ip".to_string(),
                error: "Invalid IP address format".to_string(),
            }],
        };

        assert_eq!(result.imported, 100);
        assert_eq!(result.errors.len(), 1);
    }

    #[test]
    fn test_create_ioc_request_serialization() {
        let req = CreateIocRequest {
            ioc_type: IocType::Sha256,
            value: "abc123".to_string(),
            classification: IocClassification::Malicious,
            source: "test".to_string(),
            confidence: Some(0.9),
            tags: Some(vec!["ransomware".to_string()]),
            expiration: None,
            context: Some("Detected in incident #123".to_string()),
        };

        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("sha256"));
        assert!(json.contains("malicious"));
    }
}
