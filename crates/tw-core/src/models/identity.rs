//! Identity data model for the Asset & Identity Context Store.
//!
//! Identities represent users, service accounts, and other principals
//! that are tracked for enrichment during incident triage.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Represents a user or service identity tracked in the context store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    /// Unique identifier for this identity.
    pub id: Uuid,
    /// Tenant that owns this identity.
    pub tenant_id: Uuid,
    /// Type of identity.
    pub identity_type: IdentityType,
    /// Primary identifier (username, email, or service principal name).
    pub primary_identifier: String,
    /// Human-readable display name.
    pub display_name: String,
    /// Department or organizational unit.
    pub department: Option<String>,
    /// Manager identity ID.
    pub manager: Option<Uuid>,
    /// Computed risk score (0.0 - 100.0).
    pub risk_score: f32,
    /// Current account status.
    pub status: IdentityStatus,
    /// Security groups or roles the identity belongs to.
    pub groups: Vec<String>,
    /// Permissions assigned to this identity.
    pub permissions: Vec<String>,
    /// Asset IDs associated with this identity.
    pub associated_assets: Vec<Uuid>,
    /// Timestamp of last observed activity.
    pub last_activity: DateTime<Utc>,
    /// Names of connectors that have reported this identity.
    pub source_connectors: Vec<String>,
    /// Additional metadata.
    pub metadata: serde_json::Value,
    /// Timestamp when the identity was first created.
    pub created_at: DateTime<Utc>,
    /// Timestamp of the last update.
    pub updated_at: DateTime<Utc>,
}

impl Identity {
    /// Creates a new identity with required fields.
    pub fn new(
        tenant_id: Uuid,
        identity_type: IdentityType,
        primary_identifier: String,
        display_name: String,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            tenant_id,
            identity_type,
            primary_identifier,
            display_name,
            department: None,
            manager: None,
            risk_score: 0.0,
            status: IdentityStatus::Active,
            groups: Vec::new(),
            permissions: Vec::new(),
            associated_assets: Vec::new(),
            last_activity: now,
            source_connectors: Vec::new(),
            metadata: serde_json::Value::Null,
            created_at: now,
            updated_at: now,
        }
    }

    /// Returns whether this identity is currently active.
    pub fn is_active(&self) -> bool {
        self.status == IdentityStatus::Active
    }

    /// Returns whether this identity has elevated risk (score > 70).
    pub fn is_high_risk(&self) -> bool {
        self.risk_score > 70.0
    }

    /// Associates an asset with this identity.
    pub fn associate_asset(&mut self, asset_id: Uuid) {
        if !self.associated_assets.contains(&asset_id) {
            self.associated_assets.push(asset_id);
            self.updated_at = Utc::now();
        }
    }

    /// Updates the risk score.
    pub fn set_risk_score(&mut self, score: f32) {
        self.risk_score = score.clamp(0.0, 100.0);
        self.updated_at = Utc::now();
    }

    /// Updates the last activity timestamp.
    pub fn touch(&mut self) {
        self.last_activity = Utc::now();
        self.updated_at = Utc::now();
    }
}

/// Classification of the identity type.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum IdentityType {
    /// Standard user account.
    User,
    /// Service account or application identity.
    ServiceAccount,
    /// Shared or generic account.
    SharedAccount,
    /// Administrative or privileged account.
    Admin,
    /// External or guest account.
    External,
    /// Custom identity type.
    Custom(String),
}

impl std::fmt::Display for IdentityType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IdentityType::User => write!(f, "User"),
            IdentityType::ServiceAccount => write!(f, "Service Account"),
            IdentityType::SharedAccount => write!(f, "Shared Account"),
            IdentityType::Admin => write!(f, "Admin"),
            IdentityType::External => write!(f, "External"),
            IdentityType::Custom(name) => write!(f, "Custom: {}", name),
        }
    }
}

/// Current status of an identity account.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum IdentityStatus {
    /// Account is active and can authenticate.
    Active,
    /// Account is suspended (temporary restriction).
    Suspended,
    /// Account is disabled (permanent until re-enabled).
    Disabled,
    /// Account is locked out (e.g., too many failed attempts).
    LockedOut,
    /// Account has been deprovisioned / deleted.
    Deprovisioned,
}

impl std::fmt::Display for IdentityStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IdentityStatus::Active => write!(f, "Active"),
            IdentityStatus::Suspended => write!(f, "Suspended"),
            IdentityStatus::Disabled => write!(f, "Disabled"),
            IdentityStatus::LockedOut => write!(f, "Locked Out"),
            IdentityStatus::Deprovisioned => write!(f, "Deprovisioned"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_creation() {
        let tenant_id = Uuid::new_v4();
        let identity = Identity::new(
            tenant_id,
            IdentityType::User,
            "jdoe@example.com".to_string(),
            "John Doe".to_string(),
        );

        assert!(!identity.id.is_nil());
        assert_eq!(identity.tenant_id, tenant_id);
        assert_eq!(identity.primary_identifier, "jdoe@example.com");
        assert_eq!(identity.display_name, "John Doe");
        assert_eq!(identity.identity_type, IdentityType::User);
        assert_eq!(identity.status, IdentityStatus::Active);
        assert_eq!(identity.risk_score, 0.0);
        assert!(identity.is_active());
        assert!(!identity.is_high_risk());
    }

    #[test]
    fn test_identity_risk_score() {
        let mut identity = Identity::new(
            Uuid::new_v4(),
            IdentityType::User,
            "user@example.com".to_string(),
            "Test User".to_string(),
        );

        identity.set_risk_score(85.0);
        assert_eq!(identity.risk_score, 85.0);
        assert!(identity.is_high_risk());

        // Test clamping
        identity.set_risk_score(150.0);
        assert_eq!(identity.risk_score, 100.0);

        identity.set_risk_score(-10.0);
        assert_eq!(identity.risk_score, 0.0);
    }

    #[test]
    fn test_identity_associate_asset() {
        let mut identity = Identity::new(
            Uuid::new_v4(),
            IdentityType::User,
            "user@example.com".to_string(),
            "Test User".to_string(),
        );

        let asset_id = Uuid::new_v4();
        identity.associate_asset(asset_id);
        assert_eq!(identity.associated_assets.len(), 1);

        // Duplicate should not be added
        identity.associate_asset(asset_id);
        assert_eq!(identity.associated_assets.len(), 1);

        let asset_id2 = Uuid::new_v4();
        identity.associate_asset(asset_id2);
        assert_eq!(identity.associated_assets.len(), 2);
    }

    #[test]
    fn test_identity_status() {
        let mut identity = Identity::new(
            Uuid::new_v4(),
            IdentityType::User,
            "user@example.com".to_string(),
            "Test User".to_string(),
        );

        assert!(identity.is_active());

        identity.status = IdentityStatus::Suspended;
        assert!(!identity.is_active());

        identity.status = IdentityStatus::Disabled;
        assert!(!identity.is_active());
    }

    #[test]
    fn test_identity_type_display() {
        assert_eq!(format!("{}", IdentityType::User), "User");
        assert_eq!(
            format!("{}", IdentityType::ServiceAccount),
            "Service Account"
        );
        assert_eq!(format!("{}", IdentityType::Admin), "Admin");
        assert_eq!(format!("{}", IdentityType::External), "External");
    }

    #[test]
    fn test_identity_status_display() {
        assert_eq!(format!("{}", IdentityStatus::Active), "Active");
        assert_eq!(format!("{}", IdentityStatus::Suspended), "Suspended");
        assert_eq!(format!("{}", IdentityStatus::LockedOut), "Locked Out");
        assert_eq!(
            format!("{}", IdentityStatus::Deprovisioned),
            "Deprovisioned"
        );
    }

    #[test]
    fn test_identity_serialization() {
        let mut identity = Identity::new(
            Uuid::new_v4(),
            IdentityType::ServiceAccount,
            "svc-backup@corp".to_string(),
            "Backup Service".to_string(),
        );
        identity.department = Some("IT Operations".to_string());
        identity.groups = vec!["backup-admins".to_string()];

        let json = serde_json::to_string(&identity).unwrap();
        let deserialized: Identity = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.id, identity.id);
        assert_eq!(deserialized.primary_identifier, "svc-backup@corp");
        assert_eq!(deserialized.identity_type, IdentityType::ServiceAccount);
        assert_eq!(deserialized.department, Some("IT Operations".to_string()));
        assert_eq!(deserialized.groups.len(), 1);
    }
}
