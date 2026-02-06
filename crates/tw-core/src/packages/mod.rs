//! Community content packages for Triage Warden.
//!
//! Packages allow sharing and distributing playbooks, hunts, knowledge articles,
//! and saved queries between Triage Warden instances.

pub mod export;
pub mod import;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A distributable content package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentPackage {
    /// Package metadata.
    pub manifest: PackageManifest,
    /// Package contents.
    pub contents: Vec<PackageContent>,
}

/// Metadata describing a content package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageManifest {
    /// Package name (should be unique within a registry).
    pub name: String,
    /// Semantic version string.
    pub version: String,
    /// Human-readable description of the package.
    pub description: String,
    /// Author name or organization.
    pub author: String,
    /// Optional license identifier (e.g., "MIT", "Apache-2.0").
    pub license: Option<String>,
    /// Tags for categorization and search.
    pub tags: Vec<String>,
    /// Minimum Triage Warden version required.
    pub compatibility: Option<String>,
    /// When the package was created.
    pub created_at: DateTime<Utc>,
}

impl PackageManifest {
    /// Creates a new manifest with required fields.
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        description: impl Into<String>,
        author: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            description: description.into(),
            author: author.into(),
            license: None,
            tags: Vec::new(),
            compatibility: None,
            created_at: Utc::now(),
        }
    }

    /// Sets the license.
    pub fn with_license(mut self, license: impl Into<String>) -> Self {
        self.license = Some(license.into());
        self
    }

    /// Sets the tags.
    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }

    /// Sets the compatibility version.
    pub fn with_compatibility(mut self, compat: impl Into<String>) -> Self {
        self.compatibility = Some(compat.into());
        self
    }
}

/// A single piece of content within a package.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PackageContent {
    /// A playbook definition.
    Playbook {
        name: String,
        data: serde_json::Value,
    },
    /// A threat hunt definition.
    Hunt {
        name: String,
        data: serde_json::Value,
    },
    /// A knowledge article.
    Knowledge { title: String, content: String },
    /// A saved query.
    Query {
        name: String,
        query_type: String,
        query: String,
    },
}

impl PackageContent {
    /// Returns the name/title of this content item.
    pub fn name(&self) -> &str {
        match self {
            PackageContent::Playbook { name, .. } => name,
            PackageContent::Hunt { name, .. } => name,
            PackageContent::Knowledge { title, .. } => title,
            PackageContent::Query { name, .. } => name,
        }
    }

    /// Returns the type of this content item as a string.
    pub fn content_type(&self) -> &str {
        match self {
            PackageContent::Playbook { .. } => "playbook",
            PackageContent::Hunt { .. } => "hunt",
            PackageContent::Knowledge { .. } => "knowledge",
            PackageContent::Query { .. } => "query",
        }
    }
}

/// How to resolve conflicts when importing content that already exists.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ConflictResolution {
    /// Skip items that already exist.
    Skip,
    /// Overwrite existing items.
    Overwrite,
    /// Rename imported items to avoid conflicts.
    Rename,
}

/// Errors that can occur during package operations.
#[derive(Error, Debug)]
pub enum PackageError {
    #[error("Validation failed: {0}")]
    ValidationFailed(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    #[error("Incompatible package version: {0}")]
    IncompatibleVersion(String),

    #[error("Import error: {0}")]
    ImportError(String),

    #[error("Export error: {0}")]
    ExportError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_package_manifest_creation() {
        let manifest = PackageManifest::new(
            "phishing-response",
            "1.0.0",
            "Playbooks for phishing incident response",
            "Security Team",
        )
        .with_license("MIT")
        .with_tags(vec!["phishing".to_string(), "email".to_string()])
        .with_compatibility(">=2.0.0");

        assert_eq!(manifest.name, "phishing-response");
        assert_eq!(manifest.version, "1.0.0");
        assert_eq!(manifest.license, Some("MIT".to_string()));
        assert_eq!(manifest.tags.len(), 2);
        assert_eq!(manifest.compatibility, Some(">=2.0.0".to_string()));
    }

    #[test]
    fn test_package_content_types() {
        let playbook = PackageContent::Playbook {
            name: "phishing-triage".to_string(),
            data: serde_json::json!({"stages": []}),
        };
        assert_eq!(playbook.name(), "phishing-triage");
        assert_eq!(playbook.content_type(), "playbook");

        let hunt = PackageContent::Hunt {
            name: "lateral-movement".to_string(),
            data: serde_json::json!({"query": "..."}),
        };
        assert_eq!(hunt.name(), "lateral-movement");
        assert_eq!(hunt.content_type(), "hunt");

        let knowledge = PackageContent::Knowledge {
            title: "Phishing Indicators".to_string(),
            content: "Common phishing indicators include...".to_string(),
        };
        assert_eq!(knowledge.name(), "Phishing Indicators");
        assert_eq!(knowledge.content_type(), "knowledge");

        let query = PackageContent::Query {
            name: "failed-logins".to_string(),
            query_type: "siem".to_string(),
            query: "event.type:authentication AND event.outcome:failure".to_string(),
        };
        assert_eq!(query.name(), "failed-logins");
        assert_eq!(query.content_type(), "query");
    }

    #[test]
    fn test_content_package_serialization() {
        let package = ContentPackage {
            manifest: PackageManifest::new("test-pack", "0.1.0", "Test package", "tester"),
            contents: vec![
                PackageContent::Playbook {
                    name: "pb-1".to_string(),
                    data: serde_json::json!({"enabled": true}),
                },
                PackageContent::Knowledge {
                    title: "KB-1".to_string(),
                    content: "Some knowledge".to_string(),
                },
            ],
        };

        let json = serde_json::to_string(&package).unwrap();
        let deserialized: ContentPackage = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.manifest.name, "test-pack");
        assert_eq!(deserialized.contents.len(), 2);
    }

    #[test]
    fn test_conflict_resolution_serialization() {
        let skip = ConflictResolution::Skip;
        let json = serde_json::to_string(&skip).unwrap();
        assert_eq!(json, "\"skip\"");

        let overwrite: ConflictResolution = serde_json::from_str("\"overwrite\"").unwrap();
        assert_eq!(overwrite, ConflictResolution::Overwrite);

        let rename: ConflictResolution = serde_json::from_str("\"rename\"").unwrap();
        assert_eq!(rename, ConflictResolution::Rename);
    }

    #[test]
    fn test_package_error_messages() {
        let err = PackageError::ValidationFailed("missing name".to_string());
        assert!(err.to_string().contains("missing name"));

        let err = PackageError::IncompatibleVersion("requires >=3.0".to_string());
        assert!(err.to_string().contains("requires >=3.0"));
    }
}
