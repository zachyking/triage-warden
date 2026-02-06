//! Content package export functionality.

use super::{ContentPackage, PackageContent, PackageError, PackageManifest};

/// Exports content into distributable packages.
pub struct PackageExporter;

impl PackageExporter {
    /// Creates a package containing a single playbook.
    pub fn export_playbook(
        playbook: &serde_json::Value,
        manifest: PackageManifest,
    ) -> ContentPackage {
        let name = playbook
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("unnamed-playbook")
            .to_string();

        ContentPackage {
            manifest,
            contents: vec![PackageContent::Playbook {
                name,
                data: playbook.clone(),
            }],
        }
    }

    /// Creates a package containing a single hunt definition.
    pub fn export_hunt(hunt: &serde_json::Value, manifest: PackageManifest) -> ContentPackage {
        let name = hunt
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("unnamed-hunt")
            .to_string();

        ContentPackage {
            manifest,
            contents: vec![PackageContent::Hunt {
                name,
                data: hunt.clone(),
            }],
        }
    }

    /// Serializes a content package to JSON.
    pub fn to_json(package: &ContentPackage) -> Result<String, PackageError> {
        serde_json::to_string_pretty(package)
            .map_err(|e| PackageError::SerializationError(e.to_string()))
    }

    /// Deserializes a content package from JSON.
    pub fn from_json(json: &str) -> Result<ContentPackage, PackageError> {
        serde_json::from_str(json).map_err(|e| PackageError::DeserializationError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_manifest() -> PackageManifest {
        PackageManifest::new("test-export", "1.0.0", "Test export", "tester")
    }

    #[test]
    fn test_export_playbook() {
        let playbook = serde_json::json!({
            "name": "phishing-response",
            "stages": [
                {"name": "triage", "steps": []}
            ]
        });

        let package = PackageExporter::export_playbook(&playbook, test_manifest());
        assert_eq!(package.manifest.name, "test-export");
        assert_eq!(package.contents.len(), 1);

        match &package.contents[0] {
            PackageContent::Playbook { name, data } => {
                assert_eq!(name, "phishing-response");
                assert!(data.get("stages").is_some());
            }
            _ => panic!("Expected Playbook content"),
        }
    }

    #[test]
    fn test_export_playbook_unnamed() {
        let playbook = serde_json::json!({"stages": []});
        let package = PackageExporter::export_playbook(&playbook, test_manifest());

        match &package.contents[0] {
            PackageContent::Playbook { name, .. } => {
                assert_eq!(name, "unnamed-playbook");
            }
            _ => panic!("Expected Playbook content"),
        }
    }

    #[test]
    fn test_export_hunt() {
        let hunt = serde_json::json!({
            "name": "lateral-movement-hunt",
            "query": "event.type:network AND destination.port:445"
        });

        let package = PackageExporter::export_hunt(&hunt, test_manifest());
        assert_eq!(package.contents.len(), 1);

        match &package.contents[0] {
            PackageContent::Hunt { name, data } => {
                assert_eq!(name, "lateral-movement-hunt");
                assert!(data.get("query").is_some());
            }
            _ => panic!("Expected Hunt content"),
        }
    }

    #[test]
    fn test_export_hunt_unnamed() {
        let hunt = serde_json::json!({"query": "test"});
        let package = PackageExporter::export_hunt(&hunt, test_manifest());

        match &package.contents[0] {
            PackageContent::Hunt { name, .. } => {
                assert_eq!(name, "unnamed-hunt");
            }
            _ => panic!("Expected Hunt content"),
        }
    }

    #[test]
    fn test_json_round_trip() {
        let package = ContentPackage {
            manifest: test_manifest(),
            contents: vec![
                PackageContent::Playbook {
                    name: "pb-1".to_string(),
                    data: serde_json::json!({"enabled": true}),
                },
                PackageContent::Hunt {
                    name: "hunt-1".to_string(),
                    data: serde_json::json!({"query": "test"}),
                },
                PackageContent::Knowledge {
                    title: "Article 1".to_string(),
                    content: "Content here".to_string(),
                },
                PackageContent::Query {
                    name: "query-1".to_string(),
                    query_type: "siem".to_string(),
                    query: "index=main".to_string(),
                },
            ],
        };

        let json = PackageExporter::to_json(&package).unwrap();
        let restored = PackageExporter::from_json(&json).unwrap();

        assert_eq!(restored.manifest.name, "test-export");
        assert_eq!(restored.contents.len(), 4);
        assert_eq!(restored.contents[0].content_type(), "playbook");
        assert_eq!(restored.contents[1].content_type(), "hunt");
        assert_eq!(restored.contents[2].content_type(), "knowledge");
        assert_eq!(restored.contents[3].content_type(), "query");
    }

    #[test]
    fn test_json_round_trip_single() {
        let package = ContentPackage {
            manifest: test_manifest(),
            contents: vec![PackageContent::Playbook {
                name: "pb-1".to_string(),
                data: serde_json::json!({"stages": []}),
            }],
        };

        let json = PackageExporter::to_json(&package).unwrap();
        let restored = PackageExporter::from_json(&json).unwrap();

        assert_eq!(restored.manifest.name, "test-export");
        assert_eq!(restored.contents.len(), 1);
    }

    #[test]
    fn test_from_json_invalid() {
        let result = PackageExporter::from_json("not valid json");
        assert!(result.is_err());
        match result.unwrap_err() {
            PackageError::DeserializationError(msg) => {
                assert!(!msg.is_empty());
            }
            _ => panic!("Expected DeserializationError"),
        }
    }

    #[test]
    fn test_to_json_produces_valid_json() {
        let package = ContentPackage {
            manifest: test_manifest(),
            contents: vec![],
        };

        let json = PackageExporter::to_json(&package).unwrap();
        // Verify it's valid JSON by parsing it
        let _: serde_json::Value = serde_json::from_str(&json).unwrap();
    }
}
