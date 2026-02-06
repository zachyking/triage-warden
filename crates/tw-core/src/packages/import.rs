//! Content package import functionality.

use super::{ConflictResolution, ContentPackage, PackageContent, PackageError};
use serde::{Deserialize, Serialize};

/// Validates and imports content packages.
pub struct PackageImporter;

/// Result of validating a package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    /// Whether the package is valid for import.
    pub valid: bool,
    /// Warnings (non-blocking issues).
    pub warnings: Vec<String>,
    /// Errors (blocking issues).
    pub errors: Vec<String>,
    /// Number of content items in the package.
    pub content_count: usize,
}

/// Result of importing a package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportResult {
    /// Number of items successfully imported.
    pub imported: usize,
    /// Number of items skipped (due to conflicts or errors).
    pub skipped: usize,
    /// Errors encountered during import.
    pub errors: Vec<String>,
}

impl PackageImporter {
    /// Validates a content package without importing it.
    pub fn validate(package: &ContentPackage) -> Result<ValidationResult, PackageError> {
        let mut warnings = Vec::new();
        let mut errors = Vec::new();

        // Validate manifest
        if package.manifest.name.is_empty() {
            errors.push("Package name is required".to_string());
        }
        if package.manifest.version.is_empty() {
            errors.push("Package version is required".to_string());
        }
        if package.manifest.author.is_empty() {
            warnings.push("Package author is not specified".to_string());
        }

        // Validate contents
        if package.contents.is_empty() {
            warnings.push("Package has no content items".to_string());
        }

        for (i, content) in package.contents.iter().enumerate() {
            if content.name().is_empty() {
                errors.push(format!("Content item {} has an empty name", i));
            }

            // Type-specific validation
            match content {
                PackageContent::Playbook { data, .. } => {
                    if data.is_null() {
                        errors.push(format!("Playbook '{}' has null data", content.name()));
                    }
                }
                PackageContent::Hunt { data, .. } => {
                    if data.is_null() {
                        errors.push(format!("Hunt '{}' has null data", content.name()));
                    }
                }
                PackageContent::Knowledge { content: text, .. } => {
                    if text.is_empty() {
                        warnings.push(format!(
                            "Knowledge article '{}' has empty content",
                            content.name()
                        ));
                    }
                }
                PackageContent::Query {
                    query, query_type, ..
                } => {
                    if query.is_empty() {
                        errors.push(format!(
                            "Query '{}' has an empty query string",
                            content.name()
                        ));
                    }
                    if query_type.is_empty() {
                        errors.push(format!(
                            "Query '{}' has an empty query_type",
                            content.name()
                        ));
                    }
                }
            }
        }

        Ok(ValidationResult {
            valid: errors.is_empty(),
            warnings,
            errors,
            content_count: package.contents.len(),
        })
    }

    /// Imports a content package with the given conflict resolution strategy.
    pub fn import(
        package: ContentPackage,
        resolution: ConflictResolution,
    ) -> Result<ImportResult, PackageError> {
        // First, validate
        let validation = Self::validate(&package)?;
        if !validation.valid {
            return Err(PackageError::ValidationFailed(validation.errors.join("; ")));
        }

        let mut imported = 0;
        let skipped = 0;
        let errors = Vec::new();

        for _content in &package.contents {
            // In a real implementation, this would check for existing items
            // and apply the conflict resolution strategy
            match resolution {
                ConflictResolution::Skip => {
                    // For now, import everything (no existing items to conflict with)
                    imported += 1;
                }
                ConflictResolution::Overwrite => {
                    imported += 1;
                }
                ConflictResolution::Rename => {
                    imported += 1;
                }
            }
        }

        Ok(ImportResult {
            imported,
            skipped,
            errors,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packages::PackageManifest;

    fn valid_package() -> ContentPackage {
        ContentPackage {
            manifest: PackageManifest::new("test-pack", "1.0.0", "Test package", "tester"),
            contents: vec![
                PackageContent::Playbook {
                    name: "pb-1".to_string(),
                    data: serde_json::json!({"stages": []}),
                },
                PackageContent::Knowledge {
                    title: "KB-1".to_string(),
                    content: "Some content".to_string(),
                },
            ],
        }
    }

    #[test]
    fn test_validate_valid_package() {
        let result = PackageImporter::validate(&valid_package()).unwrap();
        assert!(result.valid);
        assert!(result.errors.is_empty());
        assert_eq!(result.content_count, 2);
    }

    #[test]
    fn test_validate_empty_name() {
        let package = ContentPackage {
            manifest: PackageManifest::new("", "1.0.0", "Test", "tester"),
            contents: vec![PackageContent::Playbook {
                name: "pb".to_string(),
                data: serde_json::json!({}),
            }],
        };

        let result = PackageImporter::validate(&package).unwrap();
        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| e.contains("name is required")));
    }

    #[test]
    fn test_validate_empty_version() {
        let package = ContentPackage {
            manifest: PackageManifest::new("test", "", "Test", "tester"),
            contents: vec![],
        };

        let result = PackageImporter::validate(&package).unwrap();
        assert!(!result.valid);
        assert!(result
            .errors
            .iter()
            .any(|e| e.contains("version is required")));
    }

    #[test]
    fn test_validate_empty_contents_warning() {
        let package = ContentPackage {
            manifest: PackageManifest::new("test", "1.0.0", "Test", "tester"),
            contents: vec![],
        };

        let result = PackageImporter::validate(&package).unwrap();
        assert!(result.valid);
        assert!(result
            .warnings
            .iter()
            .any(|w| w.contains("no content items")));
    }

    #[test]
    fn test_validate_null_playbook_data() {
        let package = ContentPackage {
            manifest: PackageManifest::new("test", "1.0.0", "Test", "tester"),
            contents: vec![PackageContent::Playbook {
                name: "pb".to_string(),
                data: serde_json::Value::Null,
            }],
        };

        let result = PackageImporter::validate(&package).unwrap();
        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| e.contains("null data")));
    }

    #[test]
    fn test_validate_empty_query() {
        let package = ContentPackage {
            manifest: PackageManifest::new("test", "1.0.0", "Test", "tester"),
            contents: vec![PackageContent::Query {
                name: "q1".to_string(),
                query_type: "siem".to_string(),
                query: "".to_string(),
            }],
        };

        let result = PackageImporter::validate(&package).unwrap();
        assert!(!result.valid);
        assert!(result
            .errors
            .iter()
            .any(|e| e.contains("empty query string")));
    }

    #[test]
    fn test_validate_empty_query_type() {
        let package = ContentPackage {
            manifest: PackageManifest::new("test", "1.0.0", "Test", "tester"),
            contents: vec![PackageContent::Query {
                name: "q1".to_string(),
                query_type: "".to_string(),
                query: "SELECT *".to_string(),
            }],
        };

        let result = PackageImporter::validate(&package).unwrap();
        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| e.contains("empty query_type")));
    }

    #[test]
    fn test_import_valid_package_skip() {
        let result = PackageImporter::import(valid_package(), ConflictResolution::Skip).unwrap();
        assert_eq!(result.imported, 2);
        assert_eq!(result.skipped, 0);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_import_valid_package_overwrite() {
        let result =
            PackageImporter::import(valid_package(), ConflictResolution::Overwrite).unwrap();
        assert_eq!(result.imported, 2);
    }

    #[test]
    fn test_import_valid_package_rename() {
        let result = PackageImporter::import(valid_package(), ConflictResolution::Rename).unwrap();
        assert_eq!(result.imported, 2);
    }

    #[test]
    fn test_import_invalid_package_fails() {
        let package = ContentPackage {
            manifest: PackageManifest::new("", "1.0.0", "Test", "tester"),
            contents: vec![],
        };

        let result = PackageImporter::import(package, ConflictResolution::Skip);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_empty_content_name() {
        let package = ContentPackage {
            manifest: PackageManifest::new("test", "1.0.0", "Test", "tester"),
            contents: vec![PackageContent::Playbook {
                name: "".to_string(),
                data: serde_json::json!({}),
            }],
        };

        let result = PackageImporter::validate(&package).unwrap();
        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| e.contains("empty name")));
    }

    #[test]
    fn test_validate_empty_knowledge_content_warning() {
        let package = ContentPackage {
            manifest: PackageManifest::new("test", "1.0.0", "Test", "tester"),
            contents: vec![PackageContent::Knowledge {
                title: "Empty Article".to_string(),
                content: "".to_string(),
            }],
        };

        let result = PackageImporter::validate(&package).unwrap();
        assert!(result.valid); // Empty content is a warning, not an error
        assert!(result.warnings.iter().any(|w| w.contains("empty content")));
    }
}
