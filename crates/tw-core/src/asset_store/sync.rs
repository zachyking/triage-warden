//! Asset synchronization and identity stitching.
//!
//! Handles syncing assets from external connectors and stitching
//! identities from multiple sources based on shared attributes.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Configuration for an asset sync job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetSyncJob {
    /// Name of the connector to sync from.
    pub connector_name: String,
    /// Type of sync to perform.
    pub sync_type: SyncType,
    /// Cron-like schedule expression (e.g., "0 */6 * * *").
    pub schedule: String,
    /// Timestamp of the last successful sync run.
    pub last_run: Option<DateTime<Utc>>,
    /// Whether this sync job is enabled.
    pub enabled: bool,
}

impl AssetSyncJob {
    /// Creates a new asset sync job.
    pub fn new(connector_name: String, sync_type: SyncType, schedule: String) -> Self {
        Self {
            connector_name,
            sync_type,
            schedule,
            last_run: None,
            enabled: true,
        }
    }
}

/// Type of sync operation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SyncType {
    /// Full sync - re-import all assets from the source.
    Full,
    /// Incremental sync - only import changes since last_run.
    Incremental,
}

/// Result of a sync operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResult {
    /// Name of the connector that was synced.
    pub connector_name: String,
    /// Type of sync that was performed.
    pub sync_type: SyncType,
    /// Number of assets created.
    pub created: u64,
    /// Number of assets updated.
    pub updated: u64,
    /// Number of assets deleted.
    pub deleted: u64,
    /// Number of errors encountered.
    pub errors: u64,
    /// Total duration of the sync in milliseconds.
    pub duration_ms: u64,
    /// Timestamp when the sync completed.
    pub completed_at: DateTime<Utc>,
}

impl SyncResult {
    /// Creates a new sync result.
    pub fn new(connector_name: String, sync_type: SyncType) -> Self {
        Self {
            connector_name,
            sync_type,
            created: 0,
            updated: 0,
            deleted: 0,
            errors: 0,
            duration_ms: 0,
            completed_at: Utc::now(),
        }
    }

    /// Returns the total number of changes made.
    pub fn total_changes(&self) -> u64 {
        self.created + self.updated + self.deleted
    }

    /// Returns whether the sync completed without errors.
    pub fn is_clean(&self) -> bool {
        self.errors == 0
    }
}

/// Identity stitching: merges identities from multiple sources
/// based on shared attributes like email or username.
#[derive(Debug, Clone)]
pub struct IdentityStitchResult {
    /// Number of identities that were merged.
    pub merged_count: u64,
    /// Number of new identities created (no match found).
    pub new_count: u64,
    /// Number of conflicts detected (ambiguous matches).
    pub conflicts: u64,
}

/// Attempts to find a matching identity from a list based on
/// common attributes (email, username, display name).
///
/// Returns the index of the best match, if any.
pub fn find_identity_match(
    primary_identifier: &str,
    display_name: &str,
    existing: &[(String, String)], // (primary_identifier, display_name)
) -> Option<usize> {
    // Exact match on primary identifier (email/username)
    if let Some(idx) = existing
        .iter()
        .position(|(id, _)| id.eq_ignore_ascii_case(primary_identifier))
    {
        return Some(idx);
    }

    // Exact match on display name as a fallback (weaker signal)
    if !display_name.is_empty() {
        if let Some(idx) = existing
            .iter()
            .position(|(_, name)| name.eq_ignore_ascii_case(display_name))
        {
            return Some(idx);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_job_creation() {
        let job = AssetSyncJob::new(
            "crowdstrike".to_string(),
            SyncType::Incremental,
            "0 */6 * * *".to_string(),
        );

        assert_eq!(job.connector_name, "crowdstrike");
        assert_eq!(job.sync_type, SyncType::Incremental);
        assert!(job.last_run.is_none());
        assert!(job.enabled);
    }

    #[test]
    fn test_sync_result() {
        let mut result = SyncResult::new("okta".to_string(), SyncType::Full);
        result.created = 100;
        result.updated = 50;
        result.deleted = 5;

        assert_eq!(result.total_changes(), 155);
        assert!(result.is_clean());

        result.errors = 3;
        assert!(!result.is_clean());
    }

    #[test]
    fn test_identity_stitching_exact_match() {
        let existing = vec![
            ("alice@corp.com".to_string(), "Alice Smith".to_string()),
            ("bob@corp.com".to_string(), "Bob Jones".to_string()),
        ];

        // Exact email match
        let result = find_identity_match("alice@corp.com", "Alice Smith", &existing);
        assert_eq!(result, Some(0));

        // Case-insensitive email match
        let result = find_identity_match("Alice@Corp.com", "Alice Smith", &existing);
        assert_eq!(result, Some(0));
    }

    #[test]
    fn test_identity_stitching_display_name_fallback() {
        let existing = vec![
            ("alice@corp.com".to_string(), "Alice Smith".to_string()),
            ("bob@corp.com".to_string(), "Bob Jones".to_string()),
        ];

        // No email match, but display name matches
        let result = find_identity_match("asmith@external.com", "Bob Jones", &existing);
        assert_eq!(result, Some(1));
    }

    #[test]
    fn test_identity_stitching_no_match() {
        let existing = vec![("alice@corp.com".to_string(), "Alice Smith".to_string())];

        let result = find_identity_match("unknown@other.com", "Unknown User", &existing);
        assert_eq!(result, None);
    }

    #[test]
    fn test_sync_type_serialization() {
        let full = SyncType::Full;
        let json = serde_json::to_string(&full).unwrap();
        assert_eq!(json, "\"full\"");

        let incremental: SyncType = serde_json::from_str("\"incremental\"").unwrap();
        assert_eq!(incremental, SyncType::Incremental);
    }
}
