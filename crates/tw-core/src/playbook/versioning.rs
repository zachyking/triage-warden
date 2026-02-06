//! Playbook versioning with snapshot creation and diff computation.

use chrono::Utc;
use serde::{Deserialize, Serialize};

/// A diff between two playbook versions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionDiff {
    /// Source version number.
    pub from_version: u32,
    /// Target version number.
    pub to_version: u32,
    /// List of changes between versions.
    pub changes: Vec<VersionChange>,
}

/// A single change between two playbook versions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VersionChange {
    /// A new stage was added.
    StageAdded { stage_name: String },
    /// A stage was removed.
    StageRemoved { stage_name: String },
    /// A stage was modified.
    StageModified { stage_name: String, detail: String },
    /// A new step was added to a stage.
    StepAdded {
        stage_name: String,
        step_action: String,
    },
    /// A step was removed from a stage.
    StepRemoved {
        stage_name: String,
        step_action: String,
    },
    /// A step was modified in a stage.
    StepModified {
        stage_name: String,
        step_action: String,
        detail: String,
    },
    /// The trigger configuration changed.
    TriggerChanged { from: String, to: String },
    /// A top-level property changed.
    PropertyChanged {
        field: String,
        from: String,
        to: String,
    },
}

/// Utilities for creating and diffing playbook versions.
pub struct PlaybookVersioning;

impl PlaybookVersioning {
    /// Creates a version snapshot of a playbook.
    pub fn create_version(
        playbook: &super::model::Playbook,
        version: u32,
        changed_by: &str,
        description: &str,
    ) -> super::model::PlaybookVersion {
        let snapshot = serde_json::to_value(playbook).unwrap_or(serde_json::Value::Null);
        super::model::PlaybookVersion {
            playbook_id: playbook.id,
            version,
            snapshot,
            change_description: description.to_string(),
            changed_by: changed_by.to_string(),
            created_at: Utc::now(),
        }
    }

    /// Computes a diff between two serialized playbook versions.
    pub fn diff(
        old: &serde_json::Value,
        new: &serde_json::Value,
        from_version: u32,
        to_version: u32,
    ) -> VersionDiff {
        let mut changes = Vec::new();

        // Compare top-level properties
        Self::diff_property(old, new, "name", &mut changes);
        Self::diff_property(old, new, "description", &mut changes);
        Self::diff_property(old, new, "enabled", &mut changes);

        // Compare trigger
        let old_trigger = old
            .get("trigger_type")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let new_trigger = new
            .get("trigger_type")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if old_trigger != new_trigger {
            changes.push(VersionChange::TriggerChanged {
                from: old_trigger.to_string(),
                to: new_trigger.to_string(),
            });
        }

        // Compare trigger_condition
        Self::diff_property(old, new, "trigger_condition", &mut changes);

        // Compare stages
        Self::diff_stages(old, new, &mut changes);

        VersionDiff {
            from_version,
            to_version,
            changes,
        }
    }

    fn diff_property(
        old: &serde_json::Value,
        new: &serde_json::Value,
        field: &str,
        changes: &mut Vec<VersionChange>,
    ) {
        let old_val = old.get(field);
        let new_val = new.get(field);

        if old_val != new_val {
            changes.push(VersionChange::PropertyChanged {
                field: field.to_string(),
                from: old_val
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "null".to_string()),
                to: new_val
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "null".to_string()),
            });
        }
    }

    fn diff_stages(
        old: &serde_json::Value,
        new: &serde_json::Value,
        changes: &mut Vec<VersionChange>,
    ) {
        let old_stages = old
            .get("stages")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let new_stages = new
            .get("stages")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        // Index stages by name
        let old_by_name: std::collections::HashMap<String, &serde_json::Value> = old_stages
            .iter()
            .filter_map(|s| {
                s.get("name")
                    .and_then(|n| n.as_str())
                    .map(|n| (n.to_string(), s))
            })
            .collect();

        let new_by_name: std::collections::HashMap<String, &serde_json::Value> = new_stages
            .iter()
            .filter_map(|s| {
                s.get("name")
                    .and_then(|n| n.as_str())
                    .map(|n| (n.to_string(), s))
            })
            .collect();

        // Find added stages
        for name in new_by_name.keys() {
            if !old_by_name.contains_key(name) {
                changes.push(VersionChange::StageAdded {
                    stage_name: name.clone(),
                });
            }
        }

        // Find removed stages
        for name in old_by_name.keys() {
            if !new_by_name.contains_key(name) {
                changes.push(VersionChange::StageRemoved {
                    stage_name: name.clone(),
                });
            }
        }

        // Find modified stages
        for (name, old_stage) in &old_by_name {
            if let Some(new_stage) = new_by_name.get(name) {
                Self::diff_single_stage(name, old_stage, new_stage, changes);
            }
        }
    }

    fn diff_single_stage(
        stage_name: &str,
        old_stage: &serde_json::Value,
        new_stage: &serde_json::Value,
        changes: &mut Vec<VersionChange>,
    ) {
        // Check stage-level properties
        let old_parallel = old_stage
            .get("parallel")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let new_parallel = new_stage
            .get("parallel")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if old_parallel != new_parallel {
            changes.push(VersionChange::StageModified {
                stage_name: stage_name.to_string(),
                detail: format!("parallel changed from {} to {}", old_parallel, new_parallel),
            });
        }

        let old_desc = old_stage
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let new_desc = new_stage
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if old_desc != new_desc {
            changes.push(VersionChange::StageModified {
                stage_name: stage_name.to_string(),
                detail: format!("description changed from '{}' to '{}'", old_desc, new_desc),
            });
        }

        // Compare steps
        let old_steps = old_stage
            .get("steps")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let new_steps = new_stage
            .get("steps")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let old_actions: std::collections::HashMap<String, &serde_json::Value> = old_steps
            .iter()
            .filter_map(|s| {
                s.get("action")
                    .and_then(|a| a.as_str())
                    .map(|a| (a.to_string(), s))
            })
            .collect();

        let new_actions: std::collections::HashMap<String, &serde_json::Value> = new_steps
            .iter()
            .filter_map(|s| {
                s.get("action")
                    .and_then(|a| a.as_str())
                    .map(|a| (a.to_string(), s))
            })
            .collect();

        for action in new_actions.keys() {
            if !old_actions.contains_key(action) {
                changes.push(VersionChange::StepAdded {
                    stage_name: stage_name.to_string(),
                    step_action: action.clone(),
                });
            }
        }

        for action in old_actions.keys() {
            if !new_actions.contains_key(action) {
                changes.push(VersionChange::StepRemoved {
                    stage_name: stage_name.to_string(),
                    step_action: action.clone(),
                });
            }
        }

        for (action, old_step) in &old_actions {
            if let Some(new_step) = new_actions.get(action) {
                if old_step != new_step {
                    changes.push(VersionChange::StepModified {
                        stage_name: stage_name.to_string(),
                        step_action: action.clone(),
                        detail: "step configuration changed".to_string(),
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::playbook::model::{Playbook, PlaybookStage, PlaybookStep};

    #[test]
    fn test_create_version_snapshot() {
        let playbook = Playbook::new("test-playbook", "alert").with_description("A test playbook");

        let version =
            PlaybookVersioning::create_version(&playbook, 1, "admin@test.com", "Initial version");

        assert_eq!(version.playbook_id, playbook.id);
        assert_eq!(version.version, 1);
        assert_eq!(version.changed_by, "admin@test.com");
        assert_eq!(version.change_description, "Initial version");
        assert!(version.snapshot.is_object());
        assert_eq!(
            version.snapshot.get("name").and_then(|v| v.as_str()),
            Some("test-playbook")
        );
    }

    #[test]
    fn test_create_version_preserves_stages() {
        let playbook = Playbook::new("test", "alert")
            .with_stage(PlaybookStage::new("enrichment").with_step(PlaybookStep::new("lookup_ip")))
            .with_stage(PlaybookStage::new("analysis").with_step(PlaybookStep::new("ai_triage")));

        let version = PlaybookVersioning::create_version(&playbook, 2, "user", "Added analysis");

        let stages = version.snapshot.get("stages").unwrap().as_array().unwrap();
        assert_eq!(stages.len(), 2);
    }

    #[test]
    fn test_version_roundtrip() {
        let playbook =
            Playbook::new("roundtrip-test", "scheduled").with_description("Test roundtrip");

        let version = PlaybookVersioning::create_version(&playbook, 1, "user", "test");

        // Deserialize snapshot back to playbook
        let restored: Playbook = serde_json::from_value(version.snapshot).unwrap();
        assert_eq!(restored.name, "roundtrip-test");
        assert_eq!(restored.trigger_type, "scheduled");
        assert_eq!(restored.description, Some("Test roundtrip".to_string()));
    }

    #[test]
    fn test_diff_no_changes() {
        let playbook = Playbook::new("same", "alert");
        let snapshot = serde_json::to_value(&playbook).unwrap();

        let diff = PlaybookVersioning::diff(&snapshot, &snapshot, 1, 2);
        assert_eq!(diff.from_version, 1);
        assert_eq!(diff.to_version, 2);
        assert!(diff.changes.is_empty());
    }

    #[test]
    fn test_diff_property_changed() {
        let old = Playbook::new("old-name", "alert");
        let mut new = old.clone();
        new.name = "new-name".to_string();

        let old_json = serde_json::to_value(&old).unwrap();
        let new_json = serde_json::to_value(&new).unwrap();

        let diff = PlaybookVersioning::diff(&old_json, &new_json, 1, 2);
        assert!(diff.changes.iter().any(|c| matches!(c,
            VersionChange::PropertyChanged { field, from, to }
            if field == "name" && from.contains("old-name") && to.contains("new-name")
        )));
    }

    #[test]
    fn test_diff_trigger_changed() {
        let old = Playbook::new("test", "alert");
        let mut new = old.clone();
        new.trigger_type = "scheduled".to_string();

        let old_json = serde_json::to_value(&old).unwrap();
        let new_json = serde_json::to_value(&new).unwrap();

        let diff = PlaybookVersioning::diff(&old_json, &new_json, 1, 2);
        assert!(diff.changes.iter().any(|c| matches!(c,
            VersionChange::TriggerChanged { from, to }
            if from == "alert" && to == "scheduled"
        )));
    }

    #[test]
    fn test_diff_stage_added() {
        let old = Playbook::new("test", "alert");
        let new = Playbook::new("test", "alert").with_stage(PlaybookStage::new("enrichment"));

        let old_json = serde_json::to_value(&old).unwrap();
        let new_json = serde_json::to_value(&new).unwrap();

        let diff = PlaybookVersioning::diff(&old_json, &new_json, 1, 2);
        assert!(diff.changes.iter().any(|c| matches!(c,
            VersionChange::StageAdded { stage_name }
            if stage_name == "enrichment"
        )));
    }

    #[test]
    fn test_diff_stage_removed() {
        let old = Playbook::new("test", "alert").with_stage(PlaybookStage::new("enrichment"));
        let new = Playbook::new("test", "alert");

        let old_json = serde_json::to_value(&old).unwrap();
        let new_json = serde_json::to_value(&new).unwrap();

        let diff = PlaybookVersioning::diff(&old_json, &new_json, 1, 2);
        assert!(diff.changes.iter().any(|c| matches!(c,
            VersionChange::StageRemoved { stage_name }
            if stage_name == "enrichment"
        )));
    }

    #[test]
    fn test_diff_step_added() {
        let old = Playbook::new("test", "alert").with_stage(PlaybookStage::new("enrichment"));
        let new = Playbook::new("test", "alert")
            .with_stage(PlaybookStage::new("enrichment").with_step(PlaybookStep::new("lookup_ip")));

        let old_json = serde_json::to_value(&old).unwrap();
        let new_json = serde_json::to_value(&new).unwrap();

        let diff = PlaybookVersioning::diff(&old_json, &new_json, 1, 2);
        assert!(diff.changes.iter().any(|c| matches!(c,
            VersionChange::StepAdded { stage_name, step_action }
            if stage_name == "enrichment" && step_action == "lookup_ip"
        )));
    }

    #[test]
    fn test_diff_step_removed() {
        let old = Playbook::new("test", "alert")
            .with_stage(PlaybookStage::new("enrichment").with_step(PlaybookStep::new("lookup_ip")));
        let new = Playbook::new("test", "alert").with_stage(PlaybookStage::new("enrichment"));

        let old_json = serde_json::to_value(&old).unwrap();
        let new_json = serde_json::to_value(&new).unwrap();

        let diff = PlaybookVersioning::diff(&old_json, &new_json, 1, 2);
        assert!(diff.changes.iter().any(|c| matches!(c,
            VersionChange::StepRemoved { stage_name, step_action }
            if stage_name == "enrichment" && step_action == "lookup_ip"
        )));
    }

    #[test]
    fn test_diff_step_modified() {
        let old = Playbook::new("test", "alert")
            .with_stage(PlaybookStage::new("enrichment").with_step(PlaybookStep::new("lookup_ip")));
        let new = Playbook::new("test", "alert").with_stage(
            PlaybookStage::new("enrichment")
                .with_step(PlaybookStep::new("lookup_ip").with_requires_approval(true)),
        );

        let old_json = serde_json::to_value(&old).unwrap();
        let new_json = serde_json::to_value(&new).unwrap();

        let diff = PlaybookVersioning::diff(&old_json, &new_json, 1, 2);
        assert!(diff.changes.iter().any(|c| matches!(c,
            VersionChange::StepModified { stage_name, step_action, .. }
            if stage_name == "enrichment" && step_action == "lookup_ip"
        )));
    }

    #[test]
    fn test_diff_stage_parallel_changed() {
        let old = Playbook::new("test", "alert").with_stage(PlaybookStage::new("enrichment"));
        let new = Playbook::new("test", "alert")
            .with_stage(PlaybookStage::new("enrichment").with_parallel(true));

        let old_json = serde_json::to_value(&old).unwrap();
        let new_json = serde_json::to_value(&new).unwrap();

        let diff = PlaybookVersioning::diff(&old_json, &new_json, 1, 2);
        assert!(diff.changes.iter().any(|c| matches!(c,
            VersionChange::StageModified { stage_name, detail }
            if stage_name == "enrichment" && detail.contains("parallel")
        )));
    }

    #[test]
    fn test_version_change_serialization() {
        let changes = vec![
            VersionChange::StageAdded {
                stage_name: "new".to_string(),
            },
            VersionChange::StageRemoved {
                stage_name: "old".to_string(),
            },
            VersionChange::StageModified {
                stage_name: "s".to_string(),
                detail: "d".to_string(),
            },
            VersionChange::StepAdded {
                stage_name: "s".to_string(),
                step_action: "a".to_string(),
            },
            VersionChange::StepRemoved {
                stage_name: "s".to_string(),
                step_action: "a".to_string(),
            },
            VersionChange::StepModified {
                stage_name: "s".to_string(),
                step_action: "a".to_string(),
                detail: "d".to_string(),
            },
            VersionChange::TriggerChanged {
                from: "a".to_string(),
                to: "b".to_string(),
            },
            VersionChange::PropertyChanged {
                field: "f".to_string(),
                from: "a".to_string(),
                to: "b".to_string(),
            },
        ];

        for change in &changes {
            let json = serde_json::to_string(change).unwrap();
            let deserialized: VersionChange = serde_json::from_str(&json).unwrap();
            assert_eq!(&deserialized, change);
        }
    }

    #[test]
    fn test_version_diff_serialization() {
        let diff = VersionDiff {
            from_version: 1,
            to_version: 3,
            changes: vec![VersionChange::StageAdded {
                stage_name: "new_stage".to_string(),
            }],
        };

        let json = serde_json::to_string(&diff).unwrap();
        let deserialized: VersionDiff = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.from_version, 1);
        assert_eq!(deserialized.to_version, 3);
        assert_eq!(deserialized.changes.len(), 1);
    }
}
