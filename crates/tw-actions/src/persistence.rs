//! Local persistence helpers for action records.
//!
//! Records are stored as append-only JSON Lines (JSONL) files to provide
//! durable, auditable action-specific trails even when no external store is
//! configured.

use crate::registry::{ActionContext, ActionError};
use serde::Serialize;
use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

const PERSISTENCE_DIR_METADATA_KEY: &str = "persistence_dir";
const PERSISTENCE_DIR_ENV: &str = "TW_ACTIONS_PERSIST_DIR";
fn default_persistence_dir() -> PathBuf {
    std::env::temp_dir().join("triage-warden/action-records")
}

fn resolve_persistence_dir(context: &ActionContext) -> Result<PathBuf, ActionError> {
    if let Some(value) = context.metadata.get(PERSISTENCE_DIR_METADATA_KEY) {
        let dir = value.as_str().ok_or_else(|| {
            ActionError::InvalidParameters(format!(
                "Context metadata '{}' must be a string path",
                PERSISTENCE_DIR_METADATA_KEY
            ))
        })?;
        if dir.trim().is_empty() {
            return Err(ActionError::InvalidParameters(format!(
                "Context metadata '{}' must not be empty",
                PERSISTENCE_DIR_METADATA_KEY
            )));
        }
        return Ok(PathBuf::from(dir));
    }

    if let Ok(dir) = std::env::var(PERSISTENCE_DIR_ENV) {
        if !dir.trim().is_empty() {
            return Ok(PathBuf::from(dir));
        }
    }

    Ok(default_persistence_dir())
}

fn validate_file_name(file_name: &str) -> Result<(), ActionError> {
    if file_name.trim().is_empty() {
        return Err(ActionError::ExecutionFailed(
            "Persistence file name must not be empty".to_string(),
        ));
    }
    if file_name.contains('/') || file_name.contains('\\') || file_name.contains("..") {
        return Err(ActionError::ExecutionFailed(format!(
            "Invalid persistence file name '{}'",
            file_name
        )));
    }
    Ok(())
}

/// Persists a serializable record as a JSONL line in the configured action store.
///
/// Returns the full path to the file that was written.
pub fn persist_jsonl_record<T: Serialize>(
    context: &ActionContext,
    file_name: &str,
    record: &T,
) -> Result<String, ActionError> {
    validate_file_name(file_name)?;
    let persistence_dir = resolve_persistence_dir(context)?;

    create_dir_all(&persistence_dir).map_err(|e| {
        ActionError::ExecutionFailed(format!(
            "Failed to create persistence directory '{}': {}",
            persistence_dir.display(),
            e
        ))
    })?;

    let file_path = persistence_dir.join(file_name);
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(&file_path).map_err(|e| {
        ActionError::ExecutionFailed(format!(
            "Failed to open persistence file '{}': {}",
            file_path.display(),
            e
        ))
    })?;

    let line = serde_json::to_string(record).map_err(|e| {
        ActionError::ExecutionFailed(format!("Failed to serialize persistence record: {}", e))
    })?;

    let mut line_bytes = line.into_bytes();
    line_bytes.push(b'\n');
    file.write_all(&line_bytes).map_err(|e| {
        ActionError::ExecutionFailed(format!(
            "Failed to write persistence file '{}': {}",
            file_path.display(),
            e
        ))
    })?;
    file.sync_data().map_err(|e| {
        ActionError::ExecutionFailed(format!(
            "Failed to sync persistence file '{}': {}",
            file_path.display(),
            e
        ))
    })?;

    Ok(file_path.to_string_lossy().to_string())
}
