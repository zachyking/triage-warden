//! Sandbox submission pipeline.
//!
//! Provides automated submission of artifacts from incidents to malware
//! sandboxes based on configurable rules, with result polling and attachment.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use uuid::Uuid;

/// Rule determining when to submit artifacts to a sandbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxSubmissionRule {
    /// Unique identifier.
    pub id: Uuid,
    /// Human-readable name for the rule.
    pub name: String,
    /// Whether this rule is enabled.
    pub enabled: bool,
    /// Minimum severity to trigger submission.
    pub min_severity: Option<SeverityFilter>,
    /// Incident types that trigger submission.
    pub incident_types: Vec<String>,
    /// File types to submit (e.g., "exe", "dll", "pdf", "doc").
    pub file_types: Vec<String>,
    /// Maximum file size in bytes to submit.
    pub max_file_size: Option<u64>,
    /// Target sandbox provider(s).
    pub sandbox_providers: Vec<String>,
    /// Whether to use private/non-public analysis.
    pub private_analysis: bool,
    /// Analysis timeout in seconds.
    pub analysis_timeout_secs: u64,
    /// When this rule was created.
    pub created_at: DateTime<Utc>,
}

impl SandboxSubmissionRule {
    /// Creates a new submission rule with defaults.
    pub fn new(name: &str) -> Self {
        Self {
            id: Uuid::new_v4(),
            name: name.to_string(),
            enabled: true,
            min_severity: None,
            incident_types: Vec::new(),
            file_types: vec![
                "exe".to_string(),
                "dll".to_string(),
                "scr".to_string(),
                "bat".to_string(),
                "ps1".to_string(),
                "vbs".to_string(),
                "js".to_string(),
            ],
            max_file_size: Some(50 * 1024 * 1024), // 50 MB
            sandbox_providers: Vec::new(),
            private_analysis: true,
            analysis_timeout_secs: 300,
            created_at: Utc::now(),
        }
    }

    /// Checks if a file matches this rule.
    pub fn matches_file(&self, file_extension: &str, file_size: u64) -> bool {
        if !self.enabled {
            return false;
        }

        // Check file size
        if let Some(max_size) = self.max_file_size {
            if file_size > max_size {
                return false;
            }
        }

        // Check file type
        if !self.file_types.is_empty() {
            let ext = file_extension
                .to_lowercase()
                .trim_start_matches('.')
                .to_string();
            if !self.file_types.iter().any(|ft| ft.to_lowercase() == ext) {
                return false;
            }
        }

        true
    }

    /// Checks if an incident severity matches this rule.
    pub fn matches_severity(&self, severity: &str) -> bool {
        match &self.min_severity {
            None => true,
            Some(min) => {
                let severity_level = severity_to_level(severity);
                let min_level = match min {
                    SeverityFilter::Low => 1,
                    SeverityFilter::Medium => 2,
                    SeverityFilter::High => 3,
                    SeverityFilter::Critical => 4,
                };
                severity_level >= min_level
            }
        }
    }
}

fn severity_to_level(severity: &str) -> u8 {
    match severity.to_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

/// Severity filter for submission rules.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SeverityFilter {
    Low,
    Medium,
    High,
    Critical,
}

/// An artifact extracted from an incident for sandbox submission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentArtifact {
    /// Unique identifier.
    pub id: Uuid,
    /// Incident this artifact belongs to.
    pub incident_id: Uuid,
    /// Type of artifact.
    pub artifact_type: ArtifactType,
    /// File name (if file artifact).
    pub filename: Option<String>,
    /// File extension.
    pub file_extension: Option<String>,
    /// File size in bytes.
    pub file_size: Option<u64>,
    /// SHA256 hash (if available).
    pub sha256: Option<String>,
    /// URL (if URL artifact).
    pub url: Option<String>,
    /// When the artifact was extracted.
    pub extracted_at: DateTime<Utc>,
}

/// Type of incident artifact.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactType {
    File,
    Url,
    EmailAttachment,
    DroppedFile,
}

/// Status of a sandbox submission in the pipeline.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PipelineStatus {
    /// Queued for submission.
    Queued,
    /// Submitted to sandbox, awaiting results.
    Submitted,
    /// Analysis complete, results available.
    Completed,
    /// Submission or analysis failed.
    Failed(String),
}

/// A submission in the pipeline queue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineSubmission {
    /// Unique identifier.
    pub id: Uuid,
    /// Incident ID.
    pub incident_id: Uuid,
    /// Artifact being submitted.
    pub artifact: IncidentArtifact,
    /// Rule that triggered the submission.
    pub rule_id: Uuid,
    /// Target sandbox provider.
    pub sandbox_provider: String,
    /// Sandbox submission ID (once submitted).
    pub submission_id: Option<String>,
    /// Current status.
    pub status: PipelineStatus,
    /// Number of poll attempts.
    pub poll_count: u32,
    /// Maximum poll attempts.
    pub max_polls: u32,
    /// When the submission was queued.
    pub queued_at: DateTime<Utc>,
    /// When the submission was sent to the sandbox.
    pub submitted_at: Option<DateTime<Utc>>,
    /// When the submission was completed.
    pub completed_at: Option<DateTime<Utc>>,
}

/// In-memory pipeline queue with rate limiting.
pub struct SubmissionQueue {
    queue: VecDeque<PipelineSubmission>,
    max_concurrent: usize,
    active_count: usize,
}

impl SubmissionQueue {
    /// Creates a new submission queue.
    pub fn new(max_concurrent: usize) -> Self {
        Self {
            queue: VecDeque::new(),
            max_concurrent,
            active_count: 0,
        }
    }

    /// Adds a submission to the queue.
    pub fn enqueue(&mut self, submission: PipelineSubmission) {
        self.queue.push_back(submission);
    }

    /// Gets the next submission if capacity allows.
    pub fn dequeue(&mut self) -> Option<PipelineSubmission> {
        if self.active_count >= self.max_concurrent {
            return None;
        }
        if let Some(submission) = self.queue.pop_front() {
            self.active_count += 1;
            Some(submission)
        } else {
            None
        }
    }

    /// Marks a submission as complete, freeing capacity.
    pub fn mark_complete(&mut self) {
        self.active_count = self.active_count.saturating_sub(1);
    }

    /// Returns the number of queued submissions.
    pub fn queued_count(&self) -> usize {
        self.queue.len()
    }

    /// Returns the number of active (in-flight) submissions.
    pub fn active_count(&self) -> usize {
        self.active_count
    }

    /// Returns total capacity.
    pub fn max_concurrent(&self) -> usize {
        self.max_concurrent
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_submission_rule_creation() {
        let rule = SandboxSubmissionRule::new("Test Rule");
        assert!(rule.enabled);
        assert_eq!(rule.name, "Test Rule");
        assert!(rule.file_types.contains(&"exe".to_string()));
        assert!(rule.private_analysis);
    }

    #[test]
    fn test_rule_matches_file() {
        let rule = SandboxSubmissionRule::new("Test");

        assert!(rule.matches_file("exe", 1000));
        assert!(rule.matches_file(".dll", 1000));
        assert!(rule.matches_file("PS1", 1000));
        assert!(!rule.matches_file("txt", 1000));
        assert!(!rule.matches_file("exe", 100 * 1024 * 1024)); // Too large
    }

    #[test]
    fn test_rule_matches_severity() {
        let mut rule = SandboxSubmissionRule::new("Test");
        rule.min_severity = Some(SeverityFilter::High);

        assert!(rule.matches_severity("critical"));
        assert!(rule.matches_severity("high"));
        assert!(!rule.matches_severity("medium"));
        assert!(!rule.matches_severity("low"));
    }

    #[test]
    fn test_rule_no_severity_filter() {
        let rule = SandboxSubmissionRule::new("Test");
        assert!(rule.matches_severity("low"));
        assert!(rule.matches_severity("critical"));
    }

    #[test]
    fn test_disabled_rule() {
        let mut rule = SandboxSubmissionRule::new("Test");
        rule.enabled = false;
        assert!(!rule.matches_file("exe", 1000));
    }

    #[test]
    fn test_submission_queue() {
        let mut queue = SubmissionQueue::new(2);
        assert_eq!(queue.max_concurrent(), 2);
        assert_eq!(queue.queued_count(), 0);
        assert_eq!(queue.active_count(), 0);

        let submission = PipelineSubmission {
            id: Uuid::new_v4(),
            incident_id: Uuid::new_v4(),
            artifact: IncidentArtifact {
                id: Uuid::new_v4(),
                incident_id: Uuid::new_v4(),
                artifact_type: ArtifactType::File,
                filename: Some("malware.exe".to_string()),
                file_extension: Some("exe".to_string()),
                file_size: Some(1024),
                sha256: None,
                url: None,
                extracted_at: Utc::now(),
            },
            rule_id: Uuid::new_v4(),
            sandbox_provider: "mock".to_string(),
            submission_id: None,
            status: PipelineStatus::Queued,
            poll_count: 0,
            max_polls: 60,
            queued_at: Utc::now(),
            submitted_at: None,
            completed_at: None,
        };

        queue.enqueue(submission.clone());
        queue.enqueue(submission.clone());
        queue.enqueue(submission);

        assert_eq!(queue.queued_count(), 3);

        // Dequeue 2 (max concurrent)
        assert!(queue.dequeue().is_some());
        assert!(queue.dequeue().is_some());
        assert_eq!(queue.active_count(), 2);
        assert!(queue.dequeue().is_none()); // At capacity

        // Complete one
        queue.mark_complete();
        assert_eq!(queue.active_count(), 1);
        assert!(queue.dequeue().is_some()); // Can dequeue now
    }

    #[test]
    fn test_pipeline_status_serialization() {
        let status = PipelineStatus::Completed;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"completed\"");

        let failed = PipelineStatus::Failed("timeout".to_string());
        let json = serde_json::to_string(&failed).unwrap();
        assert!(json.contains("timeout"));
    }

    #[test]
    fn test_artifact_type_serialization() {
        let at = ArtifactType::EmailAttachment;
        let json = serde_json::to_string(&at).unwrap();
        assert_eq!(json, "\"email_attachment\"");
    }

    #[test]
    fn test_severity_filter_ordering() {
        assert_eq!(severity_to_level("critical"), 4);
        assert_eq!(severity_to_level("high"), 3);
        assert_eq!(severity_to_level("medium"), 2);
        assert_eq!(severity_to_level("low"), 1);
        assert_eq!(severity_to_level("info"), 0);
    }
}
