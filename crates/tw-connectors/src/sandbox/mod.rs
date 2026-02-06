//! Malware sandbox connectors.
//!
//! This module provides integrations with malware analysis sandboxes
//! for automated file and URL detonation, report retrieval, and
//! behavioral analysis.

pub mod anyrun;
pub mod cuckoo;
pub mod hybrid_analysis;
pub mod joe_sandbox;
pub mod mock;

use crate::traits::{Connector, ConnectorResult};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub use anyrun::{AnyRunConfig, AnyRunConnector};
pub use cuckoo::{CuckooConfig, CuckooConnector};
pub use hybrid_analysis::{HybridAnalysisConfig, HybridAnalysisConnector};
pub use joe_sandbox::{JoeSandboxConfig, JoeSandboxConnector};
pub use mock::MockSandboxConnector;

/// Unique identifier for a sandbox submission.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SubmissionId(pub String);

impl std::fmt::Display for SubmissionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Options for sandbox submission.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SubmissionOptions {
    /// Custom tags for the submission.
    pub tags: Vec<String>,
    /// Environment/VM to run in (e.g., "win10", "win7", "linux").
    pub environment: Option<String>,
    /// Analysis timeout in seconds.
    pub timeout_secs: Option<u64>,
    /// Network simulation mode.
    pub network_mode: Option<NetworkMode>,
    /// Whether to use a private/non-public analysis.
    pub private: bool,
    /// Custom command line for the file.
    pub command_line: Option<String>,
    /// Additional options specific to the sandbox provider.
    pub extra: HashMap<String, serde_json::Value>,
}

/// Network simulation modes for sandbox analysis.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    /// Allow full internet access.
    Internet,
    /// Simulate network (fake DNS, etc.).
    Simulated,
    /// No network access.
    Disabled,
}

/// Status of a sandbox analysis.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SandboxAnalysisStatus {
    /// Queued for analysis.
    Queued,
    /// Currently running.
    Running,
    /// Analysis complete.
    Completed,
    /// Analysis failed.
    Failed(String),
}

/// Overall verdict from sandbox analysis.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SandboxVerdict {
    Malicious,
    Suspicious,
    Clean,
    Unknown,
}

/// Report from a sandbox analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxReport {
    /// Submission ID.
    pub submission_id: SubmissionId,
    /// Overall verdict.
    pub verdict: SandboxVerdict,
    /// Threat score (0-100).
    pub threat_score: u8,
    /// Malware family if identified.
    pub malware_family: Option<String>,
    /// Tags/labels from analysis.
    pub tags: Vec<String>,
    /// MITRE ATT&CK techniques observed.
    pub mitre_techniques: Vec<String>,
    /// Behavioral indicators.
    pub behaviors: Vec<Behavior>,
    /// Network indicators (IPs, domains, URLs).
    pub network_indicators: NetworkIndicators,
    /// File indicators (dropped files, etc.).
    pub file_indicators: Vec<FileIndicator>,
    /// Registry modifications (Windows).
    pub registry_modifications: Vec<RegistryModification>,
    /// Process tree.
    pub processes: Vec<ProcessActivity>,
    /// Signatures/rules that matched.
    pub signatures: Vec<Signature>,
    /// Screenshot URLs/paths.
    pub screenshots: Vec<String>,
    /// Analysis duration in seconds.
    pub analysis_duration_secs: u64,
    /// Environment used.
    pub environment: String,
    /// Timestamp when analysis completed.
    pub completed_at: DateTime<Utc>,
    /// Source sandbox provider.
    pub source: String,
    /// Raw report data for provider-specific details.
    pub raw_report: Option<serde_json::Value>,
}

/// Observed behavior during analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Behavior {
    /// Description of the behavior.
    pub description: String,
    /// Severity (info, low, medium, high, critical).
    pub severity: String,
    /// Category (e.g., "persistence", "evasion", "exfiltration").
    pub category: String,
}

/// Network indicators from sandbox analysis.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkIndicators {
    /// IP addresses contacted.
    pub ips: Vec<String>,
    /// Domains contacted.
    pub domains: Vec<String>,
    /// URLs accessed.
    pub urls: Vec<String>,
    /// DNS queries made.
    pub dns_queries: Vec<String>,
    /// HTTP requests.
    pub http_requests: Vec<HttpRequest>,
}

/// An HTTP request observed during sandbox analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub host: String,
    pub user_agent: Option<String>,
}

/// File indicator from sandbox analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileIndicator {
    /// File name.
    pub name: String,
    /// File path.
    pub path: String,
    /// SHA256 hash.
    pub sha256: Option<String>,
    /// File type.
    pub file_type: Option<String>,
    /// Size in bytes.
    pub size: Option<u64>,
    /// Action (created, modified, deleted, dropped).
    pub action: String,
}

/// Registry modification from sandbox analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryModification {
    pub key: String,
    pub value: Option<String>,
    pub action: String, // created, modified, deleted
}

/// Process activity from sandbox analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessActivity {
    pub pid: u32,
    pub name: String,
    pub command_line: Option<String>,
    pub parent_pid: Option<u32>,
}

/// Signature/rule that matched during analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub name: String,
    pub description: String,
    pub severity: String,
    pub category: Option<String>,
}

/// Trait for malware sandbox connectors.
#[async_trait]
pub trait MalwareSandbox: Connector {
    /// Submits a file for analysis.
    async fn submit_file(
        &self,
        file: &[u8],
        filename: &str,
        options: &SubmissionOptions,
    ) -> ConnectorResult<SubmissionId>;

    /// Submits a URL for analysis.
    async fn submit_url(
        &self,
        url: &str,
        options: &SubmissionOptions,
    ) -> ConnectorResult<SubmissionId>;

    /// Gets the analysis report for a submission.
    async fn get_report(&self, submission_id: &SubmissionId) -> ConnectorResult<SandboxReport>;

    /// Gets the analysis status for a submission.
    async fn get_status(
        &self,
        submission_id: &SubmissionId,
    ) -> ConnectorResult<SandboxAnalysisStatus>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_submission_id_display() {
        let id = SubmissionId("abc-123".to_string());
        assert_eq!(id.to_string(), "abc-123");
    }

    #[test]
    fn test_default_submission_options() {
        let opts = SubmissionOptions::default();
        assert!(opts.tags.is_empty());
        assert!(opts.environment.is_none());
        assert!(!opts.private);
    }

    #[test]
    fn test_sandbox_verdict_serialization() {
        let verdict = SandboxVerdict::Malicious;
        let json = serde_json::to_string(&verdict).unwrap();
        assert_eq!(json, "\"malicious\"");

        let parsed: SandboxVerdict = serde_json::from_str("\"suspicious\"").unwrap();
        assert_eq!(parsed, SandboxVerdict::Suspicious);
    }

    #[test]
    fn test_analysis_status_serialization() {
        let status = SandboxAnalysisStatus::Completed;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"completed\"");
    }

    #[test]
    fn test_network_indicators_default() {
        let indicators = NetworkIndicators::default();
        assert!(indicators.ips.is_empty());
        assert!(indicators.domains.is_empty());
    }
}
