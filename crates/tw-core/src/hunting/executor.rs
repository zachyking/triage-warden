//! Hunt execution engine and finding models.
//!
//! Provides [`HuntExecutor`] for running hunts and evaluating results,
//! [`Finding`] for individual hunt findings, and [`ThresholdEvaluator`]
//! for baseline anomaly detection.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::hunt::{HuntingHunt, HuntingQuery};

/// Result of executing a hunt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HuntResult {
    /// ID of the hunt that was executed.
    pub hunt_id: Uuid,
    /// Findings from the execution.
    pub findings: Vec<Finding>,
    /// Number of queries that executed successfully.
    pub queries_executed: usize,
    /// Number of queries that failed.
    pub queries_failed: usize,
    /// When execution started.
    pub started_at: DateTime<Utc>,
    /// When execution completed.
    pub completed_at: DateTime<Utc>,
    /// Overall execution status.
    pub status: ExecutionStatus,
}

impl HuntResult {
    /// Returns the total number of findings.
    pub fn total_findings(&self) -> usize {
        self.findings.len()
    }

    /// Returns the number of critical findings.
    pub fn critical_findings(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == FindingSeverity::Critical)
            .count()
    }

    /// Returns the execution duration in seconds.
    pub fn duration_secs(&self) -> f64 {
        (self.completed_at - self.started_at).num_milliseconds() as f64 / 1000.0
    }
}

/// Overall execution status of a hunt run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStatus {
    /// All queries executed successfully.
    Success,
    /// Some queries failed but at least one succeeded.
    PartialFailure,
    /// All queries failed.
    Failed,
}

/// A finding from a hunt execution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Finding {
    /// Unique identifier for this finding.
    pub id: Uuid,
    /// ID of the hunt that produced this finding.
    pub hunt_id: Uuid,
    /// Type of finding.
    pub finding_type: FindingType,
    /// Severity of the finding.
    pub severity: FindingSeverity,
    /// Short title for the finding.
    pub title: String,
    /// Detailed description.
    pub description: String,
    /// Raw evidence data.
    pub evidence: serde_json::Value,
    /// ID of the query that produced this finding.
    pub query_id: String,
    /// When the finding was detected.
    pub detected_at: DateTime<Utc>,
    /// If promoted, the incident ID.
    pub promoted_to_incident: Option<Uuid>,
}

impl Finding {
    /// Creates a new finding.
    pub fn new(
        hunt_id: Uuid,
        finding_type: FindingType,
        severity: FindingSeverity,
        title: impl Into<String>,
        description: impl Into<String>,
        query_id: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            hunt_id,
            finding_type,
            severity,
            title: title.into(),
            description: description.into(),
            evidence: serde_json::Value::Null,
            query_id: query_id.into(),
            detected_at: Utc::now(),
            promoted_to_incident: None,
        }
    }

    /// Sets the evidence data.
    pub fn with_evidence(mut self, evidence: serde_json::Value) -> Self {
        self.evidence = evidence;
        self
    }
}

/// Classification of what a finding represents.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FindingType {
    /// Count deviates from expected baseline.
    AnomalousCount { expected: u64, actual: u64 },
    /// A specific pattern was matched.
    PatternMatch { pattern: String },
    /// A previously unseen entity appeared.
    NewEntity { entity_type: String, value: String },
    /// A metric exceeded a defined threshold.
    Threshold {
        metric: String,
        value: f64,
        threshold: f64,
    },
    /// Behavioral anomaly detected.
    Behavioral { description: String },
}

/// Severity level for findings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    /// Informational only.
    Informational,
    /// Low severity.
    Low,
    /// Medium severity.
    Medium,
    /// High severity.
    High,
    /// Critical severity.
    Critical,
}

impl std::fmt::Display for FindingSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FindingSeverity::Informational => write!(f, "Informational"),
            FindingSeverity::Low => write!(f, "Low"),
            FindingSeverity::Medium => write!(f, "Medium"),
            FindingSeverity::High => write!(f, "High"),
            FindingSeverity::Critical => write!(f, "Critical"),
        }
    }
}

/// Evaluates whether query results exceed baseline thresholds.
pub struct ThresholdEvaluator;

impl ThresholdEvaluator {
    /// Evaluates whether the actual count is anomalous compared to baseline.
    ///
    /// Returns `Some(FindingType)` if anomalous, `None` if within expected range.
    /// Uses a multiplier-based approach: actual > baseline * multiplier is anomalous.
    pub fn evaluate_count(
        actual: u64,
        expected_baseline: u64,
        multiplier: f64,
    ) -> Option<FindingType> {
        let threshold = (expected_baseline as f64 * multiplier) as u64;
        if actual > threshold {
            Some(FindingType::AnomalousCount {
                expected: expected_baseline,
                actual,
            })
        } else {
            None
        }
    }

    /// Evaluates whether a metric value exceeds the given threshold.
    pub fn evaluate_threshold(
        metric: impl Into<String>,
        value: f64,
        threshold: f64,
    ) -> Option<FindingType> {
        if value > threshold {
            Some(FindingType::Threshold {
                metric: metric.into(),
                value,
                threshold,
            })
        } else {
            None
        }
    }
}

/// Executes hunts and collects findings.
pub struct HuntExecutor {
    /// Multiplier for baseline anomaly detection (default: 3.0).
    pub anomaly_multiplier: f64,
}

impl Default for HuntExecutor {
    fn default() -> Self {
        Self {
            anomaly_multiplier: 3.0,
        }
    }
}

impl HuntExecutor {
    /// Creates a new executor with the default anomaly multiplier.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a new executor with a custom anomaly multiplier.
    pub fn with_anomaly_multiplier(mut self, multiplier: f64) -> Self {
        self.anomaly_multiplier = multiplier;
        self
    }

    /// Simulates executing a hunt and returns the result.
    ///
    /// In production this would dispatch queries to actual SIEM/EDR backends.
    /// This implementation validates the hunt and creates a result structure
    /// suitable for testing and development.
    pub async fn execute(&self, hunt: &HuntingHunt) -> HuntResult {
        let started_at = Utc::now();
        let findings = Vec::new();
        let mut queries_executed = 0;
        let mut queries_failed = 0;

        for query in &hunt.queries {
            if query.query.is_empty() {
                queries_failed += 1;
                continue;
            }
            queries_executed += 1;

            // Check for baseline threshold evaluation
            if let Some(baseline) = query.expected_baseline {
                // In a real implementation, this would run the query and get actual count.
                // For now, we just record the query was executed.
                let _ = ThresholdEvaluator::evaluate_count(0, baseline, self.anomaly_multiplier);
            }
        }

        let status = if queries_failed == 0 && queries_executed > 0 {
            ExecutionStatus::Success
        } else if queries_executed > 0 {
            ExecutionStatus::PartialFailure
        } else {
            ExecutionStatus::Failed
        };

        let completed_at = Utc::now();

        HuntResult {
            hunt_id: hunt.id,
            findings,
            queries_executed,
            queries_failed,
            started_at,
            completed_at,
            status,
        }
    }

    /// Creates a finding from query results.
    #[allow(clippy::too_many_arguments)]
    pub fn create_finding(
        &self,
        hunt_id: Uuid,
        query: &HuntingQuery,
        finding_type: FindingType,
        severity: FindingSeverity,
        title: impl Into<String>,
        description: impl Into<String>,
        evidence: serde_json::Value,
    ) -> Finding {
        Finding::new(
            hunt_id,
            finding_type,
            severity,
            title,
            description,
            &query.id,
        )
        .with_evidence(evidence)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hunting::hunt::{HuntingQuery, QueryType};

    #[test]
    fn test_finding_creation() {
        let hunt_id = Uuid::new_v4();
        let finding = Finding::new(
            hunt_id,
            FindingType::PatternMatch {
                pattern: "PsExec".to_string(),
            },
            FindingSeverity::High,
            "PsExec usage detected",
            "Remote execution via PsExec detected on host SERVER01",
            "q1",
        );

        assert_eq!(finding.hunt_id, hunt_id);
        assert_eq!(finding.severity, FindingSeverity::High);
        assert_eq!(finding.query_id, "q1");
        assert!(finding.promoted_to_incident.is_none());
    }

    #[test]
    fn test_finding_with_evidence() {
        let finding = Finding::new(
            Uuid::new_v4(),
            FindingType::NewEntity {
                entity_type: "process".to_string(),
                value: "mimikatz.exe".to_string(),
            },
            FindingSeverity::Critical,
            "New malicious process",
            "Previously unseen process mimikatz.exe",
            "q2",
        )
        .with_evidence(serde_json::json!({"host": "WKS001", "pid": 1234}));

        assert!(finding.evidence.is_object());
    }

    #[test]
    fn test_finding_severity_ordering() {
        assert!(FindingSeverity::Critical > FindingSeverity::High);
        assert!(FindingSeverity::High > FindingSeverity::Medium);
        assert!(FindingSeverity::Medium > FindingSeverity::Low);
        assert!(FindingSeverity::Low > FindingSeverity::Informational);
    }

    #[test]
    fn test_finding_severity_display() {
        assert_eq!(format!("{}", FindingSeverity::Critical), "Critical");
        assert_eq!(format!("{}", FindingSeverity::High), "High");
        assert_eq!(format!("{}", FindingSeverity::Medium), "Medium");
        assert_eq!(format!("{}", FindingSeverity::Low), "Low");
        assert_eq!(
            format!("{}", FindingSeverity::Informational),
            "Informational"
        );
    }

    #[test]
    fn test_threshold_evaluator_count_anomalous() {
        let result = ThresholdEvaluator::evaluate_count(100, 10, 3.0);
        assert!(result.is_some());
        match result.unwrap() {
            FindingType::AnomalousCount { expected, actual } => {
                assert_eq!(expected, 10);
                assert_eq!(actual, 100);
            }
            _ => panic!("Expected AnomalousCount"),
        }
    }

    #[test]
    fn test_threshold_evaluator_count_normal() {
        let result = ThresholdEvaluator::evaluate_count(25, 10, 3.0);
        assert!(result.is_none());
    }

    #[test]
    fn test_threshold_evaluator_count_boundary() {
        // Exactly at threshold (10 * 3.0 = 30) - should NOT be anomalous
        let result = ThresholdEvaluator::evaluate_count(30, 10, 3.0);
        assert!(result.is_none());

        // Just above threshold - should be anomalous
        let result = ThresholdEvaluator::evaluate_count(31, 10, 3.0);
        assert!(result.is_some());
    }

    #[test]
    fn test_threshold_evaluator_metric() {
        let result = ThresholdEvaluator::evaluate_threshold("cpu_percent", 95.0, 90.0);
        assert!(result.is_some());
        match result.unwrap() {
            FindingType::Threshold {
                metric,
                value,
                threshold,
            } => {
                assert_eq!(metric, "cpu_percent");
                assert_eq!(value, 95.0);
                assert_eq!(threshold, 90.0);
            }
            _ => panic!("Expected Threshold"),
        }
    }

    #[test]
    fn test_threshold_evaluator_metric_normal() {
        let result = ThresholdEvaluator::evaluate_threshold("cpu_percent", 50.0, 90.0);
        assert!(result.is_none());
    }

    #[test]
    fn test_hunt_result_helpers() {
        let now = Utc::now();
        let result = HuntResult {
            hunt_id: Uuid::new_v4(),
            findings: vec![
                Finding::new(
                    Uuid::new_v4(),
                    FindingType::PatternMatch {
                        pattern: "test".to_string(),
                    },
                    FindingSeverity::Critical,
                    "Critical finding",
                    "Description",
                    "q1",
                ),
                Finding::new(
                    Uuid::new_v4(),
                    FindingType::PatternMatch {
                        pattern: "test2".to_string(),
                    },
                    FindingSeverity::Low,
                    "Low finding",
                    "Description",
                    "q2",
                ),
            ],
            queries_executed: 2,
            queries_failed: 0,
            started_at: now,
            completed_at: now + chrono::Duration::seconds(10),
            status: ExecutionStatus::Success,
        };

        assert_eq!(result.total_findings(), 2);
        assert_eq!(result.critical_findings(), 1);
        assert!(result.duration_secs() >= 9.0);
    }

    #[tokio::test]
    async fn test_executor_success() {
        let executor = HuntExecutor::new();
        let hunt = HuntingHunt::new("Test", "Hypothesis").with_query(HuntingQuery {
            id: "q1".to_string(),
            query_type: QueryType::Splunk,
            query: "index=main | stats count".to_string(),
            description: "Count events".to_string(),
            timeout_secs: 60,
            expected_baseline: None,
        });

        let result = executor.execute(&hunt).await;
        assert_eq!(result.status, ExecutionStatus::Success);
        assert_eq!(result.queries_executed, 1);
        assert_eq!(result.queries_failed, 0);
    }

    #[tokio::test]
    async fn test_executor_empty_query_fails() {
        let executor = HuntExecutor::new();
        let hunt = HuntingHunt::new("Test", "Hypothesis").with_query(HuntingQuery {
            id: "q1".to_string(),
            query_type: QueryType::Splunk,
            query: "".to_string(),
            description: "Empty query".to_string(),
            timeout_secs: 60,
            expected_baseline: None,
        });

        let result = executor.execute(&hunt).await;
        assert_eq!(result.status, ExecutionStatus::Failed);
        assert_eq!(result.queries_executed, 0);
        assert_eq!(result.queries_failed, 1);
    }

    #[tokio::test]
    async fn test_executor_partial_failure() {
        let executor = HuntExecutor::new();
        let hunt = HuntingHunt::new("Test", "Hypothesis")
            .with_query(HuntingQuery {
                id: "q1".to_string(),
                query_type: QueryType::Splunk,
                query: "index=main".to_string(),
                description: "Valid query".to_string(),
                timeout_secs: 60,
                expected_baseline: None,
            })
            .with_query(HuntingQuery {
                id: "q2".to_string(),
                query_type: QueryType::Splunk,
                query: "".to_string(),
                description: "Empty query".to_string(),
                timeout_secs: 60,
                expected_baseline: None,
            });

        let result = executor.execute(&hunt).await;
        assert_eq!(result.status, ExecutionStatus::PartialFailure);
        assert_eq!(result.queries_executed, 1);
        assert_eq!(result.queries_failed, 1);
    }

    #[test]
    fn test_executor_create_finding() {
        let executor = HuntExecutor::new();
        let hunt_id = Uuid::new_v4();
        let query = HuntingQuery {
            id: "q1".to_string(),
            query_type: QueryType::Splunk,
            query: "index=main".to_string(),
            description: "test".to_string(),
            timeout_secs: 60,
            expected_baseline: None,
        };

        let finding = executor.create_finding(
            hunt_id,
            &query,
            FindingType::Behavioral {
                description: "Unusual login pattern".to_string(),
            },
            FindingSeverity::Medium,
            "Behavioral anomaly",
            "Detected unusual login pattern",
            serde_json::json!({"user": "admin", "logins": 50}),
        );

        assert_eq!(finding.hunt_id, hunt_id);
        assert_eq!(finding.query_id, "q1");
        assert_eq!(finding.severity, FindingSeverity::Medium);
    }

    #[test]
    fn test_finding_type_serialization() {
        let types: Vec<FindingType> = vec![
            FindingType::AnomalousCount {
                expected: 10,
                actual: 100,
            },
            FindingType::PatternMatch {
                pattern: "mimikatz".to_string(),
            },
            FindingType::NewEntity {
                entity_type: "process".to_string(),
                value: "evil.exe".to_string(),
            },
            FindingType::Threshold {
                metric: "bytes_out".to_string(),
                value: 1_000_000.0,
                threshold: 500_000.0,
            },
            FindingType::Behavioral {
                description: "Unusual pattern".to_string(),
            },
        ];

        for ft in types {
            let json = serde_json::to_string(&ft).unwrap();
            let back: FindingType = serde_json::from_str(&json).unwrap();
            assert_eq!(ft, back);
        }
    }

    #[test]
    fn test_execution_status_serialization() {
        let statuses = vec![
            (ExecutionStatus::Success, "\"success\""),
            (ExecutionStatus::PartialFailure, "\"partial_failure\""),
            (ExecutionStatus::Failed, "\"failed\""),
        ];

        for (status, expected) in statuses {
            let json = serde_json::to_string(&status).unwrap();
            assert_eq!(json, expected);
        }
    }

    #[test]
    fn test_executor_custom_multiplier() {
        let executor = HuntExecutor::new().with_anomaly_multiplier(5.0);
        assert_eq!(executor.anomaly_multiplier, 5.0);
    }
}
