//! Mock sandbox connector for testing.

use super::{
    Behavior, MalwareSandbox, NetworkIndicators, SandboxAnalysisStatus, SandboxReport,
    SandboxVerdict, SubmissionId, SubmissionOptions,
};
use crate::traits::{ConnectorError, ConnectorHealth, ConnectorResult};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Mock sandbox connector for testing.
pub struct MockSandboxConnector {
    name: String,
    reports: Arc<RwLock<HashMap<String, SandboxReport>>>,
    statuses: Arc<RwLock<HashMap<String, SandboxAnalysisStatus>>>,
    submission_counter: AtomicU64,
}

impl MockSandboxConnector {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            reports: Arc::new(RwLock::new(HashMap::new())),
            statuses: Arc::new(RwLock::new(HashMap::new())),
            submission_counter: AtomicU64::new(0),
        }
    }

    /// Adds a preconfigured report for a submission ID.
    pub async fn add_report(&self, submission_id: &str, report: SandboxReport) {
        let mut reports = self.reports.write().await;
        reports.insert(submission_id.to_string(), report);
    }

    /// Sets the status for a submission ID.
    pub async fn set_status(&self, submission_id: &str, status: SandboxAnalysisStatus) {
        let mut statuses = self.statuses.write().await;
        statuses.insert(submission_id.to_string(), status);
    }

    pub fn get_submission_count(&self) -> u64 {
        self.submission_counter.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl crate::traits::Connector for MockSandboxConnector {
    fn name(&self) -> &str {
        &self.name
    }

    fn connector_type(&self) -> &str {
        "sandbox"
    }

    async fn health_check(&self) -> ConnectorResult<ConnectorHealth> {
        Ok(ConnectorHealth::Healthy)
    }

    async fn test_connection(&self) -> ConnectorResult<bool> {
        Ok(true)
    }
}

#[async_trait]
impl MalwareSandbox for MockSandboxConnector {
    async fn submit_file(
        &self,
        _file: &[u8],
        filename: &str,
        _options: &SubmissionOptions,
    ) -> ConnectorResult<SubmissionId> {
        let id = self.submission_counter.fetch_add(1, Ordering::SeqCst);
        let submission_id = format!("mock-file-{}-{}", filename, id);

        // Create a default report
        let report = SandboxReport {
            submission_id: SubmissionId(submission_id.clone()),
            verdict: SandboxVerdict::Suspicious,
            threat_score: 50,
            malware_family: None,
            tags: vec!["mock".to_string()],
            mitre_techniques: vec![],
            behaviors: vec![Behavior {
                description: "File created in temp directory".to_string(),
                severity: "medium".to_string(),
                category: "file_system".to_string(),
            }],
            network_indicators: NetworkIndicators::default(),
            file_indicators: vec![],
            registry_modifications: vec![],
            processes: vec![],
            signatures: vec![],
            screenshots: vec![],
            analysis_duration_secs: 120,
            environment: "Mock Windows 10".to_string(),
            completed_at: chrono::Utc::now(),
            source: "Mock Sandbox".to_string(),
            raw_report: None,
        };

        let mut reports = self.reports.write().await;
        reports.insert(submission_id.clone(), report);

        let mut statuses = self.statuses.write().await;
        statuses.insert(submission_id.clone(), SandboxAnalysisStatus::Completed);

        Ok(SubmissionId(submission_id))
    }

    async fn submit_url(
        &self,
        url: &str,
        _options: &SubmissionOptions,
    ) -> ConnectorResult<SubmissionId> {
        let id = self.submission_counter.fetch_add(1, Ordering::SeqCst);
        let submission_id = format!("mock-url-{}", id);

        let report = SandboxReport {
            submission_id: SubmissionId(submission_id.clone()),
            verdict: SandboxVerdict::Clean,
            threat_score: 10,
            malware_family: None,
            tags: vec!["mock".to_string(), "url".to_string()],
            mitre_techniques: vec![],
            behaviors: vec![],
            network_indicators: NetworkIndicators {
                urls: vec![url.to_string()],
                ..Default::default()
            },
            file_indicators: vec![],
            registry_modifications: vec![],
            processes: vec![],
            signatures: vec![],
            screenshots: vec![],
            analysis_duration_secs: 60,
            environment: "Mock Windows 10".to_string(),
            completed_at: chrono::Utc::now(),
            source: "Mock Sandbox".to_string(),
            raw_report: None,
        };

        let mut reports = self.reports.write().await;
        reports.insert(submission_id.clone(), report);

        let mut statuses = self.statuses.write().await;
        statuses.insert(submission_id.clone(), SandboxAnalysisStatus::Completed);

        Ok(SubmissionId(submission_id))
    }

    async fn get_report(&self, submission_id: &SubmissionId) -> ConnectorResult<SandboxReport> {
        let reports = self.reports.read().await;
        reports
            .get(&submission_id.0)
            .cloned()
            .ok_or_else(|| ConnectorError::NotFound(format!("Report not found: {}", submission_id)))
    }

    async fn get_status(
        &self,
        submission_id: &SubmissionId,
    ) -> ConnectorResult<SandboxAnalysisStatus> {
        let statuses = self.statuses.read().await;
        Ok(statuses
            .get(&submission_id.0)
            .cloned()
            .unwrap_or(SandboxAnalysisStatus::Queued))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_submit_file() {
        let mock = MockSandboxConnector::new("test-mock");
        let opts = SubmissionOptions::default();
        let id = mock
            .submit_file(b"test content", "test.exe", &opts)
            .await
            .unwrap();

        assert!(id.0.contains("mock-file-test.exe"));
        assert_eq!(mock.get_submission_count(), 1);
    }

    #[tokio::test]
    async fn test_mock_submit_url() {
        let mock = MockSandboxConnector::new("test-mock");
        let opts = SubmissionOptions::default();
        let id = mock.submit_url("https://example.com", &opts).await.unwrap();

        assert!(id.0.contains("mock-url-"));
    }

    #[tokio::test]
    async fn test_mock_get_report() {
        let mock = MockSandboxConnector::new("test-mock");
        let opts = SubmissionOptions::default();
        let id = mock
            .submit_file(b"test", "malware.exe", &opts)
            .await
            .unwrap();

        let report = mock.get_report(&id).await.unwrap();
        assert_eq!(report.verdict, SandboxVerdict::Suspicious);
        assert_eq!(report.source, "Mock Sandbox");
    }

    #[tokio::test]
    async fn test_mock_get_status() {
        let mock = MockSandboxConnector::new("test-mock");
        let opts = SubmissionOptions::default();
        let id = mock.submit_file(b"test", "test.exe", &opts).await.unwrap();

        let status = mock.get_status(&id).await.unwrap();
        assert_eq!(status, SandboxAnalysisStatus::Completed);
    }

    #[tokio::test]
    async fn test_mock_report_not_found() {
        let mock = MockSandboxConnector::new("test-mock");
        let result = mock
            .get_report(&SubmissionId("nonexistent".to_string()))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_mock_custom_report() {
        let mock = MockSandboxConnector::new("test-mock");

        let custom_report = SandboxReport {
            submission_id: SubmissionId("custom-1".to_string()),
            verdict: SandboxVerdict::Malicious,
            threat_score: 95,
            malware_family: Some("Emotet".to_string()),
            tags: vec!["trojan".to_string()],
            mitre_techniques: vec!["T1055".to_string()],
            behaviors: vec![],
            network_indicators: NetworkIndicators::default(),
            file_indicators: vec![],
            registry_modifications: vec![],
            processes: vec![],
            signatures: vec![],
            screenshots: vec![],
            analysis_duration_secs: 300,
            environment: "Windows 10".to_string(),
            completed_at: chrono::Utc::now(),
            source: "Mock".to_string(),
            raw_report: None,
        };

        mock.add_report("custom-1", custom_report).await;

        let report = mock
            .get_report(&SubmissionId("custom-1".to_string()))
            .await
            .unwrap();
        assert_eq!(report.verdict, SandboxVerdict::Malicious);
        assert_eq!(report.malware_family, Some("Emotet".to_string()));
    }
}
