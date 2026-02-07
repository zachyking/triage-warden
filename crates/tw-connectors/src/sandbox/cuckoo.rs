//! Cuckoo Sandbox connector.

use super::{
    MalwareSandbox, SandboxAnalysisStatus, SandboxReport, SandboxVerdict, SubmissionId,
    SubmissionOptions,
};
use crate::http::{HttpClient, RateLimitConfig};
use crate::traits::{ConnectorConfig, ConnectorError, ConnectorHealth, ConnectorResult};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::info;

/// Cuckoo Sandbox configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CuckooConfig {
    #[serde(flatten)]
    pub connector: ConnectorConfig,
    #[serde(default = "default_rate_limit")]
    pub requests_per_minute: u32,
}

fn default_rate_limit() -> u32 {
    30
}

/// Cuckoo Sandbox connector.
pub struct CuckooConnector {
    config: CuckooConfig,
    client: HttpClient,
}

impl CuckooConnector {
    pub fn new(config: CuckooConfig) -> ConnectorResult<Self> {
        let rate_limit = RateLimitConfig {
            max_requests: config.requests_per_minute,
            period: Duration::from_secs(60),
            burst_size: 5,
        };

        let client = HttpClient::with_rate_limit(config.connector.clone(), Some(rate_limit))?;

        info!("Cuckoo Sandbox connector initialized");

        Ok(Self { config, client })
    }
}

#[async_trait]
impl crate::traits::Connector for CuckooConnector {
    fn name(&self) -> &str {
        &self.config.connector.name
    }

    fn connector_type(&self) -> &str {
        "sandbox"
    }

    async fn health_check(&self) -> ConnectorResult<ConnectorHealth> {
        match self.client.get("/cuckoo/status").await {
            Ok(r) if r.status().is_success() => Ok(ConnectorHealth::Healthy),
            Ok(r) => Ok(ConnectorHealth::Unhealthy(format!(
                "Status: {}",
                r.status()
            ))),
            Err(e) => Ok(ConnectorHealth::Unhealthy(e.to_string())),
        }
    }

    async fn test_connection(&self) -> ConnectorResult<bool> {
        let response = self.client.get("/cuckoo/status").await?;
        Ok(response.status().is_success())
    }
}

#[async_trait]
impl MalwareSandbox for CuckooConnector {
    async fn submit_file(
        &self,
        file: &[u8],
        filename: &str,
        options: &SubmissionOptions,
    ) -> ConnectorResult<SubmissionId> {
        if file.is_empty() {
            return Err(ConnectorError::InvalidRequest(
                "Cannot submit an empty file".to_string(),
            ));
        }

        let file_part =
            reqwest::multipart::Part::bytes(file.to_vec()).file_name(filename.to_string());
        let mut form = reqwest::multipart::Form::new()
            .part("file", file_part)
            .text("timeout", options.timeout_secs.unwrap_or(120).to_string());

        if let Some(command_line) = &options.command_line {
            form = form.text("options", format!("arguments={}", command_line));
        }

        if let Some(environment) = &options.environment {
            form = form.text("machine", environment.clone());
        }

        let response = self
            .client
            .post_multipart("/tasks/create/file", form)
            .await?;
        if !response.status().is_success() {
            return Err(ConnectorError::RequestFailed(format!(
                "File submission failed: {}",
                response.status()
            )));
        }

        match response.json::<CuckooSubmitResponse>().await {
            Ok(data) => Ok(SubmissionId(data.task_id.to_string())),
            Err(e) => Err(ConnectorError::InvalidResponse(e.to_string())),
        }
    }

    async fn submit_url(
        &self,
        url: &str,
        options: &SubmissionOptions,
    ) -> ConnectorResult<SubmissionId> {
        let body = serde_json::json!({
            "url": url,
            "timeout": options.timeout_secs.unwrap_or(120),
        });

        let response = self.client.post("/tasks/create/url", &body).await?;

        if !response.status().is_success() {
            return Err(ConnectorError::RequestFailed(format!(
                "URL submission failed: {}",
                response.status()
            )));
        }

        match response.json::<CuckooSubmitResponse>().await {
            Ok(data) => Ok(SubmissionId(data.task_id.to_string())),
            Err(e) => Err(ConnectorError::InvalidResponse(e.to_string())),
        }
    }

    async fn get_report(&self, submission_id: &SubmissionId) -> ConnectorResult<SandboxReport> {
        let path = format!("/tasks/report/{}", submission_id.0);
        let response = self.client.get(&path).await?;

        if !response.status().is_success() {
            return Err(ConnectorError::RequestFailed(format!(
                "Report retrieval failed: {}",
                response.status()
            )));
        }

        match response.json::<CuckooReportResponse>().await {
            Ok(data) => {
                let score = data.info.score.unwrap_or(0.0);
                let verdict = if score >= 7.0 {
                    SandboxVerdict::Malicious
                } else if score >= 3.0 {
                    SandboxVerdict::Suspicious
                } else if score > 0.0 {
                    SandboxVerdict::Clean
                } else {
                    SandboxVerdict::Unknown
                };

                let signatures = data
                    .signatures
                    .unwrap_or_default()
                    .into_iter()
                    .map(|s| super::Signature {
                        name: s.name,
                        description: s.description.unwrap_or_default(),
                        severity: format!("{}", s.severity),
                        category: None,
                    })
                    .collect();

                Ok(SandboxReport {
                    submission_id: submission_id.clone(),
                    verdict,
                    threat_score: (score * 10.0).min(100.0) as u8,
                    malware_family: data.malfamily,
                    tags: vec![],
                    mitre_techniques: vec![],
                    behaviors: vec![],
                    network_indicators: super::NetworkIndicators::default(),
                    file_indicators: vec![],
                    registry_modifications: vec![],
                    processes: vec![],
                    signatures,
                    screenshots: vec![],
                    analysis_duration_secs: data.info.duration.unwrap_or(0.0) as u64,
                    environment: "Cuckoo".to_string(),
                    completed_at: chrono::Utc::now(),
                    source: "Cuckoo Sandbox".to_string(),
                    raw_report: None,
                })
            }
            Err(e) => Err(ConnectorError::InvalidResponse(e.to_string())),
        }
    }

    async fn get_status(
        &self,
        submission_id: &SubmissionId,
    ) -> ConnectorResult<SandboxAnalysisStatus> {
        let path = format!("/tasks/view/{}", submission_id.0);
        let response = self.client.get(&path).await?;

        if !response.status().is_success() {
            return Err(ConnectorError::RequestFailed(format!(
                "Status check failed: {}",
                response.status()
            )));
        }

        match response.json::<CuckooTaskResponse>().await {
            Ok(data) => match data.task.status.as_deref() {
                Some("reported") => Ok(SandboxAnalysisStatus::Completed),
                Some("completed") => Ok(SandboxAnalysisStatus::Completed),
                Some("running") => Ok(SandboxAnalysisStatus::Running),
                Some("pending") => Ok(SandboxAnalysisStatus::Queued),
                Some("failed_analysis") | Some("failed_processing") => {
                    Ok(SandboxAnalysisStatus::Failed("Analysis failed".to_string()))
                }
                _ => Ok(SandboxAnalysisStatus::Queued),
            },
            Err(e) => Err(ConnectorError::InvalidResponse(e.to_string())),
        }
    }
}

#[derive(Debug, Deserialize)]
struct CuckooSubmitResponse {
    task_id: u64,
}

#[derive(Debug, Deserialize)]
struct CuckooReportResponse {
    info: CuckooInfo,
    signatures: Option<Vec<CuckooSignature>>,
    malfamily: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CuckooInfo {
    score: Option<f64>,
    duration: Option<f64>,
}

#[derive(Debug, Deserialize)]
struct CuckooSignature {
    name: String,
    description: Option<String>,
    severity: u32,
}

#[derive(Debug, Deserialize)]
struct CuckooTaskResponse {
    task: CuckooTask,
}

#[derive(Debug, Deserialize)]
struct CuckooTask {
    status: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_string::SecureString;
    use crate::traits::{AuthConfig, Connector};
    use std::collections::HashMap;

    fn create_test_config() -> CuckooConfig {
        CuckooConfig {
            connector: ConnectorConfig {
                name: "cuckoo-test".to_string(),
                base_url: "https://cuckoo.example.com".to_string(),
                auth: AuthConfig::BearerToken {
                    token: SecureString::new("test-token".to_string()),
                },
                timeout_secs: 60,
                max_retries: 2,
                verify_tls: true,
                headers: HashMap::new(),
            },
            requests_per_minute: 30,
        }
    }

    #[test]
    fn test_connector_creation() {
        let config = create_test_config();
        let connector = CuckooConnector::new(config).unwrap();
        assert_eq!(connector.name(), "cuckoo-test");
        assert_eq!(connector.connector_type(), "sandbox");
    }

    #[test]
    fn test_defaults() {
        assert_eq!(default_rate_limit(), 30);
    }
}
