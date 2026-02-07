//! Hybrid Analysis (CrowdStrike Falcon Sandbox) connector.

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

/// Hybrid Analysis configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridAnalysisConfig {
    #[serde(flatten)]
    pub connector: ConnectorConfig,
    #[serde(default = "default_rate_limit")]
    pub requests_per_minute: u32,
    #[serde(default = "default_environment")]
    pub default_environment: String,
}

fn default_rate_limit() -> u32 {
    20
}
fn default_environment() -> String {
    "160".to_string() // Windows 10 64-bit
}

/// Hybrid Analysis connector.
pub struct HybridAnalysisConnector {
    config: HybridAnalysisConfig,
    client: HttpClient,
}

impl HybridAnalysisConnector {
    pub fn new(config: HybridAnalysisConfig) -> ConnectorResult<Self> {
        let rate_limit = RateLimitConfig {
            max_requests: config.requests_per_minute,
            period: Duration::from_secs(60),
            burst_size: 5,
        };

        let client = HttpClient::with_rate_limit(config.connector.clone(), Some(rate_limit))?;

        info!("Hybrid Analysis connector initialized");

        Ok(Self { config, client })
    }
}

#[async_trait]
impl crate::traits::Connector for HybridAnalysisConnector {
    fn name(&self) -> &str {
        &self.config.connector.name
    }

    fn connector_type(&self) -> &str {
        "sandbox"
    }

    async fn health_check(&self) -> ConnectorResult<ConnectorHealth> {
        match self.client.get("/api/v2/system/state").await {
            Ok(r) if r.status().is_success() => Ok(ConnectorHealth::Healthy),
            Ok(r) => Ok(ConnectorHealth::Unhealthy(format!(
                "Status: {}",
                r.status()
            ))),
            Err(e) => Ok(ConnectorHealth::Unhealthy(e.to_string())),
        }
    }

    async fn test_connection(&self) -> ConnectorResult<bool> {
        let response = self.client.get("/api/v2/system/state").await?;
        Ok(response.status().is_success())
    }
}

#[async_trait]
impl MalwareSandbox for HybridAnalysisConnector {
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
            .text(
                "environment_id",
                options
                    .environment
                    .as_deref()
                    .unwrap_or(&self.config.default_environment)
                    .to_string(),
            )
            .text("no_share_third_party", options.private.to_string());

        if let Some(command_line) = &options.command_line {
            form = form.text("custom_cmd_line", command_line.clone());
        }

        let response = self
            .client
            .post_multipart("/api/v2/submit/file", form)
            .await?;
        if !response.status().is_success() {
            return Err(ConnectorError::RequestFailed(format!(
                "File submission failed: {}",
                response.status()
            )));
        }

        match response.json::<HybridAnalysisSubmitResponse>().await {
            Ok(data) => Ok(SubmissionId(data.job_id)),
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
            "environment_id": options.environment.as_deref()
                .unwrap_or(&self.config.default_environment),
            "no_share_third_party": options.private,
        });

        let response = self
            .client
            .post("/api/v2/submit/url-for-analysis", &body)
            .await?;

        if !response.status().is_success() {
            return Err(ConnectorError::RequestFailed(format!(
                "URL submission failed: {}",
                response.status()
            )));
        }

        match response.json::<HybridAnalysisSubmitResponse>().await {
            Ok(data) => Ok(SubmissionId(data.job_id)),
            Err(e) => Err(ConnectorError::InvalidResponse(e.to_string())),
        }
    }

    async fn get_report(&self, submission_id: &SubmissionId) -> ConnectorResult<SandboxReport> {
        let path = format!("/api/v2/report/{}/summary", submission_id.0);
        let response = self.client.get(&path).await?;

        if !response.status().is_success() {
            return Err(ConnectorError::RequestFailed(format!(
                "Report retrieval failed: {}",
                response.status()
            )));
        }

        match response.json::<HybridAnalysisReportResponse>().await {
            Ok(data) => {
                let verdict = match data.verdict.as_deref() {
                    Some("malicious") => SandboxVerdict::Malicious,
                    Some("suspicious") => SandboxVerdict::Suspicious,
                    Some("whitelisted") | Some("no specific threat") => SandboxVerdict::Clean,
                    _ => SandboxVerdict::Unknown,
                };

                Ok(SandboxReport {
                    submission_id: submission_id.clone(),
                    verdict,
                    threat_score: data.threat_score.unwrap_or(0) as u8,
                    malware_family: data.vx_family,
                    tags: data.tags.unwrap_or_default(),
                    mitre_techniques: data.mitre_attcks.unwrap_or_default(),
                    behaviors: vec![],
                    network_indicators: super::NetworkIndicators::default(),
                    file_indicators: vec![],
                    registry_modifications: vec![],
                    processes: vec![],
                    signatures: vec![],
                    screenshots: vec![],
                    analysis_duration_secs: 0,
                    environment: data.environment.unwrap_or_default(),
                    completed_at: chrono::Utc::now(),
                    source: "Hybrid Analysis".to_string(),
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
        let path = format!("/api/v2/report/{}/state", submission_id.0);
        let response = self.client.get(&path).await?;

        if !response.status().is_success() {
            return Err(ConnectorError::RequestFailed(format!(
                "Status check failed: {}",
                response.status()
            )));
        }

        match response.json::<HybridAnalysisStateResponse>().await {
            Ok(data) => match data.state.as_deref() {
                Some("SUCCESS") => Ok(SandboxAnalysisStatus::Completed),
                Some("IN_QUEUE") => Ok(SandboxAnalysisStatus::Queued),
                Some("IN_PROGRESS") => Ok(SandboxAnalysisStatus::Running),
                Some("ERROR") => Ok(SandboxAnalysisStatus::Failed(
                    data.error.unwrap_or_else(|| "Unknown error".to_string()),
                )),
                _ => Ok(SandboxAnalysisStatus::Queued),
            },
            Err(e) => Err(ConnectorError::InvalidResponse(e.to_string())),
        }
    }
}

#[derive(Debug, Deserialize)]
struct HybridAnalysisSubmitResponse {
    job_id: String,
}

#[derive(Debug, Deserialize)]
struct HybridAnalysisReportResponse {
    verdict: Option<String>,
    threat_score: Option<u32>,
    vx_family: Option<String>,
    tags: Option<Vec<String>>,
    mitre_attcks: Option<Vec<String>>,
    environment: Option<String>,
}

#[derive(Debug, Deserialize)]
struct HybridAnalysisStateResponse {
    state: Option<String>,
    error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_string::SecureString;
    use crate::traits::{AuthConfig, Connector};
    use std::collections::HashMap;

    fn create_test_config() -> HybridAnalysisConfig {
        HybridAnalysisConfig {
            connector: ConnectorConfig {
                name: "hybrid-analysis-test".to_string(),
                base_url: "https://www.hybrid-analysis.com".to_string(),
                auth: AuthConfig::ApiKey {
                    key: SecureString::new("test-key".to_string()),
                    header_name: "api-key".to_string(),
                },
                timeout_secs: 60,
                max_retries: 2,
                verify_tls: true,
                headers: HashMap::new(),
            },
            requests_per_minute: 20,
            default_environment: "160".to_string(),
        }
    }

    #[test]
    fn test_connector_creation() {
        let config = create_test_config();
        let connector = HybridAnalysisConnector::new(config).unwrap();
        assert_eq!(connector.name(), "hybrid-analysis-test");
        assert_eq!(connector.connector_type(), "sandbox");
    }

    #[test]
    fn test_config_defaults() {
        assert_eq!(default_rate_limit(), 20);
        assert_eq!(default_environment(), "160");
    }
}
