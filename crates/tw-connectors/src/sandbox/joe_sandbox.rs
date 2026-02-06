//! Joe Sandbox connector.

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

/// Joe Sandbox configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoeSandboxConfig {
    #[serde(flatten)]
    pub connector: ConnectorConfig,
    #[serde(default = "default_rate_limit")]
    pub requests_per_minute: u32,
}

fn default_rate_limit() -> u32 {
    10
}

/// Joe Sandbox connector.
pub struct JoeSandboxConnector {
    config: JoeSandboxConfig,
    client: HttpClient,
}

impl JoeSandboxConnector {
    pub fn new(config: JoeSandboxConfig) -> ConnectorResult<Self> {
        let rate_limit = RateLimitConfig {
            max_requests: config.requests_per_minute,
            period: Duration::from_secs(60),
            burst_size: 3,
        };

        let client = HttpClient::with_rate_limit(config.connector.clone(), Some(rate_limit))?;

        info!("Joe Sandbox connector initialized");

        Ok(Self { config, client })
    }
}

#[async_trait]
impl crate::traits::Connector for JoeSandboxConnector {
    fn name(&self) -> &str {
        &self.config.connector.name
    }

    fn connector_type(&self) -> &str {
        "sandbox"
    }

    async fn health_check(&self) -> ConnectorResult<ConnectorHealth> {
        match self.client.get("/api/v2/server/online").await {
            Ok(r) if r.status().is_success() => Ok(ConnectorHealth::Healthy),
            Ok(r) => Ok(ConnectorHealth::Unhealthy(format!(
                "Status: {}",
                r.status()
            ))),
            Err(e) => Ok(ConnectorHealth::Unhealthy(e.to_string())),
        }
    }

    async fn test_connection(&self) -> ConnectorResult<bool> {
        let response = self.client.get("/api/v2/server/online").await?;
        Ok(response.status().is_success())
    }
}

#[async_trait]
impl MalwareSandbox for JoeSandboxConnector {
    async fn submit_file(
        &self,
        _file: &[u8],
        _filename: &str,
        _options: &SubmissionOptions,
    ) -> ConnectorResult<SubmissionId> {
        Err(ConnectorError::Internal(
            "Joe Sandbox file submission requires multipart upload (not yet implemented)"
                .to_string(),
        ))
    }

    async fn submit_url(
        &self,
        url: &str,
        options: &SubmissionOptions,
    ) -> ConnectorResult<SubmissionId> {
        let body = serde_json::json!({
            "url": url,
            "systems": [options.environment.as_deref().unwrap_or("w10x64")],
            "internet-access": matches!(
                options.network_mode,
                Some(super::NetworkMode::Internet) | None
            ),
        });

        let response = self.client.post("/api/v2/submission/new", &body).await?;

        if !response.status().is_success() {
            return Err(ConnectorError::RequestFailed(format!(
                "URL submission failed: {}",
                response.status()
            )));
        }

        match response.json::<JoeSandboxSubmitResponse>().await {
            Ok(data) => Ok(SubmissionId(data.data.submission_id)),
            Err(e) => Err(ConnectorError::InvalidResponse(e.to_string())),
        }
    }

    async fn get_report(&self, submission_id: &SubmissionId) -> ConnectorResult<SandboxReport> {
        let path = format!("/api/v2/analysis/info?webid={}", submission_id.0);
        let response = self.client.get(&path).await?;

        if !response.status().is_success() {
            return Err(ConnectorError::RequestFailed(format!(
                "Report retrieval failed: {}",
                response.status()
            )));
        }

        match response.json::<JoeSandboxReportResponse>().await {
            Ok(data) => {
                let verdict = match data.data.detection.as_deref() {
                    Some("malicious") => SandboxVerdict::Malicious,
                    Some("suspicious") => SandboxVerdict::Suspicious,
                    Some("clean") => SandboxVerdict::Clean,
                    _ => SandboxVerdict::Unknown,
                };

                Ok(SandboxReport {
                    submission_id: submission_id.clone(),
                    verdict,
                    threat_score: data.data.score.unwrap_or(0).min(100) as u8,
                    malware_family: data.data.family,
                    tags: vec![],
                    mitre_techniques: vec![],
                    behaviors: vec![],
                    network_indicators: super::NetworkIndicators::default(),
                    file_indicators: vec![],
                    registry_modifications: vec![],
                    processes: vec![],
                    signatures: vec![],
                    screenshots: vec![],
                    analysis_duration_secs: data.data.duration.unwrap_or(0),
                    environment: data.data.system.unwrap_or_default(),
                    completed_at: chrono::Utc::now(),
                    source: "Joe Sandbox".to_string(),
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
        let path = format!("/api/v2/analysis/info?webid={}", submission_id.0);
        let response = self.client.get(&path).await?;

        if !response.status().is_success() {
            return Err(ConnectorError::RequestFailed(format!(
                "Status check failed: {}",
                response.status()
            )));
        }

        match response.json::<JoeSandboxReportResponse>().await {
            Ok(data) => match data.data.status.as_deref() {
                Some("finished") => Ok(SandboxAnalysisStatus::Completed),
                Some("running") => Ok(SandboxAnalysisStatus::Running),
                Some("submitted") => Ok(SandboxAnalysisStatus::Queued),
                _ => Ok(SandboxAnalysisStatus::Queued),
            },
            Err(e) => Err(ConnectorError::InvalidResponse(e.to_string())),
        }
    }
}

#[derive(Debug, Deserialize)]
struct JoeSandboxSubmitResponse {
    data: JoeSandboxSubmitData,
}

#[derive(Debug, Deserialize)]
struct JoeSandboxSubmitData {
    submission_id: String,
}

#[derive(Debug, Deserialize)]
struct JoeSandboxReportResponse {
    data: JoeSandboxReportData,
}

#[derive(Debug, Deserialize)]
struct JoeSandboxReportData {
    status: Option<String>,
    detection: Option<String>,
    score: Option<u32>,
    family: Option<String>,
    system: Option<String>,
    duration: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_string::SecureString;
    use crate::traits::{AuthConfig, Connector};
    use std::collections::HashMap;

    fn create_test_config() -> JoeSandboxConfig {
        JoeSandboxConfig {
            connector: ConnectorConfig {
                name: "joe-sandbox-test".to_string(),
                base_url: "https://jbxcloud.joesecurity.org".to_string(),
                auth: AuthConfig::ApiKey {
                    key: SecureString::new("test-key".to_string()),
                    header_name: "Authorization".to_string(),
                },
                timeout_secs: 60,
                max_retries: 2,
                verify_tls: true,
                headers: HashMap::new(),
            },
            requests_per_minute: 10,
        }
    }

    #[test]
    fn test_connector_creation() {
        let config = create_test_config();
        let connector = JoeSandboxConnector::new(config).unwrap();
        assert_eq!(connector.name(), "joe-sandbox-test");
        assert_eq!(connector.connector_type(), "sandbox");
    }

    #[test]
    fn test_defaults() {
        assert_eq!(default_rate_limit(), 10);
    }
}
