//! ANY.RUN interactive sandbox connector.

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

/// ANY.RUN configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnyRunConfig {
    #[serde(flatten)]
    pub connector: ConnectorConfig,
    #[serde(default = "default_rate_limit")]
    pub requests_per_minute: u32,
}

fn default_rate_limit() -> u32 {
    10
}

/// ANY.RUN connector.
pub struct AnyRunConnector {
    config: AnyRunConfig,
    client: HttpClient,
}

impl AnyRunConnector {
    pub fn new(config: AnyRunConfig) -> ConnectorResult<Self> {
        let rate_limit = RateLimitConfig {
            max_requests: config.requests_per_minute,
            period: Duration::from_secs(60),
            burst_size: 3,
        };

        let client = HttpClient::with_rate_limit(config.connector.clone(), Some(rate_limit))?;

        info!("ANY.RUN connector initialized");

        Ok(Self { config, client })
    }
}

#[async_trait]
impl crate::traits::Connector for AnyRunConnector {
    fn name(&self) -> &str {
        &self.config.connector.name
    }

    fn connector_type(&self) -> &str {
        "sandbox"
    }

    async fn health_check(&self) -> ConnectorResult<ConnectorHealth> {
        match self.client.get("/api/v1/user").await {
            Ok(r) if r.status().is_success() => Ok(ConnectorHealth::Healthy),
            Ok(r) => Ok(ConnectorHealth::Unhealthy(format!(
                "Status: {}",
                r.status()
            ))),
            Err(e) => Ok(ConnectorHealth::Unhealthy(e.to_string())),
        }
    }

    async fn test_connection(&self) -> ConnectorResult<bool> {
        let response = self.client.get("/api/v1/user").await?;
        Ok(response.status().is_success())
    }
}

#[async_trait]
impl MalwareSandbox for AnyRunConnector {
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
            .text("obj_type", "file")
            .part("file", file_part)
            .text(
                "env_os",
                options
                    .environment
                    .as_deref()
                    .unwrap_or("windows")
                    .to_string(),
            )
            .text(
                "opt_privacy_type",
                if options.private {
                    "owner".to_string()
                } else {
                    "public".to_string()
                },
            )
            .text(
                "opt_network_connect",
                matches!(
                    options.network_mode,
                    Some(super::NetworkMode::Internet) | None
                )
                .to_string(),
            )
            .text(
                "opt_timeout",
                options.timeout_secs.unwrap_or(60).to_string(),
            );

        if let Some(command_line) = &options.command_line {
            form = form.text("obj_ext_cmd", command_line.clone());
        }

        let response = self.client.post_multipart("/api/v1/analysis", form).await?;
        if !response.status().is_success() {
            return Err(ConnectorError::RequestFailed(format!(
                "File submission failed: {}",
                response.status()
            )));
        }

        match response.json::<AnyRunSubmitResponse>().await {
            Ok(data) => Ok(SubmissionId(data.data.task_id)),
            Err(e) => Err(ConnectorError::InvalidResponse(e.to_string())),
        }
    }

    async fn submit_url(
        &self,
        url: &str,
        options: &SubmissionOptions,
    ) -> ConnectorResult<SubmissionId> {
        let body = serde_json::json!({
            "obj_type": "url",
            "obj_url": url,
            "env_os": options.environment.as_deref().unwrap_or("windows"),
            "opt_privacy_type": if options.private { "owner" } else { "public" },
            "opt_network_connect": matches!(
                options.network_mode,
                Some(super::NetworkMode::Internet) | None
            ),
            "opt_timeout": options.timeout_secs.unwrap_or(60),
        });

        let response = self.client.post("/api/v1/analysis", &body).await?;

        if !response.status().is_success() {
            return Err(ConnectorError::RequestFailed(format!(
                "URL submission failed: {}",
                response.status()
            )));
        }

        match response.json::<AnyRunSubmitResponse>().await {
            Ok(data) => Ok(SubmissionId(data.data.task_id)),
            Err(e) => Err(ConnectorError::InvalidResponse(e.to_string())),
        }
    }

    async fn get_report(&self, submission_id: &SubmissionId) -> ConnectorResult<SandboxReport> {
        let path = format!("/api/v1/analysis/{}", submission_id.0);
        let response = self.client.get(&path).await?;

        if !response.status().is_success() {
            return Err(ConnectorError::RequestFailed(format!(
                "Report retrieval failed: {}",
                response.status()
            )));
        }

        match response.json::<AnyRunReportResponse>().await {
            Ok(data) => {
                let verdict = match data.data.verdict.as_deref() {
                    Some("malicious") => SandboxVerdict::Malicious,
                    Some("suspicious") => SandboxVerdict::Suspicious,
                    Some("No threats detected") => SandboxVerdict::Clean,
                    _ => SandboxVerdict::Unknown,
                };

                Ok(SandboxReport {
                    submission_id: submission_id.clone(),
                    verdict,
                    threat_score: data
                        .data
                        .scores
                        .as_ref()
                        .and_then(|s| s.specs.threat_level)
                        .map(|t| (t * 10.0).min(100.0) as u8)
                        .unwrap_or(0),
                    malware_family: None,
                    tags: data.data.tags.unwrap_or_default(),
                    mitre_techniques: data.data.mitre.unwrap_or_default(),
                    behaviors: vec![],
                    network_indicators: super::NetworkIndicators::default(),
                    file_indicators: vec![],
                    registry_modifications: vec![],
                    processes: vec![],
                    signatures: vec![],
                    screenshots: vec![],
                    analysis_duration_secs: data.data.duration.unwrap_or(0),
                    environment: "ANY.RUN".to_string(),
                    completed_at: chrono::Utc::now(),
                    source: "ANY.RUN".to_string(),
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
        let path = format!("/api/v1/analysis/{}", submission_id.0);
        let response = self.client.get(&path).await?;

        if !response.status().is_success() {
            return Err(ConnectorError::RequestFailed(format!(
                "Status check failed: {}",
                response.status()
            )));
        }

        match response.json::<AnyRunReportResponse>().await {
            Ok(data) => match data.data.status.as_deref() {
                Some("done") => Ok(SandboxAnalysisStatus::Completed),
                Some("running") => Ok(SandboxAnalysisStatus::Running),
                Some("queued") => Ok(SandboxAnalysisStatus::Queued),
                _ => Ok(SandboxAnalysisStatus::Queued),
            },
            Err(e) => Err(ConnectorError::InvalidResponse(e.to_string())),
        }
    }
}

#[derive(Debug, Deserialize)]
struct AnyRunSubmitResponse {
    data: AnyRunSubmitData,
}

#[derive(Debug, Deserialize)]
struct AnyRunSubmitData {
    task_id: String,
}

#[derive(Debug, Deserialize)]
struct AnyRunReportResponse {
    data: AnyRunReportData,
}

#[derive(Debug, Deserialize)]
struct AnyRunReportData {
    status: Option<String>,
    verdict: Option<String>,
    scores: Option<AnyRunScores>,
    tags: Option<Vec<String>>,
    mitre: Option<Vec<String>>,
    duration: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct AnyRunScores {
    specs: AnyRunSpecScores,
}

#[derive(Debug, Deserialize)]
struct AnyRunSpecScores {
    threat_level: Option<f64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_string::SecureString;
    use crate::traits::{AuthConfig, Connector};
    use std::collections::HashMap;

    fn create_test_config() -> AnyRunConfig {
        AnyRunConfig {
            connector: ConnectorConfig {
                name: "anyrun-test".to_string(),
                base_url: "https://api.any.run".to_string(),
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
        let connector = AnyRunConnector::new(config).unwrap();
        assert_eq!(connector.name(), "anyrun-test");
        assert_eq!(connector.connector_type(), "sandbox");
    }

    #[test]
    fn test_defaults() {
        assert_eq!(default_rate_limit(), 10);
    }
}
