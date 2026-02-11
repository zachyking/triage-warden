//! HTTP client for communicating with the Triage Warden API.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::time::Duration;
use uuid::Uuid;

/// API client for Triage Warden server.
#[derive(Clone)]
pub struct ApiClient {
    client: reqwest::Client,
    base_url: String,
}

impl ApiClient {
    /// Creates a new API client.
    pub fn new(base_url: &str) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .context("Failed to create HTTP client")?;

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
        })
    }

    /// Lists incidents with optional filtering.
    pub async fn list_incidents(&self, params: &ListIncidentsParams) -> Result<PaginatedIncidents> {
        let mut url = format!("{}/api/incidents", self.base_url);
        let mut query_parts = Vec::new();

        if let Some(status) = &params.status {
            query_parts.push(format!("status={}", status));
        }
        if let Some(severity) = &params.severity {
            query_parts.push(format!("severity={}", severity));
        }
        if let Some(page) = params.page {
            query_parts.push(format!("page={}", page));
        }
        if let Some(per_page) = params.per_page {
            query_parts.push(format!("per_page={}", per_page));
        }

        if !query_parts.is_empty() {
            url.push('?');
            url.push_str(&query_parts.join("&"));
        }

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .context("Failed to send request")?;

        self.handle_response(response).await
    }

    /// Gets a single incident by ID.
    pub async fn get_incident(&self, id: Uuid) -> Result<IncidentDetail> {
        self.get(&format!("/api/incidents/{}", id)).await
    }

    /// Executes an action on an incident.
    pub async fn execute_action(
        &self,
        incident_id: Uuid,
        request: &ExecuteActionRequest,
    ) -> Result<ActionExecutionResponse> {
        self.post(&format!("/api/incidents/{}/actions", incident_id), request)
            .await
    }

    /// Gets metrics in JSON format.
    pub async fn metrics(&self) -> Result<MetricsResponse> {
        self.get("/api/metrics").await
    }

    /// Dismisses an incident.
    pub async fn dismiss_incident(&self, id: Uuid, reason: Option<&str>) -> Result<()> {
        let form = IncidentStatusForm {
            reason: reason.map(std::string::ToString::to_string),
        };
        self.post_form_empty(&format!("/api/incidents/{}/dismiss", id), &form)
            .await
    }

    /// Resolves an incident.
    pub async fn resolve_incident(&self, id: Uuid, reason: Option<&str>) -> Result<()> {
        let form = IncidentStatusForm {
            reason: reason.map(std::string::ToString::to_string),
        };
        self.post_form_empty(&format!("/api/incidents/{}/resolve", id), &form)
            .await
    }

    /// Requests re-enrichment for an incident.
    pub async fn enrich_incident(&self, id: Uuid) -> Result<()> {
        self.post_empty(&format!("/api/incidents/{}/enrich", id))
            .await
    }

    // Helper methods

    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let url = format!("{}{}", self.base_url, path);
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .context("Failed to send request")?;

        self.handle_response(response).await
    }

    async fn post<T: DeserializeOwned, B: Serialize>(&self, path: &str, body: &B) -> Result<T> {
        let url = format!("{}{}", self.base_url, path);
        let response = self
            .client
            .post(&url)
            .json(body)
            .send()
            .await
            .context("Failed to send request")?;

        self.handle_response(response).await
    }

    async fn post_form_empty<B: Serialize>(&self, path: &str, body: &B) -> Result<()> {
        let url = format!("{}{}", self.base_url, path);
        let response = self
            .client
            .post(&url)
            .form(body)
            .send()
            .await
            .context("Failed to send request")?;

        self.handle_empty_response(response).await
    }

    async fn post_empty(&self, path: &str) -> Result<()> {
        let url = format!("{}{}", self.base_url, path);
        let response = self
            .client
            .post(&url)
            .send()
            .await
            .context("Failed to send request")?;

        self.handle_empty_response(response).await
    }

    async fn handle_response<T: DeserializeOwned>(&self, response: reqwest::Response) -> Result<T> {
        let status = response.status();

        if status.is_success() {
            response
                .json()
                .await
                .context("Failed to parse response body")
        } else {
            let error: ApiErrorResponse =
                response.json().await.unwrap_or_else(|_| ApiErrorResponse {
                    code: "UNKNOWN".to_string(),
                    message: "Unknown error".to_string(),
                    details: None,
                    request_id: None,
                });

            anyhow::bail!("API error ({}): {} - {}", status, error.code, error.message)
        }
    }

    async fn handle_empty_response(&self, response: reqwest::Response) -> Result<()> {
        let status = response.status();

        if status.is_success() {
            return Ok(());
        }

        let error: ApiErrorResponse = response.json().await.unwrap_or_else(|_| ApiErrorResponse {
            code: "UNKNOWN".to_string(),
            message: "Unknown error".to_string(),
            details: None,
            request_id: None,
        });

        anyhow::bail!("API error ({}): {} - {}", status, error.code, error.message)
    }
}

// Request/Response types (matching server DTOs)

#[derive(Debug, Default)]
pub struct ListIncidentsParams {
    pub status: Option<String>,
    pub severity: Option<String>,
    pub page: Option<u32>,
    pub per_page: Option<u32>,
}

#[derive(Debug, Serialize)]
struct IncidentStatusForm {
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PaginatedIncidents {
    pub data: Vec<IncidentSummary>,
    pub pagination: PaginationInfo,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PaginationInfo {
    pub page: u32,
    pub per_page: u32,
    pub total_items: u64,
    pub total_pages: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IncidentSummary {
    pub id: Uuid,
    pub source: String,
    pub severity: String,
    pub status: String,
    pub title: Option<String>,
    pub alert_type: Option<String>,
    pub verdict: Option<String>,
    pub confidence: Option<f64>,
    pub risk_score: Option<u8>,
    pub ticket_id: Option<String>,
    pub tags: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IncidentDetail {
    #[serde(flatten)]
    pub incident: IncidentSummary,
    pub alert_data: serde_json::Value,
    pub enrichments: Vec<serde_json::Value>,
    pub analysis: Option<serde_json::Value>,
    pub proposed_actions: Vec<ActionSummary>,
    pub audit_log: Vec<AuditEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ActionSummary {
    pub id: Uuid,
    pub action_type: String,
    pub target: serde_json::Value,
    pub reason: String,
    pub priority: u8,
    pub approval_status: String,
    pub approved_by: Option<String>,
    pub approval_timestamp: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: Uuid,
    pub action: String,
    pub actor: String,
    pub details: Option<serde_json::Value>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ExecuteActionRequest {
    pub action_type: String,
    pub target: serde_json::Value,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<serde_json::Value>,
    #[serde(default)]
    pub skip_policy_check: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ActionExecutionResponse {
    pub action_id: Uuid,
    pub incident_id: Uuid,
    pub action_type: String,
    pub status: String,
    pub message: String,
    pub result: Option<serde_json::Value>,
    pub executed_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MetricsResponse {
    pub incidents: IncidentMetrics,
    pub actions: ActionMetrics,
    pub performance: PerformanceMetrics,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IncidentMetrics {
    pub total: u64,
    pub by_status: std::collections::HashMap<String, u64>,
    pub by_severity: std::collections::HashMap<String, u64>,
    pub created_last_hour: u64,
    pub resolved_last_hour: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ActionMetrics {
    pub total_executed: u64,
    pub success_rate: f64,
    pub pending_approvals: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub mean_time_to_triage_seconds: Option<f64>,
    pub mean_time_to_respond_seconds: Option<f64>,
    pub auto_resolution_rate: Option<f64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiErrorResponse {
    pub code: String,
    pub message: String,
    pub details: Option<serde_json::Value>,
    pub request_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_trims_trailing_slash() {
        let client = ApiClient::new("http://localhost:8080/").unwrap();
        assert_eq!(client.base_url, "http://localhost:8080");
    }

    #[test]
    fn test_new_no_trailing_slash_unchanged() {
        let client = ApiClient::new("http://localhost:8080").unwrap();
        assert_eq!(client.base_url, "http://localhost:8080");
    }

    #[test]
    fn test_new_multiple_trailing_slashes() {
        let client = ApiClient::new("http://example.com///").unwrap();
        // trim_end_matches removes all trailing slashes
        assert_eq!(client.base_url, "http://example.com");
    }

    #[test]
    fn test_list_incidents_url_no_params() {
        // Verify the URL format matches what the server expects
        let client = ApiClient::new("http://localhost:8080").unwrap();
        let url = format!("{}/api/incidents", client.base_url);
        assert_eq!(url, "http://localhost:8080/api/incidents");
    }

    #[test]
    fn test_list_incidents_params_query_string() {
        let params = ListIncidentsParams {
            status: Some("open".to_string()),
            severity: Some("high".to_string()),
            page: Some(2),
            per_page: Some(50),
        };

        let mut url = "http://localhost:8080/api/incidents".to_string();
        let mut query_parts = Vec::new();

        if let Some(status) = &params.status {
            query_parts.push(format!("status={}", status));
        }
        if let Some(severity) = &params.severity {
            query_parts.push(format!("severity={}", severity));
        }
        if let Some(page) = params.page {
            query_parts.push(format!("page={}", page));
        }
        if let Some(per_page) = params.per_page {
            query_parts.push(format!("per_page={}", per_page));
        }

        if !query_parts.is_empty() {
            url.push('?');
            url.push_str(&query_parts.join("&"));
        }

        assert_eq!(
            url,
            "http://localhost:8080/api/incidents?status=open&severity=high&page=2&per_page=50"
        );
    }

    #[test]
    fn test_list_incidents_params_partial() {
        let params = ListIncidentsParams {
            status: Some("resolved".to_string()),
            severity: None,
            page: None,
            per_page: Some(10),
        };

        let mut query_parts = Vec::new();

        if let Some(status) = &params.status {
            query_parts.push(format!("status={}", status));
        }
        if let Some(severity) = &params.severity {
            query_parts.push(format!("severity={}", severity));
        }
        if let Some(page) = params.page {
            query_parts.push(format!("page={}", page));
        }
        if let Some(per_page) = params.per_page {
            query_parts.push(format!("per_page={}", per_page));
        }

        assert_eq!(query_parts.join("&"), "status=resolved&per_page=10");
    }

    #[test]
    fn test_list_incidents_params_default() {
        let params = ListIncidentsParams::default();
        assert!(params.status.is_none());
        assert!(params.severity.is_none());
        assert!(params.page.is_none());
        assert!(params.per_page.is_none());
    }

    #[test]
    fn test_execute_action_request_serialization() {
        let request = ExecuteActionRequest {
            action_type: "isolate_host".to_string(),
            target: serde_json::json!({"type": "host", "hostname": "web-01"}),
            reason: "Contain malware".to_string(),
            parameters: Some(serde_json::json!({"network_isolation": true})),
            skip_policy_check: false,
        };

        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(json["action_type"], "isolate_host");
        assert_eq!(json["target"]["hostname"], "web-01");
        assert_eq!(json["reason"], "Contain malware");
        assert_eq!(json["parameters"]["network_isolation"], true);
        assert_eq!(json["skip_policy_check"], false);
    }

    #[test]
    fn test_execute_action_request_skip_none_parameters() {
        let request = ExecuteActionRequest {
            action_type: "block_ip".to_string(),
            target: serde_json::json!({"type": "ip", "ip": "1.2.3.4"}),
            reason: "Threat intel match".to_string(),
            parameters: None,
            skip_policy_check: false,
        };

        let json = serde_json::to_value(&request).unwrap();
        // parameters should be absent when None due to skip_serializing_if
        assert!(json.get("parameters").is_none());
    }

    #[test]
    fn test_api_error_response_deserialization() {
        let json = r#"{"code":"NOT_FOUND","message":"Incident not found","details":null,"request_id":"req-123"}"#;
        let error: ApiErrorResponse = serde_json::from_str(json).unwrap();
        assert_eq!(error.code, "NOT_FOUND");
        assert_eq!(error.message, "Incident not found");
        assert!(error.details.is_none());
        assert_eq!(error.request_id.as_deref(), Some("req-123"));
    }

    #[test]
    fn test_pagination_info_deserialization() {
        let json = r#"{"page":1,"per_page":20,"total_items":150,"total_pages":8}"#;
        let info: PaginationInfo = serde_json::from_str(json).unwrap();
        assert_eq!(info.page, 1);
        assert_eq!(info.per_page, 20);
        assert_eq!(info.total_items, 150);
        assert_eq!(info.total_pages, 8);
    }

    #[test]
    fn test_incident_summary_deserialization() {
        let json = serde_json::json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "source": "email_gateway",
            "severity": "high",
            "status": "open",
            "title": "Phishing detected",
            "alert_type": "phishing",
            "verdict": "malicious",
            "confidence": 0.95,
            "risk_score": 85,
            "ticket_id": "SEC-123",
            "tags": ["phishing", "urgent"],
            "created_at": "2024-01-15T09:00:00Z",
            "updated_at": "2024-01-15T09:30:00Z"
        });

        let summary: IncidentSummary = serde_json::from_value(json).unwrap();
        assert_eq!(summary.source, "email_gateway");
        assert_eq!(summary.severity, "high");
        assert_eq!(summary.status, "open");
        assert_eq!(summary.title.as_deref(), Some("Phishing detected"));
        assert_eq!(summary.verdict.as_deref(), Some("malicious"));
        assert_eq!(summary.confidence, Some(0.95));
        assert_eq!(summary.risk_score, Some(85));
        assert_eq!(summary.tags.len(), 2);
    }

    #[test]
    fn test_metrics_response_deserialization() {
        let json = serde_json::json!({
            "incidents": {
                "total": 500,
                "by_status": {"open": 10, "resolved": 490},
                "by_severity": {"high": 50, "medium": 200, "low": 250},
                "created_last_hour": 3,
                "resolved_last_hour": 5
            },
            "actions": {
                "total_executed": 120,
                "success_rate": 0.95,
                "pending_approvals": 2
            },
            "performance": {
                "mean_time_to_triage_seconds": 45.2,
                "mean_time_to_respond_seconds": 120.5,
                "auto_resolution_rate": 0.6
            }
        });

        let metrics: MetricsResponse = serde_json::from_value(json).unwrap();
        assert_eq!(metrics.incidents.total, 500);
        assert_eq!(metrics.incidents.created_last_hour, 3);
        assert_eq!(metrics.actions.total_executed, 120);
        assert!((metrics.actions.success_rate - 0.95).abs() < f64::EPSILON);
        assert_eq!(metrics.actions.pending_approvals, 2);
        assert!(metrics.performance.mean_time_to_triage_seconds.is_some());
    }
}
