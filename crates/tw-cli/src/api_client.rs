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

#[allow(dead_code)]
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

    /// Creates a client pointing to localhost.
    pub fn localhost(port: u16) -> Result<Self> {
        Self::new(&format!("http://localhost:{}", port))
    }

    /// Checks if the API server is healthy.
    pub async fn health(&self) -> Result<HealthResponse> {
        self.get("/health").await
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

    /// Approves or denies an action.
    pub async fn approve_action(
        &self,
        incident_id: Uuid,
        request: &ApproveActionRequest,
    ) -> Result<ActionExecutionResponse> {
        self.post(&format!("/api/incidents/{}/approve", incident_id), request)
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

#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub database: DatabaseHealth,
    pub uptime_seconds: u64,
}

#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize)]
pub struct DatabaseHealth {
    pub connected: bool,
    pub pool_size: u32,
    pub idle_connections: usize,
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

#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize)]
pub struct ExecuteActionRequest {
    pub action_type: String,
    pub target: serde_json::Value,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<serde_json::Value>,
    #[serde(default)]
    pub skip_policy_check: bool,
}

#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize)]
pub struct ApproveActionRequest {
    pub action_id: Uuid,
    pub approved: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize)]
pub struct ActionExecutionResponse {
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
