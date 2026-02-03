//! Splunk SIEM connector.
//!
//! This module provides integration with Splunk Enterprise and Splunk Cloud
//! for search operations and alert management.

use crate::http::{HttpClient, RateLimitConfig};
use crate::traits::{
    ConnectorConfig, ConnectorError, ConnectorHealth, ConnectorResult, SIEMAlert, SIEMConnector,
    SIEMEvent, SavedSearch, SearchResults, SearchStats, TimeRange,
};
use async_trait::async_trait;
use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, info, instrument, warn};

/// Splunk-specific configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SplunkConfig {
    /// Base connector configuration.
    #[serde(flatten)]
    pub connector: ConnectorConfig,
    /// Splunk app context (default: "search").
    #[serde(default = "default_app")]
    pub app: String,
    /// Owner context (default: "-" for any).
    #[serde(default = "default_owner")]
    pub owner: String,
    /// Default output mode (json/xml).
    #[serde(default = "default_output_mode")]
    pub output_mode: String,
    /// Search timeout in seconds.
    #[serde(default = "default_search_timeout")]
    pub search_timeout: u64,
    /// Maximum events to return.
    #[serde(default = "default_max_results")]
    pub max_results: u32,
    /// Requests per second rate limit (default: 10).
    #[serde(default = "default_rate_limit")]
    pub requests_per_second: u32,
}

fn default_app() -> String {
    "search".to_string()
}

fn default_owner() -> String {
    "-".to_string()
}

fn default_output_mode() -> String {
    "json".to_string()
}

fn default_search_timeout() -> u64 {
    120
}

fn default_max_results() -> u32 {
    10000
}

fn default_rate_limit() -> u32 {
    10
}

/// Splunk SIEM connector.
pub struct SplunkConnector {
    config: SplunkConfig,
    client: HttpClient,
}

impl SplunkConnector {
    /// Creates a new Splunk connector.
    pub fn new(config: SplunkConfig) -> ConnectorResult<Self> {
        let rate_limit = RateLimitConfig {
            max_requests: config.requests_per_second,
            period: Duration::from_secs(1),
            burst_size: config.requests_per_second.min(5),
        };

        let client = HttpClient::with_rate_limit(config.connector.clone(), Some(rate_limit))?;

        info!(
            "Splunk connector initialized for app '{}' (timeout: {}s)",
            config.app, config.search_timeout
        );

        Ok(Self { config, client })
    }

    /// Builds a service path with app/owner context.
    fn service_path(&self, path: &str) -> String {
        format!(
            "/servicesNS/{}/{}/{}",
            self.config.owner, self.config.app, path
        )
    }

    /// Creates a blocking search job that waits for completion.
    ///
    /// This is an alternative to the async search that blocks server-side.
    /// Useful for short-running searches where you don't need progress updates.
    #[instrument(skip(self))]
    pub async fn create_blocking_search_job(
        &self,
        spl: &str,
        timerange: &TimeRange,
    ) -> ConnectorResult<String> {
        let earliest = format_splunk_time(&timerange.start);
        let latest = format_splunk_time(&timerange.end);

        let params = [
            ("search", format!("search {}", spl)),
            ("earliest_time", earliest),
            ("latest_time", latest),
            ("output_mode", self.config.output_mode.clone()),
            ("exec_mode", "blocking".to_string()),
            ("max_count", self.config.max_results.to_string()),
        ];

        let path = self.service_path("search/jobs");
        let response = self.client.post(&path, &params).await.map_err(|e| {
            ConnectorError::RequestFailed(format!("Failed to create search job: {}", e))
        })?;

        if !response.status().is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ConnectorError::RequestFailed(format!(
                "Search job creation failed: {}",
                body
            )));
        }

        let job_response: SplunkJobResponse = response.json().await.map_err(|e| {
            ConnectorError::InvalidResponse(format!("Failed to parse job response: {}", e))
        })?;

        debug!("Created search job: {}", job_response.sid);
        Ok(job_response.sid)
    }

    /// Creates an async search job.
    #[instrument(skip(self))]
    async fn create_async_search_job(
        &self,
        spl: &str,
        timerange: &TimeRange,
    ) -> ConnectorResult<String> {
        let earliest = format_splunk_time(&timerange.start);
        let latest = format_splunk_time(&timerange.end);

        let params = [
            ("search", format!("search {}", spl)),
            ("earliest_time", earliest),
            ("latest_time", latest),
            ("output_mode", self.config.output_mode.clone()),
            ("max_count", self.config.max_results.to_string()),
        ];

        let path = self.service_path("search/jobs");
        let response = self.client.post(&path, &params).await.map_err(|e| {
            ConnectorError::RequestFailed(format!("Failed to create search job: {}", e))
        })?;

        if !response.status().is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ConnectorError::RequestFailed(format!(
                "Search job creation failed: {}",
                body
            )));
        }

        let job_response: SplunkJobResponse = response.json().await.map_err(|e| {
            ConnectorError::InvalidResponse(format!("Failed to parse job response: {}", e))
        })?;

        debug!("Created async search job: {}", job_response.sid);
        Ok(job_response.sid)
    }

    /// Waits for a search job to complete.
    #[instrument(skip(self))]
    async fn wait_for_job(&self, sid: &str) -> ConnectorResult<()> {
        let path = format!(
            "{}?output_mode=json",
            self.service_path(&format!("search/jobs/{}", sid))
        );
        let timeout = Duration::from_secs(self.config.search_timeout);
        let start = std::time::Instant::now();
        let poll_interval = Duration::from_secs(1);

        loop {
            if start.elapsed() > timeout {
                return Err(ConnectorError::Timeout(format!(
                    "Search job {} timed out after {}s",
                    sid, self.config.search_timeout
                )));
            }

            let response = self.client.get(&path).await?;

            if !response.status().is_success() {
                let body = response.text().await.unwrap_or_default();
                return Err(ConnectorError::RequestFailed(format!(
                    "Failed to check job status: {}",
                    body
                )));
            }

            let status: SplunkJobStatusResponse = response.json().await.map_err(|e| {
                ConnectorError::InvalidResponse(format!("Failed to parse job status: {}", e))
            })?;

            if let Some(entry) = status.entry.first() {
                let state = &entry.content.dispatch_state;
                debug!("Job {} state: {}", sid, state);

                match state.as_str() {
                    "DONE" => return Ok(()),
                    "FAILED" => {
                        return Err(ConnectorError::RequestFailed(format!(
                            "Search job {} failed",
                            sid
                        )));
                    }
                    "PAUSED" | "FINALIZING" | "RUNNING" | "PARSING" | "QUEUED" => {
                        sleep(poll_interval).await;
                    }
                    _ => {
                        warn!("Unknown job state: {}", state);
                        sleep(poll_interval).await;
                    }
                }
            } else {
                return Err(ConnectorError::InvalidResponse(
                    "No entry in job status response".to_string(),
                ));
            }
        }
    }

    /// Gets results from a completed search job.
    #[instrument(skip(self))]
    async fn get_job_results(&self, sid: &str) -> ConnectorResult<SplunkResultsResponse> {
        let path = format!(
            "{}?output_mode=json&count={}",
            self.service_path(&format!("search/jobs/{}/results", sid)),
            self.config.max_results
        );

        let response = self.client.get(&path).await?;

        if !response.status().is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ConnectorError::RequestFailed(format!(
                "Failed to get results: {}",
                body
            )));
        }

        let results: SplunkResultsResponse = response.json().await.map_err(|e| {
            ConnectorError::InvalidResponse(format!("Failed to parse results: {}", e))
        })?;

        Ok(results)
    }

    /// Parses Splunk results into SIEM events.
    fn parse_results(&self, results: SplunkResultsResponse) -> Vec<SIEMEvent> {
        results
            .results
            .into_iter()
            .map(|r| {
                let timestamp = r
                    .get("_time")
                    .and_then(|v| v.as_str())
                    .and_then(parse_splunk_time)
                    .unwrap_or_else(Utc::now);

                let raw = r
                    .get("_raw")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                let source = r
                    .get("source")
                    .or_else(|| r.get("index"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();

                SIEMEvent {
                    timestamp,
                    raw,
                    fields: r,
                    source,
                }
            })
            .collect()
    }

    /// Escapes special characters in SPL.
    pub fn escape_spl(value: &str) -> String {
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\'', "\\'")
    }

    /// Allowed field names for get_field_values to prevent SPL injection.
    /// Only these fields can be queried directly - prevents arbitrary SPL command injection.
    const ALLOWED_FIELD_NAMES: &'static [&'static str] = &[
        "src_ip",
        "dest_ip",
        "src",
        "dest",
        "user",
        "hostname",
        "host",
        "action",
        "status",
        "severity",
        "source",
        "sourcetype",
        "index",
        "src_port",
        "dest_port",
        "protocol",
        "signature",
        "category",
        "vendor_product",
        "app",
        "dvc",
        "dvc_ip",
        "user_agent",
    ];

    /// Validates that a field name is in the allowed list.
    pub fn validate_field_name(field: &str) -> ConnectorResult<()> {
        if !Self::ALLOWED_FIELD_NAMES.contains(&field) {
            return Err(ConnectorError::RequestFailed(format!(
                "Field '{}' is not in the allowed list. Allowed fields: {:?}",
                field,
                Self::ALLOWED_FIELD_NAMES
            )));
        }
        Ok(())
    }
}

#[async_trait]
impl crate::traits::Connector for SplunkConnector {
    fn name(&self) -> &str {
        &self.config.connector.name
    }

    fn connector_type(&self) -> &str {
        "siem"
    }

    async fn health_check(&self) -> ConnectorResult<ConnectorHealth> {
        // Check server info endpoint
        let path = "/services/server/info?output_mode=json";
        match self.client.get(path).await {
            Ok(response) if response.status().is_success() => Ok(ConnectorHealth::Healthy),
            Ok(response) if response.status().as_u16() == 401 => Ok(ConnectorHealth::Unhealthy(
                "Authentication failed".to_string(),
            )),
            Ok(response) if response.status().as_u16() == 503 => {
                Ok(ConnectorHealth::Degraded("Service unavailable".to_string()))
            }
            Ok(response) => Ok(ConnectorHealth::Degraded(format!(
                "Unexpected status: {}",
                response.status()
            ))),
            Err(ConnectorError::ConnectionFailed(e)) => Ok(ConnectorHealth::Unhealthy(format!(
                "Connection failed: {}",
                e
            ))),
            Err(e) => Ok(ConnectorHealth::Unhealthy(e.to_string())),
        }
    }

    async fn test_connection(&self) -> ConnectorResult<bool> {
        let path = "/services/server/info?output_mode=json";
        let response = self.client.get(path).await?;
        Ok(response.status().is_success())
    }
}

#[async_trait]
impl SIEMConnector for SplunkConnector {
    #[instrument(skip(self), fields(query = %query))]
    async fn search(&self, query: &str, timerange: TimeRange) -> ConnectorResult<SearchResults> {
        let start_time = std::time::Instant::now();

        // Create and wait for search job
        let sid = self.create_async_search_job(query, &timerange).await?;
        self.wait_for_job(&sid).await?;

        // Get results
        let results = self.get_job_results(&sid).await?;
        let total_count = results.results.len() as u64;
        let offset = results.offset();
        let is_preview = results.is_preview();

        if is_preview {
            debug!(
                "Search {} returned preview results (offset: {})",
                sid, offset
            );
        }

        let events = self.parse_results(results);

        info!(
            "Search completed: {} events in {:?}",
            total_count,
            start_time.elapsed()
        );

        Ok(SearchResults {
            search_id: sid,
            total_count,
            events,
            stats: Some(SearchStats {
                execution_time_ms: start_time.elapsed().as_millis() as u64,
                events_scanned: total_count,
                bytes_scanned: 0, // Splunk doesn't provide this in basic results
            }),
        })
    }

    #[instrument(skip(self))]
    async fn get_saved_searches(&self) -> ConnectorResult<Vec<SavedSearch>> {
        let path = format!(
            "{}?output_mode=json&count=0",
            self.service_path("saved/searches")
        );
        let response = self.client.get(&path).await?;

        if !response.status().is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ConnectorError::RequestFailed(format!(
                "Failed to get saved searches: {}",
                body
            )));
        }

        let saved: SplunkSavedSearchesResponse = response.json().await.map_err(|e| {
            ConnectorError::InvalidResponse(format!("Failed to parse saved searches: {}", e))
        })?;

        let searches: Vec<SavedSearch> = saved
            .entry
            .into_iter()
            .map(|e| SavedSearch {
                id: e.name.clone(),
                name: e.name,
                query: e.content.search,
                alerts_enabled: e.content.is_scheduled.unwrap_or(false)
                    && e.content.alert_type.is_some(),
            })
            .collect();

        Ok(searches)
    }

    #[instrument(skip(self))]
    async fn get_recent_alerts(&self, limit: usize) -> ConnectorResult<Vec<SIEMAlert>> {
        let path = format!(
            "{}?output_mode=json&count={}",
            self.service_path("alerts/fired_alerts"),
            limit
        );
        let response = self.client.get(&path).await?;

        if !response.status().is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ConnectorError::RequestFailed(format!(
                "Failed to get fired alerts: {}",
                body
            )));
        }

        let alerts_response: SplunkFiredAlertsResponse = response.json().await.map_err(|e| {
            ConnectorError::InvalidResponse(format!("Failed to parse alerts: {}", e))
        })?;

        let alerts: Vec<SIEMAlert> = alerts_response
            .entry
            .into_iter()
            .map(|e| {
                let timestamp = e
                    .content
                    .trigger_time
                    .and_then(|t| Utc.timestamp_opt(t, 0).single())
                    .unwrap_or_else(Utc::now);

                let severity = e
                    .content
                    .severity
                    .map(|s| match s {
                        1 => "info",
                        2 => "low",
                        3 => "medium",
                        4 => "high",
                        5 => "critical",
                        _ => "unknown",
                    })
                    .unwrap_or("unknown")
                    .to_string();

                SIEMAlert {
                    id: e.name.clone(),
                    name: e.content.savedsearch_name.unwrap_or(e.name),
                    severity,
                    timestamp,
                    details: {
                        let mut m = HashMap::new();
                        if let Some(c) = e.content.triggered_alert_count {
                            m.insert("triggered_count".to_string(), serde_json::json!(c));
                        }
                        if let Some(sid) = e.content.sid {
                            m.insert("sid".to_string(), serde_json::json!(sid));
                        }
                        m
                    },
                }
            })
            .collect();

        Ok(alerts)
    }

    #[instrument(skip(self))]
    async fn get_field_values(
        &self,
        field: &str,
        timerange: TimeRange,
        limit: usize,
    ) -> ConnectorResult<Vec<String>> {
        // Validate field name against allowlist to prevent SPL injection
        Self::validate_field_name(field)?;

        // Use stats to get top values for the field
        let query = format!(
            "* | stats count by {} | head {}",
            Self::escape_spl(field),
            limit
        );
        let results = self.search(&query, timerange).await?;

        let values: Vec<String> = results
            .events
            .into_iter()
            .filter_map(|e| {
                e.fields
                    .get(field)
                    .and_then(|v| v.as_str())
                    .map(String::from)
            })
            .collect();

        Ok(values)
    }
}

// Splunk API response types

#[derive(Debug, Deserialize)]
struct SplunkJobResponse {
    sid: String,
}

#[derive(Debug, Deserialize)]
struct SplunkJobStatusResponse {
    entry: Vec<SplunkJobEntry>,
}

#[derive(Debug, Deserialize)]
struct SplunkJobEntry {
    content: SplunkJobContent,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SplunkJobContent {
    dispatch_state: String,
}

#[derive(Debug, Deserialize)]
struct SplunkResultsResponse {
    #[serde(default)]
    results: Vec<HashMap<String, serde_json::Value>>,
    #[serde(default)]
    init_offset: u64,
    #[serde(default)]
    preview: bool,
}

impl SplunkResultsResponse {
    /// Returns true if this is a preview (incomplete) result set.
    fn is_preview(&self) -> bool {
        self.preview
    }

    /// Returns the starting offset of the results.
    fn offset(&self) -> u64 {
        self.init_offset
    }
}

#[derive(Debug, Deserialize)]
struct SplunkSavedSearchesResponse {
    #[serde(default)]
    entry: Vec<SplunkSavedSearchEntry>,
}

#[derive(Debug, Deserialize)]
struct SplunkSavedSearchEntry {
    name: String,
    content: SplunkSavedSearchContent,
}

#[derive(Debug, Deserialize)]
struct SplunkSavedSearchContent {
    search: String,
    #[serde(rename = "is_scheduled")]
    is_scheduled: Option<bool>,
    #[serde(rename = "alert_type")]
    alert_type: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SplunkFiredAlertsResponse {
    #[serde(default)]
    entry: Vec<SplunkFiredAlertEntry>,
}

#[derive(Debug, Deserialize)]
struct SplunkFiredAlertEntry {
    name: String,
    content: SplunkFiredAlertContent,
}

#[derive(Debug, Deserialize)]
struct SplunkFiredAlertContent {
    #[serde(rename = "savedsearch_name")]
    savedsearch_name: Option<String>,
    #[serde(rename = "trigger_time")]
    trigger_time: Option<i64>,
    severity: Option<u8>,
    #[serde(rename = "triggered_alert_count")]
    triggered_alert_count: Option<u32>,
    sid: Option<String>,
}

/// Formats a DateTime for Splunk time specification.
fn format_splunk_time(dt: &DateTime<Utc>) -> String {
    dt.format("%Y-%m-%dT%H:%M:%S").to_string()
}

/// Parses Splunk time format to DateTime.
fn parse_splunk_time(s: &str) -> Option<DateTime<Utc>> {
    // Try ISO format first
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }

    // Try Splunk's default format: YYYY-MM-DD HH:MM:SS.sss TZ
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(
        s.split_whitespace()
            .take(2)
            .collect::<Vec<_>>()
            .join(" ")
            .as_str(),
        "%Y-%m-%d %H:%M:%S%.f",
    ) {
        return Some(Utc.from_utc_datetime(&dt));
    }

    // Try epoch timestamp
    if let Ok(epoch) = s.parse::<i64>() {
        return Utc.timestamp_opt(epoch, 0).single();
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_string::SecureString;
    use crate::traits::AuthConfig;

    fn create_test_config() -> SplunkConfig {
        SplunkConfig {
            connector: ConnectorConfig {
                name: "splunk-test".to_string(),
                base_url: "https://localhost:8089".to_string(),
                auth: AuthConfig::Basic {
                    username: "admin".to_string(),
                    password: SecureString::new("changeme".to_string()),
                },
                timeout_secs: 30,
                max_retries: 3,
                verify_tls: false,
                headers: HashMap::new(),
            },
            app: "search".to_string(),
            owner: "-".to_string(),
            output_mode: "json".to_string(),
            search_timeout: 120,
            max_results: 10000,
            requests_per_second: 10,
        }
    }

    #[test]
    fn test_service_path() {
        let config = create_test_config();
        let connector = SplunkConnector::new(config).unwrap();

        assert_eq!(
            connector.service_path("search/jobs"),
            "/servicesNS/-/search/search/jobs"
        );
    }

    #[test]
    fn test_escape_spl() {
        assert_eq!(SplunkConnector::escape_spl("test"), "test");
        assert_eq!(SplunkConnector::escape_spl("test\"value"), "test\\\"value");
        assert_eq!(SplunkConnector::escape_spl("test'value"), "test\\'value");
        assert_eq!(SplunkConnector::escape_spl("test\\value"), "test\\\\value");
    }

    #[test]
    fn test_format_splunk_time() {
        let dt = Utc.with_ymd_and_hms(2024, 1, 15, 12, 30, 45).unwrap();
        assert_eq!(format_splunk_time(&dt), "2024-01-15T12:30:45");
    }

    #[test]
    fn test_parse_splunk_time() {
        // ISO format
        let result = parse_splunk_time("2024-01-15T12:30:45Z");
        assert!(result.is_some());

        // Epoch timestamp
        let result = parse_splunk_time("1705322445");
        assert!(result.is_some());
    }

    #[test]
    fn test_config_defaults() {
        assert_eq!(default_app(), "search");
        assert_eq!(default_owner(), "-");
        assert_eq!(default_output_mode(), "json");
        assert_eq!(default_search_timeout(), 120);
        assert_eq!(default_max_results(), 10000);
        assert_eq!(default_rate_limit(), 10);
    }
}
