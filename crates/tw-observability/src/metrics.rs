//! Metrics collection for Triage Warden.
//!
//! This module provides metrics collection using the metrics crate
//! with Prometheus export support.

use chrono::{DateTime, Duration, Utc};
use metrics::{counter, describe_counter, describe_gauge, describe_histogram, gauge, histogram};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Key Performance Indicators for the triage system.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KPIs {
    /// Mean time to triage (from alert to analysis complete).
    pub mttt: Option<Duration>,
    /// Mean time to respond (from alert to action executed).
    pub mttr: Option<Duration>,
    /// Percentage of incidents auto-resolved.
    pub auto_resolution_rate: f64,
    /// Percentage of AI recommendations overridden by analysts.
    pub override_rate: f64,
    /// False positive rate.
    pub false_positive_rate: f64,
    /// Total incidents processed.
    pub total_incidents: u64,
    /// Incidents by severity.
    pub incidents_by_severity: HashMap<String, u64>,
    /// Incidents by source.
    pub incidents_by_source: HashMap<String, u64>,
}

/// Tracks timing for an incident through the pipeline.
#[derive(Debug, Clone)]
struct IncidentTiming {
    received_at: DateTime<Utc>,
    triaged_at: Option<DateTime<Utc>>,
    responded_at: Option<DateTime<Utc>>,
}

/// Historical KPI record type.
type KpiHistory = Vec<(DateTime<Utc>, KPIs)>;

/// Metrics collector for the triage system.
pub struct MetricsCollector {
    /// Incident timing data for KPI calculation.
    incident_timings: Arc<RwLock<HashMap<uuid::Uuid, IncidentTiming>>>,
    /// Historical KPI data (for future trend analysis).
    #[allow(dead_code)]
    kpi_history: Arc<RwLock<KpiHistory>>,
    /// Auto-resolved count.
    auto_resolved: Arc<RwLock<u64>>,
    /// Override count.
    overrides: Arc<RwLock<u64>>,
    /// False positive count.
    false_positives: Arc<RwLock<u64>>,
    /// Total resolved.
    total_resolved: Arc<RwLock<u64>>,
}

impl MetricsCollector {
    /// Creates a new metrics collector.
    pub fn new() -> Self {
        // Register metric descriptions
        Self::register_metrics();

        Self {
            incident_timings: Arc::new(RwLock::new(HashMap::new())),
            kpi_history: Arc::new(RwLock::new(Vec::new())),
            auto_resolved: Arc::new(RwLock::new(0)),
            overrides: Arc::new(RwLock::new(0)),
            false_positives: Arc::new(RwLock::new(0)),
            total_resolved: Arc::new(RwLock::new(0)),
        }
    }

    /// Registers metric descriptions.
    fn register_metrics() {
        describe_counter!(
            "tw_alerts_received_total",
            "Total number of alerts received"
        );
        describe_counter!(
            "tw_incidents_created_total",
            "Total number of incidents created"
        );
        describe_counter!(
            "tw_incidents_resolved_total",
            "Total number of incidents resolved"
        );
        describe_counter!(
            "tw_actions_executed_total",
            "Total number of actions executed"
        );
        describe_counter!(
            "tw_actions_denied_total",
            "Total number of actions denied by policy"
        );
        describe_counter!("tw_errors_total", "Total number of errors");

        describe_gauge!(
            "tw_incidents_in_progress",
            "Number of incidents currently being processed"
        );
        describe_gauge!(
            "tw_pending_approvals",
            "Number of pending approval requests"
        );

        describe_histogram!("tw_triage_duration_seconds", "Time to triage an incident");
        describe_histogram!(
            "tw_response_duration_seconds",
            "Time to respond to an incident"
        );
        describe_histogram!("tw_llm_latency_seconds", "LLM API call latency");
        describe_histogram!("tw_action_duration_seconds", "Action execution duration");

        // Database metrics
        describe_gauge!(
            "tw_db_pool_size",
            "Current number of connections in the database pool"
        );
        describe_gauge!(
            "tw_db_pool_idle",
            "Number of idle connections in the database pool"
        );
        describe_counter!(
            "tw_db_pool_exhausted_total",
            "Number of times the connection pool was exhausted"
        );
        describe_histogram!(
            "tw_db_query_duration_seconds",
            "Duration of database queries"
        );
        describe_counter!(
            "tw_db_queries_total",
            "Total number of database queries executed"
        );
        describe_counter!("tw_db_errors_total", "Total number of database errors");
        describe_counter!(
            "tw_db_retries_total",
            "Total number of database query retries"
        );

        // Security metrics
        describe_counter!("tw_login_attempts_total", "Total number of login attempts");
        describe_counter!(
            "tw_rate_limit_exceeded_total",
            "Total number of rate limit exceeded events"
        );
        describe_counter!(
            "tw_api_key_auth_total",
            "Total number of API key authentications"
        );
    }

    /// Records an alert received.
    pub fn record_alert_received(&self, source: &str, severity: &str) {
        counter!("tw_alerts_received_total", "source" => source.to_string(), "severity" => severity.to_string()).increment(1);
    }

    /// Records an incident created.
    pub async fn record_incident_created(
        &self,
        incident_id: uuid::Uuid,
        source: &str,
        severity: &str,
    ) {
        counter!("tw_incidents_created_total", "source" => source.to_string(), "severity" => severity.to_string()).increment(1);
        gauge!("tw_incidents_in_progress").increment(1.0);

        let mut timings = self.incident_timings.write().await;
        timings.insert(
            incident_id,
            IncidentTiming {
                received_at: Utc::now(),
                triaged_at: None,
                responded_at: None,
            },
        );
    }

    /// Records triage completion.
    pub async fn record_triage_complete(&self, incident_id: uuid::Uuid) {
        let now = Utc::now();

        let mut timings = self.incident_timings.write().await;
        if let Some(timing) = timings.get_mut(&incident_id) {
            timing.triaged_at = Some(now);

            let duration = (now - timing.received_at).num_seconds() as f64;
            histogram!("tw_triage_duration_seconds").record(duration);
        }
    }

    /// Records response completion.
    pub async fn record_response_complete(&self, incident_id: uuid::Uuid, auto_resolved: bool) {
        let now = Utc::now();

        let mut timings = self.incident_timings.write().await;
        if let Some(timing) = timings.get_mut(&incident_id) {
            timing.responded_at = Some(now);

            let duration = (now - timing.received_at).num_seconds() as f64;
            histogram!("tw_response_duration_seconds").record(duration);
        }

        if auto_resolved {
            let mut count = self.auto_resolved.write().await;
            *count += 1;
        }

        let mut total = self.total_resolved.write().await;
        *total += 1;
    }

    /// Records an incident resolved.
    pub fn record_incident_resolved(&self, resolution_type: &str) {
        counter!("tw_incidents_resolved_total", "resolution" => resolution_type.to_string())
            .increment(1);
        gauge!("tw_incidents_in_progress").decrement(1.0);
    }

    /// Records a false positive.
    pub async fn record_false_positive(&self) {
        let mut count = self.false_positives.write().await;
        *count += 1;
        counter!("tw_incidents_resolved_total", "resolution" => "false_positive").increment(1);
    }

    /// Records an analyst override of AI recommendation.
    pub async fn record_override(&self) {
        let mut count = self.overrides.write().await;
        *count += 1;
    }

    /// Records an action executed.
    pub fn record_action_executed(&self, action_type: &str, success: bool) {
        let status = if success { "success" } else { "failure" };
        counter!("tw_actions_executed_total", "action" => action_type.to_string(), "status" => status).increment(1);
    }

    /// Records an action denied.
    pub fn record_action_denied(&self, action_type: &str, reason: &str) {
        counter!("tw_actions_denied_total", "action" => action_type.to_string(), "reason" => reason.to_string()).increment(1);
    }

    /// Records action duration.
    pub fn record_action_duration(&self, action_type: &str, duration_secs: f64) {
        histogram!("tw_action_duration_seconds", "action" => action_type.to_string())
            .record(duration_secs);
    }

    /// Records an error.
    pub fn record_error(&self, error_type: &str) {
        counter!("tw_errors_total", "type" => error_type.to_string()).increment(1);
    }

    /// Records LLM latency.
    pub fn record_llm_latency(&self, provider: &str, latency_secs: f64) {
        histogram!("tw_llm_latency_seconds", "provider" => provider.to_string())
            .record(latency_secs);
    }

    /// Records pending approvals count.
    pub fn record_pending_approvals(&self, count: usize) {
        gauge!("tw_pending_approvals").set(count as f64);
    }

    // Database metrics

    /// Records database pool size.
    pub fn record_db_pool_size(&self, size: u32) {
        gauge!("tw_db_pool_size").set(size as f64);
    }

    /// Records database pool idle connections.
    pub fn record_db_pool_idle(&self, idle: u32) {
        gauge!("tw_db_pool_idle").set(idle as f64);
    }

    /// Records a database pool exhausted event.
    pub fn record_db_pool_exhausted(&self) {
        counter!("tw_db_pool_exhausted_total").increment(1);
    }

    /// Records database query duration.
    pub fn record_db_query_duration(&self, operation: &str, duration_secs: f64) {
        histogram!("tw_db_query_duration_seconds", "operation" => operation.to_string())
            .record(duration_secs);
        counter!("tw_db_queries_total", "operation" => operation.to_string()).increment(1);
    }

    /// Records a database error.
    pub fn record_db_error(&self, error_type: &str) {
        counter!("tw_db_errors_total", "type" => error_type.to_string()).increment(1);
    }

    /// Records a database retry.
    pub fn record_db_retry(&self, operation: &str, attempt: u32) {
        counter!("tw_db_retries_total", "operation" => operation.to_string(), "attempt" => attempt.to_string()).increment(1);
    }

    // Security metrics

    /// Records a login attempt.
    pub fn record_login_attempt(&self, success: bool) {
        let status = if success { "success" } else { "failure" };
        counter!("tw_login_attempts_total", "status" => status).increment(1);
    }

    /// Records a rate limit exceeded event.
    pub fn record_rate_limit_exceeded(&self, endpoint: &str) {
        counter!("tw_rate_limit_exceeded_total", "endpoint" => endpoint.to_string()).increment(1);
    }

    /// Records an API key authentication.
    pub fn record_api_key_auth(&self, success: bool) {
        let status = if success { "success" } else { "failure" };
        counter!("tw_api_key_auth_total", "status" => status).increment(1);
    }

    /// Calculates current KPIs.
    pub async fn calculate_kpis(&self) -> KPIs {
        let timings = self.incident_timings.read().await;
        let auto_resolved = *self.auto_resolved.read().await;
        let overrides = *self.overrides.read().await;
        let false_positives = *self.false_positives.read().await;
        let total_resolved = *self.total_resolved.read().await;

        // Calculate mean time to triage
        let triage_times: Vec<i64> = timings
            .values()
            .filter_map(|t| t.triaged_at.map(|ta| (ta - t.received_at).num_seconds()))
            .collect();

        let mttt = if !triage_times.is_empty() {
            let sum: i64 = triage_times.iter().sum();
            Some(Duration::seconds(sum / triage_times.len() as i64))
        } else {
            None
        };

        // Calculate mean time to respond
        let response_times: Vec<i64> = timings
            .values()
            .filter_map(|t| t.responded_at.map(|ra| (ra - t.received_at).num_seconds()))
            .collect();

        let mttr = if !response_times.is_empty() {
            let sum: i64 = response_times.iter().sum();
            Some(Duration::seconds(sum / response_times.len() as i64))
        } else {
            None
        };

        // Calculate rates
        let auto_resolution_rate = if total_resolved > 0 {
            auto_resolved as f64 / total_resolved as f64
        } else {
            0.0
        };

        let override_rate = if total_resolved > 0 {
            overrides as f64 / total_resolved as f64
        } else {
            0.0
        };

        let false_positive_rate = if total_resolved > 0 {
            false_positives as f64 / total_resolved as f64
        } else {
            0.0
        };

        KPIs {
            mttt,
            mttr,
            auto_resolution_rate,
            override_rate,
            false_positive_rate,
            total_incidents: timings.len() as u64,
            incidents_by_severity: HashMap::new(), // Would need to track this separately
            incidents_by_source: HashMap::new(),
        }
    }

    /// Cleans up old incident timing data.
    pub async fn cleanup(&self, max_age_hours: i64) {
        let cutoff = Utc::now() - Duration::hours(max_age_hours);
        let mut timings = self.incident_timings.write().await;
        timings.retain(|_, t| t.received_at > cutoff);
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_record_incident() {
        let collector = MetricsCollector::new();
        let incident_id = uuid::Uuid::new_v4();

        collector
            .record_incident_created(incident_id, "test", "high")
            .await;

        let timings = collector.incident_timings.read().await;
        assert!(timings.contains_key(&incident_id));
    }

    #[tokio::test]
    async fn test_calculate_kpis() {
        let collector = MetricsCollector::new();

        // Create and triage an incident
        let incident_id = uuid::Uuid::new_v4();
        collector
            .record_incident_created(incident_id, "test", "high")
            .await;
        collector.record_triage_complete(incident_id).await;
        collector.record_response_complete(incident_id, true).await;

        let kpis = collector.calculate_kpis().await;
        assert!(kpis.mttt.is_some());
        assert!(kpis.mttr.is_some());
        assert_eq!(kpis.total_incidents, 1);
    }

    #[tokio::test]
    async fn test_auto_resolution_rate() {
        let collector = MetricsCollector::new();

        // Two incidents, one auto-resolved
        let id1 = uuid::Uuid::new_v4();
        let id2 = uuid::Uuid::new_v4();

        collector.record_incident_created(id1, "test", "high").await;
        collector
            .record_incident_created(id2, "test", "medium")
            .await;

        collector.record_response_complete(id1, true).await; // auto-resolved
        collector.record_response_complete(id2, false).await; // manual

        let kpis = collector.calculate_kpis().await;
        assert_eq!(kpis.auto_resolution_rate, 0.5);
    }
}
