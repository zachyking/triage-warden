//! Analytics models for incident metrics, analyst performance, and security posture.
//!
//! This module provides data structures for computing and returning
//! analytics dashboards including incident metrics, analyst metrics,
//! trend data, and overall security posture scores.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

// ============================================================================
// Time Range & Granularity
// ============================================================================

/// Granularity for time-series data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Granularity {
    /// Hourly buckets.
    Hourly,
    /// Daily buckets.
    Daily,
    /// Weekly buckets.
    Weekly,
    /// Monthly buckets.
    Monthly,
}

impl Granularity {
    /// Parse from string.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "hourly" => Some(Granularity::Hourly),
            "daily" => Some(Granularity::Daily),
            "weekly" => Some(Granularity::Weekly),
            "monthly" => Some(Granularity::Monthly),
            _ => None,
        }
    }

    /// Returns the string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Granularity::Hourly => "hourly",
            Granularity::Daily => "daily",
            Granularity::Weekly => "weekly",
            Granularity::Monthly => "monthly",
        }
    }
}

impl std::fmt::Display for Granularity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A time range for analytics queries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyticsTimeRange {
    /// Start of the time range.
    pub start: DateTime<Utc>,
    /// End of the time range.
    pub end: DateTime<Utc>,
    /// Granularity for time-series data within this range.
    pub granularity: Granularity,
}

impl AnalyticsTimeRange {
    /// Create a new time range.
    pub fn new(start: DateTime<Utc>, end: DateTime<Utc>, granularity: Granularity) -> Self {
        Self {
            start,
            end,
            granularity,
        }
    }

    /// Check if the time range is valid (start < end).
    pub fn is_valid(&self) -> bool {
        self.start < self.end
    }

    /// Get the duration in seconds.
    pub fn duration_seconds(&self) -> i64 {
        (self.end - self.start).num_seconds()
    }
}

// ============================================================================
// Incident Metrics
// ============================================================================

/// Aggregate incident metrics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IncidentMetrics {
    /// Total number of incidents in the range.
    pub total_incidents: u64,

    /// Incidents grouped by severity.
    #[serde(default)]
    pub by_severity: HashMap<String, u64>,

    /// Incidents grouped by status.
    #[serde(default)]
    pub by_status: HashMap<String, u64>,

    /// Incidents grouped by type/category.
    #[serde(default)]
    pub by_type: HashMap<String, u64>,

    /// Mean time to detect (in seconds), if available.
    #[serde(default)]
    pub mttd_seconds: Option<f64>,

    /// Mean time to respond/resolve (in seconds), if available.
    #[serde(default)]
    pub mttr_seconds: Option<f64>,
}

impl IncidentMetrics {
    /// Calculate the total from severity breakdown.
    pub fn recalculate_total(&mut self) {
        self.total_incidents = self.by_severity.values().sum();
    }
}

// ============================================================================
// Analyst Metrics
// ============================================================================

/// Performance metrics for a single analyst.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalystMetrics {
    /// The analyst's user ID.
    pub analyst_id: Uuid,

    /// Number of incidents handled.
    pub incidents_handled: u64,

    /// Average resolution time in seconds.
    #[serde(default)]
    pub avg_resolution_time_secs: Option<f64>,

    /// Average feedback score (from analyst feedback).
    #[serde(default)]
    pub feedback_score: Option<f64>,
}

impl AnalystMetrics {
    /// Create new analyst metrics.
    pub fn new(analyst_id: Uuid) -> Self {
        Self {
            analyst_id,
            incidents_handled: 0,
            avg_resolution_time_secs: None,
            feedback_score: None,
        }
    }
}

// ============================================================================
// Trend Data
// ============================================================================

/// A single data point in a time-series trend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendDataPoint {
    /// Timestamp of this data point.
    pub timestamp: DateTime<Utc>,

    /// Numeric value.
    pub value: f64,

    /// Optional label (e.g., "critical", "high").
    #[serde(default)]
    pub label: Option<String>,
}

impl TrendDataPoint {
    /// Create a new trend data point.
    pub fn new(timestamp: DateTime<Utc>, value: f64) -> Self {
        Self {
            timestamp,
            value,
            label: None,
        }
    }

    /// Create with a label.
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }
}

// ============================================================================
// Security Posture
// ============================================================================

/// A technique with its occurrence count.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechniqueCount {
    /// MITRE ATT&CK technique ID (e.g., "T1566.001").
    pub technique_id: String,

    /// Human-readable technique name.
    pub name: String,

    /// Number of times this technique was observed.
    pub count: u64,
}

/// Overall security posture assessment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPosture {
    /// Overall security score (0.0 to 100.0, higher is better).
    pub overall_score: f64,

    /// Number of open critical incidents.
    pub open_critical: u64,

    /// Number of open high-severity incidents.
    pub open_high: u64,

    /// AI triage accuracy rate (from feedback).
    #[serde(default)]
    pub ai_accuracy: Option<f64>,

    /// Top MITRE ATT&CK techniques observed.
    #[serde(default)]
    pub top_techniques: Vec<TechniqueCount>,

    /// Trend data points for the posture score over time.
    #[serde(default)]
    pub trends: Vec<TrendDataPoint>,
}

impl SecurityPosture {
    /// Create a new security posture assessment.
    pub fn new(overall_score: f64) -> Self {
        Self {
            overall_score,
            open_critical: 0,
            open_high: 0,
            ai_accuracy: None,
            top_techniques: Vec::new(),
            trends: Vec::new(),
        }
    }

    /// Calculate the overall score based on metrics.
    ///
    /// Score formula: starts at 100 and deducts based on risk factors.
    pub fn calculate_score(open_critical: u64, open_high: u64, ai_accuracy: Option<f64>) -> f64 {
        let mut score = 100.0_f64;

        // Deduct 10 per open critical, 5 per open high
        score -= (open_critical as f64) * 10.0;
        score -= (open_high as f64) * 5.0;

        // Bonus/penalty for AI accuracy
        if let Some(accuracy) = ai_accuracy {
            if accuracy < 0.7 {
                score -= 10.0;
            } else if accuracy > 0.9 {
                score += 5.0;
            }
        }

        score.clamp(0.0, 100.0)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_granularity_parse() {
        assert_eq!(Granularity::parse("hourly"), Some(Granularity::Hourly));
        assert_eq!(Granularity::parse("daily"), Some(Granularity::Daily));
        assert_eq!(Granularity::parse("weekly"), Some(Granularity::Weekly));
        assert_eq!(Granularity::parse("monthly"), Some(Granularity::Monthly));
        assert_eq!(Granularity::parse("invalid"), None);
    }

    #[test]
    fn test_granularity_as_str() {
        assert_eq!(Granularity::Hourly.as_str(), "hourly");
        assert_eq!(Granularity::Daily.as_str(), "daily");
        assert_eq!(Granularity::Weekly.as_str(), "weekly");
        assert_eq!(Granularity::Monthly.as_str(), "monthly");
    }

    #[test]
    fn test_analytics_time_range_valid() {
        let start = Utc::now() - chrono::Duration::days(7);
        let end = Utc::now();
        let range = AnalyticsTimeRange::new(start, end, Granularity::Daily);

        assert!(range.is_valid());
        assert!(range.duration_seconds() > 0);
    }

    #[test]
    fn test_analytics_time_range_invalid() {
        let start = Utc::now();
        let end = Utc::now() - chrono::Duration::days(7);
        let range = AnalyticsTimeRange::new(start, end, Granularity::Daily);

        assert!(!range.is_valid());
    }

    #[test]
    fn test_incident_metrics_default() {
        let metrics = IncidentMetrics::default();
        assert_eq!(metrics.total_incidents, 0);
        assert!(metrics.by_severity.is_empty());
        assert!(metrics.mttd_seconds.is_none());
        assert!(metrics.mttr_seconds.is_none());
    }

    #[test]
    fn test_incident_metrics_recalculate_total() {
        let mut metrics = IncidentMetrics::default();
        metrics.by_severity.insert("critical".to_string(), 5);
        metrics.by_severity.insert("high".to_string(), 10);
        metrics.by_severity.insert("medium".to_string(), 20);

        metrics.recalculate_total();
        assert_eq!(metrics.total_incidents, 35);
    }

    #[test]
    fn test_analyst_metrics_new() {
        let analyst_id = Uuid::new_v4();
        let metrics = AnalystMetrics::new(analyst_id);

        assert_eq!(metrics.analyst_id, analyst_id);
        assert_eq!(metrics.incidents_handled, 0);
        assert!(metrics.avg_resolution_time_secs.is_none());
        assert!(metrics.feedback_score.is_none());
    }

    #[test]
    fn test_trend_data_point() {
        let now = Utc::now();
        let point = TrendDataPoint::new(now, 42.5).with_label("critical");

        assert_eq!(point.value, 42.5);
        assert_eq!(point.label, Some("critical".to_string()));
    }

    #[test]
    fn test_technique_count_serialization() {
        let tc = TechniqueCount {
            technique_id: "T1566.001".to_string(),
            name: "Spearphishing Attachment".to_string(),
            count: 15,
        };

        let json = serde_json::to_string(&tc).unwrap();
        assert!(json.contains("T1566.001"));
        assert!(json.contains("Spearphishing Attachment"));

        let deserialized: TechniqueCount = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.count, 15);
    }

    #[test]
    fn test_security_posture_new() {
        let posture = SecurityPosture::new(85.0);
        assert_eq!(posture.overall_score, 85.0);
        assert_eq!(posture.open_critical, 0);
        assert_eq!(posture.open_high, 0);
    }

    #[test]
    fn test_security_posture_calculate_score() {
        // Perfect: no open incidents, good AI
        let score = SecurityPosture::calculate_score(0, 0, Some(0.95));
        assert!((score - 100.0).abs() < 0.01); // clamped to 100

        // Some issues
        let score = SecurityPosture::calculate_score(2, 3, Some(0.85));
        assert!((score - 65.0).abs() < 0.01); // 100 - 20 - 15 = 65

        // Bad AI accuracy
        let score = SecurityPosture::calculate_score(0, 0, Some(0.5));
        assert!((score - 90.0).abs() < 0.01); // 100 - 10 = 90

        // Many critical open - clamped to 0
        let score = SecurityPosture::calculate_score(20, 10, None);
        assert!((score - 0.0).abs() < 0.01);
    }

    #[test]
    fn test_incident_metrics_serialization() {
        let metrics = IncidentMetrics {
            total_incidents: 50,
            by_severity: {
                let mut m = HashMap::new();
                m.insert("high".to_string(), 20);
                m
            },
            mttd_seconds: Some(120.0),
            mttr_seconds: Some(3600.0),
            ..IncidentMetrics::default()
        };

        let json = serde_json::to_string(&metrics).unwrap();
        let deserialized: IncidentMetrics = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.total_incidents, 50);
        assert_eq!(deserialized.mttd_seconds, Some(120.0));
        assert_eq!(deserialized.mttr_seconds, Some(3600.0));
    }
}
