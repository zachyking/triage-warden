//! Core threat hunting models.
//!
//! Defines the [`HuntingHunt`] struct and related types for representing
//! threat hunts, their queries, schedules, and results.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A threat hunt definition with hypothesis, queries, and schedule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HuntingHunt {
    /// Unique identifier for this hunt.
    pub id: Uuid,
    /// Tenant that owns this hunt.
    pub tenant_id: Uuid,
    /// Human-readable name.
    pub name: String,
    /// Detailed description of what this hunt looks for.
    pub description: String,
    /// The hypothesis being tested.
    pub hypothesis: String,
    /// Type of hunt execution.
    pub hunt_type: HuntType,
    /// Queries to execute as part of this hunt.
    pub queries: Vec<HuntingQuery>,
    /// Optional schedule for recurring execution.
    pub schedule: Option<HuntSchedule>,
    /// MITRE ATT&CK techniques this hunt targets.
    pub mitre_techniques: Vec<String>,
    /// Data sources required for this hunt.
    pub data_sources: Vec<String>,
    /// Current status of the hunt.
    pub status: HuntStatus,
    /// User who created this hunt.
    pub created_by: String,
    /// When the hunt was created.
    pub created_at: DateTime<Utc>,
    /// When the hunt was last updated.
    pub updated_at: DateTime<Utc>,
    /// When the hunt was last executed.
    pub last_run: Option<DateTime<Utc>>,
    /// Summary of the most recent execution result.
    pub last_result: Option<HuntResultSummary>,
    /// Tags for categorization and filtering.
    pub tags: Vec<String>,
    /// Whether the hunt is enabled for scheduled execution.
    pub enabled: bool,
}

impl HuntingHunt {
    /// Creates a new hunt with the given name and hypothesis.
    pub fn new(name: impl Into<String>, hypothesis: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            tenant_id: Uuid::nil(),
            name: name.into(),
            description: String::new(),
            hypothesis: hypothesis.into(),
            hunt_type: HuntType::OnDemand,
            queries: Vec::new(),
            schedule: None,
            mitre_techniques: Vec::new(),
            data_sources: Vec::new(),
            status: HuntStatus::Draft,
            created_by: String::new(),
            created_at: now,
            updated_at: now,
            last_run: None,
            last_result: None,
            tags: Vec::new(),
            enabled: false,
        }
    }

    /// Sets the description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Sets the hunt type.
    pub fn with_hunt_type(mut self, ht: HuntType) -> Self {
        self.hunt_type = ht;
        self
    }

    /// Adds a query to the hunt.
    pub fn with_query(mut self, q: HuntingQuery) -> Self {
        self.queries.push(q);
        self
    }

    /// Sets the schedule.
    pub fn with_schedule(mut self, s: HuntSchedule) -> Self {
        self.schedule = Some(s);
        self
    }

    /// Adds a MITRE ATT&CK technique reference.
    pub fn with_mitre_technique(mut self, t: impl Into<String>) -> Self {
        self.mitre_techniques.push(t.into());
        self
    }

    /// Adds a tag.
    pub fn with_tag(mut self, t: impl Into<String>) -> Self {
        self.tags.push(t.into());
        self
    }

    /// Sets the data sources.
    pub fn with_data_source(mut self, ds: impl Into<String>) -> Self {
        self.data_sources.push(ds.into());
        self
    }

    /// Sets the tenant ID.
    pub fn with_tenant(mut self, tenant_id: Uuid) -> Self {
        self.tenant_id = tenant_id;
        self
    }

    /// Sets the creator.
    pub fn with_created_by(mut self, creator: impl Into<String>) -> Self {
        self.created_by = creator.into();
        self
    }

    /// Sets the enabled flag.
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Sets the status.
    pub fn with_status(mut self, status: HuntStatus) -> Self {
        self.status = status;
        self
    }
}

/// How a hunt is triggered/executed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum HuntType {
    /// Runs on a cron schedule.
    Scheduled,
    /// Runs continuously as a streaming query.
    Continuous,
    /// Runs only when manually triggered.
    OnDemand,
    /// Runs when a specific condition is met (e.g., new threat intel).
    Triggered,
}

impl std::fmt::Display for HuntType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HuntType::Scheduled => write!(f, "Scheduled"),
            HuntType::Continuous => write!(f, "Continuous"),
            HuntType::OnDemand => write!(f, "On-Demand"),
            HuntType::Triggered => write!(f, "Triggered"),
        }
    }
}

/// Current lifecycle status of a hunt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum HuntStatus {
    /// Hunt is being designed, not yet executed.
    Draft,
    /// Hunt is active and will execute on schedule or trigger.
    Active,
    /// Hunt is temporarily paused.
    Paused,
    /// Hunt finished executing (one-time hunts).
    Completed,
    /// Hunt execution failed.
    Failed,
    /// Hunt is archived and no longer active.
    Archived,
}

impl std::fmt::Display for HuntStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HuntStatus::Draft => write!(f, "Draft"),
            HuntStatus::Active => write!(f, "Active"),
            HuntStatus::Paused => write!(f, "Paused"),
            HuntStatus::Completed => write!(f, "Completed"),
            HuntStatus::Failed => write!(f, "Failed"),
            HuntStatus::Archived => write!(f, "Archived"),
        }
    }
}

/// A query within a hunt that targets a specific data source.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HuntingQuery {
    /// Unique identifier for this query within the hunt.
    pub id: String,
    /// Type/language of the query.
    pub query_type: QueryType,
    /// The actual query string.
    pub query: String,
    /// Human-readable description of what the query looks for.
    pub description: String,
    /// Maximum execution time in seconds.
    pub timeout_secs: u64,
    /// Expected baseline count for anomaly detection.
    pub expected_baseline: Option<u64>,
}

/// Supported query languages/platforms.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum QueryType {
    /// Splunk SPL.
    Splunk,
    /// Elasticsearch Query DSL / KQL.
    Elasticsearch,
    /// Raw SQL.
    Sql,
    /// Azure Data Explorer / Kusto Query Language.
    Kusto,
    /// Custom query language.
    Custom(String),
}

impl std::fmt::Display for QueryType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QueryType::Splunk => write!(f, "Splunk SPL"),
            QueryType::Elasticsearch => write!(f, "Elasticsearch"),
            QueryType::Sql => write!(f, "SQL"),
            QueryType::Kusto => write!(f, "Kusto (KQL)"),
            QueryType::Custom(name) => write!(f, "Custom: {}", name),
        }
    }
}

/// Schedule configuration for recurring hunts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HuntSchedule {
    /// Cron expression defining when to run (e.g., "0 */4 * * *").
    pub cron_expression: String,
    /// Timezone for the cron schedule.
    pub timezone: String,
    /// Maximum runtime before the hunt is killed (seconds).
    pub max_runtime_secs: u64,
}

/// Summary of a hunt execution result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HuntResultSummary {
    /// Total number of findings from this execution.
    pub total_findings: usize,
    /// Number of critical-severity findings.
    pub critical_findings: usize,
    /// When the execution completed.
    pub executed_at: DateTime<Utc>,
    /// Duration of the execution in seconds.
    pub duration_secs: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hunt_creation_defaults() {
        let hunt = HuntingHunt::new("Detect Kerberoasting", "Attackers may request TGS tickets");

        assert_eq!(hunt.name, "Detect Kerberoasting");
        assert_eq!(hunt.hypothesis, "Attackers may request TGS tickets");
        assert_eq!(hunt.hunt_type, HuntType::OnDemand);
        assert_eq!(hunt.status, HuntStatus::Draft);
        assert!(!hunt.enabled);
        assert!(hunt.queries.is_empty());
        assert!(hunt.schedule.is_none());
        assert!(hunt.last_run.is_none());
        assert!(hunt.last_result.is_none());
        assert!(hunt.tags.is_empty());
        assert!(hunt.mitre_techniques.is_empty());
    }

    #[test]
    fn test_hunt_builder_pattern() {
        let hunt = HuntingHunt::new("Lateral Movement Detection", "Detect PsExec usage")
            .with_description("Looks for PsExec-like remote execution patterns")
            .with_hunt_type(HuntType::Scheduled)
            .with_mitre_technique("T1570")
            .with_mitre_technique("T1021.002")
            .with_tag("lateral-movement")
            .with_tag("priority-high")
            .with_data_source("windows_event_logs")
            .with_enabled(true)
            .with_status(HuntStatus::Active)
            .with_created_by("analyst@example.com")
            .with_query(HuntingQuery {
                id: "q1".to_string(),
                query_type: QueryType::Splunk,
                query: "index=wineventlog EventCode=7045".to_string(),
                description: "Detect new service installations".to_string(),
                timeout_secs: 300,
                expected_baseline: Some(5),
            })
            .with_schedule(HuntSchedule {
                cron_expression: "0 */4 * * *".to_string(),
                timezone: "UTC".to_string(),
                max_runtime_secs: 600,
            });

        assert_eq!(
            hunt.description,
            "Looks for PsExec-like remote execution patterns"
        );
        assert_eq!(hunt.hunt_type, HuntType::Scheduled);
        assert_eq!(hunt.mitre_techniques.len(), 2);
        assert_eq!(hunt.tags.len(), 2);
        assert_eq!(hunt.data_sources, vec!["windows_event_logs"]);
        assert!(hunt.enabled);
        assert_eq!(hunt.status, HuntStatus::Active);
        assert_eq!(hunt.created_by, "analyst@example.com");
        assert_eq!(hunt.queries.len(), 1);
        assert!(hunt.schedule.is_some());
        assert_eq!(hunt.schedule.unwrap().cron_expression, "0 */4 * * *");
    }

    #[test]
    fn test_hunt_serialization_roundtrip() {
        let hunt = HuntingHunt::new("Test Hunt", "Test hypothesis")
            .with_hunt_type(HuntType::Triggered)
            .with_tag("test");

        let json = serde_json::to_string(&hunt).unwrap();
        let deserialized: HuntingHunt = serde_json::from_str(&json).unwrap();

        assert_eq!(hunt, deserialized);
    }

    #[test]
    fn test_hunt_type_serialization() {
        let types = vec![
            (HuntType::Scheduled, "\"scheduled\""),
            (HuntType::Continuous, "\"continuous\""),
            (HuntType::OnDemand, "\"on_demand\""),
            (HuntType::Triggered, "\"triggered\""),
        ];

        for (ht, expected) in types {
            let json = serde_json::to_string(&ht).unwrap();
            assert_eq!(json, expected);
            let back: HuntType = serde_json::from_str(&json).unwrap();
            assert_eq!(back, ht);
        }
    }

    #[test]
    fn test_hunt_status_serialization() {
        let statuses = vec![
            (HuntStatus::Draft, "\"draft\""),
            (HuntStatus::Active, "\"active\""),
            (HuntStatus::Paused, "\"paused\""),
            (HuntStatus::Completed, "\"completed\""),
            (HuntStatus::Failed, "\"failed\""),
            (HuntStatus::Archived, "\"archived\""),
        ];

        for (status, expected) in statuses {
            let json = serde_json::to_string(&status).unwrap();
            assert_eq!(json, expected);
            let back: HuntStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(back, status);
        }
    }

    #[test]
    fn test_query_type_serialization() {
        let types = vec![
            (QueryType::Splunk, "\"splunk\""),
            (QueryType::Elasticsearch, "\"elasticsearch\""),
            (QueryType::Sql, "\"sql\""),
            (QueryType::Kusto, "\"kusto\""),
        ];

        for (qt, expected) in types {
            let json = serde_json::to_string(&qt).unwrap();
            assert_eq!(json, expected);
            let back: QueryType = serde_json::from_str(&json).unwrap();
            assert_eq!(back, qt);
        }
    }

    #[test]
    fn test_query_type_custom_serialization() {
        let qt = QueryType::Custom("sigma".to_string());
        let json = serde_json::to_string(&qt).unwrap();
        let back: QueryType = serde_json::from_str(&json).unwrap();
        assert_eq!(back, qt);
    }

    #[test]
    fn test_hunt_type_display() {
        assert_eq!(format!("{}", HuntType::Scheduled), "Scheduled");
        assert_eq!(format!("{}", HuntType::Continuous), "Continuous");
        assert_eq!(format!("{}", HuntType::OnDemand), "On-Demand");
        assert_eq!(format!("{}", HuntType::Triggered), "Triggered");
    }

    #[test]
    fn test_hunt_status_display() {
        assert_eq!(format!("{}", HuntStatus::Draft), "Draft");
        assert_eq!(format!("{}", HuntStatus::Active), "Active");
        assert_eq!(format!("{}", HuntStatus::Paused), "Paused");
        assert_eq!(format!("{}", HuntStatus::Completed), "Completed");
        assert_eq!(format!("{}", HuntStatus::Failed), "Failed");
        assert_eq!(format!("{}", HuntStatus::Archived), "Archived");
    }

    #[test]
    fn test_query_type_display() {
        assert_eq!(format!("{}", QueryType::Splunk), "Splunk SPL");
        assert_eq!(format!("{}", QueryType::Elasticsearch), "Elasticsearch");
        assert_eq!(format!("{}", QueryType::Sql), "SQL");
        assert_eq!(format!("{}", QueryType::Kusto), "Kusto (KQL)");
        assert_eq!(
            format!("{}", QueryType::Custom("sigma".to_string())),
            "Custom: sigma"
        );
    }

    #[test]
    fn test_hunt_schedule_serialization() {
        let schedule = HuntSchedule {
            cron_expression: "0 0 * * *".to_string(),
            timezone: "America/New_York".to_string(),
            max_runtime_secs: 3600,
        };

        let json = serde_json::to_string(&schedule).unwrap();
        let back: HuntSchedule = serde_json::from_str(&json).unwrap();
        assert_eq!(schedule, back);
    }

    #[test]
    fn test_hunt_result_summary_serialization() {
        let summary = HuntResultSummary {
            total_findings: 15,
            critical_findings: 3,
            executed_at: Utc::now(),
            duration_secs: 45.2,
        };

        let json = serde_json::to_string(&summary).unwrap();
        let back: HuntResultSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary.total_findings, back.total_findings);
        assert_eq!(summary.critical_findings, back.critical_findings);
    }

    #[test]
    fn test_hunting_query_with_baseline() {
        let query = HuntingQuery {
            id: "q-baseline".to_string(),
            query_type: QueryType::Splunk,
            query: "index=auth action=failure | stats count".to_string(),
            description: "Count failed auth attempts".to_string(),
            timeout_secs: 120,
            expected_baseline: Some(10),
        };

        assert_eq!(query.expected_baseline, Some(10));
        let json = serde_json::to_string(&query).unwrap();
        let back: HuntingQuery = serde_json::from_str(&json).unwrap();
        assert_eq!(back.expected_baseline, Some(10));
    }

    #[test]
    fn test_hunting_query_without_baseline() {
        let query = HuntingQuery {
            id: "q-no-baseline".to_string(),
            query_type: QueryType::Elasticsearch,
            query: r#"{"query":{"match":{"event.action":"login"}}}"#.to_string(),
            description: "Find login events".to_string(),
            timeout_secs: 60,
            expected_baseline: None,
        };

        assert_eq!(query.expected_baseline, None);
    }

    #[test]
    fn test_hunt_with_tenant() {
        let tenant_id = Uuid::new_v4();
        let hunt = HuntingHunt::new("Tenant Hunt", "Hypothesis").with_tenant(tenant_id);

        assert_eq!(hunt.tenant_id, tenant_id);
    }
}
