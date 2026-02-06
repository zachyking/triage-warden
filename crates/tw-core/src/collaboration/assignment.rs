//! Incident assignment and auto-assignment rules.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Tracks who an incident is assigned to and why.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentAssignment {
    /// ID of the assigned analyst (None if unassigned).
    pub assignee_id: Option<Uuid>,
    /// ID of the user who made the assignment.
    pub assigned_by: Option<Uuid>,
    /// When the assignment was made.
    pub assigned_at: Option<DateTime<Utc>>,
    /// Reason for the assignment (e.g., "auto-assigned by rule: Critical Incidents").
    pub assignment_reason: Option<String>,
}

impl IncidentAssignment {
    /// Creates an unassigned state.
    pub fn unassigned() -> Self {
        Self {
            assignee_id: None,
            assigned_by: None,
            assigned_at: None,
            assignment_reason: None,
        }
    }

    /// Creates an assignment to a specific user.
    pub fn assign(assignee_id: Uuid, assigned_by: Uuid, reason: String) -> Self {
        Self {
            assignee_id: Some(assignee_id),
            assigned_by: Some(assigned_by),
            assigned_at: Some(Utc::now()),
            assignment_reason: Some(reason),
        }
    }

    /// Returns true if the incident is currently assigned.
    pub fn is_assigned(&self) -> bool {
        self.assignee_id.is_some()
    }
}

/// A rule for automatically assigning incidents to analysts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoAssignmentRule {
    /// Unique rule identifier.
    pub id: Uuid,
    /// Human-readable rule name.
    pub name: String,
    /// Whether this rule is active.
    pub enabled: bool,
    /// Conditions that must all match for this rule to apply.
    pub conditions: Vec<AssignmentCondition>,
    /// Who to assign the incident to when conditions match.
    pub assignee: AssigneeTarget,
    /// Priority order (lower = higher priority). Rules are evaluated in priority order.
    pub priority: i32,
    /// When this rule was created.
    pub created_at: DateTime<Utc>,
}

impl AutoAssignmentRule {
    /// Creates a new auto-assignment rule.
    pub fn new(
        name: String,
        conditions: Vec<AssignmentCondition>,
        assignee: AssigneeTarget,
        priority: i32,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            name,
            enabled: true,
            conditions,
            assignee,
            priority,
            created_at: Utc::now(),
        }
    }
}

/// A condition that must be met for an auto-assignment rule to apply.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum AssignmentCondition {
    /// Incident severity must be at least this level.
    SeverityAtLeast(String),
    /// Incident type must match.
    IncidentType(String),
    /// Alert source must match.
    Source(String),
    /// Incident must have this tag.
    Tag(String),
}

/// Who to assign an incident to.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum AssigneeTarget {
    /// Assign to a specific user by ID.
    SpecificUser(Uuid),
    /// Assign to a team (the team's on-call or lead picks it up).
    Team(String),
    /// Round-robin among the listed user IDs.
    RoundRobin(Vec<Uuid>),
    /// Assign to whoever has the fewest active incidents.
    LeastBusy,
}

/// Simplified incident data used for rule evaluation.
pub struct IncidentForAssignment {
    pub severity: String,
    pub incident_type: Option<String>,
    pub source: Option<String>,
    pub tags: Vec<String>,
}

/// Engine that evaluates auto-assignment rules against incidents.
#[derive(Debug, Default)]
pub struct AssignmentEngine {
    round_robin_index: std::collections::HashMap<Uuid, usize>,
}

impl AssignmentEngine {
    /// Creates a new assignment engine.
    pub fn new() -> Self {
        Self {
            round_robin_index: std::collections::HashMap::new(),
        }
    }

    /// Evaluates rules against an incident and returns the assignee UUID if a rule matches.
    ///
    /// Rules are evaluated in priority order (lowest priority number first).
    /// The first matching rule determines the assignment.
    pub fn evaluate_rules(
        &mut self,
        incident: &IncidentForAssignment,
        rules: &[AutoAssignmentRule],
    ) -> Option<Uuid> {
        let mut sorted_rules: Vec<&AutoAssignmentRule> =
            rules.iter().filter(|r| r.enabled).collect();
        sorted_rules.sort_by_key(|r| r.priority);

        for rule in sorted_rules {
            if self.rule_matches(incident, rule) {
                return self.resolve_assignee(rule);
            }
        }

        None
    }

    fn rule_matches(&self, incident: &IncidentForAssignment, rule: &AutoAssignmentRule) -> bool {
        rule.conditions.iter().all(|condition| match condition {
            AssignmentCondition::SeverityAtLeast(min_severity) => {
                severity_rank(&incident.severity) >= severity_rank(min_severity)
            }
            AssignmentCondition::IncidentType(expected) => incident
                .incident_type
                .as_deref()
                .is_some_and(|t| t.eq_ignore_ascii_case(expected)),
            AssignmentCondition::Source(expected) => incident
                .source
                .as_deref()
                .is_some_and(|s| s.eq_ignore_ascii_case(expected)),
            AssignmentCondition::Tag(tag) => {
                incident.tags.iter().any(|t| t.eq_ignore_ascii_case(tag))
            }
        })
    }

    fn resolve_assignee(&mut self, rule: &AutoAssignmentRule) -> Option<Uuid> {
        match &rule.assignee {
            AssigneeTarget::SpecificUser(id) => Some(*id),
            AssigneeTarget::Team(_) => {
                // Team assignment is resolved externally; return None here
                // to indicate the team lead should pick it up.
                None
            }
            AssigneeTarget::RoundRobin(users) => {
                if users.is_empty() {
                    return None;
                }
                let idx = self.round_robin_index.entry(rule.id).or_insert(0);
                let user = users[*idx % users.len()];
                *idx = (*idx + 1) % users.len();
                Some(user)
            }
            AssigneeTarget::LeastBusy => {
                // Requires external workload data; return None here.
                None
            }
        }
    }
}

/// Maps severity strings to a numeric rank for comparison.
fn severity_rank(severity: &str) -> u8 {
    match severity.to_lowercase().as_str() {
        "info" => 1,
        "low" => 2,
        "medium" => 3,
        "high" => 4,
        "critical" => 5,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_incident(severity: &str) -> IncidentForAssignment {
        IncidentForAssignment {
            severity: severity.to_string(),
            incident_type: None,
            source: None,
            tags: vec![],
        }
    }

    #[test]
    fn test_incident_assignment_unassigned() {
        let assignment = IncidentAssignment::unassigned();
        assert!(!assignment.is_assigned());
        assert!(assignment.assignee_id.is_none());
        assert!(assignment.assigned_by.is_none());
    }

    #[test]
    fn test_incident_assignment_assign() {
        let assignee = Uuid::new_v4();
        let assigner = Uuid::new_v4();
        let assignment =
            IncidentAssignment::assign(assignee, assigner, "Manual assignment".to_string());
        assert!(assignment.is_assigned());
        assert_eq!(assignment.assignee_id, Some(assignee));
        assert_eq!(assignment.assigned_by, Some(assigner));
        assert!(assignment.assigned_at.is_some());
    }

    #[test]
    fn test_auto_assignment_rule_creation() {
        let rule = AutoAssignmentRule::new(
            "Critical Incidents".to_string(),
            vec![AssignmentCondition::SeverityAtLeast("critical".to_string())],
            AssigneeTarget::SpecificUser(Uuid::new_v4()),
            1,
        );
        assert!(rule.enabled);
        assert_eq!(rule.priority, 1);
        assert_eq!(rule.conditions.len(), 1);
    }

    #[test]
    fn test_severity_rank_ordering() {
        assert!(severity_rank("critical") > severity_rank("high"));
        assert!(severity_rank("high") > severity_rank("medium"));
        assert!(severity_rank("medium") > severity_rank("low"));
        assert!(severity_rank("low") > severity_rank("info"));
        assert_eq!(severity_rank("unknown"), 0);
    }

    #[test]
    fn test_severity_at_least_condition() {
        let user_id = Uuid::new_v4();
        let rule = AutoAssignmentRule::new(
            "High+ severity".to_string(),
            vec![AssignmentCondition::SeverityAtLeast("high".to_string())],
            AssigneeTarget::SpecificUser(user_id),
            1,
        );

        let mut engine = AssignmentEngine::new();

        // Critical >= High -> match
        let critical = make_incident("critical");
        assert_eq!(
            engine.evaluate_rules(&critical, &[rule.clone()]),
            Some(user_id)
        );

        // High >= High -> match
        let high = make_incident("high");
        assert_eq!(engine.evaluate_rules(&high, &[rule.clone()]), Some(user_id));

        // Medium < High -> no match
        let medium = make_incident("medium");
        assert_eq!(engine.evaluate_rules(&medium, &[rule]), None);
    }

    #[test]
    fn test_incident_type_condition() {
        let user_id = Uuid::new_v4();
        let rule = AutoAssignmentRule::new(
            "Malware".to_string(),
            vec![AssignmentCondition::IncidentType("malware".to_string())],
            AssigneeTarget::SpecificUser(user_id),
            1,
        );

        let mut engine = AssignmentEngine::new();

        let mut incident = make_incident("high");
        incident.incident_type = Some("Malware".to_string());
        assert_eq!(
            engine.evaluate_rules(&incident, &[rule.clone()]),
            Some(user_id)
        );

        incident.incident_type = Some("phishing".to_string());
        assert_eq!(engine.evaluate_rules(&incident, &[rule]), None);
    }

    #[test]
    fn test_source_condition() {
        let user_id = Uuid::new_v4();
        let rule = AutoAssignmentRule::new(
            "Crowdstrike".to_string(),
            vec![AssignmentCondition::Source("crowdstrike".to_string())],
            AssigneeTarget::SpecificUser(user_id),
            1,
        );

        let mut engine = AssignmentEngine::new();

        let mut incident = make_incident("medium");
        incident.source = Some("CrowdStrike".to_string());
        assert_eq!(
            engine.evaluate_rules(&incident, &[rule.clone()]),
            Some(user_id)
        );

        incident.source = Some("sentinel".to_string());
        assert_eq!(engine.evaluate_rules(&incident, &[rule]), None);
    }

    #[test]
    fn test_tag_condition() {
        let user_id = Uuid::new_v4();
        let rule = AutoAssignmentRule::new(
            "PCI tagged".to_string(),
            vec![AssignmentCondition::Tag("pci".to_string())],
            AssigneeTarget::SpecificUser(user_id),
            1,
        );

        let mut engine = AssignmentEngine::new();

        let mut incident = make_incident("medium");
        incident.tags = vec!["PCI".to_string(), "production".to_string()];
        assert_eq!(
            engine.evaluate_rules(&incident, &[rule.clone()]),
            Some(user_id)
        );

        incident.tags = vec!["production".to_string()];
        assert_eq!(engine.evaluate_rules(&incident, &[rule]), None);
    }

    #[test]
    fn test_multiple_conditions_all_must_match() {
        let user_id = Uuid::new_v4();
        let rule = AutoAssignmentRule::new(
            "Critical Malware".to_string(),
            vec![
                AssignmentCondition::SeverityAtLeast("critical".to_string()),
                AssignmentCondition::IncidentType("malware".to_string()),
            ],
            AssigneeTarget::SpecificUser(user_id),
            1,
        );

        let mut engine = AssignmentEngine::new();

        // Both match
        let mut incident = make_incident("critical");
        incident.incident_type = Some("malware".to_string());
        assert_eq!(
            engine.evaluate_rules(&incident, &[rule.clone()]),
            Some(user_id)
        );

        // Only severity matches
        incident.incident_type = Some("phishing".to_string());
        assert_eq!(engine.evaluate_rules(&incident, &[rule]), None);
    }

    #[test]
    fn test_round_robin_assignment() {
        let users = vec![Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()];
        let rule = AutoAssignmentRule::new(
            "Round Robin".to_string(),
            vec![AssignmentCondition::SeverityAtLeast("info".to_string())],
            AssigneeTarget::RoundRobin(users.clone()),
            1,
        );

        let mut engine = AssignmentEngine::new();
        let incident = make_incident("high");

        assert_eq!(
            engine.evaluate_rules(&incident, &[rule.clone()]),
            Some(users[0])
        );
        assert_eq!(
            engine.evaluate_rules(&incident, &[rule.clone()]),
            Some(users[1])
        );
        assert_eq!(
            engine.evaluate_rules(&incident, &[rule.clone()]),
            Some(users[2])
        );
        // Wraps around
        assert_eq!(engine.evaluate_rules(&incident, &[rule]), Some(users[0]));
    }

    #[test]
    fn test_round_robin_empty_users() {
        let rule = AutoAssignmentRule::new(
            "Empty RR".to_string(),
            vec![AssignmentCondition::SeverityAtLeast("info".to_string())],
            AssigneeTarget::RoundRobin(vec![]),
            1,
        );

        let mut engine = AssignmentEngine::new();
        let incident = make_incident("high");
        assert_eq!(engine.evaluate_rules(&incident, &[rule]), None);
    }

    #[test]
    fn test_priority_ordering() {
        let user_a = Uuid::new_v4();
        let user_b = Uuid::new_v4();

        let rule_low_prio = AutoAssignmentRule::new(
            "Low Priority".to_string(),
            vec![AssignmentCondition::SeverityAtLeast("info".to_string())],
            AssigneeTarget::SpecificUser(user_b),
            10,
        );

        let rule_high_prio = AutoAssignmentRule::new(
            "High Priority".to_string(),
            vec![AssignmentCondition::SeverityAtLeast("info".to_string())],
            AssigneeTarget::SpecificUser(user_a),
            1,
        );

        let mut engine = AssignmentEngine::new();
        let incident = make_incident("high");

        // High priority rule (lower number) should win even if listed second
        let result = engine.evaluate_rules(&incident, &[rule_low_prio, rule_high_prio]);
        assert_eq!(result, Some(user_a));
    }

    #[test]
    fn test_disabled_rules_skipped() {
        let user_id = Uuid::new_v4();
        let mut rule = AutoAssignmentRule::new(
            "Disabled".to_string(),
            vec![AssignmentCondition::SeverityAtLeast("info".to_string())],
            AssigneeTarget::SpecificUser(user_id),
            1,
        );
        rule.enabled = false;

        let mut engine = AssignmentEngine::new();
        let incident = make_incident("high");
        assert_eq!(engine.evaluate_rules(&incident, &[rule]), None);
    }

    #[test]
    fn test_team_assignment_returns_none() {
        let rule = AutoAssignmentRule::new(
            "Team".to_string(),
            vec![AssignmentCondition::SeverityAtLeast("info".to_string())],
            AssigneeTarget::Team("soc-team".to_string()),
            1,
        );

        let mut engine = AssignmentEngine::new();
        let incident = make_incident("high");
        // Team assignment returns None because it needs external resolution
        assert_eq!(engine.evaluate_rules(&incident, &[rule]), None);
    }

    #[test]
    fn test_no_rules_returns_none() {
        let mut engine = AssignmentEngine::new();
        let incident = make_incident("critical");
        assert_eq!(engine.evaluate_rules(&incident, &[]), None);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let assignment =
            IncidentAssignment::assign(Uuid::new_v4(), Uuid::new_v4(), "test".to_string());
        let json = serde_json::to_string(&assignment).unwrap();
        let deserialized: IncidentAssignment = serde_json::from_str(&json).unwrap();
        assert_eq!(assignment.assignee_id, deserialized.assignee_id);
        assert_eq!(assignment.assigned_by, deserialized.assigned_by);
    }

    #[test]
    fn test_condition_serialization() {
        let condition = AssignmentCondition::SeverityAtLeast("high".to_string());
        let json = serde_json::to_string(&condition).unwrap();
        let deserialized: AssignmentCondition = serde_json::from_str(&json).unwrap();
        assert_eq!(condition, deserialized);
    }

    #[test]
    fn test_assignee_target_serialization() {
        let targets = vec![
            AssigneeTarget::SpecificUser(Uuid::new_v4()),
            AssigneeTarget::Team("soc".to_string()),
            AssigneeTarget::RoundRobin(vec![Uuid::new_v4()]),
            AssigneeTarget::LeastBusy,
        ];

        for target in targets {
            let json = serde_json::to_string(&target).unwrap();
            let deserialized: AssigneeTarget = serde_json::from_str(&json).unwrap();
            assert_eq!(target, deserialized);
        }
    }
}
