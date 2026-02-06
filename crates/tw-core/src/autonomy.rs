//! Autonomy level management for automated incident response.
//!
//! This module provides configurable autonomy levels that control how much
//! freedom the AI system has to execute actions without human intervention.

use chrono::{DateTime, Datelike, Timelike, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Level of autonomy for the AI response system.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AutonomyLevel {
    /// AI suggests, human executes all actions.
    Assisted,
    /// AI auto-executes low-risk, human approves high-risk.
    Supervised,
    /// AI executes all except explicitly protected actions.
    Autonomous,
    /// AI executes everything (emergency mode only, requires special auth).
    FullAutonomous,
}

impl AutonomyLevel {
    /// Check if the autonomy level allows auto-execution for a given risk level.
    pub fn allows_auto_execute(&self, risk_level: &str) -> bool {
        match self {
            Self::Assisted => false,
            Self::Supervised => matches!(risk_level, "none" | "low"),
            Self::Autonomous => matches!(risk_level, "none" | "low" | "medium" | "high"),
            Self::FullAutonomous => true,
        }
    }

    /// Returns the database-compatible string representation.
    pub fn as_db_str(&self) -> &'static str {
        match self {
            Self::Assisted => "assisted",
            Self::Supervised => "supervised",
            Self::Autonomous => "autonomous",
            Self::FullAutonomous => "full_autonomous",
        }
    }

    /// Parses an AutonomyLevel from a database string.
    pub fn from_db_str(s: &str) -> Option<Self> {
        match s {
            "assisted" => Some(Self::Assisted),
            "supervised" => Some(Self::Supervised),
            "autonomous" => Some(Self::Autonomous),
            "full_autonomous" => Some(Self::FullAutonomous),
            _ => None,
        }
    }
}

impl std::fmt::Display for AutonomyLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Assisted => write!(f, "Assisted"),
            Self::Supervised => write!(f, "Supervised"),
            Self::Autonomous => write!(f, "Autonomous"),
            Self::FullAutonomous => write!(f, "Full Autonomous"),
        }
    }
}

/// Time-based rule for changing autonomy levels.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeBasedRule {
    /// Human-readable name for the rule.
    pub name: String,
    /// Start hour (0-23, inclusive).
    pub start_hour: u32,
    /// End hour (0-23, exclusive).
    pub end_hour: u32,
    /// Days of the week this rule applies (0=Sunday, 6=Saturday).
    pub days_of_week: Vec<u32>,
    /// Autonomy level when this rule applies.
    pub level: AutonomyLevel,
}

impl TimeBasedRule {
    /// Check if this rule applies at the given timestamp.
    pub fn applies_at(&self, timestamp: &DateTime<Utc>) -> bool {
        let hour = timestamp.hour();
        let weekday = timestamp.weekday().num_days_from_sunday();

        // Check day of week
        if !self.days_of_week.contains(&weekday) {
            return false;
        }

        // Check hour range (supports wrapping around midnight)
        if self.start_hour <= self.end_hour {
            hour >= self.start_hour && hour < self.end_hour
        } else {
            // Wraps around midnight (e.g., 22..6)
            hour >= self.start_hour || hour < self.end_hour
        }
    }
}

/// Configuration for autonomy levels.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutonomyConfig {
    /// Tenant ID this configuration belongs to.
    pub tenant_id: Uuid,
    /// Default autonomy level.
    pub default_level: AutonomyLevel,
    /// Per-action autonomy overrides.
    pub per_action_overrides: HashMap<String, AutonomyLevel>,
    /// Per-severity autonomy overrides.
    pub per_severity_overrides: HashMap<String, AutonomyLevel>,
    /// Time-based rules for adjusting autonomy.
    pub time_based_rules: Vec<TimeBasedRule>,
    /// Emergency contact list.
    pub emergency_contacts: Vec<String>,
    /// When this configuration was last updated.
    pub updated_at: DateTime<Utc>,
    /// Who last updated this configuration.
    pub updated_by: String,
}

/// Decision about what autonomy level applies for a specific action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutonomyDecision {
    /// Action being considered.
    pub action: String,
    /// Severity of the incident.
    pub incident_severity: String,
    /// Resolved autonomy level.
    pub resolved_level: AutonomyLevel,
    /// Whether the action can be auto-executed.
    pub auto_execute: bool,
    /// Human-readable reason for the decision.
    pub reason: String,
    /// Timestamp of the decision.
    pub timestamp: DateTime<Utc>,
}

impl AutonomyConfig {
    /// Resolve the effective autonomy level for a given action.
    ///
    /// Priority order (highest to lowest):
    /// 1. Per-action overrides
    /// 2. Per-severity overrides
    /// 3. Time-based rules
    /// 4. Default level
    pub fn resolve_level(
        &self,
        action: &str,
        severity: &str,
        timestamp: &DateTime<Utc>,
    ) -> AutonomyDecision {
        // 1. Per-action override (highest priority)
        if let Some(level) = self.per_action_overrides.get(action) {
            let risk_level = self.action_to_risk_level(action);
            return AutonomyDecision {
                action: action.to_string(),
                incident_severity: severity.to_string(),
                resolved_level: *level,
                auto_execute: level.allows_auto_execute(&risk_level),
                reason: format!("Per-action override for '{}'", action),
                timestamp: *timestamp,
            };
        }

        // 2. Per-severity override
        if let Some(level) = self.per_severity_overrides.get(severity) {
            let risk_level = self.action_to_risk_level(action);
            return AutonomyDecision {
                action: action.to_string(),
                incident_severity: severity.to_string(),
                resolved_level: *level,
                auto_execute: level.allows_auto_execute(&risk_level),
                reason: format!("Per-severity override for '{}'", severity),
                timestamp: *timestamp,
            };
        }

        // 3. Time-based rules
        if let Some(level) = self.check_time_rules(timestamp) {
            let risk_level = self.action_to_risk_level(action);
            return AutonomyDecision {
                action: action.to_string(),
                incident_severity: severity.to_string(),
                resolved_level: level,
                auto_execute: level.allows_auto_execute(&risk_level),
                reason: "Time-based rule applied".to_string(),
                timestamp: *timestamp,
            };
        }

        // 4. Default level
        let risk_level = self.action_to_risk_level(action);
        AutonomyDecision {
            action: action.to_string(),
            incident_severity: severity.to_string(),
            resolved_level: self.default_level,
            auto_execute: self.default_level.allows_auto_execute(&risk_level),
            reason: "Default autonomy level".to_string(),
            timestamp: *timestamp,
        }
    }

    /// Check if any time-based rule applies at the given timestamp.
    fn check_time_rules(&self, timestamp: &DateTime<Utc>) -> Option<AutonomyLevel> {
        for rule in &self.time_based_rules {
            if rule.applies_at(timestamp) {
                return Some(rule.level);
            }
        }
        None
    }

    /// Map action name to a risk level string for auto-execute checks.
    fn action_to_risk_level(&self, action: &str) -> String {
        match action {
            "create_ticket" | "add_ticket_comment" | "send_notification" | "search_logs" => {
                "low".to_string()
            }
            "block_ip" | "block_domain" | "block_hash" | "quarantine_email" => "medium".to_string(),
            "isolate_host" | "disable_user" | "reset_password" | "revoke_sessions" => {
                "high".to_string()
            }
            "delete_user" | "wipe_host" => "critical".to_string(),
            _ => "medium".to_string(),
        }
    }
}

impl Default for AutonomyConfig {
    fn default() -> Self {
        Self {
            tenant_id: Uuid::nil(),
            default_level: AutonomyLevel::Supervised,
            per_action_overrides: HashMap::new(),
            per_severity_overrides: HashMap::new(),
            time_based_rules: vec![],
            emergency_contacts: vec![],
            updated_at: Utc::now(),
            updated_by: "system".to_string(),
        }
    }
}

/// Audit entry recording an autonomy decision and its outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutonomyAuditEntry {
    /// Unique ID of the audit entry.
    pub id: Uuid,
    /// Tenant ID.
    pub tenant_id: Uuid,
    /// Incident ID.
    pub incident_id: Uuid,
    /// Action that was evaluated.
    pub action: String,
    /// The autonomy decision made.
    pub decision: AutonomyDecision,
    /// Whether the action was actually executed.
    pub executed: bool,
    /// Outcome of the execution (if executed).
    pub outcome: Option<String>,
    /// Timestamp of the audit entry.
    pub timestamp: DateTime<Utc>,
}

impl AutonomyAuditEntry {
    /// Create a new audit entry.
    pub fn new(
        tenant_id: Uuid,
        incident_id: Uuid,
        action: String,
        decision: AutonomyDecision,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            tenant_id,
            incident_id,
            action,
            decision,
            executed: false,
            outcome: None,
            timestamp: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn default_config() -> AutonomyConfig {
        AutonomyConfig::default()
    }

    #[test]
    fn test_autonomy_level_allows_auto_execute() {
        // Assisted: never auto-executes
        assert!(!AutonomyLevel::Assisted.allows_auto_execute("none"));
        assert!(!AutonomyLevel::Assisted.allows_auto_execute("low"));
        assert!(!AutonomyLevel::Assisted.allows_auto_execute("critical"));

        // Supervised: only none and low
        assert!(AutonomyLevel::Supervised.allows_auto_execute("none"));
        assert!(AutonomyLevel::Supervised.allows_auto_execute("low"));
        assert!(!AutonomyLevel::Supervised.allows_auto_execute("medium"));
        assert!(!AutonomyLevel::Supervised.allows_auto_execute("high"));
        assert!(!AutonomyLevel::Supervised.allows_auto_execute("critical"));

        // Autonomous: none through high
        assert!(AutonomyLevel::Autonomous.allows_auto_execute("none"));
        assert!(AutonomyLevel::Autonomous.allows_auto_execute("low"));
        assert!(AutonomyLevel::Autonomous.allows_auto_execute("medium"));
        assert!(AutonomyLevel::Autonomous.allows_auto_execute("high"));
        assert!(!AutonomyLevel::Autonomous.allows_auto_execute("critical"));

        // FullAutonomous: everything
        assert!(AutonomyLevel::FullAutonomous.allows_auto_execute("none"));
        assert!(AutonomyLevel::FullAutonomous.allows_auto_execute("critical"));
    }

    #[test]
    fn test_default_config() {
        let config = default_config();
        assert_eq!(config.default_level, AutonomyLevel::Supervised);
        assert!(config.per_action_overrides.is_empty());
        assert!(config.per_severity_overrides.is_empty());
        assert!(config.time_based_rules.is_empty());
    }

    #[test]
    fn test_resolve_default_level() {
        let config = default_config();
        let now = Utc::now();
        let decision = config.resolve_level("block_ip", "high", &now);
        assert_eq!(decision.resolved_level, AutonomyLevel::Supervised);
        assert!(!decision.auto_execute); // block_ip is medium risk, supervised only allows low
        assert!(decision.reason.contains("Default"));
    }

    #[test]
    fn test_resolve_per_action_override() {
        let mut config = default_config();
        config
            .per_action_overrides
            .insert("isolate_host".to_string(), AutonomyLevel::Assisted);
        let now = Utc::now();

        let decision = config.resolve_level("isolate_host", "critical", &now);
        assert_eq!(decision.resolved_level, AutonomyLevel::Assisted);
        assert!(!decision.auto_execute);
        assert!(decision.reason.contains("Per-action"));
    }

    #[test]
    fn test_resolve_per_severity_override() {
        let mut config = default_config();
        config
            .per_severity_overrides
            .insert("critical".to_string(), AutonomyLevel::Autonomous);
        let now = Utc::now();

        let decision = config.resolve_level("block_ip", "critical", &now);
        assert_eq!(decision.resolved_level, AutonomyLevel::Autonomous);
        assert!(decision.auto_execute); // block_ip is medium, Autonomous allows medium
        assert!(decision.reason.contains("Per-severity"));
    }

    #[test]
    fn test_per_action_takes_priority_over_severity() {
        let mut config = default_config();
        config
            .per_action_overrides
            .insert("block_ip".to_string(), AutonomyLevel::Assisted);
        config
            .per_severity_overrides
            .insert("critical".to_string(), AutonomyLevel::Autonomous);
        let now = Utc::now();

        let decision = config.resolve_level("block_ip", "critical", &now);
        assert_eq!(decision.resolved_level, AutonomyLevel::Assisted);
    }

    #[test]
    fn test_time_based_rule() {
        let mut config = default_config();
        // After-hours rule: autonomous during nights and weekends
        config.time_based_rules.push(TimeBasedRule {
            name: "after_hours".to_string(),
            start_hour: 18,
            end_hour: 8,
            days_of_week: vec![0, 1, 2, 3, 4, 5, 6], // all days
            level: AutonomyLevel::Autonomous,
        });

        // 2024-01-15 is a Monday, 20:00 UTC (after hours)
        let after_hours = Utc.with_ymd_and_hms(2024, 1, 15, 20, 0, 0).unwrap();
        let decision = config.resolve_level("block_ip", "high", &after_hours);
        assert_eq!(decision.resolved_level, AutonomyLevel::Autonomous);
        assert!(decision.reason.contains("Time-based"));

        // 2024-01-15 10:00 UTC (business hours)
        let business_hours = Utc.with_ymd_and_hms(2024, 1, 15, 10, 0, 0).unwrap();
        let decision = config.resolve_level("block_ip", "high", &business_hours);
        assert_eq!(decision.resolved_level, AutonomyLevel::Supervised);
        assert!(decision.reason.contains("Default"));
    }

    #[test]
    fn test_time_based_rule_specific_days() {
        let mut config = default_config();
        // Weekend rule: autonomous on Sat/Sun only
        config.time_based_rules.push(TimeBasedRule {
            name: "weekend".to_string(),
            start_hour: 0,
            end_hour: 24,
            days_of_week: vec![0, 6], // Sunday, Saturday
            level: AutonomyLevel::Autonomous,
        });

        // 2024-01-14 is a Sunday
        let sunday = Utc.with_ymd_and_hms(2024, 1, 14, 12, 0, 0).unwrap();
        let decision = config.resolve_level("block_ip", "high", &sunday);
        assert_eq!(decision.resolved_level, AutonomyLevel::Autonomous);

        // 2024-01-15 is a Monday
        let monday = Utc.with_ymd_and_hms(2024, 1, 15, 12, 0, 0).unwrap();
        let decision = config.resolve_level("block_ip", "high", &monday);
        assert_eq!(decision.resolved_level, AutonomyLevel::Supervised);
    }

    #[test]
    fn test_severity_override_takes_priority_over_time() {
        let mut config = default_config();
        config
            .per_severity_overrides
            .insert("critical".to_string(), AutonomyLevel::Assisted);
        config.time_based_rules.push(TimeBasedRule {
            name: "always_autonomous".to_string(),
            start_hour: 0,
            end_hour: 24,
            days_of_week: vec![0, 1, 2, 3, 4, 5, 6],
            level: AutonomyLevel::Autonomous,
        });

        let now = Utc::now();
        let decision = config.resolve_level("block_ip", "critical", &now);
        assert_eq!(decision.resolved_level, AutonomyLevel::Assisted);
    }

    #[test]
    fn test_low_risk_auto_execute_supervised() {
        let config = default_config();
        let now = Utc::now();

        // search_logs is low risk -> auto-execute in supervised
        let decision = config.resolve_level("search_logs", "high", &now);
        assert!(decision.auto_execute);

        // isolate_host is high risk -> no auto-execute in supervised
        let decision = config.resolve_level("isolate_host", "high", &now);
        assert!(!decision.auto_execute);
    }

    #[test]
    fn test_autonomy_level_db_roundtrip() {
        let levels = [
            AutonomyLevel::Assisted,
            AutonomyLevel::Supervised,
            AutonomyLevel::Autonomous,
            AutonomyLevel::FullAutonomous,
        ];

        for level in &levels {
            let db_str = level.as_db_str();
            let parsed = AutonomyLevel::from_db_str(db_str).unwrap();
            assert_eq!(&parsed, level);
        }
    }

    #[test]
    fn test_autonomy_level_display() {
        assert_eq!(AutonomyLevel::Assisted.to_string(), "Assisted");
        assert_eq!(AutonomyLevel::Supervised.to_string(), "Supervised");
        assert_eq!(AutonomyLevel::Autonomous.to_string(), "Autonomous");
        assert_eq!(AutonomyLevel::FullAutonomous.to_string(), "Full Autonomous");
    }

    #[test]
    fn test_audit_entry_creation() {
        let tenant_id = Uuid::new_v4();
        let incident_id = Uuid::new_v4();
        let decision = AutonomyDecision {
            action: "block_ip".to_string(),
            incident_severity: "high".to_string(),
            resolved_level: AutonomyLevel::Supervised,
            auto_execute: false,
            reason: "Default".to_string(),
            timestamp: Utc::now(),
        };

        let entry =
            AutonomyAuditEntry::new(tenant_id, incident_id, "block_ip".to_string(), decision);

        assert_eq!(entry.tenant_id, tenant_id);
        assert_eq!(entry.incident_id, incident_id);
        assert_eq!(entry.action, "block_ip");
        assert!(!entry.executed);
        assert!(entry.outcome.is_none());
    }

    #[test]
    fn test_time_based_rule_applies() {
        let rule = TimeBasedRule {
            name: "test".to_string(),
            start_hour: 9,
            end_hour: 17,
            days_of_week: vec![1, 2, 3, 4, 5], // Mon-Fri
            level: AutonomyLevel::Supervised,
        };

        // Monday 10:00 -> applies
        let monday_10 = Utc.with_ymd_and_hms(2024, 1, 15, 10, 0, 0).unwrap();
        assert!(rule.applies_at(&monday_10));

        // Monday 18:00 -> doesn't apply (after end hour)
        let monday_18 = Utc.with_ymd_and_hms(2024, 1, 15, 18, 0, 0).unwrap();
        assert!(!rule.applies_at(&monday_18));

        // Sunday 10:00 -> doesn't apply (wrong day)
        let sunday_10 = Utc.with_ymd_and_hms(2024, 1, 14, 10, 0, 0).unwrap();
        assert!(!rule.applies_at(&sunday_10));
    }

    #[test]
    fn test_time_based_rule_midnight_wrap() {
        let rule = TimeBasedRule {
            name: "night_shift".to_string(),
            start_hour: 22,
            end_hour: 6,
            days_of_week: vec![0, 1, 2, 3, 4, 5, 6],
            level: AutonomyLevel::Autonomous,
        };

        // 23:00 -> applies
        let late_night = Utc.with_ymd_and_hms(2024, 1, 15, 23, 0, 0).unwrap();
        assert!(rule.applies_at(&late_night));

        // 03:00 -> applies
        let early_morning = Utc.with_ymd_and_hms(2024, 1, 15, 3, 0, 0).unwrap();
        assert!(rule.applies_at(&early_morning));

        // 12:00 -> doesn't apply
        let noon = Utc.with_ymd_and_hms(2024, 1, 15, 12, 0, 0).unwrap();
        assert!(!rule.applies_at(&noon));
    }

    #[test]
    fn test_from_db_str_invalid() {
        assert!(AutonomyLevel::from_db_str("invalid").is_none());
        assert!(AutonomyLevel::from_db_str("").is_none());
    }
}
