//! Execution guardrails for automated incident response.
//!
//! This module provides runtime guardrails that limit what automated actions
//! can do, protecting critical infrastructure and preventing runaway automation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use uuid::Uuid;

/// Forbidden combination of actions that should never be executed together.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForbiddenCombination {
    /// Actions in the forbidden combination.
    pub actions: Vec<String>,
    /// Reason why this combination is forbidden.
    pub reason: String,
}

/// Result of a guardrail check.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum GuardrailResult {
    /// Action is allowed.
    Allowed,
    /// Action requires human approval before proceeding.
    RequiresApproval {
        /// Reason approval is required.
        reason: String,
    },
    /// Action is blocked by guardrails.
    Blocked {
        /// Reason the action is blocked.
        reason: String,
    },
}

/// Context for a guardrail check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardrailCheckContext {
    /// ID of the incident being responded to.
    pub incident_id: Uuid,
    /// Type of action being performed.
    pub action_type: String,
    /// Target of the action.
    pub target: String,
    /// Number of actions already taken for this incident.
    pub actions_taken_count: u32,
    /// Number of actions taken in the current hour.
    pub actions_taken_this_hour: u32,
    /// List of affected asset identifiers.
    pub affected_assets: Vec<String>,
    /// Timestamp of the action.
    pub timestamp: DateTime<Utc>,
    /// Previous actions taken (for combination checking).
    pub previous_actions: Vec<String>,
}

/// Execution guardrails configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionGuardrails {
    /// Maximum number of actions per incident.
    pub max_actions_per_incident: u32,
    /// Maximum number of actions per hour across all incidents.
    pub max_actions_per_hour: u32,
    /// Set of protected asset identifiers.
    pub protected_asset_ids: HashSet<String>,
    /// Set of protected user identifiers.
    pub protected_user_ids: HashSet<String>,
    /// Patterns for protected hostnames (glob-style).
    pub protected_hostname_patterns: Vec<String>,
    /// Actions that are forbidden entirely.
    pub forbidden_actions: HashSet<String>,
    /// Combinations of actions that are forbidden.
    pub forbidden_action_combinations: Vec<ForbiddenCombination>,
    /// Maximum blast radius (number of affected assets).
    pub max_blast_radius: u32,
    /// Actions that always require human approval.
    pub require_human_for: HashSet<String>,
    /// Whether guardrails are enabled.
    pub enabled: bool,
}

impl ExecutionGuardrails {
    /// Check if an action is allowed by the guardrails.
    ///
    /// Checks are performed in order of severity:
    /// 1. Guardrails enabled check
    /// 2. Forbidden actions
    /// 3. Protected targets
    /// 4. Action limits
    /// 5. Blast radius
    /// 6. Forbidden combinations
    /// 7. Human approval requirements
    pub fn check(&self, context: &GuardrailCheckContext) -> GuardrailResult {
        if !self.enabled {
            return GuardrailResult::Allowed;
        }

        // 1. Forbidden actions
        if self.forbidden_actions.contains(&context.action_type) {
            return GuardrailResult::Blocked {
                reason: format!(
                    "Action '{}' is forbidden by guardrails",
                    context.action_type
                ),
            };
        }

        // 2. Protected targets
        if self.is_protected_target(&context.target) {
            return GuardrailResult::Blocked {
                reason: format!("Target '{}' is protected by guardrails", context.target),
            };
        }

        // 3. Action limits - per incident
        if context.actions_taken_count >= self.max_actions_per_incident {
            return GuardrailResult::Blocked {
                reason: format!(
                    "Maximum actions per incident ({}) exceeded",
                    self.max_actions_per_incident
                ),
            };
        }

        // 4. Action limits - per hour
        if context.actions_taken_this_hour >= self.max_actions_per_hour {
            return GuardrailResult::Blocked {
                reason: format!(
                    "Maximum actions per hour ({}) exceeded",
                    self.max_actions_per_hour
                ),
            };
        }

        // 5. Blast radius
        let blast_radius = self.estimate_blast_radius(
            &context.action_type,
            &context.target,
            &context.affected_assets,
        );
        if blast_radius > self.max_blast_radius {
            return GuardrailResult::Blocked {
                reason: format!(
                    "Blast radius ({}) exceeds maximum ({})",
                    blast_radius, self.max_blast_radius
                ),
            };
        }

        // 6. Forbidden combinations
        if let Some(reason) =
            self.check_forbidden_combinations(&context.action_type, &context.previous_actions)
        {
            return GuardrailResult::Blocked {
                reason: format!("Forbidden action combination: {}", reason),
            };
        }

        // 7. Human approval requirements
        if self.require_human_for.contains(&context.action_type) {
            return GuardrailResult::RequiresApproval {
                reason: format!("Action '{}' requires human approval", context.action_type),
            };
        }

        GuardrailResult::Allowed
    }

    /// Estimate the blast radius of an action.
    ///
    /// Returns the number of assets that would be affected.
    pub fn estimate_blast_radius(
        &self,
        action: &str,
        target: &str,
        related_assets: &[String],
    ) -> u32 {
        let base = 1u32; // The target itself

        // Some actions have wider blast radius
        let multiplier: u32 = match action {
            "isolate_host" => 1,     // Affects only the host
            "block_ip" => 2,         // May affect services behind the IP
            "block_domain" => 3,     // May affect multiple services using the domain
            "disable_user" => 2,     // Affects user and their resources
            "quarantine_email" => 1, // Affects only the email
            "reset_password" => 1,   // Affects only the user
            "revoke_sessions" => 1,  // Affects only the user
            _ => 1,
        };

        let related_count = related_assets.len() as u32;

        // Count how many of the related assets match the target pattern
        let _ = target; // Target is already counted in base

        base * multiplier + related_count
    }

    /// Check if a target is protected.
    fn is_protected_target(&self, target: &str) -> bool {
        // Check exact asset ID match
        if self.protected_asset_ids.contains(target) {
            return true;
        }

        // Check exact user ID match
        if self.protected_user_ids.contains(target) {
            return true;
        }

        // Check hostname patterns
        for pattern in &self.protected_hostname_patterns {
            if Self::glob_match(pattern, target) {
                return true;
            }
        }

        false
    }

    /// Check if the action combined with previous actions forms a forbidden combination.
    fn check_forbidden_combinations(
        &self,
        action: &str,
        previous_actions: &[String],
    ) -> Option<String> {
        for combo in &self.forbidden_action_combinations {
            // Check if all actions in the forbidden combination are present
            // (either as the current action or in previous actions)
            let mut all_present = true;
            for forbidden_action in &combo.actions {
                let in_current = forbidden_action == action;
                let in_previous = previous_actions.iter().any(|a| a == forbidden_action);
                if !in_current && !in_previous {
                    all_present = false;
                    break;
                }
            }
            if all_present {
                return Some(combo.reason.clone());
            }
        }
        None
    }

    /// Simple glob matching supporting * and ? wildcards.
    fn glob_match(pattern: &str, text: &str) -> bool {
        let pattern_chars: Vec<char> = pattern.chars().collect();
        let text_chars: Vec<char> = text.chars().collect();
        Self::glob_match_recursive(&pattern_chars, &text_chars)
    }

    fn glob_match_recursive(pattern: &[char], text: &[char]) -> bool {
        if pattern.is_empty() {
            return text.is_empty();
        }

        if pattern[0] == '*' {
            // Try matching * with zero or more characters
            for i in 0..=text.len() {
                if Self::glob_match_recursive(&pattern[1..], &text[i..]) {
                    return true;
                }
            }
            return false;
        }

        if text.is_empty() {
            return false;
        }

        if pattern[0] == '?' || pattern[0] == text[0] {
            return Self::glob_match_recursive(&pattern[1..], &text[1..]);
        }

        false
    }
}

impl Default for ExecutionGuardrails {
    fn default() -> Self {
        let mut forbidden_actions = HashSet::new();
        forbidden_actions.insert("delete_user".to_string());
        forbidden_actions.insert("wipe_host".to_string());
        forbidden_actions.insert("delete_all_emails".to_string());
        forbidden_actions.insert("modify_firewall".to_string());

        let mut protected_user_ids = HashSet::new();
        protected_user_ids.insert("admin".to_string());
        protected_user_ids.insert("root".to_string());
        protected_user_ids.insert("administrator".to_string());

        let mut require_human_for = HashSet::new();
        require_human_for.insert("isolate_host".to_string());
        require_human_for.insert("disable_user".to_string());
        require_human_for.insert("reset_password".to_string());

        Self {
            max_actions_per_incident: 20,
            max_actions_per_hour: 50,
            protected_asset_ids: HashSet::new(),
            protected_user_ids,
            protected_hostname_patterns: vec!["*-prod-*".to_string(), "dc*".to_string()],
            forbidden_actions,
            forbidden_action_combinations: vec![ForbiddenCombination {
                actions: vec!["isolate_host".to_string(), "wipe_host".to_string()],
                reason: "Cannot isolate and wipe the same host".to_string(),
            }],
            max_blast_radius: 10,
            require_human_for,
            enabled: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_context() -> GuardrailCheckContext {
        GuardrailCheckContext {
            incident_id: Uuid::new_v4(),
            action_type: "block_ip".to_string(),
            target: "10.0.1.50".to_string(),
            actions_taken_count: 0,
            actions_taken_this_hour: 0,
            affected_assets: vec![],
            timestamp: Utc::now(),
            previous_actions: vec![],
        }
    }

    #[test]
    fn test_default_guardrails() {
        let g = ExecutionGuardrails::default();
        assert!(g.enabled);
        assert_eq!(g.max_actions_per_incident, 20);
        assert_eq!(g.max_actions_per_hour, 50);
        assert!(g.forbidden_actions.contains("delete_user"));
        assert!(g.forbidden_actions.contains("wipe_host"));
        assert!(g.protected_user_ids.contains("admin"));
        assert!(g.require_human_for.contains("isolate_host"));
    }

    #[test]
    fn test_allowed_action() {
        let g = ExecutionGuardrails::default();
        let ctx = default_context();
        assert_eq!(g.check(&ctx), GuardrailResult::Allowed);
    }

    #[test]
    fn test_disabled_guardrails() {
        let g = ExecutionGuardrails {
            enabled: false,
            ..ExecutionGuardrails::default()
        };
        let mut ctx = default_context();
        ctx.action_type = "delete_user".to_string();
        assert_eq!(g.check(&ctx), GuardrailResult::Allowed);
    }

    #[test]
    fn test_forbidden_action() {
        let g = ExecutionGuardrails::default();
        let mut ctx = default_context();
        ctx.action_type = "delete_user".to_string();
        match g.check(&ctx) {
            GuardrailResult::Blocked { reason } => {
                assert!(reason.contains("forbidden"));
            }
            other => panic!("Expected Blocked, got {:?}", other),
        }
    }

    #[test]
    fn test_protected_user() {
        let g = ExecutionGuardrails::default();
        let mut ctx = default_context();
        ctx.target = "admin".to_string();
        match g.check(&ctx) {
            GuardrailResult::Blocked { reason } => {
                assert!(reason.contains("protected"));
            }
            other => panic!("Expected Blocked, got {:?}", other),
        }
    }

    #[test]
    fn test_protected_asset() {
        let mut g = ExecutionGuardrails::default();
        g.protected_asset_ids.insert("critical-db-01".to_string());
        let mut ctx = default_context();
        ctx.target = "critical-db-01".to_string();
        match g.check(&ctx) {
            GuardrailResult::Blocked { reason } => {
                assert!(reason.contains("protected"));
            }
            other => panic!("Expected Blocked, got {:?}", other),
        }
    }

    #[test]
    fn test_protected_hostname_pattern() {
        let g = ExecutionGuardrails::default();
        let mut ctx = default_context();
        ctx.target = "web-prod-01".to_string();
        match g.check(&ctx) {
            GuardrailResult::Blocked { reason } => {
                assert!(reason.contains("protected"));
            }
            other => panic!("Expected Blocked, got {:?}", other),
        }
    }

    #[test]
    fn test_dc_hostname_pattern() {
        let g = ExecutionGuardrails::default();
        let mut ctx = default_context();
        ctx.target = "dc01.corp.local".to_string();
        match g.check(&ctx) {
            GuardrailResult::Blocked { reason } => {
                assert!(reason.contains("protected"));
            }
            other => panic!("Expected Blocked, got {:?}", other),
        }
    }

    #[test]
    fn test_max_actions_per_incident() {
        let g = ExecutionGuardrails::default();
        let mut ctx = default_context();
        ctx.actions_taken_count = 20;
        match g.check(&ctx) {
            GuardrailResult::Blocked { reason } => {
                assert!(reason.contains("per incident"));
            }
            other => panic!("Expected Blocked, got {:?}", other),
        }
    }

    #[test]
    fn test_max_actions_per_hour() {
        let g = ExecutionGuardrails::default();
        let mut ctx = default_context();
        ctx.actions_taken_this_hour = 50;
        match g.check(&ctx) {
            GuardrailResult::Blocked { reason } => {
                assert!(reason.contains("per hour"));
            }
            other => panic!("Expected Blocked, got {:?}", other),
        }
    }

    #[test]
    fn test_blast_radius_exceeded() {
        let g = ExecutionGuardrails {
            max_blast_radius: 3,
            ..ExecutionGuardrails::default()
        };
        let mut ctx = default_context();
        ctx.action_type = "block_domain".to_string();
        // block_domain has multiplier 3, plus 2 related assets = 5, exceeds 3
        ctx.affected_assets = vec!["a".to_string(), "b".to_string()];
        match g.check(&ctx) {
            GuardrailResult::Blocked { reason } => {
                assert!(reason.contains("Blast radius"));
            }
            other => panic!("Expected Blocked, got {:?}", other),
        }
    }

    #[test]
    fn test_forbidden_combination() {
        let mut ctx = default_context();
        // wipe_host is forbidden by itself too, so use custom guardrails
        let mut custom = ExecutionGuardrails::default();
        custom.forbidden_actions.clear();
        ctx.action_type = "isolate_host".to_string();
        ctx.previous_actions = vec!["wipe_host".to_string()];
        match custom.check(&ctx) {
            GuardrailResult::Blocked { reason } => {
                assert!(reason.contains("Forbidden action combination"));
            }
            other => panic!("Expected Blocked, got {:?}", other),
        }
    }

    #[test]
    fn test_requires_human_approval() {
        let g = ExecutionGuardrails::default();
        let mut ctx = default_context();
        ctx.action_type = "isolate_host".to_string();
        ctx.target = "workstation-dev-01".to_string(); // Not a protected pattern
        match g.check(&ctx) {
            GuardrailResult::RequiresApproval { reason } => {
                assert!(reason.contains("requires human approval"));
            }
            other => panic!("Expected RequiresApproval, got {:?}", other),
        }
    }

    #[test]
    fn test_estimate_blast_radius() {
        let g = ExecutionGuardrails::default();
        assert_eq!(g.estimate_blast_radius("isolate_host", "host1", &[]), 1);
        assert_eq!(g.estimate_blast_radius("block_ip", "1.2.3.4", &[]), 2);
        assert_eq!(
            g.estimate_blast_radius("block_domain", "evil.com", &["a".to_string()]),
            4 // 1*3 + 1
        );
        assert_eq!(
            g.estimate_blast_radius(
                "disable_user",
                "bob",
                &["res1".to_string(), "res2".to_string()]
            ),
            4 // 1*2 + 2
        );
    }

    #[test]
    fn test_glob_match() {
        assert!(ExecutionGuardrails::glob_match("*-prod-*", "web-prod-01"));
        assert!(ExecutionGuardrails::glob_match(
            "*-prod-*",
            "db-prod-cluster"
        ));
        assert!(!ExecutionGuardrails::glob_match("*-prod-*", "web-dev-01"));
        assert!(ExecutionGuardrails::glob_match("dc*", "dc01.corp.local"));
        assert!(!ExecutionGuardrails::glob_match("dc*", "workstation01"));
        assert!(ExecutionGuardrails::glob_match("?est", "test"));
        assert!(!ExecutionGuardrails::glob_match("?est", "toast"));
    }

    #[test]
    fn test_no_forbidden_combination_when_unrelated() {
        let g = ExecutionGuardrails::default();
        let mut ctx = default_context();
        ctx.action_type = "block_ip".to_string();
        ctx.previous_actions = vec!["search_logs".to_string(), "create_ticket".to_string()];
        assert_eq!(g.check(&ctx), GuardrailResult::Allowed);
    }

    #[test]
    fn test_check_order_forbidden_before_limits() {
        let g = ExecutionGuardrails {
            max_actions_per_incident: 0, // Would block by limit
            ..ExecutionGuardrails::default()
        };
        let mut ctx = default_context();
        ctx.action_type = "delete_user".to_string(); // Forbidden
        match g.check(&ctx) {
            GuardrailResult::Blocked { reason } => {
                assert!(
                    reason.contains("forbidden"),
                    "Should be blocked by forbidden, not limits"
                );
            }
            other => panic!("Expected Blocked, got {:?}", other),
        }
    }

    #[test]
    fn test_check_order_protected_before_limits() {
        let g = ExecutionGuardrails {
            max_actions_per_incident: 0, // Would block by limit
            ..ExecutionGuardrails::default()
        };
        let mut ctx = default_context();
        ctx.target = "admin".to_string(); // Protected user
        match g.check(&ctx) {
            GuardrailResult::Blocked { reason } => {
                assert!(
                    reason.contains("protected"),
                    "Should be blocked by protection, not limits"
                );
            }
            other => panic!("Expected Blocked, got {:?}", other),
        }
    }
}
