//! Extended guardrail rule model.

use crate::guardrails::{GuardrailCheckContext, GuardrailResult};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use uuid::Uuid;

/// Guardrail enforcement behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Enforcement {
    Block,
    RequireApproval,
    Warn,
}

/// Exception selector for a guardrail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardrailException {
    pub actor: Option<String>,
    pub incident_id: Option<Uuid>,
    pub reason: String,
}

/// Extended guardrail type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GuardrailType {
    ProtectedAsset { asset_ids: Vec<String> },
    ProtectedUser { user_ids: Vec<String> },
    ProtectedNetwork { cidrs: Vec<String> },
    MaxActionsPerHour { limit: u32 },
    MaxActionsPerIncident { limit: u32 },
    BusinessHoursOnly,
    MaxAffectedAssets { limit: u32 },
    MaxAffectedUsers { limit: u32 },
    NoIsolateServers,
    NoDeleteData,
    NoDisableExecutives,
    CustomRule { expression: String },
}

/// Guardrail object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionGuardrail {
    pub id: Uuid,
    pub name: String,
    pub guardrail_type: GuardrailType,
    pub enforcement: Enforcement,
    #[serde(default)]
    pub exceptions: Vec<GuardrailException>,
}

impl ActionGuardrail {
    /// Evaluates this guardrail against action context.
    pub fn evaluate(&self, context: &GuardrailCheckContext) -> GuardrailResult {
        let violated = match &self.guardrail_type {
            GuardrailType::ProtectedAsset { asset_ids } => asset_ids.contains(&context.target),
            GuardrailType::ProtectedUser { user_ids } => user_ids.contains(&context.target),
            GuardrailType::ProtectedNetwork { cidrs } => cidr_matches(&context.target, cidrs),
            GuardrailType::MaxActionsPerHour { limit } => context.actions_taken_this_hour >= *limit,
            GuardrailType::MaxActionsPerIncident { limit } => context.actions_taken_count >= *limit,
            GuardrailType::BusinessHoursOnly => {
                let hour = context.timestamp.hour();
                !(8..20).contains(&hour)
            }
            GuardrailType::MaxAffectedAssets { limit } => {
                context.affected_assets.len() as u32 > *limit
            }
            GuardrailType::MaxAffectedUsers { limit } => {
                context.affected_assets.len() as u32 > *limit
            }
            GuardrailType::NoIsolateServers => {
                context.action_type == "isolate_host" && context.target.contains("server")
            }
            GuardrailType::NoDeleteData => {
                context.action_type.contains("delete") || context.action_type.contains("wipe")
            }
            GuardrailType::NoDisableExecutives => {
                context.action_type == "disable_user" && context.target.contains("exec")
            }
            GuardrailType::CustomRule { expression } => evaluate_custom_rule(expression, context),
        };

        if !violated {
            return GuardrailResult::Allowed;
        }

        match self.enforcement {
            Enforcement::Block => GuardrailResult::Blocked {
                reason: format!("Guardrail '{}' blocked action", self.name),
            },
            Enforcement::RequireApproval => GuardrailResult::RequiresApproval {
                reason: format!("Guardrail '{}' requires approval", self.name),
            },
            Enforcement::Warn => GuardrailResult::RequiresApproval {
                reason: format!("Guardrail '{}' warning", self.name),
            },
        }
    }
}

fn cidr_matches(target: &str, cidrs: &[String]) -> bool {
    let Ok(target_ip) = target.parse::<IpAddr>() else {
        return false;
    };

    for cidr in cidrs {
        // Lightweight CIDR support for /8, /16, /24, /32
        let Some((base, prefix)) = cidr.split_once('/') else {
            continue;
        };
        let Ok(base_ip) = base.parse::<IpAddr>() else {
            continue;
        };
        let Ok(prefix) = prefix.parse::<u8>() else {
            continue;
        };

        if let (IpAddr::V4(t), IpAddr::V4(b)) = (target_ip, base_ip) {
            let mask = if prefix == 0 {
                0u32
            } else {
                u32::MAX << (32 - prefix.min(32))
            };
            let t_bits = u32::from(t);
            let b_bits = u32::from(b);
            if (t_bits & mask) == (b_bits & mask) {
                return true;
            }
        }
    }

    false
}

fn evaluate_custom_rule(expression: &str, context: &GuardrailCheckContext) -> bool {
    // Lightweight expression support: token-based checks to avoid executing arbitrary code.
    let expr = expression.to_ascii_lowercase();
    (expr.contains("action=disable_user") && context.action_type == "disable_user")
        || (expr.contains("target_contains:prod") && context.target.contains("prod"))
}

trait HourComponent {
    fn hour(&self) -> u32;
}

impl HourComponent for chrono::DateTime<chrono::Utc> {
    fn hour(&self) -> u32 {
        chrono::Timelike::hour(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guardrails::GuardrailCheckContext;
    use chrono::Utc;

    #[test]
    fn test_max_actions_rule_blocks() {
        let guardrail = ActionGuardrail {
            id: Uuid::new_v4(),
            name: "limit".to_string(),
            guardrail_type: GuardrailType::MaxActionsPerIncident { limit: 1 },
            enforcement: Enforcement::Block,
            exceptions: Vec::new(),
        };
        let context = GuardrailCheckContext {
            incident_id: Uuid::new_v4(),
            action_type: "isolate_host".to_string(),
            target: "host-1".to_string(),
            actions_taken_count: 1,
            actions_taken_this_hour: 0,
            affected_assets: Vec::new(),
            timestamp: Utc::now(),
            previous_actions: Vec::new(),
        };

        assert!(matches!(
            guardrail.evaluate(&context),
            GuardrailResult::Blocked { .. }
        ));
    }
}
