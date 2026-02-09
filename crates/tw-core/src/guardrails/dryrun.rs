//! Dry-run simulation for action execution.

use crate::guardrails::{ExecutionGuardrails, GuardrailCheckContext, GuardrailResult};
use serde::{Deserialize, Serialize};

/// Input action for simulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulatedAction {
    pub action_type: String,
    pub target: String,
    pub affected_assets: Vec<String>,
}

/// Dry-run output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationResult {
    pub would_execute: bool,
    pub guardrail_warnings: Vec<String>,
    pub estimated_impact: u32,
    pub required_approvals: Vec<String>,
}

/// Executor that simulates execution without side effects.
#[derive(Debug, Clone)]
pub struct DryRunExecutor {
    guardrails: ExecutionGuardrails,
}

impl DryRunExecutor {
    /// Creates a dry-run executor from guardrail config.
    pub fn new(guardrails: ExecutionGuardrails) -> Self {
        Self { guardrails }
    }

    /// Simulates an action against guardrails and impact heuristics.
    pub fn simulate(&self, context: &GuardrailCheckContext) -> SimulationResult {
        let guardrail_result = self.guardrails.check(context);
        let estimated_impact = self.guardrails.estimate_blast_radius(
            &context.action_type,
            &context.target,
            &context.affected_assets,
        );

        match guardrail_result {
            GuardrailResult::Allowed => SimulationResult {
                would_execute: true,
                guardrail_warnings: Vec::new(),
                estimated_impact,
                required_approvals: Vec::new(),
            },
            GuardrailResult::RequiresApproval { reason } => SimulationResult {
                would_execute: false,
                guardrail_warnings: vec![reason.clone()],
                estimated_impact,
                required_approvals: vec![reason],
            },
            GuardrailResult::Blocked { reason } => SimulationResult {
                would_execute: false,
                guardrail_warnings: vec![reason],
                estimated_impact,
                required_approvals: Vec::new(),
            },
        }
    }
}

impl Default for DryRunExecutor {
    fn default() -> Self {
        Self::new(ExecutionGuardrails::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    #[test]
    fn test_dryrun_blocks_forbidden_action() {
        let executor = DryRunExecutor::default();
        let context = GuardrailCheckContext {
            incident_id: Uuid::new_v4(),
            action_type: "wipe_host".to_string(),
            target: "server-1".to_string(),
            actions_taken_count: 0,
            actions_taken_this_hour: 0,
            affected_assets: vec!["server-1".to_string()],
            timestamp: Utc::now(),
            previous_actions: Vec::new(),
        };

        let result = executor.simulate(&context);
        assert!(!result.would_execute);
        assert!(!result.guardrail_warnings.is_empty());
    }
}
