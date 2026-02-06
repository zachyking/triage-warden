//! Playbook execution engine with dependency resolution and step tracking.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use uuid::Uuid;

use super::model::*;

/// Result of executing a single advanced playbook step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepResult {
    /// ID of the executed step.
    pub step_id: String,
    /// Status of the step.
    pub status: StepStatus,
    /// Optional output data.
    pub output: Option<serde_json::Value>,
    /// Error message if the step failed.
    pub error: Option<String>,
    /// When execution started.
    pub started_at: DateTime<Utc>,
    /// When execution completed.
    pub completed_at: DateTime<Utc>,
    /// Number of retries attempted.
    pub retries: u32,
}

/// Status of a step during execution.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum StepStatus {
    /// Step has not started.
    Pending,
    /// Step is currently executing.
    Running,
    /// Step completed successfully.
    Completed,
    /// Step failed.
    Failed,
    /// Step was skipped.
    Skipped,
    /// Step exceeded its timeout.
    TimedOut,
}

/// Result of a complete playbook execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookExecutionResult {
    /// ID of the playbook that was executed.
    pub playbook_id: Uuid,
    /// Unique execution ID.
    pub execution_id: Uuid,
    /// Overall execution status.
    pub status: ExecutionStatus,
    /// Results from each step.
    pub step_results: Vec<StepResult>,
    /// Final execution context.
    pub context: HashMap<String, serde_json::Value>,
    /// When execution started.
    pub started_at: DateTime<Utc>,
    /// When execution completed.
    pub completed_at: DateTime<Utc>,
}

/// Overall status of a playbook execution.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum ExecutionStatus {
    /// Execution is in progress.
    Running,
    /// Execution completed successfully.
    Completed,
    /// Execution failed.
    Failed,
    /// Execution was cancelled.
    Cancelled,
    /// Execution timed out.
    TimedOut,
}

/// Resolves dependencies between advanced playbook steps and determines execution order.
pub struct DependencyResolver;

impl DependencyResolver {
    /// Returns steps grouped by execution wave. Steps within each group can
    /// be executed in parallel. Groups must be executed sequentially.
    ///
    /// Uses topological sort based on `on_success` edges as dependencies.
    /// A step's `on_success` list contains step IDs that depend on this step,
    /// meaning they should run after it completes.
    pub fn resolve(steps: &[AdvancedPlaybookStep]) -> Vec<Vec<String>> {
        if steps.is_empty() {
            return Vec::new();
        }

        // Build adjacency and in-degree maps
        // on_success[A] = [B, C] means B and C depend on A
        let step_ids: HashSet<&str> = steps.iter().map(|s| s.id.as_str()).collect();
        let mut in_degree: HashMap<&str, usize> = HashMap::new();
        let mut dependents: HashMap<&str, Vec<&str>> = HashMap::new();

        for step in steps {
            in_degree.entry(step.id.as_str()).or_insert(0);
            for successor_id in &step.on_success {
                if step_ids.contains(successor_id.as_str()) {
                    *in_degree.entry(successor_id.as_str()).or_insert(0) += 1;
                    dependents
                        .entry(step.id.as_str())
                        .or_default()
                        .push(successor_id.as_str());
                }
            }
        }

        let mut waves: Vec<Vec<String>> = Vec::new();

        // Start with nodes that have no incoming edges
        let mut queue: VecDeque<&str> = in_degree
            .iter()
            .filter(|(_, &deg)| deg == 0)
            .map(|(&id, _)| id)
            .collect();

        // Sort for deterministic order
        let mut initial: Vec<&str> = queue.drain(..).collect();
        initial.sort();
        queue.extend(initial);

        let mut processed: HashSet<String> = HashSet::new();

        while !queue.is_empty() {
            // Current wave: all items in the queue
            let wave_refs: Vec<&str> = queue.drain(..).collect();

            for &id in &wave_refs {
                processed.insert(id.to_string());
            }

            let mut next_queue: Vec<&str> = Vec::new();

            for &id in &wave_refs {
                if let Some(deps) = dependents.get(id) {
                    for &dep in deps {
                        if let Some(deg) = in_degree.get_mut(dep) {
                            *deg -= 1;
                            if *deg == 0 && !processed.contains(dep) {
                                next_queue.push(dep);
                            }
                        }
                    }
                }
            }

            waves.push(wave_refs.into_iter().map(|id| id.to_string()).collect());

            next_queue.sort();
            next_queue.dedup();
            queue.extend(next_queue);
        }

        waves
    }

    /// Validates that the step graph has no circular dependencies.
    /// Returns `Ok(())` if valid, or `Err` with a description of the cycle.
    pub fn validate(steps: &[AdvancedPlaybookStep]) -> Result<(), String> {
        if steps.is_empty() {
            return Ok(());
        }

        let step_ids: HashSet<&str> = steps.iter().map(|s| s.id.as_str()).collect();
        let mut in_degree: HashMap<&str, usize> = HashMap::new();
        let mut dependents: HashMap<&str, Vec<&str>> = HashMap::new();

        for step in steps {
            in_degree.entry(step.id.as_str()).or_insert(0);
            for successor_id in &step.on_success {
                if step_ids.contains(successor_id.as_str()) {
                    *in_degree.entry(successor_id.as_str()).or_insert(0) += 1;
                    dependents
                        .entry(step.id.as_str())
                        .or_default()
                        .push(successor_id.as_str());
                }
            }
        }

        let mut queue: VecDeque<&str> = in_degree
            .iter()
            .filter(|(_, &deg)| deg == 0)
            .map(|(&id, _)| id)
            .collect();

        let mut visited_count = 0;

        while let Some(current) = queue.pop_front() {
            visited_count += 1;
            if let Some(deps) = dependents.get(current) {
                for &dep in deps {
                    if let Some(deg) = in_degree.get_mut(dep) {
                        *deg -= 1;
                        if *deg == 0 {
                            queue.push_back(dep);
                        }
                    }
                }
            }
        }

        if visited_count != step_ids.len() {
            let unvisited: Vec<&str> = in_degree
                .iter()
                .filter(|(_, &deg)| deg > 0)
                .map(|(&id, _)| id)
                .collect();
            Err(format!(
                "Circular dependency detected involving steps: {}",
                unvisited.join(", ")
            ))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_step(id: &str, on_success: Vec<&str>) -> AdvancedPlaybookStep {
        AdvancedPlaybookStep {
            id: id.to_string(),
            name: format!("Step {}", id),
            step_type: StepType::Action(ActionStepConfig {
                action: "test".to_string(),
                parameters: None,
            }),
            conditions: None,
            on_success: on_success.into_iter().map(String::from).collect(),
            on_failure: FailureHandler::Stop,
            timeout_secs: None,
            retry: None,
            metadata: HashMap::new(),
        }
    }

    // ========================================================================
    // DependencyResolver::resolve tests
    // ========================================================================

    #[test]
    fn test_resolve_empty() {
        let result = DependencyResolver::resolve(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_resolve_single_step() {
        let steps = vec![make_step("a", vec![])];
        let waves = DependencyResolver::resolve(&steps);
        assert_eq!(waves.len(), 1);
        assert_eq!(waves[0], vec!["a"]);
    }

    #[test]
    fn test_resolve_linear_chain() {
        // a -> b -> c
        let steps = vec![
            make_step("a", vec!["b"]),
            make_step("b", vec!["c"]),
            make_step("c", vec![]),
        ];
        let waves = DependencyResolver::resolve(&steps);
        assert_eq!(waves.len(), 3);
        assert_eq!(waves[0], vec!["a"]);
        assert_eq!(waves[1], vec!["b"]);
        assert_eq!(waves[2], vec!["c"]);
    }

    #[test]
    fn test_resolve_parallel_branches() {
        // a -> b, a -> c, b -> d, c -> d
        let steps = vec![
            make_step("a", vec!["b", "c"]),
            make_step("b", vec!["d"]),
            make_step("c", vec!["d"]),
            make_step("d", vec![]),
        ];
        let waves = DependencyResolver::resolve(&steps);
        assert_eq!(waves.len(), 3);
        assert_eq!(waves[0], vec!["a"]);
        // b and c should be in the same wave (parallel)
        let mut wave1 = waves[1].clone();
        wave1.sort();
        assert_eq!(wave1, vec!["b", "c"]);
        assert_eq!(waves[2], vec!["d"]);
    }

    #[test]
    fn test_resolve_independent_steps() {
        // No dependencies: all in first wave
        let steps = vec![
            make_step("a", vec![]),
            make_step("b", vec![]),
            make_step("c", vec![]),
        ];
        let waves = DependencyResolver::resolve(&steps);
        assert_eq!(waves.len(), 1);
        let mut wave0 = waves[0].clone();
        wave0.sort();
        assert_eq!(wave0, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_resolve_diamond() {
        //   a
        //  / \
        // b   c
        //  \ /
        //   d
        let steps = vec![
            make_step("a", vec!["b", "c"]),
            make_step("b", vec!["d"]),
            make_step("c", vec!["d"]),
            make_step("d", vec![]),
        ];
        let waves = DependencyResolver::resolve(&steps);
        assert_eq!(waves.len(), 3);
        assert_eq!(waves[0], vec!["a"]);
        assert_eq!(waves[2], vec!["d"]);
    }

    #[test]
    fn test_resolve_ignores_unknown_successors() {
        // a references "unknown" which doesn't exist in steps
        let steps = vec![make_step("a", vec!["unknown", "b"]), make_step("b", vec![])];
        let waves = DependencyResolver::resolve(&steps);
        assert_eq!(waves.len(), 2);
        assert_eq!(waves[0], vec!["a"]);
        assert_eq!(waves[1], vec!["b"]);
    }

    // ========================================================================
    // DependencyResolver::validate tests
    // ========================================================================

    #[test]
    fn test_validate_empty() {
        assert!(DependencyResolver::validate(&[]).is_ok());
    }

    #[test]
    fn test_validate_linear_chain() {
        let steps = vec![
            make_step("a", vec!["b"]),
            make_step("b", vec!["c"]),
            make_step("c", vec![]),
        ];
        assert!(DependencyResolver::validate(&steps).is_ok());
    }

    #[test]
    fn test_validate_circular_dependency() {
        // a -> b -> c -> a (cycle)
        let steps = vec![
            make_step("a", vec!["b"]),
            make_step("b", vec!["c"]),
            make_step("c", vec!["a"]),
        ];
        let result = DependencyResolver::validate(&steps);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("Circular dependency"));
    }

    #[test]
    fn test_validate_self_cycle() {
        // a -> a (self-cycle)
        let steps = vec![make_step("a", vec!["a"])];
        let result = DependencyResolver::validate(&steps);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_parallel_branches_ok() {
        let steps = vec![
            make_step("a", vec!["b", "c"]),
            make_step("b", vec!["d"]),
            make_step("c", vec!["d"]),
            make_step("d", vec![]),
        ];
        assert!(DependencyResolver::validate(&steps).is_ok());
    }

    // ========================================================================
    // StepResult and status tests
    // ========================================================================

    #[test]
    fn test_step_result_serialization() {
        let result = StepResult {
            step_id: "step-1".to_string(),
            status: StepStatus::Completed,
            output: Some(serde_json::json!({"blocked": true})),
            error: None,
            started_at: Utc::now(),
            completed_at: Utc::now(),
            retries: 0,
        };

        let json = serde_json::to_string(&result).unwrap();
        let deserialized: StepResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.step_id, "step-1");
        assert_eq!(deserialized.status, StepStatus::Completed);
        assert_eq!(deserialized.retries, 0);
    }

    #[test]
    fn test_step_status_variants() {
        let statuses = vec![
            StepStatus::Pending,
            StepStatus::Running,
            StepStatus::Completed,
            StepStatus::Failed,
            StepStatus::Skipped,
            StepStatus::TimedOut,
        ];
        for status in statuses {
            let json = serde_json::to_string(&status).unwrap();
            let deserialized: StepStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, status);
        }
    }

    #[test]
    fn test_execution_status_variants() {
        let statuses = vec![
            ExecutionStatus::Running,
            ExecutionStatus::Completed,
            ExecutionStatus::Failed,
            ExecutionStatus::Cancelled,
            ExecutionStatus::TimedOut,
        ];
        for status in statuses {
            let json = serde_json::to_string(&status).unwrap();
            let deserialized: ExecutionStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, status);
        }
    }

    #[test]
    fn test_playbook_execution_result_serialization() {
        let result = PlaybookExecutionResult {
            playbook_id: Uuid::new_v4(),
            execution_id: Uuid::new_v4(),
            status: ExecutionStatus::Completed,
            step_results: vec![StepResult {
                step_id: "s1".to_string(),
                status: StepStatus::Completed,
                output: None,
                error: None,
                started_at: Utc::now(),
                completed_at: Utc::now(),
                retries: 0,
            }],
            context: HashMap::new(),
            started_at: Utc::now(),
            completed_at: Utc::now(),
        };

        let json = serde_json::to_string(&result).unwrap();
        let deserialized: PlaybookExecutionResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.status, ExecutionStatus::Completed);
        assert_eq!(deserialized.step_results.len(), 1);
    }
}
