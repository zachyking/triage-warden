//! Playbook data structures for Triage Warden.
//!
//! Playbooks define automated workflows for incident triage and response.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// A playbook defines an automated workflow for incident triage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Playbook {
    /// Unique identifier for the playbook.
    pub id: Uuid,
    /// Human-readable name of the playbook.
    pub name: String,
    /// Optional description of what the playbook does.
    pub description: Option<String>,
    /// Type of trigger that activates this playbook (e.g., "alert", "scheduled").
    pub trigger_type: String,
    /// Optional condition expression for triggering.
    pub trigger_condition: Option<String>,
    /// Ordered list of stages in the playbook workflow.
    pub stages: Vec<PlaybookStage>,
    /// Whether the playbook is currently enabled.
    pub enabled: bool,
    /// Number of times this playbook has been executed.
    pub execution_count: u32,
    /// When the playbook was created.
    pub created_at: DateTime<Utc>,
    /// When the playbook was last updated.
    pub updated_at: DateTime<Utc>,
}

impl Playbook {
    /// Creates a new playbook with the given name and trigger type.
    pub fn new(name: impl Into<String>, trigger_type: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            description: None,
            trigger_type: trigger_type.into(),
            trigger_condition: None,
            stages: Vec::new(),
            enabled: true,
            execution_count: 0,
            created_at: now,
            updated_at: now,
        }
    }

    /// Sets the description.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Sets the trigger condition.
    pub fn with_trigger_condition(mut self, condition: impl Into<String>) -> Self {
        self.trigger_condition = Some(condition.into());
        self
    }

    /// Adds a stage to the playbook.
    pub fn with_stage(mut self, stage: PlaybookStage) -> Self {
        self.stages.push(stage);
        self
    }

    /// Sets the stages.
    pub fn with_stages(mut self, stages: Vec<PlaybookStage>) -> Self {
        self.stages = stages;
        self
    }

    /// Sets the enabled status.
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }
}

/// A stage in a playbook workflow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookStage {
    /// Name of the stage.
    pub name: String,
    /// Optional description of what this stage does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Whether steps in this stage can run in parallel.
    #[serde(default)]
    pub parallel: bool,
    /// Steps to execute in this stage.
    pub steps: Vec<PlaybookStep>,
}

impl PlaybookStage {
    /// Creates a new stage with the given name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: None,
            parallel: false,
            steps: Vec::new(),
        }
    }

    /// Sets the description.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Sets whether steps can run in parallel.
    pub fn with_parallel(mut self, parallel: bool) -> Self {
        self.parallel = parallel;
        self
    }

    /// Adds a step to the stage.
    pub fn with_step(mut self, step: PlaybookStep) -> Self {
        self.steps.push(step);
        self
    }

    /// Sets the steps.
    pub fn with_steps(mut self, steps: Vec<PlaybookStep>) -> Self {
        self.steps = steps;
        self
    }
}

/// A step within a playbook stage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookStep {
    /// The action to execute.
    pub action: String,
    /// Optional parameters for the action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameters: Option<serde_json::Value>,
    /// Optional input mapping.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<serde_json::Value>,
    /// Optional output variable names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<Vec<String>>,
    /// Whether this step requires approval.
    #[serde(default)]
    pub requires_approval: bool,
    /// Optional conditions for executing this step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<serde_json::Value>,
}

impl PlaybookStep {
    /// Creates a new step with the given action.
    pub fn new(action: impl Into<String>) -> Self {
        Self {
            action: action.into(),
            parameters: None,
            input: None,
            output: None,
            requires_approval: false,
            conditions: None,
        }
    }

    /// Sets the parameters.
    pub fn with_parameters(mut self, parameters: serde_json::Value) -> Self {
        self.parameters = Some(parameters);
        self
    }

    /// Sets the input mapping.
    pub fn with_input(mut self, input: serde_json::Value) -> Self {
        self.input = Some(input);
        self
    }

    /// Sets the output variable names.
    pub fn with_output(mut self, output: Vec<String>) -> Self {
        self.output = Some(output);
        self
    }

    /// Sets whether approval is required.
    pub fn with_requires_approval(mut self, requires_approval: bool) -> Self {
        self.requires_approval = requires_approval;
        self
    }

    /// Sets the conditions.
    pub fn with_conditions(mut self, conditions: serde_json::Value) -> Self {
        self.conditions = Some(conditions);
        self
    }
}

// ============================================================================
// Enhanced Playbook Types
// ============================================================================

/// Enhanced step type for advanced playbook execution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum StepType {
    /// Standard action execution.
    Action(ActionStepConfig),
    /// Decision point with conditional branches.
    Decision(DecisionConfig),
    /// Execute multiple steps in parallel.
    Parallel(ParallelConfig),
    /// Loop over a collection or until condition.
    Loop(LoopConfig),
    /// Wait for a condition or timeout.
    Wait(WaitConfig),
    /// Execute another playbook.
    SubPlaybook { playbook_id: String },
    /// Let AI decide the next action.
    AiDecision(AiDecisionConfig),
}

/// Configuration for an action step.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ActionStepConfig {
    /// The action to execute.
    pub action: String,
    /// Optional parameters for the action.
    pub parameters: Option<serde_json::Value>,
}

/// Configuration for a decision step with conditional branches.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DecisionConfig {
    /// Conditional branches to evaluate.
    pub branches: Vec<ConditionalBranch>,
    /// Default branch if no condition matches.
    pub default_branch: Option<String>,
}

/// A conditional branch in a decision step.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConditionalBranch {
    /// Name of this branch.
    pub name: String,
    /// Serialized condition to evaluate.
    pub condition: serde_json::Value,
    /// ID of the next step to execute if condition is true.
    pub next_step_id: String,
}

/// Configuration for parallel step execution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ParallelConfig {
    /// IDs of steps to execute in parallel.
    pub step_ids: Vec<String>,
    /// Policy for waiting on parallel steps.
    pub wait_policy: WaitPolicy,
}

/// Policy for waiting on parallel step completion.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum WaitPolicy {
    /// Wait for all steps to complete.
    All,
    /// Wait for any one step to complete.
    Any,
    /// Do not wait; fire and forget.
    None,
}

/// Configuration for a loop step.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LoopConfig {
    /// JSON path to a collection to iterate over.
    pub collection_path: Option<String>,
    /// Maximum number of iterations.
    pub max_iterations: u32,
    /// IDs of steps that form the loop body.
    pub body_step_ids: Vec<String>,
    /// Serialized condition to break the loop.
    pub break_condition: Option<serde_json::Value>,
}

/// Configuration for a wait step.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WaitConfig {
    /// Serialized condition to wait for.
    pub condition: Option<serde_json::Value>,
    /// Timeout in seconds.
    pub timeout_secs: u64,
    /// Polling interval in seconds.
    pub poll_interval_secs: u64,
}

/// Configuration for an AI-driven decision step.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AiDecisionConfig {
    /// Prompt template for the AI model.
    pub prompt_template: String,
    /// Available actions the AI can choose from.
    pub available_actions: Vec<String>,
    /// Optional maximum token limit for the AI response.
    pub max_tokens: Option<u32>,
}

/// Configuration for step retry behavior.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RetryConfig {
    /// Maximum number of retries.
    pub max_retries: u32,
    /// Backoff duration in seconds between retries.
    pub backoff_secs: u64,
    /// Error types that should trigger a retry.
    pub retry_on: Vec<String>,
}

/// Defines how to handle step failures.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FailureHandler {
    /// Stop playbook execution.
    Stop,
    /// Continue to the next step.
    Continue,
    /// Retry the step with the given configuration.
    Retry(RetryConfig),
    /// Execute a fallback step.
    Fallback { step_id: String },
    /// Escalate to a human operator.
    Escalate { reason: String },
}

/// Enhanced step with advanced execution control.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AdvancedPlaybookStep {
    /// Unique identifier for this step.
    pub id: String,
    /// Human-readable name of the step.
    pub name: String,
    /// Type-specific step configuration.
    pub step_type: StepType,
    /// Pre-conditions that must be met before execution.
    pub conditions: Option<Vec<serde_json::Value>>,
    /// Step IDs to execute on success.
    pub on_success: Vec<String>,
    /// How to handle failure.
    pub on_failure: FailureHandler,
    /// Timeout in seconds for this step.
    pub timeout_secs: Option<u64>,
    /// Retry configuration for this step.
    pub retry: Option<RetryConfig>,
    /// Arbitrary metadata.
    pub metadata: HashMap<String, serde_json::Value>,
}

/// A versioned snapshot of a playbook.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PlaybookVersion {
    /// ID of the playbook this version belongs to.
    pub playbook_id: Uuid,
    /// Version number.
    pub version: u32,
    /// Serialized playbook snapshot.
    pub snapshot: serde_json::Value,
    /// Description of what changed.
    pub change_description: String,
    /// Who made the change.
    pub changed_by: String,
    /// When the version was created.
    pub created_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_playbook_creation() {
        let playbook = Playbook::new("test-playbook", "alert")
            .with_description("A test playbook")
            .with_trigger_condition("severity == 'high'");

        assert_eq!(playbook.name, "test-playbook");
        assert_eq!(playbook.trigger_type, "alert");
        assert_eq!(playbook.description, Some("A test playbook".to_string()));
        assert_eq!(
            playbook.trigger_condition,
            Some("severity == 'high'".to_string())
        );
        assert!(playbook.enabled);
        assert_eq!(playbook.execution_count, 0);
    }

    #[test]
    fn test_playbook_stage() {
        let stage = PlaybookStage::new("extraction")
            .with_description("Extract indicators")
            .with_parallel(true)
            .with_step(PlaybookStep::new("parse_email"));

        assert_eq!(stage.name, "extraction");
        assert!(stage.parallel);
        assert_eq!(stage.steps.len(), 1);
    }

    #[test]
    fn test_playbook_step() {
        let step = PlaybookStep::new("lookup_urls")
            .with_requires_approval(true)
            .with_output(vec!["url_ti".to_string()]);

        assert_eq!(step.action, "lookup_urls");
        assert!(step.requires_approval);
        assert_eq!(step.output, Some(vec!["url_ti".to_string()]));
    }

    #[test]
    fn test_playbook_serialization() {
        let playbook = Playbook::new("test", "alert")
            .with_stage(PlaybookStage::new("stage1").with_step(PlaybookStep::new("action1")));

        let json = serde_json::to_string(&playbook).unwrap();
        let deserialized: Playbook = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.name, playbook.name);
        assert_eq!(deserialized.stages.len(), 1);
    }

    // Enhanced type tests

    #[test]
    fn test_step_type_action_serialization() {
        let step_type = StepType::Action(ActionStepConfig {
            action: "block_ip".to_string(),
            parameters: Some(serde_json::json!({"ip": "10.0.0.1"})),
        });

        let json = serde_json::to_string(&step_type).unwrap();
        let deserialized: StepType = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, step_type);
    }

    #[test]
    fn test_step_type_decision_serialization() {
        let step_type = StepType::Decision(DecisionConfig {
            branches: vec![ConditionalBranch {
                name: "high_severity".to_string(),
                condition: serde_json::json!({"field": "severity", "op": "Eq", "value": "high"}),
                next_step_id: "escalate".to_string(),
            }],
            default_branch: Some("log_and_close".to_string()),
        });

        let json = serde_json::to_string(&step_type).unwrap();
        let deserialized: StepType = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, step_type);
    }

    #[test]
    fn test_step_type_parallel_serialization() {
        let step_type = StepType::Parallel(ParallelConfig {
            step_ids: vec!["enrich_ip".to_string(), "enrich_domain".to_string()],
            wait_policy: WaitPolicy::All,
        });

        let json = serde_json::to_string(&step_type).unwrap();
        let deserialized: StepType = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, step_type);
    }

    #[test]
    fn test_step_type_loop_serialization() {
        let step_type = StepType::Loop(LoopConfig {
            collection_path: Some("$.indicators".to_string()),
            max_iterations: 100,
            body_step_ids: vec!["check_indicator".to_string()],
            break_condition: None,
        });

        let json = serde_json::to_string(&step_type).unwrap();
        let deserialized: StepType = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, step_type);
    }

    #[test]
    fn test_step_type_wait_serialization() {
        let step_type = StepType::Wait(WaitConfig {
            condition: Some(
                serde_json::json!({"field": "status", "op": "Eq", "value": "resolved"}),
            ),
            timeout_secs: 300,
            poll_interval_secs: 10,
        });

        let json = serde_json::to_string(&step_type).unwrap();
        let deserialized: StepType = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, step_type);
    }

    #[test]
    fn test_step_type_sub_playbook_serialization() {
        let step_type = StepType::SubPlaybook {
            playbook_id: "containment-playbook-v2".to_string(),
        };

        let json = serde_json::to_string(&step_type).unwrap();
        let deserialized: StepType = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, step_type);
    }

    #[test]
    fn test_step_type_ai_decision_serialization() {
        let step_type = StepType::AiDecision(AiDecisionConfig {
            prompt_template: "Given incident: {summary}, choose action".to_string(),
            available_actions: vec![
                "block".to_string(),
                "alert".to_string(),
                "ignore".to_string(),
            ],
            max_tokens: Some(500),
        });

        let json = serde_json::to_string(&step_type).unwrap();
        let deserialized: StepType = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, step_type);
    }

    #[test]
    fn test_failure_handler_variants() {
        let handlers = vec![
            FailureHandler::Stop,
            FailureHandler::Continue,
            FailureHandler::Retry(RetryConfig {
                max_retries: 3,
                backoff_secs: 5,
                retry_on: vec!["timeout".to_string(), "connection_error".to_string()],
            }),
            FailureHandler::Fallback {
                step_id: "fallback_step".to_string(),
            },
            FailureHandler::Escalate {
                reason: "Critical failure".to_string(),
            },
        ];

        for handler in handlers {
            let json = serde_json::to_string(&handler).unwrap();
            let deserialized: FailureHandler = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, handler);
        }
    }

    #[test]
    fn test_advanced_playbook_step_serialization() {
        let mut metadata = HashMap::new();
        metadata.insert("author".to_string(), serde_json::json!("security-team"));

        let step = AdvancedPlaybookStep {
            id: "step-1".to_string(),
            name: "Block malicious IP".to_string(),
            step_type: StepType::Action(ActionStepConfig {
                action: "block_ip".to_string(),
                parameters: Some(serde_json::json!({"ip": "10.0.0.1"})),
            }),
            conditions: Some(vec![
                serde_json::json!({"field": "severity", "op": "Gte", "value": "high"}),
            ]),
            on_success: vec!["step-2".to_string()],
            on_failure: FailureHandler::Retry(RetryConfig {
                max_retries: 2,
                backoff_secs: 10,
                retry_on: vec!["timeout".to_string()],
            }),
            timeout_secs: Some(60),
            retry: None,
            metadata,
        };

        let json = serde_json::to_string(&step).unwrap();
        let deserialized: AdvancedPlaybookStep = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, step);
    }

    #[test]
    fn test_playbook_version_serialization() {
        let version = PlaybookVersion {
            playbook_id: Uuid::new_v4(),
            version: 3,
            snapshot: serde_json::json!({"name": "test-playbook", "stages": []}),
            change_description: "Added containment stage".to_string(),
            changed_by: "analyst@example.com".to_string(),
            created_at: Utc::now(),
        };

        let json = serde_json::to_string(&version).unwrap();
        let deserialized: PlaybookVersion = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.playbook_id, version.playbook_id);
        assert_eq!(deserialized.version, 3);
        assert_eq!(deserialized.change_description, "Added containment stage");
    }

    #[test]
    fn test_wait_policy_variants() {
        for policy in [WaitPolicy::All, WaitPolicy::Any, WaitPolicy::None] {
            let json = serde_json::to_string(&policy).unwrap();
            let deserialized: WaitPolicy = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, policy);
        }
    }
}
