//! Playbook data structures for Triage Warden.
//!
//! Playbooks define automated workflows for incident triage and response.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
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
}
