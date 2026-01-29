//! Operation mode management for Triage Warden.
//!
//! This module implements switchable operation modes for different
//! automation levels, from fully manual to fully autonomous.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, instrument, warn};

/// Operation mode determining the level of automation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum OperationMode {
    /// AI observes and suggests only, no auto-execution.
    /// All actions require manual execution by analysts.
    Assisted,

    /// Auto-execute low-risk actions, require approval for high-risk.
    /// This is the default mode balancing automation with oversight.
    #[default]
    Supervised,

    /// Full automation for approved incident types.
    /// Actions execute automatically without human intervention.
    Autonomous,
}

impl std::fmt::Display for OperationMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OperationMode::Assisted => write!(f, "Assisted"),
            OperationMode::Supervised => write!(f, "Supervised"),
            OperationMode::Autonomous => write!(f, "Autonomous"),
        }
    }
}

/// Risk level for actions.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum ActionRisk {
    /// Low-risk actions (e.g., gathering information, creating tickets).
    Low,
    /// Medium-risk actions (e.g., adding firewall rules, isolating endpoints).
    Medium,
    /// High-risk actions (e.g., blocking users, quarantining systems).
    High,
    /// Critical-risk actions (e.g., shutting down systems, wiping data).
    Critical,
}

impl std::fmt::Display for ActionRisk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ActionRisk::Low => write!(f, "Low"),
            ActionRisk::Medium => write!(f, "Medium"),
            ActionRisk::High => write!(f, "High"),
            ActionRisk::Critical => write!(f, "Critical"),
        }
    }
}

/// Record of a mode change for audit purposes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModeChange {
    /// Previous operation mode.
    pub previous: OperationMode,
    /// New operation mode.
    pub new: OperationMode,
    /// Who initiated the change.
    pub changed_by: String,
    /// When the change occurred.
    pub changed_at: DateTime<Utc>,
    /// Optional reason for the change.
    pub reason: Option<String>,
}

/// Manager for operation mode with history tracking.
#[derive(Debug, Clone)]
pub struct ModeManager {
    /// Current operation mode.
    current_mode: Arc<RwLock<OperationMode>>,
    /// History of mode changes.
    history: Arc<RwLock<Vec<ModeChange>>>,
}

impl Default for ModeManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ModeManager {
    /// Creates a new ModeManager starting in Supervised mode.
    #[must_use]
    pub fn new() -> Self {
        info!(mode = %OperationMode::Supervised, "Initializing ModeManager in default Supervised mode");
        Self {
            current_mode: Arc::new(RwLock::new(OperationMode::Supervised)),
            history: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Creates a new ModeManager with a specific initial mode.
    #[must_use]
    pub fn new_with_mode(mode: OperationMode) -> Self {
        info!(mode = %mode, "Initializing ModeManager with specified mode");
        Self {
            current_mode: Arc::new(RwLock::new(mode)),
            history: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Gets the current operation mode.
    #[instrument(skip(self))]
    pub async fn get_mode(&self) -> OperationMode {
        *self.current_mode.read().await
    }

    /// Sets a new operation mode and records the change.
    ///
    /// Returns the ModeChange record for the transition.
    #[instrument(skip(self), fields(changed_by = %changed_by))]
    pub async fn set_mode(
        &self,
        mode: OperationMode,
        changed_by: &str,
        reason: Option<&str>,
    ) -> ModeChange {
        let mut current = self.current_mode.write().await;
        let previous = *current;

        let change = ModeChange {
            previous,
            new: mode,
            changed_by: changed_by.to_string(),
            changed_at: Utc::now(),
            reason: reason.map(String::from),
        };

        if previous != mode {
            info!(
                previous = %previous,
                new = %mode,
                changed_by = %changed_by,
                reason = ?reason,
                "Operation mode changed"
            );
            *current = mode;
            self.history.write().await.push(change.clone());
        } else {
            warn!(
                mode = %mode,
                changed_by = %changed_by,
                "Attempted to set mode to current mode (no change)"
            );
        }

        change
    }

    /// Gets the history of mode changes.
    #[instrument(skip(self))]
    pub async fn get_history(&self) -> Vec<ModeChange> {
        self.history.read().await.clone()
    }

    /// Checks if an action with the given risk level is allowed in the current mode.
    ///
    /// Returns `true` if the action can be auto-executed, `false` if it requires
    /// approval or manual execution.
    #[instrument(skip(self), fields(action_risk = %action_risk))]
    pub async fn is_action_allowed(&self, action_risk: ActionRisk) -> bool {
        let mode = *self.current_mode.read().await;
        let allowed = match mode {
            // In Assisted mode, no auto-execution is allowed
            OperationMode::Assisted => false,
            // In Supervised mode, only Low and Medium risk are auto-allowed
            OperationMode::Supervised => matches!(action_risk, ActionRisk::Low | ActionRisk::Medium),
            // In Autonomous mode, all actions are allowed
            OperationMode::Autonomous => true,
        };

        info!(
            mode = %mode,
            action_risk = %action_risk,
            allowed = allowed,
            "Checked action allowance"
        );

        allowed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_default_mode_is_supervised() {
        let manager = ModeManager::new();
        assert_eq!(manager.get_mode().await, OperationMode::Supervised);
    }

    #[tokio::test]
    async fn test_new_with_mode() {
        let manager = ModeManager::new_with_mode(OperationMode::Assisted);
        assert_eq!(manager.get_mode().await, OperationMode::Assisted);

        let manager = ModeManager::new_with_mode(OperationMode::Autonomous);
        assert_eq!(manager.get_mode().await, OperationMode::Autonomous);
    }

    #[tokio::test]
    async fn test_set_mode_changes_mode() {
        let manager = ModeManager::new();
        assert_eq!(manager.get_mode().await, OperationMode::Supervised);

        let change = manager
            .set_mode(OperationMode::Autonomous, "test_user", Some("Testing"))
            .await;

        assert_eq!(change.previous, OperationMode::Supervised);
        assert_eq!(change.new, OperationMode::Autonomous);
        assert_eq!(change.changed_by, "test_user");
        assert_eq!(change.reason, Some("Testing".to_string()));
        assert_eq!(manager.get_mode().await, OperationMode::Autonomous);
    }

    #[tokio::test]
    async fn test_set_mode_same_mode_no_history() {
        let manager = ModeManager::new();

        // Set to same mode
        manager
            .set_mode(OperationMode::Supervised, "test_user", None)
            .await;

        // Should not add to history
        let history = manager.get_history().await;
        assert!(history.is_empty());
    }

    #[tokio::test]
    async fn test_mode_change_history() {
        let manager = ModeManager::new();

        manager
            .set_mode(OperationMode::Assisted, "user1", Some("Going manual"))
            .await;
        manager
            .set_mode(OperationMode::Autonomous, "user2", Some("Emergency response"))
            .await;
        manager
            .set_mode(OperationMode::Supervised, "user1", Some("Back to normal"))
            .await;

        let history = manager.get_history().await;
        assert_eq!(history.len(), 3);

        assert_eq!(history[0].previous, OperationMode::Supervised);
        assert_eq!(history[0].new, OperationMode::Assisted);
        assert_eq!(history[0].changed_by, "user1");

        assert_eq!(history[1].previous, OperationMode::Assisted);
        assert_eq!(history[1].new, OperationMode::Autonomous);
        assert_eq!(history[1].changed_by, "user2");

        assert_eq!(history[2].previous, OperationMode::Autonomous);
        assert_eq!(history[2].new, OperationMode::Supervised);
        assert_eq!(history[2].changed_by, "user1");
    }

    #[tokio::test]
    async fn test_assisted_mode_denies_all_actions() {
        let manager = ModeManager::new_with_mode(OperationMode::Assisted);

        assert!(!manager.is_action_allowed(ActionRisk::Low).await);
        assert!(!manager.is_action_allowed(ActionRisk::Medium).await);
        assert!(!manager.is_action_allowed(ActionRisk::High).await);
        assert!(!manager.is_action_allowed(ActionRisk::Critical).await);
    }

    #[tokio::test]
    async fn test_supervised_mode_allows_low_medium_only() {
        let manager = ModeManager::new_with_mode(OperationMode::Supervised);

        assert!(manager.is_action_allowed(ActionRisk::Low).await);
        assert!(manager.is_action_allowed(ActionRisk::Medium).await);
        assert!(!manager.is_action_allowed(ActionRisk::High).await);
        assert!(!manager.is_action_allowed(ActionRisk::Critical).await);
    }

    #[tokio::test]
    async fn test_autonomous_mode_allows_all_actions() {
        let manager = ModeManager::new_with_mode(OperationMode::Autonomous);

        assert!(manager.is_action_allowed(ActionRisk::Low).await);
        assert!(manager.is_action_allowed(ActionRisk::Medium).await);
        assert!(manager.is_action_allowed(ActionRisk::High).await);
        assert!(manager.is_action_allowed(ActionRisk::Critical).await);
    }

    #[tokio::test]
    async fn test_mode_change_affects_action_allowance() {
        let manager = ModeManager::new();

        // Start in Supervised mode
        assert!(manager.is_action_allowed(ActionRisk::Low).await);
        assert!(!manager.is_action_allowed(ActionRisk::High).await);

        // Switch to Autonomous
        manager
            .set_mode(OperationMode::Autonomous, "admin", None)
            .await;
        assert!(manager.is_action_allowed(ActionRisk::High).await);

        // Switch to Assisted
        manager
            .set_mode(OperationMode::Assisted, "admin", None)
            .await;
        assert!(!manager.is_action_allowed(ActionRisk::Low).await);
    }

    #[tokio::test]
    async fn test_operation_mode_display() {
        assert_eq!(format!("{}", OperationMode::Assisted), "Assisted");
        assert_eq!(format!("{}", OperationMode::Supervised), "Supervised");
        assert_eq!(format!("{}", OperationMode::Autonomous), "Autonomous");
    }

    #[tokio::test]
    async fn test_action_risk_display() {
        assert_eq!(format!("{}", ActionRisk::Low), "Low");
        assert_eq!(format!("{}", ActionRisk::Medium), "Medium");
        assert_eq!(format!("{}", ActionRisk::High), "High");
        assert_eq!(format!("{}", ActionRisk::Critical), "Critical");
    }

    #[tokio::test]
    async fn test_action_risk_ordering() {
        assert!(ActionRisk::Low < ActionRisk::Medium);
        assert!(ActionRisk::Medium < ActionRisk::High);
        assert!(ActionRisk::High < ActionRisk::Critical);
    }

    #[tokio::test]
    async fn test_operation_mode_serialization() {
        let mode = OperationMode::Supervised;
        let serialized = serde_json::to_string(&mode).unwrap();
        assert_eq!(serialized, "\"supervised\"");

        let deserialized: OperationMode = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, mode);
    }

    #[tokio::test]
    async fn test_action_risk_serialization() {
        let risk = ActionRisk::High;
        let serialized = serde_json::to_string(&risk).unwrap();
        assert_eq!(serialized, "\"high\"");

        let deserialized: ActionRisk = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, risk);
    }

    #[tokio::test]
    async fn test_mode_change_serialization() {
        let change = ModeChange {
            previous: OperationMode::Assisted,
            new: OperationMode::Supervised,
            changed_by: "admin".to_string(),
            changed_at: Utc::now(),
            reason: Some("Transitioning to automated mode".to_string()),
        };

        let serialized = serde_json::to_string(&change).unwrap();
        let deserialized: ModeChange = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.previous, change.previous);
        assert_eq!(deserialized.new, change.new);
        assert_eq!(deserialized.changed_by, change.changed_by);
        assert_eq!(deserialized.reason, change.reason);
    }

    #[tokio::test]
    async fn test_manager_is_clone() {
        let manager = ModeManager::new();
        let cloned = manager.clone();

        // Changes to one should reflect in the other (shared Arc)
        manager
            .set_mode(OperationMode::Autonomous, "admin", None)
            .await;
        assert_eq!(cloned.get_mode().await, OperationMode::Autonomous);
    }

    #[tokio::test]
    async fn test_operation_mode_default() {
        let mode: OperationMode = Default::default();
        assert_eq!(mode, OperationMode::Supervised);
    }
}
