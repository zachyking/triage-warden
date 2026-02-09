//! Automation anomaly detection for guardrail auto-pause logic.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Baseline automation behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutomationBaseline {
    pub avg_actions_per_hour: f64,
    pub common_actions: HashSet<String>,
    pub avg_unique_targets: f64,
}

/// Detection thresholds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyThresholds {
    pub volume_multiplier: f64,
    pub target_multiplier: f64,
}

impl Default for AnomalyThresholds {
    fn default() -> Self {
        Self {
            volume_multiplier: 3.0,
            target_multiplier: 2.0,
        }
    }
}

/// Observed automation activity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutomationActivity {
    pub actions_per_hour: f64,
    pub action_type: String,
    pub unique_targets: f64,
}

/// Detected anomaly type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Anomaly {
    UnusualVolume,
    UnusualAction,
    UnusualTargetCount,
}

/// Detector implementation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutomationAnomalyDetector {
    pub baseline: AutomationBaseline,
    pub thresholds: AnomalyThresholds,
}

impl AutomationAnomalyDetector {
    /// Checks for anomaly against baseline and thresholds.
    pub fn check(&self, activity: &AutomationActivity) -> Option<Anomaly> {
        if activity.actions_per_hour
            > self.baseline.avg_actions_per_hour * self.thresholds.volume_multiplier
        {
            return Some(Anomaly::UnusualVolume);
        }

        if !self.baseline.common_actions.contains(&activity.action_type) {
            return Some(Anomaly::UnusualAction);
        }

        if activity.unique_targets
            > self.baseline.avg_unique_targets * self.thresholds.target_multiplier
        {
            return Some(Anomaly::UnusualTargetCount);
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anomaly_detector_detects_unusual_volume() {
        let detector = AutomationAnomalyDetector {
            baseline: AutomationBaseline {
                avg_actions_per_hour: 10.0,
                common_actions: HashSet::from(["isolate_host".to_string()]),
                avg_unique_targets: 3.0,
            },
            thresholds: AnomalyThresholds::default(),
        };
        let activity = AutomationActivity {
            actions_per_hour: 40.0,
            action_type: "isolate_host".to_string(),
            unique_targets: 2.0,
        };
        assert_eq!(detector.check(&activity), Some(Anomaly::UnusualVolume));
    }
}
