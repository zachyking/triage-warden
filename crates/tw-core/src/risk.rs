//! Risk scoring for incidents.
//!
//! This module provides composite risk scoring that incorporates base incident
//! severity, asset criticality, vulnerability risk, external exposure risk,
//! and historical risk factors into a single weighted score.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Configurable weights for each risk dimension.
///
/// Weights should sum to 1.0 for a normalized composite score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskWeights {
    /// Weight for the base incident severity (default: 0.40).
    pub base_severity: f32,
    /// Weight for the criticality of affected assets (default: 0.25).
    pub asset_criticality: f32,
    /// Weight for known vulnerability exposure (default: 0.15).
    pub vulnerability_risk: f32,
    /// Weight for external attack surface exposure (default: 0.10).
    pub exposure_risk: f32,
    /// Weight for historical incident patterns (default: 0.10).
    pub historical_risk: f32,
}

impl Default for RiskWeights {
    fn default() -> Self {
        Self {
            base_severity: 0.40,
            asset_criticality: 0.25,
            vulnerability_risk: 0.15,
            exposure_risk: 0.10,
            historical_risk: 0.10,
        }
    }
}

impl RiskWeights {
    /// Returns the sum of all weights.
    pub fn total(&self) -> f32 {
        self.base_severity
            + self.asset_criticality
            + self.vulnerability_risk
            + self.exposure_risk
            + self.historical_risk
    }

    /// Validates that weights are non-negative and sum to approximately 1.0.
    pub fn validate(&self) -> Result<(), String> {
        if self.base_severity < 0.0
            || self.asset_criticality < 0.0
            || self.vulnerability_risk < 0.0
            || self.exposure_risk < 0.0
            || self.historical_risk < 0.0
        {
            return Err("All weights must be non-negative".to_string());
        }
        let total = self.total();
        if (total - 1.0).abs() > 0.01 {
            return Err(format!(
                "Weights must sum to approximately 1.0, got {}",
                total
            ));
        }
        Ok(())
    }
}

/// A computed risk score for an incident.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentRiskScore {
    /// The incident this score applies to.
    pub incident_id: Uuid,
    /// Component score from base incident severity (0.0 - 100.0).
    pub base_severity: f32,
    /// Component score from asset criticality (0.0 - 100.0).
    pub asset_criticality: f32,
    /// Component score from known vulnerabilities (0.0 - 100.0).
    pub vulnerability_risk: f32,
    /// Component score from external exposure (0.0 - 100.0).
    pub exposure_risk: f32,
    /// Component score from historical patterns (0.0 - 100.0).
    pub historical_risk: f32,
    /// Weighted composite score (0.0 - 100.0).
    pub composite_score: f32,
    /// Individual factors that contributed to the score.
    pub factors: Vec<RiskFactor>,
    /// When this score was calculated.
    pub calculated_at: DateTime<Utc>,
}

impl IncidentRiskScore {
    /// Calculates a risk score from the given inputs and weights.
    pub fn calculate(input: RiskScoreInput, weights: &RiskWeights) -> Self {
        let composite_score = input.base_severity * weights.base_severity
            + input.asset_criticality * weights.asset_criticality
            + input.vulnerability_risk * weights.vulnerability_risk
            + input.exposure_risk * weights.exposure_risk
            + input.historical_risk * weights.historical_risk;

        // Clamp to [0, 100]
        let composite_score = composite_score.clamp(0.0, 100.0);

        Self {
            incident_id: input.incident_id,
            base_severity: input.base_severity,
            asset_criticality: input.asset_criticality,
            vulnerability_risk: input.vulnerability_risk,
            exposure_risk: input.exposure_risk,
            historical_risk: input.historical_risk,
            composite_score,
            factors: input.factors,
            calculated_at: Utc::now(),
        }
    }
}

/// A single factor contributing to a risk score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    /// Name of the risk factor.
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// How much this factor impacts the score.
    pub score_impact: f32,
    /// Where this factor was sourced from.
    pub source: String,
}

/// Input data for computing a risk score.
pub struct RiskScoreInput {
    /// The incident being scored.
    pub incident_id: Uuid,
    /// Base severity score (0.0 - 100.0).
    pub base_severity: f32,
    /// Asset criticality score (0.0 - 100.0).
    pub asset_criticality: f32,
    /// Vulnerability risk score (0.0 - 100.0).
    pub vulnerability_risk: f32,
    /// External exposure risk score (0.0 - 100.0).
    pub exposure_risk: f32,
    /// Historical risk score (0.0 - 100.0).
    pub historical_risk: f32,
    /// Detailed risk factors.
    pub factors: Vec<RiskFactor>,
}

/// Summary of vulnerability-related risk for an asset or incident.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityRisk {
    /// Number of critical vulnerabilities.
    pub critical_count: usize,
    /// Number of high vulnerabilities.
    pub high_count: usize,
    /// Notable CVEs affecting the asset.
    pub notable_cves: Vec<String>,
    /// Number of vulnerabilities with known exploits.
    pub exploitable_count: usize,
    /// Computed risk score for this vulnerability context (0.0 - 100.0).
    pub risk_score: f32,
}

impl VulnerabilityRisk {
    /// Computes a risk score from the vulnerability counts.
    ///
    /// Scoring heuristic:
    /// - Each critical vuln adds 20 points (capped at 60)
    /// - Each high vuln adds 8 points (capped at 24)
    /// - Each exploitable vuln adds 5 bonus points (capped at 16)
    pub fn compute_score(&self) -> f32 {
        let critical_score = (self.critical_count as f32 * 20.0).min(60.0);
        let high_score = (self.high_count as f32 * 8.0).min(24.0);
        let exploit_bonus = (self.exploitable_count as f32 * 5.0).min(16.0);
        (critical_score + high_score + exploit_bonus).min(100.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_weights_sum_to_one() {
        let weights = RiskWeights::default();
        let total = weights.total();
        assert!(
            (total - 1.0).abs() < 0.001,
            "Default weights should sum to 1.0, got {}",
            total
        );
    }

    #[test]
    fn test_weight_validation_valid() {
        let weights = RiskWeights::default();
        assert!(weights.validate().is_ok());
    }

    #[test]
    fn test_weight_validation_negative() {
        let weights = RiskWeights {
            base_severity: -0.1,
            ..RiskWeights::default()
        };
        assert!(weights.validate().is_err());
        assert!(weights.validate().unwrap_err().contains("non-negative"));
    }

    #[test]
    fn test_weight_validation_wrong_sum() {
        let weights = RiskWeights {
            base_severity: 0.5,
            asset_criticality: 0.5,
            vulnerability_risk: 0.5,
            exposure_risk: 0.0,
            historical_risk: 0.0,
        };
        assert!(weights.validate().is_err());
        assert!(weights.validate().unwrap_err().contains("sum to"));
    }

    #[test]
    fn test_risk_score_calculation() {
        let weights = RiskWeights::default();
        let input = RiskScoreInput {
            incident_id: Uuid::new_v4(),
            base_severity: 80.0,
            asset_criticality: 90.0,
            vulnerability_risk: 60.0,
            exposure_risk: 40.0,
            historical_risk: 30.0,
            factors: vec![],
        };

        let score = IncidentRiskScore::calculate(input, &weights);

        // Expected: 80*0.40 + 90*0.25 + 60*0.15 + 40*0.10 + 30*0.10
        // = 32.0 + 22.5 + 9.0 + 4.0 + 3.0 = 70.5
        assert!(
            (score.composite_score - 70.5).abs() < 0.01,
            "Expected 70.5, got {}",
            score.composite_score
        );
        assert_eq!(score.base_severity, 80.0);
        assert_eq!(score.asset_criticality, 90.0);
    }

    #[test]
    fn test_risk_score_all_zeros() {
        let weights = RiskWeights::default();
        let input = RiskScoreInput {
            incident_id: Uuid::new_v4(),
            base_severity: 0.0,
            asset_criticality: 0.0,
            vulnerability_risk: 0.0,
            exposure_risk: 0.0,
            historical_risk: 0.0,
            factors: vec![],
        };

        let score = IncidentRiskScore::calculate(input, &weights);
        assert_eq!(score.composite_score, 0.0);
    }

    #[test]
    fn test_risk_score_all_max() {
        let weights = RiskWeights::default();
        let input = RiskScoreInput {
            incident_id: Uuid::new_v4(),
            base_severity: 100.0,
            asset_criticality: 100.0,
            vulnerability_risk: 100.0,
            exposure_risk: 100.0,
            historical_risk: 100.0,
            factors: vec![],
        };

        let score = IncidentRiskScore::calculate(input, &weights);
        assert_eq!(score.composite_score, 100.0);
    }

    #[test]
    fn test_risk_score_clamped() {
        let weights = RiskWeights {
            base_severity: 1.0,
            asset_criticality: 1.0,
            vulnerability_risk: 0.0,
            exposure_risk: 0.0,
            historical_risk: 0.0,
        };
        let input = RiskScoreInput {
            incident_id: Uuid::new_v4(),
            base_severity: 100.0,
            asset_criticality: 100.0,
            vulnerability_risk: 0.0,
            exposure_risk: 0.0,
            historical_risk: 0.0,
            factors: vec![],
        };

        let score = IncidentRiskScore::calculate(input, &weights);
        assert_eq!(score.composite_score, 100.0);
    }

    #[test]
    fn test_risk_score_with_factors() {
        let weights = RiskWeights::default();
        let factors = vec![
            RiskFactor {
                name: "CVE-2024-1234".to_string(),
                description: "Critical RCE in libfoo".to_string(),
                score_impact: 20.0,
                source: "qualys".to_string(),
            },
            RiskFactor {
                name: "Exposed SSH".to_string(),
                description: "SSH port open to internet".to_string(),
                score_impact: 10.0,
                source: "censys".to_string(),
            },
        ];

        let input = RiskScoreInput {
            incident_id: Uuid::new_v4(),
            base_severity: 70.0,
            asset_criticality: 80.0,
            vulnerability_risk: 50.0,
            exposure_risk: 30.0,
            historical_risk: 20.0,
            factors,
        };

        let score = IncidentRiskScore::calculate(input, &weights);
        assert_eq!(score.factors.len(), 2);
        assert_eq!(score.factors[0].name, "CVE-2024-1234");
        assert_eq!(score.factors[1].source, "censys");
    }

    #[test]
    fn test_risk_score_serialization() {
        let weights = RiskWeights::default();
        let input = RiskScoreInput {
            incident_id: Uuid::new_v4(),
            base_severity: 50.0,
            asset_criticality: 60.0,
            vulnerability_risk: 40.0,
            exposure_risk: 30.0,
            historical_risk: 20.0,
            factors: vec![RiskFactor {
                name: "test".to_string(),
                description: "test factor".to_string(),
                score_impact: 5.0,
                source: "mock".to_string(),
            }],
        };

        let score = IncidentRiskScore::calculate(input, &weights);
        let json = serde_json::to_string(&score).unwrap();
        let deserialized: IncidentRiskScore = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.composite_score, score.composite_score);
        assert_eq!(deserialized.factors.len(), 1);
    }

    #[test]
    fn test_vulnerability_risk_compute_score() {
        let vuln_risk = VulnerabilityRisk {
            critical_count: 2,
            high_count: 3,
            notable_cves: vec!["CVE-2024-1234".to_string()],
            exploitable_count: 1,
            risk_score: 0.0, // Not used by compute_score
        };

        let score = vuln_risk.compute_score();
        // 2*20 = 40, 3*8 = 24, 1*5 = 5 => 69
        assert_eq!(score, 69.0);
    }

    #[test]
    fn test_vulnerability_risk_capped_scores() {
        let vuln_risk = VulnerabilityRisk {
            critical_count: 10,
            high_count: 10,
            notable_cves: vec![],
            exploitable_count: 10,
            risk_score: 0.0,
        };

        let score = vuln_risk.compute_score();
        // 10*20 = 200 -> capped 60, 10*8 = 80 -> capped 24, 10*5 = 50 -> capped 16
        // 60 + 24 + 16 = 100
        assert_eq!(score, 100.0);
    }

    #[test]
    fn test_vulnerability_risk_zero() {
        let vuln_risk = VulnerabilityRisk {
            critical_count: 0,
            high_count: 0,
            notable_cves: vec![],
            exploitable_count: 0,
            risk_score: 0.0,
        };

        assert_eq!(vuln_risk.compute_score(), 0.0);
    }

    #[test]
    fn test_vulnerability_risk_serialization() {
        let vuln_risk = VulnerabilityRisk {
            critical_count: 1,
            high_count: 2,
            notable_cves: vec!["CVE-2024-1234".to_string()],
            exploitable_count: 1,
            risk_score: 45.0,
        };

        let json = serde_json::to_string(&vuln_risk).unwrap();
        let deserialized: VulnerabilityRisk = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.critical_count, 1);
        assert_eq!(deserialized.notable_cves.len(), 1);
        assert_eq!(deserialized.risk_score, 45.0);
    }

    #[test]
    fn test_risk_weights_serialization() {
        let weights = RiskWeights::default();
        let json = serde_json::to_string(&weights).unwrap();
        let deserialized: RiskWeights = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.base_severity, 0.40);
        assert_eq!(deserialized.asset_criticality, 0.25);
        assert_eq!(deserialized.vulnerability_risk, 0.15);
        assert_eq!(deserialized.exposure_risk, 0.10);
        assert_eq!(deserialized.historical_risk, 0.10);
    }

    #[test]
    fn test_risk_factor_creation() {
        let factor = RiskFactor {
            name: "High-value target".to_string(),
            description: "Asset is a production database server".to_string(),
            score_impact: 15.0,
            source: "asset_store".to_string(),
        };
        assert_eq!(factor.name, "High-value target");
        assert_eq!(factor.score_impact, 15.0);
    }
}
