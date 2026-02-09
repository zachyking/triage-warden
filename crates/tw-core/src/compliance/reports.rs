//! Compliance report model and builders.

use crate::compliance::evidence::EvidenceItem;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Time range for compliance reporting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DateRange {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

/// Target compliance framework.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceFramework {
    Soc2TypeI,
    Soc2TypeII,
    Iso27001,
    Nist80053,
    Hipaa,
    Pci,
    Custom(String),
}

/// Status of a compliance control.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlStatus {
    Compliant,
    Partial,
    NonCompliant,
    NotApplicable,
}

/// Control-level assessment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlAssessment {
    pub control_id: String,
    pub description: String,
    pub status: ControlStatus,
    pub evidence_refs: Vec<Uuid>,
    pub notes: Option<String>,
}

/// Summary metrics for a compliance report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceSummary {
    pub total_controls: usize,
    pub compliant_controls: usize,
    pub partial_controls: usize,
    pub non_compliant_controls: usize,
    pub generated_at: DateTime<Utc>,
}

/// Compliance report structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub id: Uuid,
    pub framework: ComplianceFramework,
    pub period: DateRange,
    pub controls: Vec<ControlAssessment>,
    pub evidence: Vec<EvidenceItem>,
    pub summary: ComplianceSummary,
    pub checksum: String,
}

impl ComplianceReport {
    /// Builds a report and computes checksum/summary.
    pub fn new(
        framework: ComplianceFramework,
        period: DateRange,
        controls: Vec<ControlAssessment>,
        evidence: Vec<EvidenceItem>,
    ) -> Self {
        let compliant_controls = controls
            .iter()
            .filter(|c| c.status == ControlStatus::Compliant)
            .count();
        let partial_controls = controls
            .iter()
            .filter(|c| c.status == ControlStatus::Partial)
            .count();
        let non_compliant_controls = controls
            .iter()
            .filter(|c| c.status == ControlStatus::NonCompliant)
            .count();
        let summary = ComplianceSummary {
            total_controls: controls.len(),
            compliant_controls,
            partial_controls,
            non_compliant_controls,
            generated_at: Utc::now(),
        };

        let mut report = Self {
            id: Uuid::new_v4(),
            framework,
            period,
            controls,
            evidence,
            summary,
            checksum: String::new(),
        };
        report.checksum = report.compute_checksum();
        report
    }

    /// Computes report checksum.
    pub fn compute_checksum(&self) -> String {
        let payload = serde_json::json!({
            "id": self.id,
            "framework": self.framework,
            "period": self.period,
            "controls": self.controls,
            "evidence": self.evidence,
            "summary": self.summary,
        });
        let mut hasher = Sha256::new();
        hasher.update(serde_json::to_vec(&payload).unwrap_or_default());
        hex::encode(hasher.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compliance::evidence::EvidenceItem;

    #[test]
    fn test_report_checksum_is_stable() {
        let controls = vec![ControlAssessment {
            control_id: "CC6.1".to_string(),
            description: "Access control".to_string(),
            status: ControlStatus::Compliant,
            evidence_refs: Vec::new(),
            notes: None,
        }];
        let report = ComplianceReport::new(
            ComplianceFramework::Soc2TypeII,
            DateRange {
                start: Utc::now(),
                end: Utc::now(),
            },
            controls,
            vec![EvidenceItem::new(
                "sample evidence",
                None,
                vec!["soc2".to_string()],
            )],
        );
        assert!(!report.checksum.is_empty());
        assert_eq!(report.checksum, report.compute_checksum());
    }
}
