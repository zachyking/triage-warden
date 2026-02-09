//! Framework-specific control templates.

pub mod iso27001;
pub mod soc2;

use crate::compliance::reports::ComplianceFramework;

/// Baseline control template.
#[derive(Debug, Clone)]
pub struct ControlTemplate {
    pub id: &'static str,
    pub description: &'static str,
}

/// Returns default control templates for a framework.
pub fn default_controls_for_framework(framework: &ComplianceFramework) -> Vec<ControlTemplate> {
    match framework {
        ComplianceFramework::Soc2TypeI | ComplianceFramework::Soc2TypeII => soc2::controls(),
        ComplianceFramework::Iso27001 => iso27001::controls(),
        ComplianceFramework::Nist80053 => soc2::controls(),
        ComplianceFramework::Hipaa => soc2::controls(),
        ComplianceFramework::Pci => iso27001::controls(),
        ComplianceFramework::Custom(_) => Vec::new(),
    }
}
