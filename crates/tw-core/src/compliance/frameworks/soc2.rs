//! SOC2 control templates.

use super::ControlTemplate;

/// SOC2 baseline controls.
pub fn controls() -> Vec<ControlTemplate> {
    vec![
        ControlTemplate {
            id: "CC1.1",
            description: "Control environment and governance",
        },
        ControlTemplate {
            id: "CC6.1",
            description: "Logical and physical access controls",
        },
        ControlTemplate {
            id: "CC7.2",
            description: "Security event detection and monitoring",
        },
        ControlTemplate {
            id: "CC8.1",
            description: "Change management and deployment controls",
        },
    ]
}
