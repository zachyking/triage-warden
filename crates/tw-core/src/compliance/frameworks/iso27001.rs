//! ISO 27001 control templates.

use super::ControlTemplate;

/// ISO 27001 baseline controls.
pub fn controls() -> Vec<ControlTemplate> {
    vec![
        ControlTemplate {
            id: "A.5.1",
            description: "Information security policies",
        },
        ControlTemplate {
            id: "A.8.2",
            description: "Information classification and handling",
        },
        ControlTemplate {
            id: "A.9.1",
            description: "Access control management",
        },
        ControlTemplate {
            id: "A.12.4",
            description: "Logging and monitoring events",
        },
    ]
}
