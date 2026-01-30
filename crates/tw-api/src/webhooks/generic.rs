//! Generic webhook alert normalization.

use chrono::Utc;
use tw_core::incident::{Alert, AlertSource, Severity};
use uuid::Uuid;

use crate::dto::WebhookAlertPayload;

/// Normalizes a webhook payload into an internal Alert.
pub fn normalize_alert(payload: &WebhookAlertPayload) -> Alert {
    let source = parse_source(&payload.source);
    let severity = payload
        .severity
        .as_ref()
        .map(|s| parse_severity(s))
        .unwrap_or(Severity::Medium);

    Alert {
        id: format!("{}-{}", payload.source, Uuid::new_v4()),
        source,
        alert_type: payload.alert_type.clone(),
        severity,
        title: payload.title.clone(),
        description: payload.description.clone(),
        data: payload.data.clone(),
        timestamp: payload.timestamp.unwrap_or_else(Utc::now),
        tags: payload.tags.clone(),
    }
}

/// Parses a source string into an AlertSource.
fn parse_source(source: &str) -> AlertSource {
    let lower = source.to_lowercase();

    // Try to detect source type from common patterns
    // Check for more specific patterns first
    if lower.contains("splunk") {
        AlertSource::Siem("Splunk".to_string())
    } else if lower.contains("elastic") || lower.contains("elasticsearch") {
        AlertSource::Siem("Elastic".to_string())
    } else if lower.contains("crowdstrike") {
        AlertSource::Edr("CrowdStrike".to_string())
    } else if lower.contains("sentinel") {
        AlertSource::Edr("SentinelOne".to_string())
    } else if lower.contains("m365") || lower.contains("office365") || lower.contains("exchange") {
        // Check m365 before "defender" to handle "m365-defender" as email security
        AlertSource::EmailSecurity("M365".to_string())
    } else if lower.contains("defender") || lower.contains("mde") {
        // Microsoft Defender for Endpoint (EDR)
        AlertSource::Edr("Defender".to_string())
    } else if lower.contains("proofpoint") {
        AlertSource::EmailSecurity("Proofpoint".to_string())
    } else if lower.contains("mimecast") {
        AlertSource::EmailSecurity("Mimecast".to_string())
    } else if lower.contains("okta") {
        AlertSource::IdentityProvider("Okta".to_string())
    } else if lower.contains("azure") || lower.contains("entra") {
        AlertSource::IdentityProvider("Entra".to_string())
    } else if lower.contains("aws") || lower.contains("guardduty") {
        AlertSource::CloudSecurity("AWS".to_string())
    } else if lower.contains("gcp") {
        AlertSource::CloudSecurity("GCP".to_string())
    } else if lower.contains("user") || lower.contains("phish") {
        AlertSource::UserReported
    } else {
        AlertSource::Custom(source.to_string())
    }
}

/// Parses a severity string into a Severity enum.
fn parse_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "critical" | "crit" | "5" | "p1" => Severity::Critical,
        "high" | "4" | "p2" => Severity::High,
        "medium" | "med" | "3" | "p3" => Severity::Medium,
        "low" | "2" | "p4" => Severity::Low,
        "info" | "informational" | "1" | "p5" => Severity::Info,
        _ => Severity::Medium, // Default to medium
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_source() {
        assert!(matches!(parse_source("splunk-cloud"), AlertSource::Siem(_)));
        assert!(matches!(
            parse_source("crowdstrike-falcon"),
            AlertSource::Edr(_)
        ));
        assert!(matches!(
            parse_source("m365-defender"),
            AlertSource::EmailSecurity(_)
        ));
        assert!(matches!(
            parse_source("okta-sso"),
            AlertSource::IdentityProvider(_)
        ));
        assert!(matches!(
            parse_source("user-reported"),
            AlertSource::UserReported
        ));
        assert!(matches!(
            parse_source("unknown-system"),
            AlertSource::Custom(_)
        ));
    }

    #[test]
    fn test_parse_severity() {
        assert_eq!(parse_severity("critical"), Severity::Critical);
        assert_eq!(parse_severity("HIGH"), Severity::High);
        assert_eq!(parse_severity("p3"), Severity::Medium);
        assert_eq!(parse_severity("low"), Severity::Low);
        assert_eq!(parse_severity("informational"), Severity::Info);
        assert_eq!(parse_severity("unknown"), Severity::Medium);
    }

    #[test]
    fn test_normalize_alert() {
        let payload = WebhookAlertPayload {
            source: "crowdstrike".to_string(),
            alert_type: "malware".to_string(),
            severity: Some("high".to_string()),
            title: "Malware detected".to_string(),
            description: Some("Found suspicious file".to_string()),
            data: serde_json::json!({"file": "test.exe"}),
            timestamp: None,
            tags: vec!["malware".to_string()],
        };

        let alert = normalize_alert(&payload);

        assert!(matches!(alert.source, AlertSource::Edr(_)));
        assert_eq!(alert.severity, Severity::High);
        assert_eq!(alert.title, "Malware detected");
        assert_eq!(alert.alert_type, "malware");
    }
}
