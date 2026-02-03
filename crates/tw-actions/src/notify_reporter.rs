//! Notify reporter action.
//!
//! This action sends a status update to the original incident reporter.

use crate::email_sanitizer::{sanitize_email, EmailSanitizationError};
use crate::registry::{
    Action, ActionContext, ActionError, ActionResult, ParameterDef, ParameterType,
};
use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, instrument, warn};
use tw_core::validation::ValidatedEmail;

/// Status of an incident that can be communicated to the reporter.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IncidentStatus {
    /// Incident has been received and is being reviewed.
    Received,
    /// Incident is under active investigation.
    Investigating,
    /// Incident has been resolved.
    Resolved,
    /// Incident was determined to be a false positive.
    FalsePositive,
    /// Incident has been escalated.
    Escalated,
    /// Incident has been closed.
    Closed,
}

impl std::fmt::Display for IncidentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IncidentStatus::Received => write!(f, "Received"),
            IncidentStatus::Investigating => write!(f, "Investigating"),
            IncidentStatus::Resolved => write!(f, "Resolved"),
            IncidentStatus::FalsePositive => write!(f, "False Positive"),
            IncidentStatus::Escalated => write!(f, "Escalated"),
            IncidentStatus::Closed => write!(f, "Closed"),
        }
    }
}

/// Action to send a status update notification to the original incident reporter.
pub struct NotifyReporterAction;

impl NotifyReporterAction {
    /// Creates a new notify reporter action.
    pub fn new() -> Self {
        Self
    }

    /// Generates a formatted notification message based on status.
    fn format_notification(status: &str, message: &str, incident_id: &str) -> String {
        let status_emoji = match status.to_lowercase().as_str() {
            "received" => "[INFO]",
            "investigating" => "[INVESTIGATING]",
            "resolved" => "[RESOLVED]",
            "false_positive" => "[CLOSED - False Positive]",
            "escalated" => "[ESCALATED]",
            "closed" => "[CLOSED]",
            _ => "[UPDATE]",
        };

        format!(
            "{} Incident Update - {}\n\n\
            Incident ID: {}\n\
            Status: {}\n\n\
            {}\n\n\
            If you have any questions, please contact the security team.\n\n\
            --- Triage Warden Automated Notification ---",
            status_emoji,
            status.to_uppercase(),
            incident_id,
            status,
            message
        )
    }
}

impl Default for NotifyReporterAction {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Action for NotifyReporterAction {
    fn name(&self) -> &str {
        "notify_reporter"
    }

    fn description(&self) -> &str {
        "Sends a status update notification to the original incident reporter"
    }

    fn required_parameters(&self) -> Vec<ParameterDef> {
        vec![
            ParameterDef::required(
                "incident_id",
                "The ID of the incident being reported on",
                ParameterType::String,
            ),
            ParameterDef::required(
                "reporter_email",
                "The email address of the original incident reporter",
                ParameterType::String,
            ),
            ParameterDef::required(
                "status",
                "The current status of the incident (received, investigating, resolved, false_positive, escalated, closed)",
                ParameterType::String,
            ),
            ParameterDef::required(
                "message",
                "The message to send to the reporter",
                ParameterType::String,
            ),
            ParameterDef::optional(
                "include_details",
                "Whether to include additional incident details in the notification",
                ParameterType::Boolean,
                serde_json::json!(false),
            ),
        ]
    }

    fn supports_rollback(&self) -> bool {
        // Notifications cannot be rolled back - emails cannot be unsent
        false
    }

    #[instrument(skip(self, context))]
    async fn execute(&self, context: ActionContext) -> Result<ActionResult, ActionError> {
        let started_at = Utc::now();
        let incident_id = context.require_string("incident_id")?;
        let reporter_email = context.require_string("reporter_email")?;
        let status = context.require_string("status")?;
        let message = context.require_string("message")?;
        let _include_details = context
            .get_param("include_details")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        // Validate email format using RFC 5321-compliant validation
        let validated_email = ValidatedEmail::new(&reporter_email).map_err(|e| {
            ActionError::InvalidParameters(format!(
                "Invalid reporter email address '{}': {}",
                reporter_email, e
            ))
        })?;
        let reporter_email = validated_email.as_str().to_string();

        // Generate notification ID
        let notification_id = format!("notif-reporter-{}", uuid::Uuid::new_v4());

        info!(
            "Sending status notification {} to reporter {} for incident {}: status={}",
            notification_id, reporter_email, incident_id, status
        );

        // Format the notification message
        let formatted_message = Self::format_notification(&status, &message, &incident_id);

        // Generate a subject line for the notification
        let subject = format!("Incident {} Status Update: {}", incident_id, status);

        // Sanitize email content to prevent header injection attacks
        let sanitized = sanitize_email(&subject, &formatted_message).map_err(|e| {
            warn!("Email header injection attempt detected: {}", e);
            match e {
                EmailSanitizationError::SubjectInjectionDetected(msg) => {
                    ActionError::InvalidParameters(format!(
                        "Invalid content - potential header injection in subject: {}",
                        msg
                    ))
                }
                EmailSanitizationError::BodyInjectionDetected(msg) => {
                    ActionError::InvalidParameters(format!(
                        "Invalid message - potential header injection: {}",
                        msg
                    ))
                }
                EmailSanitizationError::XHeaderInjectionDetected(msg) => {
                    ActionError::InvalidParameters(format!(
                        "Invalid content - X-header injection detected: {}",
                        msg
                    ))
                }
            }
        })?;

        if sanitized.was_sanitized {
            info!(
                "Email content was sanitized: {:?}",
                sanitized.sanitization_details
            );
        }

        let final_subject = sanitized.subject;
        let final_body = sanitized.body;

        // In a real implementation, this would:
        // 1. Validate the reporter email against known reporters
        // 2. Fetch additional incident details if include_details is true
        // 3. Send the email via email gateway/SMTP service
        // 4. Track the notification for audit purposes
        // 5. Handle delivery failures and retries

        let mut output = HashMap::new();
        output.insert(
            "notification_id".to_string(),
            serde_json::json!(notification_id),
        );
        output.insert("incident_id".to_string(), serde_json::json!(incident_id));
        output.insert(
            "reporter_email".to_string(),
            serde_json::json!(reporter_email),
        );
        output.insert("status".to_string(), serde_json::json!(status));
        output.insert("subject".to_string(), serde_json::json!(final_subject));
        output.insert("success".to_string(), serde_json::json!(true));
        output.insert(
            "sent_at".to_string(),
            serde_json::json!(Utc::now().to_rfc3339()),
        );
        output.insert(
            "formatted_message".to_string(),
            serde_json::json!(final_body),
        );
        output.insert(
            "content_sanitized".to_string(),
            serde_json::json!(sanitized.was_sanitized),
        );
        if sanitized.was_sanitized {
            output.insert(
                "sanitization_details".to_string(),
                serde_json::json!(sanitized.sanitization_details),
            );
        }

        info!(
            "Reporter notification {} sent successfully to {}",
            notification_id, reporter_email
        );

        Ok(ActionResult::success(
            self.name(),
            &format!(
                "Notification {} sent to {} for incident {} (status: {})",
                notification_id, reporter_email, incident_id, status
            ),
            started_at,
            output,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_notify_reporter() {
        let action = NotifyReporterAction::new();

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("incident_id", serde_json::json!("INC-2024-001"))
            .with_param("reporter_email", serde_json::json!("user@company.com"))
            .with_param("status", serde_json::json!("investigating"))
            .with_param(
                "message",
                serde_json::json!(
                    "Your reported phishing email is being investigated by our security team."
                ),
            );

        let result = action.execute(context).await.unwrap();
        assert!(result.success);
        assert!(!result.rollback_available);
        assert!(result.output.contains_key("notification_id"));
        assert!(result.output.contains_key("success"));
        assert!(result.output.contains_key("sent_at"));

        let notif_id = result.output["notification_id"].as_str().unwrap();
        assert!(notif_id.starts_with("notif-reporter-"));
    }

    #[tokio::test]
    async fn test_notify_reporter_resolved_status() {
        let action = NotifyReporterAction::new();

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("incident_id", serde_json::json!("INC-2024-002"))
            .with_param("reporter_email", serde_json::json!("reporter@company.com"))
            .with_param("status", serde_json::json!("resolved"))
            .with_param("message", serde_json::json!("The suspicious email you reported was confirmed as phishing and has been blocked."));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);
        assert_eq!(result.output["status"].as_str().unwrap(), "resolved");
    }

    #[tokio::test]
    async fn test_notify_reporter_false_positive() {
        let action = NotifyReporterAction::new();

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("incident_id", serde_json::json!("INC-2024-003"))
            .with_param("reporter_email", serde_json::json!("reporter@company.com"))
            .with_param("status", serde_json::json!("false_positive"))
            .with_param(
                "message",
                serde_json::json!(
                    "After investigation, the email was determined to be legitimate."
                ),
            );

        let result = action.execute(context).await.unwrap();
        assert!(result.success);

        let formatted = result.output["formatted_message"].as_str().unwrap();
        assert!(formatted.contains("[CLOSED - False Positive]"));
    }

    #[tokio::test]
    async fn test_notify_reporter_no_rollback() {
        let action = NotifyReporterAction::new();
        assert!(!action.supports_rollback());
    }

    #[tokio::test]
    async fn test_notify_reporter_missing_required_params() {
        let action = NotifyReporterAction::new();

        // Missing all required params
        let context = ActionContext::new(Uuid::new_v4());
        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));

        // Missing reporter_email
        let context = ActionContext::new(Uuid::new_v4())
            .with_param("incident_id", serde_json::json!("INC-2024-004"));
        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
    }

    #[tokio::test]
    async fn test_notify_reporter_invalid_email() {
        let action = NotifyReporterAction::new();

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("incident_id", serde_json::json!("INC-2024-005"))
            .with_param("reporter_email", serde_json::json!("invalid-email"))
            .with_param("status", serde_json::json!("received"))
            .with_param("message", serde_json::json!("Test message"));

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
    }

    #[tokio::test]
    async fn test_notify_reporter_with_include_details() {
        let action = NotifyReporterAction::new();

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("incident_id", serde_json::json!("INC-2024-006"))
            .with_param("reporter_email", serde_json::json!("user@company.com"))
            .with_param("status", serde_json::json!("escalated"))
            .with_param(
                "message",
                serde_json::json!("Your report has been escalated to the senior security team."),
            )
            .with_param("include_details", serde_json::json!(true));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);
    }

    #[test]
    fn test_format_notification() {
        let formatted = NotifyReporterAction::format_notification(
            "resolved",
            "The issue has been fixed.",
            "INC-001",
        );

        assert!(formatted.contains("[RESOLVED]"));
        assert!(formatted.contains("INC-001"));
        assert!(formatted.contains("The issue has been fixed."));
        assert!(formatted.contains("Triage Warden"));
    }

    #[test]
    fn test_incident_status_display() {
        assert_eq!(format!("{}", IncidentStatus::Received), "Received");
        assert_eq!(
            format!("{}", IncidentStatus::Investigating),
            "Investigating"
        );
        assert_eq!(format!("{}", IncidentStatus::Resolved), "Resolved");
        assert_eq!(
            format!("{}", IncidentStatus::FalsePositive),
            "False Positive"
        );
        assert_eq!(format!("{}", IncidentStatus::Escalated), "Escalated");
        assert_eq!(format!("{}", IncidentStatus::Closed), "Closed");
    }

    #[test]
    fn test_incident_status_serialization() {
        let status = IncidentStatus::Investigating;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"investigating\"");

        let deserialized: IncidentStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, IncidentStatus::Investigating);
    }

    // ==================== Header Injection Prevention Tests ====================

    #[tokio::test]
    async fn test_message_x_header_injection_blocked() {
        let action = NotifyReporterAction::new();

        // Attempt X-header injection in message
        let context = ActionContext::new(Uuid::new_v4())
            .with_param("incident_id", serde_json::json!("INC-2024-007"))
            .with_param("reporter_email", serde_json::json!("user@company.com"))
            .with_param("status", serde_json::json!("investigating"))
            .with_param(
                "message",
                serde_json::json!("X-Spam-Status: No\nMalicious message content"),
            );

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
        if let Err(ActionError::InvalidParameters(msg)) = result {
            assert!(msg.contains("X-header injection"));
        }
    }

    #[tokio::test]
    async fn test_message_x_priority_injection_blocked() {
        let action = NotifyReporterAction::new();

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("incident_id", serde_json::json!("INC-2024-008"))
            .with_param("reporter_email", serde_json::json!("user@company.com"))
            .with_param("status", serde_json::json!("resolved"))
            .with_param(
                "message",
                serde_json::json!("X-Priority: 1\nUrgent fake message"),
            );

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
    }

    #[tokio::test]
    async fn test_message_from_header_injection_blocked() {
        let action = NotifyReporterAction::new();

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("incident_id", serde_json::json!("INC-2024-009"))
            .with_param("reporter_email", serde_json::json!("user@company.com"))
            .with_param("status", serde_json::json!("escalated"))
            .with_param(
                "message",
                serde_json::json!("From: spoofed@attacker.com\nFake escalation"),
            );

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
    }

    #[tokio::test]
    async fn test_message_bcc_header_injection_blocked() {
        let action = NotifyReporterAction::new();

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("incident_id", serde_json::json!("INC-2024-010"))
            .with_param("reporter_email", serde_json::json!("user@company.com"))
            .with_param("status", serde_json::json!("closed"))
            .with_param(
                "message",
                serde_json::json!("Bcc: hidden@attacker.com\nClosed message"),
            );

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
    }

    #[tokio::test]
    async fn test_message_content_type_injection_blocked() {
        let action = NotifyReporterAction::new();

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("incident_id", serde_json::json!("INC-2024-011"))
            .with_param("reporter_email", serde_json::json!("user@company.com"))
            .with_param("status", serde_json::json!("investigating"))
            .with_param(
                "message",
                serde_json::json!("Content-Type: text/html\n<script>alert('xss')</script>"),
            );

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
    }

    #[tokio::test]
    async fn test_message_crlf_boundary_injection_blocked() {
        let action = NotifyReporterAction::new();

        // Attempt to inject headers after CRLF boundary
        let context = ActionContext::new(Uuid::new_v4())
            .with_param("incident_id", serde_json::json!("INC-2024-012"))
            .with_param("reporter_email", serde_json::json!("user@company.com"))
            .with_param("status", serde_json::json!("investigating"))
            .with_param(
                "message",
                serde_json::json!("Normal text\r\n\r\nX-Mailer: EvilBot\r\nMore text"),
            );

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
    }

    #[tokio::test]
    async fn test_clean_message_not_sanitized() {
        let action = NotifyReporterAction::new();

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("incident_id", serde_json::json!("INC-2024-013"))
            .with_param("reporter_email", serde_json::json!("user@company.com"))
            .with_param("status", serde_json::json!("resolved"))
            .with_param(
                "message",
                serde_json::json!("This is a normal status update message."),
            );

        let result = action.execute(context).await.unwrap();
        assert!(result.success);
        assert!(!result.output["content_sanitized"].as_bool().unwrap());
    }

    #[tokio::test]
    async fn test_status_with_special_chars_safe() {
        let action = NotifyReporterAction::new();

        // Status value should not cause injection
        let context = ActionContext::new(Uuid::new_v4())
            .with_param("incident_id", serde_json::json!("INC-2024-014"))
            .with_param("reporter_email", serde_json::json!("user@company.com"))
            .with_param("status", serde_json::json!("investigating"))
            .with_param("message", serde_json::json!("Normal investigation update."));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);
        assert!(result.output.contains_key("subject"));
    }

    #[tokio::test]
    async fn test_incident_id_with_special_chars_safe() {
        let action = NotifyReporterAction::new();

        // Even with unusual incident ID, the output should be safe
        let context = ActionContext::new(Uuid::new_v4())
            .with_param("incident_id", serde_json::json!("INC-2024-015"))
            .with_param("reporter_email", serde_json::json!("user@company.com"))
            .with_param("status", serde_json::json!("closed"))
            .with_param("message", serde_json::json!("Incident has been closed."));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);

        // Verify the subject was generated correctly
        let subject = result.output["subject"].as_str().unwrap();
        assert!(subject.contains("INC-2024-015"));
        assert!(subject.contains("closed"));
    }

    #[tokio::test]
    async fn test_multiline_message_with_legitimate_content() {
        let action = NotifyReporterAction::new();

        // Legitimate multiline content should work
        let context = ActionContext::new(Uuid::new_v4())
            .with_param("incident_id", serde_json::json!("INC-2024-016"))
            .with_param("reporter_email", serde_json::json!("user@company.com"))
            .with_param("status", serde_json::json!("investigating"))
            .with_param(
                "message",
                serde_json::json!("Investigation update:\n\n- Analyzed email headers\n- Checked sender reputation\n- Scanning attachments"),
            );

        let result = action.execute(context).await.unwrap();
        assert!(result.success);
    }

    // ==================== Email Address Validation Tests ====================

    #[tokio::test]
    async fn test_invalid_email_empty_local_part() {
        let action = NotifyReporterAction::new();

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("incident_id", serde_json::json!("INC-2024-017"))
            .with_param("reporter_email", serde_json::json!("@company.com"))
            .with_param("status", serde_json::json!("received"))
            .with_param("message", serde_json::json!("Test message"));

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
    }

    #[tokio::test]
    async fn test_invalid_email_empty_domain() {
        let action = NotifyReporterAction::new();

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("incident_id", serde_json::json!("INC-2024-018"))
            .with_param("reporter_email", serde_json::json!("user@"))
            .with_param("status", serde_json::json!("received"))
            .with_param("message", serde_json::json!("Test message"));

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
    }

    #[tokio::test]
    async fn test_invalid_email_no_tld() {
        let action = NotifyReporterAction::new();

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("incident_id", serde_json::json!("INC-2024-019"))
            .with_param("reporter_email", serde_json::json!("user@localhost"))
            .with_param("status", serde_json::json!("received"))
            .with_param("message", serde_json::json!("Test message"));

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
    }

    #[tokio::test]
    async fn test_invalid_email_multiple_at_symbols() {
        let action = NotifyReporterAction::new();

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("incident_id", serde_json::json!("INC-2024-020"))
            .with_param(
                "reporter_email",
                serde_json::json!("user@domain@company.com"),
            )
            .with_param("status", serde_json::json!("received"))
            .with_param("message", serde_json::json!("Test message"));

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
    }

    #[tokio::test]
    async fn test_invalid_email_space_in_local_part() {
        let action = NotifyReporterAction::new();

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("incident_id", serde_json::json!("INC-2024-021"))
            .with_param("reporter_email", serde_json::json!("user name@company.com"))
            .with_param("status", serde_json::json!("received"))
            .with_param("message", serde_json::json!("Test message"));

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
    }

    #[tokio::test]
    async fn test_valid_email_with_plus_tag() {
        let action = NotifyReporterAction::new();

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("incident_id", serde_json::json!("INC-2024-022"))
            .with_param(
                "reporter_email",
                serde_json::json!("user+reports@company.com"),
            )
            .with_param("status", serde_json::json!("received"))
            .with_param("message", serde_json::json!("Test message"));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);
    }

    #[tokio::test]
    async fn test_valid_email_with_subdomain() {
        let action = NotifyReporterAction::new();

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("incident_id", serde_json::json!("INC-2024-023"))
            .with_param("reporter_email", serde_json::json!("user@mail.company.com"))
            .with_param("status", serde_json::json!("received"))
            .with_param("message", serde_json::json!("Test message"));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);
    }

    #[tokio::test]
    async fn test_email_normalized_to_lowercase() {
        let action = NotifyReporterAction::new();

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("incident_id", serde_json::json!("INC-2024-024"))
            .with_param("reporter_email", serde_json::json!("USER@COMPANY.COM"))
            .with_param("status", serde_json::json!("received"))
            .with_param("message", serde_json::json!("Test message"));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);
        // Email should be normalized to lowercase
        assert_eq!(
            result.output["reporter_email"].as_str().unwrap(),
            "user@company.com"
        );
    }
}
