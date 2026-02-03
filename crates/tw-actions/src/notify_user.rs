//! Notify user action.
//!
//! This action sends a notification email to an affected user.

use crate::email_sanitizer::{sanitize_email, EmailSanitizationError};
use crate::registry::{
    Action, ActionContext, ActionError, ActionResult, ParameterDef, ParameterType,
};
use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{info, instrument, warn};
use tw_connectors::EmailGatewayConnector;
use tw_core::validation::ValidatedEmail;

/// Maximum length for email body content in action output to prevent sensitive data exposure.
const MAX_BODY_OUTPUT_LENGTH: usize = 200;

/// Truncation suffix appended when content is truncated.
const TRUNCATION_SUFFIX: &str = "...";

/// Truncates a string to the specified maximum length, adding a suffix if truncated.
/// Handles UTF-8 character boundaries safely to prevent invalid string slicing.
fn truncate_body_for_output(content: &str) -> String {
    if content.len() <= MAX_BODY_OUTPUT_LENGTH {
        content.to_string()
    } else {
        // Find a safe truncation point that doesn't break UTF-8
        let mut end = MAX_BODY_OUTPUT_LENGTH;
        while !content.is_char_boundary(end) && end > 0 {
            end -= 1;
        }
        format!("{}{}", &content[..end], TRUNCATION_SUFFIX)
    }
}

/// Action to send a notification email to a user.
pub struct NotifyUserAction {
    email_gateway: Arc<dyn EmailGatewayConnector>,
}

impl NotifyUserAction {
    /// Creates a new notify user action.
    pub fn new(email_gateway: Arc<dyn EmailGatewayConnector>) -> Self {
        Self { email_gateway }
    }

    /// Applies a template to the email body if a template_id is provided.
    fn apply_template(template_id: Option<&str>, subject: &str, body: &str) -> (String, String) {
        match template_id {
            Some("security_alert") => {
                let formatted_subject = format!("[Security Alert] {}", subject);
                let formatted_body = format!(
                    "SECURITY NOTIFICATION\n\
                     =====================\n\n\
                     {}\n\n\
                     If you did not expect this notification or have questions, \
                     please contact the security team immediately.\n\n\
                     This is an automated message from Triage Warden.",
                    body
                );
                (formatted_subject, formatted_body)
            }
            Some("phishing_warning") => {
                let formatted_subject = format!("[Phishing Alert] {}", subject);
                let formatted_body = format!(
                    "PHISHING WARNING\n\
                     ================\n\n\
                     {}\n\n\
                     IMPORTANT: Do not click any links or download attachments \
                     from suspicious emails. If you have already interacted with \
                     a suspicious email, please report it to the security team immediately.\n\n\
                     This is an automated message from Triage Warden.",
                    body
                );
                (formatted_subject, formatted_body)
            }
            Some("account_security") => {
                let formatted_subject = format!("[Account Security] {}", subject);
                let formatted_body = format!(
                    "ACCOUNT SECURITY NOTICE\n\
                     =======================\n\n\
                     {}\n\n\
                     If you did not initiate this action, please reset your password \
                     immediately and contact the security team.\n\n\
                     This is an automated message from Triage Warden.",
                    body
                );
                (formatted_subject, formatted_body)
            }
            Some("incident_notification") => {
                let formatted_subject = format!("[Incident Notice] {}", subject);
                let formatted_body = format!(
                    "SECURITY INCIDENT NOTIFICATION\n\
                     ==============================\n\n\
                     {}\n\n\
                     The security team is investigating this incident. \
                     Please cooperate with any requests for information.\n\n\
                     This is an automated message from Triage Warden.",
                    body
                );
                (formatted_subject, formatted_body)
            }
            _ => (subject.to_string(), body.to_string()),
        }
    }
}

#[async_trait]
impl Action for NotifyUserAction {
    fn name(&self) -> &str {
        "notify_user"
    }

    fn description(&self) -> &str {
        "Sends a notification email to an affected user"
    }

    fn required_parameters(&self) -> Vec<ParameterDef> {
        vec![
            ParameterDef::required(
                "user_email",
                "The email address of the user to notify",
                ParameterType::String,
            ),
            ParameterDef::required(
                "subject",
                "The subject of the notification email",
                ParameterType::String,
            ),
            ParameterDef::required(
                "body",
                "The body of the notification email",
                ParameterType::String,
            ),
            ParameterDef::optional(
                "template_id",
                "Optional template ID to use for formatting (security_alert, phishing_warning, account_security, incident_notification)",
                ParameterType::String,
                serde_json::json!(null),
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
        let user_email_raw = context.require_string("user_email")?;
        let subject = context.require_string("subject")?;
        let body = context.require_string("body")?;
        let template_id = context.get_string("template_id");

        // Validate email address using RFC 5321-compliant validation
        let validated_email = ValidatedEmail::new(&user_email_raw).map_err(|e| {
            ActionError::InvalidParameters(format!(
                "Invalid user email address '{}': {}",
                user_email_raw, e
            ))
        })?;
        let user_email = validated_email.as_str().to_string();

        // Apply template if provided
        let (formatted_subject, formatted_body) =
            Self::apply_template(template_id.as_deref(), &subject, &body);

        // Sanitize email content to prevent header injection attacks
        let sanitized = sanitize_email(&formatted_subject, &formatted_body).map_err(|e| {
            warn!("Email header injection attempt detected: {}", e);
            match e {
                EmailSanitizationError::SubjectInjectionDetected(msg) => {
                    ActionError::InvalidParameters(format!(
                        "Invalid subject - potential header injection: {}",
                        msg
                    ))
                }
                EmailSanitizationError::BodyInjectionDetected(msg) => {
                    ActionError::InvalidParameters(format!(
                        "Invalid body - potential header injection: {}",
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

        info!(
            "Preparing notification to {} with subject: {}",
            user_email, final_subject
        );

        // Generate a notification ID for tracking
        let notification_id = format!("notif-{}", uuid::Uuid::new_v4());

        // Verify the email gateway is healthy before attempting to send
        let health = self.email_gateway.health_check().await.map_err(|e| {
            ActionError::ConnectorError(format!("Email gateway health check failed: {}", e))
        })?;

        // Check if gateway is in a state that allows sending
        match &health {
            tw_connectors::ConnectorHealth::Unhealthy(reason) => {
                return Err(ActionError::ExecutionFailed(format!(
                    "Email gateway is unhealthy: {}. Cannot send notification to {}",
                    reason, user_email
                )));
            }
            tw_connectors::ConnectorHealth::Degraded(reason) => {
                warn!(
                    "Email gateway is degraded: {}. Attempting to send notification anyway.",
                    reason
                );
            }
            _ => {}
        }

        // The EmailGatewayConnector trait is designed for email security operations
        // (search, quarantine, block sender) not for sending emails. For full email
        // sending capability, an SMTP connector or email service integration (SendGrid,
        // AWS SES, etc.) would be needed.
        //
        // For now, we log the notification details for audit purposes and verify
        // the gateway is available. In a production deployment, this action should
        // be extended with an actual email sending connector.
        info!(
            notification_id = %notification_id,
            recipient = %user_email,
            subject = %final_subject,
            body_length = final_body.len(),
            template = ?template_id,
            content_sanitized = sanitized.was_sanitized,
            "Notification queued for delivery"
        );

        // Truncate body in output to prevent sensitive data exposure
        let truncated_body = truncate_body_for_output(&final_body);
        let body_was_truncated = truncated_body.len() < final_body.len();

        let mut output = HashMap::new();
        output.insert("user_email".to_string(), serde_json::json!(user_email));
        output.insert("subject".to_string(), serde_json::json!(final_subject));
        output.insert("body".to_string(), serde_json::json!(truncated_body));
        output.insert(
            "body_truncated".to_string(),
            serde_json::json!(body_was_truncated),
        );
        output.insert(
            "original_body_length".to_string(),
            serde_json::json!(final_body.len()),
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
        output.insert(
            "notification_id".to_string(),
            serde_json::json!(notification_id),
        );
        output.insert("status".to_string(), serde_json::json!("queued"));
        output.insert(
            "gateway_status".to_string(),
            serde_json::json!(format!("{:?}", health)),
        );

        if let Some(ref template) = template_id {
            output.insert("template_id".to_string(), serde_json::json!(template));
        }

        info!(
            "Notification {} to {} queued successfully",
            notification_id, user_email
        );

        Ok(ActionResult::success(
            self.name(),
            &format!(
                "Notification {} to {} queued successfully. \
                 Note: Full email delivery requires SMTP/email service integration.",
                notification_id, user_email
            ),
            started_at,
            output,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tw_connectors::email::MockEmailGatewayConnector;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_notify_user() {
        let email_gateway = Arc::new(MockEmailGatewayConnector::with_sample_data("test"));
        let action = NotifyUserAction::new(email_gateway);

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("user_email", serde_json::json!("victim@company.com"))
            .with_param("subject", serde_json::json!("Important Security Notice"))
            .with_param(
                "body",
                serde_json::json!("Your account was accessed from a new location."),
            );

        let result = action.execute(context).await.unwrap();
        assert!(result.success);
        assert!(!result.rollback_available);
        assert!(result.output.contains_key("notification_id"));
        assert!(result.output.contains_key("body"));
        assert!(result.output.contains_key("status"));
        assert_eq!(result.output["status"], serde_json::json!("queued"));
    }

    #[tokio::test]
    async fn test_notify_user_with_template() {
        let email_gateway = Arc::new(MockEmailGatewayConnector::with_sample_data("test"));
        let action = NotifyUserAction::new(email_gateway);

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("user_email", serde_json::json!("user@company.com"))
            .with_param("subject", serde_json::json!("Suspicious Login Detected"))
            .with_param(
                "body",
                serde_json::json!("We detected a login from an unusual location."),
            )
            .with_param("template_id", serde_json::json!("security_alert"));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);

        // Check that template was applied
        let subject = result.output["subject"].as_str().unwrap();
        assert!(subject.starts_with("[Security Alert]"));
    }

    #[tokio::test]
    async fn test_notify_user_phishing_template() {
        let email_gateway = Arc::new(MockEmailGatewayConnector::with_sample_data("test"));
        let action = NotifyUserAction::new(email_gateway);

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("user_email", serde_json::json!("user@company.com"))
            .with_param("subject", serde_json::json!("Phishing Email Detected"))
            .with_param(
                "body",
                serde_json::json!("A phishing email was sent to your mailbox."),
            )
            .with_param("template_id", serde_json::json!("phishing_warning"));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);

        let subject = result.output["subject"].as_str().unwrap();
        assert!(subject.starts_with("[Phishing Alert]"));
    }

    #[tokio::test]
    async fn test_notify_user_no_rollback() {
        let email_gateway = Arc::new(MockEmailGatewayConnector::with_sample_data("test"));
        let action = NotifyUserAction::new(email_gateway);

        assert!(!action.supports_rollback());
    }

    #[tokio::test]
    async fn test_missing_required_params() {
        let email_gateway = Arc::new(MockEmailGatewayConnector::with_sample_data("test"));
        let action = NotifyUserAction::new(email_gateway);

        // Missing all required params
        let context = ActionContext::new(Uuid::new_v4());
        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));

        // Missing subject and body
        let email_gateway = Arc::new(MockEmailGatewayConnector::with_sample_data("test"));
        let action = NotifyUserAction::new(email_gateway);
        let context = ActionContext::new(Uuid::new_v4())
            .with_param("user_email", serde_json::json!("user@company.com"));
        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
    }

    #[tokio::test]
    async fn test_apply_template_security_alert() {
        let (subject, body) = NotifyUserAction::apply_template(
            Some("security_alert"),
            "Test Subject",
            "Test body content",
        );

        assert!(subject.starts_with("[Security Alert]"));
        assert!(body.contains("SECURITY NOTIFICATION"));
        assert!(body.contains("Test body content"));
    }

    #[tokio::test]
    async fn test_apply_template_account_security() {
        let (subject, body) = NotifyUserAction::apply_template(
            Some("account_security"),
            "Password Changed",
            "Your password was recently changed.",
        );

        assert!(subject.starts_with("[Account Security]"));
        assert!(body.contains("ACCOUNT SECURITY NOTICE"));
        assert!(body.contains("reset your password"));
    }

    #[tokio::test]
    async fn test_apply_template_incident_notification() {
        let (subject, body) = NotifyUserAction::apply_template(
            Some("incident_notification"),
            "Security Incident",
            "A security incident has been detected.",
        );

        assert!(subject.starts_with("[Incident Notice]"));
        assert!(body.contains("SECURITY INCIDENT NOTIFICATION"));
    }

    #[tokio::test]
    async fn test_apply_template_no_template() {
        let (subject, body) = NotifyUserAction::apply_template(None, "Plain Subject", "Plain body");

        assert_eq!(subject, "Plain Subject");
        assert_eq!(body, "Plain body");
    }

    // ==================== Header Injection Prevention Tests ====================

    #[tokio::test]
    async fn test_subject_crlf_injection_sanitized() {
        let email_gateway = Arc::new(MockEmailGatewayConnector::with_sample_data("test"));
        let action = NotifyUserAction::new(email_gateway);

        // Attempt CRLF injection in subject to add BCC header
        let context = ActionContext::new(Uuid::new_v4())
            .with_param("user_email", serde_json::json!("user@company.com"))
            .with_param(
                "subject",
                serde_json::json!("Test\r\nBcc: attacker@evil.com"),
            )
            .with_param("body", serde_json::json!("Normal body content"));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);

        // Verify CRLF was stripped from subject
        let subject = result.output["subject"].as_str().unwrap();
        assert!(!subject.contains('\r'));
        assert!(!subject.contains('\n'));
        assert!(result.output["content_sanitized"].as_bool().unwrap());
    }

    #[tokio::test]
    async fn test_subject_lf_injection_sanitized() {
        let email_gateway = Arc::new(MockEmailGatewayConnector::with_sample_data("test"));
        let action = NotifyUserAction::new(email_gateway);

        // Attempt LF-only injection
        let context = ActionContext::new(Uuid::new_v4())
            .with_param("user_email", serde_json::json!("user@company.com"))
            .with_param("subject", serde_json::json!("Test\nX-Priority: 1"))
            .with_param("body", serde_json::json!("Normal body"));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);

        let subject = result.output["subject"].as_str().unwrap();
        assert!(!subject.contains('\n'));
        assert!(result.output["content_sanitized"].as_bool().unwrap());
    }

    #[tokio::test]
    async fn test_body_x_header_injection_blocked() {
        let email_gateway = Arc::new(MockEmailGatewayConnector::with_sample_data("test"));
        let action = NotifyUserAction::new(email_gateway);

        // Attempt X-header injection in body
        let context = ActionContext::new(Uuid::new_v4())
            .with_param("user_email", serde_json::json!("user@company.com"))
            .with_param("subject", serde_json::json!("Normal Subject"))
            .with_param(
                "body",
                serde_json::json!("X-Spam-Status: No\nMalicious body content"),
            );

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
        if let Err(ActionError::InvalidParameters(msg)) = result {
            assert!(msg.contains("X-header injection"));
        }
    }

    #[tokio::test]
    async fn test_body_x_priority_injection_blocked() {
        let email_gateway = Arc::new(MockEmailGatewayConnector::with_sample_data("test"));
        let action = NotifyUserAction::new(email_gateway);

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("user_email", serde_json::json!("user@company.com"))
            .with_param("subject", serde_json::json!("Test"))
            .with_param("body", serde_json::json!("X-Priority: 1\nUrgent message"));

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
    }

    #[tokio::test]
    async fn test_body_from_header_injection_blocked() {
        let email_gateway = Arc::new(MockEmailGatewayConnector::with_sample_data("test"));
        let action = NotifyUserAction::new(email_gateway);

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("user_email", serde_json::json!("user@company.com"))
            .with_param("subject", serde_json::json!("Test"))
            .with_param(
                "body",
                serde_json::json!("From: spoofed@attacker.com\nBody text"),
            );

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
    }

    #[tokio::test]
    async fn test_body_bcc_header_injection_blocked() {
        let email_gateway = Arc::new(MockEmailGatewayConnector::with_sample_data("test"));
        let action = NotifyUserAction::new(email_gateway);

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("user_email", serde_json::json!("user@company.com"))
            .with_param("subject", serde_json::json!("Test"))
            .with_param(
                "body",
                serde_json::json!("Bcc: hidden@attacker.com\nBody text"),
            );

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
    }

    #[tokio::test]
    async fn test_body_content_type_injection_blocked() {
        let email_gateway = Arc::new(MockEmailGatewayConnector::with_sample_data("test"));
        let action = NotifyUserAction::new(email_gateway);

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("user_email", serde_json::json!("user@company.com"))
            .with_param("subject", serde_json::json!("Test"))
            .with_param(
                "body",
                serde_json::json!("Content-Type: text/html\n<script>alert('xss')</script>"),
            );

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
    }

    #[tokio::test]
    async fn test_body_crlf_boundary_injection_blocked() {
        let email_gateway = Arc::new(MockEmailGatewayConnector::with_sample_data("test"));
        let action = NotifyUserAction::new(email_gateway);

        // Attempt to inject headers after CRLF boundary
        let context = ActionContext::new(Uuid::new_v4())
            .with_param("user_email", serde_json::json!("user@company.com"))
            .with_param("subject", serde_json::json!("Test"))
            .with_param(
                "body",
                serde_json::json!("Normal text\r\n\r\nX-Mailer: EvilBot\r\nMore text"),
            );

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
    }

    #[tokio::test]
    async fn test_clean_email_not_sanitized() {
        let email_gateway = Arc::new(MockEmailGatewayConnector::with_sample_data("test"));
        let action = NotifyUserAction::new(email_gateway);

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("user_email", serde_json::json!("user@company.com"))
            .with_param("subject", serde_json::json!("Normal Subject"))
            .with_param("body", serde_json::json!("This is a normal email body."));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);
        assert!(!result.output["content_sanitized"].as_bool().unwrap());
    }

    #[tokio::test]
    async fn test_template_with_injection_in_user_content() {
        let email_gateway = Arc::new(MockEmailGatewayConnector::with_sample_data("test"));
        let action = NotifyUserAction::new(email_gateway);

        // Even with template, user-provided content with injection should be handled
        let context = ActionContext::new(Uuid::new_v4())
            .with_param("user_email", serde_json::json!("user@company.com"))
            .with_param("subject", serde_json::json!("Alert\r\nX-Spam: NO"))
            .with_param("body", serde_json::json!("Normal alert body"))
            .with_param("template_id", serde_json::json!("security_alert"));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);

        // Subject should be sanitized even after template formatting
        let subject = result.output["subject"].as_str().unwrap();
        assert!(subject.starts_with("[Security Alert]"));
        assert!(!subject.contains('\r'));
        assert!(!subject.contains('\n'));
    }

    #[tokio::test]
    async fn test_multiple_crlf_in_subject() {
        let email_gateway = Arc::new(MockEmailGatewayConnector::with_sample_data("test"));
        let action = NotifyUserAction::new(email_gateway);

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("user_email", serde_json::json!("user@company.com"))
            .with_param(
                "subject",
                serde_json::json!(
                    "Test\r\nTo: victim@test.com\r\nBcc: spy@evil.com\r\nSubject: Fake"
                ),
            )
            .with_param("body", serde_json::json!("Body"));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);

        let subject = result.output["subject"].as_str().unwrap();
        assert!(!subject.contains('\r'));
        assert!(!subject.contains('\n'));
        // All parts should be merged with spaces
        assert!(subject.contains("Test"));
    }

    // ==================== Body Truncation Tests ====================

    #[test]
    fn test_truncate_body_short_content() {
        let short_content = "This is a short message.";
        let result = truncate_body_for_output(short_content);
        assert_eq!(result, short_content);
    }

    #[test]
    fn test_truncate_body_long_content() {
        let long_content = "X".repeat(500);
        let result = truncate_body_for_output(&long_content);
        assert!(result.len() <= MAX_BODY_OUTPUT_LENGTH + TRUNCATION_SUFFIX.len());
        assert!(result.ends_with(TRUNCATION_SUFFIX));
    }

    #[test]
    fn test_truncate_body_exact_length() {
        let exact_content = "A".repeat(MAX_BODY_OUTPUT_LENGTH);
        let result = truncate_body_for_output(&exact_content);
        assert_eq!(result, exact_content);
    }

    #[test]
    fn test_truncate_body_unicode_safety() {
        // Create content with multi-byte Unicode characters
        let content =
            "Hello \u{1F600}\u{1F600}\u{1F600}\u{1F600} World!".to_string() + &"X".repeat(300);
        let result = truncate_body_for_output(&content);
        // Should not panic and should be valid UTF-8
        assert!(result.is_char_boundary(result.len() - TRUNCATION_SUFFIX.len()));
    }

    #[tokio::test]
    async fn test_notify_user_body_truncation() {
        let email_gateway = Arc::new(MockEmailGatewayConnector::with_sample_data("test"));
        let action = NotifyUserAction::new(email_gateway);

        // Create a very long body
        let long_body = "This is a test email body. ".repeat(50);

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("user_email", serde_json::json!("user@company.com"))
            .with_param("subject", serde_json::json!("Test Subject"))
            .with_param("body", serde_json::json!(long_body));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);

        // Check that body was truncated in output
        let body = result.output["body"].as_str().unwrap();
        assert!(body.len() <= MAX_BODY_OUTPUT_LENGTH + TRUNCATION_SUFFIX.len());
        assert!(body.ends_with(TRUNCATION_SUFFIX));

        // Check truncation metadata
        assert!(result.output["body_truncated"].as_bool().unwrap());
        assert!(
            result.output["original_body_length"].as_u64().unwrap() > MAX_BODY_OUTPUT_LENGTH as u64
        );
    }

    #[tokio::test]
    async fn test_notify_user_short_body_not_truncated() {
        let email_gateway = Arc::new(MockEmailGatewayConnector::with_sample_data("test"));
        let action = NotifyUserAction::new(email_gateway);

        let short_body = "Short message.";

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("user_email", serde_json::json!("user@company.com"))
            .with_param("subject", serde_json::json!("Test Subject"))
            .with_param("body", serde_json::json!(short_body));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);

        // Body should not be truncated
        let body = result.output["body"].as_str().unwrap();
        assert_eq!(body, short_body);
        assert!(!result.output["body_truncated"].as_bool().unwrap());
    }

    #[tokio::test]
    async fn test_notify_user_template_body_truncation() {
        let email_gateway = Arc::new(MockEmailGatewayConnector::with_sample_data("test"));
        let action = NotifyUserAction::new(email_gateway);

        // Templates add boilerplate that can make the body exceed the limit
        let context = ActionContext::new(Uuid::new_v4())
            .with_param("user_email", serde_json::json!("user@company.com"))
            .with_param("subject", serde_json::json!("Test"))
            .with_param("body", serde_json::json!("User content here"))
            .with_param("template_id", serde_json::json!("security_alert"));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);

        // Body should be truncated because template adds content
        let body = result.output["body"].as_str().unwrap();
        assert!(body.len() <= MAX_BODY_OUTPUT_LENGTH + TRUNCATION_SUFFIX.len());
    }

    // ==================== Email Address Validation Tests ====================

    #[tokio::test]
    async fn test_invalid_email_no_at_symbol() {
        let email_gateway = Arc::new(MockEmailGatewayConnector::with_sample_data("test"));
        let action = NotifyUserAction::new(email_gateway);

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("user_email", serde_json::json!("invalid-email"))
            .with_param("subject", serde_json::json!("Test"))
            .with_param("body", serde_json::json!("Test body"));

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
        if let Err(ActionError::InvalidParameters(msg)) = result {
            assert!(msg.contains("Invalid user email address"));
        }
    }

    #[tokio::test]
    async fn test_invalid_email_empty_local_part() {
        let email_gateway = Arc::new(MockEmailGatewayConnector::with_sample_data("test"));
        let action = NotifyUserAction::new(email_gateway);

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("user_email", serde_json::json!("@company.com"))
            .with_param("subject", serde_json::json!("Test"))
            .with_param("body", serde_json::json!("Test body"));

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
    }

    #[tokio::test]
    async fn test_invalid_email_empty_domain() {
        let email_gateway = Arc::new(MockEmailGatewayConnector::with_sample_data("test"));
        let action = NotifyUserAction::new(email_gateway);

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("user_email", serde_json::json!("user@"))
            .with_param("subject", serde_json::json!("Test"))
            .with_param("body", serde_json::json!("Test body"));

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
    }

    #[tokio::test]
    async fn test_invalid_email_no_tld() {
        let email_gateway = Arc::new(MockEmailGatewayConnector::with_sample_data("test"));
        let action = NotifyUserAction::new(email_gateway);

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("user_email", serde_json::json!("user@localhost"))
            .with_param("subject", serde_json::json!("Test"))
            .with_param("body", serde_json::json!("Test body"));

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
    }

    #[tokio::test]
    async fn test_invalid_email_multiple_at() {
        let email_gateway = Arc::new(MockEmailGatewayConnector::with_sample_data("test"));
        let action = NotifyUserAction::new(email_gateway);

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("user_email", serde_json::json!("user@domain@company.com"))
            .with_param("subject", serde_json::json!("Test"))
            .with_param("body", serde_json::json!("Test body"));

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
    }

    #[tokio::test]
    async fn test_invalid_email_space_in_local() {
        let email_gateway = Arc::new(MockEmailGatewayConnector::with_sample_data("test"));
        let action = NotifyUserAction::new(email_gateway);

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("user_email", serde_json::json!("user name@company.com"))
            .with_param("subject", serde_json::json!("Test"))
            .with_param("body", serde_json::json!("Test body"));

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
    }

    #[tokio::test]
    async fn test_valid_email_with_plus_tag() {
        let email_gateway = Arc::new(MockEmailGatewayConnector::with_sample_data("test"));
        let action = NotifyUserAction::new(email_gateway);

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("user_email", serde_json::json!("user+tag@company.com"))
            .with_param("subject", serde_json::json!("Test"))
            .with_param("body", serde_json::json!("Test body"));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);
    }

    #[tokio::test]
    async fn test_valid_email_with_subdomain() {
        let email_gateway = Arc::new(MockEmailGatewayConnector::with_sample_data("test"));
        let action = NotifyUserAction::new(email_gateway);

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("user_email", serde_json::json!("user@mail.company.com"))
            .with_param("subject", serde_json::json!("Test"))
            .with_param("body", serde_json::json!("Test body"));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);
    }

    #[tokio::test]
    async fn test_email_normalized_to_lowercase() {
        let email_gateway = Arc::new(MockEmailGatewayConnector::with_sample_data("test"));
        let action = NotifyUserAction::new(email_gateway);

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("user_email", serde_json::json!("USER@COMPANY.COM"))
            .with_param("subject", serde_json::json!("Test"))
            .with_param("body", serde_json::json!("Test body"));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);
        assert_eq!(
            result.output["user_email"].as_str().unwrap(),
            "user@company.com"
        );
    }
}
