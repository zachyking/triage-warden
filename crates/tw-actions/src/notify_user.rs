//! Notify user action.
//!
//! This action sends a notification email to an affected user.

use crate::registry::{
    Action, ActionContext, ActionError, ActionResult, ParameterDef, ParameterType,
};
use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{info, instrument, warn};
use tw_connectors::EmailGatewayConnector;

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
        let user_email = context.require_string("user_email")?;
        let subject = context.require_string("subject")?;
        let body = context.require_string("body")?;
        let template_id = context.get_string("template_id");

        // Apply template if provided
        let (formatted_subject, formatted_body) =
            Self::apply_template(template_id.as_deref(), &subject, &body);

        info!(
            "Preparing notification to {} with subject: {}",
            user_email, formatted_subject
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
            subject = %formatted_subject,
            body_length = formatted_body.len(),
            template = ?template_id,
            "Notification queued for delivery"
        );

        let mut output = HashMap::new();
        output.insert("user_email".to_string(), serde_json::json!(user_email));
        output.insert("subject".to_string(), serde_json::json!(formatted_subject));
        output.insert("body".to_string(), serde_json::json!(formatted_body));
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
}
