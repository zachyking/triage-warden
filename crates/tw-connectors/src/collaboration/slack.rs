//! Slack connector for sending notifications and interactive messages.
//!
//! Supports sending messages via webhook, Block Kit formatting for rich
//! incident notifications, and interactive message builders for approve/reject flows.

use crate::http::HttpClient;
use crate::secure_string::SecureString;
use crate::traits::{
    AuthConfig, ConnectorConfig, ConnectorError, ConnectorHealth, ConnectorResult,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Slack connector configuration.
#[derive(Debug, Clone)]
pub struct SlackConfig {
    /// Bot token for Slack API access.
    pub bot_token: SecureString,
    /// App-level token for Socket Mode (optional).
    pub app_token: Option<SecureString>,
    /// Default channel for notifications.
    pub default_channel: String,
    /// Incoming webhook URL (alternative to bot token).
    pub webhook_url: Option<String>,
}

/// Slack connector for sending messages and notifications.
pub struct SlackConnector {
    config: SlackConfig,
    client: HttpClient,
}

/// A Slack Block Kit block element.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SlackBlock {
    /// Header block.
    Header { text: SlackTextObject },
    /// Section block with text and optional accessory.
    Section {
        text: SlackTextObject,
        #[serde(skip_serializing_if = "Option::is_none")]
        accessory: Option<SlackAccessory>,
        #[serde(skip_serializing_if = "Option::is_none")]
        fields: Option<Vec<SlackTextObject>>,
    },
    /// Divider block.
    Divider,
    /// Actions block with interactive elements.
    Actions { elements: Vec<SlackActionElement> },
    /// Context block for secondary information.
    Context { elements: Vec<SlackContextElement> },
}

/// Slack text object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackTextObject {
    /// Text type: "plain_text" or "mrkdwn".
    #[serde(rename = "type")]
    pub text_type: String,
    /// The text content.
    pub text: String,
    /// Whether to enable emoji rendering (plain_text only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub emoji: Option<bool>,
}

impl SlackTextObject {
    /// Creates a plain text object.
    pub fn plain(text: impl Into<String>) -> Self {
        Self {
            text_type: "plain_text".to_string(),
            text: text.into(),
            emoji: Some(true),
        }
    }

    /// Creates a markdown text object.
    pub fn mrkdwn(text: impl Into<String>) -> Self {
        Self {
            text_type: "mrkdwn".to_string(),
            text: text.into(),
            emoji: None,
        }
    }
}

/// Slack accessory element.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SlackAccessory {
    /// Button accessory.
    Button {
        text: SlackTextObject,
        action_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        url: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        value: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        style: Option<String>,
    },
}

/// Slack action element for interactive messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SlackActionElement {
    /// Button element.
    Button {
        text: SlackTextObject,
        action_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        value: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        style: Option<String>,
    },
}

/// Slack context element.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SlackContextElement {
    /// Text element.
    Text(SlackTextObject),
}

/// A Slack message payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackMessage {
    /// Target channel ID or name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    /// Plain text fallback for notifications.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Block Kit blocks.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocks: Option<Vec<SlackBlock>>,
}

/// Slash command request from Slack.
#[derive(Debug, Clone, Deserialize)]
pub struct SlackSlashCommand {
    /// The command name (e.g., "/tw").
    pub command: String,
    /// Text after the command.
    pub text: String,
    /// User who invoked the command.
    pub user_id: String,
    /// User display name.
    pub user_name: String,
    /// Channel where the command was invoked.
    pub channel_id: String,
    /// Response URL for deferred responses.
    pub response_url: String,
    /// Unique trigger ID.
    pub trigger_id: String,
}

/// Slash command response back to Slack.
#[derive(Debug, Clone, Serialize)]
pub struct SlackSlashResponse {
    /// Response type: "in_channel" or "ephemeral".
    pub response_type: String,
    /// Plain text content.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Block Kit blocks for rich response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocks: Option<Vec<SlackBlock>>,
}

impl SlackConnector {
    /// Creates a new Slack connector.
    pub fn new(config: SlackConfig) -> ConnectorResult<Self> {
        let connector_config = ConnectorConfig {
            name: "slack".to_string(),
            base_url: "https://slack.com/api".to_string(),
            auth: AuthConfig::BearerToken {
                token: config.bot_token.clone(),
            },
            timeout_secs: 30,
            max_retries: 2,
            verify_tls: true,
            headers: HashMap::new(),
        };

        let client = HttpClient::new(connector_config)?;

        Ok(Self { config, client })
    }

    /// Sends a simple text message to the default channel.
    pub async fn send_message(&self, text: &str) -> ConnectorResult<()> {
        self.send_message_to_channel(&self.config.default_channel, text)
            .await
    }

    /// Sends a simple text message to a specific channel.
    pub async fn send_message_to_channel(&self, channel: &str, text: &str) -> ConnectorResult<()> {
        if let Some(ref webhook_url) = self.config.webhook_url {
            let payload = serde_json::json!({
                "channel": channel,
                "text": text,
            });
            self.send_webhook(webhook_url, &payload).await
        } else {
            let payload = serde_json::json!({
                "channel": channel,
                "text": text,
            });
            let _response: serde_json::Value =
                self.client.post_json("/chat.postMessage", &payload).await?;
            Ok(())
        }
    }

    /// Sends a rich Block Kit message.
    pub async fn send_rich_message(&self, message: &SlackMessage) -> ConnectorResult<()> {
        if let Some(ref webhook_url) = self.config.webhook_url {
            self.send_webhook(webhook_url, message).await
        } else {
            let _response: serde_json::Value =
                self.client.post_json("/chat.postMessage", message).await?;
            Ok(())
        }
    }

    /// Builds an incident notification as Block Kit blocks.
    pub fn build_incident_notification(
        incident_id: &str,
        title: &str,
        severity: &str,
        summary: &str,
        verdict: Option<&str>,
        confidence: Option<f64>,
    ) -> Vec<SlackBlock> {
        let severity_emoji = match severity.to_lowercase().as_str() {
            "critical" => ":red_circle:",
            "high" => ":large_orange_circle:",
            "medium" => ":large_yellow_circle:",
            "low" => ":large_green_circle:",
            _ => ":white_circle:",
        };

        let mut blocks = vec![
            SlackBlock::Header {
                text: SlackTextObject::plain(format!("{} Security Incident", severity_emoji)),
            },
            SlackBlock::Section {
                text: SlackTextObject::mrkdwn(format!("*{}*\n{}", title, summary)),
                accessory: None,
                fields: Some(vec![
                    SlackTextObject::mrkdwn(format!("*Severity:*\n{}", severity)),
                    SlackTextObject::mrkdwn(format!("*Incident ID:*\n`{}`", incident_id)),
                ]),
            },
        ];

        if let Some(v) = verdict {
            let mut fields = vec![SlackTextObject::mrkdwn(format!("*Verdict:*\n{}", v))];
            if let Some(c) = confidence {
                fields.push(SlackTextObject::mrkdwn(format!(
                    "*Confidence:*\n{:.0}%",
                    c * 100.0
                )));
            }
            blocks.push(SlackBlock::Section {
                text: SlackTextObject::mrkdwn("*AI Analysis*"),
                accessory: None,
                fields: Some(fields),
            });
        }

        blocks.push(SlackBlock::Divider);
        blocks.push(SlackBlock::Context {
            elements: vec![SlackContextElement::Text(SlackTextObject::mrkdwn(
                "Sent by *Triage Warden*".to_string(),
            ))],
        });

        blocks
    }

    /// Builds interactive approve/reject action buttons.
    pub fn build_approval_actions(incident_id: &str, action_id: &str) -> Vec<SlackBlock> {
        vec![SlackBlock::Actions {
            elements: vec![
                SlackActionElement::Button {
                    text: SlackTextObject::plain("Approve"),
                    action_id: format!("tw_approve_{}_{}", incident_id, action_id),
                    value: Some(
                        serde_json::json!({
                            "incident_id": incident_id,
                            "action_id": action_id,
                            "decision": "approve"
                        })
                        .to_string(),
                    ),
                    style: Some("primary".to_string()),
                },
                SlackActionElement::Button {
                    text: SlackTextObject::plain("Reject"),
                    action_id: format!("tw_reject_{}_{}", incident_id, action_id),
                    value: Some(
                        serde_json::json!({
                            "incident_id": incident_id,
                            "action_id": action_id,
                            "decision": "reject"
                        })
                        .to_string(),
                    ),
                    style: Some("danger".to_string()),
                },
                SlackActionElement::Button {
                    text: SlackTextObject::plain("Escalate"),
                    action_id: format!("tw_escalate_{}", incident_id),
                    value: Some(
                        serde_json::json!({
                            "incident_id": incident_id,
                            "decision": "escalate"
                        })
                        .to_string(),
                    ),
                    style: None,
                },
            ],
        }]
    }

    /// Parses a slash command and returns a response.
    pub fn parse_slash_command(command: &SlackSlashCommand) -> SlackSlashResponse {
        let parts: Vec<&str> = command.text.split_whitespace().collect();
        let subcommand = parts.first().copied().unwrap_or("help");

        match subcommand {
            "incident" => {
                let incident_id = parts.get(1).copied().unwrap_or("(none)");
                SlackSlashResponse {
                    response_type: "ephemeral".to_string(),
                    text: Some(format!("Looking up incident: {}", incident_id)),
                    blocks: None,
                }
            }
            "approve" => {
                let action_id = parts.get(1).copied().unwrap_or("(none)");
                SlackSlashResponse {
                    response_type: "ephemeral".to_string(),
                    text: Some(format!("Approving action: {}", action_id)),
                    blocks: None,
                }
            }
            "escalate" => {
                let incident_id = parts.get(1).copied().unwrap_or("(none)");
                SlackSlashResponse {
                    response_type: "ephemeral".to_string(),
                    text: Some(format!("Escalating incident: {}", incident_id)),
                    blocks: None,
                }
            }
            _ => SlackSlashResponse {
                response_type: "ephemeral".to_string(),
                text: Some(
                    "Available commands: `/tw incident <id>`, `/tw approve <id>`, `/tw escalate <id>`"
                        .to_string(),
                ),
                blocks: None,
            },
        }
    }

    /// Sends a payload to a webhook URL.
    async fn send_webhook(
        &self,
        webhook_url: &str,
        payload: &impl Serialize,
    ) -> ConnectorResult<()> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| ConnectorError::ConfigError(e.to_string()))?;

        let response = client
            .post(webhook_url)
            .json(payload)
            .send()
            .await
            .map_err(|e| ConnectorError::RequestFailed(e.to_string()))?;

        if response.status().is_success() {
            Ok(())
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(ConnectorError::RequestFailed(format!(
                "Slack webhook returned {}: {}",
                status, body
            )))
        }
    }
}

#[async_trait]
impl crate::traits::Connector for SlackConnector {
    fn name(&self) -> &str {
        "slack"
    }

    fn connector_type(&self) -> &str {
        "collaboration"
    }

    async fn health_check(&self) -> ConnectorResult<ConnectorHealth> {
        if self.config.webhook_url.is_some() {
            // Webhook mode - no API to ping, assume healthy
            return Ok(ConnectorHealth::Healthy);
        }

        // Bot token mode - test with auth.test
        let response: serde_json::Value = self.client.get_json("/auth.test").await?;
        if response.get("ok").and_then(|v| v.as_bool()) == Some(true) {
            Ok(ConnectorHealth::Healthy)
        } else {
            let error = response
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error");
            Ok(ConnectorHealth::Unhealthy(error.to_string()))
        }
    }

    async fn test_connection(&self) -> ConnectorResult<bool> {
        match self.health_check().await? {
            ConnectorHealth::Healthy => Ok(true),
            _ => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_incident_notification_critical() {
        let blocks = SlackConnector::build_incident_notification(
            "INC-001",
            "Ransomware Detected",
            "critical",
            "Ransomware binary detected on workstation-001",
            Some("true_positive"),
            Some(0.95),
        );

        assert!(!blocks.is_empty());
        // Should have header, section with fields, analysis section, divider, context
        assert!(blocks.len() >= 4);

        // Verify header
        match &blocks[0] {
            SlackBlock::Header { text } => {
                assert!(text.text.contains(":red_circle:"));
            }
            _ => panic!("Expected header block"),
        }

        // Verify severity field
        match &blocks[1] {
            SlackBlock::Section { fields, .. } => {
                let fields = fields.as_ref().unwrap();
                assert!(fields.iter().any(|f| f.text.contains("critical")));
                assert!(fields.iter().any(|f| f.text.contains("INC-001")));
            }
            _ => panic!("Expected section block"),
        }
    }

    #[test]
    fn test_build_incident_notification_low_severity() {
        let blocks = SlackConnector::build_incident_notification(
            "INC-002",
            "Port Scan Detected",
            "low",
            "Port scan from external IP",
            None,
            None,
        );

        assert!(!blocks.is_empty());
        match &blocks[0] {
            SlackBlock::Header { text } => {
                assert!(text.text.contains(":large_green_circle:"));
            }
            _ => panic!("Expected header block"),
        }
    }

    #[test]
    fn test_build_approval_actions() {
        let blocks = SlackConnector::build_approval_actions("INC-001", "ACT-001");

        assert_eq!(blocks.len(), 1);
        match &blocks[0] {
            SlackBlock::Actions { elements } => {
                assert_eq!(elements.len(), 3);

                // Approve button
                match &elements[0] {
                    SlackActionElement::Button { text, style, .. } => {
                        assert_eq!(text.text, "Approve");
                        assert_eq!(style.as_deref(), Some("primary"));
                    }
                }

                // Reject button
                match &elements[1] {
                    SlackActionElement::Button { text, style, .. } => {
                        assert_eq!(text.text, "Reject");
                        assert_eq!(style.as_deref(), Some("danger"));
                    }
                }

                // Escalate button
                match &elements[2] {
                    SlackActionElement::Button { text, style, .. } => {
                        assert_eq!(text.text, "Escalate");
                        assert!(style.is_none());
                    }
                }
            }
            _ => panic!("Expected actions block"),
        }
    }

    #[test]
    fn test_parse_slash_command_incident() {
        let command = SlackSlashCommand {
            command: "/tw".to_string(),
            text: "incident INC-001".to_string(),
            user_id: "U123".to_string(),
            user_name: "analyst".to_string(),
            channel_id: "C456".to_string(),
            response_url: "https://hooks.slack.com/actions/xxx".to_string(),
            trigger_id: "T789".to_string(),
        };

        let response = SlackConnector::parse_slash_command(&command);
        assert_eq!(response.response_type, "ephemeral");
        assert!(response.text.unwrap().contains("INC-001"));
    }

    #[test]
    fn test_parse_slash_command_approve() {
        let command = SlackSlashCommand {
            command: "/tw".to_string(),
            text: "approve ACT-001".to_string(),
            user_id: "U123".to_string(),
            user_name: "analyst".to_string(),
            channel_id: "C456".to_string(),
            response_url: "https://hooks.slack.com/actions/xxx".to_string(),
            trigger_id: "T789".to_string(),
        };

        let response = SlackConnector::parse_slash_command(&command);
        assert!(response.text.unwrap().contains("ACT-001"));
    }

    #[test]
    fn test_parse_slash_command_help() {
        let command = SlackSlashCommand {
            command: "/tw".to_string(),
            text: "".to_string(),
            user_id: "U123".to_string(),
            user_name: "analyst".to_string(),
            channel_id: "C456".to_string(),
            response_url: "https://hooks.slack.com/actions/xxx".to_string(),
            trigger_id: "T789".to_string(),
        };

        let response = SlackConnector::parse_slash_command(&command);
        assert!(response.text.unwrap().contains("Available commands"));
    }

    #[test]
    fn test_slack_text_object_plain() {
        let text = SlackTextObject::plain("Hello");
        assert_eq!(text.text_type, "plain_text");
        assert_eq!(text.text, "Hello");
        assert_eq!(text.emoji, Some(true));
    }

    #[test]
    fn test_slack_text_object_mrkdwn() {
        let text = SlackTextObject::mrkdwn("*Bold*");
        assert_eq!(text.text_type, "mrkdwn");
        assert_eq!(text.text, "*Bold*");
        assert!(text.emoji.is_none());
    }

    #[test]
    fn test_slack_message_serialization() {
        let message = SlackMessage {
            channel: Some("#security".to_string()),
            text: Some("Test message".to_string()),
            blocks: None,
        };

        let json = serde_json::to_string(&message).unwrap();
        assert!(json.contains("#security"));
        assert!(json.contains("Test message"));
    }

    #[test]
    fn test_incident_notification_with_verdict() {
        let blocks = SlackConnector::build_incident_notification(
            "INC-003",
            "Phishing Email",
            "medium",
            "Phishing email detected",
            Some("true_positive"),
            Some(0.85),
        );

        // Should include analysis section with verdict and confidence
        let has_analysis = blocks.iter().any(|block| match block {
            SlackBlock::Section { fields, .. } => fields.as_ref().is_some_and(|fs| {
                fs.iter().any(|f| f.text.contains("true_positive"))
                    && fs.iter().any(|f| f.text.contains("85%"))
            }),
            _ => false,
        });
        assert!(has_analysis);
    }
}
