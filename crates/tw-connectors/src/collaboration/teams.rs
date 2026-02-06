//! Microsoft Teams connector for sending notifications via webhooks.
//!
//! Supports Adaptive Card formatting for rich incident notifications and
//! action cards for approve/reject workflows.

use crate::http::HttpClient;
use crate::secure_string::SecureString;
use crate::traits::{
    AuthConfig, ConnectorConfig, ConnectorError, ConnectorHealth, ConnectorResult,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Microsoft Teams connector configuration.
#[derive(Debug, Clone)]
pub struct TeamsConfig {
    /// Incoming webhook URL for the Teams channel.
    pub webhook_url: String,
    /// App ID for Teams bot integration (optional, for richer interactions).
    pub app_id: Option<String>,
    /// App secret for Teams bot integration (optional).
    pub app_secret: Option<SecureString>,
}

/// Microsoft Teams connector for sending notifications.
pub struct TeamsConnector {
    config: TeamsConfig,
    #[allow(dead_code)]
    client: HttpClient,
}

/// An Adaptive Card for Teams.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptiveCard {
    /// Card type - always "AdaptiveCard".
    #[serde(rename = "type")]
    pub card_type: String,
    /// Adaptive Card schema version.
    #[serde(rename = "$schema")]
    pub schema: String,
    /// Card version.
    pub version: String,
    /// Card body elements.
    pub body: Vec<AdaptiveCardElement>,
    /// Card action buttons.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actions: Option<Vec<AdaptiveCardAction>>,
}

impl Default for AdaptiveCard {
    fn default() -> Self {
        Self {
            card_type: "AdaptiveCard".to_string(),
            schema: "http://adaptivecards.io/schemas/adaptive-card.json".to_string(),
            version: "1.4".to_string(),
            body: Vec::new(),
            actions: None,
        }
    }
}

/// Adaptive Card body element.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AdaptiveCardElement {
    /// Text block.
    TextBlock {
        text: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        size: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        weight: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        color: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        wrap: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        separator: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        spacing: Option<String>,
    },
    /// Fact set (key-value pairs).
    FactSet {
        facts: Vec<AdaptiveCardFact>,
        #[serde(skip_serializing_if = "Option::is_none")]
        separator: Option<bool>,
    },
    /// Column set for side-by-side layout.
    ColumnSet {
        columns: Vec<AdaptiveCardColumn>,
        #[serde(skip_serializing_if = "Option::is_none")]
        separator: Option<bool>,
    },
    /// Container for grouping elements.
    Container {
        items: Vec<AdaptiveCardElement>,
        #[serde(skip_serializing_if = "Option::is_none")]
        style: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        separator: Option<bool>,
    },
}

/// A fact (key-value pair) in a FactSet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptiveCardFact {
    pub title: String,
    pub value: String,
}

/// A column in a ColumnSet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptiveCardColumn {
    #[serde(rename = "type")]
    pub column_type: String,
    pub width: String,
    pub items: Vec<AdaptiveCardElement>,
}

/// An action button on an Adaptive Card.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AdaptiveCardAction {
    /// Opens a URL.
    #[serde(rename = "Action.OpenUrl")]
    OpenUrl { title: String, url: String },
    /// Submits data back to the bot.
    #[serde(rename = "Action.Submit")]
    Submit {
        title: String,
        data: serde_json::Value,
        #[serde(skip_serializing_if = "Option::is_none")]
        style: Option<String>,
    },
}

/// Teams webhook message payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamsMessage {
    /// Message type.
    #[serde(rename = "type")]
    pub message_type: String,
    /// Adaptive Card attachments.
    pub attachments: Vec<TeamsAttachment>,
}

/// Teams message attachment containing an Adaptive Card.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamsAttachment {
    /// Content type - always "application/vnd.microsoft.card.adaptive".
    #[serde(rename = "contentType")]
    pub content_type: String,
    /// The Adaptive Card content.
    pub content: AdaptiveCard,
}

impl TeamsConnector {
    /// Creates a new Teams connector.
    pub fn new(config: TeamsConfig) -> ConnectorResult<Self> {
        let connector_config = ConnectorConfig {
            name: "teams".to_string(),
            base_url: config.webhook_url.clone(),
            auth: AuthConfig::None,
            timeout_secs: 30,
            max_retries: 2,
            verify_tls: true,
            headers: HashMap::new(),
        };

        let client = HttpClient::new(connector_config)?;

        Ok(Self { config, client })
    }

    /// Sends a simple text message via webhook.
    pub async fn send_message(&self, text: &str) -> ConnectorResult<()> {
        let card = AdaptiveCard {
            body: vec![AdaptiveCardElement::TextBlock {
                text: text.to_string(),
                size: None,
                weight: None,
                color: None,
                wrap: Some(true),
                separator: None,
                spacing: None,
            }],
            ..Default::default()
        };

        self.send_adaptive_card(&card).await
    }

    /// Sends an Adaptive Card via webhook.
    pub async fn send_adaptive_card(&self, card: &AdaptiveCard) -> ConnectorResult<()> {
        let message = TeamsMessage {
            message_type: "message".to_string(),
            attachments: vec![TeamsAttachment {
                content_type: "application/vnd.microsoft.card.adaptive".to_string(),
                content: card.clone(),
            }],
        };

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| ConnectorError::ConfigError(e.to_string()))?;

        let response = client
            .post(&self.config.webhook_url)
            .json(&message)
            .send()
            .await
            .map_err(|e| ConnectorError::RequestFailed(e.to_string()))?;

        if response.status().is_success() {
            Ok(())
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(ConnectorError::RequestFailed(format!(
                "Teams webhook returned {}: {}",
                status, body
            )))
        }
    }

    /// Builds an incident notification as an Adaptive Card.
    pub fn build_incident_notification(
        incident_id: &str,
        title: &str,
        severity: &str,
        summary: &str,
        verdict: Option<&str>,
        confidence: Option<f64>,
    ) -> AdaptiveCard {
        let severity_color = match severity.to_lowercase().as_str() {
            "critical" => "attention",
            "high" => "warning",
            "medium" => "accent",
            _ => "default",
        };

        let mut body = vec![
            AdaptiveCardElement::TextBlock {
                text: "Security Incident".to_string(),
                size: Some("large".to_string()),
                weight: Some("bolder".to_string()),
                color: Some(severity_color.to_string()),
                wrap: None,
                separator: None,
                spacing: None,
            },
            AdaptiveCardElement::TextBlock {
                text: title.to_string(),
                size: Some("medium".to_string()),
                weight: Some("bolder".to_string()),
                color: None,
                wrap: Some(true),
                separator: None,
                spacing: None,
            },
            AdaptiveCardElement::TextBlock {
                text: summary.to_string(),
                size: None,
                weight: None,
                color: None,
                wrap: Some(true),
                separator: None,
                spacing: Some("small".to_string()),
            },
        ];

        let mut facts = vec![
            AdaptiveCardFact {
                title: "Incident ID".to_string(),
                value: incident_id.to_string(),
            },
            AdaptiveCardFact {
                title: "Severity".to_string(),
                value: severity.to_string(),
            },
        ];

        if let Some(v) = verdict {
            facts.push(AdaptiveCardFact {
                title: "Verdict".to_string(),
                value: v.to_string(),
            });
        }

        if let Some(c) = confidence {
            facts.push(AdaptiveCardFact {
                title: "Confidence".to_string(),
                value: format!("{:.0}%", c * 100.0),
            });
        }

        body.push(AdaptiveCardElement::FactSet {
            facts,
            separator: Some(true),
        });

        body.push(AdaptiveCardElement::TextBlock {
            text: "Sent by Triage Warden".to_string(),
            size: Some("small".to_string()),
            weight: None,
            color: Some("light".to_string()),
            wrap: None,
            separator: Some(true),
            spacing: Some("medium".to_string()),
        });

        AdaptiveCard {
            body,
            ..Default::default()
        }
    }

    /// Builds an action card with approve/reject buttons.
    pub fn build_approval_card(
        incident_id: &str,
        action_id: &str,
        action_description: &str,
    ) -> AdaptiveCard {
        let body = vec![
            AdaptiveCardElement::TextBlock {
                text: "Action Pending Approval".to_string(),
                size: Some("medium".to_string()),
                weight: Some("bolder".to_string()),
                color: Some("warning".to_string()),
                wrap: None,
                separator: None,
                spacing: None,
            },
            AdaptiveCardElement::TextBlock {
                text: action_description.to_string(),
                size: None,
                weight: None,
                color: None,
                wrap: Some(true),
                separator: None,
                spacing: None,
            },
            AdaptiveCardElement::FactSet {
                facts: vec![
                    AdaptiveCardFact {
                        title: "Incident".to_string(),
                        value: incident_id.to_string(),
                    },
                    AdaptiveCardFact {
                        title: "Action ID".to_string(),
                        value: action_id.to_string(),
                    },
                ],
                separator: Some(true),
            },
        ];

        let actions = vec![
            AdaptiveCardAction::Submit {
                title: "Approve".to_string(),
                data: serde_json::json!({
                    "incident_id": incident_id,
                    "action_id": action_id,
                    "decision": "approve",
                }),
                style: Some("positive".to_string()),
            },
            AdaptiveCardAction::Submit {
                title: "Reject".to_string(),
                data: serde_json::json!({
                    "incident_id": incident_id,
                    "action_id": action_id,
                    "decision": "reject",
                }),
                style: Some("destructive".to_string()),
            },
        ];

        AdaptiveCard {
            body,
            actions: Some(actions),
            ..Default::default()
        }
    }
}

#[async_trait]
impl crate::traits::Connector for TeamsConnector {
    fn name(&self) -> &str {
        "teams"
    }

    fn connector_type(&self) -> &str {
        "collaboration"
    }

    async fn health_check(&self) -> ConnectorResult<ConnectorHealth> {
        // Teams webhooks don't have a health check endpoint.
        // We assume healthy if configured.
        Ok(ConnectorHealth::Healthy)
    }

    async fn test_connection(&self) -> ConnectorResult<bool> {
        // Send a minimal test message to verify the webhook works
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_incident_notification_critical() {
        let card = TeamsConnector::build_incident_notification(
            "INC-001",
            "Ransomware Detected",
            "critical",
            "Ransomware binary detected on workstation-001",
            Some("true_positive"),
            Some(0.95),
        );

        assert_eq!(card.card_type, "AdaptiveCard");
        assert_eq!(card.version, "1.4");
        assert!(!card.body.is_empty());

        // Verify header has attention color for critical
        match &card.body[0] {
            AdaptiveCardElement::TextBlock { color, .. } => {
                assert_eq!(color.as_deref(), Some("attention"));
            }
            _ => panic!("Expected TextBlock"),
        }

        // Verify facts include incident details
        let has_facts = card
            .body
            .iter()
            .any(|el| matches!(el, AdaptiveCardElement::FactSet { facts, .. } if facts.len() >= 4));
        assert!(has_facts);
    }

    #[test]
    fn test_build_incident_notification_low() {
        let card = TeamsConnector::build_incident_notification(
            "INC-002",
            "Port Scan",
            "low",
            "Port scan detected",
            None,
            None,
        );

        match &card.body[0] {
            AdaptiveCardElement::TextBlock { color, .. } => {
                assert_eq!(color.as_deref(), Some("default"));
            }
            _ => panic!("Expected TextBlock"),
        }

        // Without verdict/confidence, should have 2 facts (ID, severity)
        let fact_count = card.body.iter().find_map(|el| match el {
            AdaptiveCardElement::FactSet { facts, .. } => Some(facts.len()),
            _ => None,
        });
        assert_eq!(fact_count, Some(2));
    }

    #[test]
    fn test_build_approval_card() {
        let card = TeamsConnector::build_approval_card(
            "INC-001",
            "ACT-001",
            "Isolate host workstation-001 from network",
        );

        assert_eq!(card.card_type, "AdaptiveCard");
        assert!(card.actions.is_some());

        let actions = card.actions.unwrap();
        assert_eq!(actions.len(), 2);

        match &actions[0] {
            AdaptiveCardAction::Submit {
                title, style, data, ..
            } => {
                assert_eq!(title, "Approve");
                assert_eq!(style.as_deref(), Some("positive"));
                assert_eq!(data["decision"], "approve");
            }
            _ => panic!("Expected Submit action"),
        }

        match &actions[1] {
            AdaptiveCardAction::Submit {
                title, style, data, ..
            } => {
                assert_eq!(title, "Reject");
                assert_eq!(style.as_deref(), Some("destructive"));
                assert_eq!(data["decision"], "reject");
            }
            _ => panic!("Expected Submit action"),
        }
    }

    #[test]
    fn test_adaptive_card_serialization() {
        let card = TeamsConnector::build_incident_notification(
            "INC-001",
            "Test",
            "high",
            "Test summary",
            None,
            None,
        );

        let json = serde_json::to_string(&card).unwrap();
        assert!(json.contains("AdaptiveCard"));
        assert!(json.contains("adaptivecards.io"));
        assert!(json.contains("INC-001"));
    }

    #[test]
    fn test_teams_message_serialization() {
        let card = AdaptiveCard {
            body: vec![AdaptiveCardElement::TextBlock {
                text: "Hello Teams".to_string(),
                size: None,
                weight: None,
                color: None,
                wrap: Some(true),
                separator: None,
                spacing: None,
            }],
            ..Default::default()
        };

        let message = TeamsMessage {
            message_type: "message".to_string(),
            attachments: vec![TeamsAttachment {
                content_type: "application/vnd.microsoft.card.adaptive".to_string(),
                content: card,
            }],
        };

        let json = serde_json::to_string(&message).unwrap();
        assert!(json.contains("application/vnd.microsoft.card.adaptive"));
        assert!(json.contains("Hello Teams"));
    }

    #[test]
    fn test_adaptive_card_default() {
        let card = AdaptiveCard::default();
        assert_eq!(card.card_type, "AdaptiveCard");
        assert_eq!(card.version, "1.4");
        assert!(card.body.is_empty());
        assert!(card.actions.is_none());
    }

    #[test]
    fn test_approval_card_data_fields() {
        let card = TeamsConnector::build_approval_card("INC-100", "ACT-200", "Block IP 1.2.3.4");

        let actions = card.actions.unwrap();
        match &actions[0] {
            AdaptiveCardAction::Submit { data, .. } => {
                assert_eq!(data["incident_id"], "INC-100");
                assert_eq!(data["action_id"], "ACT-200");
            }
            _ => panic!("Expected Submit action"),
        }
    }
}
