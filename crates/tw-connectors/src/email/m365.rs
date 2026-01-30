//! Microsoft 365 Email Gateway connector.
//!
//! This module provides integration with Microsoft Graph API for email
//! management, threat investigation, and security operations.

use crate::http::{HttpClient, RateLimitConfig};
use crate::traits::{
    ActionResult, ConnectorConfig, ConnectorError, ConnectorHealth, ConnectorResult,
    EmailAttachment, EmailGatewayConnector, EmailMessage, EmailSearchQuery, EmailThreatData,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use tracing::{debug, info, instrument, warn};

/// Microsoft 365-specific configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct M365Config {
    /// Base connector configuration.
    #[serde(flatten)]
    pub connector: ConnectorConfig,
    /// Azure AD tenant ID.
    pub tenant_id: String,
    /// Target user/mailbox for searches (or "all" for org-wide via Search API).
    pub target_mailbox: Option<String>,
    /// Use Security & Compliance Center for advanced threat data.
    #[serde(default)]
    pub use_security_center: bool,
}

/// Microsoft 365 Email Gateway connector.
pub struct M365Connector {
    config: M365Config,
    client: HttpClient,
}

impl M365Connector {
    /// Creates a new M365 connector.
    pub fn new(config: M365Config) -> ConnectorResult<Self> {
        // Microsoft Graph rate limits vary by endpoint
        // Using conservative limits: ~120 requests/minute for most endpoints
        let rate_limit = RateLimitConfig {
            max_requests: 120,
            period: Duration::from_secs(60),
            burst_size: 20,
        };

        // Ensure base URL is Graph API
        let mut connector_config = config.connector.clone();
        if connector_config.base_url.is_empty() {
            connector_config.base_url = "https://graph.microsoft.com/v1.0".to_string();
        }

        let client = HttpClient::with_rate_limit(connector_config, Some(rate_limit))?;

        info!(
            "M365 connector initialized for tenant '{}'",
            config.tenant_id
        );

        Ok(Self { config, client })
    }

    /// Gets the target mailbox path.
    fn mailbox_path(&self) -> String {
        match &self.config.target_mailbox {
            Some(mailbox) if mailbox != "all" => format!("/users/{}", mailbox),
            _ => "/me".to_string(),
        }
    }

    /// Builds an OData filter for email search.
    fn build_email_filter(&self, query: &EmailSearchQuery) -> String {
        let mut filters: Vec<String> = Vec::new();

        // Time range filter
        filters.push(format!(
            "receivedDateTime ge {} and receivedDateTime le {}",
            query.timerange.start.format("%Y-%m-%dT%H:%M:%SZ"),
            query.timerange.end.format("%Y-%m-%dT%H:%M:%SZ")
        ));

        // Sender filter
        if let Some(sender) = &query.sender {
            filters.push(format!("from/emailAddress/address eq '{}'", escape_odata(sender)));
        }

        // Has attachments filter
        if let Some(has_attachments) = query.has_attachments {
            filters.push(format!("hasAttachments eq {}", has_attachments));
        }

        filters.join(" and ")
    }

    /// Parses a Graph API message into EmailMessage.
    fn parse_message(&self, msg: &GraphMessage) -> EmailMessage {
        let received_at = msg
            .received_date_time
            .as_ref()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);

        let sender = msg
            .from
            .as_ref()
            .and_then(|f| f.email_address.as_ref())
            .map(|e| e.formatted())
            .unwrap_or_default();

        let recipients: Vec<String> = msg
            .to_recipients
            .as_ref()
            .map(|r| {
                r.iter()
                    .filter_map(|r| r.email_address.as_ref())
                    .map(|e| e.formatted())
                    .collect()
            })
            .unwrap_or_default();

        let attachments: Vec<EmailAttachment> = msg
            .attachments
            .as_ref()
            .map(|a| {
                a.iter()
                    .map(|att| EmailAttachment {
                        id: att.id.clone().unwrap_or_default(),
                        name: att.name.clone().unwrap_or_default(),
                        content_type: att.content_type.clone().unwrap_or_default(),
                        size: att.size.unwrap_or(0) as u64,
                        sha256: None, // Graph API doesn't provide hashes directly
                    })
                    .collect()
            })
            .unwrap_or_default();

        // Extract URLs from body (basic implementation)
        let urls = extract_urls_from_body(msg.body.as_ref().and_then(|b| b.text_content()));

        // Build headers from available fields
        let mut headers = HashMap::new();
        if let Some(headers_list) = &msg.internet_message_headers {
            for header in headers_list {
                if let (Some(name), Some(value)) = (&header.name, &header.value) {
                    headers.insert(name.clone(), value.clone());
                }
            }
        }

        EmailMessage {
            id: msg.id.clone().unwrap_or_default(),
            internet_message_id: msg.internet_message_id.clone().unwrap_or_default(),
            sender,
            recipients,
            subject: msg.subject.clone().unwrap_or_default(),
            received_at,
            has_attachments: msg.has_attachments.unwrap_or(false),
            attachments,
            urls,
            headers,
            threat_assessment: None, // Populated separately if needed
        }
    }

    /// Gets email with full details including headers.
    async fn get_message_with_headers(&self, message_id: &str) -> ConnectorResult<GraphMessage> {
        let path = format!(
            "{}/messages/{}?$expand=attachments&$select=id,subject,from,toRecipients,receivedDateTime,hasAttachments,body,internetMessageId,internetMessageHeaders",
            self.mailbox_path(),
            message_id
        );

        let response = self.client.get(&path).await?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(ConnectorError::NotFound(format!(
                "Message not found: {}",
                message_id
            )));
        }

        if !response.status().is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ConnectorError::RequestFailed(format!(
                "Failed to get message: {}",
                body
            )));
        }

        let msg: GraphMessage = response
            .json()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(format!("Failed to parse message: {}", e)))?;

        Ok(msg)
    }
}

#[async_trait]
impl crate::traits::Connector for M365Connector {
    fn name(&self) -> &str {
        &self.config.connector.name
    }

    fn connector_type(&self) -> &str {
        "email_gateway"
    }

    async fn health_check(&self) -> ConnectorResult<ConnectorHealth> {
        // Check by getting user profile or org info
        let path = "/organization";
        match self.client.get(path).await {
            Ok(response) if response.status().is_success() => Ok(ConnectorHealth::Healthy),
            Ok(response) if response.status().as_u16() == 401 => {
                Ok(ConnectorHealth::Unhealthy("Authentication failed".to_string()))
            }
            Ok(response) if response.status().as_u16() == 403 => {
                Ok(ConnectorHealth::Unhealthy("Authorization denied - check permissions".to_string()))
            }
            Ok(response) if response.status().as_u16() == 429 => {
                Ok(ConnectorHealth::Degraded("Rate limited".to_string()))
            }
            Ok(response) => Ok(ConnectorHealth::Degraded(format!(
                "Unexpected status: {}",
                response.status()
            ))),
            Err(ConnectorError::ConnectionFailed(e)) => {
                Ok(ConnectorHealth::Unhealthy(format!("Connection failed: {}", e)))
            }
            Err(e) => Ok(ConnectorHealth::Unhealthy(e.to_string())),
        }
    }

    async fn test_connection(&self) -> ConnectorResult<bool> {
        let path = "/organization";
        let response = self.client.get(path).await?;
        Ok(response.status().is_success())
    }
}

#[async_trait]
impl EmailGatewayConnector for M365Connector {
    #[instrument(skip(self))]
    async fn search_emails(&self, query: EmailSearchQuery) -> ConnectorResult<Vec<EmailMessage>> {
        let filter = self.build_email_filter(&query);

        // Build search request
        let mut path = format!(
            "{}/messages?$filter={}&$top={}&$orderby=receivedDateTime desc&$select=id,subject,from,toRecipients,receivedDateTime,hasAttachments,internetMessageId",
            self.mailbox_path(),
            urlencoding::encode(&filter),
            query.limit
        );

        // Add subject search if specified
        if let Some(subject) = &query.subject_contains {
            // Use $search for subject contains
            path = format!(
                "{}/messages?$search=\"subject:{}\"&$top={}&$orderby=receivedDateTime desc&$select=id,subject,from,toRecipients,receivedDateTime,hasAttachments,internetMessageId",
                self.mailbox_path(),
                urlencoding::encode(subject),
                query.limit
            );
        }

        let response = self.client.get(&path).await?;

        if !response.status().is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ConnectorError::RequestFailed(format!(
                "Failed to search emails: {}",
                body
            )));
        }

        let result: GraphMessagesResponse = response
            .json()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(format!("Failed to parse response: {}", e)))?;

        let messages: Vec<EmailMessage> = result
            .value
            .iter()
            .map(|m| self.parse_message(m))
            .collect();

        debug!("Found {} emails matching query", messages.len());
        Ok(messages)
    }

    #[instrument(skip(self), fields(message_id = %message_id))]
    async fn get_email(&self, message_id: &str) -> ConnectorResult<EmailMessage> {
        let msg = self.get_message_with_headers(message_id).await?;
        Ok(self.parse_message(&msg))
    }

    #[instrument(skip(self), fields(message_id = %message_id))]
    async fn quarantine_email(&self, message_id: &str) -> ConnectorResult<ActionResult> {
        // Move message to Junk Email folder
        let path = format!("{}/messages/{}/move", self.mailbox_path(), message_id);
        let body = serde_json::json!({
            "destinationId": "junkemail"
        });

        let response = self.client.post(&path, &body).await?;

        if !response.status().is_success() {
            let error = response.text().await.unwrap_or_default();
            return Err(ConnectorError::RequestFailed(format!(
                "Failed to quarantine email: {}",
                error
            )));
        }

        info!("Quarantined email: {}", message_id);

        Ok(ActionResult {
            success: true,
            action_id: format!("quarantine-{}", message_id),
            message: format!("Email {} moved to quarantine", message_id),
            timestamp: Utc::now(),
        })
    }

    #[instrument(skip(self), fields(message_id = %message_id))]
    async fn release_email(&self, message_id: &str) -> ConnectorResult<ActionResult> {
        // Move message back to Inbox
        let path = format!("{}/messages/{}/move", self.mailbox_path(), message_id);
        let body = serde_json::json!({
            "destinationId": "inbox"
        });

        let response = self.client.post(&path, &body).await?;

        if !response.status().is_success() {
            let error = response.text().await.unwrap_or_default();
            return Err(ConnectorError::RequestFailed(format!(
                "Failed to release email: {}",
                error
            )));
        }

        info!("Released email from quarantine: {}", message_id);

        Ok(ActionResult {
            success: true,
            action_id: format!("release-{}", message_id),
            message: format!("Email {} moved to inbox", message_id),
            timestamp: Utc::now(),
        })
    }

    #[instrument(skip(self), fields(sender = %sender))]
    async fn block_sender(&self, sender: &str) -> ConnectorResult<ActionResult> {
        // Note: Blocking senders in M365 requires Exchange Online PowerShell or
        // Security & Compliance Center. For now, we add to junk email rules.
        let path = format!("{}/mailFolders/junkemail/messageRules", self.mailbox_path());
        let body = serde_json::json!({
            "displayName": format!("Block sender: {}", sender),
            "sequence": 1,
            "conditions": {
                "senderContains": [sender]
            },
            "actions": {
                "moveToFolder": "deleteditems",
                "stopProcessingRules": true
            }
        });

        let response = self.client.post(&path, &body).await?;

        // Note: This endpoint might not be available for all M365 configurations
        if !response.status().is_success() {
            warn!(
                "Could not create mail rule to block sender. Consider using Security & Compliance Center."
            );
            return Err(ConnectorError::RequestFailed(format!(
                "Failed to block sender: {} - Consider using Security & Compliance Center",
                sender
            )));
        }

        info!("Blocked sender: {}", sender);

        Ok(ActionResult {
            success: true,
            action_id: format!("block-{}", sender),
            message: format!("Sender {} blocked", sender),
            timestamp: Utc::now(),
        })
    }

    #[instrument(skip(self), fields(sender = %sender))]
    async fn unblock_sender(&self, sender: &str) -> ConnectorResult<ActionResult> {
        // List rules and find the one blocking this sender
        let path = format!("{}/mailFolders/inbox/messageRules", self.mailbox_path());
        let response = self.client.get(&path).await?;

        if !response.status().is_success() {
            let error = response.text().await.unwrap_or_default();
            return Err(ConnectorError::RequestFailed(format!(
                "Failed to list mail rules: {}",
                error
            )));
        }

        let rules: GraphRulesResponse = response
            .json()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(format!("Failed to parse rules: {}", e)))?;

        // Find rule that blocks this sender
        let rule_id = rules.value.iter().find_map(|r| {
            let display_name = r.display_name.as_deref().unwrap_or("");
            if display_name.contains(&format!("Block sender: {}", sender)) {
                r.id.clone()
            } else {
                None
            }
        });

        match rule_id {
            Some(id) => {
                let delete_path = format!(
                    "{}/mailFolders/inbox/messageRules/{}",
                    self.mailbox_path(),
                    id
                );
                let response = self.client.delete(&delete_path).await?;

                if !response.status().is_success() {
                    let error = response.text().await.unwrap_or_default();
                    return Err(ConnectorError::RequestFailed(format!(
                        "Failed to delete block rule: {}",
                        error
                    )));
                }

                info!("Unblocked sender: {}", sender);

                Ok(ActionResult {
                    success: true,
                    action_id: format!("unblock-{}", sender),
                    message: format!("Sender {} unblocked", sender),
                    timestamp: Utc::now(),
                })
            }
            None => Err(ConnectorError::NotFound(format!(
                "No block rule found for sender: {}",
                sender
            ))),
        }
    }

    #[instrument(skip(self), fields(message_id = %message_id))]
    async fn get_threat_data(&self, message_id: &str) -> ConnectorResult<EmailThreatData> {
        if !self.config.use_security_center {
            // Return basic threat data without Security Center
            return Ok(EmailThreatData {
                delivery_action: "Delivered".to_string(),
                threat_types: Vec::new(),
                detection_methods: Vec::new(),
                urls_clicked: Vec::new(),
            });
        }

        // Query Security API for threat data
        // Note: This requires additional permissions and might need different auth
        let path = format!(
            "/security/alerts?$filter=contains(description, '{}')",
            message_id
        );

        let response = self.client.get(&path).await?;

        if !response.status().is_success() {
            debug!(
                "No security alerts found for message {}",
                message_id
            );
            return Ok(EmailThreatData {
                delivery_action: "Unknown".to_string(),
                threat_types: Vec::new(),
                detection_methods: Vec::new(),
                urls_clicked: Vec::new(),
            });
        }

        let alerts: GraphSecurityAlertsResponse = response
            .json()
            .await
            .map_err(|e| {
                debug!("Failed to parse security alerts: {}", e);
                ConnectorError::InvalidResponse(format!("Failed to parse security alerts: {}", e))
            })?;

        // Log alert IDs for correlation
        let alert_ids: Vec<&str> = alerts
            .value
            .iter()
            .filter_map(|a| a.id.as_deref())
            .collect();
        if !alert_ids.is_empty() {
            debug!("Found {} security alerts for message: {:?}", alert_ids.len(), alert_ids);
        }

        let threat_types: Vec<String> = alerts
            .value
            .iter()
            .filter_map(|a| a.category.clone())
            .collect();

        let detection_methods: Vec<String> = alerts
            .value
            .iter()
            .filter_map(|a| a.detection_source.clone())
            .collect();

        Ok(EmailThreatData {
            delivery_action: if threat_types.is_empty() {
                "Delivered".to_string()
            } else {
                "Blocked".to_string()
            },
            threat_types,
            detection_methods,
            urls_clicked: Vec::new(), // Would need additional API calls
        })
    }
}

// Graph API response types

#[derive(Debug, Deserialize)]
struct GraphMessagesResponse {
    #[serde(default)]
    value: Vec<GraphMessage>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GraphMessage {
    id: Option<String>,
    subject: Option<String>,
    from: Option<GraphEmailRecipient>,
    to_recipients: Option<Vec<GraphEmailRecipient>>,
    received_date_time: Option<String>,
    has_attachments: Option<bool>,
    internet_message_id: Option<String>,
    body: Option<GraphBody>,
    attachments: Option<Vec<GraphAttachment>>,
    internet_message_headers: Option<Vec<GraphHeader>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GraphEmailRecipient {
    email_address: Option<GraphEmailAddress>,
}

#[derive(Debug, Deserialize)]
struct GraphEmailAddress {
    address: String,
    name: Option<String>,
}

impl GraphEmailAddress {
    /// Returns formatted email with name if available.
    fn formatted(&self) -> String {
        match &self.name {
            Some(name) if !name.is_empty() => format!("{} <{}>", name, self.address),
            _ => self.address.clone(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GraphBody {
    #[allow(dead_code)] // Part of API response, may be used for content type detection
    content_type: Option<String>,
    content: Option<String>,
}

impl GraphBody {
    /// Returns the content.
    fn text_content(&self) -> Option<&str> {
        self.content.as_deref()
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GraphAttachment {
    id: Option<String>,
    name: Option<String>,
    content_type: Option<String>,
    size: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct GraphHeader {
    name: Option<String>,
    value: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GraphRulesResponse {
    #[serde(default)]
    value: Vec<GraphRule>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GraphRule {
    id: Option<String>,
    display_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GraphSecurityAlertsResponse {
    #[serde(default)]
    value: Vec<GraphSecurityAlert>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GraphSecurityAlert {
    id: Option<String>,
    category: Option<String>,
    detection_source: Option<String>,
}

/// Escapes special characters for OData filter.
fn escape_odata(value: &str) -> String {
    value.replace("'", "''")
}

/// Extracts URLs from email body content.
fn extract_urls_from_body(content: Option<&str>) -> Vec<String> {
    let Some(content) = content else {
        return Vec::new();
    };

    // Simple URL extraction using regex pattern
    let url_pattern = regex::Regex::new(
        r#"https?://[^\s<>"'{}|\[\]^`\\]+"#
    ).ok();

    url_pattern
        .map(|re| {
            re.find_iter(content)
                .map(|m| m.as_str().to_string())
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::AuthConfig;

    fn create_test_config() -> M365Config {
        M365Config {
            connector: ConnectorConfig {
                name: "m365-test".to_string(),
                base_url: "https://graph.microsoft.com/v1.0".to_string(),
                auth: AuthConfig::OAuth2 {
                    client_id: "test-client-id".to_string(),
                    client_secret: "test-client-secret".to_string(),
                    token_url: "https://login.microsoftonline.com/test-tenant/oauth2/v2.0/token"
                        .to_string(),
                    scopes: vec!["https://graph.microsoft.com/.default".to_string()],
                },
                timeout_secs: 30,
                max_retries: 3,
                verify_tls: true,
                headers: HashMap::new(),
            },
            tenant_id: "test-tenant".to_string(),
            target_mailbox: Some("security@contoso.com".to_string()),
            use_security_center: false,
        }
    }

    #[test]
    fn test_mailbox_path() {
        let config = create_test_config();
        let connector = M365Connector::new(config).unwrap();
        assert_eq!(connector.mailbox_path(), "/users/security@contoso.com");
    }

    #[test]
    fn test_mailbox_path_all() {
        let mut config = create_test_config();
        config.target_mailbox = Some("all".to_string());
        let connector = M365Connector::new(config).unwrap();
        assert_eq!(connector.mailbox_path(), "/me");
    }

    #[test]
    fn test_escape_odata() {
        assert_eq!(escape_odata("test"), "test");
        assert_eq!(escape_odata("it's"), "it''s");
        assert_eq!(escape_odata("test'value'here"), "test''value''here");
    }

    #[test]
    fn test_extract_urls() {
        let content = "Check out https://example.com and http://test.org/page for more info.";
        let urls = extract_urls_from_body(Some(content));
        assert_eq!(urls.len(), 2);
        assert!(urls.contains(&"https://example.com".to_string()));
        assert!(urls.contains(&"http://test.org/page".to_string()));
    }

    #[test]
    fn test_extract_urls_empty() {
        let urls = extract_urls_from_body(None);
        assert!(urls.is_empty());
    }

    #[test]
    fn test_connector_creation() {
        let config = create_test_config();
        let connector = M365Connector::new(config);
        assert!(connector.is_ok());
    }

    #[test]
    fn test_build_email_filter() {
        use crate::traits::TimeRange;

        let config = create_test_config();
        let connector = M365Connector::new(config).unwrap();

        let query = EmailSearchQuery {
            sender: Some("attacker@evil.com".to_string()),
            recipient: None,
            subject_contains: None,
            timerange: TimeRange::last_hours(24),
            has_attachments: Some(true),
            threat_type: None,
            limit: 100,
        };

        let filter = connector.build_email_filter(&query);
        assert!(filter.contains("receivedDateTime ge"));
        assert!(filter.contains("receivedDateTime le"));
        assert!(filter.contains("from/emailAddress/address eq 'attacker@evil.com'"));
        assert!(filter.contains("hasAttachments eq true"));
    }
}
