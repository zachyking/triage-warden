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
            filters.push(format!(
                "from/emailAddress/address eq '{}'",
                escape_odata(sender)
            ));
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

        let msg: GraphMessage = response.json().await.map_err(|e| {
            ConnectorError::InvalidResponse(format!("Failed to parse message: {}", e))
        })?;

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
            Ok(response) if response.status().as_u16() == 401 => Ok(ConnectorHealth::Unhealthy(
                "Authentication failed".to_string(),
            )),
            Ok(response) if response.status().as_u16() == 403 => Ok(ConnectorHealth::Unhealthy(
                "Authorization denied - check permissions".to_string(),
            )),
            Ok(response) if response.status().as_u16() == 429 => {
                Ok(ConnectorHealth::Degraded("Rate limited".to_string()))
            }
            Ok(response) => Ok(ConnectorHealth::Degraded(format!(
                "Unexpected status: {}",
                response.status()
            ))),
            Err(ConnectorError::ConnectionFailed(e)) => Ok(ConnectorHealth::Unhealthy(format!(
                "Connection failed: {}",
                e
            ))),
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

        let result: GraphMessagesResponse = response.json().await.map_err(|e| {
            ConnectorError::InvalidResponse(format!("Failed to parse response: {}", e))
        })?;

        let messages: Vec<EmailMessage> =
            result.value.iter().map(|m| self.parse_message(m)).collect();

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
        if self.config.use_security_center {
            // Use Security & Compliance Center threat indicators API
            return self.block_sender_via_threat_indicator(sender).await;
        }

        // Fallback: Use mail rules (less effective but doesn't require special permissions)
        self.block_sender_via_mail_rule(sender).await
    }

    #[instrument(skip(self), fields(sender = %sender))]
    async fn unblock_sender(&self, sender: &str) -> ConnectorResult<ActionResult> {
        if self.config.use_security_center {
            // Use Security & Compliance Center threat indicators API
            return self.unblock_sender_via_threat_indicator(sender).await;
        }

        // Fallback: Remove mail rule
        self.unblock_sender_via_mail_rule(sender).await
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

        // Query Defender for Office 365 alerts using the v2 API
        // This requires SecurityEvents.Read.All permission
        self.get_defender_threat_data(message_id).await
    }
}

// Security & Compliance Center helper methods
impl M365Connector {
    /// Blocks a sender by creating a threat indicator in the Security & Compliance Center.
    /// Requires ThreatIndicators.ReadWrite.OwnedBy permission.
    async fn block_sender_via_threat_indicator(
        &self,
        sender: &str,
    ) -> ConnectorResult<ActionResult> {
        let path = "/security/tiIndicators";

        // Calculate expiration (1 year from now)
        let expiration = Utc::now() + chrono::Duration::days(365);

        let indicator = CreateThreatIndicatorRequest {
            action: "block".to_string(),
            description: format!("Blocked by Triage Warden: {}", sender),
            expiration_date_time: expiration.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            target_product: "Azure Sentinel".to_string(),
            threat_type: "Phishing".to_string(),
            tlp_level: "white".to_string(),
            email_sender_address: sender.to_string(),
        };

        let response = self.client.post(path, &indicator).await;

        match response {
            Ok(resp) if resp.status().is_success() => {
                let created: ThreatIndicator = resp.json().await.map_err(|e| {
                    ConnectorError::InvalidResponse(format!(
                        "Failed to parse threat indicator response: {}",
                        e
                    ))
                })?;

                let indicator_id = created.id.unwrap_or_else(|| "unknown".to_string());
                info!(
                    "Created threat indicator {} to block sender: {}",
                    indicator_id, sender
                );

                Ok(ActionResult {
                    success: true,
                    action_id: format!("ti-block-{}", indicator_id),
                    message: format!("Sender {} blocked via threat indicator", sender),
                    timestamp: Utc::now(),
                })
            }
            Ok(resp) if resp.status().as_u16() == 403 => {
                warn!(
                    "Permission denied for threat indicators API. Required: ThreatIndicators.ReadWrite.OwnedBy. Falling back to mail rules."
                );
                // Fall back to mail rules when permissions are missing
                self.block_sender_via_mail_rule(sender).await
            }
            Ok(resp) if resp.status().as_u16() == 401 => {
                warn!(
                    "Authentication failed for threat indicators API. Check app registration permissions."
                );
                Err(ConnectorError::AuthenticationFailed(
                    "Threat indicators API requires ThreatIndicators.ReadWrite.OwnedBy permission"
                        .to_string(),
                ))
            }
            Ok(resp) => {
                let status = resp.status();
                let error = resp.text().await.unwrap_or_default();
                warn!("Failed to create threat indicator ({}): {}", status, error);
                Err(ConnectorError::RequestFailed(format!(
                    "Failed to create threat indicator: {} - {}",
                    status, error
                )))
            }
            Err(e) => {
                warn!("Error calling threat indicators API: {}", e);
                Err(e)
            }
        }
    }

    /// Unblocks a sender by finding and deleting the threat indicator.
    /// Requires ThreatIndicators.ReadWrite.OwnedBy permission.
    async fn unblock_sender_via_threat_indicator(
        &self,
        sender: &str,
    ) -> ConnectorResult<ActionResult> {
        // First, find the threat indicator for this sender
        let filter_str = format!("emailSenderAddress eq '{}'", sender);
        let filter = urlencoding::encode(&filter_str);
        let path = format!("/security/tiIndicators?$filter={}", filter);

        let response = self.client.get(&path).await;

        match response {
            Ok(resp) if resp.status().is_success() => {
                let indicators: ThreatIndicatorsResponse = resp.json().await.map_err(|e| {
                    ConnectorError::InvalidResponse(format!(
                        "Failed to parse threat indicators: {}",
                        e
                    ))
                })?;

                if indicators.value.is_empty() {
                    // No threat indicator found, try mail rules fallback
                    debug!(
                        "No threat indicator found for sender {}, checking mail rules",
                        sender
                    );
                    return self.unblock_sender_via_mail_rule(sender).await;
                }

                // Delete each matching threat indicator
                let mut deleted_count = 0;
                for indicator in indicators.value {
                    if let Some(id) = indicator.id {
                        let delete_path = format!("/security/tiIndicators/{}", id);
                        let delete_response = self.client.delete(&delete_path).await;

                        match delete_response {
                            Ok(resp)
                                if resp.status().is_success() || resp.status().as_u16() == 204 =>
                            {
                                debug!("Deleted threat indicator: {}", id);
                                deleted_count += 1;
                            }
                            Ok(resp) => {
                                let error = resp.text().await.unwrap_or_default();
                                warn!("Failed to delete threat indicator {}: {}", id, error);
                            }
                            Err(e) => {
                                warn!("Error deleting threat indicator {}: {}", id, e);
                            }
                        }
                    }
                }

                if deleted_count > 0 {
                    info!(
                        "Unblocked sender {} by removing {} threat indicator(s)",
                        sender, deleted_count
                    );
                    Ok(ActionResult {
                        success: true,
                        action_id: format!("ti-unblock-{}", sender),
                        message: format!(
                            "Sender {} unblocked ({} indicator(s) removed)",
                            sender, deleted_count
                        ),
                        timestamp: Utc::now(),
                    })
                } else {
                    Err(ConnectorError::RequestFailed(format!(
                        "Found threat indicator(s) for {} but failed to delete them",
                        sender
                    )))
                }
            }
            Ok(resp) if resp.status().as_u16() == 403 => {
                warn!(
                    "Permission denied for threat indicators API. Required: ThreatIndicators.ReadWrite.OwnedBy. Falling back to mail rules."
                );
                self.unblock_sender_via_mail_rule(sender).await
            }
            Ok(resp) if resp.status().as_u16() == 401 => {
                warn!(
                    "Authentication failed for threat indicators API. Check app registration permissions."
                );
                Err(ConnectorError::AuthenticationFailed(
                    "Threat indicators API requires ThreatIndicators.ReadWrite.OwnedBy permission"
                        .to_string(),
                ))
            }
            Ok(resp) => {
                let error = resp.text().await.unwrap_or_default();
                warn!("Failed to query threat indicators: {}", error);
                // Fall back to mail rules
                self.unblock_sender_via_mail_rule(sender).await
            }
            Err(e) => {
                warn!("Error querying threat indicators API: {}", e);
                Err(e)
            }
        }
    }

    /// Blocks a sender using mail rules (fallback method).
    async fn block_sender_via_mail_rule(&self, sender: &str) -> ConnectorResult<ActionResult> {
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

        if !response.status().is_success() {
            let error = response.text().await.unwrap_or_default();
            warn!("Could not create mail rule to block sender: {}", error);
            return Err(ConnectorError::RequestFailed(format!(
                "Failed to block sender {} via mail rule: {}",
                sender, error
            )));
        }

        info!("Blocked sender via mail rule: {}", sender);

        Ok(ActionResult {
            success: true,
            action_id: format!("rule-block-{}", sender),
            message: format!("Sender {} blocked via mail rule", sender),
            timestamp: Utc::now(),
        })
    }

    /// Unblocks a sender by removing the mail rule (fallback method).
    async fn unblock_sender_via_mail_rule(&self, sender: &str) -> ConnectorResult<ActionResult> {
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

        let rules: GraphRulesResponse = response.json().await.map_err(|e| {
            ConnectorError::InvalidResponse(format!("Failed to parse rules: {}", e))
        })?;

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

                info!("Unblocked sender via mail rule: {}", sender);

                Ok(ActionResult {
                    success: true,
                    action_id: format!("rule-unblock-{}", sender),
                    message: format!("Sender {} unblocked via mail rule", sender),
                    timestamp: Utc::now(),
                })
            }
            None => Err(ConnectorError::NotFound(format!(
                "No block rule or threat indicator found for sender: {}",
                sender
            ))),
        }
    }

    /// Gets threat data from Defender for Office 365 using alerts_v2 API.
    /// Requires SecurityEvents.Read.All permission.
    async fn get_defender_threat_data(&self, message_id: &str) -> ConnectorResult<EmailThreatData> {
        // Query alerts_v2 API for email-related alerts
        // Filter by service source to get Defender for Office 365 alerts
        let path = format!(
            "/security/alerts_v2?$filter=serviceSource eq 'microsoftDefenderForOffice365' and contains(description, '{}')",
            escape_odata(message_id)
        );

        let response = self.client.get(&path).await;

        match response {
            Ok(resp) if resp.status().is_success() => {
                let alerts: DefenderAlertsResponse = resp.json().await.map_err(|e| {
                    debug!("Failed to parse Defender alerts: {}", e);
                    ConnectorError::InvalidResponse(format!(
                        "Failed to parse Defender alerts: {}",
                        e
                    ))
                })?;

                // Log alert details for debugging
                if !alerts.value.is_empty() {
                    let alert_ids: Vec<&str> = alerts
                        .value
                        .iter()
                        .filter_map(|a| a.id.as_deref())
                        .collect();
                    debug!(
                        "Found {} Defender alerts for message {}: {:?}",
                        alert_ids.len(),
                        message_id,
                        alert_ids
                    );
                }

                // Extract threat information from alerts
                let threat_types: Vec<String> = alerts
                    .value
                    .iter()
                    .filter_map(|a| {
                        // Prefer threat display name, fall back to category
                        a.threat_display_name.clone().or_else(|| a.category.clone())
                    })
                    .collect();

                let detection_methods: Vec<String> = alerts
                    .value
                    .iter()
                    .filter_map(|a| a.detection_source.clone())
                    .collect();

                // Extract clicked URLs from evidence
                let urls_clicked: Vec<crate::traits::UrlClick> = alerts
                    .value
                    .iter()
                    .flat_map(|a| &a.evidence)
                    .filter_map(|e| {
                        e.url.as_ref().map(|url| crate::traits::UrlClick {
                            url: url.clone(),
                            user: e.email_address.clone().unwrap_or_default(),
                            clicked_at: Utc::now(), // Actual click time not available in this response
                            verdict: e
                                .remediation_status
                                .clone()
                                .unwrap_or_else(|| "Unknown".to_string()),
                        })
                    })
                    .collect();

                // Determine delivery action from alert status and evidence
                let delivery_action = Self::determine_delivery_action(&alerts.value);

                Ok(EmailThreatData {
                    delivery_action,
                    threat_types,
                    detection_methods,
                    urls_clicked,
                })
            }
            Ok(resp) if resp.status().as_u16() == 403 => {
                warn!(
                    "Permission denied for alerts_v2 API. Required: SecurityEvents.Read.All. Returning minimal threat data."
                );
                Ok(EmailThreatData {
                    delivery_action: "Unknown".to_string(),
                    threat_types: Vec::new(),
                    detection_methods: vec!["Permission denied for Defender alerts".to_string()],
                    urls_clicked: Vec::new(),
                })
            }
            Ok(resp) if resp.status().as_u16() == 401 => {
                warn!(
                    "Authentication failed for alerts_v2 API. Check app registration permissions."
                );
                Err(ConnectorError::AuthenticationFailed(
                    "Security alerts API requires SecurityEvents.Read.All permission".to_string(),
                ))
            }
            Ok(resp) => {
                let error = resp.text().await.unwrap_or_default();
                debug!(
                    "No Defender alerts found for message {}: {}",
                    message_id, error
                );
                Ok(EmailThreatData {
                    delivery_action: "Unknown".to_string(),
                    threat_types: Vec::new(),
                    detection_methods: Vec::new(),
                    urls_clicked: Vec::new(),
                })
            }
            Err(e) => {
                debug!("Error querying Defender alerts: {}", e);
                Ok(EmailThreatData {
                    delivery_action: "Unknown".to_string(),
                    threat_types: Vec::new(),
                    detection_methods: Vec::new(),
                    urls_clicked: Vec::new(),
                })
            }
        }
    }

    /// Determines the delivery action based on alert severity and evidence.
    fn determine_delivery_action(alerts: &[DefenderAlert]) -> String {
        if alerts.is_empty() {
            return "Delivered".to_string();
        }

        // Check if any alert indicates blocking
        for alert in alerts {
            // Check evidence for remediation status
            for evidence in &alert.evidence {
                if let Some(status) = &evidence.remediation_status {
                    let status_lower = status.to_lowercase();
                    if status_lower.contains("blocked") || status_lower.contains("quarantined") {
                        return "Blocked".to_string();
                    }
                    if status_lower.contains("removed") || status_lower.contains("deleted") {
                        return "Removed".to_string();
                    }
                }
            }

            // Check alert severity for high-risk indicators
            if let Some(severity) = &alert.severity {
                let severity_lower = severity.to_lowercase();
                if severity_lower == "high" || severity_lower == "critical" {
                    return "Quarantined".to_string();
                }
            }
        }

        // Default to delivered with warning if alerts exist but no blocking action
        "DeliveredWithWarning".to_string()
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

// Security API response types

/// Response wrapper for threat indicators list.
#[derive(Debug, Deserialize)]
struct ThreatIndicatorsResponse {
    #[serde(default)]
    value: Vec<ThreatIndicator>,
}

/// Threat indicator from the Security API.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ThreatIndicator {
    /// Unique ID for the threat indicator.
    id: Option<String>,
    /// Action to take when the indicator is matched.
    action: Option<String>,
    /// Description of the threat indicator.
    description: Option<String>,
    /// Expiration date/time for the indicator.
    expiration_date_time: Option<String>,
    /// Target product for the indicator (e.g., "Azure Sentinel").
    target_product: Option<String>,
    /// Type of threat (e.g., "Phishing", "Malware").
    threat_type: Option<String>,
    /// TLP level for sharing (white, green, amber, red).
    tlp_level: Option<String>,
    /// Email sender address to block.
    email_sender_address: Option<String>,
    /// Indicates if the indicator is active.
    is_active: Option<bool>,
}

/// Request body to create a threat indicator.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateThreatIndicatorRequest {
    action: String,
    description: String,
    expiration_date_time: String,
    target_product: String,
    threat_type: String,
    tlp_level: String,
    email_sender_address: String,
}

/// Response wrapper for Defender alerts (v2 API).
#[derive(Debug, Deserialize)]
struct DefenderAlertsResponse {
    #[serde(default)]
    value: Vec<DefenderAlert>,
}

/// A Defender for Office 365 alert (alerts_v2 schema).
/// Fields are populated from JSON deserialization and used in threat analysis.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)] // Fields are used for deserialization and analysis
struct DefenderAlert {
    /// Unique alert ID.
    id: Option<String>,
    /// Alert title.
    title: Option<String>,
    /// Alert description.
    description: Option<String>,
    /// Severity level (low, medium, high, critical).
    severity: Option<String>,
    /// Alert status (new, inProgress, resolved, etc.).
    status: Option<String>,
    /// Category of the alert (e.g., "InitialAccess", "Phishing").
    category: Option<String>,
    /// Service source that generated the alert.
    service_source: Option<String>,
    /// Detection source/technology.
    detection_source: Option<String>,
    /// Threat display name.
    threat_display_name: Option<String>,
    /// Threat family name.
    threat_family_name: Option<String>,
    /// Creation timestamp.
    created_date_time: Option<String>,
    /// Last update timestamp.
    last_update_date_time: Option<String>,
    /// Evidence associated with the alert.
    #[serde(default)]
    evidence: Vec<AlertEvidence>,
}

/// Evidence details for a Defender alert.
/// Fields are populated from JSON deserialization and used in threat analysis.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)] // Fields are used for deserialization and analysis
struct AlertEvidence {
    /// Type of evidence (e.g., "mailbox", "email", "url").
    #[serde(rename = "@odata.type")]
    odata_type: Option<String>,
    /// Remediation status.
    remediation_status: Option<String>,
    /// Remediation status details.
    remediation_status_details: Option<String>,
    /// Associated email addresses.
    email_address: Option<String>,
    /// Sender information.
    sender: Option<String>,
    /// Subject line.
    subject: Option<String>,
    /// Network message ID.
    network_message_id: Option<String>,
    /// URL if this is URL evidence.
    url: Option<String>,
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
    let url_pattern = regex::Regex::new(r#"https?://[^\s<>"'{}|\[\]^`\\]+"#).ok();

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
    use crate::secure_string::SecureString;
    use crate::traits::AuthConfig;

    fn create_test_config() -> M365Config {
        M365Config {
            connector: ConnectorConfig {
                name: "m365-test".to_string(),
                base_url: "https://graph.microsoft.com/v1.0".to_string(),
                auth: AuthConfig::OAuth2 {
                    client_id: "test-client-id".to_string(),
                    client_secret: SecureString::new("test-client-secret".to_string()),
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

    // Security API response parsing tests

    #[test]
    fn test_parse_threat_indicator_response() {
        let json = r#"{
            "id": "ti-12345",
            "action": "block",
            "description": "Blocked by Triage Warden: attacker@evil.com",
            "expirationDateTime": "2025-12-31T00:00:00Z",
            "targetProduct": "Azure Sentinel",
            "threatType": "Phishing",
            "tlpLevel": "white",
            "emailSenderAddress": "attacker@evil.com",
            "isActive": true
        }"#;

        let indicator: ThreatIndicator = serde_json::from_str(json).unwrap();
        assert_eq!(indicator.id, Some("ti-12345".to_string()));
        assert_eq!(indicator.action, Some("block".to_string()));
        assert_eq!(
            indicator.email_sender_address,
            Some("attacker@evil.com".to_string())
        );
        assert_eq!(indicator.threat_type, Some("Phishing".to_string()));
        assert_eq!(indicator.is_active, Some(true));
    }

    #[test]
    fn test_parse_threat_indicators_list() {
        let json = r#"{
            "value": [
                {
                    "id": "ti-001",
                    "action": "block",
                    "emailSenderAddress": "spam@evil.com"
                },
                {
                    "id": "ti-002",
                    "action": "block",
                    "emailSenderAddress": "phish@malicious.org"
                }
            ]
        }"#;

        let response: ThreatIndicatorsResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.value.len(), 2);
        assert_eq!(response.value[0].id, Some("ti-001".to_string()));
        assert_eq!(
            response.value[1].email_sender_address,
            Some("phish@malicious.org".to_string())
        );
    }

    #[test]
    fn test_parse_empty_threat_indicators() {
        let json = r#"{"value": []}"#;
        let response: ThreatIndicatorsResponse = serde_json::from_str(json).unwrap();
        assert!(response.value.is_empty());
    }

    #[test]
    fn test_parse_defender_alert_response() {
        let json = r##"{
            "id": "alert-12345",
            "title": "Phishing email detected",
            "description": "A phishing email was detected from attacker@evil.com",
            "severity": "high",
            "status": "new",
            "category": "InitialAccess",
            "serviceSource": "microsoftDefenderForOffice365",
            "detectionSource": "AntiPhishing",
            "threatDisplayName": "Credential Phishing",
            "threatFamilyName": "PhishKit",
            "createdDateTime": "2024-01-15T10:30:00Z",
            "lastUpdateDateTime": "2024-01-15T10:35:00Z",
            "evidence": [
                {
                    "@odata.type": "#microsoft.graph.security.emailEvidence",
                    "remediationStatus": "blocked",
                    "emailAddress": "victim@company.com",
                    "sender": "attacker@evil.com",
                    "subject": "Urgent: Update your password"
                }
            ]
        }"##;

        let alert: DefenderAlert = serde_json::from_str(json).unwrap();
        assert_eq!(alert.id, Some("alert-12345".to_string()));
        assert_eq!(alert.severity, Some("high".to_string()));
        assert_eq!(alert.category, Some("InitialAccess".to_string()));
        assert_eq!(
            alert.threat_display_name,
            Some("Credential Phishing".to_string())
        );
        assert_eq!(alert.evidence.len(), 1);
        assert_eq!(
            alert.evidence[0].remediation_status,
            Some("blocked".to_string())
        );
        assert_eq!(
            alert.evidence[0].sender,
            Some("attacker@evil.com".to_string())
        );
    }

    #[test]
    fn test_parse_defender_alerts_list() {
        let json = r##"{
            "value": [
                {
                    "id": "alert-001",
                    "title": "Phishing attempt",
                    "severity": "medium",
                    "category": "Phishing",
                    "detectionSource": "SafeLinks",
                    "evidence": []
                },
                {
                    "id": "alert-002",
                    "title": "Malware attachment",
                    "severity": "critical",
                    "category": "Malware",
                    "detectionSource": "SafeAttachments",
                    "evidence": [
                        {
                            "@odata.type": "#microsoft.graph.security.urlEvidence",
                            "url": "https://malicious.site/payload",
                            "remediationStatus": "quarantined"
                        }
                    ]
                }
            ]
        }"##;

        let response: DefenderAlertsResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.value.len(), 2);
        assert_eq!(response.value[0].severity, Some("medium".to_string()));
        assert_eq!(response.value[1].severity, Some("critical".to_string()));
        assert_eq!(response.value[1].evidence.len(), 1);
        assert_eq!(
            response.value[1].evidence[0].url,
            Some("https://malicious.site/payload".to_string())
        );
    }

    #[test]
    fn test_parse_alert_evidence_with_url() {
        let json = r##"{
            "@odata.type": "#microsoft.graph.security.urlEvidence",
            "url": "https://phishing.site/login",
            "remediationStatus": "blocked",
            "remediationStatusDetails": "URL blocked by Safe Links"
        }"##;

        let evidence: AlertEvidence = serde_json::from_str(json).unwrap();
        assert_eq!(
            evidence.url,
            Some("https://phishing.site/login".to_string())
        );
        assert_eq!(evidence.remediation_status, Some("blocked".to_string()));
    }

    #[test]
    fn test_determine_delivery_action_blocked() {
        let alerts = vec![DefenderAlert {
            id: Some("alert-1".to_string()),
            title: None,
            description: None,
            severity: Some("high".to_string()),
            status: None,
            category: None,
            service_source: None,
            detection_source: None,
            threat_display_name: None,
            threat_family_name: None,
            created_date_time: None,
            last_update_date_time: None,
            evidence: vec![AlertEvidence {
                odata_type: None,
                remediation_status: Some("blocked".to_string()),
                remediation_status_details: None,
                email_address: None,
                sender: None,
                subject: None,
                network_message_id: None,
                url: None,
            }],
        }];

        let action = M365Connector::determine_delivery_action(&alerts);
        assert_eq!(action, "Blocked");
    }

    #[test]
    fn test_determine_delivery_action_quarantined() {
        let alerts = vec![DefenderAlert {
            id: Some("alert-1".to_string()),
            title: None,
            description: None,
            severity: Some("critical".to_string()),
            status: None,
            category: None,
            service_source: None,
            detection_source: None,
            threat_display_name: None,
            threat_family_name: None,
            created_date_time: None,
            last_update_date_time: None,
            evidence: vec![],
        }];

        let action = M365Connector::determine_delivery_action(&alerts);
        assert_eq!(action, "Quarantined");
    }

    #[test]
    fn test_determine_delivery_action_empty() {
        let alerts: Vec<DefenderAlert> = vec![];
        let action = M365Connector::determine_delivery_action(&alerts);
        assert_eq!(action, "Delivered");
    }

    #[test]
    fn test_determine_delivery_action_with_warning() {
        let alerts = vec![DefenderAlert {
            id: Some("alert-1".to_string()),
            title: None,
            description: None,
            severity: Some("low".to_string()),
            status: None,
            category: None,
            service_source: None,
            detection_source: None,
            threat_display_name: None,
            threat_family_name: None,
            created_date_time: None,
            last_update_date_time: None,
            evidence: vec![],
        }];

        let action = M365Connector::determine_delivery_action(&alerts);
        assert_eq!(action, "DeliveredWithWarning");
    }

    #[test]
    fn test_create_threat_indicator_request_serialization() {
        let request = CreateThreatIndicatorRequest {
            action: "block".to_string(),
            description: "Blocked by Triage Warden".to_string(),
            expiration_date_time: "2025-12-31T00:00:00Z".to_string(),
            target_product: "Azure Sentinel".to_string(),
            threat_type: "Phishing".to_string(),
            tlp_level: "white".to_string(),
            email_sender_address: "attacker@evil.com".to_string(),
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("\"action\":\"block\""));
        assert!(json.contains("\"emailSenderAddress\":\"attacker@evil.com\""));
        assert!(json.contains("\"targetProduct\":\"Azure Sentinel\""));
        assert!(json.contains("\"tlpLevel\":\"white\""));
    }

    #[test]
    fn test_connector_with_security_center_enabled() {
        let mut config = create_test_config();
        config.use_security_center = true;
        let connector = M365Connector::new(config).unwrap();
        assert!(connector.config.use_security_center);
    }

    #[test]
    fn test_connector_with_security_center_disabled() {
        let config = create_test_config();
        let connector = M365Connector::new(config).unwrap();
        assert!(!connector.config.use_security_center);
    }
}
