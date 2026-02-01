//! Mock Email Gateway connector for testing.
//!
//! Provides a configurable mock connector for testing email gateway operations
//! including email search, quarantine, and sender blocking.

use crate::traits::{
    ActionResult, ConnectorError, ConnectorHealth, ConnectorResult, EmailAttachment,
    EmailGatewayConnector, EmailMessage, EmailSearchQuery, EmailThreatData,
};
use async_trait::async_trait;
use chrono::{Duration, Utc};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Mock Email Gateway connector for testing.
pub struct MockEmailGatewayConnector {
    name: String,
    emails: Arc<RwLock<HashMap<String, EmailMessage>>>,
    quarantined: Arc<RwLock<HashSet<String>>>,
    blocked_senders: Arc<RwLock<HashSet<String>>>,
}

impl MockEmailGatewayConnector {
    /// Creates a new mock email gateway connector.
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            emails: Arc::new(RwLock::new(HashMap::new())),
            quarantined: Arc::new(RwLock::new(HashSet::new())),
            blocked_senders: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Creates a mock email gateway connector with sample data.
    pub fn with_sample_data(name: &str) -> Self {
        let now = Utc::now();

        let sample_emails = vec![
            EmailMessage {
                id: "msg-001".to_string(),
                internet_message_id: "<msg001@example.com>".to_string(),
                sender: "phisher@malicious.com".to_string(),
                recipients: vec!["victim@company.com".to_string()],
                subject: "Urgent: Update Your Password Now!".to_string(),
                received_at: now - Duration::hours(1),
                has_attachments: true,
                attachments: vec![EmailAttachment {
                    id: "att-001".to_string(),
                    name: "invoice.pdf.exe".to_string(),
                    content_type: "application/x-msdownload".to_string(),
                    size: 102400,
                    sha256: Some("abc123def456".to_string()),
                }],
                urls: vec![
                    "https://phishing-site.com/login".to_string(),
                    "https://malware-download.com/payload".to_string(),
                ],
                headers: {
                    let mut h = HashMap::new();
                    h.insert(
                        "X-Originating-IP".to_string(),
                        "[203.0.113.100]".to_string(),
                    );
                    h.insert(
                        "Authentication-Results".to_string(),
                        "spf=fail; dkim=fail; dmarc=fail".to_string(),
                    );
                    h
                },
                threat_assessment: None,
            },
            EmailMessage {
                id: "msg-002".to_string(),
                internet_message_id: "<msg002@example.com>".to_string(),
                sender: "legitimate@partner.com".to_string(),
                recipients: vec!["employee@company.com".to_string()],
                subject: "Q4 Report".to_string(),
                received_at: now - Duration::hours(2),
                has_attachments: true,
                attachments: vec![EmailAttachment {
                    id: "att-002".to_string(),
                    name: "q4_report.pdf".to_string(),
                    content_type: "application/pdf".to_string(),
                    size: 204800,
                    sha256: Some("cleanfile123".to_string()),
                }],
                urls: vec!["https://partner.com/reports".to_string()],
                headers: {
                    let mut h = HashMap::new();
                    h.insert(
                        "Authentication-Results".to_string(),
                        "spf=pass; dkim=pass; dmarc=pass".to_string(),
                    );
                    h
                },
                threat_assessment: None,
            },
            EmailMessage {
                id: "msg-003".to_string(),
                internet_message_id: "<msg003@example.com>".to_string(),
                sender: "spammer@bulk-mail.com".to_string(),
                recipients: vec![
                    "user1@company.com".to_string(),
                    "user2@company.com".to_string(),
                ],
                subject: "You've Won $1,000,000!!!".to_string(),
                received_at: now - Duration::minutes(30),
                has_attachments: false,
                attachments: vec![],
                urls: vec!["https://spam-site.com/claim".to_string()],
                headers: {
                    let mut h = HashMap::new();
                    h.insert("X-Spam-Score".to_string(), "9.5".to_string());
                    h
                },
                threat_assessment: None,
            },
            EmailMessage {
                id: "msg-004".to_string(),
                internet_message_id: "<msg004@example.com>".to_string(),
                sender: "ceo-spoof@evil.com".to_string(),
                recipients: vec!["finance@company.com".to_string()],
                subject: "Urgent Wire Transfer Needed".to_string(),
                received_at: now - Duration::minutes(15),
                has_attachments: false,
                attachments: vec![],
                urls: vec![],
                headers: {
                    let mut h = HashMap::new();
                    h.insert("Reply-To".to_string(), "fake-ceo@gmail.com".to_string());
                    h.insert(
                        "Authentication-Results".to_string(),
                        "spf=none; dkim=none".to_string(),
                    );
                    h
                },
                threat_assessment: None,
            },
        ];

        // Build HashMap directly and wrap in RwLock
        let mut emails_map = HashMap::new();
        for email in sample_emails {
            emails_map.insert(email.id.clone(), email);
        }

        Self {
            name: name.to_string(),
            emails: Arc::new(RwLock::new(emails_map)),
            quarantined: Arc::new(RwLock::new(HashSet::new())),
            blocked_senders: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Adds an email to the mock.
    pub async fn add_email(&self, email: EmailMessage) {
        self.emails.write().await.insert(email.id.clone(), email);
    }

    /// Checks if a sender is blocked.
    pub async fn is_sender_blocked(&self, sender: &str) -> bool {
        self.blocked_senders.read().await.contains(sender)
    }

    /// Checks if an email is quarantined.
    pub async fn is_quarantined(&self, message_id: &str) -> bool {
        self.quarantined.read().await.contains(message_id)
    }

    /// Gets the list of blocked senders.
    pub async fn get_blocked_senders(&self) -> Vec<String> {
        self.blocked_senders.read().await.iter().cloned().collect()
    }

    /// Clears all data.
    pub async fn clear(&self) {
        self.emails.write().await.clear();
        self.quarantined.write().await.clear();
        self.blocked_senders.write().await.clear();
    }
}

#[async_trait]
impl crate::traits::Connector for MockEmailGatewayConnector {
    fn name(&self) -> &str {
        &self.name
    }

    fn connector_type(&self) -> &str {
        "email_gateway"
    }

    async fn health_check(&self) -> ConnectorResult<ConnectorHealth> {
        Ok(ConnectorHealth::Healthy)
    }

    async fn test_connection(&self) -> ConnectorResult<bool> {
        Ok(true)
    }
}

#[async_trait]
impl EmailGatewayConnector for MockEmailGatewayConnector {
    async fn search_emails(&self, query: EmailSearchQuery) -> ConnectorResult<Vec<EmailMessage>> {
        let emails = self.emails.read().await;
        let quarantined = self.quarantined.read().await;

        let results: Vec<EmailMessage> = emails
            .values()
            .filter(|email| {
                // Skip quarantined emails unless specifically searching for them
                if quarantined.contains(&email.id) {
                    return false;
                }

                // Filter by sender
                if let Some(ref sender) = query.sender {
                    if !email.sender.to_lowercase().contains(&sender.to_lowercase()) {
                        return false;
                    }
                }

                // Filter by recipient
                if let Some(ref recipient) = query.recipient {
                    let recipient_lower = recipient.to_lowercase();
                    if !email
                        .recipients
                        .iter()
                        .any(|r| r.to_lowercase().contains(&recipient_lower))
                    {
                        return false;
                    }
                }

                // Filter by subject
                if let Some(ref subject) = query.subject_contains {
                    if !email
                        .subject
                        .to_lowercase()
                        .contains(&subject.to_lowercase())
                    {
                        return false;
                    }
                }

                // Filter by time range
                if email.received_at < query.timerange.start
                    || email.received_at > query.timerange.end
                {
                    return false;
                }

                // Filter by has_attachments
                if let Some(has_attachments) = query.has_attachments {
                    if email.has_attachments != has_attachments {
                        return false;
                    }
                }

                true
            })
            .take(query.limit)
            .cloned()
            .collect();

        Ok(results)
    }

    async fn get_email(&self, message_id: &str) -> ConnectorResult<EmailMessage> {
        let emails = self.emails.read().await;
        emails
            .get(message_id)
            .cloned()
            .ok_or_else(|| ConnectorError::NotFound(format!("Email not found: {}", message_id)))
    }

    async fn quarantine_email(&self, message_id: &str) -> ConnectorResult<ActionResult> {
        // Verify email exists
        {
            let emails = self.emails.read().await;
            if !emails.contains_key(message_id) {
                return Err(ConnectorError::NotFound(format!(
                    "Email not found: {}",
                    message_id
                )));
            }
        }

        // Check if already quarantined
        {
            let quarantined = self.quarantined.read().await;
            if quarantined.contains(message_id) {
                return Err(ConnectorError::RequestFailed(format!(
                    "Email {} is already quarantined",
                    message_id
                )));
            }
        }

        // Quarantine it
        self.quarantined
            .write()
            .await
            .insert(message_id.to_string());

        Ok(ActionResult {
            success: true,
            action_id: format!("quarantine-{}", uuid::Uuid::new_v4()),
            message: format!("Email {} moved to quarantine", message_id),
            timestamp: Utc::now(),
        })
    }

    async fn release_email(&self, message_id: &str) -> ConnectorResult<ActionResult> {
        // Verify email exists
        {
            let emails = self.emails.read().await;
            if !emails.contains_key(message_id) {
                return Err(ConnectorError::NotFound(format!(
                    "Email not found: {}",
                    message_id
                )));
            }
        }

        // Check if quarantined
        {
            let quarantined = self.quarantined.read().await;
            if !quarantined.contains(message_id) {
                return Err(ConnectorError::RequestFailed(format!(
                    "Email {} is not quarantined",
                    message_id
                )));
            }
        }

        // Release it
        self.quarantined.write().await.remove(message_id);

        Ok(ActionResult {
            success: true,
            action_id: format!("release-{}", uuid::Uuid::new_v4()),
            message: format!("Email {} released from quarantine", message_id),
            timestamp: Utc::now(),
        })
    }

    async fn block_sender(&self, sender: &str) -> ConnectorResult<ActionResult> {
        let mut blocked = self.blocked_senders.write().await;

        if blocked.contains(sender) {
            return Err(ConnectorError::RequestFailed(format!(
                "Sender {} is already blocked",
                sender
            )));
        }

        blocked.insert(sender.to_string());

        Ok(ActionResult {
            success: true,
            action_id: format!("block-{}", uuid::Uuid::new_v4()),
            message: format!("Sender {} blocked", sender),
            timestamp: Utc::now(),
        })
    }

    async fn unblock_sender(&self, sender: &str) -> ConnectorResult<ActionResult> {
        let mut blocked = self.blocked_senders.write().await;

        if !blocked.contains(sender) {
            return Err(ConnectorError::NotFound(format!(
                "Sender {} is not blocked",
                sender
            )));
        }

        blocked.remove(sender);

        Ok(ActionResult {
            success: true,
            action_id: format!("unblock-{}", uuid::Uuid::new_v4()),
            message: format!("Sender {} unblocked", sender),
            timestamp: Utc::now(),
        })
    }

    async fn get_threat_data(&self, message_id: &str) -> ConnectorResult<EmailThreatData> {
        // Verify email exists
        let email = {
            let emails = self.emails.read().await;
            emails.get(message_id).cloned().ok_or_else(|| {
                ConnectorError::NotFound(format!("Email not found: {}", message_id))
            })?
        };

        // Generate mock threat data based on email characteristics
        let mut threat_types = Vec::new();
        let mut detection_methods = Vec::new();

        // Check for suspicious characteristics
        if email.sender.contains("phish") || email.subject.to_lowercase().contains("urgent") {
            threat_types.push("Phishing".to_string());
            detection_methods.push("URLAnalysis".to_string());
        }

        if email.sender.contains("spam") || email.subject.contains("Won") {
            threat_types.push("Spam".to_string());
            detection_methods.push("SpamFilter".to_string());
        }

        if email.attachments.iter().any(|a| a.name.ends_with(".exe")) {
            threat_types.push("Malware".to_string());
            detection_methods.push("AttachmentScanning".to_string());
        }

        if email.sender.contains("spoof") {
            threat_types.push("BEC".to_string());
            detection_methods.push("ImpersonationDetection".to_string());
        }

        let quarantined = self.quarantined.read().await;
        let delivery_action = if quarantined.contains(message_id) {
            "Quarantined".to_string()
        } else if !threat_types.is_empty() {
            "DeliveredWithWarning".to_string()
        } else {
            "Delivered".to_string()
        };

        Ok(EmailThreatData {
            delivery_action,
            threat_types,
            detection_methods,
            urls_clicked: vec![], // Mock doesn't track clicks
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TimeRange;

    #[tokio::test]
    async fn test_search_emails() {
        let connector = MockEmailGatewayConnector::with_sample_data("test");

        let query = EmailSearchQuery {
            sender: Some("phisher".to_string()),
            recipient: None,
            subject_contains: None,
            timerange: TimeRange::last_hours(24),
            has_attachments: None,
            threat_type: None,
            limit: 100,
        };

        let results = connector.search_emails(query).await.unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].sender.contains("phisher"));
    }

    #[tokio::test]
    async fn test_get_email() {
        let connector = MockEmailGatewayConnector::with_sample_data("test");

        let email = connector.get_email("msg-001").await.unwrap();
        assert_eq!(email.id, "msg-001");
        assert!(email.sender.contains("phisher"));
    }

    #[tokio::test]
    async fn test_email_not_found() {
        let connector = MockEmailGatewayConnector::with_sample_data("test");

        let result = connector.get_email("nonexistent").await;
        assert!(matches!(result, Err(ConnectorError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_quarantine_email() {
        let connector = MockEmailGatewayConnector::with_sample_data("test");

        let result = connector.quarantine_email("msg-001").await.unwrap();
        assert!(result.success);
        assert!(connector.is_quarantined("msg-001").await);

        // Should fail if already quarantined
        let result = connector.quarantine_email("msg-001").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_release_email() {
        let connector = MockEmailGatewayConnector::with_sample_data("test");

        // First quarantine
        connector.quarantine_email("msg-001").await.unwrap();

        // Then release
        let result = connector.release_email("msg-001").await.unwrap();
        assert!(result.success);
        assert!(!connector.is_quarantined("msg-001").await);
    }

    #[tokio::test]
    async fn test_block_sender() {
        let connector = MockEmailGatewayConnector::with_sample_data("test");

        let result = connector.block_sender("attacker@evil.com").await.unwrap();
        assert!(result.success);
        assert!(connector.is_sender_blocked("attacker@evil.com").await);

        // Should fail if already blocked
        let result = connector.block_sender("attacker@evil.com").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_unblock_sender() {
        let connector = MockEmailGatewayConnector::with_sample_data("test");

        // First block
        connector.block_sender("attacker@evil.com").await.unwrap();

        // Then unblock
        let result = connector.unblock_sender("attacker@evil.com").await.unwrap();
        assert!(result.success);
        assert!(!connector.is_sender_blocked("attacker@evil.com").await);
    }

    #[tokio::test]
    async fn test_get_threat_data() {
        let connector = MockEmailGatewayConnector::with_sample_data("test");

        let threat_data = connector.get_threat_data("msg-001").await.unwrap();
        assert!(threat_data.threat_types.contains(&"Phishing".to_string()));
        assert!(threat_data.threat_types.contains(&"Malware".to_string()));
    }

    #[tokio::test]
    async fn test_search_excludes_quarantined() {
        let connector = MockEmailGatewayConnector::with_sample_data("test");

        // Quarantine an email
        connector.quarantine_email("msg-001").await.unwrap();

        // Search should not return quarantined email
        let query = EmailSearchQuery {
            sender: Some("phisher".to_string()),
            recipient: None,
            subject_contains: None,
            timerange: TimeRange::last_hours(24),
            has_attachments: None,
            threat_type: None,
            limit: 100,
        };

        let results = connector.search_emails(query).await.unwrap();
        assert!(results.is_empty());
    }
}
