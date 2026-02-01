# Email Gateway Connector

Manage email security operations including search, quarantine, and sender blocking.

## Interface

```rust
#[async_trait]
pub trait EmailGatewayConnector: Connector {
    /// Search for emails
    async fn search_emails(&self, query: EmailSearchQuery) -> ConnectorResult<Vec<EmailMessage>>;

    /// Get specific email by ID
    async fn get_email(&self, message_id: &str) -> ConnectorResult<EmailMessage>;

    /// Move email to quarantine
    async fn quarantine_email(&self, message_id: &str) -> ConnectorResult<ActionResult>;

    /// Release email from quarantine
    async fn release_email(&self, message_id: &str) -> ConnectorResult<ActionResult>;

    /// Block sender
    async fn block_sender(&self, sender: &str) -> ConnectorResult<ActionResult>;

    /// Unblock sender
    async fn unblock_sender(&self, sender: &str) -> ConnectorResult<ActionResult>;

    /// Get threat data for email
    async fn get_threat_data(&self, message_id: &str) -> ConnectorResult<EmailThreatData>;
}

pub struct EmailMessage {
    pub id: String,
    pub internet_message_id: String,
    pub sender: String,
    pub recipients: Vec<String>,
    pub subject: String,
    pub received_at: DateTime<Utc>,
    pub has_attachments: bool,
    pub attachments: Vec<EmailAttachment>,
    pub urls: Vec<String>,
    pub headers: HashMap<String, String>,
    pub threat_assessment: Option<ThreatAssessment>,
}

pub struct EmailSearchQuery {
    pub sender: Option<String>,
    pub recipient: Option<String>,
    pub subject_contains: Option<String>,
    pub timerange: TimeRange,
    pub has_attachments: Option<bool>,
    pub threat_type: Option<String>,
    pub limit: usize,
}
```

## Microsoft 365

### Configuration

```bash
TW_EMAIL_GATEWAY_MODE=m365
TW_M365_TENANT_ID=your-tenant-id
TW_M365_CLIENT_ID=your-client-id
TW_M365_CLIENT_SECRET=your-client-secret
```

### App Registration

Create an Azure AD app registration with these API permissions:

| Permission | Type | Purpose |
|------------|------|---------|
| `Mail.Read` | Application | Read emails |
| `Mail.ReadWrite` | Application | Quarantine actions |
| `ThreatAssessment.Read.All` | Application | Threat data |
| `Policy.Read.All` | Application | Block list management |

### Example Usage

```rust
let connector = M365Connector::new(tenant_id, client_id, client_secret)?;

// Search for suspicious emails
let query = EmailSearchQuery {
    sender: Some("suspicious@domain.com".to_string()),
    timerange: TimeRange::last_hours(24),
    ..Default::default()
};
let emails = connector.search_emails(query).await?;

// Quarantine malicious email
let result = connector.quarantine_email("AAMkAGI2...").await?;

// Block sender
let result = connector.block_sender("phisher@malicious.com").await?;
```

### Quarantine Behavior

When quarantined:
- Email moved to quarantine folder
- User notified (configurable)
- Admin can release if false positive

## Mock Connector

```bash
TW_EMAIL_GATEWAY_MODE=mock
```

Provides sample emails with various threat characteristics:
- Phishing with malicious URLs
- Malware with executable attachments
- BEC/impersonation attempts
- Clean legitimate emails

## Python Bridge

```python
from tw_bridge import EmailGatewayBridge

bridge = EmailGatewayBridge("m365")

# Search emails
emails = bridge.search_emails(
    sender="suspicious@domain.com",
    hours=24
)

for email in emails:
    print(f"From: {email['sender']}")
    print(f"Subject: {email['subject']}")
    print(f"Attachments: {len(email['attachments'])}")

# Quarantine email
result = bridge.quarantine_email("AAMkAGI2...")
if result['success']:
    print("Email quarantined")

# Block sender
result = bridge.block_sender("phisher@malicious.com")
```

## Response Actions

| Action | Description | Rollback |
|--------|-------------|----------|
| `quarantine_email` | Move to quarantine | `release_email` |
| `block_sender` | Add to blocklist | `unblock_sender` |

## Threat Data

Get detailed threat information:

```rust
let threat_data = connector.get_threat_data("AAMkAGI2...").await?;

println!("Delivery action: {}", threat_data.delivery_action);
println!("Threat types: {:?}", threat_data.threat_types);
println!("Detection methods: {:?}", threat_data.detection_methods);
```

Fields:
- `delivery_action`: Delivered, Quarantined, Blocked
- `threat_types`: Phishing, Malware, Spam, BEC
- `detection_methods`: URLAnalysis, AttachmentScanning, ImpersonationDetection
- `urls_clicked`: URLs clicked by recipient (if tracking enabled)
