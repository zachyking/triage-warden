# Ticketing Connector

Create and manage security incident tickets in external ticketing systems.

## Interface

```rust
#[async_trait]
pub trait TicketingConnector: Connector {
    /// Create a new ticket
    async fn create_ticket(&self, ticket: CreateTicketRequest) -> ConnectorResult<Ticket>;

    /// Get ticket by ID
    async fn get_ticket(&self, ticket_id: &str) -> ConnectorResult<Ticket>;

    /// Update ticket fields
    async fn update_ticket(&self, ticket_id: &str, update: UpdateTicketRequest) -> ConnectorResult<Ticket>;

    /// Add comment to ticket
    async fn add_comment(&self, ticket_id: &str, comment: &str) -> ConnectorResult<()>;

    /// Search tickets
    async fn search_tickets(&self, query: TicketSearchQuery) -> ConnectorResult<Vec<Ticket>>;
}

pub struct CreateTicketRequest {
    pub title: String,
    pub description: String,
    pub priority: TicketPriority,
    pub ticket_type: String,
    pub labels: Vec<String>,
    pub assignee: Option<String>,
    pub custom_fields: HashMap<String, String>,
}

pub struct Ticket {
    pub id: String,
    pub key: String,
    pub title: String,
    pub description: String,
    pub status: String,
    pub priority: TicketPriority,
    pub assignee: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub url: String,
}
```

## Jira

### Configuration

```bash
TW_TICKETING_MODE=jira
TW_JIRA_URL=https://company.atlassian.net
TW_JIRA_EMAIL=automation@company.com
TW_JIRA_API_TOKEN=your-api-token
TW_JIRA_PROJECT_KEY=SEC
```

### API Token

Generate an API token at: https://id.atlassian.com/manage-profile/security/api-tokens

Required permissions:
- Create issues
- Edit issues
- Add comments
- Browse project

### Example Usage

```rust
let connector = JiraConnector::new(url, email, token, project_key)?;

// Create security ticket
let request = CreateTicketRequest {
    title: "Phishing Incident - INC-2024-001".to_string(),
    description: "Phishing email detected and quarantined.\n\n## Details\n...".to_string(),
    priority: TicketPriority::High,
    ticket_type: "Security Incident".to_string(),
    labels: vec!["phishing".to_string(), "triage-warden".to_string()],
    assignee: Some("analyst@company.com".to_string()),
    custom_fields: HashMap::new(),
};

let ticket = connector.create_ticket(request).await?;
println!("Created: {} - {}", ticket.key, ticket.url);

// Add investigation notes
connector.add_comment(
    &ticket.id,
    "## Investigation Notes\n\n- Sender reputation: Malicious\n- URLs: 2 phishing links"
).await?;
```

### Issue Types

Configure the Jira project with these issue types:

| Issue Type | Usage |
|------------|-------|
| Security Incident | Main incident ticket |
| Investigation | Sub-task for investigation steps |
| Remediation | Sub-task for response actions |

### Custom Fields

Map custom fields in configuration:

```bash
TW_JIRA_FIELD_SEVERITY=customfield_10001
TW_JIRA_FIELD_INCIDENT_ID=customfield_10002
TW_JIRA_FIELD_VERDICT=customfield_10003
```

## Mock Connector

```bash
TW_TICKETING_MODE=mock
```

Simulates ticket operations with in-memory storage.

## Python Bridge

```python
from tw_bridge import TicketingBridge

bridge = TicketingBridge("jira")

# Create ticket
ticket = bridge.create_ticket(
    title="Phishing Incident - INC-2024-001",
    description="Phishing email detected...",
    priority="high",
    ticket_type="Security Incident",
    labels=["phishing", "triage-warden"]
)
print(f"Created: {ticket['key']}")
print(f"URL: {ticket['url']}")

# Add comment
bridge.add_comment(
    ticket_id=ticket['id'],
    comment="Investigation complete. Verdict: Malicious"
)

# Update status
bridge.update_ticket(
    ticket_id=ticket['id'],
    status="Done"
)

# Search tickets
tickets = bridge.search_tickets(
    query="project = SEC AND labels = phishing",
    limit=10
)
```

## Ticket Templates

Define templates for consistent ticket creation:

```toml
# config/ticket_templates.toml

[templates.phishing]
title = "Phishing: {subject}"
description = """
## Incident Summary
- **Type**: Phishing
- **Severity**: {severity}
- **Incident ID**: {incident_id}

## Details
{details}

## Recommended Actions
{recommended_actions}
"""
labels = ["phishing", "triage-warden"]

[templates.malware]
title = "Malware Alert: {hostname}"
description = """
## Incident Summary
- **Type**: Malware
- **Host**: {hostname}
- **Detection**: {detection}

## IOCs
{iocs}
"""
labels = ["malware", "triage-warden"]
```

## Integration with Incidents

Tickets are automatically linked to incidents:

```rust
// Create ticket action stores the ticket key
let action = execute_action("create_ticket", incident_id, params).await?;

// Incident updated with ticket reference
incident.metadata["ticket_key"] = "SEC-1234";
incident.metadata["ticket_url"] = "https://company.atlassian.net/browse/SEC-1234";
```
