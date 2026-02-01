# Email Actions

Actions for analyzing and responding to email-based threats.

## Analysis Actions

### parse_email

Extract headers, body, attachments, and URLs from raw email.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `raw_email` | string | Yes | Raw email content (RFC 822) |

**Output:**

```json
{
  "headers": {
    "From": "sender@example.com",
    "To": "recipient@company.com",
    "Subject": "Important Document",
    "Date": "2024-01-15T10:30:00Z",
    "Message-ID": "<abc123@example.com>",
    "X-Originating-IP": "[192.168.1.100]"
  },
  "sender": "sender@example.com",
  "recipients": ["recipient@company.com"],
  "subject": "Important Document",
  "body_text": "Please review the attached document...",
  "body_html": "<html>...",
  "attachments": [
    {
      "filename": "document.pdf",
      "content_type": "application/pdf",
      "size": 102400,
      "sha256": "abc123..."
    }
  ],
  "urls": [
    "https://example.com/document",
    "https://suspicious-site.com/login"
  ]
}
```

### check_email_authentication

Validate SPF, DKIM, and DMARC authentication results.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `headers` | object | Yes | Email headers (from parse_email) |

**Output:**

```json
{
  "spf": {
    "result": "pass",
    "domain": "example.com"
  },
  "dkim": {
    "result": "pass",
    "domain": "example.com",
    "selector": "default"
  },
  "dmarc": {
    "result": "pass",
    "policy": "reject"
  },
  "authentication_passed": true,
  "risk_indicators": []
}
```

**Risk Indicators:**

- `spf_fail` - SPF validation failed
- `dkim_fail` - DKIM signature invalid
- `dmarc_fail` - DMARC policy violation
- `header_mismatch` - From/Reply-To mismatch
- `suspicious_routing` - Unusual mail routing

## Response Actions

### quarantine_email

Move email to quarantine via email gateway.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `message_id` | string | Yes | Email message ID |
| `reason` | string | No | Reason for quarantine |

**Output:**

```json
{
  "quarantine_id": "quar-abc123",
  "message_id": "AAMkAGI2...",
  "quarantined_at": "2024-01-15T10:35:00Z"
}
```

**Rollback:** `release_email` - Releases email from quarantine

### block_sender

Add sender to organization blocklist.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `sender` | string | Yes | Email address to block |
| `scope` | string | No | Block scope: `organization` or `user` |

**Output:**

```json
{
  "block_id": "block-abc123",
  "sender": "phisher@malicious.com",
  "scope": "organization",
  "blocked_at": "2024-01-15T10:35:00Z"
}
```

**Rollback:** `unblock_sender` - Removes sender from blocklist

## Usage Examples

### Phishing Response Playbook

```yaml
name: phishing_response
steps:
  - action: parse_email
    output: parsed

  - action: check_email_authentication
    parameters:
      headers: "{{ parsed.headers }}"
    output: auth

  - action: lookup_sender_reputation
    parameters:
      sender: "{{ parsed.sender }}"
    output: reputation

  - condition: "reputation.score < 0.3 or not auth.authentication_passed"
    action: quarantine_email
    parameters:
      message_id: "{{ incident.raw_data.message_id }}"
      reason: "Failed authentication and low sender reputation"

  - condition: "reputation.score < 0.2"
    action: block_sender
    parameters:
      sender: "{{ parsed.sender }}"
      scope: organization
```

### CLI Example

```bash
# Quarantine suspicious email
tw-cli action execute \
  --action quarantine_email \
  --param message_id="AAMkAGI2..." \
  --param reason="Phishing indicators detected"

# Block malicious sender
tw-cli action execute \
  --action block_sender \
  --param sender="phisher@malicious.com" \
  --param scope=organization
```
