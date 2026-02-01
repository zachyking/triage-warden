# Lookup Actions

Actions for enriching incidents with threat intelligence data.

## lookup_sender_reputation

Query threat intelligence for sender domain and IP reputation.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `sender` | string | Yes | Email address |
| `originating_ip` | string | No | Sending server IP |

**Output:**

```json
{
  "sender": "suspicious@domain.com",
  "domain": "domain.com",
  "domain_reputation": {
    "score": 0.25,
    "categories": ["phishing", "newly-registered"],
    "first_seen": "2024-01-10",
    "registrar": "NameCheap"
  },
  "ip_reputation": {
    "ip": "192.168.1.100",
    "score": 0.3,
    "categories": ["spam", "proxy"],
    "country": "RU",
    "asn": "AS12345"
  },
  "overall_score": 0.25,
  "risk_level": "high"
}
```

**Score Interpretation:**

| Score | Risk Level |
|-------|------------|
| 0.0 - 0.3 | High risk |
| 0.3 - 0.6 | Medium risk |
| 0.6 - 0.8 | Low risk |
| 0.8 - 1.0 | Clean |

## lookup_urls

Check URLs against threat intelligence.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `urls` | array | Yes | List of URLs to check |

**Output:**

```json
{
  "results": [
    {
      "url": "https://legitimate-site.com/page",
      "malicious": false,
      "categories": ["business"],
      "confidence": 0.95
    },
    {
      "url": "https://phishing-site.com/login",
      "malicious": true,
      "categories": ["phishing", "credential-theft"],
      "confidence": 0.92,
      "threat_details": {
        "targeted_brand": "Microsoft",
        "first_seen": "2024-01-14"
      }
    }
  ],
  "malicious_count": 1,
  "total_count": 2
}
```

## lookup_attachments

Hash attachments and check against threat intelligence.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `attachments` | array | Yes | List of attachment objects with `sha256` |

**Output:**

```json
{
  "results": [
    {
      "filename": "invoice.pdf",
      "sha256": "abc123...",
      "malicious": false,
      "file_type": "PDF document",
      "confidence": 0.9
    },
    {
      "filename": "update.exe",
      "sha256": "def456...",
      "malicious": true,
      "file_type": "Windows executable",
      "confidence": 0.98,
      "threat_details": {
        "malware_family": "Emotet",
        "first_seen": "2024-01-12",
        "detection_engines": 45
      }
    }
  ],
  "malicious_count": 1,
  "total_count": 2
}
```

## lookup_hash

Look up a single file hash.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `hash` | string | Yes | MD5, SHA1, or SHA256 hash |

**Output:**

```json
{
  "hash": "abc123...",
  "hash_type": "sha256",
  "malicious": true,
  "confidence": 0.95,
  "malware_family": "Emotet",
  "categories": ["trojan", "banking"],
  "first_seen": "2024-01-12",
  "last_seen": "2024-01-15",
  "detection_ratio": "45/70"
}
```

## lookup_ip

Query IP address reputation.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `ip` | string | Yes | IP address |

**Output:**

```json
{
  "ip": "192.168.1.100",
  "malicious": true,
  "confidence": 0.8,
  "categories": ["c2", "malware-distribution"],
  "country": "RU",
  "asn": "AS12345",
  "asn_org": "Example ISP",
  "last_seen": "2024-01-15",
  "associated_malware": ["Cobalt Strike"]
}
```

## Usage in Playbooks

```yaml
name: email_triage
steps:
  - action: parse_email
    output: parsed

  - action: lookup_sender_reputation
    parameters:
      sender: "{{ parsed.sender }}"
    output: sender_rep

  - action: lookup_urls
    parameters:
      urls: "{{ parsed.urls }}"
    output: url_results

  - action: lookup_attachments
    parameters:
      attachments: "{{ parsed.attachments }}"
    output: attachment_results

  # Make decision based on lookups
  - condition: >
      sender_rep.risk_level == 'high' or
      url_results.malicious_count > 0 or
      attachment_results.malicious_count > 0
    set_verdict:
      classification: malicious
      confidence: 0.9
```

## Caching

Lookup results are cached to reduce API calls:

| Lookup | Cache Duration |
|--------|----------------|
| Hash | 24 hours |
| URL | 1 hour |
| Domain | 6 hours |
| IP | 6 hours |

Force fresh lookup with `skip_cache: true` parameter.
