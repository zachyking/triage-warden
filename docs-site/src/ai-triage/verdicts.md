# Verdict Types

Understanding the classification outcomes from AI triage.

## Classifications

| Classification | Description | Typical Response |
|----------------|-------------|------------------|
| **Malicious** | Confirmed threat | Immediate containment |
| **Suspicious** | Likely threat, needs investigation | Queue for analyst review |
| **Benign** | Not a threat | Close or archive |
| **Inconclusive** | Insufficient data | Request more information |

## Malicious

The incident is a confirmed security threat.

**Criteria:**
- Multiple strong threat indicators
- High-confidence threat intelligence matches
- Clear malicious intent (credential theft, malware, etc.)

**Example:**
```json
{
  "classification": "malicious",
  "confidence": 0.95,
  "category": "phishing",
  "reasoning": "Email contains credential phishing page targeting Microsoft 365. Sender domain registered yesterday, fails all email authentication. URL redirects to fake login mimicking Microsoft branding."
}
```

**Response:**
- Execute recommended containment actions
- Create incident ticket
- Notify affected users

## Suspicious

The incident shows concerning indicators but lacks definitive proof.

**Criteria:**
- Some threat indicators present
- Mixed or conflicting signals
- Unusual but not clearly malicious behavior

**Example:**
```json
{
  "classification": "suspicious",
  "confidence": 0.65,
  "category": "potential_phishing",
  "reasoning": "Email sender is unknown but domain is 6 months old with valid authentication. URL leads to legitimate document sharing service but file name uses urgency tactics. Recipient has not received email from this sender before."
}
```

**Response:**
- Queue for analyst review
- Gather additional context
- Consider temporary quarantine pending review

## Benign

The incident is not a security threat.

**Criteria:**
- No threat indicators found
- Known good sender/source
- Normal expected behavior

**Example:**
```json
{
  "classification": "benign",
  "confidence": 0.92,
  "category": "legitimate_email",
  "reasoning": "Email from known vendor with established sending history. All authentication passes. Attachment is a standard invoice PDF matching expected format. No suspicious URLs or indicators."
}
```

**Response:**
- Close incident
- Release from quarantine if held
- Update detection rules if false positive

## Inconclusive

Insufficient data to make a determination.

**Criteria:**
- Missing critical information
- Tool failures preventing analysis
- Conflicting strong indicators

**Example:**
```json
{
  "classification": "inconclusive",
  "confidence": 0.3,
  "category": "unknown",
  "reasoning": "Unable to analyze attachment - file corrupted. Sender reputation service unavailable. Email authentication results are mixed (SPF pass, DKIM fail). Need manual review of attachment content.",
  "missing_data": [
    "attachment_analysis",
    "sender_reputation"
  ]
}
```

**Response:**
- Escalate to analyst
- Retry failed tool calls
- Request additional information

## Confidence Scores

Confidence ranges and their meaning:

| Range | Interpretation |
|-------|----------------|
| 0.9 - 1.0 | Very high confidence, clear evidence |
| 0.7 - 0.9 | High confidence, strong indicators |
| 0.5 - 0.7 | Moderate confidence, mixed signals |
| 0.3 - 0.5 | Low confidence, limited evidence |
| 0.0 - 0.3 | Very low confidence, insufficient data |

## Category Types

### Email Threats

| Category | Description |
|----------|-------------|
| `phishing` | Credential theft attempt |
| `spear_phishing` | Targeted phishing |
| `bec` | Business email compromise |
| `malware_delivery` | Malicious attachment/link |
| `spam` | Unsolicited bulk email |

### Endpoint Threats

| Category | Description |
|----------|-------------|
| `malware` | Malicious software detected |
| `ransomware` | Ransomware activity |
| `cryptominer` | Cryptocurrency mining |
| `rat` | Remote access trojan |
| `pup` | Potentially unwanted program |

### Access Threats

| Category | Description |
|----------|-------------|
| `brute_force` | Password guessing attempt |
| `credential_stuffing` | Leaked credential use |
| `impossible_travel` | Geographically impossible login |
| `account_takeover` | Compromised account |

## Using Verdicts

### Automation Rules

```yaml
# Auto-respond to high-confidence malicious
- trigger:
    classification: malicious
    confidence: ">= 0.9"
  actions:
    - quarantine_email
    - block_sender
    - create_ticket

# Queue suspicious for review
- trigger:
    classification: suspicious
  actions:
    - escalate:
        level: analyst
        reason: "Suspicious activity requires review"
```

### Metrics

Track verdict distribution:

```promql
# Verdict counts by classification
sum by (classification) (triage_verdict_total)

# Average confidence by category
avg by (category) (triage_confidence)
```
