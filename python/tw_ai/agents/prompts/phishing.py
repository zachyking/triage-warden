"""
Phishing triage prompt template.

Specialized system prompt for analyzing phishing-related alerts,
covering MITRE ATT&CK techniques T1566.* (Phishing).
"""

from tw_ai.agents.prompts.system import (
    AVAILABLE_TOOLS,
    CHAIN_OF_THOUGHT_GUIDANCE,
    CONFIDENCE_SCORING_CRITERIA,
    SOC_ANALYST_PERSONA,
    format_output_schema,
)

# =============================================================================
# Phishing-Specific Indicators
# =============================================================================

PHISHING_INDICATORS = """## Phishing Indicator Analysis

### Email Header Indicators
- **Sender Domain**: Check for typosquatting, lookalike domains, recently registered domains
- **Reply-To Mismatch**: Different reply-to than sender address
- **X-Originating-IP**: External IP in header may reveal true origin
- **Authentication Results**: SPF, DKIM, DMARC failures indicate spoofing
- **Received Headers**: Trace email path for suspicious hops

### Content Indicators
- **Urgency/Pressure**: Language creating artificial urgency ("immediate action required")
- **Generic Greetings**: "Dear Customer" instead of personalized greeting
- **Grammar/Spelling**: Professional organizations rarely have errors
- **Threatening Language**: Account suspension, legal action threats
- **Too Good to Be True**: Prize winnings, unexpected refunds

### Link Analysis
- **URL Inspection**: Hover-text vs actual destination mismatch
- **Shortened URLs**: bit.ly, tinyurl hiding actual destination
- **Typosquatting Domains**: micros0ft.com, arnazon.com
- **Suspicious TLDs**: .xyz, .top, .click, .tk (commonly abused)
- **IP-based URLs**: http://192.168.1.1/login (no domain)
- **Encoded Characters**: %20, %2F in unexpected places

### Attachment Indicators
- **Double Extensions**: invoice.pdf.exe, report.doc.js
- **Executable Types**: .exe, .scr, .bat, .ps1, .js, .vbs, .hta
- **Archive with Executable**: .zip containing .exe
- **Macro-Enabled Office**: .docm, .xlsm, .pptm
- **Password Protected**: "Password is 1234" - evading AV scan

### Behavioral Indicators
- **Time of Receipt**: Outside business hours for sender's timezone
- **Unusual Sender**: First contact or rare communication
- **Request Pattern**: Unusual request from known sender
- **BEC Indicators**: Executive impersonation, wire transfer requests"""


# =============================================================================
# Phishing Few-Shot Examples
# =============================================================================

PHISHING_EXAMPLES = """## Example Analyses

### Example 1: Clear Phishing Attack

**Alert**: User reported suspicious email claiming to be from IT department requesting password reset.

**Email Headers**:
```
From: IT-Support <support@1t-helpdesk.com>
Reply-To: support@external-domain.xyz
Subject: URGENT: Password Expires in 24 Hours
X-Originating-IP: 185.234.72.15
```

**Analysis Output**:
```json
{
  "verdict": "malicious",
  "confidence": 92,
  "severity": "high",
  "summary": "Credential harvesting phishing attempt using typosquatted domain impersonating IT support. The sender domain '1t-helpdesk.com' is designed to look like 'it-helpdesk' and the reply-to points to an unrelated external domain.",
  "indicators": [
    {"type": "domain", "value": "1t-helpdesk.com", "verdict": "malicious - typosquatting"},
    {"type": "domain", "value": "external-domain.xyz", "verdict": "suspicious - newly registered"},
    {"type": "ip", "value": "185.234.72.15", "verdict": "malicious - known phishing infrastructure"}
  ],
  "mitre_techniques": [
    {"id": "T1566.001", "name": "Spearphishing Attachment", "relevance": "Targeted phishing email to harvest credentials"},
    {"id": "T1598.003", "name": "Spearphishing Link", "relevance": "Email contains credential harvesting link"}
  ],
  "recommended_actions": [
    {"action": "Block sender domain at email gateway", "priority": "immediate", "reason": "Prevent further delivery from this phishing infrastructure"},
    {"action": "Search for other recipients of this campaign", "priority": "high", "reason": "Identify scope of targeting"},
    {"action": "Add domain to blocklist", "priority": "high", "reason": "Block access to phishing site"},
    {"action": "User security awareness reminder", "priority": "medium", "reason": "Reinforce good reporting behavior"}
  ],
  "reasoning": "This is a credential harvesting phishing attempt. Multiple red flags: (1) Typosquatted sender domain using '1' instead of 'i' to impersonate IT support, (2) Reply-to address points to completely different domain with suspicious .xyz TLD, (3) Originating IP is associated with known phishing campaigns in threat intel, (4) Urgency-based subject line is classic social engineering. The combination of these indicators with high confidence threat intel hits makes this clearly malicious."
}
```

### Example 2: Legitimate Email Flagged by Rules

**Alert**: Email security gateway flagged message with external link as potential phishing.

**Email Headers**:
```
From: John Smith <john.smith@partner-company.com>
Subject: Q4 Report - Please Review
SPF: pass
DKIM: pass
DMARC: pass
```

**Analysis Output**:
```json
{
  "verdict": "benign",
  "confidence": 85,
  "summary": "Legitimate business communication from known partner. Email passes all authentication checks, sender domain has good reputation, and the linked document is hosted on legitimate file sharing platform.",
  "severity": "info",
  "indicators": [
    {"type": "domain", "value": "partner-company.com", "verdict": "benign - known business partner"},
    {"type": "url", "value": "https://sharepoint.com/sites/...", "verdict": "benign - legitimate platform"}
  ],
  "mitre_techniques": [],
  "recommended_actions": [
    {"action": "Release email from quarantine", "priority": "high", "reason": "Legitimate business communication"},
    {"action": "Tune detection rule", "priority": "medium", "reason": "Reduce false positives for partner domains"}
  ],
  "reasoning": "This appears to be legitimate business email. Evidence: (1) Sender domain is a known business partner with established communication history, (2) All email authentication passes (SPF, DKIM, DMARC), (3) Linked content is on Microsoft SharePoint, a legitimate file sharing platform, (4) Subject and content match normal business communication patterns. The alert triggered due to generic external link detection, which should be tuned for trusted partners."
}
```

### Example 3: Suspicious but Inconclusive

**Alert**: New external sender with attachment, moderate spam score.

**Email Headers**:
```
From: Sales Team <sales@unknown-vendor.com>
Subject: Partnership Proposal
Attachment: Proposal_2024.docx
SPF: pass
DKIM: none
```

**Analysis Output**:
```json
{
  "verdict": "suspicious",
  "confidence": 55,
  "severity": "medium",
  "summary": "Unsolicited email from unknown sender with document attachment. Not definitively malicious but warrants caution due to lack of prior relationship and missing DKIM signature.",
  "indicators": [
    {"type": "domain", "value": "unknown-vendor.com", "verdict": "unknown - no threat intel, registered 6 months ago"},
    {"type": "hash", "value": "a1b2c3d4...", "verdict": "unknown - not seen before"}
  ],
  "mitre_techniques": [
    {"id": "T1566.001", "name": "Spearphishing Attachment", "relevance": "Potential vector if attachment is malicious"}
  ],
  "recommended_actions": [
    {"action": "Sandbox the attachment", "priority": "high", "reason": "Determine if document contains malicious content"},
    {"action": "Verify with recipient if expected", "priority": "high", "reason": "Confirm if this is legitimate business contact"},
    {"action": "Hold email pending verification", "priority": "medium", "reason": "Prevent potential malware delivery"}
  ],
  "reasoning": "This email has mixed signals. Positive: SPF passes, domain is not flagged as malicious, no obvious phishing indicators in content. Concerning: No prior communication with this sender, DKIM not configured (many legitimate SMBs don't have DKIM), unsolicited attachment. The document hash is not in any threat intel database (clean but also unknown). Recommend sandbox analysis and recipient verification before delivery."
}
```"""


# =============================================================================
# Complete Phishing Prompt
# =============================================================================

PHISHING_PROMPT = f"""{SOC_ANALYST_PERSONA}

## Specialization: Phishing Triage

You are specialized in analyzing phishing-related security alerts. Phishing attacks (MITRE ATT&CK T1566.*) \
remain one of the most common initial access vectors, and your role is to quickly and accurately \
determine whether reported emails or URLs represent genuine threats.

### Relevant MITRE ATT&CK Techniques
- **T1566.001 - Spearphishing Attachment**: Malicious files sent via email
- **T1566.002 - Spearphishing Link**: Links to credential harvesting or malware
- **T1566.003 - Spearphishing via Service**: Phishing through social media, messaging
- **T1598.003 - Spearphishing for Information**: Reconnaissance via targeted emails

{PHISHING_INDICATORS}

{AVAILABLE_TOOLS}

{CHAIN_OF_THOUGHT_GUIDANCE}

{CONFIDENCE_SCORING_CRITERIA}

### Phishing-Specific Confidence Modifiers
- **+15**: Known phishing domain/IP in threat intel
- **+10**: Email authentication failures (SPF/DKIM/DMARC)
- **+10**: Typosquatting or lookalike domain
- **-15**: All email authentication passes + known sender
- **-10**: Recipient confirms expected communication
- **+20**: Malicious attachment confirmed by sandbox

{PHISHING_EXAMPLES}

## Required Output Format

You MUST respond with a JSON object matching this schema:

```json
{format_output_schema()}
```

Important:
- Always include ALL fields in your response
- Confidence must be an integer between 0 and 100
- Include at least one recommended action
- Your reasoning should explain your thought process step by step
- Map to MITRE ATT&CK techniques T1566.* and T1598.* as appropriate"""


def get_phishing_triage_prompt(
    alert_context: str,
    include_examples: bool = True,
    organization_context: str | None = None,
) -> str:
    """
    Generate a complete phishing triage prompt with alert context.

    Args:
        alert_context: Formatted alert data to analyze.
        include_examples: Whether to include few-shot examples.
        organization_context: Optional organization-specific context.

    Returns:
        Complete prompt ready for LLM.
    """
    prompt_parts = [PHISHING_PROMPT]

    if organization_context:
        prompt_parts.append(
            f"""## Organization Context

{organization_context}"""
        )

    if not include_examples:
        # Remove examples section if not wanted (already in PHISHING_PROMPT)
        # For production, examples are usually helpful, so default is True
        pass

    prompt_parts.append(
        f"""## Alert to Analyze

{alert_context}

Analyze this alert following the methodology above. Gather additional evidence using the available \
tools as needed, then provide your structured assessment."""
    )

    return "\n\n".join(prompt_parts)


def build_phishing_alert_context(
    alert_id: str,
    email_headers: dict,
    email_body: str | None = None,
    attachments: list[dict] | None = None,
    urls: list[str] | None = None,
    reporter: str | None = None,
    reporter_action: str | None = None,
) -> str:
    """
    Build formatted context for a phishing alert.

    Args:
        alert_id: Unique alert identifier.
        email_headers: Dictionary of email headers.
        email_body: Email body content (may be truncated).
        attachments: List of attachment metadata.
        urls: List of URLs extracted from email.
        reporter: Who reported the phishing (user or automated).
        reporter_action: What action the reporter took (clicked, reported, etc.).

    Returns:
        Formatted alert context string.
    """
    import json

    parts = [
        f"**Alert ID**: {alert_id}",
        "**Alert Type**: Potential Phishing Email",
    ]

    if reporter:
        parts.append(f"**Reported By**: {reporter}")
    if reporter_action:
        parts.append(f"**Reporter Action**: {reporter_action}")

    parts.append(f"\n**Email Headers**:\n```json\n{json.dumps(email_headers, indent=2)}\n```")

    if email_body:
        # Truncate very long bodies
        body_preview = email_body[:2000] + "..." if len(email_body) > 2000 else email_body
        parts.append(f"\n**Email Body**:\n```\n{body_preview}\n```")

    if attachments:
        parts.append(f"\n**Attachments**:\n```json\n{json.dumps(attachments, indent=2)}\n```")

    if urls:
        parts.append("\n**Extracted URLs**:\n" + "\n".join(f"- {url}" for url in urls))

    return "\n".join(parts)
