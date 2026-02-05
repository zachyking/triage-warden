"""
Evidence collection prompt components for audit-ready investigation reports.

This module defines prompts that guide the AI to collect and cite evidence
in a structured format that supports Stage 2.1 explainability requirements.

The evidence collection system ensures:
1. Every finding is backed by observable evidence
2. Evidence sources are clearly cited for auditability
3. Confidence scores are provided per-evidence item
4. Investigation steps are documented for reproducibility
"""

from typing import Any

# =============================================================================
# Evidence Collection Instructions
# =============================================================================

EVIDENCE_COLLECTION_PROMPT = """## Evidence-Based Analysis Requirements

When analyzing this incident, you MUST:

1. **List each piece of evidence you examine**
   - Explicitly state what data you looked at
   - Note where the evidence came from (source system, enrichment, alert data)
   - Extract specific values (IPs, hashes, domains, timestamps)

2. **Cite the source of each evidence item**
   - Alert data: Reference specific fields from the original alert
   - Enrichments: Note which enrichment provided the data (e.g., "VirusTotal lookup", "SIEM query")
   - Threat intelligence: Cite the TI provider and lookup date
   - Tool results: Reference the specific tool call that gathered the evidence

3. **Explain how each piece contributes to your verdict**
   - State whether the evidence supports malicious, benign, or suspicious assessment
   - Explain the reasoning for each assessment
   - Note any conflicting evidence and how you resolved it

4. **Rate your confidence for each individual finding**
   - Use a 0-100 scale for each evidence item
   - Higher confidence for corroborated findings
   - Lower confidence for single-source or ambiguous data

## Evidence Output Format

For each piece of evidence, include it in the `evidence` array with this structure:

```json
{
  "evidence": [
    {
      "source_type": "threat_intel|siem|edr|email|enrichment|alert_data|manual",
      "source_name": "VirusTotal|Splunk|CrowdStrike|etc.",
      "data_type": "network_activity|file_artifact|process_execution|user_behavior|email_content|threat_intel_match|mitre_observation|authentication_event|malware_indicator",
      "value": {"key": "the actual evidence data"},
      "finding": "Description of what this evidence shows",
      "relevance": "How this evidence relates to the verdict",
      "confidence": 85,
      "link": "optional URL to view in source system"
    }
  ]
}
```

## Investigation Steps Documentation

Document your investigation process in the `investigation_steps` array:

```json
{
  "investigation_steps": [
    {
      "order": 1,
      "action": "What you did (e.g., 'Queried VirusTotal for file hash')",
      "result": "What you found (e.g., '45/70 engines flagged as malicious')",
      "tool": "Optional: which tool was used",
      "status": "completed|failed|skipped"
    }
  ]
}
```

## Evidence Quality Standards

### High-Quality Evidence (Confidence 80-100):
- Multiple independent sources confirm the finding
- Direct observation of malicious behavior
- Known-bad indicators with recent threat intel
- Clear MITRE ATT&CK technique alignment

### Medium-Quality Evidence (Confidence 50-79):
- Single authoritative source
- Suspicious but not definitively malicious
- Behavioral anomalies without clear malicious intent
- Historical or slightly outdated threat intel

### Low-Quality Evidence (Confidence 0-49):
- Single low-fidelity source
- Circumstantial or indirect indicators
- No threat intel coverage
- Potentially coincidental patterns

## Evidence Categories by Source

### From Alert Data
- Original alert fields and values
- Timestamps and event sequences
- User/host identifiers affected
- Initial severity and classification

### From Enrichments
- Threat intelligence lookups (hash, IP, domain reputation)
- Asset context (criticality, ownership, role)
- User context (privilege level, behavior baseline)
- Historical correlation with past incidents

### From Tool Results
- SIEM query results with specific log entries
- EDR telemetry showing process/network activity
- Email header analysis findings
- Sandbox detonation results for attachments

### Manual Observations
- Pattern recognition across data sources
- Attack chain reconstruction
- Behavioral analysis conclusions
- Risk assessment based on context"""


# =============================================================================
# Evidence-Enhanced Output Schema
# =============================================================================

EVIDENCE_OUTPUT_SCHEMA = {
    "verdict": {
        "type": "string",
        "enum": ["true_positive", "false_positive", "suspicious", "inconclusive"],
        "description": "Final determination of the alert",
    },
    "confidence": {
        "type": "integer",
        "minimum": 0,
        "maximum": 100,
        "description": "Overall confidence score in the verdict (0-100)",
    },
    "severity": {
        "type": "string",
        "enum": ["critical", "high", "medium", "low", "informational"],
        "description": "Severity level for response prioritization",
    },
    "summary": {
        "type": "string",
        "description": "Concise summary of findings (2-3 sentences)",
    },
    "evidence": {
        "type": "array",
        "items": {
            "type": "object",
            "properties": {
                "source_type": {
                    "type": "string",
                    "enum": [
                        "threat_intel",
                        "siem",
                        "edr",
                        "email",
                        "enrichment",
                        "alert_data",
                        "manual",
                        "cloud",
                        "identity_provider",
                    ],
                    "description": "Category of evidence source",
                },
                "source_name": {
                    "type": "string",
                    "description": "Specific source (e.g., 'VirusTotal', 'Splunk', 'CrowdStrike')",
                },
                "data_type": {
                    "type": "string",
                    "enum": [
                        "network_activity",
                        "file_artifact",
                        "process_execution",
                        "user_behavior",
                        "email_content",
                        "threat_intel_match",
                        "mitre_observation",
                        "system_change",
                        "dns_activity",
                        "web_activity",
                        "cloud_activity",
                        "authentication_event",
                        "data_access",
                        "malware_indicator",
                    ],
                    "description": "Type of evidence data",
                },
                "value": {
                    "type": "object",
                    "description": "The actual evidence data/values",
                },
                "finding": {
                    "type": "string",
                    "description": "What this evidence shows or indicates",
                },
                "relevance": {
                    "type": "string",
                    "description": "How this evidence relates to and supports the verdict",
                },
                "confidence": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 100,
                    "description": "Confidence in this specific piece of evidence (0-100)",
                },
                "link": {
                    "type": "string",
                    "description": "Optional deep link to view evidence in source system",
                },
            },
            "required": [
                "source_type",
                "source_name",
                "data_type",
                "value",
                "finding",
                "relevance",
                "confidence",
            ],
        },
        "description": "List of evidence items supporting the analysis",
    },
    "investigation_steps": {
        "type": "array",
        "items": {
            "type": "object",
            "properties": {
                "order": {
                    "type": "integer",
                    "minimum": 1,
                    "description": "Step order in the investigation (1-indexed)",
                },
                "action": {
                    "type": "string",
                    "description": "Description of the action taken",
                },
                "result": {
                    "type": "string",
                    "description": "Result or output of this step",
                },
                "tool": {
                    "type": "string",
                    "description": "Optional: tool or system used for this step",
                },
                "status": {
                    "type": "string",
                    "enum": ["completed", "failed", "skipped"],
                    "description": "Status of this investigation step",
                },
            },
            "required": ["order", "action", "result", "status"],
        },
        "description": "Ordered list of investigation steps taken",
    },
    "indicators": {
        "type": "array",
        "items": {
            "type": "object",
            "properties": {
                "type": {
                    "type": "string",
                    "description": "Indicator type (ip, domain, hash, url, email)",
                },
                "value": {"type": "string", "description": "The indicator value"},
                "verdict": {
                    "type": "string",
                    "description": "Assessment of this specific indicator",
                },
            },
        },
        "description": "List of extracted and analyzed indicators",
    },
    "mitre_techniques": {
        "type": "array",
        "items": {
            "type": "object",
            "properties": {
                "id": {"type": "string", "description": "MITRE technique ID (e.g., T1566.001)"},
                "name": {"type": "string", "description": "Technique name"},
                "tactic": {"type": "string", "description": "Associated tactic"},
                "relevance": {
                    "type": "string",
                    "description": "How this technique relates to the alert",
                },
            },
        },
        "description": "Mapped MITRE ATT&CK techniques",
    },
    "recommended_actions": {
        "type": "array",
        "items": {
            "type": "object",
            "properties": {
                "action": {"type": "string", "description": "Specific action to take"},
                "priority": {"type": "string", "enum": ["immediate", "high", "medium", "low"]},
                "reason": {"type": "string", "description": "Justification for the action"},
            },
        },
        "description": "Recommended response actions",
    },
    "reasoning": {
        "type": "string",
        "description": "Detailed chain-of-thought reasoning explaining the analysis",
    },
}


def format_evidence_output_schema() -> str:
    """Format the evidence-enhanced output schema as a string for inclusion in prompts."""
    import json

    return json.dumps(EVIDENCE_OUTPUT_SCHEMA, indent=2)


# =============================================================================
# Evidence Collection Examples
# =============================================================================

EVIDENCE_COLLECTION_EXAMPLES = """## Evidence Collection Examples

### Example 1: Phishing with Multiple Evidence Sources

**Evidence Array**:
```json
{
  "evidence": [
    {
      "source_type": "alert_data",
      "source_name": "Email Security Gateway",
      "data_type": "email_content",
      "value": {
        "sender": "support@micros0ft.com",
        "subject": "URGENT: Account Verification Required",
        "spf_result": "fail",
        "dkim_result": "none"
      },
      "finding": "Email from typosquatted domain with failed authentication",
      "relevance": "Typosquatting 'micros0ft' for 'microsoft' is a common phishing technique. SPF failure indicates the sender is not authorized.",
      "confidence": 90
    },
    {
      "source_type": "threat_intel",
      "source_name": "VirusTotal",
      "data_type": "threat_intel_match",
      "value": {
        "domain": "micros0ft.com",
        "malicious_votes": 12,
        "total_votes": 15,
        "categories": ["phishing", "malware"]
      },
      "finding": "Domain flagged as malicious by 12/15 security vendors",
      "relevance": "High-confidence threat intel confirms this is a known phishing domain",
      "confidence": 95,
      "link": "https://www.virustotal.com/gui/domain/micros0ft.com"
    },
    {
      "source_type": "siem",
      "source_name": "Splunk",
      "data_type": "user_behavior",
      "value": {
        "user": "jsmith@company.com",
        "clicked_link": false,
        "reported_at": "2024-01-15T14:32:00Z",
        "prior_phishing_reports": 2
      },
      "finding": "User did not click link and reported the email promptly",
      "relevance": "No credential exposure risk; user followed security awareness training",
      "confidence": 100
    }
  ],
  "investigation_steps": [
    {
      "order": 1,
      "action": "Extracted sender domain from email headers",
      "result": "Identified 'micros0ft.com' as sender domain with typosquatting pattern",
      "status": "completed"
    },
    {
      "order": 2,
      "action": "Queried VirusTotal for domain reputation",
      "result": "Domain flagged as malicious/phishing by 12/15 vendors",
      "tool": "lookup_domain",
      "status": "completed"
    },
    {
      "order": 3,
      "action": "Searched SIEM for user interaction with email",
      "result": "User reported email without clicking any links",
      "tool": "search_siem",
      "status": "completed"
    },
    {
      "order": 4,
      "action": "Checked for other recipients in organization",
      "result": "Found 3 additional recipients of the same campaign",
      "tool": "search_siem",
      "status": "completed"
    }
  ]
}
```

### Example 2: Malware Alert with EDR Evidence

**Evidence Array**:
```json
{
  "evidence": [
    {
      "source_type": "edr",
      "source_name": "CrowdStrike",
      "data_type": "process_execution",
      "value": {
        "process_name": "powershell.exe",
        "command_line": "powershell -enc JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAA...",
        "parent_process": "WINWORD.EXE",
        "user": "DOMAIN\\jsmith"
      },
      "finding": "Encoded PowerShell launched from Word document",
      "relevance": "Classic Office macro malware execution pattern - Word spawning encoded PowerShell is highly suspicious",
      "confidence": 92
    },
    {
      "source_type": "edr",
      "source_name": "CrowdStrike",
      "data_type": "network_activity",
      "value": {
        "destination_ip": "185.234.72.15",
        "destination_port": 443,
        "bytes_out": 4532,
        "process": "powershell.exe"
      },
      "finding": "PowerShell made outbound connection to external IP",
      "relevance": "Network connection immediately after encoded PowerShell execution suggests C2 communication attempt",
      "confidence": 88
    },
    {
      "source_type": "threat_intel",
      "source_name": "CrowdStrike Threat Intel",
      "data_type": "threat_intel_match",
      "value": {
        "ip": "185.234.72.15",
        "actor": "WIZARD SPIDER",
        "malware_family": "TrickBot",
        "last_seen": "2024-01-10"
      },
      "finding": "Destination IP associated with WIZARD SPIDER TrickBot infrastructure",
      "relevance": "Known threat actor infrastructure confirms this is active malware campaign",
      "confidence": 95,
      "link": "https://falcon.crowdstrike.com/intelligence/actors/wizard-spider"
    },
    {
      "source_type": "edr",
      "source_name": "CrowdStrike",
      "data_type": "file_artifact",
      "value": {
        "file_path": "C:\\Users\\jsmith\\AppData\\Local\\Temp\\update.exe",
        "sha256": "a1b2c3d4e5f6...",
        "signed": false,
        "created_at": "2024-01-15T14:32:15Z"
      },
      "finding": "Unsigned executable dropped to temp directory",
      "relevance": "Payload drop is consistent with TrickBot infection chain",
      "confidence": 90
    }
  ],
  "investigation_steps": [
    {
      "order": 1,
      "action": "Reviewed EDR process tree for affected host",
      "result": "Identified Word -> PowerShell -> network connection chain",
      "tool": "get_host_info",
      "status": "completed"
    },
    {
      "order": 2,
      "action": "Decoded base64 PowerShell command",
      "result": "Downloader script targeting external IP for payload retrieval",
      "status": "completed"
    },
    {
      "order": 3,
      "action": "Queried threat intel for destination IP",
      "result": "IP matched known TrickBot C2 infrastructure",
      "tool": "lookup_ip",
      "status": "completed"
    },
    {
      "order": 4,
      "action": "Checked if payload was successfully downloaded",
      "result": "update.exe dropped but execution was blocked by EDR",
      "tool": "get_host_info",
      "status": "completed"
    },
    {
      "order": 5,
      "action": "Mapped attack to MITRE ATT&CK framework",
      "result": "T1566.001 (Spearphishing Attachment), T1059.001 (PowerShell), T1071.001 (Web Protocols)",
      "tool": "map_to_mitre",
      "status": "completed"
    }
  ]
}
```"""


# =============================================================================
# Prompt Assembly Functions
# =============================================================================


def get_evidence_enhanced_prompt(
    base_prompt: str,
    include_examples: bool = True,
) -> str:
    """
    Enhance a base prompt with evidence collection requirements.

    This function adds the evidence collection instructions and schema
    to any existing triage prompt.

    Args:
        base_prompt: The base system prompt to enhance.
        include_examples: Whether to include evidence collection examples.

    Returns:
        Enhanced prompt with evidence collection requirements.
    """
    parts = [base_prompt, EVIDENCE_COLLECTION_PROMPT]

    if include_examples:
        parts.append(EVIDENCE_COLLECTION_EXAMPLES)

    parts.append(f"""## Required Output Format (Evidence-Enhanced)

You MUST respond with a JSON object matching this schema:

```json
{format_evidence_output_schema()}
```

**Critical Requirements**:
1. Include at least 3 evidence items supporting your verdict
2. Each evidence item must have a confidence score
3. Document your investigation steps in order
4. Your reasoning must reference the evidence you collected
5. All evidence sources must be cited""")

    return "\n\n".join(parts)


def build_evidence_context(
    alert_data: dict[str, Any],
    enrichments: list[dict[str, Any]] | None = None,
    prior_analysis: dict[str, Any] | None = None,
) -> str:
    """
    Build formatted context for evidence-aware analysis.

    Args:
        alert_data: Raw alert data to analyze.
        enrichments: List of enrichment results already gathered.
        prior_analysis: Optional prior analysis to review/update.

    Returns:
        Formatted context string for inclusion in prompts.
    """
    import json

    parts = ["## Evidence Sources Available\n"]

    # Alert data as primary evidence source
    parts.append(f"""### Primary Source: Alert Data
```json
{json.dumps(alert_data, indent=2, default=str)}
```
""")

    # Include enrichments as additional evidence
    if enrichments:
        parts.append("### Enrichment Evidence\n")
        for i, enrichment in enumerate(enrichments, 1):
            source = enrichment.get("source", "Unknown")
            data = enrichment.get("data", {})
            parts.append(f"""**Enrichment {i}** (Source: {source}):
```json
{json.dumps(data, indent=2, default=str)}
```
""")

    # Include prior analysis if reviewing
    if prior_analysis:
        parts.append(f"""### Prior Analysis (for Review)
```json
{json.dumps(prior_analysis, indent=2, default=str)}
```

If reviewing a prior analysis, you should:
1. Verify the evidence cited still supports the conclusion
2. Check if new evidence has emerged
3. Update confidence scores based on current assessment
4. Add any new evidence discovered during review
""")

    return "\n".join(parts)
