"""AI-driven hunting hypothesis generation.

Uses LLM analysis of recent incidents, threat intelligence, asset profiles,
and MITRE ATT&CK coverage gaps to generate actionable hunting hypotheses.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class Hypothesis(BaseModel):
    """A generated hunting hypothesis with supporting details."""

    statement: str = Field(description="The hypothesis statement to test")
    priority: str = Field(
        description="Priority level: high, medium, or low",
        pattern="^(high|medium|low)$",
    )
    expected_indicators: list[str] = Field(
        default_factory=list,
        description="IOCs or patterns to look for",
    )
    suggested_queries: list[dict[str, str]] = Field(
        default_factory=list,
        description="Suggested queries keyed by platform (e.g., {'splunk': '...'})",
    )
    mitre_techniques: list[str] = Field(
        default_factory=list,
        description="Relevant MITRE ATT&CK technique IDs",
    )
    rationale: str = Field(
        description="Explanation of why this hypothesis is worth investigating",
    )
    data_sources: list[str] = Field(
        default_factory=list,
        description="Required data sources to test this hypothesis",
    )


class HuntingContext(BaseModel):
    """Context provided to the hypothesis generator."""

    recent_incidents: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Recent incident summaries for pattern analysis",
    )
    threat_intel_summary: str = Field(
        default="",
        description="Current threat landscape summary",
    )
    asset_profile: dict[str, Any] = Field(
        default_factory=dict,
        description="Organization asset profile (OS distribution, critical assets, etc.)",
    )
    mitre_coverage_gaps: list[str] = Field(
        default_factory=list,
        description="MITRE technique IDs with no current detection coverage",
    )
    recent_false_positives: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Recent false positives that may indicate missed detections",
    )


class HypothesisGenerator:
    """Generates hunting hypotheses using LLM analysis of security context.

    The generator takes organizational context (recent incidents, threat intel,
    asset profiles, detection gaps) and produces prioritized hunting hypotheses
    that analysts can use to create threat hunts.
    """

    def __init__(self, llm_provider: Any | None = None):
        """Initialize the generator.

        Args:
            llm_provider: Optional LLM provider for hypothesis generation.
                If None, uses rule-based generation as fallback.
        """
        self._llm = llm_provider

    async def generate(self, context: HuntingContext) -> list[Hypothesis]:
        """Generate hunting hypotheses based on the provided context.

        Produces 3-5 prioritized hypotheses by analyzing:
        - Recent incident patterns for recurring threats
        - Threat intel for emerging attack techniques
        - MITRE coverage gaps for blind spots
        - False positives that may mask real attacks

        Args:
            context: Security context for hypothesis generation.

        Returns:
            List of 3-5 Hypothesis objects ordered by priority.
        """
        if self._llm is not None:
            return await self._generate_with_llm(context)
        return self._generate_rule_based(context)

    async def _generate_with_llm(self, context: HuntingContext) -> list[Hypothesis]:
        """Generate hypotheses using LLM analysis."""
        prompt = self._build_prompt(context)
        try:
            response = await self._llm.generate(prompt)  # type: ignore[union-attr]
            hypotheses = self._parse_hypotheses(response)
            if hypotheses:
                return hypotheses
        except Exception as e:
            logger.warning("LLM hypothesis generation failed, using fallback: %s", e)

        return self._generate_rule_based(context)

    def _build_prompt(self, context: HuntingContext) -> str:
        """Build the LLM prompt for hypothesis generation.

        Args:
            context: Security context to incorporate.

        Returns:
            Formatted prompt string.
        """
        sections = [
            "You are a senior threat hunter. Based on the following security context, "
            "generate 3-5 actionable hunting hypotheses.\n",
        ]

        if context.recent_incidents:
            incident_summary = json.dumps(context.recent_incidents[:10], indent=2)
            sections.append(f"## Recent Incidents\n{incident_summary}\n")

        if context.threat_intel_summary:
            sections.append(f"## Threat Intelligence\n{context.threat_intel_summary}\n")

        if context.asset_profile:
            asset_summary = json.dumps(context.asset_profile, indent=2)
            sections.append(f"## Asset Profile\n{asset_summary}\n")

        if context.mitre_coverage_gaps:
            gaps = ", ".join(context.mitre_coverage_gaps[:20])
            sections.append(f"## MITRE ATT&CK Coverage Gaps\n{gaps}\n")

        if context.recent_false_positives:
            fp_summary = json.dumps(context.recent_false_positives[:5], indent=2)
            sections.append(f"## Recent False Positives\n{fp_summary}\n")

        sections.append(
            "## Output Format\n"
            "Return a JSON array of hypotheses. Each hypothesis must have:\n"
            '- "statement": The hypothesis to test\n'
            '- "priority": "high", "medium", or "low"\n'
            '- "expected_indicators": List of IOCs/patterns to look for\n'
            '- "suggested_queries": List of {query_type: query} dicts\n'
            '- "mitre_techniques": List of technique IDs (e.g., T1558.003)\n'
            '- "rationale": Why this is worth investigating\n'
            '- "data_sources": Required data sources\n\n'
            "Return ONLY the JSON array, no other text."
        )

        return "\n".join(sections)

    def _parse_hypotheses(self, response: str) -> list[Hypothesis]:
        """Parse LLM response into Hypothesis objects.

        Args:
            response: Raw LLM response text.

        Returns:
            List of validated Hypothesis objects.
        """
        # Try to extract JSON from the response
        text = response.strip()

        # Handle markdown code blocks
        if "```json" in text:
            start = text.index("```json") + 7
            end = text.index("```", start)
            text = text[start:end].strip()
        elif "```" in text:
            start = text.index("```") + 3
            end = text.index("```", start)
            text = text[start:end].strip()

        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            logger.warning("Failed to parse LLM response as JSON")
            return []

        if not isinstance(data, list):
            logger.warning("LLM response is not a JSON array")
            return []

        hypotheses = []
        for item in data:
            try:
                hypothesis = Hypothesis.model_validate(item)
                hypotheses.append(hypothesis)
            except Exception as e:
                logger.warning("Failed to validate hypothesis: %s", e)
                continue

        return hypotheses

    def _generate_rule_based(self, context: HuntingContext) -> list[Hypothesis]:
        """Generate hypotheses using rule-based logic (fallback).

        Uses simple heuristics based on the context to produce hypotheses
        when no LLM is available.
        """
        hypotheses = []

        # Hypothesis from MITRE coverage gaps
        if context.mitre_coverage_gaps:
            gap_techniques = context.mitre_coverage_gaps[:5]
            technique_map = _get_technique_info()
            for tech_id in gap_techniques:
                info = technique_map.get(tech_id)
                if info:
                    stmt = (
                        "Attackers may be exploiting our"
                        f" detection gap for {info['name']}"
                        f" ({tech_id})"
                    )
                    rationale = (
                        "No current detection coverage for"
                        f" {info['name']}. This technique is"
                        " commonly used in"
                        f" {info.get('tactic', 'attacks')}."
                    )
                    hypotheses.append(
                        Hypothesis(
                            statement=stmt,
                            priority="high",
                            expected_indicators=info.get("indicators", []),
                            suggested_queries=info.get("queries", []),
                            mitre_techniques=[tech_id],
                            rationale=rationale,
                            data_sources=info.get("data_sources", []),
                        )
                    )

        # Hypothesis from recent incidents
        if context.recent_incidents:
            source_counts: dict[str, int] = {}
            for incident in context.recent_incidents:
                source = incident.get("source", "unknown")
                source_counts[source] = source_counts.get(source, 0) + 1

            if source_counts:
                top_source = max(source_counts, key=source_counts.get)  # type: ignore[arg-type]
                if source_counts[top_source] >= 3:
                    stmt = (
                        f"Recurring alerts from {top_source}"
                        " may indicate persistent threat"
                        " activity"
                    )
                    query = f'index=alerts source="{top_source}"' " | stats count by signature"
                    count = source_counts[top_source]
                    rationale = (
                        f"{count} recent incidents from"
                        f" {top_source} suggest either a"
                        " persistent threat or a detection"
                        " gap."
                    )
                    hypotheses.append(
                        Hypothesis(
                            statement=stmt,
                            priority="medium",
                            expected_indicators=[
                                "Repeated alert patterns",
                                "Common IOCs across incidents",
                            ],
                            suggested_queries=[
                                {"splunk": query},
                            ],
                            mitre_techniques=[],
                            rationale=rationale,
                            data_sources=[
                                "siem_alerts",
                                "edr_detections",
                            ],
                        )
                    )

        # Hypothesis from false positives
        if context.recent_false_positives:
            fp_stmt = (
                "False positives may be masking genuine"
                " malicious activity in noisy detection"
                " rules"
            )
            fp_query = (
                "index=alerts status=false_positive" " | stats count by rule_name" " | sort -count"
            )
            fp_count = len(context.recent_false_positives)
            fp_rationale = (
                f"{fp_count} recent false positives may"
                " be training analysts to ignore"
                " legitimate threats."
            )
            hypotheses.append(
                Hypothesis(
                    statement=fp_stmt,
                    priority="medium",
                    expected_indicators=[
                        "Anomalous behavior in" " false-positive-heavy alert" " categories",
                        "Genuine IOCs mixed with" " benign activity",
                    ],
                    suggested_queries=[
                        {"splunk": fp_query},
                    ],
                    mitre_techniques=[],
                    rationale=fp_rationale,
                    data_sources=[
                        "siem_alerts",
                        "analyst_feedback",
                    ],
                )
            )

        # Hypothesis from threat intel
        if context.threat_intel_summary:
            ti_stmt = (
                "Current threat landscape may include"
                " emerging TTPs not covered by"
                " existing rules"
            )
            ti_query = (
                "index=proxy dest_ip IN" " (threat_intel_feed)" " | stats count by src_ip, dest_ip"
            )
            ti_rationale = (
                "Active threat intelligence suggests"
                " new techniques that may bypass"
                " current detections."
            )
            hypotheses.append(
                Hypothesis(
                    statement=ti_stmt,
                    priority="high",
                    expected_indicators=[
                        "New malware families",
                        "Novel C2 infrastructure",
                    ],
                    suggested_queries=[
                        {"splunk": ti_query},
                    ],
                    mitre_techniques=[],
                    rationale=ti_rationale,
                    data_sources=[
                        "threat_intel_feeds",
                        "proxy_logs",
                        "dns_logs",
                    ],
                )
            )

        # Default hypothesis if nothing else generated
        if not hypotheses:
            default_stmt = (
                "Review baseline network behavior for" " anomalies that may indicate compromise"
            )
            default_query = (
                "index=network"
                " | stats sum(bytes_out) by src_ip"
                " | sort -sum(bytes_out) | head 20"
            )
            hypotheses.append(
                Hypothesis(
                    statement=default_stmt,
                    priority="low",
                    expected_indicators=[
                        "Unusual outbound connections",
                        "New processes",
                        "Anomalous data volumes",
                    ],
                    suggested_queries=[
                        {"splunk": default_query},
                    ],
                    mitre_techniques=["T1071"],
                    rationale=("Periodic baseline review helps" " detect slow-and-low attacks."),
                    data_sources=[
                        "network_traffic",
                        "firewall_logs",
                    ],
                )
            )

        # Sort by priority and limit to 5
        priority_order = {"high": 0, "medium": 1, "low": 2}
        hypotheses.sort(key=lambda h: priority_order.get(h.priority, 3))
        return hypotheses[:5]


def _get_technique_info() -> dict[str, dict[str, Any]]:
    """Returns a mapping of common MITRE technique IDs to hunting info."""
    return {
        "T1558.003": {
            "name": "Kerberoasting",
            "tactic": "Credential Access",
            "indicators": ["Excessive TGS requests", "RC4 encryption in tickets"],
            "queries": [
                {"splunk": "index=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17"},
                {
                    "elasticsearch": (
                        'event.code: "4769" AND'
                        " winlog.event_data"
                        '.TicketEncryptionType: "0x17"'
                    ),
                },
            ],
            "data_sources": ["windows_security_events"],
        },
        "T1003.001": {
            "name": "LSASS Memory Credential Dumping",
            "tactic": "Credential Access",
            "indicators": ["LSASS memory access by non-system processes"],
            "queries": [
                {"splunk": 'index=sysmon EventCode=10 TargetImage="*lsass.exe"'},
            ],
            "data_sources": ["sysmon", "edr_process_events"],
        },
        "T1570": {
            "name": "Lateral Tool Transfer",
            "tactic": "Lateral Movement",
            "indicators": [
                "SMB file transfers between workstations",
                "PsExec service creation",
            ],
            "queries": [
                {"splunk": 'index=wineventlog EventCode=7045 Service_Name="PSEXESVC"'},
            ],
            "data_sources": ["windows_system_events", "smb_logs"],
        },
        "T1053.005": {
            "name": "Scheduled Task Creation",
            "tactic": "Persistence",
            "indicators": ["New scheduled tasks created by non-admin processes"],
            "queries": [
                {"splunk": "index=wineventlog EventCode=4698"},
            ],
            "data_sources": ["windows_security_events"],
        },
        "T1048": {
            "name": "Exfiltration Over Alternative Protocol",
            "tactic": "Exfiltration",
            "indicators": ["Large DNS queries", "Unusual outbound protocols"],
            "queries": [
                {"splunk": "index=dns | eval subdomain_len=len(query) | where subdomain_len > 50"},
            ],
            "data_sources": ["dns_logs", "network_traffic"],
        },
        "T1071.001": {
            "name": "Application Layer Protocol: Web",
            "tactic": "Command and Control",
            "indicators": [
                "Regular-interval HTTP beaconing",
                "Encoded payloads in URLs",
            ],
            "queries": [
                {"splunk": "index=proxy | bucket _time span=60s | stats count by src_ip, dest_ip"},
            ],
            "data_sources": ["proxy_logs", "network_traffic"],
        },
        "T1059.001": {
            "name": "PowerShell Abuse",
            "tactic": "Execution",
            "indicators": ["Encoded PowerShell commands", "Download cradles"],
            "queries": [
                {
                    "splunk": (
                        "index=sysmon EventCode=1"
                        ' Image="*powershell.exe"'
                        ' CommandLine="*-enc*"'
                    )
                },
            ],
            "data_sources": ["sysmon", "powershell_logs"],
        },
        "T1046": {
            "name": "Network Service Scanning",
            "tactic": "Discovery",
            "indicators": ["Single host connecting to many ports", "ICMP sweeps"],
            "queries": [
                {
                    "splunk": (
                        "index=network"
                        " | stats dc(dest_port) as ports"
                        " by src_ip | where ports > 20"
                    ),
                },
            ],
            "data_sources": ["network_traffic", "firewall_logs"],
        },
        "T1078": {
            "name": "Valid Accounts",
            "tactic": "Initial Access",
            "indicators": ["Logins from unusual locations", "Impossible travel"],
            "queries": [
                {
                    "splunk": (
                        "index=auth action=success"
                        " | iplocation src_ip"
                        " | stats dc(Country) by user"
                    ),
                },
            ],
            "data_sources": ["authentication_logs", "identity_provider"],
        },
        "T1547.001": {
            "name": "Registry Run Keys / Startup Folder",
            "tactic": "Persistence",
            "indicators": ["New Run key entries", "Files in startup folder"],
            "queries": [
                {"splunk": 'index=sysmon EventCode=13 TargetObject="*\\CurrentVersion\\Run*"'},
            ],
            "data_sources": ["sysmon", "edr_registry_events"],
        },
    }
