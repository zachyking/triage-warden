"""Hallucination detection for AI-generated triage analyses.

This module implements detection of hallucinated content in LLM-generated
security analyses, including:
- IP addresses cited but not present in incident data
- MITRE ATT&CK techniques that don't match observed behavior
- Evidence sources that weren't actually consulted
- Claims not supported by provided RAG context

The HallucinationDetector provides a defense against AI-generated
fabrications that could lead to incorrect incident response decisions.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

import structlog
from pydantic import BaseModel, ConfigDict, Field

from tw_ai.agents.models import (
    TriageAnalysis,
)
from tw_ai.analysis.security import extract_indicators

logger = structlog.get_logger()


# =============================================================================
# Types and Enums
# =============================================================================


class WarningType(str, Enum):
    """Types of hallucination warnings."""

    HALLUCINATED_IP = "hallucinated_ip"
    HALLUCINATED_DOMAIN = "hallucinated_domain"
    HALLUCINATED_HASH = "hallucinated_hash"
    QUESTIONABLE_MITRE = "questionable_mitre"
    UNSUPPORTED_EVIDENCE_SOURCE = "unsupported_evidence_source"
    RAG_CITATION_MISMATCH = "rag_citation_mismatch"
    FABRICATED_CLAIM = "fabricated_claim"
    CONFIDENCE_MISMATCH = "confidence_mismatch"
    TEMPORAL_INCONSISTENCY = "temporal_inconsistency"


class HallucinationSeverity(str, Enum):
    """Severity levels for hallucination warnings."""

    CRITICAL = "critical"  # High-impact hallucination that could cause harm
    HIGH = "high"  # Significant fabrication that affects analysis quality
    MEDIUM = "medium"  # Notable hallucination that warrants review
    LOW = "low"  # Minor fabrication with limited impact


# =============================================================================
# Models
# =============================================================================


class HallucinationWarning(BaseModel):
    """A warning indicating potential hallucination in the analysis.

    Warnings are generated when the AI analysis contains content
    that cannot be verified against the incident data or provided context.
    """

    model_config = ConfigDict(str_strip_whitespace=True)

    type: WarningType = Field(description="Type of hallucination detected")
    severity: HallucinationSeverity = Field(description="Severity level of this warning")
    detail: str = Field(description="Human-readable description of the issue")
    evidence: dict[str, Any] = Field(
        default_factory=dict,
        description="Supporting evidence for this warning",
    )
    location: str | None = Field(
        default=None,
        description="Where in the analysis the hallucination was found",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When this warning was generated",
    )

    def to_audit_dict(self) -> dict[str, Any]:
        """Convert to dictionary for audit logging."""
        return {
            "type": self.type.value,
            "severity": self.severity.value,
            "detail": self.detail,
            "evidence": self.evidence,
            "location": self.location,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class HallucinationConfig:
    """Configuration for hallucination detection.

    Customize thresholds and behavior of the HallucinationDetector.
    """

    # Enable/disable specific checks
    check_ips: bool = True
    check_domains: bool = True
    check_hashes: bool = True
    check_mitre: bool = True
    check_evidence_sources: bool = True
    check_rag_citations: bool = True
    check_confidence: bool = True

    # Thresholds
    max_warnings_before_flag: int = 3
    mitre_confidence_threshold: float = 0.3  # Min confidence for technique match

    # Known valid sources that don't require verification
    known_evidence_sources: set[str] = field(
        default_factory=lambda: {
            "VirusTotal",
            "Splunk",
            "CrowdStrike",
            "Microsoft Defender",
            "Sentinel",
            "Chronicle",
            "Carbon Black",
            "Tanium",
            "Cortex XDR",
            "SentinelOne",
            "Elastic Security",
            "IBM QRadar",
            "AbuseIPDB",
            "Shodan",
            "GreyNoise",
            "AlienVault OTX",
            "Recorded Future",
            "ThreatConnect",
            "MISP",
        }
    )

    # Valid MITRE tactics for technique validation
    valid_mitre_tactics: set[str] = field(
        default_factory=lambda: {
            "Reconnaissance",
            "Resource Development",
            "Initial Access",
            "Execution",
            "Persistence",
            "Privilege Escalation",
            "Defense Evasion",
            "Credential Access",
            "Discovery",
            "Lateral Movement",
            "Collection",
            "Command and Control",
            "Exfiltration",
            "Impact",
        }
    )


@dataclass
class HallucinationResult:
    """Result of hallucination detection analysis.

    Contains all warnings found and metadata about the check.
    """

    warnings: list[HallucinationWarning] = field(default_factory=list)
    total_checks_performed: int = 0
    passed_checks: int = 0
    failed_checks: int = 0
    should_flag_for_review: bool = False
    analysis_timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def has_warnings(self) -> bool:
        """Check if any warnings were generated."""
        return len(self.warnings) > 0

    @property
    def critical_count(self) -> int:
        """Count of critical severity warnings."""
        return sum(1 for w in self.warnings if w.severity == HallucinationSeverity.CRITICAL)

    @property
    def high_count(self) -> int:
        """Count of high severity warnings."""
        return sum(1 for w in self.warnings if w.severity == HallucinationSeverity.HIGH)

    def get_summary(self) -> dict[str, Any]:
        """Get a summary of the hallucination check results."""
        return {
            "total_warnings": len(self.warnings),
            "critical": self.critical_count,
            "high": self.high_count,
            "medium": sum(1 for w in self.warnings if w.severity == HallucinationSeverity.MEDIUM),
            "low": sum(1 for w in self.warnings if w.severity == HallucinationSeverity.LOW),
            "checks_performed": self.total_checks_performed,
            "checks_passed": self.passed_checks,
            "checks_failed": self.failed_checks,
            "flagged_for_review": self.should_flag_for_review,
            "timestamp": self.analysis_timestamp.isoformat(),
        }

    def to_audit_dict(self) -> dict[str, Any]:
        """Convert to dictionary for audit logging."""
        return {
            "summary": self.get_summary(),
            "warnings": [w.to_audit_dict() for w in self.warnings],
        }


# =============================================================================
# Hallucination Detector
# =============================================================================


class HallucinationDetector:
    """Detects hallucinations in AI-generated triage analyses.

    The detector cross-references claims made in the analysis against
    the actual incident data and provided context to identify fabrications.

    Example usage:
        ```python
        detector = HallucinationDetector()
        result = detector.check(analysis, incident_data)

        if result.should_flag_for_review:
            # Route to human analyst
            queue_for_review(analysis, result.warnings)
        ```
    """

    def __init__(self, config: HallucinationConfig | None = None) -> None:
        """Initialize the detector with optional configuration.

        Args:
            config: Detection configuration. Uses defaults if not provided.
        """
        self._config = config or HallucinationConfig()

    @property
    def config(self) -> HallucinationConfig:
        """Get the current configuration."""
        return self._config

    def check(
        self,
        analysis: TriageAnalysis,
        incident_data: dict[str, Any] | str,
        rag_context: dict[str, Any] | None = None,
    ) -> HallucinationResult:
        """Check an analysis for hallucinations.

        This is the main entry point for hallucination detection.
        It runs all enabled checks and aggregates the results.

        Args:
            analysis: The triage analysis to check.
            incident_data: The raw incident/alert data (dict or string).
            rag_context: Optional RAG context that was provided to the LLM.

        Returns:
            HallucinationResult with all warnings found.
        """
        result = HallucinationResult()

        # Convert incident_data to string for indicator extraction
        incident_text = str(incident_data) if isinstance(incident_data, dict) else incident_data

        # Extract actual indicators from incident data
        actual_indicators = extract_indicators(incident_text)
        actual_ips = {i.value for i in actual_indicators if i.type == "ip"}
        actual_domains = {i.value for i in actual_indicators if i.type == "domain"}
        actual_hashes = {i.value for i in actual_indicators if i.type == "hash"}

        # Run checks
        if self._config.check_ips:
            self._check_ip_hallucinations(analysis, incident_text, actual_ips, result)

        if self._config.check_domains:
            self._check_domain_hallucinations(analysis, incident_text, actual_domains, result)

        if self._config.check_hashes:
            self._check_hash_hallucinations(analysis, incident_text, actual_hashes, result)

        if self._config.check_mitre:
            self._check_mitre_plausibility(analysis, incident_data, result)

        if self._config.check_evidence_sources:
            self._check_evidence_sources(analysis, result)

        if self._config.check_rag_citations and rag_context:
            self._check_rag_citations(analysis, rag_context, result)

        if self._config.check_confidence:
            self._check_confidence_consistency(analysis, result)

        # Determine if should flag for review
        result.should_flag_for_review = (
            len(result.warnings) >= self._config.max_warnings_before_flag
            or result.critical_count > 0
            or result.high_count >= 2
        )

        # Log the result
        logger.info(
            "hallucination_check_completed",
            total_warnings=len(result.warnings),
            flagged_for_review=result.should_flag_for_review,
            checks_performed=result.total_checks_performed,
        )

        return result

    def _check_ip_hallucinations(
        self,
        analysis: TriageAnalysis,
        incident_text: str,
        actual_ips: set[str],
        result: HallucinationResult,
    ) -> None:
        """Check if cited IPs exist in incident data.

        Args:
            analysis: The triage analysis.
            incident_text: Raw incident data as text.
            actual_ips: Set of IPs extracted from incident data.
            result: Result object to add warnings to.
        """
        result.total_checks_performed += 1

        # Extract IPs mentioned in the analysis reasoning and summary
        analysis_text = f"{analysis.reasoning} {analysis.summary}"
        cited_indicators = extract_indicators(analysis_text)
        cited_ips = {i.value for i in cited_indicators if i.type == "ip"}

        # Also check IPs in the indicators list
        for indicator in analysis.indicators:
            if indicator.type == "ip":
                cited_ips.add(indicator.value)

        # Find IPs that were cited but not in incident data
        hallucinated_ips = cited_ips - actual_ips

        # Filter out common non-specific IPs that might be examples
        non_specific_ips = {"127.0.0.1", "0.0.0.0", "255.255.255.255"}
        hallucinated_ips -= non_specific_ips

        if hallucinated_ips:
            result.failed_checks += 1
            for ip in hallucinated_ips:
                result.warnings.append(
                    HallucinationWarning(
                        type=WarningType.HALLUCINATED_IP,
                        severity=HallucinationSeverity.HIGH,
                        detail=f"IP address '{ip}' cited but not found in incident data",
                        evidence={
                            "cited_ip": ip,
                            "actual_ips": list(actual_ips)[:10],  # Limit for readability
                            "source": "reasoning_or_indicators",
                        },
                        location="reasoning/indicators",
                    )
                )
        else:
            result.passed_checks += 1

    def _check_domain_hallucinations(
        self,
        analysis: TriageAnalysis,
        incident_text: str,
        actual_domains: set[str],
        result: HallucinationResult,
    ) -> None:
        """Check if cited domains exist in incident data.

        Args:
            analysis: The triage analysis.
            incident_text: Raw incident data as text.
            actual_domains: Set of domains extracted from incident data.
            result: Result object to add warnings to.
        """
        result.total_checks_performed += 1

        # Extract domains mentioned in the analysis
        analysis_text = f"{analysis.reasoning} {analysis.summary}"
        cited_indicators = extract_indicators(analysis_text)
        cited_domains = {i.value for i in cited_indicators if i.type == "domain"}

        # Also check domains in the indicators list
        for indicator in analysis.indicators:
            if indicator.type == "domain":
                cited_domains.add(indicator.value)

        # Build a set of valid domains from incident data
        # Include domains extracted directly AND domains from emails
        all_actual_domains = set(actual_domains)
        actual_emails = extract_indicators(incident_text)
        for ind in actual_emails:
            if ind.type == "email":
                # Extract domain from email (everything after @)
                if "@" in ind.value:
                    email_domain = ind.value.split("@")[1]
                    all_actual_domains.add(email_domain)

        # Also do a simple substring check against the raw incident text
        # to catch domains that appear in the text but weren't extracted
        incident_text_lower = incident_text.lower()

        # Find domains that were cited but not in incident data
        hallucinated_domains = set()
        for domain in cited_domains:
            # Check if domain is in extracted domains or appears in raw text
            domain_lower = domain.lower()
            if (
                domain_lower not in {d.lower() for d in all_actual_domains}
                and domain_lower not in incident_text_lower
            ):
                hallucinated_domains.add(domain)

        # Filter out common example domains
        example_domains = {
            "example.com",
            "example.org",
            "example.net",
            "test.com",
            "localhost",
        }
        hallucinated_domains -= example_domains

        if hallucinated_domains:
            result.failed_checks += 1
            for domain in hallucinated_domains:
                result.warnings.append(
                    HallucinationWarning(
                        type=WarningType.HALLUCINATED_DOMAIN,
                        severity=HallucinationSeverity.HIGH,
                        detail=f"Domain '{domain}' cited but not found in incident data",
                        evidence={
                            "cited_domain": domain,
                            "actual_domains": list(all_actual_domains)[:10],
                            "source": "reasoning_or_indicators",
                        },
                        location="reasoning/indicators",
                    )
                )
        else:
            result.passed_checks += 1

    def _check_hash_hallucinations(
        self,
        analysis: TriageAnalysis,
        incident_text: str,
        actual_hashes: set[str],
        result: HallucinationResult,
    ) -> None:
        """Check if cited hashes exist in incident data.

        Args:
            analysis: The triage analysis.
            incident_text: Raw incident data as text.
            actual_hashes: Set of hashes extracted from incident data.
            result: Result object to add warnings to.
        """
        result.total_checks_performed += 1

        # Extract hashes mentioned in the analysis
        analysis_text = f"{analysis.reasoning} {analysis.summary}"
        cited_indicators = extract_indicators(analysis_text)
        cited_hashes = {i.value for i in cited_indicators if i.type == "hash"}

        # Also check hashes in the indicators list
        for indicator in analysis.indicators:
            if indicator.type == "hash":
                cited_hashes.add(indicator.value.lower())

        # Normalize actual hashes
        actual_hashes_normalized = {h.lower() for h in actual_hashes}

        # Find hashes that were cited but not in incident data
        hallucinated_hashes = cited_hashes - actual_hashes_normalized

        if hallucinated_hashes:
            result.failed_checks += 1
            for hash_val in hallucinated_hashes:
                # Determine hash type by length
                hash_type = "unknown"
                if len(hash_val) == 32:
                    hash_type = "MD5"
                elif len(hash_val) == 40:
                    hash_type = "SHA1"
                elif len(hash_val) == 64:
                    hash_type = "SHA256"

                result.warnings.append(
                    HallucinationWarning(
                        type=WarningType.HALLUCINATED_HASH,
                        severity=HallucinationSeverity.HIGH,
                        detail=f"{hash_type} hash '{hash_val[:16]}...' cited but not in incident",
                        evidence={
                            "cited_hash": hash_val,
                            "hash_type": hash_type,
                            "actual_hash_count": len(actual_hashes),
                            "source": "reasoning_or_indicators",
                        },
                        location="reasoning/indicators",
                    )
                )
        else:
            result.passed_checks += 1

    def _check_mitre_plausibility(
        self,
        analysis: TriageAnalysis,
        incident_data: dict[str, Any] | str,
        result: HallucinationResult,
    ) -> None:
        """Check if MITRE techniques are plausible for observed behavior.

        This performs basic plausibility checks:
        - Validates technique ID format
        - Checks tactic validity
        - Looks for behavioral evidence supporting the technique

        Args:
            analysis: The triage analysis.
            incident_data: Raw incident data.
            result: Result object to add warnings to.
        """
        if not analysis.mitre_techniques:
            return

        result.total_checks_performed += 1

        incident_text = (
            str(incident_data) if isinstance(incident_data, dict) else incident_data
        ).lower()

        has_issues = False

        for technique in analysis.mitre_techniques:
            issues: list[str] = []

            # Check tactic validity
            if technique.tactic not in self._config.valid_mitre_tactics:
                issues.append(f"Invalid tactic '{technique.tactic}'")

            # Check for behavioral indicators that support the technique
            technique_indicators = self._get_technique_indicators(technique.id)
            if technique_indicators:
                found_indicators = sum(
                    1 for ind in technique_indicators if ind.lower() in incident_text
                )
                if found_indicators == 0:
                    issues.append(f"No behavioral indicators found for {technique.id}")

            if issues:
                has_issues = True
                result.warnings.append(
                    HallucinationWarning(
                        type=WarningType.QUESTIONABLE_MITRE,
                        severity=HallucinationSeverity.MEDIUM,
                        detail=(
                            f"MITRE technique {technique.id} ({technique.name}) "
                            f"may not match observed behavior: {'; '.join(issues)}"
                        ),
                        evidence={
                            "technique_id": technique.id,
                            "technique_name": technique.name,
                            "tactic": technique.tactic,
                            "issues": issues,
                            "relevance_stated": technique.relevance,
                        },
                        location="mitre_techniques",
                    )
                )

        if has_issues:
            result.failed_checks += 1
        else:
            result.passed_checks += 1

    def _get_technique_indicators(self, technique_id: str) -> list[str]:
        """Get behavioral indicators for a MITRE technique.

        This is a simplified mapping of common techniques to behavioral indicators.
        In a full implementation, this would query a MITRE ATT&CK knowledge base.

        Args:
            technique_id: MITRE technique ID (e.g., T1566).

        Returns:
            List of behavioral indicator keywords.
        """
        # Common technique indicators (simplified)
        technique_indicators: dict[str, list[str]] = {
            "T1566": ["phishing", "email", "attachment", "link", "malicious"],
            "T1566.001": ["attachment", "macro", "document", "office", "pdf"],
            "T1566.002": ["link", "url", "click", "redirect", "credential"],
            "T1059": ["powershell", "cmd", "bash", "script", "command"],
            "T1059.001": ["powershell", "ps1", "invoke", "iex", "bypass"],
            "T1059.003": ["cmd", "batch", "bat", "command prompt"],
            "T1204": ["user execution", "click", "run", "open", "download"],
            "T1547": ["startup", "registry", "autorun", "persistence", "boot"],
            "T1547.001": ["run key", "registry", "hkcu", "hklm", "startup"],
            "T1053": ["scheduled task", "cron", "at job", "task scheduler"],
            "T1078": ["valid account", "credential", "login", "authentication"],
            "T1486": ["ransomware", "encrypt", "ransom", "bitcoin", "decrypt"],
            "T1003": ["credential dump", "lsass", "mimikatz", "hash", "password"],
            "T1003.001": ["lsass", "memory", "dump", "procdump", "mimikatz"],
            "T1021": ["rdp", "ssh", "smb", "remote", "lateral"],
            "T1021.001": ["rdp", "remote desktop", "3389", "mstsc"],
            "T1021.002": ["smb", "445", "admin$", "c$", "share"],
            "T1071": ["c2", "beacon", "callback", "command and control"],
            "T1071.001": ["http", "https", "web", "post", "get"],
            "T1041": ["exfiltration", "upload", "transfer", "data theft"],
            "T1083": ["file discovery", "dir", "ls", "find", "enumerate"],
            "T1082": ["system info", "hostname", "whoami", "systeminfo"],
            "T1018": ["remote discovery", "ping", "netscan", "portscan"],
            "T1562": ["defense evasion", "disable", "antivirus", "firewall"],
            "T1055": ["process injection", "inject", "hollow", "dll"],
            "T1055.001": ["dll injection", "loadlibrary", "inject"],
        }

        # Get base technique indicators if subtechnique
        base_technique = technique_id.split(".")[0]
        indicators = technique_indicators.get(technique_id, [])
        if technique_id != base_technique:
            indicators.extend(technique_indicators.get(base_technique, []))

        return indicators

    def _check_evidence_sources(
        self,
        analysis: TriageAnalysis,
        result: HallucinationResult,
    ) -> None:
        """Check if evidence sources are valid/known.

        Args:
            analysis: The triage analysis.
            result: Result object to add warnings to.
        """
        if not analysis.evidence:
            return

        result.total_checks_performed += 1

        has_issues = False

        for evidence in analysis.evidence:
            # Check if source name is in known sources
            source_name = evidence.source_name.strip()

            # Try to match against known sources (case-insensitive)
            known_match = any(
                known.lower() in source_name.lower() or source_name.lower() in known.lower()
                for known in self._config.known_evidence_sources
            )

            if not known_match:
                # Check if it looks like a plausible source name
                # (contains alphanumeric characters and reasonable length)
                if (
                    len(source_name) < 2
                    or len(source_name) > 100
                    or not re.match(r"^[a-zA-Z0-9\s\-_.]+$", source_name)
                ):
                    has_issues = True
                    result.warnings.append(
                        HallucinationWarning(
                            type=WarningType.UNSUPPORTED_EVIDENCE_SOURCE,
                            severity=HallucinationSeverity.LOW,
                            detail=f"Unknown evidence source '{source_name}' - may be hallucinated",
                            evidence={
                                "source_name": source_name,
                                "source_type": evidence.source_type,
                                "finding": evidence.finding[:100],
                            },
                            location="evidence",
                        )
                    )

        if has_issues:
            result.failed_checks += 1
        else:
            result.passed_checks += 1

    def _check_rag_citations(
        self,
        analysis: TriageAnalysis,
        rag_context: dict[str, Any],
        result: HallucinationResult,
    ) -> None:
        """Check if RAG citations match the provided context.

        Args:
            analysis: The triage analysis.
            rag_context: The RAG context that was provided to the LLM.
            result: Result object to add warnings to.
        """
        if not analysis.rag_citations or not analysis.rag_context_used:
            return

        result.total_checks_performed += 1

        has_issues = False

        # Extract document IDs from RAG context
        context_doc_ids: set[str] = set()
        for key in ["similar_incidents", "playbooks", "mitre_techniques", "threat_intel"]:
            if key in rag_context:
                for doc in rag_context.get(key, []):
                    if isinstance(doc, dict):
                        doc_id = doc.get("id") or doc.get("doc_id") or doc.get("document_id")
                        if doc_id:
                            context_doc_ids.add(str(doc_id))

        # Check each citation
        for citation in analysis.rag_citations:
            if isinstance(citation, dict):
                cited_id = (
                    citation.get("id") or citation.get("doc_id") or citation.get("document_id")
                )
                if cited_id and str(cited_id) not in context_doc_ids:
                    has_issues = True
                    result.warnings.append(
                        HallucinationWarning(
                            type=WarningType.RAG_CITATION_MISMATCH,
                            severity=HallucinationSeverity.MEDIUM,
                            detail=f"Citation references document '{cited_id}' not in RAG context",
                            evidence={
                                "cited_id": cited_id,
                                "citation": citation,
                                "available_doc_ids": list(context_doc_ids)[:10],
                            },
                            location="rag_citations",
                        )
                    )

        if has_issues:
            result.failed_checks += 1
        else:
            result.passed_checks += 1

    def _check_confidence_consistency(
        self,
        analysis: TriageAnalysis,
        result: HallucinationResult,
    ) -> None:
        """Check if confidence scores are consistent with evidence.

        High confidence with little evidence suggests potential hallucination.

        Args:
            analysis: The triage analysis.
            result: Result object to add warnings to.
        """
        result.total_checks_performed += 1

        issues: list[str] = []

        # High confidence with little evidence
        if analysis.confidence >= 90 and len(analysis.evidence) < 2:
            confidence = analysis.confidence
            evidence_count = len(analysis.evidence)
            issues.append(
                f"Very high confidence ({confidence}%) with only {evidence_count} evidence"
            )

        # High severity with low confidence
        if analysis.severity in ("critical", "high") and analysis.confidence < 50:
            issues.append(
                f"High severity ({analysis.severity}) with low confidence ({analysis.confidence}%)"
            )

        # Critical verdict with no investigation steps
        if (
            analysis.verdict == "true_positive"
            and analysis.severity == "critical"
            and len(analysis.investigation_steps) == 0
        ):
            issues.append("Critical true positive verdict with no documented investigation steps")

        # Check evidence confidence vs overall confidence
        if analysis.evidence:
            avg_evidence_confidence = sum(e.confidence for e in analysis.evidence) / len(
                analysis.evidence
            )
            if analysis.confidence > avg_evidence_confidence + 30:
                issues.append(
                    f"Overall confidence ({analysis.confidence}%) significantly exceeds "
                    f"average evidence confidence ({avg_evidence_confidence:.0f}%)"
                )

        if issues:
            result.failed_checks += 1
            result.warnings.append(
                HallucinationWarning(
                    type=WarningType.CONFIDENCE_MISMATCH,
                    severity=HallucinationSeverity.MEDIUM,
                    detail=f"Confidence/evidence inconsistency: {'; '.join(issues)}",
                    evidence={
                        "confidence": analysis.confidence,
                        "severity": analysis.severity,
                        "verdict": analysis.verdict,
                        "evidence_count": len(analysis.evidence),
                        "investigation_steps_count": len(analysis.investigation_steps),
                        "issues": issues,
                    },
                    location="confidence/evidence",
                )
            )
        else:
            result.passed_checks += 1


# =============================================================================
# Module-level functions
# =============================================================================

_default_detector: HallucinationDetector | None = None


def get_default_detector() -> HallucinationDetector:
    """Get or create the default hallucination detector instance."""
    global _default_detector
    if _default_detector is None:
        _default_detector = HallucinationDetector()
    return _default_detector


def check_for_hallucinations(
    analysis: TriageAnalysis,
    incident_data: dict[str, Any] | str,
    rag_context: dict[str, Any] | None = None,
) -> HallucinationResult:
    """Convenience function to check an analysis for hallucinations.

    Args:
        analysis: The triage analysis to check.
        incident_data: The raw incident/alert data.
        rag_context: Optional RAG context provided to the LLM.

    Returns:
        HallucinationResult with all warnings found.
    """
    return get_default_detector().check(analysis, incident_data, rag_context)
