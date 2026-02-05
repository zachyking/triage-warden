"""Investigation Report Generator.

This module provides the main report generation functionality that transforms
incident data and AI triage analysis into structured, export-ready reports.

Stage 2.1.3 Implementation.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from tw_ai.agents.models import (
    EvidenceItem,
    Indicator,
    InvestigationStep,
    MITRETechnique,
    RecommendedAction,
    TriageAnalysis,
)
from tw_ai.reports.models import (
    AlertSummary,
    AuditLogEntry,
    EvidenceSummary,
    FormattedAction,
    FormattedEvidence,
    FormattedIndicator,
    FormattedMitreTechnique,
    InvestigationReport,
    ReportMetadata,
    TimelineEntry,
    VerdictSummary,
)


class InvestigationReportGenerator:
    """Generates structured investigation reports from incident data.

    This class transforms raw incident data and AI triage analysis into
    comprehensive, audit-ready investigation reports that can be exported
    to various formats (JSON, HTML, PDF).

    Example:
        >>> generator = InvestigationReportGenerator()
        >>> report = generator.generate(incident_data, analysis)
        >>> json_output = report.to_json()
    """

    # Priority order mapping for sorting actions
    PRIORITY_ORDER = {"immediate": 1, "high": 2, "medium": 3, "low": 4}

    # Verdict display names
    VERDICT_DISPLAY = {
        "true_positive": "True Positive",
        "false_positive": "False Positive",
        "suspicious": "Suspicious",
        "inconclusive": "Inconclusive",
    }

    # Severity display names
    SEVERITY_DISPLAY = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "informational": "Informational",
    }

    # MITRE ATT&CK base URL for technique links
    MITRE_BASE_URL = "https://attack.mitre.org/techniques/"

    def generate(
        self,
        incident_data: dict[str, Any],
        analysis: TriageAnalysis | dict[str, Any],
        *,
        generated_by: str = "Triage Warden AI",
    ) -> InvestigationReport:
        """Generate a complete investigation report.

        Args:
            incident_data: Raw incident data dictionary containing:
                - id: Incident UUID
                - tenant_id: Optional tenant UUID
                - source: Alert source information
                - severity: Incident severity
                - alert_data: Raw alert data
                - enrichments: List of enrichment data
                - audit_log: List of audit entries
                - created_at: Incident creation timestamp
            analysis: TriageAnalysis model or dictionary containing AI analysis.
            generated_by: Name of the system/analyst generating the report.

        Returns:
            InvestigationReport: Complete report ready for export.
        """
        # Convert analysis to model if needed
        if isinstance(analysis, dict):
            analysis = TriageAnalysis.model_validate(analysis)

        # Extract incident ID
        incident_id = str(incident_data.get("id", "unknown"))
        tenant_id = incident_data.get("tenant_id")

        # Build report components
        metadata = self._build_metadata(incident_id, generated_by, tenant_id)
        executive_summary = self._generate_executive_summary(analysis, incident_data)
        verdict = self._build_verdict_summary(analysis)
        alert = self._build_alert_summary(incident_data)
        timeline = self._build_timeline(analysis.investigation_steps)
        evidence, evidence_summary = self._format_evidence(analysis.evidence)
        mitre_techniques = self._format_mitre_techniques(analysis.mitre_techniques)
        indicators = self._format_indicators(analysis.indicators)
        recommended_actions = self._format_recommendations(analysis.recommended_actions)
        audit_log = self._format_audit_log(incident_data.get("audit_log", []))

        return InvestigationReport(
            metadata=metadata,
            executive_summary=executive_summary,
            verdict=verdict,
            alert=alert,
            timeline=timeline,
            evidence=evidence,
            evidence_summary=evidence_summary,
            mitre_techniques=mitre_techniques,
            indicators=indicators,
            recommended_actions=recommended_actions,
            reasoning=analysis.reasoning or "",
            raw_alert_data=incident_data.get("alert_data", {}),
            enrichments=incident_data.get("enrichments", []),
            audit_log=audit_log,
        )

    def _build_metadata(
        self,
        incident_id: str,
        generated_by: str,
        tenant_id: str | None,
    ) -> ReportMetadata:
        """Build report metadata."""
        return ReportMetadata(
            incident_id=incident_id,
            generated_at=datetime.now(timezone.utc),
            generated_by=generated_by,
            tenant_id=str(tenant_id) if tenant_id else None,
        )

    def _generate_executive_summary(
        self,
        analysis: TriageAnalysis,
        incident_data: dict[str, Any],
    ) -> str:
        """Generate a 2-3 sentence executive summary.

        The summary includes:
        - Brief description of the alert/incident
        - The verdict with confidence level
        - Key findings or recommended actions
        """
        # Get alert context
        alert_source = self._get_alert_source_display(incident_data.get("source", {}))
        alert_type = incident_data.get("alert_data", {}).get("alert_type", "security incident")

        # Verdict description
        verdict_display = self.VERDICT_DISPLAY.get(analysis.verdict, analysis.verdict)
        confidence_desc = self._confidence_description(analysis.confidence)

        # Build summary
        parts = []

        # First sentence: What happened
        parts.append(
            f"A {analysis.severity} severity {alert_type} alert from {alert_source} "
            f"was analyzed and classified as {verdict_display}."
        )

        # Second sentence: Confidence and key finding
        if analysis.evidence:
            high_conf_evidence = [e for e in analysis.evidence if e.confidence >= 80]
            if high_conf_evidence:
                key_finding = high_conf_evidence[0].finding
                parts.append(
                    f"This assessment is made with {confidence_desc} confidence, "
                    f"supported by key evidence: {key_finding}"
                )
            else:
                parts.append(
                    f"This assessment is made with {confidence_desc} confidence "
                    f"based on {len(analysis.evidence)} pieces of evidence."
                )
        else:
            parts.append(f"This assessment is made with {confidence_desc} confidence.")

        # Third sentence: Primary recommendation (if any)
        if analysis.recommended_actions:
            # Sort by priority and get the highest priority action
            sorted_actions = sorted(
                analysis.recommended_actions,
                key=lambda a: self.PRIORITY_ORDER.get(a.priority, 5),
            )
            primary_action = sorted_actions[0]
            parts.append(f"Primary recommended action: {primary_action.action}")

        return " ".join(parts)

    def _build_verdict_summary(self, analysis: TriageAnalysis) -> VerdictSummary:
        """Build the verdict summary section."""
        return VerdictSummary(
            verdict=analysis.verdict,
            verdict_display=self.VERDICT_DISPLAY.get(analysis.verdict, analysis.verdict),
            confidence=analysis.confidence,
            calibrated_confidence=None,  # Will be populated if calibration is available
            severity=analysis.severity,
            severity_display=self.SEVERITY_DISPLAY.get(analysis.severity, analysis.severity),
            risk_score=None,  # Populated from analysis if available
        )

    def _build_alert_summary(self, incident_data: dict[str, Any]) -> AlertSummary:
        """Build the alert summary section."""
        alert_data = incident_data.get("alert_data", {})
        source = incident_data.get("source", {})

        # Handle created_at - it might be a string or datetime
        created_at = incident_data.get("created_at")
        if isinstance(created_at, str):
            try:
                created_at = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
            except ValueError:
                created_at = None

        return AlertSummary(
            alert_id=alert_data.get("id", str(incident_data.get("id", "unknown"))),
            source=self._get_alert_source_display(source),
            alert_type=alert_data.get("alert_type"),
            title=alert_data.get("title"),
            created_at=created_at,
        )

    def _build_timeline(
        self,
        investigation_steps: list[InvestigationStep],
    ) -> list[TimelineEntry]:
        """Build the investigation timeline from investigation steps."""
        timeline = []

        for step in sorted(investigation_steps, key=lambda s: s.order):
            timeline.append(
                TimelineEntry(
                    order=step.order,
                    timestamp=None,  # InvestigationStep doesn't have timestamp in Python model
                    action=step.action,
                    result=step.result,
                    tool=step.tool,
                    status=step.status,
                    duration_ms=None,
                )
            )

        return timeline

    def _format_evidence(
        self,
        evidence_items: list[EvidenceItem],
    ) -> tuple[list[FormattedEvidence], EvidenceSummary]:
        """Format evidence items for the report.

        Returns:
            Tuple of (formatted_evidence_list, evidence_summary)
        """
        formatted = []

        for i, item in enumerate(evidence_items, start=1):
            formatted.append(
                FormattedEvidence(
                    order=i,
                    source_type=item.source_type,
                    source_name=item.source_name,
                    data_type=item.data_type,
                    finding=item.finding,
                    relevance=item.relevance,
                    confidence=item.confidence,
                    link=item.link,
                    raw_value=item.value,
                )
            )

        # Build summary statistics
        summary = self._build_evidence_summary(evidence_items)

        return formatted, summary

    def _build_evidence_summary(
        self,
        evidence_items: list[EvidenceItem],
    ) -> EvidenceSummary:
        """Build evidence summary statistics."""
        if not evidence_items:
            return EvidenceSummary(
                total_evidence=0,
                average_confidence=0.0,
                high_confidence_count=0,
                medium_confidence_count=0,
                low_confidence_count=0,
                sources_used=[],
                data_types_found=[],
            )

        total = len(evidence_items)
        avg_confidence = sum(e.confidence for e in evidence_items) / total
        high_count = sum(1 for e in evidence_items if e.confidence >= 80)
        medium_count = sum(1 for e in evidence_items if 50 <= e.confidence < 80)
        low_count = sum(1 for e in evidence_items if e.confidence < 50)
        sources = list({e.source_name for e in evidence_items})
        data_types = list({e.data_type for e in evidence_items})

        return EvidenceSummary(
            total_evidence=total,
            average_confidence=round(avg_confidence, 1),
            high_confidence_count=high_count,
            medium_confidence_count=medium_count,
            low_confidence_count=low_count,
            sources_used=sources,
            data_types_found=list(data_types),
        )

    def _format_mitre_techniques(
        self,
        techniques: list[MITRETechnique],
    ) -> list[FormattedMitreTechnique]:
        """Format MITRE ATT&CK techniques for the report."""
        formatted = []

        for technique in techniques:
            # Build MITRE ATT&CK URL
            # T1566.001 -> T1566/001
            technique_path = technique.id.replace(".", "/")
            url = f"{self.MITRE_BASE_URL}{technique_path}/"

            formatted.append(
                FormattedMitreTechnique(
                    technique_id=technique.id,
                    name=technique.name,
                    tactic=technique.tactic,
                    relevance=technique.relevance,
                    url=url,
                )
            )

        return formatted

    def _format_indicators(
        self,
        indicators: list[Indicator],
    ) -> list[FormattedIndicator]:
        """Format indicators of compromise for the report."""
        return [
            FormattedIndicator(
                indicator_type=ind.type,
                value=ind.value,
                verdict=ind.verdict,
                context=ind.context,
            )
            for ind in indicators
        ]

    def _format_recommendations(
        self,
        actions: list[RecommendedAction],
    ) -> list[FormattedAction]:
        """Format recommended actions, sorted by priority."""
        # Sort by priority
        sorted_actions = sorted(
            actions,
            key=lambda a: self.PRIORITY_ORDER.get(a.priority, 5),
        )

        return [
            FormattedAction(
                order=i + 1,
                action=action.action,
                priority=action.priority,
                reason=action.reason,
                requires_approval=action.requires_approval,
            )
            for i, action in enumerate(sorted_actions)
        ]

    def _format_audit_log(
        self,
        audit_entries: list[dict[str, Any]],
    ) -> list[AuditLogEntry]:
        """Format audit log entries for the report appendix."""
        formatted = []

        for entry in audit_entries:
            timestamp = entry.get("timestamp")
            if isinstance(timestamp, str):
                try:
                    timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                except ValueError:
                    timestamp = datetime.now(timezone.utc)
            elif not isinstance(timestamp, datetime):
                timestamp = datetime.now(timezone.utc)

            # Format action details
            action = entry.get("action", "unknown")
            if isinstance(action, dict):
                action = action.get("type", str(action))

            details = entry.get("details")
            if isinstance(details, dict):
                details = str(details)

            formatted.append(
                AuditLogEntry(
                    timestamp=timestamp,
                    action=str(action),
                    actor=entry.get("actor", "system"),
                    details=details,
                )
            )

        # Sort by timestamp
        return sorted(formatted, key=lambda e: e.timestamp)

    def _get_alert_source_display(self, source: dict[str, Any] | str) -> str:
        """Get a display-friendly name for the alert source."""
        if isinstance(source, str):
            return source

        if not source:
            return "Unknown Source"

        # Handle different source formats
        if "type" in source:
            source_type: str = str(source["type"])
            if source_type == "siem":
                return f"SIEM ({source.get('platform', 'unknown')})"
            elif source_type == "edr":
                return f"EDR ({source.get('platform', 'unknown')})"
            elif source_type == "email_security":
                return f"Email Security ({source.get('gateway', 'unknown')})"
            elif source_type == "user_reported":
                return "User Reported"
            else:
                return source_type.replace("_", " ").title()

        # Handle variant format (e.g., {"Siem": "Splunk"})
        for key, value in source.items():
            if isinstance(value, str):
                return f"{key} ({value})"
            result: str = key
            return result

        return "Unknown Source"

    def _confidence_description(self, confidence: int) -> str:
        """Convert numeric confidence to descriptive text."""
        if confidence >= 90:
            return "very high"
        elif confidence >= 75:
            return "high"
        elif confidence >= 50:
            return "moderate"
        elif confidence >= 25:
            return "low"
        else:
            return "very low"
