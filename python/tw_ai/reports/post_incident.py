"""Post-Incident Report Generator.

This module provides functionality to generate post-incident reports
that include executive summaries, incident timelines, root cause analysis,
impact assessments, lessons learned, and recommendations.

Stage 4.4.1 Implementation.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

# ============================================================================
# Models
# ============================================================================


class TimelineEntry(BaseModel):
    """A single entry in the incident timeline."""

    model_config = ConfigDict(str_strip_whitespace=True)

    timestamp: datetime | None = Field(
        default=None,
        description="When this event occurred",
    )
    event: str = Field(description="Description of the event")
    source: str | None = Field(
        default=None,
        description="Source of this timeline event",
    )
    actor: str | None = Field(
        default=None,
        description="Who or what performed the action",
    )


class ImpactAssessment(BaseModel):
    """Assessment of the incident's impact."""

    model_config = ConfigDict(str_strip_whitespace=True)

    scope: str = Field(
        default="unknown",
        description="Scope of the impact (e.g., department, organization-wide)",
    )
    affected_assets: list[str] = Field(
        default_factory=list,
        description="List of affected assets",
    )
    affected_users: list[str] = Field(
        default_factory=list,
        description="List of affected users or groups",
    )
    data_impact: str = Field(
        default="none",
        description="Description of data impact (none, confidentiality, integrity, availability)",
    )
    business_impact: str = Field(
        default="minimal",
        description="Description of business impact",
    )
    severity_justification: str = Field(
        default="",
        description="Justification for the severity rating",
    )


class ActionSummary(BaseModel):
    """Summary of a response action taken."""

    model_config = ConfigDict(str_strip_whitespace=True)

    action: str = Field(description="Description of the action")
    performed_by: str | None = Field(
        default=None,
        description="Who performed the action",
    )
    timestamp: datetime | None = Field(
        default=None,
        description="When the action was performed",
    )
    result: str | None = Field(
        default=None,
        description="Outcome of the action",
    )


class Recommendation(BaseModel):
    """A recommendation from the post-incident review."""

    model_config = ConfigDict(str_strip_whitespace=True)

    title: str = Field(description="Short title of the recommendation")
    description: str = Field(description="Detailed description")
    priority: str = Field(
        default="medium",
        description="Priority level (critical, high, medium, low)",
    )
    category: str = Field(
        default="general",
        description="Category (detection, response, prevention, process, training, tooling)",
    )
    owner: str | None = Field(
        default=None,
        description="Suggested owner for this recommendation",
    )


class PostIncidentReport(BaseModel):
    """Complete post-incident report."""

    model_config = ConfigDict(str_strip_whitespace=True)

    # Metadata
    incident_id: str = Field(description="Incident identifier")
    report_generated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When this report was generated",
    )
    report_version: str = Field(
        default="1.0",
        description="Report format version",
    )

    # Content sections
    executive_summary: str = Field(
        default="",
        description="High-level summary for leadership",
    )
    incident_timeline: list[TimelineEntry] = Field(
        default_factory=list,
        description="Chronological timeline of events",
    )
    root_cause_analysis: str = Field(
        default="",
        description="Root cause analysis",
    )
    impact_assessment: ImpactAssessment = Field(
        default_factory=ImpactAssessment,
        description="Impact assessment details",
    )
    response_actions: list[ActionSummary] = Field(
        default_factory=list,
        description="Actions taken during response",
    )
    lessons_learned: list[str] = Field(
        default_factory=list,
        description="Lessons learned from this incident",
    )
    recommendations: list[Recommendation] = Field(
        default_factory=list,
        description="Recommendations for improvement",
    )
    mitre_techniques: list[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK technique IDs observed",
    )
    appendix: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional data and references",
    )


# ============================================================================
# Generator
# ============================================================================


class PostIncidentReportGenerator:
    """Generates post-incident reports from incident data and analysis.

    This class transforms incident data, AI triage analysis, and enrichment
    data into a comprehensive post-incident report suitable for stakeholder
    review and organizational learning.

    Example:
        >>> generator = PostIncidentReportGenerator()
        >>> report = generator.generate(incident_data, analysis, enrichments)
        >>> markdown = generator.export_markdown(report)
    """

    # Priority mapping for sorting recommendations
    PRIORITY_ORDER = {"critical": 1, "high": 2, "medium": 3, "low": 4}

    # Severity descriptions for executive summaries
    SEVERITY_LABELS = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Informational",
    }

    def generate(
        self,
        incident_data: dict[str, Any],
        analysis: dict[str, Any],
        enrichments: dict[str, Any] | None = None,
    ) -> PostIncidentReport:
        """Generate a complete post-incident report.

        Args:
            incident_data: Raw incident data dictionary.
            analysis: AI triage analysis results.
            enrichments: Additional enrichment data (optional).

        Returns:
            PostIncidentReport ready for export.
        """
        enrichments = enrichments or {}

        incident_id = str(incident_data.get("id", "unknown"))
        timeline = self._build_timeline(incident_data)
        impact = self._assess_impact(incident_data, analysis)
        executive_summary = self._generate_executive_summary(incident_data, analysis)
        actions = self._extract_actions(incident_data, analysis)
        lessons = self._extract_lessons(analysis, actions)
        recommendations = self._generate_recommendations(analysis)
        mitre_techniques = self._extract_mitre_techniques(analysis)
        root_cause = self._extract_root_cause(analysis)

        appendix: dict[str, Any] = {}
        if enrichments:
            appendix["enrichments"] = enrichments
        if incident_data.get("alert_data"):
            appendix["original_alert"] = incident_data["alert_data"]

        return PostIncidentReport(
            incident_id=incident_id,
            executive_summary=executive_summary,
            incident_timeline=timeline,
            root_cause_analysis=root_cause,
            impact_assessment=impact,
            response_actions=actions,
            lessons_learned=lessons,
            recommendations=recommendations,
            mitre_techniques=mitre_techniques,
            appendix=appendix,
        )

    def _build_timeline(
        self,
        incident_data: dict[str, Any],
    ) -> list[TimelineEntry]:
        """Aggregate events into a chronological timeline."""
        entries: list[TimelineEntry] = []

        # Add incident creation
        created_at = incident_data.get("created_at")
        if created_at:
            if isinstance(created_at, str):
                try:
                    created_at = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                except ValueError:
                    created_at = None

        entries.append(
            TimelineEntry(
                timestamp=created_at,
                event="Incident created / alert received",
                source=str(incident_data.get("source", "unknown")),
            )
        )

        # Add audit log entries
        for audit in incident_data.get("audit_log", []):
            ts = audit.get("timestamp")
            if isinstance(ts, str):
                try:
                    ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                except ValueError:
                    ts = None

            action_data = audit.get("action", "unknown")
            if isinstance(action_data, dict):
                action_str = action_data.get("type", str(action_data))
            else:
                action_str = str(action_data)

            entries.append(
                TimelineEntry(
                    timestamp=ts,
                    event=action_str,
                    actor=audit.get("actor", "system"),
                )
            )

        # Add investigation steps from analysis
        for step in incident_data.get("investigation_steps", []):
            entries.append(
                TimelineEntry(
                    event=step.get("action", "Investigation step"),
                    source=step.get("tool"),
                )
            )

        # Sort by timestamp (entries without timestamp go last)
        entries.sort(key=lambda e: e.timestamp or datetime.max.replace(tzinfo=timezone.utc))

        return entries

    def _assess_impact(
        self,
        incident_data: dict[str, Any],
        analysis: dict[str, Any],
    ) -> ImpactAssessment:
        """Assess the impact of the incident."""
        severity = analysis.get("severity", incident_data.get("severity", "medium"))
        verdict = analysis.get("verdict", "inconclusive")

        # Determine scope
        affected_assets: list[str] = []
        for enrichment in incident_data.get("enrichments", []):
            if isinstance(enrichment, dict):
                assets = enrichment.get("affected_assets", [])
                if isinstance(assets, list):
                    affected_assets.extend(str(a) for a in assets)

        # Determine data impact based on verdict and evidence
        data_impact = "none"
        if verdict in ("true_positive", "likely_true_positive"):
            evidence = analysis.get("evidence", [])
            for item in evidence:
                if isinstance(item, dict):
                    finding = item.get("finding", "").lower()
                    if any(
                        kw in finding for kw in ["exfiltration", "data loss", "leaked", "stolen"]
                    ):
                        data_impact = "confidentiality breach"
                        break
                    if any(kw in finding for kw in ["modified", "tampered", "altered"]):
                        data_impact = "integrity compromise"
                        break
            if data_impact == "none":
                data_impact = "potential exposure"

        # Scope based on affected assets count
        if len(affected_assets) == 0:
            scope = "contained"
        elif len(affected_assets) <= 5:
            scope = "limited"
        elif len(affected_assets) <= 20:
            scope = "moderate"
        else:
            scope = "widespread"

        # Business impact
        severity_label = self.SEVERITY_LABELS.get(severity, severity)
        business_impact = f"{severity_label} severity incident"
        if verdict == "true_positive":
            business_impact += " confirmed as true positive requiring remediation"
        elif verdict == "false_positive":
            business_impact += " determined to be false positive"

        return ImpactAssessment(
            scope=scope,
            affected_assets=affected_assets,
            affected_users=[],
            data_impact=data_impact,
            business_impact=business_impact,
            severity_justification=f"Severity rated as {severity} based on analysis findings",
        )

    def _generate_executive_summary(
        self,
        incident_data: dict[str, Any],
        analysis: dict[str, Any],
    ) -> str:
        """Generate a template-based executive summary."""
        severity = analysis.get("severity", incident_data.get("severity", "unknown"))
        verdict = analysis.get("verdict", "inconclusive")
        confidence = analysis.get("confidence", 0)
        source = incident_data.get("source", "unknown")
        if isinstance(source, dict):
            source = source.get("type", str(source))

        severity_label = self.SEVERITY_LABELS.get(severity, severity)

        parts = []
        parts.append(
            f"A {severity_label.lower()} severity security incident was detected "
            f"via {source} and classified as {verdict.replace('_', ' ')} "
            f"with {confidence}% confidence."
        )

        # Add key findings
        reasoning = analysis.get("reasoning", "")
        if reasoning:
            # Take first sentence of reasoning as key finding
            first_sentence = reasoning.split(".")[0].strip()
            if first_sentence:
                parts.append(f"Key finding: {first_sentence}.")

        # Add outcome
        recommended_actions = analysis.get("recommended_actions", [])
        if recommended_actions:
            action_count = len(recommended_actions)
            parts.append(f"{action_count} response action(s) were recommended.")

        return " ".join(parts)

    def _extract_actions(
        self,
        incident_data: dict[str, Any],
        analysis: dict[str, Any],
    ) -> list[ActionSummary]:
        """Extract response actions from analysis."""
        actions: list[ActionSummary] = []

        for action_data in analysis.get("recommended_actions", []):
            if isinstance(action_data, dict):
                actions.append(
                    ActionSummary(
                        action=action_data.get("action", "Unknown action"),
                        result=action_data.get("reason"),
                    )
                )

        return actions

    def _extract_lessons(
        self,
        analysis: dict[str, Any],
        actions: list[ActionSummary],
    ) -> list[str]:
        """Extract lessons learned from the analysis and response."""
        lessons: list[str] = []

        # Lesson from detection
        verdict = analysis.get("verdict", "")
        confidence = analysis.get("confidence", 0)

        if verdict == "false_positive":
            lessons.append(
                "Detection rule produced a false positive; consider tuning "
                "detection logic to reduce noise."
            )
        elif verdict == "true_positive" and confidence < 70:
            lessons.append(
                "True positive was detected but with low confidence; "
                "consider adding additional detection signals."
            )

        # Lesson from evidence gaps
        evidence = analysis.get("evidence", [])
        if len(evidence) == 0:
            lessons.append(
                "No evidence was collected during analysis; "
                "review data source availability and integration."
            )
        elif len(evidence) < 3:
            lessons.append(
                "Limited evidence was available; consider expanding "
                "enrichment sources for more comprehensive analysis."
            )

        # Lesson from response actions
        if not actions:
            lessons.append(
                "No specific response actions were recommended; "
                "review playbook coverage for this incident type."
            )

        # Lesson from MITRE coverage
        techniques = analysis.get("mitre_techniques", [])
        if techniques:
            lessons.append(
                f"{len(techniques)} MITRE ATT&CK technique(s) were identified; "
                "ensure detection rules cover these techniques."
            )

        return lessons

    def _generate_recommendations(
        self,
        analysis: dict[str, Any],
    ) -> list[Recommendation]:
        """Generate recommendations from analysis findings."""
        recommendations: list[Recommendation] = []

        verdict = analysis.get("verdict", "")
        severity = analysis.get("severity", "medium")

        # Detection improvement recommendation
        if verdict == "false_positive":
            recommendations.append(
                Recommendation(
                    title="Tune detection rule",
                    description=(
                        "Review and tune the detection rule that generated this "
                        "false positive to reduce analyst fatigue."
                    ),
                    priority="medium",
                    category="detection",
                )
            )
        elif verdict in ("true_positive", "likely_true_positive"):
            if severity in ("critical", "high"):
                recommendations.append(
                    Recommendation(
                        title="Review incident response procedure",
                        description=(
                            "Review and update the incident response procedure "
                            "for this type of incident based on lessons learned."
                        ),
                        priority="high",
                        category="response",
                    )
                )

            recommendations.append(
                Recommendation(
                    title="Update threat intelligence",
                    description=(
                        "Incorporate IOCs and TTPs from this incident "
                        "into threat intelligence feeds and detection rules."
                    ),
                    priority="medium",
                    category="prevention",
                )
            )

        # Training recommendation for recurring issues
        techniques = analysis.get("mitre_techniques", [])
        if techniques:
            recommendations.append(
                Recommendation(
                    title="Security awareness training",
                    description=(
                        "Conduct training covering the attack techniques "
                        "observed in this incident to improve organizational awareness."
                    ),
                    priority="low",
                    category="training",
                )
            )

        # Sort by priority
        recommendations.sort(key=lambda r: self.PRIORITY_ORDER.get(r.priority, 5))

        return recommendations

    def _extract_mitre_techniques(
        self,
        analysis: dict[str, Any],
    ) -> list[str]:
        """Extract MITRE technique IDs from analysis."""
        techniques = analysis.get("mitre_techniques", [])
        result = []
        for t in techniques:
            if isinstance(t, dict):
                tid = t.get("id", "")
                if tid:
                    result.append(tid)
            elif isinstance(t, str):
                result.append(t)
        return result

    def _extract_root_cause(
        self,
        analysis: dict[str, Any],
    ) -> str:
        """Extract root cause from analysis reasoning."""
        reasoning = analysis.get("reasoning", "")
        if reasoning:
            return f"Based on analysis: {reasoning}"
        return "Root cause analysis pending further investigation."

    def export_markdown(self, report: PostIncidentReport) -> str:
        """Export the report as a Markdown document.

        Args:
            report: The post-incident report to export.

        Returns:
            Markdown-formatted string.
        """
        lines: list[str] = []

        lines.append(f"# Post-Incident Report: {report.incident_id}")
        lines.append("")
        lines.append(f"**Generated:** {report.report_generated_at.strftime('%Y-%m-%d %H:%M UTC')}")
        lines.append("")

        # Executive Summary
        lines.append("## Executive Summary")
        lines.append("")
        lines.append(report.executive_summary)
        lines.append("")

        # Timeline
        if report.incident_timeline:
            lines.append("## Incident Timeline")
            lines.append("")
            lines.append("| Time | Event | Source | Actor |")
            lines.append("|------|-------|--------|-------|")
            for entry in report.incident_timeline:
                ts = entry.timestamp.strftime("%Y-%m-%d %H:%M") if entry.timestamp else "N/A"
                lines.append(
                    f"| {ts} | {entry.event} | "
                    f"{entry.source or 'N/A'} | {entry.actor or 'N/A'} |"
                )
            lines.append("")

        # Root Cause
        lines.append("## Root Cause Analysis")
        lines.append("")
        lines.append(report.root_cause_analysis)
        lines.append("")

        # Impact Assessment
        lines.append("## Impact Assessment")
        lines.append("")
        lines.append(f"- **Scope:** {report.impact_assessment.scope}")
        lines.append(f"- **Data Impact:** {report.impact_assessment.data_impact}")
        lines.append(f"- **Business Impact:** {report.impact_assessment.business_impact}")
        if report.impact_assessment.affected_assets:
            lines.append(
                f"- **Affected Assets:** " f"{', '.join(report.impact_assessment.affected_assets)}"
            )
        lines.append(
            f"- **Severity Justification:** " f"{report.impact_assessment.severity_justification}"
        )
        lines.append("")

        # Response Actions
        if report.response_actions:
            lines.append("## Response Actions")
            lines.append("")
            for i, action in enumerate(report.response_actions, 1):
                lines.append(f"{i}. **{action.action}**")
                if action.result:
                    lines.append(f"   - Result: {action.result}")
                if action.performed_by:
                    lines.append(f"   - Performed by: {action.performed_by}")
            lines.append("")

        # Lessons Learned
        if report.lessons_learned:
            lines.append("## Lessons Learned")
            lines.append("")
            for lesson in report.lessons_learned:
                lines.append(f"- {lesson}")
            lines.append("")

        # Recommendations
        if report.recommendations:
            lines.append("## Recommendations")
            lines.append("")
            lines.append("| Priority | Title | Category | Owner |")
            lines.append("|----------|-------|----------|-------|")
            for rec in report.recommendations:
                lines.append(
                    f"| {rec.priority.upper()} | {rec.title} | "
                    f"{rec.category} | {rec.owner or 'TBD'} |"
                )
            lines.append("")
            for rec in report.recommendations:
                lines.append(f"### {rec.title}")
                lines.append("")
                lines.append(rec.description)
                lines.append("")

        # MITRE Techniques
        if report.mitre_techniques:
            lines.append("## MITRE ATT&CK Techniques")
            lines.append("")
            for tech_id in report.mitre_techniques:
                technique_path = tech_id.replace(".", "/")
                url = f"https://attack.mitre.org/techniques/{technique_path}/"
                lines.append(f"- [{tech_id}]({url})")
            lines.append("")

        return "\n".join(lines)

    def export_json(self, report: PostIncidentReport) -> str:
        """Export the report as a JSON string.

        Args:
            report: The post-incident report to export.

        Returns:
            JSON-formatted string.
        """
        return report.model_dump_json(indent=2)
