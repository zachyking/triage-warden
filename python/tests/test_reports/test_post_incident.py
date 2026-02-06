"""Tests for post-incident report generation (Stage 4.4.1)."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from tw_ai.reports.post_incident import (
    ActionSummary,
    ImpactAssessment,
    PostIncidentReport,
    PostIncidentReportGenerator,
    Recommendation,
    TimelineEntry,
)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def generator():
    """Create a PostIncidentReportGenerator instance."""
    return PostIncidentReportGenerator()


@pytest.fixture
def basic_incident_data():
    """Basic incident data for testing."""
    return {
        "id": "inc-001",
        "source": "siem",
        "severity": "high",
        "created_at": "2024-01-15T10:30:00Z",
        "alert_data": {
            "alert_type": "suspicious_login",
            "title": "Multiple failed login attempts",
        },
        "enrichments": [],
        "audit_log": [
            {
                "timestamp": "2024-01-15T10:31:00Z",
                "action": "triage_started",
                "actor": "ai_agent",
            },
            {
                "timestamp": "2024-01-15T10:35:00Z",
                "action": "analysis_complete",
                "actor": "ai_agent",
            },
        ],
    }


@pytest.fixture
def basic_analysis():
    """Basic analysis data for testing."""
    return {
        "verdict": "true_positive",
        "severity": "high",
        "confidence": 85,
        "reasoning": "Multiple failed login attempts followed by successful login from unusual location. This indicates credential stuffing attack.",
        "evidence": [
            {
                "source_type": "log",
                "source_name": "auth_logs",
                "finding": "50 failed login attempts in 5 minutes",
                "confidence": 90,
            },
            {
                "source_type": "geo",
                "source_name": "ip_geolocation",
                "finding": "Login from unusual country",
                "confidence": 80,
            },
        ],
        "recommended_actions": [
            {
                "action": "Block source IP",
                "priority": "immediate",
                "reason": "Active attack in progress",
            },
            {
                "action": "Reset user password",
                "priority": "high",
                "reason": "Credentials may be compromised",
            },
        ],
        "mitre_techniques": [
            {"id": "T1110", "name": "Brute Force"},
            {"id": "T1078", "name": "Valid Accounts"},
        ],
    }


@pytest.fixture
def false_positive_analysis():
    """Analysis data for a false positive incident."""
    return {
        "verdict": "false_positive",
        "severity": "low",
        "confidence": 92,
        "reasoning": "Alert triggered by legitimate automated process.",
        "evidence": [],
        "recommended_actions": [],
        "mitre_techniques": [],
    }


@pytest.fixture
def enriched_incident_data(basic_incident_data):
    """Incident data with enrichments."""
    basic_incident_data["enrichments"] = [
        {
            "affected_assets": ["web-server-01", "db-server-02"],
        }
    ]
    return basic_incident_data


# ============================================================================
# Model Tests
# ============================================================================


class TestModels:
    """Tests for post-incident report models."""

    def test_timeline_entry_defaults(self):
        entry = TimelineEntry(event="Test event")
        assert entry.event == "Test event"
        assert entry.timestamp is None
        assert entry.source is None
        assert entry.actor is None

    def test_timeline_entry_full(self):
        now = datetime.now(timezone.utc)
        entry = TimelineEntry(
            timestamp=now,
            event="Alert received",
            source="SIEM",
            actor="system",
        )
        assert entry.timestamp == now
        assert entry.source == "SIEM"

    def test_impact_assessment_defaults(self):
        impact = ImpactAssessment()
        assert impact.scope == "unknown"
        assert impact.data_impact == "none"
        assert impact.business_impact == "minimal"
        assert impact.affected_assets == []
        assert impact.affected_users == []

    def test_action_summary(self):
        action = ActionSummary(
            action="Block IP",
            performed_by="analyst",
            result="IP blocked successfully",
        )
        assert action.action == "Block IP"
        assert action.performed_by == "analyst"

    def test_recommendation(self):
        rec = Recommendation(
            title="Update firewall rules",
            description="Add blocking rule for malicious IP range",
            priority="high",
            category="prevention",
            owner="network_team",
        )
        assert rec.title == "Update firewall rules"
        assert rec.priority == "high"
        assert rec.category == "prevention"
        assert rec.owner == "network_team"

    def test_recommendation_defaults(self):
        rec = Recommendation(
            title="Test",
            description="Test desc",
        )
        assert rec.priority == "medium"
        assert rec.category == "general"
        assert rec.owner is None

    def test_post_incident_report_defaults(self):
        report = PostIncidentReport(incident_id="test-001")
        assert report.incident_id == "test-001"
        assert report.executive_summary == ""
        assert report.incident_timeline == []
        assert report.lessons_learned == []
        assert report.recommendations == []
        assert report.mitre_techniques == []
        assert report.appendix == {}

    def test_post_incident_report_serialization(self):
        report = PostIncidentReport(
            incident_id="test-002",
            executive_summary="Test summary",
            lessons_learned=["Lesson 1", "Lesson 2"],
            mitre_techniques=["T1566"],
        )
        data = report.model_dump()
        assert data["incident_id"] == "test-002"
        assert len(data["lessons_learned"]) == 2
        assert "T1566" in data["mitre_techniques"]


# ============================================================================
# Generator Tests
# ============================================================================


class TestPostIncidentReportGenerator:
    """Tests for PostIncidentReportGenerator."""

    def test_generate_basic(self, generator, basic_incident_data, basic_analysis):
        report = generator.generate(basic_incident_data, basic_analysis)

        assert report.incident_id == "inc-001"
        assert report.executive_summary != ""
        assert len(report.incident_timeline) > 0
        assert report.root_cause_analysis != ""

    def test_generate_with_enrichments(
        self, generator, enriched_incident_data, basic_analysis
    ):
        enrichments = {"threat_intel": {"known_campaign": "APT29"}}
        report = generator.generate(
            enriched_incident_data, basic_analysis, enrichments
        )

        assert "enrichments" in report.appendix
        assert report.appendix["enrichments"]["threat_intel"]["known_campaign"] == "APT29"

    def test_executive_summary_content(
        self, generator, basic_incident_data, basic_analysis
    ):
        report = generator.generate(basic_incident_data, basic_analysis)

        # Should mention severity, verdict, and confidence
        assert "high" in report.executive_summary.lower()
        assert "true positive" in report.executive_summary.lower()
        assert "85%" in report.executive_summary

    def test_timeline_ordering(self, generator, basic_incident_data, basic_analysis):
        report = generator.generate(basic_incident_data, basic_analysis)

        # Timeline should include incident creation and audit log entries
        assert len(report.incident_timeline) >= 3  # creation + 2 audit entries

        # Entries with timestamps should be ordered
        timestamped = [e for e in report.incident_timeline if e.timestamp]
        for i in range(len(timestamped) - 1):
            assert timestamped[i].timestamp <= timestamped[i + 1].timestamp

    def test_impact_assessment_true_positive(
        self, generator, enriched_incident_data, basic_analysis
    ):
        report = generator.generate(enriched_incident_data, basic_analysis)

        assert report.impact_assessment.scope != "unknown"
        assert report.impact_assessment.data_impact != "none"
        assert "true positive" in report.impact_assessment.business_impact.lower()

    def test_impact_assessment_false_positive(
        self, generator, basic_incident_data, false_positive_analysis
    ):
        report = generator.generate(basic_incident_data, false_positive_analysis)

        assert "false positive" in report.impact_assessment.business_impact.lower()

    def test_lessons_learned_true_positive(
        self, generator, basic_incident_data, basic_analysis
    ):
        report = generator.generate(basic_incident_data, basic_analysis)

        assert len(report.lessons_learned) > 0
        # Should have lesson about MITRE techniques
        mitre_lessons = [l for l in report.lessons_learned if "MITRE" in l]
        assert len(mitre_lessons) > 0

    def test_lessons_learned_false_positive(
        self, generator, basic_incident_data, false_positive_analysis
    ):
        report = generator.generate(basic_incident_data, false_positive_analysis)

        # Should suggest tuning detection
        tuning_lessons = [
            l for l in report.lessons_learned if "false positive" in l.lower()
        ]
        assert len(tuning_lessons) > 0

    def test_recommendations_true_positive(
        self, generator, basic_incident_data, basic_analysis
    ):
        report = generator.generate(basic_incident_data, basic_analysis)

        assert len(report.recommendations) > 0
        # Should include response review for high severity TP
        categories = [r.category for r in report.recommendations]
        assert "response" in categories or "prevention" in categories

    def test_recommendations_false_positive(
        self, generator, basic_incident_data, false_positive_analysis
    ):
        report = generator.generate(basic_incident_data, false_positive_analysis)

        # Should recommend tuning detection
        detection_recs = [
            r for r in report.recommendations if r.category == "detection"
        ]
        assert len(detection_recs) > 0

    def test_recommendations_sorted_by_priority(
        self, generator, basic_incident_data, basic_analysis
    ):
        report = generator.generate(basic_incident_data, basic_analysis)

        if len(report.recommendations) > 1:
            priority_order = {"critical": 1, "high": 2, "medium": 3, "low": 4}
            for i in range(len(report.recommendations) - 1):
                p1 = priority_order.get(report.recommendations[i].priority, 5)
                p2 = priority_order.get(report.recommendations[i + 1].priority, 5)
                assert p1 <= p2

    def test_mitre_techniques_extraction(
        self, generator, basic_incident_data, basic_analysis
    ):
        report = generator.generate(basic_incident_data, basic_analysis)

        assert "T1110" in report.mitre_techniques
        assert "T1078" in report.mitre_techniques

    def test_mitre_techniques_string_format(self, generator, basic_incident_data):
        analysis = {
            "verdict": "true_positive",
            "severity": "medium",
            "confidence": 75,
            "mitre_techniques": ["T1566", "T1059.001"],
            "evidence": [],
            "recommended_actions": [],
        }
        report = generator.generate(basic_incident_data, analysis)

        assert "T1566" in report.mitre_techniques
        assert "T1059.001" in report.mitre_techniques

    def test_root_cause_from_reasoning(
        self, generator, basic_incident_data, basic_analysis
    ):
        report = generator.generate(basic_incident_data, basic_analysis)

        assert "credential stuffing" in report.root_cause_analysis.lower()

    def test_appendix_contains_alert_data(
        self, generator, basic_incident_data, basic_analysis
    ):
        report = generator.generate(basic_incident_data, basic_analysis)

        assert "original_alert" in report.appendix
        assert report.appendix["original_alert"]["alert_type"] == "suspicious_login"


# ============================================================================
# Export Tests
# ============================================================================


class TestExport:
    """Tests for report export functionality."""

    def test_export_markdown(self, generator, basic_incident_data, basic_analysis):
        report = generator.generate(basic_incident_data, basic_analysis)
        markdown = generator.export_markdown(report)

        assert "# Post-Incident Report:" in markdown
        assert "## Executive Summary" in markdown
        assert "## Root Cause Analysis" in markdown
        assert "## Impact Assessment" in markdown
        assert "## MITRE ATT&CK Techniques" in markdown

    def test_export_markdown_timeline_table(
        self, generator, basic_incident_data, basic_analysis
    ):
        report = generator.generate(basic_incident_data, basic_analysis)
        markdown = generator.export_markdown(report)

        assert "## Incident Timeline" in markdown
        assert "| Time | Event | Source | Actor |" in markdown

    def test_export_markdown_recommendations_table(
        self, generator, basic_incident_data, basic_analysis
    ):
        report = generator.generate(basic_incident_data, basic_analysis)
        markdown = generator.export_markdown(report)

        assert "## Recommendations" in markdown
        assert "| Priority | Title | Category | Owner |" in markdown

    def test_export_json(self, generator, basic_incident_data, basic_analysis):
        report = generator.generate(basic_incident_data, basic_analysis)
        json_str = generator.export_json(report)

        data = json.loads(json_str)
        assert data["incident_id"] == "inc-001"
        assert "executive_summary" in data
        assert "incident_timeline" in data
        assert "recommendations" in data

    def test_export_json_roundtrip(
        self, generator, basic_incident_data, basic_analysis
    ):
        report = generator.generate(basic_incident_data, basic_analysis)
        json_str = generator.export_json(report)

        # Parse back and verify
        data = json.loads(json_str)
        report2 = PostIncidentReport.model_validate(data)

        assert report2.incident_id == report.incident_id
        assert len(report2.lessons_learned) == len(report.lessons_learned)
        assert len(report2.mitre_techniques) == len(report.mitre_techniques)

    def test_export_markdown_mitre_links(
        self, generator, basic_incident_data, basic_analysis
    ):
        report = generator.generate(basic_incident_data, basic_analysis)
        markdown = generator.export_markdown(report)

        assert "https://attack.mitre.org/techniques/T1110/" in markdown
        assert "https://attack.mitre.org/techniques/T1078/" in markdown


# ============================================================================
# Edge Case Tests
# ============================================================================


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_generate_minimal_data(self, generator):
        report = generator.generate(
            {"id": "min-001"},
            {"verdict": "inconclusive", "severity": "low", "confidence": 50},
        )
        assert report.incident_id == "min-001"
        assert report.executive_summary != ""

    def test_generate_empty_analysis(self, generator):
        report = generator.generate(
            {"id": "empty-001"},
            {},
        )
        assert report.incident_id == "empty-001"
        assert len(report.lessons_learned) > 0  # Should still generate some lessons

    def test_generate_with_dict_source(self, generator):
        report = generator.generate(
            {"id": "dict-src", "source": {"type": "siem", "platform": "Splunk"}},
            {"verdict": "true_positive", "severity": "medium", "confidence": 70},
        )
        assert report.incident_id == "dict-src"

    def test_generate_with_dict_audit_action(self, generator):
        report = generator.generate(
            {
                "id": "dict-action",
                "audit_log": [
                    {"action": {"type": "escalated"}, "actor": "system"},
                ],
            },
            {"verdict": "suspicious", "severity": "medium", "confidence": 60},
        )
        assert len(report.incident_timeline) >= 2  # creation + audit entry

    def test_impact_with_data_exfiltration(self, generator):
        report = generator.generate(
            {"id": "exfil-001"},
            {
                "verdict": "true_positive",
                "severity": "critical",
                "confidence": 95,
                "evidence": [
                    {"finding": "Data exfiltration detected to external server"}
                ],
            },
        )
        assert "confidentiality" in report.impact_assessment.data_impact.lower()

    def test_impact_scope_with_many_assets(self, generator):
        enrichments_list = [
            {"affected_assets": [f"server-{i}" for i in range(25)]}
        ]
        report = generator.generate(
            {"id": "wide-001", "enrichments": enrichments_list},
            {"verdict": "true_positive", "severity": "high", "confidence": 80},
        )
        assert report.impact_assessment.scope == "widespread"
