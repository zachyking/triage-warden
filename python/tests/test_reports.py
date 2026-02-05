"""Tests for the investigation report generation module (Stage 2.1.3)."""

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from tw_ai.agents.models import (
    EvidenceItem,
    Indicator,
    InvestigationStep,
    MITRETechnique,
    RecommendedAction,
    TriageAnalysis,
)
from tw_ai.reports import (
    InvestigationReportGenerator,
    InvestigationReport,
    ReportFormat,
    JsonFormatter,
    HtmlFormatter,
    get_formatter,
    export_report,
)
from tw_ai.reports.models import (
    ReportMetadata,
    VerdictSummary,
    AlertSummary,
    TimelineEntry,
    FormattedEvidence,
    EvidenceSummary,
    FormattedMitreTechnique,
    FormattedIndicator,
    FormattedAction,
)


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def sample_evidence():
    """Create sample evidence items."""
    return [
        EvidenceItem(
            source_type="threat_intel",
            source_name="VirusTotal",
            data_type="threat_intel_match",
            value={"malicious": 45, "total": 70},
            finding="Domain flagged by 45/70 vendors",
            relevance="Strongly indicates malicious activity",
            confidence=95,
            link="https://virustotal.com/gui/domain/malicious.com",
        ),
        EvidenceItem(
            source_type="siem",
            source_name="Splunk",
            data_type="network_activity",
            value={"src_ip": "192.168.1.100", "dst_ip": "10.0.0.1"},
            finding="Outbound connection to known C2",
            relevance="Confirms communication with threat actor",
            confidence=85,
            link=None,
        ),
        EvidenceItem(
            source_type="email",
            source_name="Proofpoint",
            data_type="email_content",
            value={"subject": "Urgent: Update password", "sender": "attacker@malicious.com"},
            finding="Email contains credential harvesting link",
            relevance="Initial attack vector identified",
            confidence=70,
        ),
    ]


@pytest.fixture
def sample_investigation_steps():
    """Create sample investigation steps."""
    return [
        InvestigationStep(
            order=1,
            action="Query VirusTotal for domain reputation",
            result="Domain flagged as malicious by 45/70 vendors",
            tool="lookup_domain",
            status="completed",
        ),
        InvestigationStep(
            order=2,
            action="Search SIEM for related network activity",
            result="Found 15 outbound connections to the domain",
            tool="siem_search",
            status="completed",
        ),
        InvestigationStep(
            order=3,
            action="Analyze email headers",
            result="Email originated from compromised server",
            tool="email_analysis",
            status="completed",
        ),
    ]


@pytest.fixture
def sample_mitre_techniques():
    """Create sample MITRE ATT&CK techniques."""
    return [
        MITRETechnique(
            id="T1566.001",
            name="Phishing: Spearphishing Attachment",
            tactic="Initial Access",
            relevance="Email with malicious attachment observed",
        ),
        MITRETechnique(
            id="T1071.001",
            name="Web Protocols",
            tactic="Command and Control",
            relevance="C2 communication over HTTPS",
        ),
    ]


@pytest.fixture
def sample_indicators():
    """Create sample indicators."""
    return [
        Indicator(
            type="domain",
            value="malicious.com",
            verdict="malicious",
            context="Known phishing domain",
        ),
        Indicator(
            type="ip",
            value="10.0.0.1",
            verdict="suspicious",
            context="Possible C2 server",
        ),
        Indicator(
            type="hash",
            value="d41d8cd98f00b204e9800998ecf8427e",
            verdict="malicious",
            context="Malware payload hash",
        ),
    ]


@pytest.fixture
def sample_recommended_actions():
    """Create sample recommended actions."""
    return [
        RecommendedAction(
            action="Block sender domain at email gateway",
            priority="immediate",
            reason="Known phishing domain",
            requires_approval=False,
        ),
        RecommendedAction(
            action="Isolate affected workstation",
            priority="high",
            reason="Potential malware infection",
            requires_approval=True,
        ),
        RecommendedAction(
            action="Reset user credentials",
            priority="medium",
            reason="Credentials may be compromised",
            requires_approval=False,
        ),
    ]


@pytest.fixture
def sample_analysis(
    sample_evidence,
    sample_investigation_steps,
    sample_mitre_techniques,
    sample_indicators,
    sample_recommended_actions,
):
    """Create a complete sample triage analysis."""
    return TriageAnalysis(
        verdict="true_positive",
        confidence=92,
        severity="high",
        summary="Confirmed phishing attack with credential harvesting attempt",
        indicators=sample_indicators,
        mitre_techniques=sample_mitre_techniques,
        recommended_actions=sample_recommended_actions,
        reasoning="Multiple high-confidence indicators point to a coordinated phishing attack. "
        "The domain reputation is severely negative across multiple threat intelligence sources. "
        "Network analysis confirms C2 communication patterns.",
        evidence=sample_evidence,
        investigation_steps=sample_investigation_steps,
    )


@pytest.fixture
def sample_incident_data():
    """Create sample incident data dictionary."""
    return {
        "id": "12345678-1234-1234-1234-123456789012",
        "tenant_id": "00000000-0000-0000-0000-000000000001",
        "source": {"type": "email_security", "gateway": "Proofpoint"},
        "severity": "high",
        "alert_data": {
            "id": "alert-001",
            "alert_type": "phishing",
            "title": "Suspected phishing email",
            "subject": "Urgent: Update your password",
            "sender": "attacker@malicious.com",
            "recipient": "user@company.com",
        },
        "enrichments": [
            {
                "enrichment_type": "threat_intel",
                "source": "VirusTotal",
                "data": {"malicious": 45, "total": 70},
            },
        ],
        "audit_log": [
            {
                "timestamp": "2024-01-15T10:00:00Z",
                "action": "incident_created",
                "actor": "system",
                "details": None,
            },
            {
                "timestamp": "2024-01-15T10:05:00Z",
                "action": "analysis_completed",
                "actor": "ai",
                "details": {"model": "gpt-4"},
            },
        ],
        "created_at": "2024-01-15T10:00:00Z",
    }


# =============================================================================
# Report Generator Tests
# =============================================================================


class TestInvestigationReportGenerator:
    """Tests for InvestigationReportGenerator class."""

    def test_generate_report_basic(self, sample_analysis, sample_incident_data):
        """Test basic report generation."""
        generator = InvestigationReportGenerator()
        report = generator.generate(sample_incident_data, sample_analysis)

        assert isinstance(report, InvestigationReport)
        assert report.metadata.incident_id == "12345678-1234-1234-1234-123456789012"
        assert report.verdict.verdict == "true_positive"
        assert report.verdict.confidence == 92

    def test_generate_executive_summary(self, sample_analysis, sample_incident_data):
        """Test executive summary generation."""
        generator = InvestigationReportGenerator()
        report = generator.generate(sample_incident_data, sample_analysis)

        # Executive summary should include key information
        assert "True Positive" in report.executive_summary
        assert "high" in report.executive_summary.lower() or "High" in report.executive_summary
        assert "confidence" in report.executive_summary.lower()

    def test_generate_timeline(self, sample_analysis, sample_incident_data):
        """Test timeline generation from investigation steps."""
        generator = InvestigationReportGenerator()
        report = generator.generate(sample_incident_data, sample_analysis)

        assert len(report.timeline) == 3
        assert report.timeline[0].order == 1
        assert report.timeline[0].action == "Query VirusTotal for domain reputation"
        assert report.timeline[0].tool == "lookup_domain"

    def test_generate_evidence_table(self, sample_analysis, sample_incident_data):
        """Test evidence formatting."""
        generator = InvestigationReportGenerator()
        report = generator.generate(sample_incident_data, sample_analysis)

        assert len(report.evidence) == 3
        assert report.evidence[0].source_name == "VirusTotal"
        assert report.evidence[0].confidence == 95
        assert report.evidence[0].link is not None

    def test_evidence_summary_statistics(self, sample_analysis, sample_incident_data):
        """Test evidence summary statistics calculation."""
        generator = InvestigationReportGenerator()
        report = generator.generate(sample_incident_data, sample_analysis)

        summary = report.evidence_summary
        assert summary.total_evidence == 3
        assert 80 <= summary.average_confidence <= 90  # (95 + 85 + 70) / 3 = 83.3
        assert summary.high_confidence_count == 2  # 95 and 85
        assert summary.medium_confidence_count == 1  # 70
        assert summary.low_confidence_count == 0

    def test_generate_mitre_techniques(self, sample_analysis, sample_incident_data):
        """Test MITRE technique formatting."""
        generator = InvestigationReportGenerator()
        report = generator.generate(sample_incident_data, sample_analysis)

        assert len(report.mitre_techniques) == 2
        assert report.mitre_techniques[0].technique_id == "T1566.001"
        assert "attack.mitre.org" in report.mitre_techniques[0].url

    def test_mitre_url_generation(self, sample_analysis, sample_incident_data):
        """Test MITRE ATT&CK URL generation."""
        generator = InvestigationReportGenerator()
        report = generator.generate(sample_incident_data, sample_analysis)

        # T1566.001 should become T1566/001 in URL
        technique = report.mitre_techniques[0]
        assert technique.url == "https://attack.mitre.org/techniques/T1566/001/"

    def test_generate_indicators(self, sample_analysis, sample_incident_data):
        """Test indicator formatting."""
        generator = InvestigationReportGenerator()
        report = generator.generate(sample_incident_data, sample_analysis)

        assert len(report.indicators) == 3
        assert report.indicators[0].indicator_type == "domain"
        assert report.indicators[0].value == "malicious.com"
        assert report.indicators[0].verdict == "malicious"

    def test_generate_recommendations_sorted_by_priority(
        self, sample_analysis, sample_incident_data
    ):
        """Test that recommendations are sorted by priority."""
        generator = InvestigationReportGenerator()
        report = generator.generate(sample_incident_data, sample_analysis)

        assert len(report.recommended_actions) == 3
        # Should be sorted: immediate, high, medium
        assert report.recommended_actions[0].priority == "immediate"
        assert report.recommended_actions[1].priority == "high"
        assert report.recommended_actions[2].priority == "medium"

    def test_generate_audit_log(self, sample_analysis, sample_incident_data):
        """Test audit log formatting."""
        generator = InvestigationReportGenerator()
        report = generator.generate(sample_incident_data, sample_analysis)

        assert len(report.audit_log) == 2
        assert report.audit_log[0].actor == "system"
        assert report.audit_log[1].actor == "ai"

    def test_generate_with_dict_analysis(self, sample_incident_data):
        """Test report generation with dict analysis input."""
        analysis_dict = {
            "verdict": "suspicious",
            "confidence": 65,
            "severity": "medium",
            "summary": "Suspicious activity detected",
            "indicators": [],
            "mitre_techniques": [],
            "recommended_actions": [],
            "reasoning": "Needs further investigation",
            "evidence": [],
            "investigation_steps": [],
        }

        generator = InvestigationReportGenerator()
        report = generator.generate(sample_incident_data, analysis_dict)

        assert report.verdict.verdict == "suspicious"
        assert report.verdict.confidence == 65

    def test_generate_with_empty_evidence(self, sample_incident_data):
        """Test report generation with no evidence."""
        analysis = TriageAnalysis(
            verdict="inconclusive",
            confidence=30,
            severity="low",
            summary="Insufficient data for analysis",
            indicators=[],
            mitre_techniques=[],
            recommended_actions=[],
            reasoning="No conclusive evidence found",
            evidence=[],
            investigation_steps=[],
        )

        generator = InvestigationReportGenerator()
        report = generator.generate(sample_incident_data, analysis)

        assert len(report.evidence) == 0
        assert report.evidence_summary.total_evidence == 0
        assert report.evidence_summary.average_confidence == 0.0

    def test_confidence_description(self, sample_incident_data):
        """Test confidence level descriptions."""
        generator = InvestigationReportGenerator()

        # Test different confidence levels
        assert generator._confidence_description(95) == "very high"
        assert generator._confidence_description(80) == "high"
        assert generator._confidence_description(60) == "moderate"
        assert generator._confidence_description(30) == "low"
        assert generator._confidence_description(10) == "very low"


# =============================================================================
# Report Model Tests
# =============================================================================


class TestReportModels:
    """Tests for report model classes."""

    def test_investigation_report_to_json(self, sample_analysis, sample_incident_data):
        """Test JSON serialization of report."""
        generator = InvestigationReportGenerator()
        report = generator.generate(sample_incident_data, sample_analysis)

        json_str = report.to_json()
        assert isinstance(json_str, str)
        assert "true_positive" in json_str
        assert "VirusTotal" in json_str

    def test_investigation_report_to_dict(self, sample_analysis, sample_incident_data):
        """Test dictionary conversion of report."""
        generator = InvestigationReportGenerator()
        report = generator.generate(sample_incident_data, sample_analysis)

        data = report.to_dict()
        assert isinstance(data, dict)
        assert data["verdict"]["verdict"] == "true_positive"
        assert len(data["evidence"]) == 3

    def test_report_metadata_fields(self):
        """Test ReportMetadata model fields."""
        metadata = ReportMetadata(
            incident_id="test-123",
            generated_at=datetime.now(timezone.utc),
            generated_by="Test Generator",
            tenant_id="tenant-456",
        )

        assert metadata.incident_id == "test-123"
        assert metadata.report_version == "1.0"
        assert metadata.tenant_id == "tenant-456"

    def test_evidence_summary_fields(self):
        """Test EvidenceSummary model fields."""
        summary = EvidenceSummary(
            total_evidence=5,
            average_confidence=75.5,
            high_confidence_count=2,
            medium_confidence_count=2,
            low_confidence_count=1,
            sources_used=["VirusTotal", "Splunk"],
            data_types_found=["threat_intel_match", "network_activity"],
        )

        assert summary.total_evidence == 5
        assert summary.average_confidence == 75.5
        assert len(summary.sources_used) == 2


# =============================================================================
# Formatter Tests
# =============================================================================


class TestFormatters:
    """Tests for report formatters."""

    def test_json_formatter(self, sample_analysis, sample_incident_data):
        """Test JSON formatter."""
        generator = InvestigationReportGenerator()
        report = generator.generate(sample_incident_data, sample_analysis)

        formatter = JsonFormatter()
        output = formatter.format(report)

        assert isinstance(output, str)
        assert formatter.content_type() == "application/json"
        assert formatter.file_extension() == ".json"

    def test_json_formatter_exclude_raw_data(self, sample_analysis, sample_incident_data):
        """Test JSON formatter with raw data excluded."""
        generator = InvestigationReportGenerator()
        report = generator.generate(sample_incident_data, sample_analysis)

        formatter = JsonFormatter(include_raw_data=False)
        output = formatter.format(report)

        import json

        data = json.loads(output)
        assert "raw_alert_data" not in data
        assert "enrichments" not in data

    def test_html_formatter(self, sample_analysis, sample_incident_data):
        """Test HTML formatter."""
        generator = InvestigationReportGenerator()
        report = generator.generate(sample_incident_data, sample_analysis)

        formatter = HtmlFormatter()
        output = formatter.format(report)

        assert isinstance(output, str)
        assert formatter.content_type() == "text/html"
        assert formatter.file_extension() == ".html"
        assert "<!DOCTYPE html>" in output
        assert "Investigation Report" in output

    def test_get_formatter_json(self):
        """Test get_formatter for JSON."""
        formatter = get_formatter("json")
        assert isinstance(formatter, JsonFormatter)

    def test_get_formatter_html(self):
        """Test get_formatter for HTML."""
        formatter = get_formatter("html")
        assert isinstance(formatter, HtmlFormatter)

    def test_get_formatter_case_insensitive(self):
        """Test that get_formatter is case insensitive."""
        assert isinstance(get_formatter("JSON"), JsonFormatter)
        assert isinstance(get_formatter("Html"), HtmlFormatter)

    def test_get_formatter_invalid(self):
        """Test get_formatter with invalid format."""
        with pytest.raises(ValueError, match="Unsupported format"):
            get_formatter("invalid")

    def test_export_report_json(self, sample_analysis, sample_incident_data, tmp_path):
        """Test export_report function for JSON."""
        generator = InvestigationReportGenerator()
        report = generator.generate(sample_incident_data, sample_analysis)

        output_file = tmp_path / "test_report.json"
        content = export_report(report, "json", output_file)

        assert isinstance(content, str)
        assert output_file.exists()

        import json

        with open(output_file) as f:
            data = json.load(f)
            assert data["verdict"]["verdict"] == "true_positive"

    def test_export_report_html(self, sample_analysis, sample_incident_data, tmp_path):
        """Test export_report function for HTML."""
        generator = InvestigationReportGenerator()
        report = generator.generate(sample_incident_data, sample_analysis)

        output_file = tmp_path / "test_report.html"
        content = export_report(report, "html", output_file)

        assert isinstance(content, str)
        assert output_file.exists()
        assert "<!DOCTYPE html>" in content


# =============================================================================
# Edge Case Tests
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_incident_data(self):
        """Test report generation with minimal incident data."""
        incident_data = {
            "id": "test-123",
            "source": {},
            "alert_data": {},
        }

        analysis = TriageAnalysis(
            verdict="inconclusive",
            confidence=0,
            severity="informational",
            summary="Minimal test",
            indicators=[],
            mitre_techniques=[],
            recommended_actions=[],
            reasoning="",
            evidence=[],
            investigation_steps=[],
        )

        generator = InvestigationReportGenerator()
        report = generator.generate(incident_data, analysis)

        assert report.metadata.incident_id == "test-123"
        assert report.alert.source == "Unknown Source"

    def test_special_characters_in_reasoning(self, sample_incident_data):
        """Test that special characters in reasoning are handled."""
        analysis = TriageAnalysis(
            verdict="suspicious",
            confidence=50,
            severity="medium",
            summary="Test with special chars",
            indicators=[],
            mitre_techniques=[],
            recommended_actions=[],
            reasoning="Test <script>alert('xss')</script> & \"quotes\" 'apostrophes'",
            evidence=[],
            investigation_steps=[],
        )

        generator = InvestigationReportGenerator()
        report = generator.generate(sample_incident_data, analysis)

        # HTML export should escape special characters
        formatter = HtmlFormatter()
        html = formatter.format(report)

        assert "<script>" not in html  # Should be escaped

    def test_unicode_content(self, sample_incident_data):
        """Test handling of unicode content."""
        analysis = TriageAnalysis(
            verdict="suspicious",
            confidence=50,
            severity="medium",
            summary="Test with unicode: 日本語 emoji: 🔒 symbols: ™®©",
            indicators=[],
            mitre_techniques=[],
            recommended_actions=[],
            reasoning="Unicode reasoning: αβγδ 🔒",
            evidence=[],
            investigation_steps=[],
        )

        generator = InvestigationReportGenerator()
        report = generator.generate(sample_incident_data, analysis)

        # The reasoning field is stored directly in the report
        assert "αβγδ" in report.reasoning
        json_output = report.to_json()
        # Verify unicode content survives JSON serialization (literal or escaped)
        assert "αβγδ" in json_output or "\\u03b1" in json_output

    def test_very_long_content(self, sample_incident_data):
        """Test handling of very long content."""
        long_text = "A" * 10000  # 10KB of text

        analysis = TriageAnalysis(
            verdict="true_positive",
            confidence=90,
            severity="high",
            summary=long_text,
            indicators=[],
            mitre_techniques=[],
            recommended_actions=[],
            reasoning=long_text,
            evidence=[],
            investigation_steps=[],
        )

        generator = InvestigationReportGenerator()
        report = generator.generate(sample_incident_data, analysis)

        # Should handle without error
        assert len(report.reasoning) == 10000
        json_output = report.to_json()
        # The reasoning (10000 chars) plus report structure produces > 10000 chars of JSON
        assert len(json_output) > 10000


# =============================================================================
# ReportFormat Enum Tests
# =============================================================================


class TestReportFormat:
    """Tests for ReportFormat enum."""

    def test_enum_values(self):
        """Test ReportFormat enum values."""
        assert ReportFormat.JSON.value == "json"
        assert ReportFormat.HTML.value == "html"
        assert ReportFormat.PDF.value == "pdf"

    def test_enum_comparison(self):
        """Test ReportFormat enum comparison."""
        assert ReportFormat.JSON == ReportFormat.JSON
        assert ReportFormat.JSON != ReportFormat.HTML


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
