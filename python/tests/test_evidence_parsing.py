"""
Tests for evidence parsing functionality (Stage 2.1.2).

This module tests:
- EvidenceItem and InvestigationStep model validation
- Evidence parsing from JSON responses
- Legacy [EVIDENCE] tag parsing
- Evidence quality validation
- Integration with output_parser
"""

import pytest
from pydantic import ValidationError

from tw_ai.agents.models import (
    EvidenceItem,
    InvestigationStep,
    TriageAnalysis,
)
from tw_ai.agents.evidence_parser import (
    parse_evidence_from_dict,
    parse_investigation_steps_from_dict,
    parse_evidence_from_text,
    extract_evidence_from_response,
    validate_evidence_quality,
    _normalize_evidence_fields,
    _normalize_step_fields,
)
from tw_ai.agents.output_parser import (
    parse_triage_analysis,
    parse_triage_analysis_with_evidence_validation,
)


# =============================================================================
# EvidenceItem Model Tests
# =============================================================================


class TestEvidenceItemModel:
    """Tests for EvidenceItem Pydantic model."""

    def test_valid_evidence_item(self):
        """Test creating a valid evidence item."""
        evidence = EvidenceItem(
            source_type="threat_intel",
            source_name="VirusTotal",
            data_type="threat_intel_match",
            value={"malicious_votes": 45, "total_votes": 70},
            finding="Hash flagged as malicious by 45/70 engines",
            relevance="High detection rate confirms malware",
            confidence=95,
        )

        assert evidence.source_type == "threat_intel"
        assert evidence.source_name == "VirusTotal"
        assert evidence.confidence == 95
        assert evidence.link is None

    def test_evidence_with_link(self):
        """Test evidence item with deep link."""
        evidence = EvidenceItem(
            source_type="siem",
            source_name="Splunk",
            data_type="network_activity",
            value={"src_ip": "192.168.1.100", "dst_ip": "10.0.0.1"},
            finding="Suspicious outbound connection",
            relevance="Network traffic to known C2 infrastructure",
            confidence=88,
            link="https://splunk.example.com/search?sid=123",
        )

        assert evidence.link == "https://splunk.example.com/search?sid=123"

    def test_invalid_source_type(self):
        """Test that invalid source_type raises error."""
        with pytest.raises(ValidationError) as exc_info:
            EvidenceItem(
                source_type="invalid_source",
                source_name="Test",
                data_type="network_activity",
                value={"data": "test"},
                finding="Test finding",
                relevance="Test relevance",
                confidence=50,
            )

        assert "source_type" in str(exc_info.value)

    def test_invalid_data_type(self):
        """Test that invalid data_type raises error."""
        with pytest.raises(ValidationError) as exc_info:
            EvidenceItem(
                source_type="threat_intel",
                source_name="Test",
                data_type="invalid_data_type",
                value={"data": "test"},
                finding="Test finding",
                relevance="Test relevance",
                confidence=50,
            )

        assert "data_type" in str(exc_info.value)

    def test_confidence_bounds(self):
        """Test confidence is bounded 0-100."""
        with pytest.raises(ValidationError):
            EvidenceItem(
                source_type="threat_intel",
                source_name="Test",
                data_type="network_activity",
                value={"data": "test"},
                finding="Test",
                relevance="Test",
                confidence=150,
            )

        with pytest.raises(ValidationError):
            EvidenceItem(
                source_type="threat_intel",
                source_name="Test",
                data_type="network_activity",
                value={"data": "test"},
                finding="Test",
                relevance="Test",
                confidence=-10,
            )

    def test_empty_string_fields(self):
        """Test that empty string fields raise error."""
        with pytest.raises(ValidationError):
            EvidenceItem(
                source_type="threat_intel",
                source_name="",  # Empty
                data_type="network_activity",
                value={"data": "test"},
                finding="Test",
                relevance="Test",
                confidence=50,
            )


# =============================================================================
# InvestigationStep Model Tests
# =============================================================================


class TestInvestigationStepModel:
    """Tests for InvestigationStep Pydantic model."""

    def test_valid_step(self):
        """Test creating a valid investigation step."""
        step = InvestigationStep(
            order=1,
            action="Query VirusTotal for file hash",
            result="Hash identified as Emotet trojan",
            tool="lookup_hash",
            status="completed",
        )

        assert step.order == 1
        assert step.status == "completed"
        assert step.tool == "lookup_hash"

    def test_step_without_tool(self):
        """Test step without optional tool field."""
        step = InvestigationStep(
            order=2,
            action="Analyze email headers",
            result="SPF and DKIM failures detected",
            status="completed",
        )

        assert step.tool is None

    def test_step_order_validation(self):
        """Test that order must be >= 1."""
        with pytest.raises(ValidationError):
            InvestigationStep(
                order=0,
                action="Test",
                result="Test",
                status="completed",
            )

    def test_step_status_values(self):
        """Test valid status values."""
        for status in ["completed", "failed", "skipped"]:
            step = InvestigationStep(
                order=1,
                action="Test",
                result="Test",
                status=status,
            )
            assert step.status == status


# =============================================================================
# Evidence Parsing Tests
# =============================================================================


class TestEvidenceParsingFromDict:
    """Tests for parse_evidence_from_dict function."""

    def test_parse_valid_evidence_array(self):
        """Test parsing a valid evidence array."""
        data = {
            "evidence": [
                {
                    "source_type": "threat_intel",
                    "source_name": "VirusTotal",
                    "data_type": "threat_intel_match",
                    "value": {"detection_rate": "95%"},
                    "finding": "Malware detected",
                    "relevance": "Confirms malicious file",
                    "confidence": 95,
                },
                {
                    "source_type": "siem",
                    "source_name": "Splunk",
                    "data_type": "network_activity",
                    "value": {"connections": 5},
                    "finding": "Multiple C2 connections",
                    "relevance": "Active communication with threat actor",
                    "confidence": 88,
                },
            ]
        }

        evidence = parse_evidence_from_dict(data)

        assert len(evidence) == 2
        assert evidence[0].source_name == "VirusTotal"
        assert evidence[1].source_name == "Splunk"

    def test_parse_with_normalization(self):
        """Test parsing with field name normalization."""
        data = {
            "evidence": [
                {
                    "type": "threat_intel",  # Should normalize to source_type
                    "source": "VirusTotal",  # Should normalize to source_name
                    "dataType": "threat_intel_match",  # Should normalize to data_type
                    "data": {"score": 95},  # Should normalize to value
                    "description": "Malware",  # Should normalize to finding
                    "explanation": "Confirms threat",  # Should normalize to relevance
                    "score": 90,  # Should normalize to confidence
                }
            ]
        }

        evidence = parse_evidence_from_dict(data)

        assert len(evidence) == 1
        assert evidence[0].source_type == "threat_intel"
        assert evidence[0].source_name == "VirusTotal"
        assert evidence[0].data_type == "threat_intel_match"
        assert evidence[0].confidence == 90

    def test_skip_invalid_items(self):
        """Test that invalid items are skipped with logging."""
        data = {
            "evidence": [
                {
                    "source_type": "threat_intel",
                    "source_name": "VirusTotal",
                    "data_type": "threat_intel_match",
                    "value": {"data": "valid"},
                    "finding": "Valid finding",
                    "relevance": "Valid relevance",
                    "confidence": 90,
                },
                {
                    # Missing required fields
                    "source_type": "siem",
                },
                "not a dict",  # Invalid type
            ]
        }

        evidence = parse_evidence_from_dict(data)

        # Only the first valid item should be parsed
        assert len(evidence) == 1
        assert evidence[0].source_name == "VirusTotal"

    def test_empty_evidence_array(self):
        """Test parsing empty evidence array."""
        data = {"evidence": []}
        evidence = parse_evidence_from_dict(data)
        assert len(evidence) == 0

    def test_no_evidence_key(self):
        """Test parsing when evidence key is missing."""
        data = {"verdict": "true_positive"}
        evidence = parse_evidence_from_dict(data)
        assert len(evidence) == 0


class TestInvestigationStepsParsing:
    """Tests for parse_investigation_steps_from_dict function."""

    def test_parse_valid_steps(self):
        """Test parsing valid investigation steps."""
        data = {
            "investigation_steps": [
                {
                    "order": 1,
                    "action": "Extract indicators",
                    "result": "Found 3 IPs and 2 domains",
                    "status": "completed",
                },
                {
                    "order": 2,
                    "action": "Query threat intel",
                    "result": "2 IPs flagged as malicious",
                    "tool": "lookup_ip",
                    "status": "completed",
                },
            ]
        }

        steps = parse_investigation_steps_from_dict(data)

        assert len(steps) == 2
        assert steps[0].order == 1
        assert steps[1].tool == "lookup_ip"

    def test_normalize_step_fields(self):
        """Test step field normalization."""
        item = {
            "step": 3,  # Should normalize to order
            "description": "Analyze data",  # Should normalize to action
            "output": "Data analyzed",  # Should normalize to result
            "tool_used": "analyzer",  # Should normalize to tool
            "state": "done",  # Should normalize to status = completed
        }

        normalized = _normalize_step_fields(item, order=1)

        assert normalized["order"] == 3
        assert normalized["action"] == "Analyze data"
        assert normalized["result"] == "Data analyzed"
        assert normalized["tool"] == "analyzer"
        assert normalized["status"] == "completed"

    def test_default_order_and_status(self):
        """Test that order and status get defaults."""
        item = {
            "action": "Test action",
            "result": "Test result",
        }

        normalized = _normalize_step_fields(item, order=5)

        assert normalized["order"] == 5
        assert normalized["status"] == "completed"


# =============================================================================
# Legacy Evidence Tag Parsing Tests
# =============================================================================


class TestEvidenceTagParsing:
    """Tests for parse_evidence_from_text function."""

    def test_parse_single_evidence_tag(self):
        """Test parsing a single [EVIDENCE] tag."""
        text = """
        Based on my analysis:
        [EVIDENCE] Source: VirusTotal | Type: hash | Finding: File is malicious | Confidence: 95

        This is clearly a threat.
        """

        evidence = parse_evidence_from_text(text)

        assert len(evidence) == 1
        assert evidence[0].source_name == "VirusTotal"
        assert evidence[0].confidence == 95

    def test_parse_multiple_evidence_tags(self):
        """Test parsing multiple [EVIDENCE] tags."""
        text = """
        Analysis findings:
        [EVIDENCE] Source: Splunk | Type: network | Finding: C2 connection detected | Confidence: 88
        [EVIDENCE] Source: CrowdStrike | Type: process | Finding: Malicious process | Confidence: 92
        [EVIDENCE] Source: Email Gateway | Type: email | Finding: SPF failure | Confidence: 75
        """

        evidence = parse_evidence_from_text(text)

        assert len(evidence) == 3
        assert evidence[0].source_name == "Splunk"
        assert evidence[1].source_name == "CrowdStrike"
        assert evidence[2].source_name == "Email Gateway"

    def test_no_evidence_tags(self):
        """Test parsing text without evidence tags."""
        text = "This is just normal text without any evidence tags."

        evidence = parse_evidence_from_text(text)

        assert len(evidence) == 0

    def test_malformed_evidence_tag(self):
        """Test that malformed tags are skipped."""
        text = """
        [EVIDENCE] Source: VirusTotal | Missing other fields
        [EVIDENCE] Source: Splunk | Type: network | Finding: Valid | Confidence: 80
        """

        evidence = parse_evidence_from_text(text)

        # Only the valid tag should be parsed
        assert len(evidence) == 1
        assert evidence[0].source_name == "Splunk"


# =============================================================================
# Evidence Quality Validation Tests
# =============================================================================


class TestEvidenceQualityValidation:
    """Tests for validate_evidence_quality function."""

    def test_valid_evidence_quality(self):
        """Test evidence that meets quality requirements."""
        evidence = [
            EvidenceItem(
                source_type="threat_intel",
                source_name="VirusTotal",
                data_type="threat_intel_match",
                value={"data": "test"},
                finding="Test",
                relevance="Test",
                confidence=90,
            ),
            EvidenceItem(
                source_type="siem",
                source_name="Splunk",
                data_type="network_activity",
                value={"data": "test"},
                finding="Test",
                relevance="Test",
                confidence=85,
            ),
            EvidenceItem(
                source_type="edr",
                source_name="CrowdStrike",
                data_type="process_execution",
                value={"data": "test"},
                finding="Test",
                relevance="Test",
                confidence=80,
            ),
        ]

        report = validate_evidence_quality(evidence)

        assert report["valid"] is True
        assert report["evidence_count"] == 3
        assert report["avg_confidence"] == 85.0
        assert report["high_confidence_count"] == 3
        assert len(report["recommendations"]) == 0

    def test_insufficient_evidence_count(self):
        """Test evidence with insufficient count."""
        evidence = [
            EvidenceItem(
                source_type="threat_intel",
                source_name="VirusTotal",
                data_type="threat_intel_match",
                value={"data": "test"},
                finding="Test",
                relevance="Test",
                confidence=90,
            ),
        ]

        report = validate_evidence_quality(evidence, min_items=3)

        assert report["valid"] is False
        assert "Collect at least 3" in report["recommendations"][0]

    def test_low_confidence_evidence(self):
        """Test evidence with low average confidence."""
        evidence = [
            EvidenceItem(
                source_type="threat_intel",
                source_name="Test",
                data_type="threat_intel_match",
                value={"data": "test"},
                finding="Test",
                relevance="Test",
                confidence=30,
            ),
            EvidenceItem(
                source_type="siem",
                source_name="Test",
                data_type="network_activity",
                value={"data": "test"},
                finding="Test",
                relevance="Test",
                confidence=35,
            ),
            EvidenceItem(
                source_type="edr",
                source_name="Test",
                data_type="process_execution",
                value={"data": "test"},
                finding="Test",
                relevance="Test",
                confidence=40,
            ),
        ]

        report = validate_evidence_quality(evidence, min_avg_confidence=50.0)

        assert report["valid"] is False
        assert any("Improve evidence quality" in r for r in report["recommendations"])

    def test_empty_evidence_list(self):
        """Test validation with no evidence."""
        report = validate_evidence_quality([])

        assert report["valid"] is False
        assert report["evidence_count"] == 0
        assert report["reason"] == "No evidence collected"


# =============================================================================
# Integration Tests with Output Parser
# =============================================================================


class TestOutputParserEvidenceIntegration:
    """Tests for evidence parsing integration with output_parser."""

    def test_parse_analysis_with_evidence(self):
        """Test parsing analysis that includes evidence."""
        json_response = """{
            "verdict": "true_positive",
            "confidence": 92,
            "severity": "high",
            "summary": "Confirmed phishing attack with malicious payload",
            "indicators": [
                {"type": "domain", "value": "evil.com", "verdict": "malicious"}
            ],
            "mitre_techniques": [
                {"id": "T1566", "name": "Phishing", "tactic": "Initial Access", "relevance": "Email-based attack"}
            ],
            "recommended_actions": [
                {"action": "Block domain", "priority": "immediate", "reason": "Prevent access"}
            ],
            "reasoning": "Multiple indicators confirm this is a phishing attack.",
            "evidence": [
                {
                    "source_type": "threat_intel",
                    "source_name": "VirusTotal",
                    "data_type": "threat_intel_match",
                    "value": {"detection_rate": "95%"},
                    "finding": "Domain flagged by 45/70 engines",
                    "relevance": "High detection rate confirms malicious domain",
                    "confidence": 95
                },
                {
                    "source_type": "email",
                    "source_name": "Email Gateway",
                    "data_type": "email_content",
                    "value": {"spf": "fail", "dkim": "none"},
                    "finding": "Email authentication failures",
                    "relevance": "Indicates spoofed sender",
                    "confidence": 88
                },
                {
                    "source_type": "siem",
                    "source_name": "Splunk",
                    "data_type": "user_behavior",
                    "value": {"clicked": false, "reported": true},
                    "finding": "User reported without clicking",
                    "relevance": "No credential exposure",
                    "confidence": 100
                }
            ],
            "investigation_steps": [
                {
                    "order": 1,
                    "action": "Analyzed email headers",
                    "result": "Found SPF failure and missing DKIM",
                    "status": "completed"
                },
                {
                    "order": 2,
                    "action": "Queried VirusTotal for sender domain",
                    "result": "Domain flagged as malicious",
                    "tool": "lookup_domain",
                    "status": "completed"
                }
            ]
        }"""

        analysis = parse_triage_analysis(json_response)

        assert analysis.verdict == "true_positive"
        assert analysis.confidence == 92
        assert len(analysis.evidence) == 3
        assert len(analysis.investigation_steps) == 2

        # Check evidence details
        assert analysis.evidence[0].source_name == "VirusTotal"
        assert analysis.evidence[1].source_name == "Email Gateway"
        assert analysis.evidence[2].confidence == 100

        # Check investigation steps
        assert analysis.investigation_steps[0].action == "Analyzed email headers"
        assert analysis.investigation_steps[1].tool == "lookup_domain"

    def test_parse_analysis_without_evidence(self):
        """Test parsing analysis without evidence (backward compatible)."""
        json_response = """{
            "verdict": "false_positive",
            "confidence": 80,
            "severity": "low",
            "summary": "Legitimate email flagged by rule",
            "indicators": [],
            "mitre_techniques": [],
            "recommended_actions": [
                {"action": "Release email", "priority": "high", "reason": "Legitimate"}
            ],
            "reasoning": "This is a legitimate email."
        }"""

        analysis = parse_triage_analysis(json_response)

        assert analysis.verdict == "false_positive"
        assert len(analysis.evidence) == 0
        assert len(analysis.investigation_steps) == 0

    def test_parse_with_legacy_evidence_tags(self):
        """Test parsing that falls back to legacy evidence tags."""
        json_response = """{
            "verdict": "suspicious",
            "confidence": 65,
            "severity": "medium",
            "summary": "Suspicious activity detected",
            "indicators": [],
            "mitre_techniques": [],
            "recommended_actions": [
                {"action": "Investigate", "priority": "high", "reason": "Suspicious"}
            ],
            "reasoning": "Analysis findings: [EVIDENCE] Source: VirusTotal | Type: hash | Finding: File is unknown | Confidence: 60"
        }"""

        analysis = parse_triage_analysis(json_response)

        assert analysis.verdict == "suspicious"
        # Should extract evidence from reasoning
        assert len(analysis.evidence) == 1
        assert analysis.evidence[0].source_name == "VirusTotal"

    def test_parse_with_evidence_validation(self):
        """Test parse_triage_analysis_with_evidence_validation."""
        json_response = """{
            "verdict": "true_positive",
            "confidence": 90,
            "severity": "high",
            "summary": "Confirmed threat",
            "indicators": [],
            "mitre_techniques": [],
            "recommended_actions": [
                {"action": "Contain", "priority": "immediate", "reason": "Active threat"}
            ],
            "reasoning": "Analysis complete.",
            "evidence": [
                {
                    "source_type": "threat_intel",
                    "source_name": "VirusTotal",
                    "data_type": "threat_intel_match",
                    "value": {"data": "test"},
                    "finding": "Malicious",
                    "relevance": "Confirms threat",
                    "confidence": 95
                },
                {
                    "source_type": "edr",
                    "source_name": "CrowdStrike",
                    "data_type": "process_execution",
                    "value": {"data": "test"},
                    "finding": "Suspicious process",
                    "relevance": "Execution chain",
                    "confidence": 88
                },
                {
                    "source_type": "siem",
                    "source_name": "Splunk",
                    "data_type": "network_activity",
                    "value": {"data": "test"},
                    "finding": "C2 traffic",
                    "relevance": "Active communication",
                    "confidence": 85
                }
            ],
            "investigation_steps": []
        }"""

        analysis, report = parse_triage_analysis_with_evidence_validation(json_response)

        assert analysis.verdict == "true_positive"
        assert report["valid"] is True
        assert report["evidence_count"] == 3


# =============================================================================
# TriageAnalysis Evidence Methods Tests
# =============================================================================


class TestTriageAnalysisEvidenceMethods:
    """Tests for evidence-related methods on TriageAnalysis."""

    def test_get_evidence_summary(self):
        """Test get_evidence_summary method."""
        analysis = TriageAnalysis(
            verdict="true_positive",
            confidence=90,
            severity="high",
            summary="Test analysis",
            evidence=[
                EvidenceItem(
                    source_type="threat_intel",
                    source_name="VirusTotal",
                    data_type="threat_intel_match",
                    value={"data": "test"},
                    finding="Test",
                    relevance="Test",
                    confidence=95,
                ),
                EvidenceItem(
                    source_type="siem",
                    source_name="Splunk",
                    data_type="network_activity",
                    value={"data": "test"},
                    finding="Test",
                    relevance="Test",
                    confidence=85,
                ),
                EvidenceItem(
                    source_type="edr",
                    source_name="CrowdStrike",
                    data_type="process_execution",
                    value={"data": "test"},
                    finding="Test",
                    relevance="Test",
                    confidence=45,
                ),
            ],
        )

        summary = analysis.get_evidence_summary()

        assert summary["total_evidence"] == 3
        assert summary["avg_confidence"] == 75.0
        assert summary["high_confidence_count"] == 2
        assert summary["low_confidence_count"] == 1
        assert "VirusTotal" in summary["sources"]
        assert "Splunk" in summary["sources"]

    def test_has_sufficient_evidence_true(self):
        """Test has_sufficient_evidence returns True when met."""
        analysis = TriageAnalysis(
            verdict="true_positive",
            confidence=90,
            severity="high",
            summary="Test",
            evidence=[
                EvidenceItem(
                    source_type="threat_intel",
                    source_name="Test",
                    data_type="threat_intel_match",
                    value={"data": "test"},
                    finding="Test",
                    relevance="Test",
                    confidence=80,
                ),
                EvidenceItem(
                    source_type="siem",
                    source_name="Test",
                    data_type="network_activity",
                    value={"data": "test"},
                    finding="Test",
                    relevance="Test",
                    confidence=70,
                ),
                EvidenceItem(
                    source_type="edr",
                    source_name="Test",
                    data_type="process_execution",
                    value={"data": "test"},
                    finding="Test",
                    relevance="Test",
                    confidence=60,
                ),
            ],
        )

        assert analysis.has_sufficient_evidence(min_items=3, min_avg_confidence=50.0)

    def test_has_sufficient_evidence_false(self):
        """Test has_sufficient_evidence returns False when not met."""
        analysis = TriageAnalysis(
            verdict="suspicious",
            confidence=50,
            severity="medium",
            summary="Test",
            evidence=[
                EvidenceItem(
                    source_type="threat_intel",
                    source_name="Test",
                    data_type="threat_intel_match",
                    value={"data": "test"},
                    finding="Test",
                    relevance="Test",
                    confidence=40,
                ),
            ],
        )

        assert not analysis.has_sufficient_evidence(min_items=3)
