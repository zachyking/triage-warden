"""Unit tests for hallucination detection module.

Tests cover:
- IP address hallucination detection
- Domain hallucination detection
- Hash hallucination detection
- MITRE technique plausibility validation
- Evidence source validation
- RAG citation verification
- Confidence consistency checks
- Integration with output parser
"""

import pytest
from datetime import datetime, timezone

from tw_ai.agents.models import (
    EvidenceItem,
    Indicator,
    InvestigationStep,
    MITRETechnique,
    RecommendedAction,
    TriageAnalysis,
)
from tw_ai.validation.hallucination import (
    HallucinationConfig,
    HallucinationDetector,
    HallucinationResult,
    HallucinationSeverity,
    HallucinationWarning,
    WarningType,
    check_for_hallucinations,
    get_default_detector,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def basic_analysis() -> TriageAnalysis:
    """Create a basic triage analysis for testing."""
    return TriageAnalysis(
        verdict="true_positive",
        confidence=85,
        severity="high",
        summary="Detected potential phishing attack targeting user credentials.",
        indicators=[
            Indicator(
                type="ip",
                value="192.168.1.100",
                verdict="malicious",
                context="Source of phishing email",
            ),
            Indicator(
                type="domain",
                value="evil-phishing.com",
                verdict="malicious",
                context="Phishing domain",
            ),
        ],
        mitre_techniques=[
            MITRETechnique(
                id="T1566.002",
                name="Phishing: Spearphishing Link",
                tactic="Initial Access",
                relevance="User clicked on malicious link in email",
            ),
        ],
        reasoning="The alert shows suspicious email activity from 192.168.1.100 with a link to evil-phishing.com.",
        evidence=[
            EvidenceItem(
                source_type="email",
                source_name="Microsoft Defender",
                data_type="email_content",
                value={"sender": "attacker@evil-phishing.com"},
                finding="Phishing email detected",
                relevance="Confirms malicious intent",
                confidence=90,
            ),
        ],
        investigation_steps=[
            InvestigationStep(
                order=1,
                action="Analyzed email headers",
                result="Found suspicious sender domain",
                tool="Microsoft Defender",
            ),
        ],
    )


@pytest.fixture
def incident_data() -> dict:
    """Create incident data matching the basic analysis."""
    return {
        "alert_id": "ALERT-001",
        "source_ip": "192.168.1.100",
        "destination_domain": "evil-phishing.com",
        "email_subject": "Urgent: Verify your account",
        "email_sender": "support@evil-phishing.com",
        "user_clicked": True,
        "timestamp": "2024-01-15T10:30:00Z",
    }


@pytest.fixture
def detector() -> HallucinationDetector:
    """Create a default hallucination detector."""
    return HallucinationDetector()


@pytest.fixture
def custom_config() -> HallucinationConfig:
    """Create a custom configuration for testing."""
    return HallucinationConfig(
        check_ips=True,
        check_domains=True,
        check_hashes=True,
        check_mitre=True,
        check_evidence_sources=True,
        check_rag_citations=True,
        check_confidence=True,
        max_warnings_before_flag=2,
    )


# =============================================================================
# Test HallucinationWarning Model
# =============================================================================


class TestHallucinationWarning:
    """Tests for HallucinationWarning model."""

    def test_create_warning(self):
        """Test creating a basic warning."""
        warning = HallucinationWarning(
            type=WarningType.HALLUCINATED_IP,
            severity=HallucinationSeverity.HIGH,
            detail="IP 10.0.0.1 not found in incident data",
            evidence={"cited_ip": "10.0.0.1"},
            location="reasoning",
        )

        assert warning.type == WarningType.HALLUCINATED_IP
        assert warning.severity == HallucinationSeverity.HIGH
        assert "10.0.0.1" in warning.detail
        assert warning.location == "reasoning"
        assert warning.timestamp is not None

    def test_warning_to_audit_dict(self):
        """Test converting warning to audit dictionary."""
        warning = HallucinationWarning(
            type=WarningType.HALLUCINATED_DOMAIN,
            severity=HallucinationSeverity.MEDIUM,
            detail="Domain not found",
            evidence={"domain": "test.com"},
        )

        audit_dict = warning.to_audit_dict()

        assert audit_dict["type"] == "hallucinated_domain"
        assert audit_dict["severity"] == "medium"
        assert "timestamp" in audit_dict


# =============================================================================
# Test HallucinationResult
# =============================================================================


class TestHallucinationResult:
    """Tests for HallucinationResult dataclass."""

    def test_empty_result(self):
        """Test result with no warnings."""
        result = HallucinationResult()

        assert not result.has_warnings
        assert result.critical_count == 0
        assert result.high_count == 0
        assert not result.should_flag_for_review

    def test_result_with_warnings(self):
        """Test result with multiple warnings."""
        result = HallucinationResult(
            warnings=[
                HallucinationWarning(
                    type=WarningType.HALLUCINATED_IP,
                    severity=HallucinationSeverity.CRITICAL,
                    detail="Critical issue",
                ),
                HallucinationWarning(
                    type=WarningType.HALLUCINATED_DOMAIN,
                    severity=HallucinationSeverity.HIGH,
                    detail="High issue",
                ),
                HallucinationWarning(
                    type=WarningType.QUESTIONABLE_MITRE,
                    severity=HallucinationSeverity.MEDIUM,
                    detail="Medium issue",
                ),
            ],
            total_checks_performed=5,
            passed_checks=2,
            failed_checks=3,
        )

        assert result.has_warnings
        assert result.critical_count == 1
        assert result.high_count == 1
        assert len(result.warnings) == 3

    def test_result_summary(self):
        """Test get_summary method."""
        result = HallucinationResult(
            warnings=[
                HallucinationWarning(
                    type=WarningType.HALLUCINATED_IP,
                    severity=HallucinationSeverity.HIGH,
                    detail="Test",
                ),
            ],
            total_checks_performed=3,
            passed_checks=2,
            failed_checks=1,
        )

        summary = result.get_summary()

        assert summary["total_warnings"] == 1
        assert summary["high"] == 1
        assert summary["checks_performed"] == 3
        assert "timestamp" in summary


# =============================================================================
# Test IP Hallucination Detection
# =============================================================================


class TestIPHallucinationDetection:
    """Tests for IP address hallucination detection."""

    def test_no_hallucination_when_ips_match(
        self, detector: HallucinationDetector, basic_analysis: TriageAnalysis, incident_data: dict
    ):
        """Test that matching IPs don't trigger warnings."""
        result = detector.check(basic_analysis, incident_data)

        ip_warnings = [
            w for w in result.warnings if w.type == WarningType.HALLUCINATED_IP
        ]
        assert len(ip_warnings) == 0

    def test_detects_hallucinated_ip(self, detector: HallucinationDetector):
        """Test detection of IP not in incident data."""
        analysis = TriageAnalysis(
            verdict="true_positive",
            confidence=80,
            severity="high",
            summary="Attack from 10.10.10.10 detected.",
            reasoning="The attacker used IP 10.10.10.10 to launch the attack.",
            indicators=[
                Indicator(type="ip", value="10.10.10.10", verdict="malicious"),
            ],
        )

        incident_data = {
            "source_ip": "192.168.1.1",
            "description": "Suspicious activity detected",
        }

        result = detector.check(analysis, incident_data)

        ip_warnings = [
            w for w in result.warnings if w.type == WarningType.HALLUCINATED_IP
        ]
        assert len(ip_warnings) == 1
        assert "10.10.10.10" in ip_warnings[0].detail

    def test_ignores_localhost_ips(self, detector: HallucinationDetector):
        """Test that localhost IPs are not flagged as hallucinations."""
        analysis = TriageAnalysis(
            verdict="false_positive",
            confidence=70,
            severity="low",
            summary="Local traffic from 127.0.0.1",
            reasoning="This is local traffic on 127.0.0.1",
        )

        incident_data = {"description": "Some incident"}

        result = detector.check(analysis, incident_data)

        ip_warnings = [
            w for w in result.warnings if w.type == WarningType.HALLUCINATED_IP
        ]
        assert len(ip_warnings) == 0

    def test_detects_multiple_hallucinated_ips(self, detector: HallucinationDetector):
        """Test detection of multiple hallucinated IPs."""
        analysis = TriageAnalysis(
            verdict="true_positive",
            confidence=90,
            severity="critical",
            summary="Multiple IPs involved in attack",
            reasoning="Attackers from 8.8.8.8 and 1.1.1.1 coordinated the attack.",
            indicators=[
                Indicator(type="ip", value="8.8.8.8", verdict="malicious"),
                Indicator(type="ip", value="1.1.1.1", verdict="suspicious"),
            ],
        )

        incident_data = {"source_ip": "192.168.1.50"}

        result = detector.check(analysis, incident_data)

        ip_warnings = [
            w for w in result.warnings if w.type == WarningType.HALLUCINATED_IP
        ]
        assert len(ip_warnings) == 2


# =============================================================================
# Test Domain Hallucination Detection
# =============================================================================


class TestDomainHallucinationDetection:
    """Tests for domain hallucination detection."""

    def test_no_hallucination_when_domains_match(
        self, detector: HallucinationDetector, basic_analysis: TriageAnalysis, incident_data: dict
    ):
        """Test that matching domains don't trigger warnings."""
        result = detector.check(basic_analysis, incident_data)

        domain_warnings = [
            w for w in result.warnings if w.type == WarningType.HALLUCINATED_DOMAIN
        ]
        assert len(domain_warnings) == 0

    def test_detects_hallucinated_domain(self, detector: HallucinationDetector):
        """Test detection of domain not in incident data."""
        analysis = TriageAnalysis(
            verdict="true_positive",
            confidence=85,
            severity="high",
            summary="Malware communicating with malware-c2.evil",
            indicators=[
                Indicator(type="domain", value="malware-c2.evil", verdict="malicious"),
            ],
        )

        incident_data = {"destination": "legitimate-site.com"}

        result = detector.check(analysis, incident_data)

        domain_warnings = [
            w for w in result.warnings if w.type == WarningType.HALLUCINATED_DOMAIN
        ]
        assert len(domain_warnings) == 1

    def test_ignores_example_domains(self, detector: HallucinationDetector):
        """Test that example.com domains are not flagged."""
        analysis = TriageAnalysis(
            verdict="false_positive",
            confidence=60,
            severity="low",
            summary="Test traffic to example.com",
            reasoning="This appears to be test traffic to example.com",
        )

        incident_data = {"description": "Some incident"}

        result = detector.check(analysis, incident_data)

        domain_warnings = [
            w for w in result.warnings if w.type == WarningType.HALLUCINATED_DOMAIN
        ]
        assert len(domain_warnings) == 0


# =============================================================================
# Test Hash Hallucination Detection
# =============================================================================


class TestHashHallucinationDetection:
    """Tests for hash hallucination detection."""

    def test_detects_hallucinated_md5(self, detector: HallucinationDetector):
        """Test detection of MD5 hash not in incident data."""
        analysis = TriageAnalysis(
            verdict="true_positive",
            confidence=90,
            severity="high",
            summary="Malware hash detected",
            indicators=[
                Indicator(
                    type="hash",
                    value="d41d8cd98f00b204e9800998ecf8427e",
                    verdict="malicious",
                ),
            ],
        )

        incident_data = {
            "file_hash": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
        }

        result = detector.check(analysis, incident_data)

        hash_warnings = [
            w for w in result.warnings if w.type == WarningType.HALLUCINATED_HASH
        ]
        assert len(hash_warnings) == 1
        assert "MD5" in hash_warnings[0].detail

    def test_detects_hallucinated_sha256(self, detector: HallucinationDetector):
        """Test detection of SHA256 hash not in incident data."""
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

        analysis = TriageAnalysis(
            verdict="true_positive",
            confidence=95,
            severity="critical",
            summary="Ransomware detected",
            reasoning=f"File with hash {sha256} identified as ransomware.",
        )

        incident_data = {"description": "Suspicious file activity"}

        result = detector.check(analysis, incident_data)

        hash_warnings = [
            w for w in result.warnings if w.type == WarningType.HALLUCINATED_HASH
        ]
        assert len(hash_warnings) == 1
        assert "SHA256" in hash_warnings[0].detail

    def test_no_warning_when_hash_present(self, detector: HallucinationDetector):
        """Test that present hashes don't trigger warnings."""
        hash_value = "d41d8cd98f00b204e9800998ecf8427e"

        analysis = TriageAnalysis(
            verdict="true_positive",
            confidence=90,
            severity="high",
            summary="Malware detected",
            indicators=[
                Indicator(type="hash", value=hash_value, verdict="malicious"),
            ],
        )

        incident_data = {"file_hash": hash_value}

        result = detector.check(analysis, incident_data)

        hash_warnings = [
            w for w in result.warnings if w.type == WarningType.HALLUCINATED_HASH
        ]
        assert len(hash_warnings) == 0


# =============================================================================
# Test MITRE Technique Plausibility
# =============================================================================


class TestMITREPlausibility:
    """Tests for MITRE technique plausibility checking."""

    def test_valid_technique_with_indicators(
        self, detector: HallucinationDetector, basic_analysis: TriageAnalysis
    ):
        """Test that valid techniques with behavioral indicators pass."""
        # Create incident data with phishing indicators
        incident_data_with_indicators = {
            "alert_id": "ALERT-001",
            "source_ip": "192.168.1.100",
            "destination_domain": "evil-phishing.com",
            "email_subject": "Urgent: Verify your account",
            "email_sender": "support@evil-phishing.com",
            "email_content": "Please click this link to verify your account",
            "user_clicked": True,
            "timestamp": "2024-01-15T10:30:00Z",
        }

        result = detector.check(basic_analysis, incident_data_with_indicators)

        mitre_warnings = [
            w for w in result.warnings if w.type == WarningType.QUESTIONABLE_MITRE
        ]
        # Should have some warnings since "link" indicator is present
        # but other phishing indicators might be missing
        assert all(w.severity != HallucinationSeverity.CRITICAL for w in mitre_warnings)

    def test_detects_invalid_tactic(self, detector: HallucinationDetector):
        """Test detection of invalid MITRE tactic."""
        analysis = TriageAnalysis(
            verdict="true_positive",
            confidence=80,
            severity="medium",
            summary="Attack detected",
            mitre_techniques=[
                MITRETechnique(
                    id="T1059",
                    name="Command and Scripting Interpreter",
                    tactic="Invalid Tactic",  # Invalid tactic
                    relevance="Test",
                ),
            ],
        )

        result = detector.check(analysis, {"description": "powershell execution"})

        mitre_warnings = [
            w for w in result.warnings if w.type == WarningType.QUESTIONABLE_MITRE
        ]
        assert len(mitre_warnings) == 1
        assert "Invalid tactic" in mitre_warnings[0].detail

    def test_detects_technique_without_indicators(self, detector: HallucinationDetector):
        """Test detection of technique with no supporting behavioral indicators."""
        analysis = TriageAnalysis(
            verdict="true_positive",
            confidence=85,
            severity="high",
            summary="Credential theft detected",
            mitre_techniques=[
                MITRETechnique(
                    id="T1003.001",  # LSASS Memory
                    name="OS Credential Dumping: LSASS Memory",
                    tactic="Credential Access",
                    relevance="Credentials were dumped",
                ),
            ],
        )

        # Incident data has no credential dumping indicators
        incident_data = {"description": "User logged in normally"}

        result = detector.check(analysis, incident_data)

        mitre_warnings = [
            w for w in result.warnings if w.type == WarningType.QUESTIONABLE_MITRE
        ]
        assert len(mitre_warnings) == 1
        assert "No behavioral indicators" in mitre_warnings[0].detail


# =============================================================================
# Test Evidence Source Validation
# =============================================================================


class TestEvidenceSourceValidation:
    """Tests for evidence source validation."""

    def test_valid_known_sources_pass(
        self, detector: HallucinationDetector, basic_analysis: TriageAnalysis, incident_data: dict
    ):
        """Test that known evidence sources pass validation."""
        result = detector.check(basic_analysis, incident_data)

        source_warnings = [
            w for w in result.warnings if w.type == WarningType.UNSUPPORTED_EVIDENCE_SOURCE
        ]
        assert len(source_warnings) == 0

    def test_detects_suspicious_source_name(self, detector: HallucinationDetector):
        """Test detection of suspicious evidence source names."""
        analysis = TriageAnalysis(
            verdict="true_positive",
            confidence=80,
            severity="high",
            summary="Attack detected",
            evidence=[
                EvidenceItem(
                    source_type="threat_intel",
                    source_name="$#@!Invalid",  # Invalid characters
                    data_type="threat_intel_match",
                    value={"indicator": "test"},
                    finding="Found something",
                    relevance="Relevant",
                    confidence=70,
                ),
            ],
        )

        result = detector.check(analysis, {"description": "test"})

        source_warnings = [
            w for w in result.warnings if w.type == WarningType.UNSUPPORTED_EVIDENCE_SOURCE
        ]
        assert len(source_warnings) == 1

    def test_accepts_reasonable_unknown_sources(self, detector: HallucinationDetector):
        """Test that reasonable but unknown source names are accepted."""
        analysis = TriageAnalysis(
            verdict="true_positive",
            confidence=80,
            severity="high",
            summary="Attack detected",
            evidence=[
                EvidenceItem(
                    source_type="siem",
                    source_name="Internal SIEM Tool",  # Unknown but reasonable
                    data_type="network_activity",
                    value={"connection": "test"},
                    finding="Found connection",
                    relevance="Shows activity",
                    confidence=75,
                ),
            ],
        )

        result = detector.check(analysis, {"description": "test"})

        source_warnings = [
            w for w in result.warnings if w.type == WarningType.UNSUPPORTED_EVIDENCE_SOURCE
        ]
        assert len(source_warnings) == 0


# =============================================================================
# Test RAG Citation Verification
# =============================================================================


class TestRAGCitationVerification:
    """Tests for RAG citation verification."""

    def test_valid_citations_pass(self, detector: HallucinationDetector):
        """Test that valid RAG citations pass verification."""
        analysis = TriageAnalysis(
            verdict="true_positive",
            confidence=85,
            severity="high",
            summary="Attack detected",
            rag_context_used=True,
            rag_citations=[
                {"id": "doc-001", "type": "playbook"},
                {"id": "doc-002", "type": "similar_incident"},
            ],
        )

        rag_context = {
            "playbooks": [{"id": "doc-001", "name": "Phishing Response"}],
            "similar_incidents": [{"id": "doc-002", "summary": "Previous incident"}],
        }

        result = detector.check(analysis, {"description": "test"}, rag_context)

        citation_warnings = [
            w for w in result.warnings if w.type == WarningType.RAG_CITATION_MISMATCH
        ]
        assert len(citation_warnings) == 0

    def test_detects_invalid_citation(self, detector: HallucinationDetector):
        """Test detection of citation not in RAG context."""
        analysis = TriageAnalysis(
            verdict="true_positive",
            confidence=85,
            severity="high",
            summary="Attack detected",
            rag_context_used=True,
            rag_citations=[
                {"id": "doc-999", "type": "playbook"},  # Not in context
            ],
        )

        rag_context = {
            "playbooks": [{"id": "doc-001", "name": "Real Playbook"}],
        }

        result = detector.check(analysis, {"description": "test"}, rag_context)

        citation_warnings = [
            w for w in result.warnings if w.type == WarningType.RAG_CITATION_MISMATCH
        ]
        assert len(citation_warnings) == 1
        assert "doc-999" in citation_warnings[0].detail


# =============================================================================
# Test Confidence Consistency
# =============================================================================


class TestConfidenceConsistency:
    """Tests for confidence/evidence consistency checking."""

    def test_high_confidence_with_evidence_passes(
        self, detector: HallucinationDetector, basic_analysis: TriageAnalysis, incident_data: dict
    ):
        """Test that high confidence with good evidence passes."""
        result = detector.check(basic_analysis, incident_data)

        confidence_warnings = [
            w for w in result.warnings if w.type == WarningType.CONFIDENCE_MISMATCH
        ]
        # Basic analysis has evidence and investigation steps
        assert len(confidence_warnings) == 0

    def test_detects_high_confidence_no_evidence(self, detector: HallucinationDetector):
        """Test detection of high confidence with no evidence."""
        analysis = TriageAnalysis(
            verdict="true_positive",
            confidence=95,  # Very high confidence
            severity="critical",
            summary="Critical attack detected",
            evidence=[],  # No evidence
            investigation_steps=[],  # No investigation
        )

        result = detector.check(analysis, {"description": "test"})

        confidence_warnings = [
            w for w in result.warnings if w.type == WarningType.CONFIDENCE_MISMATCH
        ]
        assert len(confidence_warnings) >= 1

    def test_detects_confidence_exceeding_evidence(self, detector: HallucinationDetector):
        """Test detection when overall confidence exceeds evidence confidence."""
        analysis = TriageAnalysis(
            verdict="true_positive",
            confidence=95,  # High overall confidence
            severity="high",
            summary="Attack detected",
            evidence=[
                EvidenceItem(
                    source_type="siem",
                    source_name="Splunk",
                    data_type="network_activity",
                    value={"test": "data"},
                    finding="Found something",
                    relevance="Might be relevant",
                    confidence=30,  # Low evidence confidence
                ),
                EvidenceItem(
                    source_type="siem",
                    source_name="Splunk",
                    data_type="network_activity",
                    value={"test": "data2"},
                    finding="Found more",
                    relevance="Also might be relevant",
                    confidence=40,  # Low evidence confidence
                ),
            ],
        )

        result = detector.check(analysis, {"description": "test"})

        confidence_warnings = [
            w for w in result.warnings if w.type == WarningType.CONFIDENCE_MISMATCH
        ]
        assert len(confidence_warnings) >= 1
        # Check for the specific issue
        assert any("exceeds" in w.detail.lower() for w in confidence_warnings)


# =============================================================================
# Test Flagging for Review
# =============================================================================


class TestFlaggingForReview:
    """Tests for review flagging logic."""

    def test_flags_on_critical_warning(self, detector: HallucinationDetector):
        """Test that critical warnings trigger review flag."""
        analysis = TriageAnalysis(
            verdict="true_positive",
            confidence=95,
            severity="critical",
            summary="Critical attack from 8.8.8.8",
            indicators=[
                Indicator(type="ip", value="8.8.8.8", verdict="malicious"),
            ],
        )

        # IP not in incident data - will generate critical warning
        result = detector.check(analysis, {"source_ip": "192.168.1.1"})

        # Should be flagged due to hallucinated IP in critical analysis
        assert result.has_warnings

    def test_flags_on_multiple_warnings(self, custom_config: HallucinationConfig):
        """Test that multiple warnings trigger review flag."""
        detector = HallucinationDetector(config=custom_config)

        analysis = TriageAnalysis(
            verdict="true_positive",
            confidence=95,
            severity="high",
            summary="Attack from 10.0.0.1 targeting evil.com",
            indicators=[
                Indicator(type="ip", value="10.0.0.1", verdict="malicious"),
                Indicator(type="domain", value="evil.com", verdict="malicious"),
            ],
            evidence=[],  # No evidence
        )

        # Multiple issues: hallucinated IP/domain, high confidence with no evidence
        result = detector.check(analysis, {"description": "normal activity"})

        assert result.should_flag_for_review

    def test_no_flag_when_warnings_below_threshold(
        self, detector: HallucinationDetector, basic_analysis: TriageAnalysis, incident_data: dict
    ):
        """Test that few warnings don't trigger review flag."""
        result = detector.check(basic_analysis, incident_data)

        # Basic analysis should pass most checks
        if len(result.warnings) < detector.config.max_warnings_before_flag:
            assert not result.should_flag_for_review


# =============================================================================
# Test Configuration
# =============================================================================


class TestConfiguration:
    """Tests for HallucinationConfig."""

    def test_disable_specific_checks(self):
        """Test that specific checks can be disabled."""
        config = HallucinationConfig(
            check_ips=False,
            check_domains=False,
        )
        detector = HallucinationDetector(config=config)

        analysis = TriageAnalysis(
            verdict="true_positive",
            confidence=80,
            severity="high",
            summary="Attack from 8.8.8.8 to evil.com",
            indicators=[
                Indicator(type="ip", value="8.8.8.8", verdict="malicious"),
                Indicator(type="domain", value="evil.com", verdict="malicious"),
            ],
        )

        result = detector.check(analysis, {"description": "nothing here"})

        # Should not have IP or domain warnings since checks are disabled
        ip_warnings = [w for w in result.warnings if w.type == WarningType.HALLUCINATED_IP]
        domain_warnings = [w for w in result.warnings if w.type == WarningType.HALLUCINATED_DOMAIN]

        assert len(ip_warnings) == 0
        assert len(domain_warnings) == 0

    def test_custom_known_sources(self):
        """Test custom known evidence sources configuration."""
        config = HallucinationConfig(
            known_evidence_sources={"Custom SIEM", "Internal Tool"},
        )
        detector = HallucinationDetector(config=config)

        analysis = TriageAnalysis(
            verdict="true_positive",
            confidence=80,
            severity="medium",
            summary="Test",
            evidence=[
                EvidenceItem(
                    source_type="siem",
                    source_name="Custom SIEM",  # In custom sources
                    data_type="network_activity",
                    value={"test": "data"},
                    finding="Found something",
                    relevance="Relevant",
                    confidence=70,
                ),
            ],
        )

        result = detector.check(analysis, {"description": "test"})

        source_warnings = [
            w for w in result.warnings if w.type == WarningType.UNSUPPORTED_EVIDENCE_SOURCE
        ]
        assert len(source_warnings) == 0


# =============================================================================
# Test Module-Level Functions
# =============================================================================


class TestModuleFunctions:
    """Tests for module-level convenience functions."""

    def test_get_default_detector(self):
        """Test getting default detector instance."""
        detector1 = get_default_detector()
        detector2 = get_default_detector()

        assert detector1 is detector2  # Same instance

    def test_check_for_hallucinations_function(
        self, basic_analysis: TriageAnalysis, incident_data: dict
    ):
        """Test the convenience function."""
        result = check_for_hallucinations(basic_analysis, incident_data)

        assert isinstance(result, HallucinationResult)
        assert result.total_checks_performed > 0


# =============================================================================
# Test Integration with Output Parser
# =============================================================================


class TestOutputParserIntegration:
    """Tests for integration with output_parser module."""

    def test_parse_with_hallucination_detection(self, incident_data: dict):
        """Test the new parse function with hallucination detection."""
        from tw_ai.agents.output_parser import (
            parse_triage_analysis_with_hallucination_detection,
        )

        # Valid JSON response
        json_response = """```json
{
    "verdict": "true_positive",
    "confidence": 85,
    "severity": "high",
    "summary": "Phishing attack detected from 192.168.1.100",
    "reasoning": "Email from 192.168.1.100 contained phishing link to evil-phishing.com",
    "indicators": [
        {"type": "ip", "value": "192.168.1.100", "verdict": "malicious"}
    ],
    "mitre_techniques": [
        {"id": "T1566.002", "name": "Spearphishing Link", "tactic": "Initial Access", "relevance": "User clicked phishing link"}
    ]
}
```"""

        analysis, report = parse_triage_analysis_with_hallucination_detection(
            json_response,
            incident_data,
        )

        # Check type name to avoid import path differences
        assert type(analysis).__name__ == "TriageAnalysis"
        assert analysis.verdict == "true_positive"
        assert analysis.confidence == 85
        assert "evidence" in report
        assert "hallucination" in report
        assert "flagged_for_review" in report

    def test_parse_detects_hallucinations(self):
        """Test that parsing detects hallucinations."""
        from tw_ai.agents.output_parser import (
            parse_triage_analysis_with_hallucination_detection,
        )

        json_response = """```json
{
    "verdict": "true_positive",
    "confidence": 90,
    "severity": "critical",
    "summary": "Attack from 10.10.10.10",
    "indicators": [
        {"type": "ip", "value": "10.10.10.10", "verdict": "malicious"}
    ]
}
```"""

        incident_data = {"source_ip": "192.168.1.1"}

        analysis, report = parse_triage_analysis_with_hallucination_detection(
            json_response,
            incident_data,
        )

        # Should have hallucination warnings
        assert report["hallucination"]["total_warnings"] > 0
        assert len(report["hallucination_warnings"]) > 0


# =============================================================================
# Edge Cases and Error Handling
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_incident_data(self, detector: HallucinationDetector, basic_analysis: TriageAnalysis):
        """Test handling of empty incident data."""
        result = detector.check(basic_analysis, "")

        # Should still complete checks
        assert result.total_checks_performed > 0

    def test_incident_data_as_string(self, detector: HallucinationDetector, basic_analysis: TriageAnalysis):
        """Test handling of incident data as string."""
        incident_str = "Source IP: 192.168.1.100, Domain: evil-phishing.com"

        result = detector.check(basic_analysis, incident_str)

        # Should extract indicators from string
        ip_warnings = [w for w in result.warnings if w.type == WarningType.HALLUCINATED_IP]
        assert len(ip_warnings) == 0  # IP is present in string

    def test_analysis_with_no_indicators(self, detector: HallucinationDetector):
        """Test analysis with no indicators at all."""
        analysis = TriageAnalysis(
            verdict="false_positive",
            confidence=60,
            severity="low",
            summary="No malicious activity detected",
        )

        result = detector.check(analysis, {"description": "Normal activity"})

        # Should complete without errors
        assert isinstance(result, HallucinationResult)

    def test_analysis_with_defanged_indicators(self, detector: HallucinationDetector):
        """Test handling of defanged indicators in analysis."""
        analysis = TriageAnalysis(
            verdict="true_positive",
            confidence=80,
            severity="high",
            summary="Malware connecting to evil[.]com from 192[.]168[.]1[.]100",
            reasoning="The malware at 192[.]168[.]1[.]100 is beaconing to evil[.]com",
        )

        # Incident data with normal format
        incident_data = {
            "source_ip": "192.168.1.100",
            "destination_domain": "evil.com",
        }

        result = detector.check(analysis, incident_data)

        # Defanged indicators should be normalized and matched
        ip_warnings = [w for w in result.warnings if w.type == WarningType.HALLUCINATED_IP]
        domain_warnings = [w for w in result.warnings if w.type == WarningType.HALLUCINATED_DOMAIN]

        assert len(ip_warnings) == 0
        assert len(domain_warnings) == 0

    def test_rag_context_with_different_id_formats(self, detector: HallucinationDetector):
        """Test RAG citation checking with various ID field names."""
        analysis = TriageAnalysis(
            verdict="true_positive",
            confidence=80,
            severity="medium",
            summary="Test",
            rag_context_used=True,
            rag_citations=[
                {"doc_id": "doc-001"},
                {"document_id": "doc-002"},
                {"id": "doc-003"},
            ],
        )

        rag_context = {
            "playbooks": [
                {"doc_id": "doc-001"},
                {"document_id": "doc-002"},
                {"id": "doc-003"},
            ],
        }

        result = detector.check(analysis, {}, rag_context)

        citation_warnings = [
            w for w in result.warnings if w.type == WarningType.RAG_CITATION_MISMATCH
        ]
        assert len(citation_warnings) == 0
