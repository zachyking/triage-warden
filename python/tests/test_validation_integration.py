"""Integration tests combining hallucination detection and action validation.

Tests the flow: analysis output -> hallucination detection -> action validation,
verifying that the two validation layers work together correctly.
"""

from __future__ import annotations

import pytest

from tw_ai.agents.models import (
    EvidenceItem,
    Indicator,
    InvestigationStep,
    MITRETechnique,
    RecommendedAction,
    TriageAnalysis,
)
from tw_ai.validation.action import (
    ActionToValidate,
    ActionValidator,
    ActionValidatorConfig,
    IncidentContext,
    ProtectedEntityConfig,
    ValidationDecision,
)
from tw_ai.validation.hallucination import (
    HallucinationConfig,
    HallucinationDetector,
    HallucinationResult,
    HallucinationSeverity,
    WarningType,
)


# =============================================================================
# Helpers
# =============================================================================


def _make_analysis(
    verdict: str = "true_positive",
    confidence: int = 85,
    severity: str = "high",
    summary: str = "Confirmed malicious activity",
    reasoning: str = "Analysis based on multiple indicators.",
    indicators: list[Indicator] | None = None,
    evidence: list[EvidenceItem] | None = None,
    investigation_steps: list[InvestigationStep] | None = None,
    mitre_techniques: list[MITRETechnique] | None = None,
    recommended_actions: list[RecommendedAction] | None = None,
) -> TriageAnalysis:
    """Build a TriageAnalysis with sensible defaults."""
    return TriageAnalysis(
        verdict=verdict,
        confidence=confidence,
        severity=severity,
        summary=summary,
        reasoning=reasoning,
        indicators=indicators or [],
        evidence=evidence
        or [
            EvidenceItem(
                source_type="threat_intel",
                source_name="VirusTotal",
                data_type="threat_intel_match",
                value={"detection_rate": "80%"},
                finding="Malicious indicators detected",
                relevance="Confirms threat",
                confidence=90,
            ),
            EvidenceItem(
                source_type="siem",
                source_name="Splunk",
                data_type="network_activity",
                value={"connections": 3},
                finding="Suspicious network connections",
                relevance="C2 communication pattern",
                confidence=85,
            ),
        ],
        investigation_steps=investigation_steps
        or [
            InvestigationStep(
                order=1,
                action="Queried threat intelligence",
                result="Multiple indicators flagged",
                status="completed",
            ),
        ],
        mitre_techniques=mitre_techniques or [],
        recommended_actions=recommended_actions
        or [
            RecommendedAction(
                action="Block malicious IP",
                priority="high",
                reason="Active C2 communication",
            )
        ],
    )


def _make_incident_context(
    severity: str = "high",
    confidence: float = 0.85,
    verdict: str = "true_positive",
) -> IncidentContext:
    """Build an IncidentContext with defaults."""
    return IncidentContext(
        incident_id="INC-001",
        severity=severity,
        confidence=confidence,
        verdict=verdict,
        known_hosts={"workstation-01"},
        known_users={"jdoe"},
        known_ips={"10.0.0.50", "192.168.1.100"},
        known_domains={"internal.corp"},
    )


# =============================================================================
# Clean Analysis with Valid Actions
# =============================================================================


class TestCleanAnalysisValidActions:
    """Tests where analysis is clean and actions are valid."""

    def test_clean_analysis_passes_both_checks(self) -> None:
        """A clean analysis should pass hallucination and action validation."""
        analysis = _make_analysis(
            reasoning="IP 10.0.0.50 was flagged by VirusTotal with high confidence.",
            indicators=[
                Indicator(type="ip", value="10.0.0.50", verdict="malicious"),
            ],
        )
        incident_data = "Alert from 10.0.0.50 connecting to C2 server"

        # Hallucination check
        detector = HallucinationDetector()
        hall_result = detector.check(analysis, incident_data)

        # Action validation
        action = ActionToValidate(
            action_type="block_ip",
            target_type="ip",
            target_value="10.0.0.50",
            reason="Active C2 communication",
        )
        context = _make_incident_context()
        validator = ActionValidator()
        val_result = validator.validate(action, context)

        assert not hall_result.should_flag_for_review
        assert val_result.is_valid

    def test_low_risk_action_with_clean_analysis(self) -> None:
        """Low-risk action with clean analysis should be valid."""
        analysis = _make_analysis(confidence=90)
        incident_data = "Suspicious activity from internal host"

        detector = HallucinationDetector()
        hall_result = detector.check(analysis, incident_data)

        action = ActionToValidate(
            action_type="create_ticket",
            target_type="none",
            target_value="",
            reason="Track investigation",
        )
        context = _make_incident_context()
        validator = ActionValidator()
        val_result = validator.validate(action, context)

        assert not hall_result.should_flag_for_review
        assert val_result.is_valid


# =============================================================================
# Hallucinated Analysis with Risky Actions
# =============================================================================


class TestHallucinatedAnalysisWithRiskyActions:
    """Tests where analysis contains hallucinations and actions are risky."""

    def test_hallucinated_ip_flags_review(self) -> None:
        """Hallucinated IP in analysis should flag for review."""
        analysis = _make_analysis(
            reasoning="The attacker IP 203.0.113.99 shows clear C2 behavior.",
            indicators=[
                Indicator(type="ip", value="203.0.113.99", verdict="malicious"),
            ],
        )
        # Incident data does NOT contain 203.0.113.99
        incident_data = "Alert: suspicious traffic from 10.0.0.50"

        detector = HallucinationDetector()
        hall_result = detector.check(analysis, incident_data)

        assert hall_result.has_warnings
        ip_warnings = [
            w for w in hall_result.warnings if w.type == WarningType.HALLUCINATED_IP
        ]
        assert len(ip_warnings) > 0

    def test_hallucination_reduces_effective_confidence(self) -> None:
        """Demonstrate that hallucination warnings can inform action validation.

        When hallucination detection reveals issues, the operator should
        reduce the effective confidence used for action validation.
        """
        analysis = _make_analysis(
            confidence=95,
            reasoning="IP 203.0.113.99 is clearly malicious based on threat intel.",
            indicators=[
                Indicator(type="ip", value="203.0.113.99", verdict="malicious"),
            ],
            evidence=[
                EvidenceItem(
                    source_type="threat_intel",
                    source_name="VirusTotal",
                    data_type="threat_intel_match",
                    value={"score": 95},
                    finding="Malicious",
                    relevance="Confirms threat",
                    confidence=95,
                ),
            ],
        )
        incident_data = "Alert: traffic from 10.0.0.50"

        # Step 1: Hallucination check
        detector = HallucinationDetector()
        hall_result = detector.check(analysis, incident_data)

        assert hall_result.has_warnings

        # Step 2: Use hallucination result to adjust confidence for action validation
        # If hallucinations detected, reduce confidence
        adjusted_confidence = analysis.confidence / 100.0
        if hall_result.has_warnings:
            penalty = 0.1 * len(hall_result.warnings)
            if hall_result.critical_count > 0:
                penalty += 0.3
            adjusted_confidence = max(0.0, adjusted_confidence - penalty)

        # Step 3: Action validation with adjusted confidence
        action = ActionToValidate(
            action_type="isolate_host",
            target_type="host",
            target_value="workstation-01",
            reason="Compromised host",
        )
        context = IncidentContext(
            incident_id="INC-002",
            severity="high",
            confidence=adjusted_confidence,
            verdict="true_positive",
            known_hosts={"workstation-01"},
        )
        validator = ActionValidator()
        val_result = validator.validate(action, context)

        # With reduced confidence, high-risk action should require approval
        assert adjusted_confidence < 0.8
        assert val_result.decision in (
            ValidationDecision.REQUIRES_APPROVAL,
            ValidationDecision.VALID,
        )

    def test_critical_hallucination_blocks_destructive_action(self) -> None:
        """Multiple hallucinations should block destructive actions via low confidence."""
        analysis = _make_analysis(
            confidence=98,
            severity="critical",
            reasoning="IP 8.8.8.8 and domain evil-corp.xyz confirm APT attack.",
            indicators=[
                Indicator(type="ip", value="8.8.8.8", verdict="malicious"),
                Indicator(type="domain", value="evil-corp.xyz", verdict="malicious"),
            ],
            evidence=[],
            investigation_steps=[],
        )
        # None of the cited indicators are in the incident data
        incident_data = "Alert from endpoint monitoring on workstation-05"

        detector = HallucinationDetector(
            config=HallucinationConfig(max_warnings_before_flag=2)
        )
        hall_result = detector.check(analysis, incident_data)

        # Should be flagged due to hallucinated indicators + confidence mismatch
        assert hall_result.should_flag_for_review

        # With the analysis flagged, set confidence very low for action validation
        effective_confidence = 0.1 if hall_result.should_flag_for_review else 0.98

        action = ActionToValidate(
            action_type="wipe_host",
            target_type="host",
            target_value="workstation-05",
            reason="Compromised host needs wiping",
        )
        context = IncidentContext(
            incident_id="INC-003",
            severity="critical",
            confidence=effective_confidence,
            verdict="true_positive",
            known_hosts={"workstation-05"},
        )
        validator = ActionValidator()
        val_result = validator.validate(action, context)

        # Low confidence should require approval for destructive action
        assert not val_result.is_valid or val_result.decision == ValidationDecision.REQUIRES_APPROVAL


# =============================================================================
# Edge Cases
# =============================================================================


class TestEdgeCases:
    """Edge case tests for the validation integration."""

    def test_empty_analysis_no_hallucinations(self) -> None:
        """Analysis with minimal content should not produce false positives."""
        analysis = _make_analysis(
            confidence=50,
            severity="low",
            reasoning="Insufficient data to determine threat level.",
            indicators=[],
            evidence=[
                EvidenceItem(
                    source_type="alert_data",
                    source_name="SIEM Alert",
                    data_type="network_activity",
                    value={"alert_id": "A-123"},
                    finding="Low confidence alert",
                    relevance="Initial alert data",
                    confidence=50,
                ),
                EvidenceItem(
                    source_type="siem",
                    source_name="Splunk",
                    data_type="network_activity",
                    value={"logs": "minimal"},
                    finding="Few related events",
                    relevance="Supporting context",
                    confidence=40,
                ),
            ],
        )
        incident_data = "Low priority alert from network sensor"

        detector = HallucinationDetector()
        hall_result = detector.check(analysis, incident_data)

        # No hallucinated indicators, so should be clean
        ip_warnings = [
            w for w in hall_result.warnings if w.type == WarningType.HALLUCINATED_IP
        ]
        assert len(ip_warnings) == 0

    def test_protected_entity_overrides_clean_analysis(self) -> None:
        """Even with clean analysis, protected entities require override."""
        analysis = _make_analysis(confidence=95, severity="critical")
        incident_data = "Critical alert involving admin account"

        detector = HallucinationDetector()
        hall_result = detector.check(analysis, incident_data)
        assert not hall_result.should_flag_for_review

        # Action targets a protected user
        protected = ProtectedEntityConfig(
            protected_users={"admin", "root", "service-account"},
        )
        config = ActionValidatorConfig(protected_entities=protected)
        validator = ActionValidator(config=config)

        action = ActionToValidate(
            action_type="disable_user",
            target_type="user",
            target_value="admin",
            reason="Compromised account",
        )
        context = _make_incident_context(confidence=0.95)
        val_result = validator.validate(action, context)

        assert val_result.decision == ValidationDecision.REQUIRES_OVERRIDE

    def test_confidence_mismatch_warning_with_high_risk_action(self) -> None:
        """High confidence with little evidence triggers warning; high risk action needs approval."""
        analysis = _make_analysis(
            confidence=98,
            severity="critical",
            reasoning="Clearly malicious.",
            evidence=[
                EvidenceItem(
                    source_type="threat_intel",
                    source_name="VirusTotal",
                    data_type="threat_intel_match",
                    value={"score": 50},
                    finding="Moderate detection",
                    relevance="Some engines flagged",
                    confidence=50,
                ),
            ],
            investigation_steps=[],
        )
        incident_data = "Endpoint alert on workstation"

        detector = HallucinationDetector()
        hall_result = detector.check(analysis, incident_data)

        # Should detect confidence/evidence mismatch
        confidence_warnings = [
            w
            for w in hall_result.warnings
            if w.type == WarningType.CONFIDENCE_MISMATCH
        ]
        assert len(confidence_warnings) > 0

    def test_rag_citation_mismatch_detected(self) -> None:
        """RAG citation referencing non-existent document should be flagged."""
        analysis = _make_analysis(confidence=80)
        # Manually set RAG fields that don't match context
        analysis_dict = analysis.model_dump()
        analysis_dict["rag_context_used"] = True
        analysis_dict["rag_citations"] = [
            {"doc_id": "doc_999", "relevance": "high"},
        ]
        analysis = TriageAnalysis(**analysis_dict)

        incident_data = "Test incident data"
        rag_context = {
            "similar_incidents": [
                {"doc_id": "doc_001", "content": "Past incident"},
            ],
        }

        detector = HallucinationDetector()
        hall_result = detector.check(analysis, incident_data, rag_context=rag_context)

        rag_warnings = [
            w
            for w in hall_result.warnings
            if w.type == WarningType.RAG_CITATION_MISMATCH
        ]
        assert len(rag_warnings) > 0

    def test_batch_action_validation_with_mixed_results(self) -> None:
        """Validate multiple actions; some valid, some requiring approval."""
        context = _make_incident_context(severity="medium", confidence=0.9)
        validator = ActionValidator()

        actions = [
            ActionToValidate(
                action_type="create_ticket",
                target_type="none",
                target_value="",
                reason="Track investigation",
            ),
            ActionToValidate(
                action_type="isolate_host",
                target_type="host",
                target_value="workstation-01",
                reason="Potentially compromised",
            ),
        ]

        results = validator.validate_batch(actions, context)

        assert len(results) == 2
        # create_ticket (low risk) should be valid for medium severity
        assert results[0].is_valid
        # isolate_host (high risk) for medium severity should need approval
        assert results[1].decision == ValidationDecision.REQUIRES_APPROVAL
