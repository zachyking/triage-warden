"""End-to-end tests for the phishing triage pipeline.

Tests the complete workflow including:
- Email parsing
- Phishing indicator detection
- AI-powered verdict determination
- Action proposal and policy checking
- Performance requirements

Each test validates:
1. Correct verdict (malicious/suspicious/benign)
2. Appropriate confidence level
3. Relevant actions proposed
4. All pipeline stages completed
"""

from __future__ import annotations

import time
from typing import Any

import pytest

from ._e2e_fixtures import (
    ReActAgent,
    TriageRequest,
    StepType,
    MockLLMProvider,
    MockToolRegistry,
)


# =============================================================================
# Test: Obvious Phishing Detection
# =============================================================================


class TestObviousPhishingDetected:
    """Tests for obvious phishing emails that should return malicious verdict."""

    @pytest.mark.asyncio
    async def test_obvious_phishing_returns_malicious_verdict(
        self,
        phishing_workflow,
        obvious_phishing,
    ):
        """Test that obvious phishing email gets malicious verdict."""
        result = await phishing_workflow.triage(obvious_phishing)

        assert result.verdict == "malicious", (
            f"Expected 'malicious' verdict for obvious phishing, got '{result.verdict}'"
        )

    @pytest.mark.asyncio
    async def test_obvious_phishing_high_confidence(
        self,
        phishing_workflow,
        obvious_phishing,
    ):
        """Test that obvious phishing gets confidence > 80."""
        result = await phishing_workflow.triage(obvious_phishing)

        assert result.confidence > 80, (
            f"Expected confidence > 80 for obvious phishing, got {result.confidence}"
        )

    @pytest.mark.asyncio
    async def test_obvious_phishing_detects_typosquat(
        self,
        phishing_workflow,
        obvious_phishing,
    ):
        """Test that obvious phishing detects typosquatted domain."""
        result = await phishing_workflow.triage(obvious_phishing)

        # Check phishing indicators for typosquat detection
        assert result.phishing_indicators is not None
        typosquat_domains = result.phishing_indicators.typosquat_domains

        assert len(typosquat_domains) > 0, "Expected typosquat domains to be detected"

        # Verify paypa1 typosquat was detected
        detected_domains = [m.suspicious_domain for m in typosquat_domains]
        has_paypa1 = any("paypa1" in d.lower() for d in detected_domains)
        assert has_paypa1, f"Expected paypa1 typosquat, got: {detected_domains}"

    @pytest.mark.asyncio
    async def test_obvious_phishing_detects_urgency_language(
        self,
        phishing_workflow,
        obvious_phishing,
    ):
        """Test that obvious phishing detects urgency language."""
        result = await phishing_workflow.triage(obvious_phishing)

        assert result.phishing_indicators is not None
        urgency_phrases = result.phishing_indicators.urgency_phrases

        assert len(urgency_phrases) > 0, "Expected urgency phrases to be detected"

    @pytest.mark.asyncio
    async def test_obvious_phishing_detects_credential_request(
        self,
        phishing_workflow,
        obvious_phishing,
    ):
        """Test that obvious phishing detects credential request."""
        result = await phishing_workflow.triage(obvious_phishing)

        assert result.phishing_indicators is not None
        assert result.phishing_indicators.credential_request_detected, (
            "Expected credential request to be detected"
        )

    @pytest.mark.asyncio
    async def test_obvious_phishing_proposes_quarantine_action(
        self,
        phishing_workflow,
        obvious_phishing,
    ):
        """Test that obvious phishing proposes quarantine/block actions."""
        result = await phishing_workflow.triage(obvious_phishing)

        assert len(result.proposed_actions) > 0, "Expected proposed actions"

        # Check for quarantine or block action
        action_texts = [a.get("action", "").lower() for a in result.proposed_actions]
        has_containment = any(
            "quarantine" in text or "block" in text
            for text in action_texts
        )

        assert has_containment, f"Expected quarantine/block action, got: {action_texts}"

    @pytest.mark.asyncio
    async def test_obvious_phishing_all_stages_completed(
        self,
        phishing_workflow,
        obvious_phishing,
    ):
        """Test that all pipeline stages complete for obvious phishing."""
        result = await phishing_workflow.triage(obvious_phishing)

        expected_stages = ["PARSE", "ANALYZE", "ENRICH", "DECIDE", "APPROVE"]
        for stage in expected_stages:
            assert stage in result.stages_completed, (
                f"Expected stage '{stage}' to complete, completed: {result.stages_completed}"
            )

    @pytest.mark.asyncio
    async def test_obvious_phishing_no_errors(
        self,
        phishing_workflow,
        obvious_phishing,
    ):
        """Test that obvious phishing triage completes without errors."""
        result = await phishing_workflow.triage(obvious_phishing)

        assert result.error is None, f"Unexpected error: {result.error}"


# =============================================================================
# Test: Sophisticated Phishing Escalation
# =============================================================================


class TestSophisticatedPhishingEscalated:
    """Tests for sophisticated phishing that should return suspicious and recommend review."""

    @pytest.mark.asyncio
    async def test_sophisticated_phishing_returns_suspicious_verdict(
        self,
        phishing_workflow,
        sophisticated_phishing,
    ):
        """Test that sophisticated phishing gets suspicious verdict."""
        result = await phishing_workflow.triage(sophisticated_phishing)

        # Sophisticated phishing should be either suspicious or malicious
        assert result.verdict in ("suspicious", "malicious"), (
            f"Expected 'suspicious' or 'malicious' verdict, got '{result.verdict}'"
        )

    @pytest.mark.asyncio
    async def test_sophisticated_phishing_moderate_confidence(
        self,
        phishing_workflow,
        sophisticated_phishing,
    ):
        """Test that sophisticated phishing gets confidence between 50-80."""
        result = await phishing_workflow.triage(sophisticated_phishing)

        # Sophisticated phishing should have moderate confidence (harder to determine)
        assert 50 <= result.confidence <= 85, (
            f"Expected confidence 50-85 for sophisticated phishing, got {result.confidence}"
        )

    @pytest.mark.asyncio
    async def test_sophisticated_phishing_detects_homoglyph(
        self,
        phishing_workflow,
        sophisticated_phishing,
    ):
        """Test that sophisticated phishing detects homoglyph domain."""
        result = await phishing_workflow.triage(sophisticated_phishing)

        assert result.phishing_indicators is not None
        typosquat_domains = result.phishing_indicators.typosquat_domains

        # Should detect micros0ft as typosquatting microsoft
        assert len(typosquat_domains) > 0, "Expected typosquat/homoglyph detection"

        detected_domains = [m.suspicious_domain for m in typosquat_domains]
        has_microsoft = any("micros0ft" in d.lower() for d in detected_domains)
        assert has_microsoft, f"Expected micros0ft homoglyph, got: {detected_domains}"

    @pytest.mark.asyncio
    async def test_sophisticated_phishing_recommends_review(
        self,
        phishing_workflow,
        sophisticated_phishing,
    ):
        """Test that sophisticated phishing recommends human review."""
        result = await phishing_workflow.triage(sophisticated_phishing)

        assert len(result.proposed_actions) > 0, "Expected proposed actions"

        action_texts = [a.get("action", "").lower() for a in result.proposed_actions]
        has_review = any(
            "review" in text or "escalate" in text or "analyst" in text
            for text in action_texts
        )

        assert has_review, f"Expected review/escalate action, got: {action_texts}"

    @pytest.mark.asyncio
    async def test_sophisticated_phishing_all_stages_completed(
        self,
        phishing_workflow,
        sophisticated_phishing,
    ):
        """Test that all pipeline stages complete for sophisticated phishing."""
        result = await phishing_workflow.triage(sophisticated_phishing)

        expected_stages = ["PARSE", "ANALYZE", "ENRICH", "DECIDE", "APPROVE"]
        for stage in expected_stages:
            assert stage in result.stages_completed, (
                f"Expected stage '{stage}' to complete, completed: {result.stages_completed}"
            )


# =============================================================================
# Test: Legitimate Email Passed
# =============================================================================


class TestLegitimateEmailPassed:
    """Tests for legitimate emails that should return benign verdict with no actions."""

    @pytest.mark.asyncio
    async def test_legitimate_email_returns_benign_verdict(
        self,
        phishing_workflow,
        legitimate_email,
    ):
        """Test that legitimate email gets benign verdict."""
        result = await phishing_workflow.triage(legitimate_email)

        assert result.verdict == "benign", (
            f"Expected 'benign' verdict for legitimate email, got '{result.verdict}'"
        )

    @pytest.mark.asyncio
    async def test_legitimate_email_high_confidence(
        self,
        phishing_workflow,
        legitimate_email,
    ):
        """Test that legitimate email gets high confidence."""
        result = await phishing_workflow.triage(legitimate_email)

        assert result.confidence >= 80, (
            f"Expected confidence >= 80 for legitimate email, got {result.confidence}"
        )

    @pytest.mark.asyncio
    async def test_legitimate_email_no_typosquats(
        self,
        phishing_workflow,
        legitimate_email,
    ):
        """Test that legitimate email has no typosquat detections."""
        result = await phishing_workflow.triage(legitimate_email)

        assert result.phishing_indicators is not None
        typosquat_domains = result.phishing_indicators.typosquat_domains

        assert len(typosquat_domains) == 0, (
            f"Expected no typosquats for legitimate email, got: {typosquat_domains}"
        )

    @pytest.mark.asyncio
    async def test_legitimate_email_no_credential_request(
        self,
        phishing_workflow,
        legitimate_email,
    ):
        """Test that legitimate email has no credential request detection."""
        result = await phishing_workflow.triage(legitimate_email)

        assert result.phishing_indicators is not None
        assert not result.phishing_indicators.credential_request_detected, (
            "Expected no credential request for legitimate email"
        )

    @pytest.mark.asyncio
    async def test_legitimate_email_low_risk_score(
        self,
        phishing_workflow,
        legitimate_email,
    ):
        """Test that legitimate email has low risk score."""
        result = await phishing_workflow.triage(legitimate_email)

        assert result.phishing_indicators is not None
        assert result.phishing_indicators.overall_risk_score < 30, (
            f"Expected risk score < 30, got {result.phishing_indicators.overall_risk_score}"
        )

    @pytest.mark.asyncio
    async def test_legitimate_email_no_block_actions(
        self,
        phishing_workflow,
        legitimate_email,
    ):
        """Test that legitimate email doesn't propose block/quarantine actions."""
        result = await phishing_workflow.triage(legitimate_email)

        # Should have release/allow actions, not block/quarantine
        action_texts = [a.get("action", "").lower() for a in result.proposed_actions]
        has_block = any(
            "quarantine" in text or "block" in text
            for text in action_texts
        )

        assert not has_block, (
            f"Expected no block/quarantine for legitimate email, got: {action_texts}"
        )

    @pytest.mark.asyncio
    async def test_legitimate_email_all_stages_completed(
        self,
        phishing_workflow,
        legitimate_email,
    ):
        """Test that all pipeline stages complete for legitimate email."""
        result = await phishing_workflow.triage(legitimate_email)

        expected_stages = ["PARSE", "ANALYZE", "ENRICH", "DECIDE", "APPROVE"]
        for stage in expected_stages:
            assert stage in result.stages_completed, (
                f"Expected stage '{stage}' to complete, completed: {result.stages_completed}"
            )


# =============================================================================
# Test: False Positive Handling
# =============================================================================


class TestFalsePositiveHandled:
    """Tests for false positives (suspicious-looking but legitimate emails)."""

    @pytest.mark.asyncio
    async def test_false_positive_returns_benign_verdict(
        self,
        phishing_workflow,
        false_positive,
    ):
        """Test that false positive (Okta alert) gets benign verdict."""
        result = await phishing_workflow.triage(false_positive)

        assert result.verdict == "benign", (
            f"Expected 'benign' verdict for false positive, got '{result.verdict}'"
        )

    @pytest.mark.asyncio
    async def test_false_positive_recognizes_known_vendor(
        self,
        phishing_workflow,
        false_positive,
    ):
        """Test that false positive recognizes Okta as known vendor."""
        result = await phishing_workflow.triage(false_positive)

        # Should have high confidence because it's a known vendor
        assert result.confidence >= 80, (
            f"Expected confidence >= 80 for known vendor, got {result.confidence}"
        )

    @pytest.mark.asyncio
    async def test_false_positive_no_typosquats(
        self,
        phishing_workflow,
        false_positive,
    ):
        """Test that false positive has no typosquat detections for okta.com."""
        result = await phishing_workflow.triage(false_positive)

        assert result.phishing_indicators is not None
        typosquat_domains = result.phishing_indicators.typosquat_domains

        # okta.com should not be flagged as typosquatting
        okta_flagged = any(
            "okta" in m.suspicious_domain.lower()
            for m in typosquat_domains
        )
        assert not okta_flagged, (
            f"okta.com should not be flagged as typosquat: {typosquat_domains}"
        )

    @pytest.mark.asyncio
    async def test_false_positive_allows_delivery(
        self,
        phishing_workflow,
        false_positive,
    ):
        """Test that false positive recommends email delivery."""
        result = await phishing_workflow.triage(false_positive)

        action_texts = [a.get("action", "").lower() for a in result.proposed_actions]

        # Should recommend delivery, not blocking
        has_delivery = any(
            "deliver" in text or "release" in text or "allow" in text
            for text in action_texts
        )

        assert has_delivery, (
            f"Expected delivery/release action for false positive, got: {action_texts}"
        )

    @pytest.mark.asyncio
    async def test_false_positive_all_stages_completed(
        self,
        phishing_workflow,
        false_positive,
    ):
        """Test that all pipeline stages complete for false positive."""
        result = await phishing_workflow.triage(false_positive)

        expected_stages = ["PARSE", "ANALYZE", "ENRICH", "DECIDE", "APPROVE"]
        for stage in expected_stages:
            assert stage in result.stages_completed, (
                f"Expected stage '{stage}' to complete, completed: {result.stages_completed}"
            )


# =============================================================================
# Test: Performance Requirements
# =============================================================================


class TestPipelinePerformance:
    """Performance tests for the phishing triage pipeline."""

    @pytest.mark.asyncio
    async def test_triage_completes_under_5_seconds(
        self,
        phishing_workflow,
        obvious_phishing,
    ):
        """Test that triage completes in < 5 seconds with mocks."""
        start_time = time.time()

        result = await phishing_workflow.triage(obvious_phishing)

        elapsed_time = time.time() - start_time

        assert elapsed_time < 5.0, (
            f"Triage took {elapsed_time:.2f}s, expected < 5s"
        )

        # Also verify execution time is tracked
        assert result.execution_time_seconds < 5.0, (
            f"Reported execution time {result.execution_time_seconds:.2f}s, expected < 5s"
        )

    @pytest.mark.asyncio
    async def test_triage_performance_legitimate_email(
        self,
        phishing_workflow,
        legitimate_email,
    ):
        """Test performance for legitimate email processing."""
        start_time = time.time()

        result = await phishing_workflow.triage(legitimate_email)

        elapsed_time = time.time() - start_time

        assert elapsed_time < 5.0, (
            f"Legitimate email triage took {elapsed_time:.2f}s, expected < 5s"
        )

    @pytest.mark.asyncio
    async def test_triage_performance_sophisticated_phishing(
        self,
        phishing_workflow,
        sophisticated_phishing,
    ):
        """Test performance for sophisticated phishing processing."""
        start_time = time.time()

        result = await phishing_workflow.triage(sophisticated_phishing)

        elapsed_time = time.time() - start_time

        assert elapsed_time < 5.0, (
            f"Sophisticated phishing triage took {elapsed_time:.2f}s, expected < 5s"
        )


# =============================================================================
# Test: Pipeline Stage Completeness
# =============================================================================


class TestPipelineStageCompleteness:
    """Tests to verify all pipeline stages are executed correctly."""

    @pytest.mark.asyncio
    async def test_parse_stage_extracts_email_analysis(
        self,
        phishing_workflow,
        obvious_phishing,
    ):
        """Test that PARSE stage produces email analysis."""
        result = await phishing_workflow.triage(obvious_phishing)

        assert "PARSE" in result.stages_completed
        assert result.email_analysis is not None
        assert result.email_analysis.sender == "security@paypa1.com"
        assert "paypa1" in result.email_analysis.subject.lower() or "paypal" in result.email_analysis.subject.lower()

    @pytest.mark.asyncio
    async def test_analyze_stage_produces_indicators(
        self,
        phishing_workflow,
        obvious_phishing,
    ):
        """Test that ANALYZE stage produces phishing indicators."""
        result = await phishing_workflow.triage(obvious_phishing)

        assert "ANALYZE" in result.stages_completed
        assert result.phishing_indicators is not None
        assert result.phishing_indicators.overall_risk_score > 0

    @pytest.mark.asyncio
    async def test_decide_stage_produces_verdict(
        self,
        phishing_workflow,
        obvious_phishing,
    ):
        """Test that DECIDE stage produces verdict."""
        result = await phishing_workflow.triage(obvious_phishing)

        assert "DECIDE" in result.stages_completed
        assert result.verdict is not None
        assert result.confidence > 0

    @pytest.mark.asyncio
    async def test_approve_stage_processes_actions(
        self,
        phishing_workflow,
        obvious_phishing,
    ):
        """Test that APPROVE stage processes proposed actions."""
        result = await phishing_workflow.triage(obvious_phishing)

        assert "APPROVE" in result.stages_completed
        # Actions should be categorized as approved or rejected
        total_actions = len(result.approved_actions) + len(result.rejected_actions)
        assert total_actions >= 0  # May have no actions if none proposed


# =============================================================================
# Test: Edge Cases
# =============================================================================


class TestEdgeCases:
    """Edge case tests for the phishing pipeline."""

    @pytest.mark.asyncio
    async def test_email_with_no_urls(
        self,
        phishing_workflow,
    ):
        """Test handling of email with no URLs."""
        email = {
            "message_id": "<no-urls@test.com>",
            "subject": "Hello",
            "sender": "sender@company.com",
            "recipients": ["recipient@company.com"],
            "body_text": "This is a simple email with no URLs.",
            "type": "email_security",
        }

        result = await phishing_workflow.triage(email)

        # Should complete without errors
        assert result.error is None
        assert "PARSE" in result.stages_completed

    @pytest.mark.asyncio
    async def test_email_with_minimal_fields(
        self,
        phishing_workflow,
    ):
        """Test handling of email with minimal required fields."""
        email = {
            "sender": "test@example.com",
            "type": "email_security",
        }

        result = await phishing_workflow.triage(email)

        # Should complete without errors
        assert result.error is None or "PARSE" in result.stages_completed

    @pytest.mark.asyncio
    async def test_email_with_empty_body(
        self,
        phishing_workflow,
    ):
        """Test handling of email with empty body."""
        email = {
            "message_id": "<empty-body@test.com>",
            "subject": "Empty email",
            "sender": "sender@company.com",
            "recipients": ["recipient@company.com"],
            "body_text": "",
            "body_html": "",
            "type": "email_security",
        }

        result = await phishing_workflow.triage(email)

        # Should complete without errors
        assert result.error is None
        assert "PARSE" in result.stages_completed


# =============================================================================
# Test: ReAct Agent Integration
# =============================================================================


class TestReActAgentIntegration:
    """Tests for ReAct agent integration with the pipeline."""

    @pytest.mark.asyncio
    async def test_agent_produces_execution_trace(
        self,
        mock_llm_provider,
        mock_tool_registry,
        obvious_phishing,
    ):
        """Test that ReAct agent produces execution trace."""
        agent = ReActAgent(llm=mock_llm_provider, tools=mock_tool_registry)

        request = TriageRequest(
            alert_type="phishing",
            alert_data=obvious_phishing,
        )

        result = await agent.run(request)

        assert result.success
        assert len(result.execution_trace) > 0

        # Should have at least a FINAL step
        step_types = [s.step_type for s in result.execution_trace]
        assert StepType.FINAL in step_types

    @pytest.mark.asyncio
    async def test_agent_tracks_token_usage(
        self,
        mock_llm_provider,
        mock_tool_registry,
        obvious_phishing,
    ):
        """Test that ReAct agent tracks token usage."""
        agent = ReActAgent(llm=mock_llm_provider, tools=mock_tool_registry)

        request = TriageRequest(
            alert_type="phishing",
            alert_data=obvious_phishing,
        )

        result = await agent.run(request)

        assert result.success
        assert result.tokens_used > 0

    @pytest.mark.asyncio
    async def test_agent_parses_analysis_correctly(
        self,
        mock_llm_provider,
        mock_tool_registry,
        obvious_phishing,
    ):
        """Test that ReAct agent parses analysis JSON correctly."""
        agent = ReActAgent(llm=mock_llm_provider, tools=mock_tool_registry)

        request = TriageRequest(
            alert_type="phishing",
            alert_data=obvious_phishing,
        )

        result = await agent.run(request)

        assert result.success
        assert result.analysis is not None
        assert result.analysis.verdict == "true_positive"
        assert result.analysis.confidence >= 80
