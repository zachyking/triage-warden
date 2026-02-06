"""Tests for the dynamic playbook step generator."""

from __future__ import annotations

import json
from typing import Any

import pytest

from tw_ai.playbook.generator import (
    DynamicStepGenerator,
    GeneratedStep,
    StepGenerationContext,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def basic_context() -> StepGenerationContext:
    """Create a basic step generation context."""
    return StepGenerationContext(
        incident_summary="Suspicious login from unknown IP address",
        incident_severity="high",
        incident_type="unauthorized_access",
    )


@pytest.fixture
def detailed_context() -> StepGenerationContext:
    """Create a detailed context with all fields populated."""
    return StepGenerationContext(
        incident_summary="Phishing email with malicious attachment detected",
        incident_severity="critical",
        incident_type="phishing",
        available_actions=["block_sender", "quarantine_email", "isolate_host", "notify_team"],
        organization_policies={"auto_quarantine_phishing": True, "require_approval_for_isolation": True},
        previous_step_results=[
            {"action": "collect_evidence", "status": "completed", "output": {"indicators": 5}},
        ],
    )


@pytest.fixture
def low_severity_context() -> StepGenerationContext:
    """Create a low-severity context."""
    return StepGenerationContext(
        incident_summary="Informational alert from monitoring system",
        incident_severity="low",
        incident_type="monitoring_alert",
    )


@pytest.fixture
def malware_context() -> StepGenerationContext:
    """Create a malware incident context."""
    return StepGenerationContext(
        incident_summary="Malware detected on endpoint by EDR",
        incident_severity="high",
        incident_type="malware_detection",
    )


class MockLLM:
    """Mock LLM provider for testing."""

    def __init__(self, response: str) -> None:
        self.response = response
        self.prompts: list[str] = []

    async def generate(self, prompt: str) -> str:
        self.prompts.append(prompt)
        return self.response


# =============================================================================
# GeneratedStep Model Tests
# =============================================================================


class TestGeneratedStep:
    """Tests for the GeneratedStep model."""

    def test_minimal_step(self) -> None:
        """Test creating a step with minimal fields."""
        step = GeneratedStep(name="Test Step", action="test_action")
        assert step.name == "Test Step"
        assert step.action == "test_action"
        assert step.parameters == {}
        assert step.requires_approval is False
        assert step.risk_level == "low"
        assert step.rationale == ""
        assert step.estimated_duration_secs == 60

    def test_full_step(self) -> None:
        """Test creating a step with all fields."""
        step = GeneratedStep(
            name="Block IP",
            action="block_ip",
            parameters={"ip": "10.0.0.1", "duration": 3600},
            requires_approval=True,
            risk_level="high",
            rationale="Malicious IP detected in threat intel",
            estimated_duration_secs=30,
        )
        assert step.parameters["ip"] == "10.0.0.1"
        assert step.requires_approval is True
        assert step.risk_level == "high"

    def test_step_serialization(self) -> None:
        """Test step serialization to dict and JSON."""
        step = GeneratedStep(
            name="Test",
            action="test",
            parameters={"key": "value"},
        )
        data = step.model_dump()
        assert data["name"] == "Test"
        assert data["action"] == "test"

        json_str = step.model_dump_json()
        parsed = json.loads(json_str)
        assert parsed["action"] == "test"


# =============================================================================
# StepGenerationContext Model Tests
# =============================================================================


class TestStepGenerationContext:
    """Tests for the StepGenerationContext model."""

    def test_minimal_context(self) -> None:
        """Test creating context with minimal fields."""
        ctx = StepGenerationContext(
            incident_summary="Test incident",
            incident_severity="medium",
            incident_type="generic",
        )
        assert ctx.incident_summary == "Test incident"
        assert ctx.available_actions == []
        assert ctx.organization_policies == {}
        assert ctx.previous_step_results == []

    def test_full_context(self, detailed_context: StepGenerationContext) -> None:
        """Test context with all fields populated."""
        assert detailed_context.incident_type == "phishing"
        assert len(detailed_context.available_actions) == 4
        assert detailed_context.organization_policies["auto_quarantine_phishing"] is True
        assert len(detailed_context.previous_step_results) == 1


# =============================================================================
# Prompt Building Tests
# =============================================================================


class TestPromptBuilding:
    """Tests for the prompt building functionality."""

    def test_prompt_contains_incident_info(self, basic_context: StepGenerationContext) -> None:
        """Test that prompt includes incident details."""
        generator = DynamicStepGenerator()
        prompt = generator._build_prompt(basic_context)

        assert "Suspicious login from unknown IP" in prompt
        assert "high" in prompt
        assert "unauthorized_access" in prompt

    def test_prompt_contains_available_actions(self, detailed_context: StepGenerationContext) -> None:
        """Test that prompt includes available actions."""
        generator = DynamicStepGenerator()
        prompt = generator._build_prompt(detailed_context)

        assert "block_sender" in prompt
        assert "quarantine_email" in prompt
        assert "isolate_host" in prompt

    def test_prompt_contains_policies(self, detailed_context: StepGenerationContext) -> None:
        """Test that prompt includes organization policies."""
        generator = DynamicStepGenerator()
        prompt = generator._build_prompt(detailed_context)

        assert "auto_quarantine_phishing" in prompt

    def test_prompt_contains_previous_results(self, detailed_context: StepGenerationContext) -> None:
        """Test that prompt includes previous step results."""
        generator = DynamicStepGenerator()
        prompt = generator._build_prompt(detailed_context)

        assert "collect_evidence" in prompt

    def test_prompt_omits_empty_sections(self, basic_context: StepGenerationContext) -> None:
        """Test that prompt omits empty optional sections."""
        generator = DynamicStepGenerator()
        prompt = generator._build_prompt(basic_context)

        assert "Available actions:" not in prompt
        assert "Organization policies:" not in prompt
        assert "Previous step results:" not in prompt

    def test_prompt_requests_json_output(self, basic_context: StepGenerationContext) -> None:
        """Test that prompt instructs LLM to output JSON."""
        generator = DynamicStepGenerator()
        prompt = generator._build_prompt(basic_context)

        assert "JSON" in prompt


# =============================================================================
# Step Parsing Tests
# =============================================================================


class TestStepParsing:
    """Tests for parsing LLM responses into steps."""

    def test_parse_valid_json_array(self) -> None:
        """Test parsing a valid JSON array of steps."""
        generator = DynamicStepGenerator()
        response = json.dumps([
            {
                "name": "Collect Evidence",
                "action": "collect_evidence",
                "parameters": {},
                "requires_approval": False,
                "risk_level": "low",
                "rationale": "Gather initial evidence",
                "estimated_duration_secs": 30,
            },
            {
                "name": "Block IP",
                "action": "block_ip",
                "parameters": {"ip": "10.0.0.1"},
                "requires_approval": True,
                "risk_level": "high",
                "rationale": "Block malicious source",
                "estimated_duration_secs": 15,
            },
        ])

        steps = generator._parse_steps(response)
        assert len(steps) == 2
        assert steps[0].name == "Collect Evidence"
        assert steps[1].action == "block_ip"
        assert steps[1].requires_approval is True

    def test_parse_json_in_markdown_code_block(self) -> None:
        """Test parsing JSON wrapped in markdown code blocks."""
        generator = DynamicStepGenerator()
        response = """Here are the recommended steps:

```json
[
    {
        "name": "Collect Evidence",
        "action": "collect_evidence",
        "parameters": {},
        "requires_approval": false,
        "risk_level": "low",
        "rationale": "Gather evidence",
        "estimated_duration_secs": 30
    }
]
```

These steps should help resolve the incident."""

        steps = generator._parse_steps(response)
        assert len(steps) == 1
        assert steps[0].action == "collect_evidence"

    def test_parse_json_with_surrounding_text(self) -> None:
        """Test extracting JSON array from text with surrounding content."""
        generator = DynamicStepGenerator()
        response = """Based on my analysis, I recommend the following steps:
[{"name": "Test", "action": "test_action", "parameters": {}, "requires_approval": false, "risk_level": "low", "rationale": "testing", "estimated_duration_secs": 10}]
Let me know if you need anything else."""

        steps = generator._parse_steps(response)
        assert len(steps) == 1
        assert steps[0].action == "test_action"

    def test_parse_invalid_json(self) -> None:
        """Test parsing invalid JSON returns empty list."""
        generator = DynamicStepGenerator()
        steps = generator._parse_steps("This is not JSON at all")
        assert steps == []

    def test_parse_empty_response(self) -> None:
        """Test parsing empty response returns empty list."""
        generator = DynamicStepGenerator()
        steps = generator._parse_steps("")
        assert steps == []

    def test_parse_json_object_not_array(self) -> None:
        """Test parsing a JSON object (not array) returns empty list."""
        generator = DynamicStepGenerator()
        steps = generator._parse_steps('{"name": "single step", "action": "test"}')
        assert steps == []

    def test_parse_minimal_step_fields(self) -> None:
        """Test parsing steps with only required fields uses defaults."""
        generator = DynamicStepGenerator()
        response = json.dumps([{"name": "Minimal", "action": "minimal_action"}])

        steps = generator._parse_steps(response)
        assert len(steps) == 1
        assert steps[0].requires_approval is False
        assert steps[0].risk_level == "low"
        assert steps[0].estimated_duration_secs == 60


# =============================================================================
# Default Steps Tests
# =============================================================================


class TestDefaultSteps:
    """Tests for default step generation when no LLM is available."""

    @pytest.mark.asyncio
    async def test_default_steps_always_includes_evidence_collection(
        self, basic_context: StepGenerationContext
    ) -> None:
        """Test that default steps always start with evidence collection."""
        generator = DynamicStepGenerator()
        steps = await generator.generate_steps(basic_context)

        assert len(steps) > 0
        assert steps[0].action == "collect_evidence"

    @pytest.mark.asyncio
    async def test_default_steps_always_includes_enrichment(
        self, basic_context: StepGenerationContext
    ) -> None:
        """Test that default steps include enrichment."""
        generator = DynamicStepGenerator()
        steps = await generator.generate_steps(basic_context)

        actions = [s.action for s in steps]
        assert "enrich_indicators" in actions

    @pytest.mark.asyncio
    async def test_default_steps_always_ends_with_report(
        self, basic_context: StepGenerationContext
    ) -> None:
        """Test that default steps always end with documentation."""
        generator = DynamicStepGenerator()
        steps = await generator.generate_steps(basic_context)

        assert steps[-1].action == "create_report"

    @pytest.mark.asyncio
    async def test_critical_severity_includes_isolation(self) -> None:
        """Test that critical severity includes system isolation."""
        context = StepGenerationContext(
            incident_summary="Critical breach detected",
            incident_severity="critical",
            incident_type="breach",
        )
        generator = DynamicStepGenerator()
        steps = await generator.generate_steps(context)

        actions = [s.action for s in steps]
        assert "isolate_host" in actions

    @pytest.mark.asyncio
    async def test_critical_isolation_requires_approval(self) -> None:
        """Test that isolation step requires approval."""
        context = StepGenerationContext(
            incident_summary="Critical breach",
            incident_severity="critical",
            incident_type="breach",
        )
        generator = DynamicStepGenerator()
        steps = await generator.generate_steps(context)

        isolation_step = next(s for s in steps if s.action == "isolate_host")
        assert isolation_step.requires_approval is True
        assert isolation_step.risk_level == "high"

    @pytest.mark.asyncio
    async def test_high_severity_includes_notification(self) -> None:
        """Test that high severity includes team notification."""
        context = StepGenerationContext(
            incident_summary="High severity alert",
            incident_severity="high",
            incident_type="alert",
        )
        generator = DynamicStepGenerator()
        steps = await generator.generate_steps(context)

        actions = [s.action for s in steps]
        assert "notify_team" in actions

    @pytest.mark.asyncio
    async def test_low_severity_no_isolation_or_notification(
        self, low_severity_context: StepGenerationContext
    ) -> None:
        """Test that low severity does not include isolation or notification."""
        generator = DynamicStepGenerator()
        steps = await generator.generate_steps(low_severity_context)

        actions = [s.action for s in steps]
        assert "isolate_host" not in actions
        assert "notify_team" not in actions

    @pytest.mark.asyncio
    async def test_phishing_type_includes_block_sender(self) -> None:
        """Test that phishing incidents include sender blocking."""
        context = StepGenerationContext(
            incident_summary="Phishing email reported",
            incident_severity="medium",
            incident_type="phishing",
        )
        generator = DynamicStepGenerator()
        steps = await generator.generate_steps(context)

        actions = [s.action for s in steps]
        assert "block_sender" in actions

    @pytest.mark.asyncio
    async def test_malware_type_includes_sandbox(
        self, malware_context: StepGenerationContext
    ) -> None:
        """Test that malware incidents include sandbox submission."""
        generator = DynamicStepGenerator()
        steps = await generator.generate_steps(malware_context)

        actions = [s.action for s in steps]
        assert "sandbox_submit" in actions

    @pytest.mark.asyncio
    async def test_access_type_includes_revoke(self) -> None:
        """Test that unauthorized access incidents include access revocation."""
        context = StepGenerationContext(
            incident_summary="Unauthorized access detected",
            incident_severity="high",
            incident_type="unauthorized_access",
        )
        generator = DynamicStepGenerator()
        steps = await generator.generate_steps(context)

        actions = [s.action for s in steps]
        assert "revoke_access" in actions

    @pytest.mark.asyncio
    async def test_revoke_access_requires_approval(self) -> None:
        """Test that access revocation requires approval."""
        context = StepGenerationContext(
            incident_summary="Unauthorized access detected",
            incident_severity="high",
            incident_type="unauthorized_access",
        )
        generator = DynamicStepGenerator()
        steps = await generator.generate_steps(context)

        revoke_step = next(s for s in steps if s.action == "revoke_access")
        assert revoke_step.requires_approval is True
        assert revoke_step.risk_level == "high"


# =============================================================================
# LLM Integration Tests
# =============================================================================


class TestLLMIntegration:
    """Tests for LLM-based step generation."""

    @pytest.mark.asyncio
    async def test_generate_steps_with_llm(self, basic_context: StepGenerationContext) -> None:
        """Test step generation with a mock LLM provider."""
        mock_response = json.dumps([
            {
                "name": "Investigate Login",
                "action": "investigate_login",
                "parameters": {"ip": "10.0.0.1"},
                "requires_approval": False,
                "risk_level": "low",
                "rationale": "Check the login source",
                "estimated_duration_secs": 30,
            },
        ])
        llm = MockLLM(mock_response)
        generator = DynamicStepGenerator(llm_provider=llm)

        steps = await generator.generate_steps(basic_context)

        assert len(steps) == 1
        assert steps[0].action == "investigate_login"
        assert len(llm.prompts) == 1

    @pytest.mark.asyncio
    async def test_llm_prompt_sent_correctly(self, detailed_context: StepGenerationContext) -> None:
        """Test that the correct prompt is sent to the LLM."""
        llm = MockLLM("[]")
        generator = DynamicStepGenerator(llm_provider=llm)

        await generator.generate_steps(detailed_context)

        assert len(llm.prompts) == 1
        prompt = llm.prompts[0]
        assert "phishing" in prompt.lower()
        assert "critical" in prompt.lower()

    @pytest.mark.asyncio
    async def test_llm_returns_invalid_json(self, basic_context: StepGenerationContext) -> None:
        """Test handling of invalid JSON from LLM."""
        llm = MockLLM("I cannot generate steps for this incident.")
        generator = DynamicStepGenerator(llm_provider=llm)

        steps = await generator.generate_steps(basic_context)
        assert steps == []

    @pytest.mark.asyncio
    async def test_no_llm_uses_defaults(self, basic_context: StepGenerationContext) -> None:
        """Test that no LLM provider triggers default step generation."""
        generator = DynamicStepGenerator(llm_provider=None)
        steps = await generator.generate_steps(basic_context)

        assert len(steps) > 0
        assert steps[0].action == "collect_evidence"

    @pytest.mark.asyncio
    async def test_all_default_steps_have_rationale(
        self, basic_context: StepGenerationContext
    ) -> None:
        """Test that all default steps include a rationale."""
        generator = DynamicStepGenerator()
        steps = await generator.generate_steps(basic_context)

        for step in steps:
            assert step.rationale != "", f"Step '{step.name}' has no rationale"

    @pytest.mark.asyncio
    async def test_all_default_steps_have_valid_risk_level(
        self, basic_context: StepGenerationContext
    ) -> None:
        """Test that all default steps have valid risk levels."""
        generator = DynamicStepGenerator()
        steps = await generator.generate_steps(basic_context)

        valid_levels = {"low", "medium", "high", "critical"}
        for step in steps:
            assert step.risk_level in valid_levels, (
                f"Step '{step.name}' has invalid risk level '{step.risk_level}'"
            )
