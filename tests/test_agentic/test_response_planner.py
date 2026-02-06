"""Tests for the response planning agent."""

from __future__ import annotations

import json

import pytest

from tw_ai.agents.response_planner import (
    ResponsePlan,
    ResponsePlanningAgent,
    ResponseStep,
    RiskLevel,
)

# =============================================================================
# RiskLevel tests
# =============================================================================


class TestRiskLevel:
    def test_ordering(self):
        assert RiskLevel.NONE < RiskLevel.LOW
        assert RiskLevel.LOW < RiskLevel.MEDIUM
        assert RiskLevel.MEDIUM < RiskLevel.HIGH
        assert RiskLevel.HIGH < RiskLevel.CRITICAL

    def test_equality(self):
        assert RiskLevel.HIGH == RiskLevel.HIGH
        assert not (RiskLevel.HIGH < RiskLevel.HIGH)

    def test_ge_le(self):
        assert RiskLevel.HIGH >= RiskLevel.MEDIUM
        assert RiskLevel.HIGH >= RiskLevel.HIGH
        assert RiskLevel.LOW <= RiskLevel.MEDIUM
        assert RiskLevel.LOW <= RiskLevel.LOW

    def test_gt(self):
        assert RiskLevel.CRITICAL > RiskLevel.HIGH
        assert not (RiskLevel.LOW > RiskLevel.MEDIUM)

    def test_comparison_with_non_risk_level(self):
        """RiskLevel comparison with incompatible types raises TypeError."""
        # Comparing with int raises TypeError (no str fallback)
        with pytest.raises(TypeError):
            _ = RiskLevel.LOW >= 42
        with pytest.raises(TypeError):
            _ = RiskLevel.HIGH < 99
        # Returns NotImplemented for our custom operators,
        # but str fallback handles str comparisons without error
        assert RiskLevel.HIGH.__lt__("some_string") is NotImplemented
        assert RiskLevel.HIGH.__ge__("some_string") is NotImplemented


# =============================================================================
# ResponseStep tests
# =============================================================================


class TestResponseStep:
    def test_basic_creation(self):
        step = ResponseStep(
            id="step-1",
            name="Block IP",
            description="Block malicious IP",
            action="block_ip",
        )
        assert step.id == "step-1"
        assert step.risk_level == RiskLevel.LOW
        assert not step.requires_approval
        assert step.depends_on == []
        assert step.rollback_action is None

    def test_with_all_fields(self):
        step = ResponseStep(
            id="step-2",
            name="Isolate Host",
            description="Isolate infected machine",
            action="isolate_host",
            parameters={"hostname": "ws-001"},
            risk_level=RiskLevel.HIGH,
            requires_approval=True,
            estimated_duration_secs=120,
            depends_on=["step-1"],
            rollback_action="unisolate_host",
            rollback_parameters={"hostname": "ws-001"},
        )
        assert step.risk_level == RiskLevel.HIGH
        assert step.requires_approval
        assert step.depends_on == ["step-1"]
        assert step.rollback_action == "unisolate_host"


# =============================================================================
# ResponsePlan tests
# =============================================================================


class TestResponsePlan:
    def test_empty_plan(self):
        plan = ResponsePlan(
            id="plan-1",
            incident_id="inc-1",
            summary="Test plan",
        )
        assert plan.steps == []
        assert plan.total_risk == RiskLevel.LOW
        assert plan.requires_human_review

    def test_plan_with_steps(self):
        plan = ResponsePlan(
            id="plan-1",
            incident_id="inc-1",
            summary="Phishing response",
            steps=[
                ResponseStep(
                    id="s1",
                    name="Quarantine",
                    description="Quarantine email",
                    action="quarantine_email",
                ),
                ResponseStep(
                    id="s2",
                    name="Block",
                    description="Block domain",
                    action="block_domain",
                    depends_on=["s1"],
                ),
            ],
        )
        assert len(plan.steps) == 2
        assert plan.steps[1].depends_on == ["s1"]


# =============================================================================
# Default plan generation tests
# =============================================================================


class TestDefaultPlan:
    @pytest.fixture
    def agent(self):
        return ResponsePlanningAgent()

    @pytest.mark.asyncio
    async def test_phishing_plan(self, agent):
        plan = await agent.plan_response(
            incident_summary="User reported suspicious email",
            incident_severity="high",
            incident_type="phishing",
        )
        assert len(plan.steps) > 0
        assert plan.summary
        actions = [s.action for s in plan.steps]
        assert "quarantine_email" in actions
        assert "create_ticket" in actions

    @pytest.mark.asyncio
    async def test_malware_plan(self, agent):
        plan = await agent.plan_response(
            incident_summary="Malware detected on workstation",
            incident_severity="critical",
            incident_type="malware",
        )
        assert len(plan.steps) > 0
        actions = [s.action for s in plan.steps]
        assert "isolate_host" in actions
        assert "block_hash" in actions

    @pytest.mark.asyncio
    async def test_brute_force_plan(self, agent):
        plan = await agent.plan_response(
            incident_summary="Multiple failed login attempts detected",
            incident_severity="medium",
            incident_type="brute_force",
        )
        assert len(plan.steps) > 0
        actions = [s.action for s in plan.steps]
        assert "block_ip" in actions
        assert "reset_password" in actions

    @pytest.mark.asyncio
    async def test_data_exfiltration_plan(self, agent):
        plan = await agent.plan_response(
            incident_summary="Large data transfer to external IP",
            incident_severity="critical",
            incident_type="data_exfiltration",
        )
        assert len(plan.steps) > 0
        actions = [s.action for s in plan.steps]
        assert "isolate_host" in actions
        assert "disable_user" in actions

    @pytest.mark.asyncio
    async def test_unknown_type_fallback(self, agent):
        plan = await agent.plan_response(
            incident_summary="Unknown incident type",
            incident_severity="medium",
            incident_type="unknown_type",
        )
        assert len(plan.steps) > 0
        actions = [s.action for s in plan.steps]
        assert "search_logs" in actions
        assert "create_ticket" in actions

    @pytest.mark.asyncio
    async def test_default_plan_has_dependencies(self, agent):
        plan = await agent.plan_response(
            incident_summary="Test",
            incident_severity="high",
            incident_type="phishing",
        )
        # Steps should form a chain (each depends on previous)
        for i, step in enumerate(plan.steps):
            if i > 0:
                assert len(step.depends_on) > 0

    @pytest.mark.asyncio
    async def test_default_plan_risk_assessment(self, agent):
        plan = await agent.plan_response(
            incident_summary="Malware",
            incident_severity="critical",
            incident_type="malware",
        )
        # Malware plan has high-risk steps
        assert plan.total_risk >= RiskLevel.HIGH

    @pytest.mark.asyncio
    async def test_default_plan_duration(self, agent):
        plan = await agent.plan_response(
            incident_summary="Test",
            incident_severity="high",
            incident_type="phishing",
        )
        assert plan.estimated_duration_secs > 0
        total = sum(s.estimated_duration_secs for s in plan.steps)
        assert plan.estimated_duration_secs == total


# =============================================================================
# LLM-based planning tests
# =============================================================================


class TestLLMPlanning:
    @pytest.mark.asyncio
    async def test_llm_plan_generation(self):
        llm_response = json.dumps(
            {
                "summary": "LLM-generated phishing response",
                "reasoning": "Based on indicators",
                "mitre_techniques": ["T1566"],
                "steps": [
                    {
                        "id": "s1",
                        "name": "Quarantine",
                        "description": "Quarantine email",
                        "action": "quarantine_email",
                        "parameters": {"message_id": "abc123"},
                        "risk_level": "medium",
                        "requires_approval": False,
                        "estimated_duration_secs": 30,
                        "depends_on": [],
                    }
                ],
            }
        )

        async def mock_llm(prompt: str) -> str:
            return llm_response

        agent = ResponsePlanningAgent(llm_provider=mock_llm)
        plan = await agent.plan_response(
            incident_summary="Phishing email detected",
            incident_severity="high",
            incident_type="phishing",
        )
        assert plan.summary == "LLM-generated phishing response"
        assert len(plan.steps) == 1
        assert plan.steps[0].action == "quarantine_email"
        assert plan.mitre_techniques == ["T1566"]

    @pytest.mark.asyncio
    async def test_llm_failure_falls_back_to_default(self):
        async def failing_llm(prompt: str) -> str:
            raise RuntimeError("LLM failed")

        agent = ResponsePlanningAgent(llm_provider=failing_llm)
        plan = await agent.plan_response(
            incident_summary="Test",
            incident_severity="high",
            incident_type="phishing",
        )
        # Should get a default plan
        assert len(plan.steps) > 0
        assert "quarantine_email" in [s.action for s in plan.steps]

    @pytest.mark.asyncio
    async def test_llm_markdown_code_fence_parsing(self):
        inner = '{"summary":"test","steps":[{"name":"test",'
        inner += '"description":"test","action":"test"}]}'
        llm_response = f"```json\n{inner}\n```"

        async def mock_llm(prompt: str) -> str:
            return llm_response

        agent = ResponsePlanningAgent(llm_provider=mock_llm)
        plan = await agent.plan_response(
            incident_summary="Test",
            incident_severity="medium",
            incident_type="unknown",
        )
        assert plan.summary == "test"


# =============================================================================
# Plan validation tests
# =============================================================================


class TestPlanValidation:
    @pytest.fixture
    def agent(self):
        return ResponsePlanningAgent()

    def test_valid_plan(self, agent):
        plan = ResponsePlan(
            id="p1",
            incident_id="i1",
            summary="Test",
            steps=[
                ResponseStep(
                    id="s1",
                    name="Search logs",
                    description="Search",
                    action="search_logs",
                    risk_level=RiskLevel.LOW,
                ),
            ],
        )
        result = agent.validate_plan(plan)
        assert result.valid
        assert len(result.errors) == 0

    def test_empty_plan_invalid(self, agent):
        plan = ResponsePlan(id="p1", incident_id="i1", summary="Empty")
        result = agent.validate_plan(plan)
        assert not result.valid
        assert any("no steps" in e for e in result.errors)

    def test_forbidden_action(self, agent):
        plan = ResponsePlan(
            id="p1",
            incident_id="i1",
            summary="Test",
            steps=[
                ResponseStep(
                    id="s1",
                    name="Delete user",
                    description="Delete",
                    action="delete_user",
                ),
            ],
        )
        result = agent.validate_plan(plan)
        assert not result.valid
        assert "s1" in result.blocked_steps

    def test_invalid_dependency(self, agent):
        plan = ResponsePlan(
            id="p1",
            incident_id="i1",
            summary="Test",
            steps=[
                ResponseStep(
                    id="s1",
                    name="Step 1",
                    description="Step",
                    action="search_logs",
                    depends_on=["nonexistent"],
                ),
            ],
        )
        result = agent.validate_plan(plan)
        assert not result.valid
        assert any("nonexistent" in e for e in result.errors)

    def test_circular_dependency(self, agent):
        plan = ResponsePlan(
            id="p1",
            incident_id="i1",
            summary="Test",
            steps=[
                ResponseStep(
                    id="s1",
                    name="Step 1",
                    description="Step",
                    action="search_logs",
                    depends_on=["s2"],
                ),
                ResponseStep(
                    id="s2",
                    name="Step 2",
                    description="Step",
                    action="search_logs",
                    depends_on=["s1"],
                ),
            ],
        )
        result = agent.validate_plan(plan)
        assert not result.valid
        assert any("circular" in e.lower() for e in result.errors)

    def test_high_risk_without_approval_warning(self, agent):
        plan = ResponsePlan(
            id="p1",
            incident_id="i1",
            summary="Test",
            steps=[
                ResponseStep(
                    id="s1",
                    name="Isolate",
                    description="Isolate host",
                    action="isolate_host",
                    risk_level=RiskLevel.HIGH,
                    requires_approval=False,
                ),
            ],
        )
        result = agent.validate_plan(plan)
        assert result.valid  # It's a warning, not an error
        assert len(result.warnings) > 0

    def test_high_risk_without_rollback_warning(self, agent):
        plan = ResponsePlan(
            id="p1",
            incident_id="i1",
            summary="Test",
            steps=[
                ResponseStep(
                    id="s1",
                    name="Isolate",
                    description="Isolate host",
                    action="isolate_host",
                    risk_level=RiskLevel.HIGH,
                    requires_approval=True,
                    rollback_action=None,
                ),
            ],
        )
        result = agent.validate_plan(plan)
        assert any("rollback" in w.lower() for w in result.warnings)

    def test_approval_tracking(self, agent):
        plan = ResponsePlan(
            id="p1",
            incident_id="i1",
            summary="Test",
            steps=[
                ResponseStep(
                    id="s1",
                    name="Search",
                    description="Search",
                    action="search_logs",
                    requires_approval=False,
                ),
                ResponseStep(
                    id="s2",
                    name="Isolate",
                    description="Isolate",
                    action="isolate_host",
                    risk_level=RiskLevel.HIGH,
                    requires_approval=True,
                    rollback_action="unisolate_host",
                    depends_on=["s1"],
                ),
            ],
        )
        result = agent.validate_plan(plan)
        assert result.valid
        assert "s2" in result.requires_approval_steps
        assert "s1" not in result.requires_approval_steps

    def test_too_many_steps(self, agent):
        steps = [
            ResponseStep(
                id=f"s{i}",
                name=f"Step {i}",
                description="Step",
                action="search_logs",
            )
            for i in range(25)
        ]
        plan = ResponsePlan(id="p1", incident_id="i1", summary="Test", steps=steps)
        result = agent.validate_plan(plan)
        assert not result.valid
        assert any("maximum" in e.lower() for e in result.errors)


# =============================================================================
# Risk assessment tests
# =============================================================================


class TestRiskAssessment:
    def test_empty_steps_none_risk(self):
        agent = ResponsePlanningAgent()
        assert agent._assess_total_risk([]) == RiskLevel.NONE

    def test_single_low_risk(self):
        agent = ResponsePlanningAgent()
        steps = [
            ResponseStep(
                id="s1",
                name="Test",
                description="Test",
                action="test",
                risk_level=RiskLevel.LOW,
            )
        ]
        assert agent._assess_total_risk(steps) == RiskLevel.LOW

    def test_highest_risk_wins(self):
        agent = ResponsePlanningAgent()
        steps = [
            ResponseStep(
                id="s1",
                name="Low",
                description="Low",
                action="test",
                risk_level=RiskLevel.LOW,
            ),
            ResponseStep(
                id="s2",
                name="High",
                description="High",
                action="test",
                risk_level=RiskLevel.HIGH,
            ),
            ResponseStep(
                id="s3",
                name="Medium",
                description="Medium",
                action="test",
                risk_level=RiskLevel.MEDIUM,
            ),
        ]
        assert agent._assess_total_risk(steps) == RiskLevel.HIGH


# =============================================================================
# Policy config tests
# =============================================================================


class TestPolicyConfig:
    def test_custom_forbidden_actions(self):
        agent = ResponsePlanningAgent(
            policy_config={"forbidden_actions": ["custom_action"]}
        )
        plan = ResponsePlan(
            id="p1",
            incident_id="i1",
            summary="Test",
            steps=[
                ResponseStep(
                    id="s1",
                    name="Custom",
                    description="Custom",
                    action="custom_action",
                ),
            ],
        )
        result = agent.validate_plan(plan)
        assert not result.valid

    def test_custom_max_risk(self):
        agent = ResponsePlanningAgent(policy_config={"max_risk_level": "medium"})
        plan = ResponsePlan(
            id="p1",
            incident_id="i1",
            summary="Test",
            steps=[
                ResponseStep(
                    id="s1",
                    name="High risk",
                    description="High",
                    action="test_action",
                    risk_level=RiskLevel.HIGH,
                    requires_approval=True,
                    rollback_action="rollback",
                ),
            ],
        )
        result = agent.validate_plan(plan)
        assert not result.valid
        assert "s1" in result.blocked_steps

    def test_protected_targets(self):
        agent = ResponsePlanningAgent(policy_config={"protected_targets": ["prod-db"]})
        plan = ResponsePlan(
            id="p1",
            incident_id="i1",
            summary="Test",
            steps=[
                ResponseStep(
                    id="s1",
                    name="Isolate",
                    description="Isolate",
                    action="isolate_host",
                    parameters={"hostname": "prod-db-01"},
                ),
            ],
        )
        result = agent.validate_plan(plan)
        assert not result.valid
