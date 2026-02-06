"""Tests for the adaptive response executor."""

from __future__ import annotations

import pytest

from tw_ai.agents.adaptive_executor import (
    ActionStatus,
    AdaptiveResponseExecutor,
    ApprovalResponse,
    StepExecutionResult,
)
from tw_ai.agents.response_planner import (
    ResponsePlan,
    ResponseStep,
    RiskLevel,
)

# =============================================================================
# Helpers
# =============================================================================


def make_plan(steps: list[ResponseStep] | None = None) -> ResponsePlan:
    return ResponsePlan(
        id="plan-1",
        incident_id="inc-1",
        summary="Test plan",
        steps=steps or [],
    )


def make_step(
    step_id: str = "s1",
    action: str = "block_ip",
    requires_approval: bool = False,
    depends_on: list[str] | None = None,
    rollback_action: str | None = None,
    risk_level: RiskLevel = RiskLevel.LOW,
) -> ResponseStep:
    return ResponseStep(
        id=step_id,
        name=f"Step {step_id}",
        description=f"Description for {step_id}",
        action=action,
        parameters={"target": "10.0.0.1"},
        risk_level=risk_level,
        requires_approval=requires_approval,
        depends_on=depends_on or [],
        rollback_action=rollback_action,
    )


# =============================================================================
# Basic execution tests
# =============================================================================


class TestBasicExecution:
    @pytest.mark.asyncio
    async def test_empty_plan(self):
        executor = AdaptiveResponseExecutor()
        plan = make_plan(steps=[])
        result = await executor.execute_plan(plan)
        assert result.status == ActionStatus.COMPLETED
        assert result.actions_taken == 0

    @pytest.mark.asyncio
    async def test_single_step_simulated(self):
        executor = AdaptiveResponseExecutor()
        plan = make_plan(steps=[make_step()])
        result = await executor.execute_plan(plan)
        assert result.status == ActionStatus.COMPLETED
        assert result.actions_taken == 1
        assert len(result.step_results) == 1
        assert result.step_results[0].status == ActionStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_multiple_steps(self):
        executor = AdaptiveResponseExecutor()
        plan = make_plan(
            steps=[
                make_step("s1", action="search_logs"),
                make_step("s2", action="block_ip", depends_on=["s1"]),
                make_step("s3", action="create_ticket", depends_on=["s2"]),
            ]
        )
        result = await executor.execute_plan(plan)
        assert result.status == ActionStatus.COMPLETED
        assert result.actions_taken == 3
        assert all(r.status == ActionStatus.COMPLETED for r in result.step_results)

    @pytest.mark.asyncio
    async def test_custom_action_executor(self):
        outputs = []

        async def mock_executor(action, params, context):
            outputs.append(action)
            return {"action": action, "success": True}

        executor = AdaptiveResponseExecutor(action_executor=mock_executor)
        plan = make_plan(steps=[make_step("s1", action="block_ip")])
        result = await executor.execute_plan(plan)
        assert result.status == ActionStatus.COMPLETED
        assert outputs == ["block_ip"]

    @pytest.mark.asyncio
    async def test_total_duration_recorded(self):
        executor = AdaptiveResponseExecutor()
        plan = make_plan(steps=[make_step()])
        result = await executor.execute_plan(plan)
        assert result.total_duration_secs >= 0


# =============================================================================
# Action limit tests
# =============================================================================


class TestActionLimits:
    @pytest.mark.asyncio
    async def test_max_actions_enforced(self):
        executor = AdaptiveResponseExecutor(max_actions=2)
        plan = make_plan(
            steps=[
                make_step("s1"),
                make_step("s2"),
                make_step("s3"),
            ]
        )
        result = await executor.execute_plan(plan)
        completed = sum(
            1 for r in result.step_results if r.status == ActionStatus.COMPLETED
        )
        skipped = sum(
            1 for r in result.step_results if r.status == ActionStatus.SKIPPED
        )
        assert completed == 2
        assert skipped == 1


# =============================================================================
# Dependency tests
# =============================================================================


class TestDependencies:
    @pytest.mark.asyncio
    async def test_failed_dependency_skips_step(self):
        call_count = 0

        async def failing_executor(action, params, context):
            nonlocal call_count
            call_count += 1
            if action == "block_ip":
                raise RuntimeError("Connection failed")
            return {"success": True}

        executor = AdaptiveResponseExecutor(
            action_executor=failing_executor, max_retries=0
        )
        plan = make_plan(
            steps=[
                make_step("s1", action="block_ip"),
                make_step("s2", action="create_ticket", depends_on=["s1"]),
            ]
        )
        result = await executor.execute_plan(plan)
        assert result.step_results[0].status == ActionStatus.FAILED
        assert result.step_results[1].status == ActionStatus.SKIPPED
        assert "Dependencies failed" in result.step_results[1].error

    @pytest.mark.asyncio
    async def test_independent_steps_both_execute(self):
        executor = AdaptiveResponseExecutor()
        plan = make_plan(
            steps=[
                make_step("s1", action="block_ip"),
                make_step("s2", action="search_logs"),  # no dependency on s1
            ]
        )
        result = await executor.execute_plan(plan)
        assert all(r.status == ActionStatus.COMPLETED for r in result.step_results)


# =============================================================================
# Approval tests
# =============================================================================


class TestApproval:
    @pytest.mark.asyncio
    async def test_no_handler_rejects(self):
        executor = AdaptiveResponseExecutor()
        plan = make_plan(steps=[make_step("s1", requires_approval=True)])
        result = await executor.execute_plan(plan)
        assert result.step_results[0].status == ActionStatus.REJECTED

    @pytest.mark.asyncio
    async def test_approval_granted(self):
        async def approve_handler(request):
            return ApprovalResponse(approved=True, approved_by="analyst")

        executor = AdaptiveResponseExecutor(approval_handler=approve_handler)
        plan = make_plan(steps=[make_step("s1", requires_approval=True)])
        result = await executor.execute_plan(plan)
        assert result.step_results[0].status == ActionStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_approval_denied(self):
        async def deny_handler(request):
            return ApprovalResponse(approved=False, reason="Too risky")

        executor = AdaptiveResponseExecutor(approval_handler=deny_handler)
        plan = make_plan(steps=[make_step("s1", requires_approval=True)])
        result = await executor.execute_plan(plan)
        assert result.step_results[0].status == ActionStatus.REJECTED
        assert "Too risky" in result.step_results[0].error

    @pytest.mark.asyncio
    async def test_approval_handler_dict_response(self):
        async def dict_handler(request):
            return {"approved": True, "approved_by": "analyst"}

        executor = AdaptiveResponseExecutor(approval_handler=dict_handler)
        plan = make_plan(steps=[make_step("s1", requires_approval=True)])
        result = await executor.execute_plan(plan)
        assert result.step_results[0].status == ActionStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_approval_handler_error(self):
        async def error_handler(request):
            raise RuntimeError("Handler crashed")

        executor = AdaptiveResponseExecutor(approval_handler=error_handler)
        plan = make_plan(steps=[make_step("s1", requires_approval=True)])
        result = await executor.execute_plan(plan)
        assert result.step_results[0].status == ActionStatus.REJECTED


# =============================================================================
# Retry tests
# =============================================================================


class TestRetries:
    @pytest.mark.asyncio
    async def test_retry_on_failure(self):
        attempts = 0

        async def flaky_executor(action, params, context):
            nonlocal attempts
            attempts += 1
            if attempts < 3:
                raise RuntimeError("Transient error")
            return {"success": True}

        executor = AdaptiveResponseExecutor(
            action_executor=flaky_executor, max_retries=2
        )
        plan = make_plan(steps=[make_step()])
        result = await executor.execute_plan(plan)
        assert result.step_results[0].status == ActionStatus.COMPLETED
        assert result.step_results[0].retries == 2

    @pytest.mark.asyncio
    async def test_exhausted_retries(self):
        async def always_fail(action, params, context):
            raise RuntimeError("Always fails")

        executor = AdaptiveResponseExecutor(action_executor=always_fail, max_retries=1)
        plan = make_plan(steps=[make_step()])
        result = await executor.execute_plan(plan)
        assert result.step_results[0].status == ActionStatus.FAILED
        assert "Always fails" in result.step_results[0].error


# =============================================================================
# Rollback tests
# =============================================================================


class TestRollback:
    @pytest.mark.asyncio
    async def test_rollback_on_failure(self):
        rollback_calls = []

        async def executor(action, params, context):
            if action == "isolate_host":
                raise RuntimeError("Isolation failed")
            if action == "unisolate_host":
                rollback_calls.append(action)
                return {"success": True}
            return {"success": True}

        exec_ = AdaptiveResponseExecutor(action_executor=executor, max_retries=0)
        plan = make_plan(
            steps=[
                make_step(
                    "s1",
                    action="isolate_host",
                    rollback_action="unisolate_host",
                    risk_level=RiskLevel.HIGH,
                )
            ]
        )
        result = await exec_.execute_plan(plan)
        assert result.step_results[0].status == ActionStatus.ROLLED_BACK
        assert rollback_calls == ["unisolate_host"]

    @pytest.mark.asyncio
    async def test_no_rollback_without_action(self):
        async def always_fail(action, params, context):
            raise RuntimeError("Failed")

        exec_ = AdaptiveResponseExecutor(action_executor=always_fail, max_retries=0)
        plan = make_plan(steps=[make_step("s1", rollback_action=None)])
        result = await exec_.execute_plan(plan)
        assert result.step_results[0].status == ActionStatus.FAILED


# =============================================================================
# Escalation tests
# =============================================================================


class TestEscalation:
    @pytest.mark.asyncio
    async def test_escalation_on_many_failures(self):
        async def always_fail(action, params, context):
            raise RuntimeError("Failed")

        exec_ = AdaptiveResponseExecutor(action_executor=always_fail, max_retries=0)
        plan = make_plan(
            steps=[
                make_step("s1"),
                make_step("s2"),
                make_step("s3"),
            ]
        )
        result = await exec_.execute_plan(plan)
        assert result.escalated
        assert result.escalation_reason

    @pytest.mark.asyncio
    async def test_no_escalation_on_single_failure(self):
        call_count = 0

        async def fail_first(action, params, context):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise RuntimeError("First failure")
            return {"success": True}

        exec_ = AdaptiveResponseExecutor(action_executor=fail_first, max_retries=0)
        plan = make_plan(
            steps=[
                make_step("s1"),
                make_step("s2"),
            ]
        )
        result = await exec_.execute_plan(plan)
        assert not result.escalated

    def test_should_escalate_logic(self):
        exec_ = AdaptiveResponseExecutor()

        # Empty results
        assert exec_._should_escalate({}, []) == (False, "")

        # 3 consecutive failures at the end (with some successes before)
        results = [
            StepExecutionResult(step_id="s0", status=ActionStatus.COMPLETED),
            StepExecutionResult(step_id="s1", status=ActionStatus.COMPLETED),
            StepExecutionResult(step_id="s2", status=ActionStatus.COMPLETED),
            StepExecutionResult(step_id="s3", status=ActionStatus.COMPLETED),
            StepExecutionResult(step_id="s4", status=ActionStatus.FAILED),
            StepExecutionResult(step_id="s5", status=ActionStatus.FAILED),
            StepExecutionResult(step_id="s6", status=ActionStatus.FAILED),
        ]
        should, reason = exec_._should_escalate({}, results)
        assert should
        assert "consecutive" in reason

        # Mixed results (1 failure, 2 successes) - no escalation
        results2 = [
            StepExecutionResult(step_id="s1", status=ActionStatus.COMPLETED),
            StepExecutionResult(step_id="s2", status=ActionStatus.FAILED),
            StepExecutionResult(step_id="s3", status=ActionStatus.COMPLETED),
        ]
        should2, _ = exec_._should_escalate({}, results2)
        assert not should2


# =============================================================================
# Execution order tests
# =============================================================================


class TestExecutionOrder:
    def test_topological_sort(self):
        exec_ = AdaptiveResponseExecutor()
        steps = [
            make_step("s3", depends_on=["s2"]),
            make_step("s1"),
            make_step("s2", depends_on=["s1"]),
        ]
        ordered = exec_._resolve_execution_order(steps)
        ids = [s.id for s in ordered]
        assert ids.index("s1") < ids.index("s2")
        assert ids.index("s2") < ids.index("s3")

    def test_independent_steps_order(self):
        exec_ = AdaptiveResponseExecutor()
        steps = [
            make_step("s1"),
            make_step("s2"),
        ]
        ordered = exec_._resolve_execution_order(steps)
        assert len(ordered) == 2
