"""Adaptive response executor with feedback loop."""

from __future__ import annotations

import time
from enum import Enum
from typing import Any

import structlog
from pydantic import BaseModel, Field

from tw_ai.agents.response_planner import ResponsePlan, ResponseStep

logger = structlog.get_logger()


class ActionStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    APPROVAL_PENDING = "approval_pending"
    REJECTED = "rejected"
    ROLLED_BACK = "rolled_back"


class StepExecutionResult(BaseModel):
    """Result of executing a single response step."""

    step_id: str
    status: ActionStatus
    output: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    duration_secs: float = 0.0
    retries: int = 0


class ExecutionResult(BaseModel):
    """Result of executing a complete response plan."""

    plan_id: str
    status: ActionStatus
    step_results: list[StepExecutionResult] = Field(default_factory=list)
    total_duration_secs: float = 0.0
    actions_taken: int = 0
    actions_failed: int = 0
    actions_skipped: int = 0
    escalated: bool = False
    escalation_reason: str | None = None


class ApprovalRequest(BaseModel):
    """Request for human approval of an action."""

    step_id: str
    action: str
    parameters: dict[str, Any]
    risk_level: str
    reason: str


class ApprovalResponse(BaseModel):
    """Response to an approval request."""

    approved: bool
    reason: str = ""
    approved_by: str = ""


class AdaptiveResponseExecutor:
    """Executes response plans with real-time adaptation."""

    def __init__(
        self,
        max_actions: int = 20,
        max_retries: int = 2,
        approval_handler: Any = None,
        llm_provider: Any = None,
        action_executor: Any = None,
    ):
        self._max_actions = max_actions
        self._max_retries = max_retries
        self._approval_handler = approval_handler
        self._llm = llm_provider
        self._action_executor = action_executor
        self._action_count = 0

    async def execute_plan(self, plan: ResponsePlan) -> ExecutionResult:
        """Execute a response plan with adaptive behavior."""
        self._action_count = 0
        start_time = time.monotonic()

        step_results: list[StepExecutionResult] = []
        completed_ids: set[str] = set()
        failed_ids: set[str] = set()

        # Build execution order from dependency graph
        execution_order = self._resolve_execution_order(plan.steps)

        for step in execution_order:
            # Check action limit
            if self._action_count >= self._max_actions:
                logger.warning(
                    "Action limit reached",
                    max_actions=self._max_actions,
                    plan_id=plan.id,
                )
                step_results.append(
                    StepExecutionResult(
                        step_id=step.id,
                        status=ActionStatus.SKIPPED,
                        error="Action limit reached",
                    )
                )
                continue

            # Check if dependencies are satisfied
            unmet_deps = [d for d in step.depends_on if d not in completed_ids]
            failed_deps = [d for d in step.depends_on if d in failed_ids]

            if failed_deps:
                logger.info(
                    "Skipping step due to failed dependencies",
                    step_id=step.id,
                    failed_deps=failed_deps,
                )
                step_results.append(
                    StepExecutionResult(
                        step_id=step.id,
                        status=ActionStatus.SKIPPED,
                        error=f"Dependencies failed: {', '.join(failed_deps)}",
                    )
                )
                continue

            if unmet_deps:
                logger.info(
                    "Skipping step due to unmet dependencies",
                    step_id=step.id,
                    unmet_deps=unmet_deps,
                )
                step_results.append(
                    StepExecutionResult(
                        step_id=step.id,
                        status=ActionStatus.SKIPPED,
                        error=f"Unmet dependencies: {', '.join(unmet_deps)}",
                    )
                )
                continue

            # Build context from previous results
            context = {
                "plan_id": plan.id,
                "incident_id": plan.incident_id,
                "completed_steps": list(completed_ids),
                "previous_results": {r.step_id: r.output for r in step_results},
            }

            # Handle approval
            if step.requires_approval:
                approval = await self._request_approval(step)
                if not approval.approved:
                    logger.info(
                        "Step rejected by approver",
                        step_id=step.id,
                        reason=approval.reason,
                    )
                    step_results.append(
                        StepExecutionResult(
                            step_id=step.id,
                            status=ActionStatus.REJECTED,
                            error=f"Rejected: {approval.reason}",
                        )
                    )
                    failed_ids.add(step.id)
                    continue

            result = await self._execute_step(step, context)
            step_results.append(result)

            if result.status == ActionStatus.COMPLETED:
                completed_ids.add(step.id)
                self._action_count += 1
            elif result.status == ActionStatus.FAILED:
                failed_ids.add(step.id)
                self._action_count += 1

                # Try rollback
                if step.rollback_action:
                    rollback_ok = await self._rollback_step(step, result)
                    if rollback_ok:
                        result.status = ActionStatus.ROLLED_BACK

                # Check if we should escalate
                should_escalate, reason = self._should_escalate(context, step_results)
                if should_escalate:
                    elapsed = time.monotonic() - start_time
                    return ExecutionResult(
                        plan_id=plan.id,
                        status=ActionStatus.FAILED,
                        step_results=step_results,
                        total_duration_secs=round(elapsed, 2),
                        actions_taken=sum(
                            1
                            for r in step_results
                            if r.status in (ActionStatus.COMPLETED, ActionStatus.FAILED)
                        ),
                        actions_failed=sum(
                            1 for r in step_results if r.status == ActionStatus.FAILED
                        ),
                        actions_skipped=sum(
                            1 for r in step_results if r.status == ActionStatus.SKIPPED
                        ),
                        escalated=True,
                        escalation_reason=reason,
                    )

        elapsed = time.monotonic() - start_time
        actions_taken = sum(
            1
            for r in step_results
            if r.status in (ActionStatus.COMPLETED, ActionStatus.FAILED, ActionStatus.ROLLED_BACK)
        )
        actions_failed = sum(
            1 for r in step_results if r.status in (ActionStatus.FAILED, ActionStatus.ROLLED_BACK)
        )
        actions_skipped = sum(
            1 for r in step_results if r.status in (ActionStatus.SKIPPED, ActionStatus.REJECTED)
        )

        overall_status = ActionStatus.COMPLETED
        if actions_failed > 0 and actions_failed == len(step_results):
            overall_status = ActionStatus.FAILED
        elif actions_failed > 0:
            overall_status = ActionStatus.COMPLETED  # partial success

        return ExecutionResult(
            plan_id=plan.id,
            status=overall_status,
            step_results=step_results,
            total_duration_secs=round(elapsed, 2),
            actions_taken=actions_taken,
            actions_failed=actions_failed,
            actions_skipped=actions_skipped,
            escalated=False,
        )

    async def _execute_step(
        self, step: ResponseStep, context: dict[str, Any]
    ) -> StepExecutionResult:
        """Execute a single step with retries."""
        retries = 0
        last_error: str | None = None

        while retries <= self._max_retries:
            start = time.monotonic()
            try:
                if self._action_executor is not None:
                    output = await self._action_executor(step.action, step.parameters, context)
                else:
                    # Simulate execution when no executor is provided
                    output = {
                        "action": step.action,
                        "status": "simulated",
                        "parameters": step.parameters,
                    }

                elapsed = time.monotonic() - start
                return StepExecutionResult(
                    step_id=step.id,
                    status=ActionStatus.COMPLETED,
                    output=(output if isinstance(output, dict) else {"result": str(output)}),
                    duration_secs=round(elapsed, 2),
                    retries=retries,
                )
            except Exception as exc:
                elapsed = time.monotonic() - start
                last_error = str(exc)
                retries += 1
                logger.warning(
                    "Step execution failed",
                    step_id=step.id,
                    action=step.action,
                    retry=retries,
                    error=last_error,
                )

                if retries <= self._max_retries:
                    # Try to find an alternative
                    alt = await self._find_alternative(step, last_error)
                    if alt is not None:
                        step = alt

        elapsed = time.monotonic() - start
        return StepExecutionResult(
            step_id=step.id,
            status=ActionStatus.FAILED,
            error=last_error,
            duration_secs=round(elapsed, 2),
            retries=retries - 1,
        )

    async def _request_approval(self, step: ResponseStep) -> ApprovalResponse:
        """Request human approval for a step."""
        request = ApprovalRequest(
            step_id=step.id,
            action=step.action,
            parameters=step.parameters,
            risk_level=step.risk_level.value,
            reason=(
                f"Action '{step.action}' (risk: {step.risk_level.value})"
                f" requires approval: {step.description}"
            ),
        )

        if self._approval_handler is not None:
            try:
                response = await self._approval_handler(request)
                if isinstance(response, ApprovalResponse):
                    return response
                if isinstance(response, dict):
                    return ApprovalResponse(**response)
                return ApprovalResponse(
                    approved=bool(response),
                    reason="Handler returned non-dict response",
                )
            except Exception as exc:
                logger.error(
                    "Approval handler failed",
                    step_id=step.id,
                    error=str(exc),
                )
                return ApprovalResponse(
                    approved=False,
                    reason=f"Approval handler error: {exc}",
                )

        # Default: reject if no handler
        return ApprovalResponse(
            approved=False,
            reason="No approval handler configured",
        )

    async def _find_alternative(self, failed_step: ResponseStep, error: str) -> ResponseStep | None:
        """Find alternative action when a step fails."""
        if self._llm is None:
            return None

        try:
            prompt = (
                f"The action '{failed_step.action}' failed with error: {error}\n"
                f"Original step: {failed_step.name} - {failed_step.description}\n"
                "Suggest an alternative action as JSON with fields: "
                "action, parameters, description. Or respond with null if no alternative."
            )
            response = await self._llm(prompt)
            if not response or response.strip().lower() == "null":
                return None

            import json

            data = json.loads(response)
            return ResponseStep(
                id=failed_step.id,
                name=f"Alternative: {data.get('description', failed_step.name)}",
                description=data.get("description", failed_step.description),
                action=data.get("action", failed_step.action),
                parameters=data.get("parameters", failed_step.parameters),
                risk_level=failed_step.risk_level,
                requires_approval=failed_step.requires_approval,
                estimated_duration_secs=failed_step.estimated_duration_secs,
                depends_on=failed_step.depends_on,
                rollback_action=failed_step.rollback_action,
                rollback_parameters=failed_step.rollback_parameters,
            )
        except Exception:
            logger.debug("Could not find alternative action", exc_info=True)
            return None

    async def _rollback_step(self, step: ResponseStep, result: StepExecutionResult) -> bool:
        """Attempt to rollback a failed step."""
        if not step.rollback_action:
            return False

        logger.info(
            "Attempting rollback",
            step_id=step.id,
            rollback_action=step.rollback_action,
        )

        try:
            if self._action_executor is not None:
                await self._action_executor(step.rollback_action, step.rollback_parameters, {})
            logger.info("Rollback succeeded", step_id=step.id)
            return True
        except Exception as exc:
            logger.error(
                "Rollback failed",
                step_id=step.id,
                rollback_action=step.rollback_action,
                error=str(exc),
            )
            return False

    def _should_escalate(
        self,
        context: dict[str, Any],
        results: list[StepExecutionResult],
    ) -> tuple[bool, str]:
        """Determine if the execution should be escalated."""
        if not results:
            return False, ""

        failed_count = sum(1 for r in results if r.status == ActionStatus.FAILED)
        total_count = len(results)

        # Escalate if more than half of steps failed
        if total_count >= 3 and failed_count > total_count / 2:
            return True, f"Too many failures: {failed_count}/{total_count} steps failed"

        # Escalate if 3+ consecutive failures
        consecutive_failures = 0
        for r in reversed(results):
            if r.status == ActionStatus.FAILED:
                consecutive_failures += 1
            else:
                break
        if consecutive_failures >= 3:
            return True, f"{consecutive_failures} consecutive step failures"

        return False, ""

    def _resolve_execution_order(self, steps: list[ResponseStep]) -> list[ResponseStep]:
        """Resolve step execution order based on dependencies (topological sort)."""
        step_map = {s.id: s for s in steps}
        visited: set[str] = set()
        order: list[str] = []

        def visit(step_id: str) -> None:
            if step_id in visited:
                return
            visited.add(step_id)
            step = step_map.get(step_id)
            if step is None:
                return
            for dep in step.depends_on:
                visit(dep)
            order.append(step_id)

        for s in steps:
            visit(s.id)

        return [step_map[sid] for sid in order if sid in step_map]
