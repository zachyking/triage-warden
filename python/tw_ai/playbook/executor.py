"""Playbook executor for running playbook workflows.

This module provides:
- Asynchronous playbook execution
- Parallel step execution within stages
- Conditional branching based on stage results
- Template variable resolution
"""

from __future__ import annotations

import asyncio
import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

import structlog

from tw_ai.playbook.loader import Branch, Playbook, Stage, Step

logger = structlog.get_logger()


# =============================================================================
# Action Handler Protocol
# =============================================================================


class ActionHandler(Protocol):
    """Protocol for action handlers."""

    async def __call__(self, action: str, input_data: dict[str, Any]) -> dict[str, Any]:
        """Execute an action with the given input.

        Args:
            action: The action name to execute
            input_data: Input parameters for the action

        Returns:
            Dict containing the action results
        """
        ...


# =============================================================================
# Execution Results
# =============================================================================


@dataclass
class StepResult:
    """Result of executing a single step."""

    action: str
    success: bool
    output: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    execution_time_ms: int = 0
    skipped: bool = False
    skip_reason: str | None = None
    requires_approval: bool = False
    approved: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "action": self.action,
            "success": self.success,
            "output": self.output,
            "error": self.error,
            "execution_time_ms": self.execution_time_ms,
            "skipped": self.skipped,
            "skip_reason": self.skip_reason,
            "requires_approval": self.requires_approval,
            "approved": self.approved,
        }


@dataclass
class StageResult:
    """Result of executing a stage."""

    name: str
    success: bool
    steps: list[StepResult] = field(default_factory=list)
    branch_taken: str | None = None
    execution_time_ms: int = 0
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "name": self.name,
            "success": self.success,
            "steps": [s.to_dict() for s in self.steps],
            "branch_taken": self.branch_taken,
            "execution_time_ms": self.execution_time_ms,
            "error": self.error,
        }

    def get_outputs(self) -> dict[str, Any]:
        """Get aggregated outputs from all successful steps."""
        outputs: dict[str, Any] = {}
        for step in self.steps:
            if step.success and not step.skipped:
                outputs.update(step.output)
        return outputs


@dataclass
class ExecutionResult:
    """Result of executing a complete playbook."""

    success: bool
    stages_completed: int = 0
    total_stages: int = 0
    final_state: dict[str, Any] = field(default_factory=dict)
    actions_taken: list[dict[str, Any]] = field(default_factory=list)
    stage_results: list[StageResult] = field(default_factory=list)
    execution_time_seconds: float = 0.0
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "success": self.success,
            "stages_completed": self.stages_completed,
            "total_stages": self.total_stages,
            "final_state": self.final_state,
            "actions_taken": self.actions_taken,
            "stage_results": [s.to_dict() for s in self.stage_results],
            "execution_time_seconds": self.execution_time_seconds,
            "error": self.error,
        }


# =============================================================================
# Execution Context
# =============================================================================


@dataclass
class ExecutionContext:
    """Context for playbook execution.

    Contains:
    - Input parameters
    - Stage outputs
    - Variable resolution
    """

    input: dict[str, Any] = field(default_factory=dict)
    stages: dict[str, dict[str, Any]] = field(default_factory=dict)
    trigger: dict[str, Any] = field(default_factory=dict)

    def get(self, path: str, default: Any = None) -> Any:
        """Get a value by dotted path.

        Args:
            path: Dotted path like 'input.message_id' or 'extraction.urls'
            default: Default value if path not found

        Returns:
            The value at the path or default
        """
        parts = path.split(".")
        if not parts:
            return default

        root = parts[0]
        rest = parts[1:]

        if root == "input":
            value = self.input
        elif root == "trigger":
            value = self.trigger
        elif root in self.stages:
            value = self.stages[root]
        else:
            return default

        for part in rest:
            if isinstance(value, dict):
                value = value.get(part)
                if value is None:
                    return default
            else:
                return default

        return value

    def set_stage_output(self, stage_name: str, outputs: dict[str, Any]) -> None:
        """Set outputs for a stage.

        Args:
            stage_name: Name of the stage
            outputs: Output values to store
        """
        if stage_name not in self.stages:
            self.stages[stage_name] = {}
        self.stages[stage_name].update(outputs)

    def to_dict(self) -> dict[str, Any]:
        """Convert context to a flat dictionary for condition evaluation."""
        result = {
            "input": self.input,
            "trigger": self.trigger,
        }
        result.update(self.stages)
        return result


# =============================================================================
# Playbook Executor
# =============================================================================


class PlaybookExecutor:
    """Executor for running playbook workflows.

    This class handles:
    - Sequential stage execution
    - Parallel step execution within stages
    - Conditional branching based on results
    - Template variable resolution

    Example:
        executor = PlaybookExecutor(action_handler=my_handler)
        result = await executor.execute(playbook, {"message_id": "123"})
        if result.success:
            print(f"Completed {result.stages_completed} stages")
    """

    # Template variable pattern: {{ variable.path }}
    TEMPLATE_PATTERN = re.compile(r"\{\{\s*([a-zA-Z_][a-zA-Z0-9_.]*)\s*\}\}")

    def __init__(
        self,
        action_handler: ActionHandler | None = None,
        approval_handler: Callable[[str, dict[str, Any]], Awaitable[bool]] | None = None,
        max_parallel_steps: int = 10,
    ) -> None:
        """Initialize the playbook executor.

        Args:
            action_handler: Handler function for executing actions
            approval_handler: Handler function for approval requests
            max_parallel_steps: Maximum number of steps to run in parallel
        """
        self._action_handler = action_handler or self._default_action_handler
        self._approval_handler = approval_handler
        self._max_parallel_steps = max_parallel_steps
        self._logger = logger.bind(component="playbook_executor")

    async def execute(
        self,
        playbook: Playbook,
        context: dict[str, Any],
        trigger_data: dict[str, Any] | None = None,
    ) -> ExecutionResult:
        """Execute a playbook with the given context.

        Args:
            playbook: The playbook to execute
            context: Input parameters for the playbook
            trigger_data: Optional trigger event data

        Returns:
            ExecutionResult with details of the execution
        """
        start_time = time.time()

        self._logger.info(
            "playbook_execution_start",
            playbook=playbook.name,
            version=playbook.version,
            input_keys=list(context.keys()),
        )

        # Initialize execution context
        exec_context = ExecutionContext(
            input=context,
            trigger=trigger_data or {},
        )

        stage_results: list[StageResult] = []
        actions_taken: list[dict[str, Any]] = []
        stages_completed = 0
        error: str | None = None

        try:
            for stage in playbook.stages:
                self._logger.info(
                    "stage_execution_start",
                    stage=stage.name,
                    parallel=stage.parallel,
                    has_branches=bool(stage.branches),
                )

                stage_result = await self._execute_stage(stage, exec_context)
                stage_results.append(stage_result)

                # Collect actions taken
                for step_result in stage_result.steps:
                    if not step_result.skipped:
                        actions_taken.append(
                            {
                                "stage": stage.name,
                                "action": step_result.action,
                                "success": step_result.success,
                                "output": step_result.output,
                            }
                        )

                # Update context with stage outputs
                exec_context.set_stage_output(stage.name, stage_result.get_outputs())

                if stage_result.success:
                    stages_completed += 1
                else:
                    self._logger.error(
                        "stage_execution_failed",
                        stage=stage.name,
                        error=stage_result.error,
                    )
                    error = f"Stage '{stage.name}' failed: {stage_result.error}"
                    break

        except Exception as e:
            self._logger.error(
                "playbook_execution_error",
                playbook=playbook.name,
                error=str(e),
                exc_info=True,
            )
            error = str(e)

        execution_time = time.time() - start_time

        result = ExecutionResult(
            success=error is None and stages_completed == len(playbook.stages),
            stages_completed=stages_completed,
            total_stages=len(playbook.stages),
            final_state=exec_context.to_dict(),
            actions_taken=actions_taken,
            stage_results=stage_results,
            execution_time_seconds=execution_time,
            error=error,
        )

        self._logger.info(
            "playbook_execution_complete",
            playbook=playbook.name,
            success=result.success,
            stages_completed=stages_completed,
            total_stages=len(playbook.stages),
            execution_time_seconds=execution_time,
        )

        return result

    async def _execute_stage(
        self,
        stage: Stage,
        context: ExecutionContext,
    ) -> StageResult:
        """Execute a single stage."""
        start_time = time.time()

        # Check if this is a branching stage
        if stage.branches:
            return await self._execute_branching_stage(stage, context)

        # Execute regular stage
        if stage.parallel:
            step_results = await self._execute_steps_parallel(stage.steps, context)
        else:
            step_results = await self._execute_steps_sequential(stage.steps, context)

        execution_time_ms = int((time.time() - start_time) * 1000)

        # Determine overall success
        success = all(r.success or r.skipped for r in step_results)

        # Find first error if any
        error = None
        for r in step_results:
            if not r.success and not r.skipped:
                error = r.error
                break

        return StageResult(
            name=stage.name,
            success=success,
            steps=step_results,
            execution_time_ms=execution_time_ms,
            error=error,
        )

    async def _execute_branching_stage(
        self,
        stage: Stage,
        context: ExecutionContext,
    ) -> StageResult:
        """Execute a stage with conditional branches."""
        start_time = time.time()
        context_dict = context.to_dict()

        # Find the first matching branch
        matched_branch: tuple[str, Branch] | None = None
        for branch_name, branch in stage.branches.items():
            if branch.evaluate_conditions(context_dict):
                matched_branch = (branch_name, branch)
                self._logger.info(
                    "branch_matched",
                    stage=stage.name,
                    branch=branch_name,
                )
                break

        if matched_branch is None:
            self._logger.warning(
                "no_branch_matched",
                stage=stage.name,
            )
            return StageResult(
                name=stage.name,
                success=True,  # No branch matched is not necessarily an error
                execution_time_ms=int((time.time() - start_time) * 1000),
            )

        branch_name, branch = matched_branch

        # Execute branch steps
        step_results = await self._execute_steps_sequential(branch.steps, context)

        execution_time_ms = int((time.time() - start_time) * 1000)

        success = all(r.success or r.skipped for r in step_results)
        error = None
        for r in step_results:
            if not r.success and not r.skipped:
                error = r.error
                break

        return StageResult(
            name=stage.name,
            success=success,
            steps=step_results,
            branch_taken=branch_name,
            execution_time_ms=execution_time_ms,
            error=error,
        )

    async def _execute_steps_sequential(
        self,
        steps: list[Step],
        context: ExecutionContext,
    ) -> list[StepResult]:
        """Execute steps sequentially."""
        results: list[StepResult] = []

        for step in steps:
            result = await self._execute_step(step, context)
            results.append(result)

            # Update context with step outputs if successful
            if result.success and not result.skipped:
                # Add outputs to current stage context for subsequent steps
                for key, value in result.output.items():
                    context.stages.setdefault("_current", {})[key] = value

        return results

    async def _execute_steps_parallel(
        self,
        steps: list[Step],
        context: ExecutionContext,
    ) -> list[StepResult]:
        """Execute steps in parallel."""
        # Create semaphore to limit parallelism
        semaphore = asyncio.Semaphore(self._max_parallel_steps)

        async def execute_with_semaphore(step: Step) -> StepResult:
            async with semaphore:
                return await self._execute_step(step, context)

        # Execute all steps concurrently
        tasks = [execute_with_semaphore(step) for step in steps]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Convert exceptions to StepResults
        processed_results: list[StepResult] = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                processed_results.append(
                    StepResult(
                        action=steps[i].action,
                        success=False,
                        error=str(result),
                    )
                )
            else:
                processed_results.append(result)

        return processed_results

    async def _execute_step(
        self,
        step: Step,
        context: ExecutionContext,
    ) -> StepResult:
        """Execute a single step."""
        start_time = time.time()

        # Check conditions
        if step.conditions:
            context_dict = context.to_dict()
            for condition in step.conditions:
                if not condition.evaluate(context_dict):
                    self._logger.info(
                        "step_skipped_condition",
                        action=step.action,
                    )
                    return StepResult(
                        action=step.action,
                        success=True,
                        skipped=True,
                        skip_reason="Condition not met",
                    )

        # Check approval requirement
        if step.requires_approval:
            if self._approval_handler:
                resolved_input = self._resolve_templates(step.input, context)
                approved = await self._approval_handler(step.action, resolved_input)
                if not approved:
                    self._logger.info(
                        "step_skipped_approval",
                        action=step.action,
                    )
                    return StepResult(
                        action=step.action,
                        success=True,
                        skipped=True,
                        skip_reason="Approval denied",
                        requires_approval=True,
                        approved=False,
                    )
            else:
                # No approval handler, mark as pending
                self._logger.info(
                    "step_pending_approval",
                    action=step.action,
                )
                return StepResult(
                    action=step.action,
                    success=True,
                    skipped=True,
                    skip_reason="Awaiting approval",
                    requires_approval=True,
                    approved=None,
                )

        # Resolve template variables in input
        resolved_input = self._resolve_templates(step.input, context)

        self._logger.debug(
            "step_execution_start",
            action=step.action,
            input_keys=list(resolved_input.keys()),
        )

        try:
            # Execute the action
            output = await self._action_handler(step.action, resolved_input)

            execution_time_ms = int((time.time() - start_time) * 1000)

            self._logger.info(
                "step_execution_success",
                action=step.action,
                execution_time_ms=execution_time_ms,
            )

            return StepResult(
                action=step.action,
                success=True,
                output=output,
                execution_time_ms=execution_time_ms,
                requires_approval=step.requires_approval,
                approved=True if step.requires_approval else None,
            )

        except Exception as e:
            execution_time_ms = int((time.time() - start_time) * 1000)

            self._logger.error(
                "step_execution_error",
                action=step.action,
                error=str(e),
                execution_time_ms=execution_time_ms,
            )

            return StepResult(
                action=step.action,
                success=False,
                error=str(e),
                execution_time_ms=execution_time_ms,
            )

    def _resolve_templates(
        self,
        data: Any,
        context: ExecutionContext,
    ) -> Any:
        """Resolve template variables in data.

        Handles patterns like {{ input.message_id }} or {{ extraction.urls }}

        Args:
            data: Data structure with potential template variables
            context: Execution context for variable resolution

        Returns:
            Data with resolved variables
        """
        if isinstance(data, str):
            # Check for template pattern
            def replace_match(match: re.Match) -> str:
                path = match.group(1)
                value = context.get(path, match.group(0))  # Return original if not found
                if isinstance(value, str):
                    return value
                elif value is not None:
                    return str(value)
                return match.group(0)

            # Check if the entire string is a single template
            full_match = self.TEMPLATE_PATTERN.fullmatch(data.strip())
            if full_match:
                path = full_match.group(1)
                value = context.get(path)
                if value is not None:
                    return value  # Return the actual type, not string
                return data

            # Replace embedded templates
            return self.TEMPLATE_PATTERN.sub(replace_match, data)

        elif isinstance(data, dict):
            return {key: self._resolve_templates(value, context) for key, value in data.items()}

        elif isinstance(data, list):
            return [self._resolve_templates(item, context) for item in data]

        return data

    async def _default_action_handler(
        self,
        action: str,
        input_data: dict[str, Any],
    ) -> dict[str, Any]:
        """Default action handler that logs actions but doesn't execute them.

        This is used when no action handler is provided, useful for dry-run testing.
        """
        self._logger.info(
            "default_action_handler",
            action=action,
            input_keys=list(input_data.keys()),
        )
        return {
            "action": action,
            "status": "simulated",
            "input": input_data,
        }
