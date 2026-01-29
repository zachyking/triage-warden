"""ReAct (Reasoning + Acting) agent implementation for security triage.

This module provides a production-ready ReAct agent with:
- Configurable iteration limits, token budgets, and timeouts
- Token counting and budget enforcement using tiktoken
- Retry logic with exponential backoff for tool failures
- Structured logging with structlog
- Execution timeout support via asyncio.timeout
- Full execution trace for debugging and observability
- Streaming callbacks for UI updates
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Awaitable, Protocol, Optional

import structlog

try:
    import tiktoken
    _TIKTOKEN_AVAILABLE = True
except ImportError:
    tiktoken = None
    _TIKTOKEN_AVAILABLE = False


# =============================================================================
# Python 3.9/3.10 compatibility for asyncio.timeout
# =============================================================================

if sys.version_info >= (3, 11):
    # Python 3.11+ has native asyncio.timeout
    async_timeout = asyncio.timeout
else:
    # Fallback for Python 3.9/3.10
    @asynccontextmanager
    async def async_timeout(delay: Optional[float]):
        """Async context manager for timeout (Python 3.9/3.10 compatibility).

        Args:
            delay: Timeout in seconds. If None, no timeout is applied.
        """
        if delay is None:
            yield
            return

        task = asyncio.current_task()
        if task is None:
            yield
            return

        loop = asyncio.get_event_loop()
        handle = loop.call_later(delay, task.cancel)
        try:
            yield
        except asyncio.CancelledError:
            raise asyncio.TimeoutError()
        finally:
            handle.cancel()

from tw_ai.llm.base import LLMProvider, LLMResponse, Message, Role, ToolDefinition
from tw_ai.agents.tools import Tool, ToolRegistry
from tw_ai.agents.models import TriageAnalysis
from tw_ai.agents.output_parser import parse_triage_analysis, ParseError

logger = structlog.get_logger()


# =============================================================================
# Type Definitions and Callbacks
# =============================================================================


class StepType(str, Enum):
    """Type of step in the execution trace."""
    THOUGHT = "thought"
    ACTION = "action"
    OBSERVATION = "observation"
    ERROR = "error"
    FINAL = "final"


@dataclass
class Step:
    """A single step in the agent's execution trace."""

    step_type: StepType
    content: str
    timestamp: float = field(default_factory=time.time)
    tokens_used: int = 0
    tool_name: str | None = None
    tool_arguments: dict[str, Any] | None = None
    tool_result: Any = None
    error: str | None = None
    retry_count: int = 0
    duration_ms: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert step to dictionary for serialization."""
        return {
            "step_type": self.step_type.value,
            "content": self.content,
            "timestamp": self.timestamp,
            "tokens_used": self.tokens_used,
            "tool_name": self.tool_name,
            "tool_arguments": self.tool_arguments,
            "tool_result": self.tool_result,
            "error": self.error,
            "retry_count": self.retry_count,
            "duration_ms": self.duration_ms,
        }


@dataclass
class TriageRequest:
    """Request for triage analysis.

    Attributes:
        alert_type: Type of alert (e.g., "phishing", "malware", "intrusion")
        alert_data: Raw alert data to analyze
        context: Optional additional context
        priority: Optional priority level
    """

    alert_type: str
    alert_data: dict[str, Any]
    context: dict[str, Any] | None = None
    priority: str | None = None

    def to_task_string(self) -> str:
        """Convert request to a task string for the agent."""
        task_parts = [
            f"Triage the following {self.alert_type} alert:",
            "",
            "## Alert Data",
            json.dumps(self.alert_data, indent=2),
        ]

        if self.context:
            task_parts.extend([
                "",
                "## Additional Context",
                json.dumps(self.context, indent=2),
            ])

        if self.priority:
            task_parts.extend([
                "",
                f"## Priority: {self.priority}",
            ])

        task_parts.extend([
            "",
            "Analyze this alert thoroughly and provide your verdict.",
        ])

        return "\n".join(task_parts)


@dataclass
class AgentResult:
    """Result from an agent execution.

    Attributes:
        success: Whether the execution completed successfully
        analysis: Parsed TriageAnalysis if successful
        execution_trace: Full list of steps for debugging
        tokens_used: Total tokens consumed
        execution_time_seconds: Wall-clock execution time
        error: Error message if failed
        raw_output: Raw LLM output (useful for debugging)
    """

    success: bool
    analysis: TriageAnalysis | None = None
    execution_trace: list[Step] = field(default_factory=list)
    tokens_used: int = 0
    execution_time_seconds: float = 0.0
    error: str | None = None
    raw_output: str | None = None

    # Legacy fields for backward compatibility
    output: str = ""
    reasoning: list[str] = field(default_factory=list)
    actions_taken: list[dict[str, Any]] = field(default_factory=list)
    tool_calls: int = 0
    total_tokens: int = 0

    def __post_init__(self):
        """Populate legacy fields from new fields."""
        if self.analysis:
            self.output = self.analysis.summary
            self.reasoning = [self.analysis.reasoning] if self.analysis.reasoning else []
        elif self.raw_output:
            self.output = self.raw_output

        # Populate actions_taken from execution trace
        for step in self.execution_trace:
            if step.step_type == StepType.ACTION and step.tool_name:
                self.actions_taken.append({
                    "tool": step.tool_name,
                    "arguments": step.tool_arguments,
                    "result_preview": str(step.tool_result)[:200] if step.tool_result else "",
                })

        self.tool_calls = len(self.actions_taken)
        self.total_tokens = self.tokens_used


class OnThoughtCallback(Protocol):
    """Callback protocol for thought events."""
    async def __call__(self, thought: str, step: Step) -> None: ...


class OnActionCallback(Protocol):
    """Callback protocol for action events."""
    async def __call__(self, tool_name: str, arguments: dict[str, Any], step: Step) -> None: ...


class OnObservationCallback(Protocol):
    """Callback protocol for observation events."""
    async def __call__(self, result: Any, step: Step) -> None: ...


# =============================================================================
# Token Counter
# =============================================================================


class TokenCounter:
    """Counts tokens using tiktoken or fallback estimation."""

    def __init__(self, model: str = "gpt-4"):
        """Initialize token counter.

        Args:
            model: Model name for tiktoken encoding
        """
        self.model = model
        self._encoder = None

        if _TIKTOKEN_AVAILABLE:
            try:
                self._encoder = tiktoken.encoding_for_model(model)
            except KeyError:
                # Fall back to cl100k_base for unknown models
                try:
                    self._encoder = tiktoken.get_encoding("cl100k_base")
                except Exception:
                    logger.warning("tiktoken_encoding_failed", model=model)

    def count(self, text: str) -> int:
        """Count tokens in text.

        Args:
            text: Text to count tokens for

        Returns:
            Estimated token count
        """
        if not text:
            return 0

        if self._encoder:
            try:
                return len(self._encoder.encode(text))
            except Exception:
                pass

        # Fallback: estimate ~4 characters per token
        return len(text) // 4

    def count_messages(self, messages: list[Message]) -> int:
        """Count tokens in a list of messages.

        Args:
            messages: List of messages to count

        Returns:
            Estimated total token count
        """
        total = 0
        for msg in messages:
            # Add overhead per message (~4 tokens)
            total += 4
            total += self.count(msg.content)
            if msg.name:
                total += self.count(msg.name)
        return total


# =============================================================================
# ReAct Agent
# =============================================================================


class ReActAgent:
    """
    Production-ready ReAct (Reasoning + Acting) agent for security triage.

    The agent follows this pattern:
    1. Think - Reason about the current state and what to do next
    2. Act - Call a tool to gather information or take action
    3. Observe - Process the tool result
    4. Repeat until the task is complete or limits are reached

    Features:
    - Configurable max_iterations, max_tokens, and timeout_seconds
    - Token counting with tiktoken
    - Tool retry with exponential backoff
    - Structured logging
    - Execution trace for debugging
    - Streaming callbacks for UI updates
    """

    # Default configuration
    DEFAULT_MAX_ITERATIONS = 10
    DEFAULT_MAX_TOKENS = 8000
    DEFAULT_TIMEOUT_SECONDS = 120
    DEFAULT_TOOL_RETRIES = 2
    DEFAULT_RETRY_BASE_DELAY = 1.0  # seconds

    def __init__(
        self,
        llm: LLMProvider,
        tools: ToolRegistry,
        system_prompt: str | None = None,
        max_iterations: int = DEFAULT_MAX_ITERATIONS,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        tool_retries: int = DEFAULT_TOOL_RETRIES,
        retry_base_delay: float = DEFAULT_RETRY_BASE_DELAY,
        on_thought: OnThoughtCallback | None = None,
        on_action: OnActionCallback | None = None,
        on_observation: OnObservationCallback | None = None,
    ):
        """
        Initialize the ReAct agent.

        Args:
            llm: LLM provider for reasoning
            tools: Registry of available tools
            system_prompt: Custom system prompt (uses default if not provided)
            max_iterations: Maximum number of think-act-observe cycles
            max_tokens: Maximum token budget for the entire execution
            timeout_seconds: Overall execution timeout
            tool_retries: Number of retries for failed tool calls
            retry_base_delay: Base delay for exponential backoff
            on_thought: Callback for thought events
            on_action: Callback for action events
            on_observation: Callback for observation events
        """
        self.llm = llm
        self.tools = tools
        self.max_iterations = max_iterations
        self.max_tokens = max_tokens
        self.timeout_seconds = timeout_seconds
        self.tool_retries = tool_retries
        self.retry_base_delay = retry_base_delay
        self.system_prompt = system_prompt or self._default_system_prompt()

        # Callbacks
        self._on_thought = on_thought
        self._on_action = on_action
        self._on_observation = on_observation

        # Token counter
        self._token_counter = TokenCounter()

        logger.info(
            "react_agent_initialized",
            max_iterations=max_iterations,
            max_tokens=max_tokens,
            timeout_seconds=timeout_seconds,
            tool_retries=tool_retries,
            tools_available=tools.list_tools(),
        )

    def _default_system_prompt(self) -> str:
        """Generate the default system prompt for security triage."""
        return """You are an expert Security Operations Center (SOC) analyst AI assistant. Your role is to help triage security incidents by:

1. Analyzing available evidence (alerts, logs, threat intel)
2. Gathering additional context using the available tools
3. Determining if the incident is a true positive, false positive, or needs escalation
4. Recommending appropriate response actions

When analyzing incidents:
- Always verify claims with threat intelligence lookups
- Consider the full context (user behavior, asset criticality, timing)
- Map findings to MITRE ATT&CK framework when applicable
- Be thorough but efficient - don't make unnecessary tool calls

Output your final analysis as a JSON object with this schema:
{
    "verdict": "true_positive" | "false_positive" | "suspicious" | "inconclusive",
    "confidence": 0-100,
    "severity": "critical" | "high" | "medium" | "low" | "informational",
    "summary": "Brief summary of findings",
    "indicators": [{"type": "ip|domain|hash|...", "value": "...", "verdict": "..."}],
    "mitre_techniques": [{"id": "T1234", "name": "...", "tactic": "...", "relevance": "..."}],
    "recommended_actions": [{"action": "...", "priority": "immediate|high|medium|low", "reason": "..."}],
    "reasoning": "Detailed reasoning chain"
}

You have access to tools for threat intelligence, SIEM queries, and EDR data. Use them wisely to build a complete picture of the incident."""

    async def run(
        self,
        request: TriageRequest | str,
        context: dict[str, Any] | None = None,
    ) -> AgentResult:
        """
        Execute the ReAct loop for the given triage request.

        Args:
            request: TriageRequest or task string
            context: Additional context (only used if request is a string)

        Returns:
            AgentResult with analysis and execution details
        """
        start_time = time.time()

        # Convert string to TriageRequest if needed
        if isinstance(request, str):
            task = request
        else:
            task = request.to_task_string()
            context = request.context

        logger.info("agent_run_start", task_preview=task[:100])

        try:
            # Apply timeout
            async with async_timeout(self.timeout_seconds):
                return await self._run_internal(task, context, start_time)
        except asyncio.TimeoutError:
            execution_time = time.time() - start_time
            logger.error(
                "agent_timeout",
                timeout_seconds=self.timeout_seconds,
                execution_time=execution_time,
            )
            return AgentResult(
                success=False,
                execution_time_seconds=execution_time,
                error=f"Execution timed out after {self.timeout_seconds} seconds",
            )
        except Exception as e:
            execution_time = time.time() - start_time
            logger.error("agent_run_error", error=str(e), exc_info=True)
            return AgentResult(
                success=False,
                execution_time_seconds=execution_time,
                error=str(e),
            )

    async def _run_internal(
        self,
        task: str,
        context: dict[str, Any] | None,
        start_time: float,
    ) -> AgentResult:
        """Internal execution logic."""
        # Build initial messages
        messages: list[Message] = [
            Message.system(self.system_prompt),
        ]

        # Add context if provided
        if context:
            context_str = "## Incident Context\n" + json.dumps(context, indent=2)
            messages.append(Message.user(f"{context_str}\n\n## Task\n{task}"))
        else:
            messages.append(Message.user(task))

        # Get tool definitions
        tool_defs = self.tools.get_tool_definitions()

        # Track execution
        execution_trace: list[Step] = []
        total_tokens = 0
        iterations = 0

        # Initial token count
        total_tokens += self._token_counter.count_messages(messages)

        while iterations < self.max_iterations:
            iterations += 1

            # Check token budget
            if total_tokens >= self.max_tokens:
                logger.warning(
                    "agent_token_budget_exceeded",
                    total_tokens=total_tokens,
                    max_tokens=self.max_tokens,
                )
                return self._create_budget_exceeded_result(
                    execution_trace, total_tokens, start_time
                )

            logger.debug(
                "agent_iteration",
                iteration=iterations,
                tokens_used=total_tokens,
                tokens_remaining=self.max_tokens - total_tokens,
            )

            # Get LLM response
            step_start = time.time()
            response = await self.llm.complete(
                messages=messages,
                tools=tool_defs if tool_defs else None,
                temperature=0.1,
            )
            step_duration = int((time.time() - step_start) * 1000)

            # Track tokens from response
            response_tokens = response.usage.get("total_tokens", 0)
            if response_tokens == 0:
                # Estimate if not provided
                response_tokens = self._token_counter.count(response.content or "")
            total_tokens += response_tokens

            # Check if we have tool calls
            if response.has_tool_calls:
                # Record thought if present
                if response.content:
                    thought_step = Step(
                        step_type=StepType.THOUGHT,
                        content=response.content,
                        tokens_used=response_tokens,
                        duration_ms=step_duration,
                    )
                    execution_trace.append(thought_step)

                    logger.info(
                        "agent_thought",
                        iteration=iterations,
                        thought_preview=response.content[:200],
                    )

                    if self._on_thought:
                        await self._on_thought(response.content, thought_step)

                    messages.append(Message.assistant(response.content))

                # Process each tool call
                for tool_call in response.tool_calls:
                    action_step, observation_step = await self._execute_tool_with_retry(
                        tool_call.name,
                        tool_call.arguments,
                        tool_call.id,
                    )

                    execution_trace.append(action_step)
                    execution_trace.append(observation_step)

                    # Add tool result to messages
                    result_str = self._format_tool_result(observation_step.tool_result)
                    messages.append(
                        Message.tool_result(result_str, tool_call.id)
                    )

                    # Track tokens for tool result
                    total_tokens += self._token_counter.count(result_str)

            else:
                # No tool calls - this is the final response
                final_output = response.content or ""

                final_step = Step(
                    step_type=StepType.FINAL,
                    content=final_output,
                    tokens_used=response_tokens,
                    duration_ms=step_duration,
                )
                execution_trace.append(final_step)

                logger.info(
                    "agent_run_complete",
                    iterations=iterations,
                    tool_calls=sum(1 for s in execution_trace if s.step_type == StepType.ACTION),
                    total_tokens=total_tokens,
                    execution_time_seconds=time.time() - start_time,
                )

                # Try to parse as TriageAnalysis
                analysis = None
                parse_error = None
                try:
                    analysis = parse_triage_analysis(final_output)
                except ParseError as e:
                    parse_error = str(e)
                    logger.warning(
                        "agent_parse_error",
                        error=parse_error,
                        output_preview=final_output[:500],
                    )

                return AgentResult(
                    success=analysis is not None,
                    analysis=analysis,
                    execution_trace=execution_trace,
                    tokens_used=total_tokens,
                    execution_time_seconds=time.time() - start_time,
                    raw_output=final_output,
                    error=parse_error,
                )

        # Max iterations reached
        logger.warning(
            "agent_max_iterations",
            iterations=iterations,
            total_tokens=total_tokens,
        )

        return AgentResult(
            success=False,
            execution_trace=execution_trace,
            tokens_used=total_tokens,
            execution_time_seconds=time.time() - start_time,
            error="max_iterations_reached",
        )

    async def _execute_tool_with_retry(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        tool_call_id: str,
    ) -> tuple[Step, Step]:
        """Execute a tool with retry logic.

        Args:
            tool_name: Name of the tool to execute
            arguments: Tool arguments
            tool_call_id: ID of the tool call

        Returns:
            Tuple of (action_step, observation_step)
        """
        # Create action step
        action_step = Step(
            step_type=StepType.ACTION,
            content=f"Calling tool: {tool_name}",
            tool_name=tool_name,
            tool_arguments=arguments,
        )

        logger.info(
            "agent_action",
            tool=tool_name,
            arguments=arguments,
        )

        if self._on_action:
            await self._on_action(tool_name, arguments, action_step)

        # Execute with retry
        last_error = None
        result = None

        for attempt in range(self.tool_retries + 1):
            try:
                step_start = time.time()
                result = await self.tools.execute(tool_name, arguments)
                step_duration = int((time.time() - step_start) * 1000)

                # Success
                observation_step = Step(
                    step_type=StepType.OBSERVATION,
                    content=f"Tool {tool_name} completed successfully",
                    tool_name=tool_name,
                    tool_result=result,
                    duration_ms=step_duration,
                    retry_count=attempt,
                )

                logger.info(
                    "agent_observation",
                    tool=tool_name,
                    result_preview=str(result)[:200],
                    attempt=attempt + 1,
                    duration_ms=step_duration,
                )

                if self._on_observation:
                    await self._on_observation(result, observation_step)

                return action_step, observation_step

            except Exception as e:
                last_error = str(e)
                logger.warning(
                    "tool_execution_error",
                    tool=tool_name,
                    error=last_error,
                    attempt=attempt + 1,
                    max_retries=self.tool_retries,
                )

                if attempt < self.tool_retries:
                    # Exponential backoff
                    delay = self.retry_base_delay * (2 ** attempt)
                    await asyncio.sleep(delay)

        # All retries failed
        observation_step = Step(
            step_type=StepType.ERROR,
            content=f"Tool {tool_name} failed after {self.tool_retries + 1} attempts",
            tool_name=tool_name,
            tool_result={"error": last_error},
            error=last_error,
            retry_count=self.tool_retries,
        )

        logger.error(
            "tool_execution_failed",
            tool=tool_name,
            error=last_error,
            total_attempts=self.tool_retries + 1,
        )

        if self._on_observation:
            await self._on_observation({"error": last_error}, observation_step)

        return action_step, observation_step

    def _format_tool_result(self, result: Any) -> str:
        """Format tool result for inclusion in messages."""
        if result is None:
            return "No result"

        if isinstance(result, dict):
            # Check if it's an error result
            if "error" in result and result.get("success") is False:
                return f"Error: {result['error']}"
            return json.dumps(result, indent=2, default=str)

        if isinstance(result, (list, tuple)):
            return json.dumps(result, indent=2, default=str)

        return str(result)

    def _create_budget_exceeded_result(
        self,
        execution_trace: list[Step],
        total_tokens: int,
        start_time: float,
    ) -> AgentResult:
        """Create result when token budget is exceeded."""
        return AgentResult(
            success=False,
            execution_trace=execution_trace,
            tokens_used=total_tokens,
            execution_time_seconds=time.time() - start_time,
            error=f"Token budget exceeded: {total_tokens} >= {self.max_tokens}",
        )

    def save_execution_trace(self, result: AgentResult, filepath: str) -> None:
        """Save execution trace to a JSON file for debugging.

        Args:
            result: AgentResult to save
            filepath: Path to save the trace
        """
        trace_data = {
            "success": result.success,
            "tokens_used": result.tokens_used,
            "execution_time_seconds": result.execution_time_seconds,
            "error": result.error,
            "steps": [step.to_dict() for step in result.execution_trace],
            "analysis": result.analysis.model_dump() if result.analysis else None,
        }

        with open(filepath, "w") as f:
            json.dump(trace_data, f, indent=2, default=str)

        logger.info("execution_trace_saved", filepath=filepath)


# =============================================================================
# Legacy compatibility
# =============================================================================

# Keep old AgentResult for backward compatibility - it's now enhanced
__all__ = [
    "ReActAgent",
    "AgentResult",
    "TriageRequest",
    "Step",
    "StepType",
    "TokenCounter",
]
