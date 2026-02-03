"""ReAct (Reasoning + Acting) agent implementation for security triage.

This module provides a production-ready ReAct agent with:
- Configurable iteration limits, token budgets, and timeouts
- Token counting and budget enforcement using tiktoken
- Retry logic with exponential backoff for tool failures
- Structured logging with structlog
- Execution timeout support via asyncio.timeout
- Full execution trace for debugging and observability
- Streaming callbacks for UI updates
- PII redaction for data sent to external LLM providers
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol

import structlog

# =============================================================================
# Error Sanitization for Production Security
# =============================================================================


class AgentErrorCode:
    """Error codes for agent errors to enable client-side handling."""

    TIMEOUT = "AGENT_TIMEOUT"
    MAX_ITERATIONS = "AGENT_MAX_ITERATIONS"
    TOKEN_BUDGET_EXCEEDED = "AGENT_TOKEN_BUDGET"
    PARSE_ERROR = "AGENT_PARSE_ERROR"
    TOOL_ERROR = "AGENT_TOOL_ERROR"
    LLM_ERROR = "AGENT_LLM_ERROR"
    INTERNAL_ERROR = "AGENT_INTERNAL_ERROR"


def _is_production() -> bool:
    """Check if running in production environment."""
    for var in ("TW_ENV", "NODE_ENV", "ENVIRONMENT"):
        value = os.environ.get(var, "").lower()
        if value in ("production", "prod"):
            return True
    return False


def _sanitize_agent_error(error: Exception) -> str:
    """
    Sanitize error messages for client responses.

    In production, returns a generic error message without internal details.
    In development, returns the full error message for debugging.

    Args:
        error: The exception that occurred.

    Returns:
        A sanitized error message safe for client consumption.
    """
    error_str = str(error)

    # Map known error patterns to error codes and generic messages
    error_mappings = [
        ("timed out", AgentErrorCode.TIMEOUT, "Request timed out"),
        ("timeout", AgentErrorCode.TIMEOUT, "Request timed out"),
        ("max_iterations", AgentErrorCode.MAX_ITERATIONS, "Analysis limit reached"),
        ("token budget", AgentErrorCode.TOKEN_BUDGET_EXCEEDED, "Processing limit exceeded"),
        ("parse", AgentErrorCode.PARSE_ERROR, "Unable to process response"),
        ("json", AgentErrorCode.PARSE_ERROR, "Unable to process response"),
        ("validation", AgentErrorCode.PARSE_ERROR, "Invalid response format"),
        ("llm", AgentErrorCode.LLM_ERROR, "AI service error"),
        ("api", AgentErrorCode.LLM_ERROR, "Service temporarily unavailable"),
        ("rate limit", AgentErrorCode.LLM_ERROR, "Service temporarily unavailable"),
        ("connection", AgentErrorCode.LLM_ERROR, "Service temporarily unavailable"),
    ]

    error_lower = error_str.lower()
    error_code = AgentErrorCode.INTERNAL_ERROR
    generic_message = "An error occurred during analysis"

    for pattern, code, message in error_mappings:
        if pattern in error_lower:
            error_code = code
            generic_message = message
            break

    if _is_production():
        # In production, never expose internal error details, stack traces,
        # or raw LLM output that could leak system internals
        return f"[{error_code}] {generic_message}"
    else:
        # In development, include full error for debugging
        return f"[{error_code}] {error_str}"


_tiktoken_module: Any = None
_TIKTOKEN_AVAILABLE = False

try:
    import tiktoken as _tiktoken_import

    _tiktoken_module = _tiktoken_import
    _TIKTOKEN_AVAILABLE = True
except ImportError:
    pass


# =============================================================================
# Python 3.9/3.10 compatibility for asyncio.timeout
# =============================================================================

if sys.version_info >= (3, 11):
    # Python 3.11+ has native asyncio.timeout
    async_timeout = asyncio.timeout
else:
    # Fallback for Python 3.9/3.10
    @asynccontextmanager
    async def async_timeout(delay: float | None) -> AsyncIterator[None]:
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


from tw_ai.agents.models import TriageAnalysis  # noqa: E402
from tw_ai.agents.output_parser import ParseError, parse_triage_analysis  # noqa: E402
from tw_ai.agents.tools import ToolRegistry  # noqa: E402
from tw_ai.llm.base import LLMProvider, Message  # noqa: E402
from tw_ai.sanitization import (  # noqa: E402
    PIIRedactor,
    PromptInjectionError,
    PromptSanitizer,
    RedactionMode,
    RedactionRecord,
    create_security_analysis_redactor,
)

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
        redact_pii: Whether to redact PII before sending to LLM (default: True)
        pii_redaction_mode: Redaction mode ('strict' or 'permissive')
        sanitize_for_injection: Whether to sanitize for prompt injection (default: True)
    """

    alert_type: str
    alert_data: dict[str, Any]
    context: dict[str, Any] | None = None
    priority: str | None = None
    redact_pii: bool = True
    pii_redaction_mode: str = "permissive"  # "strict" or "permissive"
    sanitize_for_injection: bool = True  # Enable prompt injection protection

    # Store redaction audit records after to_task_string is called
    _redaction_records: list[RedactionRecord] = field(default_factory=list, repr=False)
    # Store injection detection records
    _injection_detections: list[dict[str, Any]] = field(default_factory=list, repr=False)

    def to_task_string(
        self,
        pii_redactor: PIIRedactor | None = None,
        prompt_sanitizer: PromptSanitizer | None = None,
    ) -> str:
        """Convert request to a task string for the agent.

        Args:
            pii_redactor: Optional PIIRedactor instance. If not provided and
                          redact_pii is True, a default redactor will be created.
            prompt_sanitizer: Optional PromptSanitizer instance. If not provided
                             and sanitize_for_injection is True, a default will be created.

        Returns:
            Task string with PII redacted and prompt injection sanitized if enabled.

        Raises:
            PromptInjectionError: If a critical prompt injection pattern is detected.
        """
        # Create redactor if needed
        if self.redact_pii and pii_redactor is None:
            if self.pii_redaction_mode == "strict":
                pii_redactor = PIIRedactor(mode=RedactionMode.STRICT)
            else:
                # Permissive mode allows emails and IPs for security analysis
                pii_redactor = create_security_analysis_redactor()

        # Create prompt sanitizer if needed
        if self.sanitize_for_injection and prompt_sanitizer is None:
            prompt_sanitizer = PromptSanitizer()

        # Prepare data with sanitization
        alert_data_for_prompt: dict[str, Any]
        context_for_prompt: dict[str, Any] | None = None

        # Step 1: Sanitize for prompt injection (must be done first to block attacks)
        if self.sanitize_for_injection and prompt_sanitizer:
            try:
                sanitized_alert, alert_detections = prompt_sanitizer.sanitize_dict(self.alert_data)
                self._injection_detections.extend(alert_detections)
                alert_data_for_prompt = sanitized_alert

                if self.context:
                    sanitized_context, context_detections = prompt_sanitizer.sanitize_dict(
                        self.context
                    )
                    self._injection_detections.extend(context_detections)
                    context_for_prompt = sanitized_context

                # Log injection detection summary
                if self._injection_detections:
                    logger.warning(
                        "prompt_injection_patterns_detected_in_triage_request",
                        alert_type=self.alert_type,
                        detection_count=len(self._injection_detections),
                        patterns=[d["pattern_name"] for d in self._injection_detections],
                    )
            except PromptInjectionError as e:
                # Critical injection pattern detected - re-raise to block processing
                logger.error(
                    "prompt_injection_blocked",
                    alert_type=self.alert_type,
                    pattern_name=e.pattern_name,
                    severity=e.severity.value,
                )
                raise
        else:
            alert_data_for_prompt = self.alert_data
            context_for_prompt = self.context

        # Step 2: Redact PII from (potentially sanitized) data
        alert_data_str: str
        context_str: str | None = None

        if self.redact_pii and pii_redactor:
            # Redact alert data
            redacted_alert, alert_records = pii_redactor.redact_dict(
                alert_data_for_prompt, path_prefix="alert_data"
            )
            alert_data_str = json.dumps(redacted_alert, indent=2)
            self._redaction_records.extend(alert_records)

            # Redact context if present
            if context_for_prompt:
                redacted_context, context_records = pii_redactor.redact_dict(
                    context_for_prompt, path_prefix="context"
                )
                context_str = json.dumps(redacted_context, indent=2)
                self._redaction_records.extend(context_records)

            # Log redaction summary
            if self._redaction_records:
                logger.info(
                    "pii_redaction_applied_to_triage_request",
                    alert_type=self.alert_type,
                    total_redactions=len(self._redaction_records),
                    redaction_mode=self.pii_redaction_mode,
                )
        else:
            alert_data_str = json.dumps(alert_data_for_prompt, indent=2)
            if context_for_prompt:
                context_str = json.dumps(context_for_prompt, indent=2)

        # Build task string with clear data boundaries to prevent injection
        # Using structured format that marks data boundaries clearly
        task_parts = [
            f"Triage the following {self.alert_type} alert:",
            "",
            "[BEGIN ALERT DATA - USER PROVIDED DATA]",
            alert_data_str,
            "[END ALERT DATA - USER PROVIDED DATA]",
        ]

        if context_str:
            task_parts.extend(
                [
                    "",
                    "[BEGIN CONTEXT DATA - USER PROVIDED DATA]",
                    context_str,
                    "[END CONTEXT DATA - USER PROVIDED DATA]",
                ]
            )

        if self.priority:
            task_parts.extend(
                [
                    "",
                    f"## Priority: {self.priority}",
                ]
            )

        task_parts.extend(
            [
                "",
                "Analyze this alert thoroughly and provide your verdict.",
            ]
        )

        return "\n".join(task_parts)

    def get_redaction_audit_log(self) -> list[dict[str, Any]]:
        """Get audit log of PII redactions performed on this request.

        Returns:
            List of redaction records as dictionaries.
        """
        return [record.to_dict() for record in self._redaction_records]

    def get_injection_detection_log(self) -> list[dict[str, Any]]:
        """Get log of prompt injection patterns detected in this request.

        Returns:
            List of detection records as dictionaries.
        """
        return list(self._injection_detections)


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

    def __post_init__(self) -> None:
        """Populate legacy fields from new fields."""
        if self.analysis:
            self.output = self.analysis.summary
            self.reasoning = [self.analysis.reasoning] if self.analysis.reasoning else []
        elif self.raw_output:
            self.output = self.raw_output

        # Populate actions_taken from execution trace
        for step in self.execution_trace:
            if step.step_type == StepType.ACTION and step.tool_name:
                self.actions_taken.append(
                    {
                        "tool": step.tool_name,
                        "arguments": step.tool_arguments,
                        "result_preview": str(step.tool_result)[:200] if step.tool_result else "",
                    }
                )

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

        if _TIKTOKEN_AVAILABLE and _tiktoken_module is not None:
            try:
                self._encoder = _tiktoken_module.encoding_for_model(model)
            except KeyError:
                # Fall back to cl100k_base for unknown models
                try:
                    self._encoder = _tiktoken_module.get_encoding("cl100k_base")
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
    - PII redaction for data sent to external LLM providers
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
        pii_redactor: PIIRedactor | None = None,
        enable_pii_redaction: bool = True,
        prompt_sanitizer: PromptSanitizer | None = None,
        enable_prompt_sanitization: bool = True,
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
            pii_redactor: Custom PIIRedactor instance (uses default if not provided)
            enable_pii_redaction: Whether to enable PII redaction (default: True)
            prompt_sanitizer: Custom PromptSanitizer instance (uses default if not provided)
            enable_prompt_sanitization: Enable prompt injection protection (default: True)
        """
        self.llm = llm
        self.tools = tools
        self.max_iterations = max_iterations
        self.max_tokens = max_tokens
        self.timeout_seconds = timeout_seconds
        self.tool_retries = tool_retries
        self.retry_base_delay = retry_base_delay
        self.system_prompt = system_prompt or self._default_system_prompt()
        self.enable_pii_redaction = enable_pii_redaction
        self.enable_prompt_sanitization = enable_prompt_sanitization

        # PII redactor (use default security analysis redactor if none provided)
        self._pii_redactor: PIIRedactor | None
        if enable_pii_redaction:
            self._pii_redactor = pii_redactor or create_security_analysis_redactor()
        else:
            self._pii_redactor = None

        # Prompt sanitizer for injection protection
        self._prompt_sanitizer: PromptSanitizer | None
        if enable_prompt_sanitization:
            self._prompt_sanitizer = prompt_sanitizer or PromptSanitizer()
        else:
            self._prompt_sanitizer = None

        # Callbacks
        self._on_thought = on_thought
        self._on_action = on_action
        self._on_observation = on_observation

        # Token counter
        self._token_counter = TokenCounter()

        # Store PII redaction audit log for the current run
        self._current_run_redaction_log: list[RedactionRecord] = []

        # Store prompt injection detection log for the current run
        self._current_run_injection_log: list[dict[str, Any]] = []

        logger.info(
            "react_agent_initialized",
            max_iterations=max_iterations,
            max_tokens=max_tokens,
            timeout_seconds=timeout_seconds,
            tool_retries=tool_retries,
            tools_available=tools.list_tools(),
            pii_redaction_enabled=enable_pii_redaction,
            prompt_sanitization_enabled=enable_prompt_sanitization,
        )

    def _default_system_prompt(self) -> str:
        """Generate the default system prompt for security triage."""
        return """You are an expert Security Operations Center (SOC) analyst AI assistant.
Your role is to help triage security incidents by:

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
    "mitre_techniques": [{"id": "T1234", "name": "...", "tactic": "..."}],
    "recommended_actions": [{"action": "...", "priority": "immediate|high|medium|low"}],
    "reasoning": "Detailed reasoning chain"
}

You have access to tools for threat intelligence, SIEM queries, and EDR data.
Use them wisely to build a complete picture of the incident."""

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

        Note:
            If prompt injection is detected in the request, an AgentResult with
            success=False will be returned with the injection error details.
        """
        start_time = time.time()

        # Clear previous run's logs
        self._current_run_injection_log = []

        # Convert string to TriageRequest if needed
        if isinstance(request, str):
            # For raw string requests, apply sanitization if enabled
            if self.enable_prompt_sanitization and self._prompt_sanitizer:
                try:
                    result = self._prompt_sanitizer.sanitize(request)
                    task = result.sanitized
                    if result.detections:
                        self._current_run_injection_log.extend(result.detections)
                        logger.warning(
                            "prompt_injection_patterns_detected_in_raw_task",
                            detection_count=len(result.detections),
                            patterns=[d["pattern_name"] for d in result.detections],
                        )
                except PromptInjectionError as e:
                    execution_time = time.time() - start_time
                    logger.error(
                        "prompt_injection_blocked_in_raw_task",
                        pattern_name=e.pattern_name,
                        severity=e.severity.value,
                    )
                    return AgentResult(
                        success=False,
                        execution_time_seconds=execution_time,
                        error=f"[PROMPT_INJECTION_BLOCKED] {e.pattern_name}: {str(e)}",
                    )
            else:
                task = request
        else:
            # For TriageRequest, use its sanitization method
            try:
                task = request.to_task_string(
                    pii_redactor=self._pii_redactor,
                    prompt_sanitizer=self._prompt_sanitizer,
                )
                context = request.context
                # Copy injection detection log from request
                self._current_run_injection_log.extend(request.get_injection_detection_log())
            except PromptInjectionError as e:
                execution_time = time.time() - start_time
                logger.error(
                    "prompt_injection_blocked_in_triage_request",
                    pattern_name=e.pattern_name,
                    severity=e.severity.value,
                )
                return AgentResult(
                    success=False,
                    execution_time_seconds=execution_time,
                    error=f"[PROMPT_INJECTION_BLOCKED] {e.pattern_name}: {str(e)}",
                )

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
            # Log full error details server-side for debugging
            logger.error("agent_run_error", error=str(e), exc_info=True)

            # Return sanitized error to client - never expose internal details
            sanitized_error = _sanitize_agent_error(e)
            return AgentResult(
                success=False,
                execution_time_seconds=execution_time,
                error=sanitized_error,
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
                    messages.append(Message.tool_result(result_str, tool_call.id))

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
                    delay = self.retry_base_delay * (2**attempt)
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
            "pii_redaction_log": self.get_pii_redaction_audit_log(),
        }

        with open(filepath, "w") as f:
            json.dump(trace_data, f, indent=2, default=str)

        logger.info("execution_trace_saved", filepath=filepath)

    def get_pii_redaction_audit_log(self) -> list[dict[str, Any]]:
        """Get the PII redaction audit log from the last run.

        Returns:
            List of redaction records as dictionaries.
        """
        if self._pii_redactor:
            return self._pii_redactor.export_audit_log()
        return []

    def clear_pii_redaction_audit_log(self) -> int:
        """Clear the PII redaction audit log.

        Returns:
            Number of records cleared.
        """
        if self._pii_redactor:
            return self._pii_redactor.clear_audit_log()
        return 0

    def get_injection_detection_log(self) -> list[dict[str, Any]]:
        """Get the prompt injection detection log from the last run.

        Returns:
            List of detection records as dictionaries.
        """
        return list(self._current_run_injection_log)

    def clear_injection_detection_log(self) -> int:
        """Clear the prompt injection detection log.

        Returns:
            Number of records cleared.
        """
        count = len(self._current_run_injection_log)
        self._current_run_injection_log = []
        return count


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
    # Re-export sanitization utilities for convenience
    "PIIRedactor",
    "RedactionMode",
    "PromptSanitizer",
    "PromptInjectionError",
]
