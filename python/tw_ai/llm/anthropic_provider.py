"""Anthropic LLM provider."""

import os
from typing import Any

import structlog
from anthropic import AsyncAnthropic
from tenacity import retry, stop_after_attempt, wait_exponential

from tw_ai.llm.base import LLMProvider, LLMResponse, Message, Role, ToolCall, ToolDefinition

logger = structlog.get_logger()


class AnthropicProvider(LLMProvider):
    """Anthropic LLM provider."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str = "claude-3-5-sonnet-20241022",
    ):
        """
        Initialize the Anthropic provider.

        Args:
            api_key: Anthropic API key. If not provided, uses ANTHROPIC_API_KEY env var.
            model: Model to use.
        """
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self.model = model
        self.client = AsyncAnthropic(api_key=self.api_key)

    @property
    def name(self) -> str:
        return "anthropic"

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
    )
    async def complete(
        self,
        messages: list[Message],
        tools: list[ToolDefinition] | None = None,
        temperature: float = 0.1,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """Generate a completion using Anthropic API."""
        logger.debug(
            "anthropic_complete",
            model=self.model,
            message_count=len(messages),
            tool_count=len(tools) if tools else 0,
        )

        # Extract system message and convert others to Anthropic format
        system_content = ""
        anthropic_messages = []

        for msg in messages:
            if msg.role == Role.SYSTEM:
                system_content = msg.content
            elif msg.role == Role.TOOL:
                # Anthropic uses tool_result content blocks
                anthropic_messages.append(
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "tool_result",
                                "tool_use_id": msg.tool_call_id,
                                "content": msg.content,
                            }
                        ],
                    }
                )
            else:
                anthropic_messages.append(
                    {
                        "role": msg.role.value,
                        "content": msg.content,
                    }
                )

        # Build request kwargs
        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": anthropic_messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }

        if system_content:
            kwargs["system"] = system_content

        if tools:
            kwargs["tools"] = [t.to_anthropic_format() for t in tools]

        # Make the API call
        response = await self.client.messages.create(**kwargs)

        # Parse the response
        content = ""
        tool_calls = []

        for block in response.content:
            if block.type == "text":
                content = block.text
            elif block.type == "tool_use":
                tool_calls.append(
                    ToolCall(
                        id=block.id,
                        name=block.name,
                        arguments=dict(block.input) if isinstance(block.input, dict) else {},
                    )
                )

        return LLMResponse(
            content=content if content else None,
            tool_calls=tool_calls,
            finish_reason=response.stop_reason or "end_turn",
            usage={
                "prompt_tokens": response.usage.input_tokens,
                "completion_tokens": response.usage.output_tokens,
                "total_tokens": response.usage.input_tokens + response.usage.output_tokens,
            },
            model=response.model,
            raw_response=response,
        )

    async def health_check(self) -> bool:
        """Check if Anthropic API is accessible."""
        try:
            # Simple completion test
            response = await self.client.messages.create(
                model=self.model,
                max_tokens=10,
                messages=[{"role": "user", "content": "Hi"}],
            )
            return response.content is not None
        except Exception as e:
            logger.error("anthropic_health_check_failed", error=str(e))
            return False
