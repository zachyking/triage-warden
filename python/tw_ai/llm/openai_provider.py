"""OpenAI LLM provider."""

from __future__ import annotations

import json
import os
from typing import Any

import structlog
from openai import AsyncOpenAI
from tenacity import retry, stop_after_attempt, wait_exponential

from tw_ai.llm.base import LLMProvider, LLMResponse, Message, ToolCall, ToolDefinition

logger = structlog.get_logger()


class OpenAIProvider(LLMProvider):
    """OpenAI LLM provider."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str = "gpt-4-turbo",
        base_url: str | None = None,
    ):
        """
        Initialize the OpenAI provider.

        Args:
            api_key: OpenAI API key. If not provided, uses OPENAI_API_KEY env var.
            model: Model to use.
            base_url: Optional custom base URL for API-compatible services.
        """
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        self.model = model
        self.client = AsyncOpenAI(api_key=self.api_key, base_url=base_url)

    @property
    def name(self) -> str:
        return "openai"

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
        """Generate a completion using OpenAI API."""
        logger.debug(
            "openai_complete",
            model=self.model,
            message_count=len(messages),
            tool_count=len(tools) if tools else 0,
        )

        # Convert messages to OpenAI format
        openai_messages = []
        for msg in messages:
            openai_msg: dict[str, Any] = {
                "role": msg.role.value,
                "content": msg.content,
            }
            if msg.tool_call_id:
                openai_msg["tool_call_id"] = msg.tool_call_id
            if msg.name:
                openai_msg["name"] = msg.name
            openai_messages.append(openai_msg)

        # Build request kwargs
        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": openai_messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        if tools:
            kwargs["tools"] = [t.to_openai_format() for t in tools]
            kwargs["tool_choice"] = "auto"

        # Make the API call
        response = await self.client.chat.completions.create(**kwargs)

        # Parse the response
        choice = response.choices[0]
        message = choice.message

        tool_calls = []
        if message.tool_calls:
            for tc in message.tool_calls:
                tool_calls.append(
                    ToolCall(
                        id=tc.id,
                        name=tc.function.name,
                        arguments=json.loads(tc.function.arguments),
                    )
                )

        return LLMResponse(
            content=message.content,
            tool_calls=tool_calls,
            finish_reason=choice.finish_reason or "stop",
            usage={
                "prompt_tokens": response.usage.prompt_tokens if response.usage else 0,
                "completion_tokens": response.usage.completion_tokens if response.usage else 0,
                "total_tokens": response.usage.total_tokens if response.usage else 0,
            },
            model=response.model,
            raw_response=response,
        )

    async def health_check(self) -> bool:
        """Check if OpenAI API is accessible."""
        try:
            await self.client.models.list()
            return True
        except Exception as e:
            logger.error("openai_health_check_failed", error=str(e))
            return False
