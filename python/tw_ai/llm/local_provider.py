"""Local LLM provider for self-hosted models (vLLM, Ollama, etc.)."""

import json
from typing import Any

import httpx
import structlog
from tenacity import retry, stop_after_attempt, wait_exponential

from tw_ai.llm.base import LLMProvider, LLMResponse, Message, ToolCall, ToolDefinition

logger = structlog.get_logger()


class LocalProvider(LLMProvider):
    """Local LLM provider using OpenAI-compatible API."""

    def __init__(
        self,
        base_url: str = "http://localhost:8000/v1",
        model: str = "foundation-sec-8b",
        api_key: str = "not-needed",
    ):
        """
        Initialize the local provider.

        Args:
            base_url: Base URL for the local API server.
            model: Model name/identifier.
            api_key: API key (often not needed for local deployments).
        """
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.client = httpx.AsyncClient(
            base_url=self.base_url,
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=120.0,
        )

    @property
    def name(self) -> str:
        return "local"

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
        """Generate a completion using local API."""
        logger.debug(
            "local_complete",
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

        # Build request body
        body: dict[str, Any] = {
            "model": self.model,
            "messages": openai_messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        if tools:
            body["tools"] = [t.to_openai_format() for t in tools]
            body["tool_choice"] = "auto"

        # Make the API call
        response = await self.client.post("/chat/completions", json=body)
        response.raise_for_status()
        data = response.json()

        # Parse the response
        choice = data["choices"][0]
        message = choice["message"]

        tool_calls = []
        if "tool_calls" in message and message["tool_calls"]:
            for tc in message["tool_calls"]:
                tool_calls.append(
                    ToolCall(
                        id=tc["id"],
                        name=tc["function"]["name"],
                        arguments=json.loads(tc["function"]["arguments"]),
                    )
                )

        usage = data.get("usage", {})
        return LLMResponse(
            content=message.get("content"),
            tool_calls=tool_calls,
            finish_reason=choice.get("finish_reason", "stop"),
            usage={
                "prompt_tokens": usage.get("prompt_tokens", 0),
                "completion_tokens": usage.get("completion_tokens", 0),
                "total_tokens": usage.get("total_tokens", 0),
            },
            model=data.get("model", self.model),
            raw_response=data,
        )

    async def health_check(self) -> bool:
        """Check if local API is accessible."""
        try:
            response = await self.client.get("/models")
            return response.status_code == 200
        except Exception as e:
            logger.error("local_health_check_failed", error=str(e))
            return False

    async def close(self) -> None:
        """Close the HTTP client."""
        await self.client.aclose()
