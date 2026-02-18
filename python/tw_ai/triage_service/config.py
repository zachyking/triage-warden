"""Configuration for the triage service."""

from __future__ import annotations

import os
from typing import Any

import structlog

logger = structlog.get_logger()


class TriageServiceConfig:
    """Configuration loaded from environment variables."""

    def __init__(self) -> None:
        # LLM provider settings
        self.llm_provider: str = os.environ.get("TW_LLM_PROVIDER", "openai")
        self.llm_model: str = os.environ.get("TW_LLM_MODEL", "gpt-4-turbo")
        self.llm_base_url: str | None = os.environ.get("TW_LLM_BASE_URL")
        self.llm_api_key: str | None = os.environ.get("TW_LLM_API_KEY")

        # Agent settings
        self.agent_max_iterations: int = int(os.environ.get("TW_AGENT_MAX_ITERATIONS", "10"))
        self.agent_max_tokens: int = int(os.environ.get("TW_AGENT_MAX_TOKENS", "8000"))
        self.agent_timeout_seconds: float = float(os.environ.get("TW_AGENT_TIMEOUT_SECONDS", "90"))

        # Service settings
        self.host: str = os.environ.get("TW_TRIAGE_HOST", "0.0.0.0")
        self.port: int = int(os.environ.get("TW_TRIAGE_PORT", "8091"))

    def is_llm_configured(self) -> bool:
        """Check whether an LLM API key is available."""
        if self.llm_api_key:
            return True
        # Fall back to provider-specific env vars
        if self.llm_provider == "openai":
            return bool(os.environ.get("OPENAI_API_KEY"))
        if self.llm_provider == "anthropic":
            return bool(os.environ.get("ANTHROPIC_API_KEY"))
        return False

    def create_llm_provider(self) -> Any:
        """Create the LLM provider from config.

        Returns:
            An LLMProvider instance.

        Raises:
            ValueError: If the provider cannot be configured.
        """
        provider = self.llm_provider.lower()

        if provider == "openai":
            from tw_ai.llm.openai_provider import OpenAIProvider

            return OpenAIProvider(
                api_key=self.llm_api_key or os.environ.get("OPENAI_API_KEY"),
                model=self.llm_model,
                base_url=self.llm_base_url,
            )
        elif provider == "anthropic":
            from tw_ai.llm.anthropic_provider import AnthropicProvider

            return AnthropicProvider(
                api_key=self.llm_api_key or os.environ.get("ANTHROPIC_API_KEY"),
                model=self.llm_model,
            )
        else:
            raise ValueError(f"Unknown LLM provider: {provider}. Supported: openai, anthropic")


# Global singleton
_config: TriageServiceConfig | None = None


def get_config() -> TriageServiceConfig:
    """Get or create the global config singleton."""
    global _config
    if _config is None:
        _config = TriageServiceConfig()
    return _config
