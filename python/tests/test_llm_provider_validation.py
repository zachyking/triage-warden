"""Unit tests for LLM provider API key validation."""

from __future__ import annotations

import os
from unittest import mock

import pytest


class TestAnthropicProviderAPIKeyValidation:
    """Tests for Anthropic provider API key validation."""

    def test_missing_api_key_raises_value_error(self):
        """Test that missing API key raises ValueError with clear message."""
        # Ensure environment variable is not set
        with mock.patch.dict(os.environ, {}, clear=True):
            # Remove ANTHROPIC_API_KEY if it exists
            os.environ.pop("ANTHROPIC_API_KEY", None)
            
            from tw_ai.llm.anthropic_provider import AnthropicProvider
            
            with pytest.raises(ValueError) as exc_info:
                AnthropicProvider()
            
            error_message = str(exc_info.value)
            assert "ANTHROPIC_API_KEY" in error_message
            assert "environment variable not set" in error_message

    def test_api_key_from_parameter(self):
        """Test that API key can be provided via parameter."""
        from tw_ai.llm.anthropic_provider import AnthropicProvider
        
        # Should not raise when api_key is provided
        provider = AnthropicProvider(api_key="test-api-key")
        assert provider.api_key == "test-api-key"

    def test_api_key_from_environment(self):
        """Test that API key can be provided via environment variable."""
        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "env-api-key"}):
            from tw_ai.llm.anthropic_provider import AnthropicProvider
            
            provider = AnthropicProvider()
            assert provider.api_key == "env-api-key"

    def test_parameter_takes_precedence_over_environment(self):
        """Test that parameter API key takes precedence over environment."""
        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "env-api-key"}):
            from tw_ai.llm.anthropic_provider import AnthropicProvider
            
            provider = AnthropicProvider(api_key="param-api-key")
            assert provider.api_key == "param-api-key"

    def test_empty_string_api_key_raises_error(self):
        """Test that empty string API key raises ValueError."""
        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": ""}):
            from tw_ai.llm.anthropic_provider import AnthropicProvider
            
            with pytest.raises(ValueError) as exc_info:
                AnthropicProvider()
            
            assert "ANTHROPIC_API_KEY" in str(exc_info.value)


class TestOpenAIProviderAPIKeyValidation:
    """Tests for OpenAI provider API key validation."""

    def test_missing_api_key_raises_value_error(self):
        """Test that missing API key raises ValueError with clear message."""
        with mock.patch.dict(os.environ, {}, clear=True):
            os.environ.pop("OPENAI_API_KEY", None)
            
            from tw_ai.llm.openai_provider import OpenAIProvider
            
            with pytest.raises(ValueError) as exc_info:
                OpenAIProvider()
            
            error_message = str(exc_info.value)
            assert "OPENAI_API_KEY" in error_message
            assert "environment variable not set" in error_message

    def test_api_key_from_parameter(self):
        """Test that API key can be provided via parameter."""
        from tw_ai.llm.openai_provider import OpenAIProvider
        
        provider = OpenAIProvider(api_key="test-api-key")
        assert provider.api_key == "test-api-key"

    def test_api_key_from_environment(self):
        """Test that API key can be provided via environment variable."""
        with mock.patch.dict(os.environ, {"OPENAI_API_KEY": "env-api-key"}):
            from tw_ai.llm.openai_provider import OpenAIProvider
            
            provider = OpenAIProvider()
            assert provider.api_key == "env-api-key"

    def test_parameter_takes_precedence_over_environment(self):
        """Test that parameter API key takes precedence over environment."""
        with mock.patch.dict(os.environ, {"OPENAI_API_KEY": "env-api-key"}):
            from tw_ai.llm.openai_provider import OpenAIProvider
            
            provider = OpenAIProvider(api_key="param-api-key")
            assert provider.api_key == "param-api-key"

    def test_empty_string_api_key_raises_error(self):
        """Test that empty string API key raises ValueError."""
        with mock.patch.dict(os.environ, {"OPENAI_API_KEY": ""}):
            from tw_ai.llm.openai_provider import OpenAIProvider
            
            with pytest.raises(ValueError) as exc_info:
                OpenAIProvider()
            
            assert "OPENAI_API_KEY" in str(exc_info.value)


class TestLocalProviderEndpointValidation:
    """Tests for Local provider endpoint URL validation."""

    def test_missing_endpoint_raises_value_error(self):
        """Test that missing endpoint raises ValueError with clear message."""
        with mock.patch.dict(os.environ, {}, clear=True):
            os.environ.pop("LOCAL_LLM_ENDPOINT", None)
            
            from tw_ai.llm.local_provider import LocalProvider
            
            with pytest.raises(ValueError) as exc_info:
                LocalProvider()
            
            error_message = str(exc_info.value)
            assert "LOCAL_LLM_ENDPOINT" in error_message
            assert "environment variable not set" in error_message

    def test_endpoint_from_parameter(self):
        """Test that endpoint can be provided via parameter."""
        from tw_ai.llm.local_provider import LocalProvider
        
        provider = LocalProvider(base_url="http://localhost:8080/v1")
        assert provider.base_url == "http://localhost:8080/v1"

    def test_endpoint_from_environment(self):
        """Test that endpoint can be provided via environment variable."""
        with mock.patch.dict(os.environ, {"LOCAL_LLM_ENDPOINT": "http://env-endpoint:8000/v1"}):
            from tw_ai.llm.local_provider import LocalProvider
            
            provider = LocalProvider()
            assert provider.base_url == "http://env-endpoint:8000/v1"

    def test_parameter_takes_precedence_over_environment(self):
        """Test that parameter endpoint takes precedence over environment."""
        with mock.patch.dict(os.environ, {"LOCAL_LLM_ENDPOINT": "http://env-endpoint:8000/v1"}):
            from tw_ai.llm.local_provider import LocalProvider
            
            provider = LocalProvider(base_url="http://param-endpoint:9000/v1")
            assert provider.base_url == "http://param-endpoint:9000/v1"

    def test_empty_string_endpoint_raises_error(self):
        """Test that empty string endpoint raises ValueError."""
        with mock.patch.dict(os.environ, {"LOCAL_LLM_ENDPOINT": ""}):
            from tw_ai.llm.local_provider import LocalProvider
            
            with pytest.raises(ValueError) as exc_info:
                LocalProvider()
            
            assert "LOCAL_LLM_ENDPOINT" in str(exc_info.value)

    def test_trailing_slash_stripped(self):
        """Test that trailing slash is stripped from endpoint URL."""
        from tw_ai.llm.local_provider import LocalProvider
        
        provider = LocalProvider(base_url="http://localhost:8080/v1/")
        assert provider.base_url == "http://localhost:8080/v1"


class TestErrorMessageClarity:
    """Tests for error message clarity and actionability."""

    def test_anthropic_error_includes_both_options(self):
        """Test Anthropic error message mentions both env var and parameter."""
        with mock.patch.dict(os.environ, {}, clear=True):
            os.environ.pop("ANTHROPIC_API_KEY", None)
            
            from tw_ai.llm.anthropic_provider import AnthropicProvider
            
            with pytest.raises(ValueError) as exc_info:
                AnthropicProvider()
            
            error_message = str(exc_info.value)
            assert "ANTHROPIC_API_KEY environment variable" in error_message
            assert "api_key parameter" in error_message

    def test_openai_error_includes_both_options(self):
        """Test OpenAI error message mentions both env var and parameter."""
        with mock.patch.dict(os.environ, {}, clear=True):
            os.environ.pop("OPENAI_API_KEY", None)
            
            from tw_ai.llm.openai_provider import OpenAIProvider
            
            with pytest.raises(ValueError) as exc_info:
                OpenAIProvider()
            
            error_message = str(exc_info.value)
            assert "OPENAI_API_KEY environment variable" in error_message
            assert "api_key parameter" in error_message

    def test_local_error_includes_both_options(self):
        """Test Local provider error message mentions both env var and parameter."""
        with mock.patch.dict(os.environ, {}, clear=True):
            os.environ.pop("LOCAL_LLM_ENDPOINT", None)
            
            from tw_ai.llm.local_provider import LocalProvider
            
            with pytest.raises(ValueError) as exc_info:
                LocalProvider()
            
            error_message = str(exc_info.value)
            assert "LOCAL_LLM_ENDPOINT environment variable" in error_message
            assert "base_url parameter" in error_message
