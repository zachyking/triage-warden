"""Unit tests for error sanitization (Security Task 6.3).

These tests verify that error messages are properly sanitized in production
to prevent information disclosure attacks.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path
from unittest import mock

import pytest


# Direct module loading to avoid Python 3.10+ syntax in tw_ai/__init__.py
_base_path = Path(__file__).parent.parent / "tw_ai"


def _load_module(name: str, file_path: Path):
    """Load a module directly from file path."""
    spec = importlib.util.spec_from_file_location(name, file_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# Load output_parser module
_parser = _load_module("tw_ai.agents.output_parser_test", _base_path / "agents" / "output_parser.py")
ParseError = _parser.ParseError
ErrorCode = _parser.ErrorCode

# Load react module
_react = _load_module("tw_ai.agents.react_test", _base_path / "agents" / "react.py")
AgentErrorCode = _react.AgentErrorCode
_sanitize_agent_error = _react._sanitize_agent_error


# ============================================================================
# Test Fixtures
# ============================================================================


@pytest.fixture
def production_env():
    """Set production environment for test."""
    original = os.environ.get("TW_ENV")
    os.environ["TW_ENV"] = "production"
    yield
    if original:
        os.environ["TW_ENV"] = original
    else:
        os.environ.pop("TW_ENV", None)


@pytest.fixture
def development_env():
    """Ensure development environment for test."""
    original_tw = os.environ.pop("TW_ENV", None)
    original_node = os.environ.pop("NODE_ENV", None)
    original_env = os.environ.pop("ENVIRONMENT", None)
    yield
    if original_tw:
        os.environ["TW_ENV"] = original_tw
    if original_node:
        os.environ["NODE_ENV"] = original_node
    if original_env:
        os.environ["ENVIRONMENT"] = original_env


# ============================================================================
# Agent Error Sanitization Tests
# ============================================================================


class TestAgentErrorCodes:
    """Tests for AgentErrorCode constants."""

    def test_all_codes_defined(self):
        """Verify all error codes are defined."""
        assert AgentErrorCode.TIMEOUT == "AGENT_TIMEOUT"
        assert AgentErrorCode.MAX_ITERATIONS == "AGENT_MAX_ITERATIONS"
        assert AgentErrorCode.TOKEN_BUDGET_EXCEEDED == "AGENT_TOKEN_BUDGET"
        assert AgentErrorCode.PARSE_ERROR == "AGENT_PARSE_ERROR"
        assert AgentErrorCode.TOOL_ERROR == "AGENT_TOOL_ERROR"
        assert AgentErrorCode.LLM_ERROR == "AGENT_LLM_ERROR"
        assert AgentErrorCode.INTERNAL_ERROR == "AGENT_INTERNAL_ERROR"

    def test_codes_follow_naming_convention(self):
        """Verify error codes follow AGENT_ prefix convention."""
        codes = [
            AgentErrorCode.TIMEOUT,
            AgentErrorCode.MAX_ITERATIONS,
            AgentErrorCode.TOKEN_BUDGET_EXCEEDED,
            AgentErrorCode.PARSE_ERROR,
            AgentErrorCode.TOOL_ERROR,
            AgentErrorCode.LLM_ERROR,
            AgentErrorCode.INTERNAL_ERROR,
        ]
        for code in codes:
            assert code.startswith("AGENT_")
            assert code.isupper()


class TestSanitizeAgentError:
    """Tests for _sanitize_agent_error function."""

    def test_timeout_error_mapping(self, development_env):
        """Test timeout errors are mapped correctly."""
        error = Exception("Request timed out after 30 seconds")
        result = _sanitize_agent_error(error)
        assert AgentErrorCode.TIMEOUT in result

    def test_max_iterations_error_mapping(self, development_env):
        """Test max_iterations errors are mapped correctly."""
        error = Exception("max_iterations reached at 10")
        result = _sanitize_agent_error(error)
        assert AgentErrorCode.MAX_ITERATIONS in result

    def test_token_budget_error_mapping(self, development_env):
        """Test token budget errors are mapped correctly."""
        error = Exception("token budget exceeded: 8000/8000")
        result = _sanitize_agent_error(error)
        assert AgentErrorCode.TOKEN_BUDGET_EXCEEDED in result

    def test_parse_error_mapping(self, development_env):
        """Test parse errors are mapped correctly."""
        error = Exception("Failed to parse JSON response")
        result = _sanitize_agent_error(error)
        assert AgentErrorCode.PARSE_ERROR in result

    def test_llm_error_mapping(self, development_env):
        """Test LLM API errors are mapped correctly."""
        error = Exception("LLM API returned 500")
        result = _sanitize_agent_error(error)
        assert AgentErrorCode.LLM_ERROR in result

    def test_rate_limit_error_mapping(self, development_env):
        """Test rate limit errors are mapped correctly."""
        error = Exception("Rate limit exceeded")
        result = _sanitize_agent_error(error)
        assert AgentErrorCode.LLM_ERROR in result

    def test_connection_error_mapping(self, development_env):
        """Test connection errors are mapped correctly."""
        error = Exception("Connection refused to LLM service")
        result = _sanitize_agent_error(error)
        assert AgentErrorCode.LLM_ERROR in result

    def test_unknown_error_defaults_to_internal(self, development_env):
        """Test unknown errors default to INTERNAL_ERROR."""
        error = Exception("Some completely unknown error type")
        result = _sanitize_agent_error(error)
        assert AgentErrorCode.INTERNAL_ERROR in result

    def test_development_includes_full_message(self, development_env):
        """Test that development mode includes full error message."""
        error = Exception("Detailed error: connection to db://secret:pass@host failed")
        result = _sanitize_agent_error(error)
        assert "Detailed error" in result
        assert "secret:pass" in result  # Full details in dev

    def test_production_hides_sensitive_details(self, production_env):
        """Test that production mode hides sensitive details."""
        error = Exception("Database connection failed: postgres://user:secret_password@internal-host:5432/db")
        result = _sanitize_agent_error(error)
        assert "secret_password" not in result
        assert "internal-host" not in result
        assert "postgres://" not in result

    def test_production_shows_generic_message(self, production_env):
        """Test that production shows generic error messages."""
        error = Exception("Internal stack trace: File '/app/secret/path.py', line 42")
        result = _sanitize_agent_error(error)
        assert "stack trace" not in result.lower()
        assert "/app/secret/path.py" not in result
        assert "line 42" not in result

    def test_error_code_always_present(self, production_env):
        """Test that error code is always in the output."""
        error = Exception("Any error")
        result = _sanitize_agent_error(error)
        # Should contain an error code in brackets
        assert "[AGENT_" in result

    def test_no_stack_trace_patterns_in_production(self, production_env):
        """Test that stack trace patterns never appear in production."""
        stack_trace_patterns = [
            "Traceback (most recent call last)",
            'File "',
            ".py\", line",
            "    raise ",
            "    return ",
        ]

        for pattern in stack_trace_patterns:
            error = Exception(f"Error with {pattern} in message")
            result = _sanitize_agent_error(error)
            assert pattern not in result


# ============================================================================
# ParseError Sanitization Tests
# ============================================================================


class TestParseErrorCodes:
    """Tests for ParseError error codes."""

    def test_all_codes_defined(self):
        """Verify all error codes are defined."""
        assert ErrorCode.EMPTY_RESPONSE == "PARSE_EMPTY_RESPONSE"
        assert ErrorCode.NO_JSON_FOUND == "PARSE_NO_JSON_FOUND"
        assert ErrorCode.INVALID_JSON == "PARSE_INVALID_JSON"
        assert ErrorCode.VALIDATION_FAILED == "PARSE_VALIDATION_FAILED"
        assert ErrorCode.INTERNAL_ERROR == "PARSE_INTERNAL_ERROR"

    def test_codes_follow_naming_convention(self):
        """Verify error codes follow PARSE_ prefix convention."""
        codes = [
            ErrorCode.EMPTY_RESPONSE,
            ErrorCode.NO_JSON_FOUND,
            ErrorCode.INVALID_JSON,
            ErrorCode.VALIDATION_FAILED,
            ErrorCode.INTERNAL_ERROR,
        ]
        for code in codes:
            assert code.startswith("PARSE_")
            assert code.isupper()


class TestParseErrorSanitization:
    """Tests for ParseError sanitization behavior."""

    def test_parse_error_has_error_code_attribute(self, development_env):
        """Test that ParseError has error_code attribute."""
        error = ParseError("Test error", error_code=ErrorCode.INTERNAL_ERROR)
        assert hasattr(error, "error_code")
        assert error.error_code == ErrorCode.INTERNAL_ERROR

    def test_parse_error_development_stores_raw_text(self, development_env):
        """Test that raw_text is stored in development."""
        raw_text = "sensitive LLM output"
        error = ParseError("Test", raw_text=raw_text, error_code=ErrorCode.INTERNAL_ERROR)
        assert error.raw_text == raw_text

    def test_parse_error_production_clears_raw_text(self, production_env):
        """Test that raw_text is cleared in production."""
        raw_text = "sensitive LLM output"
        error = ParseError("Test", raw_text=raw_text, error_code=ErrorCode.INTERNAL_ERROR)
        assert error.raw_text is None

    def test_parse_error_development_stores_cause(self, development_env):
        """Test that cause is stored in development."""
        cause = ValueError("Original error")
        error = ParseError("Test", cause=cause, error_code=ErrorCode.INTERNAL_ERROR)
        assert error.cause == cause

    def test_parse_error_production_clears_cause(self, production_env):
        """Test that cause is cleared in production."""
        cause = ValueError("Original error with secrets")
        error = ParseError("Test", cause=cause, error_code=ErrorCode.INTERNAL_ERROR)
        assert error.cause is None


# ============================================================================
# Information Disclosure Prevention Tests
# ============================================================================


class TestInformationDisclosurePrevention:
    """Tests to verify no information disclosure in error messages."""

    def test_no_file_paths_in_production_errors(self, production_env):
        """Test that file paths are not exposed in production."""
        sensitive_paths = [
            "/app/secret/config.py",
            "/home/user/.credentials",
            "/var/lib/postgresql/data",
            "C:\\Users\\admin\\secrets.txt",
        ]

        for path in sensitive_paths:
            error = Exception(f"Error occurred in {path}")
            result = _sanitize_agent_error(error)
            assert path not in result

    def test_no_credentials_in_production_errors(self, production_env):
        """Test that credentials are not exposed in production."""
        error = Exception("Failed to connect: postgres://user:password123@localhost/db")
        result = _sanitize_agent_error(error)
        assert "password123" not in result
        assert "user:" not in result

    def test_no_api_keys_in_production_errors(self, production_env):
        """Test that API keys are not exposed in production."""
        error = Exception("API call failed with key: sk-abc123xyz789secretkey")
        result = _sanitize_agent_error(error)
        assert "sk-abc123xyz789secretkey" not in result

    def test_no_internal_ips_in_production_errors(self, production_env):
        """Test that internal IPs are not exposed in production."""
        error = Exception("Connection failed to 10.0.0.15:5432")
        result = _sanitize_agent_error(error)
        assert "10.0.0.15" not in result

    def test_no_raw_llm_output_in_production_errors(self, production_env):
        """Test that raw LLM output is not exposed in production."""
        llm_output = """
        I apologize, but I cannot complete that task because:
        1. The system prompt restricts...
        2. The internal configuration shows...
        """
        error = Exception(f"Parse error: {llm_output}")
        result = _sanitize_agent_error(error)
        assert "system prompt" not in result.lower()
        assert "internal configuration" not in result.lower()


# ============================================================================
# Integration Tests
# ============================================================================


class TestErrorSanitizationIntegration:
    """Integration tests for error sanitization across components."""

    def test_error_codes_are_unique_across_modules(self):
        """Test that error codes don't conflict between modules."""
        parse_codes = {
            ErrorCode.EMPTY_RESPONSE,
            ErrorCode.NO_JSON_FOUND,
            ErrorCode.INVALID_JSON,
            ErrorCode.VALIDATION_FAILED,
            ErrorCode.INTERNAL_ERROR,
        }

        agent_codes = {
            AgentErrorCode.TIMEOUT,
            AgentErrorCode.MAX_ITERATIONS,
            AgentErrorCode.TOKEN_BUDGET_EXCEEDED,
            AgentErrorCode.PARSE_ERROR,
            AgentErrorCode.TOOL_ERROR,
            AgentErrorCode.LLM_ERROR,
            AgentErrorCode.INTERNAL_ERROR,
        }

        # All codes should be unique
        all_codes = parse_codes | agent_codes
        assert len(all_codes) == len(parse_codes) + len(agent_codes)

        # All should follow their respective prefix conventions
        for code in parse_codes:
            assert code.startswith("PARSE_")
        for code in agent_codes:
            assert code.startswith("AGENT_")

    def test_client_can_handle_all_error_codes(self, production_env):
        """Test that all possible errors return codes clients can handle."""
        test_errors = [
            Exception("Connection timed out"),
            Exception("max_iterations reached"),
            Exception("Token budget exceeded"),
            Exception("Failed to parse JSON"),
            Exception("LLM API error"),
            Exception("Unknown internal error"),
        ]

        for error in test_errors:
            result = _sanitize_agent_error(error)
            # Should always have an error code in brackets
            assert "[AGENT_" in result
            # Should end with a user-friendly message
            assert not result.endswith("]")
