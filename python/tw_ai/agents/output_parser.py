"""Output parsing and validation for LLM responses."""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any

from pydantic import ValidationError

from tw_ai.agents.models import TriageAnalysis

logger = logging.getLogger(__name__)


# Error codes for client-side handling
class ErrorCode:
    """Error codes for ParseError to enable client-side handling."""

    EMPTY_RESPONSE = "PARSE_EMPTY_RESPONSE"
    NO_JSON_FOUND = "PARSE_NO_JSON_FOUND"
    INVALID_JSON = "PARSE_INVALID_JSON"
    VALIDATION_FAILED = "PARSE_VALIDATION_FAILED"
    INTERNAL_ERROR = "PARSE_INTERNAL_ERROR"


def _is_production() -> bool:
    """Check if running in production environment."""
    for var in ("TW_ENV", "NODE_ENV", "ENVIRONMENT"):
        value = os.environ.get(var, "").lower()
        if value in ("production", "prod"):
            return True
    return False


def _sanitize_error_message(
    code: str,
    detailed_message: str,
    generic_message: str,
) -> str:
    """
    Return appropriate error message based on environment.

    In production, returns a generic message to prevent information disclosure.
    In development, returns the detailed message for debugging.

    Args:
        code: Error code for client-side handling.
        detailed_message: Detailed error message for logging/development.
        generic_message: Generic message safe for production.

    Returns:
        Appropriate error message for the environment.
    """
    if _is_production():
        return f"[{code}] {generic_message}"
    return f"[{code}] {detailed_message}"


class ParseError(Exception):
    """Raised when parsing LLM output fails.

    In production environments, this error will not include sensitive details
    like raw LLM output or stack traces. Use the error_code attribute for
    programmatic error handling.
    """

    def __init__(
        self,
        message: str,
        raw_text: str | None = None,
        cause: Exception | None = None,
        error_code: str = ErrorCode.INTERNAL_ERROR,
    ):
        """
        Initialize ParseError with context.

        Args:
            message: Human-readable error message.
            raw_text: The raw text that failed to parse (only stored in non-production).
            cause: The underlying exception that caused the error.
            error_code: Machine-readable error code for client handling.
        """
        super().__init__(message)
        self.error_code = error_code

        # Only store raw_text and detailed cause in non-production environments
        # to prevent information leakage in production
        if _is_production():
            # Log detailed info server-side only
            if raw_text:
                logger.error(
                    "Parse error occurred",
                    extra={
                        "error_code": error_code,
                        "raw_text_preview": raw_text[:500] if raw_text else None,
                        "cause": str(cause) if cause else None,
                    },
                )
            self.raw_text = None
            self.cause = None
        else:
            self.raw_text = raw_text
            self.cause = cause


def _fix_json_common_issues(text: str) -> str:
    """
    Attempt to fix common JSON formatting issues from LLM output.

    Handles:
    - Trailing commas before ] or }
    - Single quotes instead of double quotes
    - Unquoted keys
    - Missing commas between elements

    Args:
        text: The potentially malformed JSON string.

    Returns:
        A cleaned JSON string.
    """
    # Remove trailing commas before closing brackets/braces
    # Pattern: comma followed by optional whitespace, then ] or }
    text = re.sub(r",\s*([}\]])", r"\1", text)

    # Replace single quotes with double quotes (careful with apostrophes)
    # First, handle cases where the string is clearly using single quotes for JSON
    # This regex looks for patterns like 'key': or : 'value'
    text = re.sub(r"'(\w+)'(\s*:)", r'"\1"\2', text)  # 'key': -> "key":
    text = re.sub(r":\s*'([^']*)'", r': "\1"', text)  # : 'value' -> : "value"

    # Handle boolean and null values that might be lowercase
    # JSON requires true/false/null to be lowercase, but LLMs sometimes use True/False/None
    text = re.sub(r"\bTrue\b", "true", text)
    text = re.sub(r"\bFalse\b", "false", text)
    text = re.sub(r"\bNone\b", "null", text)

    return text


def _extract_json_block(text: str) -> str | None:
    """
    Extract JSON from markdown code blocks.

    Looks for ```json ... ``` or ``` ... ``` patterns.

    Args:
        text: The text potentially containing a JSON code block.

    Returns:
        The extracted JSON string, or None if no code block found.
    """
    # Try ```json first
    json_block_pattern = r"```json\s*([\s\S]*?)\s*```"
    match = re.search(json_block_pattern, text, re.IGNORECASE)
    if match:
        return match.group(1).strip()

    # Try generic code block
    generic_block_pattern = r"```\s*([\s\S]*?)\s*```"
    match = re.search(generic_block_pattern, text)
    if match:
        content = match.group(1).strip()
        # Verify it looks like JSON (starts with { or [)
        if content and content[0] in "{[":
            return content

    return None


def _find_json_object(text: str) -> str | None:
    """
    Find a JSON object or array in text without code blocks.

    Uses bracket matching to extract valid JSON structures.

    Args:
        text: The text to search.

    Returns:
        The extracted JSON string, or None if not found.
    """
    # Find the first { or [ that could start a JSON structure
    start_chars = {"{": "}", "[": "]"}

    for i, char in enumerate(text):
        if char in start_chars:
            # Try to find the matching closing bracket
            end_char = start_chars[char]
            depth = 0
            in_string = False
            escape_next = False

            for j in range(i, len(text)):
                c = text[j]

                if escape_next:
                    escape_next = False
                    continue

                if c == "\\":
                    escape_next = True
                    continue

                if c == '"' and not escape_next:
                    in_string = not in_string
                    continue

                if in_string:
                    continue

                if c == char:
                    depth += 1
                elif c == end_char:
                    depth -= 1
                    if depth == 0:
                        return text[i : j + 1]

    return None


def parse_json_from_response(text: str) -> dict[str, Any]:
    """
    Extract and parse JSON from an LLM response.

    This function handles various formats:
    - JSON in ```json ... ``` code blocks
    - JSON in plain ``` ... ``` code blocks
    - Raw JSON objects in the response
    - Common formatting issues (trailing commas, single quotes)

    Args:
        text: The raw LLM response text.

    Returns:
        The parsed JSON as a dictionary.

    Raises:
        ParseError: If no valid JSON can be extracted.
    """
    if not text or not text.strip():
        raise ParseError(
            _sanitize_error_message(
                ErrorCode.EMPTY_RESPONSE,
                "Empty response text",
                "No response received",
            ),
            raw_text=text,
            error_code=ErrorCode.EMPTY_RESPONSE,
        )

    # Strategy 1: Try to extract from code block
    json_str = _extract_json_block(text)

    # Strategy 2: Try to find raw JSON object
    if json_str is None:
        json_str = _find_json_object(text)

    # Strategy 3: Maybe the whole text is JSON
    if json_str is None:
        json_str = text.strip()

    if not json_str:
        raise ParseError(
            _sanitize_error_message(
                ErrorCode.NO_JSON_FOUND,
                "No JSON content found in response",
                "Unable to parse response format",
            ),
            raw_text=text,
            error_code=ErrorCode.NO_JSON_FOUND,
        )

    # Try to parse as-is first
    try:
        result: dict[str, Any] = json.loads(json_str)
        return result
    except json.JSONDecodeError:
        pass

    # Try with common fixes applied
    fixed_json = _fix_json_common_issues(json_str)
    try:
        fixed_result: dict[str, Any] = json.loads(fixed_json)
        return fixed_result
    except json.JSONDecodeError as e:
        # Log detailed error server-side
        logger.error(
            "JSON parse error",
            extra={
                "error_msg": e.msg,
                "error_pos": e.pos,
                "json_preview": json_str[:200] if json_str else None,
            },
        )
        raise ParseError(
            _sanitize_error_message(
                ErrorCode.INVALID_JSON,
                f"Failed to parse JSON: {e.msg} at position {e.pos}",
                "Invalid response format - unable to parse",
            ),
            raw_text=text,
            cause=e,
            error_code=ErrorCode.INVALID_JSON,
        ) from e


def parse_triage_analysis(text: str) -> TriageAnalysis:
    """
    Parse and validate a triage analysis from LLM response.

    This function extracts JSON from the response and validates it
    against the TriageAnalysis schema.

    Args:
        text: The raw LLM response text.

    Returns:
        A validated TriageAnalysis object.

    Raises:
        ParseError: If parsing or validation fails.
    """
    try:
        data = parse_json_from_response(text)
    except ParseError:
        raise

    # Handle optional fields that might be missing
    if "indicators" not in data:
        data["indicators"] = []
    if "mitre_techniques" not in data:
        data["mitre_techniques"] = []
    if "recommended_actions" not in data:
        data["recommended_actions"] = []
    if "reasoning" not in data:
        data["reasoning"] = ""

    # Validate with Pydantic
    try:
        return TriageAnalysis.model_validate(data)
    except ValidationError as e:
        # Build a helpful error message for development
        error_messages = []
        for error in e.errors():
            loc = " -> ".join(str(x) for x in error["loc"])
            msg = error["msg"]
            error_messages.append(f"  - {loc}: {msg}")

        detailed_message = "Validation failed:\n" + "\n".join(error_messages)

        # Log detailed validation errors server-side
        logger.error(
            "Triage analysis validation failed",
            extra={
                "validation_errors": e.errors(),
                "error_count": len(e.errors()),
            },
        )

        raise ParseError(
            _sanitize_error_message(
                ErrorCode.VALIDATION_FAILED,
                detailed_message,
                "Response validation failed - invalid data format",
            ),
            raw_text=text,
            cause=e,
            error_code=ErrorCode.VALIDATION_FAILED,
        ) from e
