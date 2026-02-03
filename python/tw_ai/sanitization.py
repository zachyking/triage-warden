"""PII redaction, data sanitization, and prompt injection protection for LLM prompts.

This module provides:
1. Configurable PII detection and redaction to prevent sensitive data from
   being sent to external LLM providers.
2. Prompt injection protection to prevent malicious user input from
   manipulating LLM behavior.

PII Redaction Features:
- Configurable redaction patterns for SSN, credit cards, emails, phone numbers
- Two modes: strict (redact all PII) vs permissive (allow certain PII types)
- Preserves structure with replacement tokens like [REDACTED_SSN]
- Audit logging of all redactions for compliance tracking

Prompt Injection Protection Features:
- Configurable sanitization rules
- Detection of common prompt injection patterns (e.g., "ignore previous instructions")
- Escaping of special characters that could manipulate prompts
- Structured output format protection
- Logging of detected injection attempts
"""

from __future__ import annotations

import json
import re
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from re import Pattern
from typing import Any

import structlog

logger = structlog.get_logger()


class PIIType(str, Enum):
    """Types of PII that can be detected and redacted."""

    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    EMAIL = "email"
    PHONE = "phone"
    IP_ADDRESS = "ip_address"
    AWS_KEY = "aws_key"
    API_KEY = "api_key"


class RedactionMode(str, Enum):
    """Mode for PII redaction."""

    STRICT = "strict"  # Redact all PII types
    PERMISSIVE = "permissive"  # Allow certain PII types (e.g., emails for security analysis)


@dataclass
class PIIPattern:
    """A pattern for detecting a specific type of PII."""

    pii_type: PIIType
    pattern: Pattern[str]
    replacement: str
    description: str
    enabled: bool = True

    def __post_init__(self) -> None:
        """Compile the pattern if it's a string."""
        if isinstance(self.pattern, str):
            self.pattern = re.compile(self.pattern)


@dataclass
class RedactionRecord:
    """Record of a single redaction for audit purposes."""

    record_id: str
    pii_type: PIIType
    original_hash: str  # SHA256 hash of original value (for audit without storing PII)
    replacement: str
    context_preview: str  # Surrounding context (redacted)
    timestamp: float
    field_path: str | None = None  # JSON path if applicable

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "record_id": self.record_id,
            "pii_type": self.pii_type.value,
            "original_hash": self.original_hash,
            "replacement": self.replacement,
            "context_preview": self.context_preview,
            "timestamp": self.timestamp,
            "field_path": self.field_path,
        }


@dataclass
class RedactionResult:
    """Result of a redaction operation."""

    redacted_text: str
    original_text: str
    redaction_count: int
    records: list[RedactionRecord] = field(default_factory=list)
    pii_types_found: set[PIIType] = field(default_factory=set)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "redacted_text": self.redacted_text,
            "redaction_count": self.redaction_count,
            "pii_types_found": [t.value for t in self.pii_types_found],
            "records": [r.to_dict() for r in self.records],
        }


def _hash_value(value: str) -> str:
    """Create a SHA256 hash of a value for audit purposes."""
    import hashlib

    return hashlib.sha256(value.encode()).hexdigest()[:16]  # Truncated for readability


def _luhn_checksum(card_number: str) -> bool:
    """Validate credit card number using Luhn algorithm."""
    digits = [int(d) for d in card_number if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False

    # Luhn algorithm
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]

    checksum = sum(odd_digits)
    for digit in even_digits:
        doubled = digit * 2
        checksum += doubled if doubled < 10 else doubled - 9

    return checksum % 10 == 0


class PIIRedactor:
    """Configurable PII detection and redaction.

    Example usage:
        redactor = PIIRedactor(mode=RedactionMode.STRICT)
        result = redactor.redact("Contact: john@example.com, SSN: 123-45-6789")
        print(result.redacted_text)
        # Output: "Contact: [REDACTED_EMAIL], SSN: [REDACTED_SSN]"
    """

    # Default PII patterns
    DEFAULT_PATTERNS = [
        PIIPattern(
            pii_type=PIIType.SSN,
            pattern=re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
            replacement="[REDACTED_SSN]",
            description="US Social Security Number (XXX-XX-XXXX format)",
        ),
        PIIPattern(
            pii_type=PIIType.SSN,
            # 9 consecutive digits, not followed by more digits
            pattern=re.compile(r"\b\d{9}\b(?!\d)"),
            replacement="[REDACTED_SSN]",
            description="US Social Security Number (9 consecutive digits)",
            enabled=False,  # Disabled by default due to false positives
        ),
        PIIPattern(
            pii_type=PIIType.CREDIT_CARD,
            pattern=re.compile(r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b"),
            replacement="[REDACTED_CC]",
            description="Credit card number (16 digits with optional separators)",
        ),
        PIIPattern(
            pii_type=PIIType.CREDIT_CARD,
            pattern=re.compile(r"\b\d{4}[- ]?\d{6}[- ]?\d{5}\b"),
            replacement="[REDACTED_CC]",
            description="American Express card number (15 digits)",
        ),
        PIIPattern(
            pii_type=PIIType.EMAIL,
            pattern=re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
            replacement="[REDACTED_EMAIL]",
            description="Email address",
        ),
        PIIPattern(
            pii_type=PIIType.PHONE,
            pattern=re.compile(r"\b(?:\+1[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}\b"),
            replacement="[REDACTED_PHONE]",
            description="US phone number (various formats)",
        ),
        PIIPattern(
            pii_type=PIIType.PHONE,
            pattern=re.compile(r"\b\+\d{1,3}[- ]?\d{6,14}\b"),
            replacement="[REDACTED_PHONE]",
            description="International phone number",
        ),
        PIIPattern(
            pii_type=PIIType.AWS_KEY,
            pattern=re.compile(r"\b(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\b"),
            replacement="[REDACTED_AWS_KEY]",
            description="AWS Access Key ID",
        ),
        PIIPattern(
            pii_type=PIIType.API_KEY,
            pattern=re.compile(
                r"\b(sk-[A-Za-z0-9]{32,}|ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36})\b"
            ),
            replacement="[REDACTED_API_KEY]",
            description="Common API keys (OpenAI, GitHub)",
        ),
    ]

    # PII types allowed in permissive mode (useful for security analysis)
    PERMISSIVE_ALLOWED = {
        PIIType.EMAIL,  # Emails are often needed for phishing analysis
        PIIType.IP_ADDRESS,  # IPs are critical for threat intel
    }

    def __init__(
        self,
        mode: RedactionMode = RedactionMode.STRICT,
        custom_patterns: list[PIIPattern] | None = None,
        allowed_types: set[PIIType] | None = None,
        enable_audit_log: bool = True,
        validate_credit_cards: bool = True,
    ) -> None:
        """Initialize the PII redactor.

        Args:
            mode: Redaction mode (strict or permissive)
            custom_patterns: Additional custom patterns to include
            allowed_types: Override default allowed types for permissive mode
            enable_audit_log: Whether to log redaction audit records
            validate_credit_cards: Whether to validate CC numbers with Luhn algorithm
        """
        self.mode = mode
        self.enable_audit_log = enable_audit_log
        self.validate_credit_cards = validate_credit_cards

        # Set allowed types based on mode
        if mode == RedactionMode.PERMISSIVE:
            self.allowed_types = allowed_types or self.PERMISSIVE_ALLOWED.copy()
        else:
            self.allowed_types = allowed_types or set()

        # Build pattern list
        self.patterns = [p for p in self.DEFAULT_PATTERNS if p.enabled]
        if custom_patterns:
            self.patterns.extend(custom_patterns)

        # Audit log storage
        self._audit_log: list[RedactionRecord] = []

        logger.info(
            "pii_redactor_initialized",
            mode=mode.value,
            pattern_count=len(self.patterns),
            allowed_types=[t.value for t in self.allowed_types],
        )

    def add_pattern(self, pattern: PIIPattern) -> None:
        """Add a custom pattern to the redactor.

        Args:
            pattern: The PIIPattern to add
        """
        self.patterns.append(pattern)
        logger.debug(
            "pii_pattern_added",
            pii_type=pattern.pii_type.value,
            description=pattern.description,
        )

    def remove_pattern(self, pii_type: PIIType) -> int:
        """Remove all patterns for a specific PII type.

        Args:
            pii_type: The PII type to remove patterns for

        Returns:
            Number of patterns removed
        """
        original_count = len(self.patterns)
        self.patterns = [p for p in self.patterns if p.pii_type != pii_type]
        removed = original_count - len(self.patterns)
        logger.debug("pii_patterns_removed", pii_type=pii_type.value, count=removed)
        return removed

    def _should_redact(self, pii_type: PIIType) -> bool:
        """Check if a PII type should be redacted based on mode and allowed types."""
        if self.mode == RedactionMode.STRICT:
            return pii_type not in self.allowed_types
        else:  # PERMISSIVE
            return pii_type not in self.allowed_types

    def _validate_match(self, pii_type: PIIType, match: str) -> bool:
        """Validate a match beyond regex pattern matching.

        Args:
            pii_type: Type of PII detected
            match: The matched string

        Returns:
            True if the match is valid PII
        """
        if pii_type == PIIType.CREDIT_CARD and self.validate_credit_cards:
            # Validate credit card with Luhn algorithm
            return _luhn_checksum(match)

        return True

    def _create_context_preview(
        self, text: str, match_start: int, match_end: int, window: int = 20
    ) -> str:
        """Create a preview of the context around a match (with the match redacted)."""
        start = max(0, match_start - window)
        end = min(len(text), match_end + window)

        before = text[start:match_start]
        after = text[match_end:end]

        return f"...{before}[MATCH]{after}..."

    def redact(self, text: str, field_path: str | None = None) -> RedactionResult:
        """Redact PII from text.

        Args:
            text: The text to redact
            field_path: Optional JSON path for audit logging

        Returns:
            RedactionResult with redacted text and audit records
        """
        if not text:
            return RedactionResult(
                redacted_text=text,
                original_text=text,
                redaction_count=0,
            )

        result_text = text
        records: list[RedactionRecord] = []
        pii_types_found: set[PIIType] = set()
        total_redactions = 0

        # Track offset adjustments due to replacements
        offset = 0

        # Process each pattern
        for pattern in self.patterns:
            if not self._should_redact(pattern.pii_type):
                continue

            # Find all matches in original text
            for match in pattern.pattern.finditer(text):
                matched_value = match.group()

                # Validate the match
                if not self._validate_match(pattern.pii_type, matched_value):
                    continue

                pii_types_found.add(pattern.pii_type)

                # Calculate adjusted positions
                adjusted_start = match.start() + offset
                adjusted_end = match.end() + offset

                # Create audit record
                record = RedactionRecord(
                    record_id=str(uuid.uuid4())[:8],
                    pii_type=pattern.pii_type,
                    original_hash=_hash_value(matched_value),
                    replacement=pattern.replacement,
                    context_preview=self._create_context_preview(text, match.start(), match.end()),
                    timestamp=time.time(),
                    field_path=field_path,
                )
                records.append(record)

                # Perform replacement
                before = result_text[:adjusted_start]
                after = result_text[adjusted_end:]
                result_text = before + pattern.replacement + after

                # Update offset
                offset += len(pattern.replacement) - len(matched_value)
                total_redactions += 1

        # Log audit records
        if self.enable_audit_log and records:
            self._audit_log.extend(records)
            logger.info(
                "pii_redaction_performed",
                redaction_count=total_redactions,
                pii_types=[t.value for t in pii_types_found],
                field_path=field_path,
            )

        return RedactionResult(
            redacted_text=result_text,
            original_text=text,
            redaction_count=total_redactions,
            records=records,
            pii_types_found=pii_types_found,
        )

    def redact_dict(
        self,
        data: dict[str, Any],
        path_prefix: str = "",
    ) -> tuple[dict[str, Any], list[RedactionRecord]]:
        """Recursively redact PII from a dictionary.

        Args:
            data: The dictionary to redact
            path_prefix: Current JSON path prefix for audit logging

        Returns:
            Tuple of (redacted dict, list of redaction records)
        """
        result: dict[str, Any] = {}
        all_records: list[RedactionRecord] = []

        for key, value in data.items():
            current_path = f"{path_prefix}.{key}" if path_prefix else key

            if isinstance(value, str):
                redaction_result = self.redact(value, field_path=current_path)
                result[key] = redaction_result.redacted_text
                all_records.extend(redaction_result.records)

            elif isinstance(value, dict):
                nested_result, nested_records = self.redact_dict(value, current_path)
                result[key] = nested_result
                all_records.extend(nested_records)

            elif isinstance(value, list):
                result[key] = []
                for i, item in enumerate(value):
                    item_path = f"{current_path}[{i}]"
                    if isinstance(item, str):
                        redaction_result = self.redact(item, field_path=item_path)
                        result[key].append(redaction_result.redacted_text)
                        all_records.extend(redaction_result.records)
                    elif isinstance(item, dict):
                        nested_result, nested_records = self.redact_dict(item, item_path)
                        result[key].append(nested_result)
                        all_records.extend(nested_records)
                    else:
                        result[key].append(item)
            else:
                result[key] = value

        return result, all_records

    def redact_json(self, json_str: str) -> tuple[str, list[RedactionRecord]]:
        """Redact PII from a JSON string.

        Args:
            json_str: The JSON string to redact

        Returns:
            Tuple of (redacted JSON string, list of redaction records)
        """
        try:
            data = json.loads(json_str)
            if isinstance(data, dict):
                redacted_data, records = self.redact_dict(data)
                return json.dumps(redacted_data, indent=2), records
            elif isinstance(data, list):
                # Handle list at root level
                result_list: list[Any] = []
                all_records: list[RedactionRecord] = []
                for i, item in enumerate(data):
                    if isinstance(item, dict):
                        redacted_item, records = self.redact_dict(item, f"[{i}]")
                        result_list.append(redacted_item)
                        all_records.extend(records)
                    elif isinstance(item, str):
                        redaction_result = self.redact(item, field_path=f"[{i}]")
                        result_list.append(redaction_result.redacted_text)
                        all_records.extend(redaction_result.records)
                    else:
                        result_list.append(item)
                return json.dumps(result_list, indent=2), all_records
            else:
                # Scalar value
                if isinstance(data, str):
                    result = self.redact(data)
                    return json.dumps(result.redacted_text), result.records
                return json_str, []
        except json.JSONDecodeError:
            # Fall back to text redaction
            result = self.redact(json_str)
            return result.redacted_text, result.records

    def get_audit_log(self) -> list[RedactionRecord]:
        """Get the audit log of all redactions.

        Returns:
            List of RedactionRecord objects
        """
        return self._audit_log.copy()

    def clear_audit_log(self) -> int:
        """Clear the audit log.

        Returns:
            Number of records cleared
        """
        count = len(self._audit_log)
        self._audit_log.clear()
        logger.debug("audit_log_cleared", records_cleared=count)
        return count

    def export_audit_log(self) -> list[dict[str, Any]]:
        """Export the audit log as a list of dictionaries.

        Returns:
            List of audit records as dictionaries
        """
        return [record.to_dict() for record in self._audit_log]


# Convenience factory functions
def create_strict_redactor(**kwargs: Any) -> PIIRedactor:
    """Create a strict PII redactor that redacts all PII types.

    Args:
        **kwargs: Additional arguments to pass to PIIRedactor

    Returns:
        PIIRedactor configured in strict mode
    """
    return PIIRedactor(mode=RedactionMode.STRICT, **kwargs)


def create_permissive_redactor(
    allowed_types: set[PIIType] | None = None,
    **kwargs: Any,
) -> PIIRedactor:
    """Create a permissive PII redactor that allows certain PII types.

    Args:
        allowed_types: Set of PII types to allow (defaults to EMAIL and IP_ADDRESS)
        **kwargs: Additional arguments to pass to PIIRedactor

    Returns:
        PIIRedactor configured in permissive mode
    """
    return PIIRedactor(
        mode=RedactionMode.PERMISSIVE,
        allowed_types=allowed_types,
        **kwargs,
    )


def create_security_analysis_redactor(**kwargs: Any) -> PIIRedactor:
    """Create a PII redactor optimized for security alert analysis.

    This redactor allows emails and IP addresses (critical for threat analysis)
    while still redacting sensitive PII like SSN and credit cards.

    Args:
        **kwargs: Additional arguments to pass to PIIRedactor

    Returns:
        PIIRedactor configured for security analysis
    """
    return PIIRedactor(
        mode=RedactionMode.PERMISSIVE,
        allowed_types={PIIType.EMAIL, PIIType.IP_ADDRESS},
        **kwargs,
    )


__all__ = [
    # PII Redaction
    "PIIType",
    "RedactionMode",
    "PIIPattern",
    "RedactionRecord",
    "RedactionResult",
    "PIIRedactor",
    "create_strict_redactor",
    "create_permissive_redactor",
    "create_security_analysis_redactor",
    # Prompt Injection Protection
    "PromptSanitizer",
    "PromptInjectionError",
    "SanitizationResult",
    "SanitizationAction",
    "InjectionSeverity",
    "InjectionPattern",
    "DEFAULT_INJECTION_PATTERNS",
    "create_safe_data_block",
    "sanitize_alert_data",
    "sanitize_string",
]


# =============================================================================
# Prompt Injection Protection
# =============================================================================


class SanitizationAction(str, Enum):
    """Action to take when a prompt injection pattern is detected."""

    BLOCK = "block"  # Raise an exception
    ESCAPE = "escape"  # Escape the content
    REMOVE = "remove"  # Remove the matching content
    LOG_ONLY = "log_only"  # Log but allow through


class InjectionSeverity(str, Enum):
    """Severity level of detected injection attempts."""

    CRITICAL = "critical"  # Definite attack attempt
    HIGH = "high"  # Very likely attack
    MEDIUM = "medium"  # Suspicious pattern
    LOW = "low"  # Possibly benign


@dataclass
class InjectionPattern:
    """A pattern that may indicate prompt injection."""

    name: str
    pattern: re.Pattern[str]
    severity: InjectionSeverity
    action: SanitizationAction
    description: str

    def __post_init__(self) -> None:
        """Compile pattern if string."""
        if isinstance(self.pattern, str):
            self.pattern = re.compile(self.pattern, re.IGNORECASE | re.MULTILINE)


@dataclass
class SanitizationResult:
    """Result of prompt sanitization operation."""

    sanitized: str
    was_modified: bool
    blocked: bool
    detections: list[dict[str, Any]] = field(default_factory=list)

    @property
    def had_detections(self) -> bool:
        """Check if any patterns were detected."""
        return len(self.detections) > 0


class PromptInjectionError(Exception):
    """Raised when a prompt injection attack is detected and blocked."""

    def __init__(
        self,
        message: str,
        pattern_name: str,
        severity: InjectionSeverity,
        matched_content: str,
    ):
        super().__init__(message)
        self.pattern_name = pattern_name
        self.severity = severity
        self.matched_content = matched_content[:100]  # Truncate for safety


# Default patterns for detecting prompt injection attacks
DEFAULT_INJECTION_PATTERNS: list[InjectionPattern] = [
    # Direct instruction override attempts
    InjectionPattern(
        name="ignore_instructions",
        pattern=re.compile(
            r"(?:ignore|disregard|forget|override|skip|bypass)\s+"
            r"(?:all\s+)?(?:previous|prior|above|earlier|your|the|any)?\s*"
            r"(?:instructions?|prompts?|rules?|guidelines?|constraints?|context)",
            re.IGNORECASE | re.MULTILINE,
        ),
        severity=InjectionSeverity.CRITICAL,
        action=SanitizationAction.BLOCK,
        description="Attempt to override system instructions",
    ),
    InjectionPattern(
        name="new_instructions",
        pattern=re.compile(
            r"(?:new|updated?|revised?|actual|real)\s+"
            r"(?:instructions?|prompts?|rules?|task|mission|objective)",
            re.IGNORECASE | re.MULTILINE,
        ),
        severity=InjectionSeverity.HIGH,
        action=SanitizationAction.ESCAPE,
        description="Attempt to inject new instructions",
    ),
    # Role manipulation
    InjectionPattern(
        name="role_switch",
        pattern=re.compile(
            r"(?:you\s+are\s+now|act\s+as|pretend\s+(?:to\s+be|you(?:'re|\s+are))|"
            r"roleplay\s+as|assume\s+the\s+role|switch\s+to|become)\s+"
            r"(?:a\s+|an\s+)?(?:different|new|another|my)?\s*"
            r"(?:assistant|ai|bot|agent|system|admin|root|developer)?",
            re.IGNORECASE | re.MULTILINE,
        ),
        severity=InjectionSeverity.CRITICAL,
        action=SanitizationAction.BLOCK,
        description="Attempt to change AI role or identity",
    ),
    # System prompt extraction
    InjectionPattern(
        name="system_prompt_extraction",
        pattern=re.compile(
            r"(?:show|reveal|display|print|output|repeat|tell\s+me|what\s+(?:is|are)|"
            r"share|expose|dump|extract|give\s+me)\s+"
            r"(?:your|the|all)?\s*"
            r"(?:system\s+)?(?:prompt|instructions?|rules?|guidelines?|context|configuration)",
            re.IGNORECASE | re.MULTILINE,
        ),
        severity=InjectionSeverity.HIGH,
        action=SanitizationAction.ESCAPE,
        description="Attempt to extract system prompt",
    ),
    # Message role markers (common in chat-based attacks)
    InjectionPattern(
        name="role_markers",
        pattern=re.compile(
            r"^\s*(?:system|assistant|user|human|ai|bot|admin)\s*:\s*",
            re.IGNORECASE | re.MULTILINE,
        ),
        severity=InjectionSeverity.CRITICAL,
        action=SanitizationAction.REMOVE,
        description="Fake message role markers",
    ),
    # XML/HTML-like injection
    InjectionPattern(
        name="xml_injection",
        pattern=re.compile(
            r"<\s*/?(?:system|prompt|instruction|context|rules?|admin|override|"
            r"assistant|user|message|ignore|jailbreak)[^>]*>",
            re.IGNORECASE | re.MULTILINE,
        ),
        severity=InjectionSeverity.HIGH,
        action=SanitizationAction.REMOVE,
        description="XML-like prompt injection tags",
    ),
    # Delimiter manipulation
    InjectionPattern(
        name="delimiter_injection",
        pattern=re.compile(
            r"(?:```|---|\*{3,}|#{3,}|={3,})\s*"
            r"(?:system|instructions?|end\s+(?:of\s+)?(?:input|context|prompt)|"
            r"begin\s+(?:new\s+)?(?:output|response|instructions?))",
            re.IGNORECASE | re.MULTILINE,
        ),
        severity=InjectionSeverity.HIGH,
        action=SanitizationAction.ESCAPE,
        description="Delimiter-based injection attempt",
    ),
    # Jailbreak attempts
    InjectionPattern(
        name="jailbreak_keywords",
        pattern=re.compile(
            r"\b(?:jailbreak|dan\s+mode|developer\s+mode|unrestricted\s+mode|"
            r"no\s+restrictions?|bypass\s+(?:safety|filter|content)|"
            r"disable\s+(?:safety|filter|guidelines?)|remove\s+(?:limitations?|restrictions?))\b",
            re.IGNORECASE | re.MULTILINE,
        ),
        severity=InjectionSeverity.CRITICAL,
        action=SanitizationAction.BLOCK,
        description="Known jailbreak technique",
    ),
    # Tool/function call manipulation
    InjectionPattern(
        name="tool_manipulation",
        pattern=re.compile(
            r"(?:call|execute|run|invoke|use)\s+(?:the\s+)?(?:following\s+)?"
            r"(?:tool|function|command|action)\s*:\s*\{",
            re.IGNORECASE | re.MULTILINE,
        ),
        severity=InjectionSeverity.HIGH,
        action=SanitizationAction.ESCAPE,
        description="Attempt to manipulate tool calls",
    ),
    # Response format manipulation
    InjectionPattern(
        name="format_manipulation",
        pattern=re.compile(
            r"(?:output|respond|reply|answer)\s+"
            r"(?:only\s+)?(?:in|with|using)\s+"
            r"(?:the\s+following|this)\s+(?:format|json|structure)\s*:\s*\{",
            re.IGNORECASE | re.MULTILINE,
        ),
        severity=InjectionSeverity.MEDIUM,
        action=SanitizationAction.ESCAPE,
        description="Attempt to override output format",
    ),
    # Encoding tricks
    InjectionPattern(
        name="encoding_tricks",
        pattern=re.compile(
            r"(?:base64|hex|rot13|url\s*encod|unicode|utf-?8)\s*:\s*[a-zA-Z0-9+/=]{20,}",
            re.IGNORECASE | re.MULTILINE,
        ),
        severity=InjectionSeverity.MEDIUM,
        action=SanitizationAction.ESCAPE,
        description="Potential encoded payload",
    ),
]


class PromptSanitizer:
    """Sanitizes user-controlled input before embedding in LLM prompts.

    This class provides configurable protection against prompt injection attacks
    by detecting and neutralizing malicious patterns in user input.

    Example usage:
        sanitizer = PromptSanitizer()
        result = sanitizer.sanitize(user_input)
        if result.blocked:
            raise ValueError("Input blocked due to prompt injection attempt")
        safe_input = result.sanitized
    """

    # Characters that could be used for injection if not properly escaped
    SPECIAL_CHARS = {
        "```": "[CODE_BLOCK]",
        "---": "[SEPARATOR]",
        "###": "[HEADING]",
        "***": "[EMPHASIS]",
        "<|": "[DELIMITER_START]",
        "|>": "[DELIMITER_END]",
        "{{": "[TEMPLATE_START]",
        "}}": "[TEMPLATE_END]",
    }

    def __init__(
        self,
        patterns: list[InjectionPattern] | None = None,
        escape_special_chars: bool = True,
        max_input_length: int = 50000,
        strict_mode: bool = False,
        log_detections: bool = True,
    ):
        """Initialize the prompt sanitizer.

        Args:
            patterns: Custom injection patterns (uses defaults if None)
            escape_special_chars: Whether to escape special characters
            max_input_length: Maximum allowed input length
            strict_mode: If True, block on any detection (not just CRITICAL/HIGH)
            log_detections: Whether to log detected patterns
        """
        self.patterns = list(patterns) if patterns is not None else list(DEFAULT_INJECTION_PATTERNS)
        self.escape_special_chars = escape_special_chars
        self.max_input_length = max_input_length
        self.strict_mode = strict_mode
        self.log_detections = log_detections

    def sanitize(self, text: str) -> SanitizationResult:
        """Sanitize input text for safe embedding in prompts.

        Args:
            text: User-controlled input text

        Returns:
            SanitizationResult with sanitized text and detection information

        Raises:
            PromptInjectionError: If a blocking pattern is detected
        """
        if not text:
            return SanitizationResult(sanitized="", was_modified=False, blocked=False)

        original_length = len(text)

        # Check length
        if len(text) > self.max_input_length:
            text = text[: self.max_input_length]
            logger.warning(
                "sanitizer_input_truncated",
                original_length=original_length,
                max_length=self.max_input_length,
            )

        sanitized = text
        was_modified = len(text) != original_length
        detections: list[dict[str, Any]] = []

        # Check each pattern - we need to process iteratively because
        # removals/escapes change string positions
        for pattern in self.patterns:
            # Re-find matches after each modification
            match = pattern.pattern.search(sanitized)
            while match:
                detection = {
                    "pattern_name": pattern.name,
                    "severity": pattern.severity.value,
                    "action": pattern.action.value,
                    "matched_text": match.group()[:50],  # Truncate for logging
                    "position": match.start(),
                    "description": pattern.description,
                }
                detections.append(detection)

                if self.log_detections:
                    logger.warning(
                        "prompt_injection_detected",
                        pattern=pattern.name,
                        severity=pattern.severity.value,
                        action=pattern.action.value,
                        matched_preview=match.group()[:30],
                    )

                # Determine action
                should_block = pattern.action == SanitizationAction.BLOCK or (
                    self.strict_mode
                    and pattern.severity in (InjectionSeverity.CRITICAL, InjectionSeverity.HIGH)
                )

                if should_block:
                    raise PromptInjectionError(
                        f"Prompt injection detected: {pattern.description}",
                        pattern_name=pattern.name,
                        severity=pattern.severity,
                        matched_content=match.group(),
                    )

                if pattern.action == SanitizationAction.REMOVE:
                    sanitized = sanitized[: match.start()] + sanitized[match.end() :]
                    was_modified = True
                elif pattern.action == SanitizationAction.ESCAPE:
                    # Escape by wrapping in neutral markers
                    escaped = f"[USER_INPUT: {match.group()}]"
                    sanitized = sanitized[: match.start()] + escaped + sanitized[match.end() :]
                    was_modified = True
                    # Move past the escaped content to avoid infinite loop
                    break
                else:
                    # LOG_ONLY: move past this match
                    break

                # Look for next match
                match = pattern.pattern.search(sanitized)

        # Re-check blocking patterns after all modifications
        # This handles cases where removal creates new patterns
        if was_modified:
            for pattern in self.patterns:
                if pattern.action == SanitizationAction.BLOCK:
                    new_match = pattern.pattern.search(sanitized)
                    if new_match:
                        raise PromptInjectionError(
                            f"Prompt injection detected after sanitization: {pattern.description}",
                            pattern_name=pattern.name,
                            severity=pattern.severity,
                            matched_content=new_match.group(),
                        )

        # Escape special characters
        if self.escape_special_chars:
            for char, replacement in self.SPECIAL_CHARS.items():
                if char in sanitized:
                    sanitized = sanitized.replace(char, replacement)
                    was_modified = True

        return SanitizationResult(
            sanitized=sanitized,
            was_modified=was_modified,
            blocked=False,
            detections=detections,
        )

    def sanitize_dict(
        self,
        data: dict[str, Any],
        recursive: bool = True,
        keys_to_sanitize: set[str] | None = None,
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        """Sanitize all string values in a dictionary.

        Args:
            data: Dictionary with potentially unsafe values
            recursive: Whether to sanitize nested dicts
            keys_to_sanitize: If provided, only sanitize these keys (None = all)

        Returns:
            Tuple of (sanitized_dict, all_detections)

        Raises:
            PromptInjectionError: If a blocking pattern is detected
        """
        all_detections: list[dict[str, Any]] = []

        def sanitize_value(value: Any, key: str = "") -> Any:
            if isinstance(value, str):
                if keys_to_sanitize is None or key in keys_to_sanitize:
                    result = self.sanitize(value)
                    all_detections.extend(result.detections)
                    return result.sanitized
                return value
            elif isinstance(value, dict) and recursive:
                return {k: sanitize_value(v, k) for k, v in value.items()}
            elif isinstance(value, list) and recursive:
                return [sanitize_value(item, key) for item in value]
            else:
                return value

        sanitized_data = {k: sanitize_value(v, k) for k, v in data.items()}

        return sanitized_data, all_detections

    def is_safe(self, text: str) -> bool:
        """Quick check if text appears safe (no blocking patterns).

        Args:
            text: Text to check

        Returns:
            True if no blocking patterns detected
        """
        try:
            self.sanitize(text)
            return True
        except PromptInjectionError:
            return False

    def add_pattern(self, pattern: InjectionPattern) -> None:
        """Add a custom pattern to the sanitizer.

        Args:
            pattern: Pattern to add
        """
        self.patterns.append(pattern)

    def remove_pattern(self, pattern_name: str) -> bool:
        """Remove a pattern by name.

        Args:
            pattern_name: Name of pattern to remove

        Returns:
            True if pattern was found and removed
        """
        for i, pattern in enumerate(self.patterns):
            if pattern.name == pattern_name:
                del self.patterns[i]
                return True
        return False


def create_safe_data_block(
    data: dict[str, Any],
    sanitizer: PromptSanitizer | None = None,
    label: str = "Alert Data",
) -> str:
    """Create a safely formatted data block for embedding in prompts.

    This function creates a structured data block that:
    1. Sanitizes all user-controlled values
    2. Uses clear delimiters that the LLM is trained to recognize as data
    3. Prevents injection through JSON structure manipulation

    Args:
        data: User-controlled data to embed
        sanitizer: Optional custom sanitizer (uses default if None)
        label: Label for the data block

    Returns:
        Safely formatted string for prompt embedding

    Raises:
        PromptInjectionError: If dangerous content is detected
    """
    if sanitizer is None:
        sanitizer = PromptSanitizer()

    # Sanitize all string values in the data
    sanitized_data, detections = sanitizer.sanitize_dict(data)

    # Log if there were any detections
    if detections:
        logger.info(
            "data_block_sanitized",
            detection_count=len(detections),
            label=label,
        )

    # Format as a clearly delimited data block
    # Using markers that indicate this is user data, not instructions
    json_str = json.dumps(sanitized_data, indent=2, default=str)

    # Wrap in clear data boundaries
    block = f"""[BEGIN {label.upper()} - USER PROVIDED DATA]
{json_str}
[END {label.upper()} - USER PROVIDED DATA]"""

    return block


def sanitize_alert_data(alert_data: dict[str, Any]) -> dict[str, Any]:
    """Convenience function to sanitize alert data.

    Args:
        alert_data: Raw alert data from user/external source

    Returns:
        Sanitized alert data safe for prompt embedding

    Raises:
        PromptInjectionError: If dangerous content is detected
    """
    sanitizer = PromptSanitizer()
    sanitized, _ = sanitizer.sanitize_dict(alert_data)
    return sanitized


def sanitize_string(text: str) -> str:
    """Convenience function to sanitize a single string.

    Args:
        text: Text to sanitize

    Returns:
        Sanitized text

    Raises:
        PromptInjectionError: If dangerous content is detected
    """
    sanitizer = PromptSanitizer()
    return sanitizer.sanitize(text).sanitized
