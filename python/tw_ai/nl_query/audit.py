"""Query audit logging and sanitization for NL queries.

Provides logging of all NL queries for audit and compliance,
and input sanitization to prevent injection attacks.
"""

from __future__ import annotations

import re
from collections import deque
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from tw_ai.nl_query.intent import QueryIntent


class QueryAuditEntry(BaseModel):
    """Audit log entry for a single NL query."""

    model_config = ConfigDict(str_strip_whitespace=True)

    query_text: str = Field(description="The original query text")
    intent: QueryIntent = Field(description="Classified intent")
    translated_query: str = Field(default="", description="The translated query representation")
    user_id: str = Field(default="anonymous", description="User who made the query")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    execution_time_ms: int = Field(default=0, description="Query execution time in ms")
    result_count: int = Field(default=0, description="Number of results returned")
    sanitized: bool = Field(default=False, description="Whether the query was sanitized")
    metadata: dict[str, Any] = Field(default_factory=dict)


class QueryAuditLog:
    """Audit logger for NL queries.

    Maintains an in-memory log of recent queries and provides methods
    for exporting and analyzing query patterns.
    """

    def __init__(self, max_entries: int = 1000) -> None:
        """Initialize the audit log.

        Args:
            max_entries: Maximum number of entries to keep in memory.
        """
        self._entries: deque[QueryAuditEntry] = deque(maxlen=max_entries)
        self._max_entries = max_entries

    @property
    def entry_count(self) -> int:
        """Number of entries in the log."""
        return len(self._entries)

    def log(self, entry: QueryAuditEntry) -> None:
        """Add an audit entry.

        Args:
            entry: The audit entry to log.
        """
        self._entries.append(entry)

    def log_query(
        self,
        query_text: str,
        intent: QueryIntent,
        user_id: str = "anonymous",
        translated_query: str = "",
        execution_time_ms: int = 0,
        result_count: int = 0,
        sanitized: bool = False,
    ) -> QueryAuditEntry:
        """Log a query and return the entry.

        Args:
            query_text: The original query.
            intent: Classified intent.
            user_id: User who made the query.
            translated_query: Translated query string.
            execution_time_ms: Execution time.
            result_count: Number of results.
            sanitized: Whether sanitization was applied.

        Returns:
            The created audit entry.
        """
        entry = QueryAuditEntry(
            query_text=query_text,
            intent=intent,
            user_id=user_id,
            translated_query=translated_query,
            execution_time_ms=execution_time_ms,
            result_count=result_count,
            sanitized=sanitized,
        )
        self._entries.append(entry)
        return entry

    def get_entries(
        self,
        user_id: str | None = None,
        intent: QueryIntent | None = None,
        limit: int = 50,
    ) -> list[QueryAuditEntry]:
        """Get audit entries with optional filtering.

        Args:
            user_id: Filter by user ID.
            intent: Filter by intent.
            limit: Maximum number of entries to return.

        Returns:
            List of matching audit entries, most recent first.
        """
        entries = list(reversed(self._entries))

        if user_id is not None:
            entries = [e for e in entries if e.user_id == user_id]
        if intent is not None:
            entries = [e for e in entries if e.intent == intent]

        return entries[:limit]

    def get_stats(self) -> dict[str, Any]:
        """Get aggregate statistics about logged queries.

        Returns:
            Dictionary with query statistics.
        """
        if not self._entries:
            return {
                "total_queries": 0,
                "unique_users": 0,
                "intent_distribution": {},
                "avg_execution_time_ms": 0,
            }

        entries = list(self._entries)
        intent_counts: dict[str, int] = {}
        users: set[str] = set()
        total_time = 0

        for entry in entries:
            intent_counts[entry.intent.value] = intent_counts.get(entry.intent.value, 0) + 1
            users.add(entry.user_id)
            total_time += entry.execution_time_ms

        return {
            "total_queries": len(entries),
            "unique_users": len(users),
            "intent_distribution": intent_counts,
            "avg_execution_time_ms": round(total_time / len(entries), 1),
            "sanitized_count": sum(1 for e in entries if e.sanitized),
        }

    def clear(self) -> None:
        """Clear all audit entries."""
        self._entries.clear()


# Patterns that indicate potential injection attempts
_DISALLOWED_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # Comment patterns first (before statement patterns that may overlap)
    ("sql_comment", re.compile(r"--\s|/\*|\*/", re.IGNORECASE)),
    # Statement-level injection patterns
    ("sql_union", re.compile(r"\bUNION\s+(?:ALL\s+)?SELECT\b", re.IGNORECASE)),
    ("sql_drop", re.compile(r"\bDROP\s+(?:TABLE|DATABASE)\b", re.IGNORECASE)),
    ("sql_delete", re.compile(r"\bDELETE\s+FROM\b", re.IGNORECASE)),
    ("sql_insert", re.compile(r"\bINSERT\s+INTO\b", re.IGNORECASE)),
    ("sql_update_set", re.compile(r"\bUPDATE\s+\w+\s+SET\b", re.IGNORECASE)),
    # Other injection patterns
    ("script_tag", re.compile(r"<\s*script", re.IGNORECASE)),
    ("command_injection", re.compile(r"[;&|`]\s*(?:rm|cat|curl|wget|bash|sh|python)\b")),
    ("escape_sequence", re.compile(r"\\x[0-9a-fA-F]{2}")),
    ("null_byte", re.compile(r"\\0|%00")),
]


class QuerySanitizer:
    """Sanitizes NL queries to prevent injection attacks.

    Strips potential injection patterns, validates query length,
    and checks for disallowed patterns.
    """

    def __init__(
        self,
        max_query_length: int = 2000,
        min_query_length: int = 1,
        additional_patterns: list[tuple[str, re.Pattern[str]]] | None = None,
    ) -> None:
        """Initialize the sanitizer.

        Args:
            max_query_length: Maximum allowed query length.
            min_query_length: Minimum allowed query length.
            additional_patterns: Extra disallowed patterns.
        """
        self._max_length = max_query_length
        self._min_length = min_query_length
        self._patterns = list(_DISALLOWED_PATTERNS)
        if additional_patterns:
            self._patterns.extend(additional_patterns)

    def sanitize(self, query: str) -> tuple[str, list[str]]:
        """Sanitize a query, returning the clean query and any warnings.

        Args:
            query: The raw query string.

        Returns:
            Tuple of (sanitized query, list of warning messages).
        """
        warnings: list[str] = []

        if not query:
            return "", ["Empty query"]

        # Strip whitespace
        clean = query.strip()

        # Check length
        if len(clean) > self._max_length:
            clean = clean[: self._max_length]
            warnings.append(f"Query truncated to {self._max_length} characters")

        if len(clean) < self._min_length:
            return "", [f"Query too short (minimum {self._min_length} characters)"]

        # Check for disallowed patterns
        for pattern_name, pattern in self._patterns:
            if pattern.search(clean):
                warnings.append(f"Disallowed pattern detected: {pattern_name}")
                # Remove the matched pattern
                clean = pattern.sub("", clean).strip()

        # Remove control characters (except newlines and tabs)
        clean = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", clean)

        return clean, warnings

    def is_safe(self, query: str) -> bool:
        """Check if a query is safe without modifying it.

        Args:
            query: The query to check.

        Returns:
            True if the query passes all safety checks.
        """
        if not query or len(query.strip()) < self._min_length:
            return False
        if len(query) > self._max_length:
            return False

        for _, pattern in self._patterns:
            if pattern.search(query):
                return False

        return True


__all__ = [
    "QueryAuditEntry",
    "QueryAuditLog",
    "QuerySanitizer",
]
