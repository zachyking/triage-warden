"""Base class for query backends."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from tw_ai.nl_query.translator import TranslatedQuery


class QueryResult(BaseModel):
    """Result from a backend query generation."""

    model_config = ConfigDict(str_strip_whitespace=True)

    query_string: str = Field(description="Generated query string")
    query_type: str = Field(description="Type of query (e.g., SPL, KQL, SQL)")
    parameters: dict[str, Any] = Field(
        default_factory=dict,
        description="Query parameters (for parameterized queries)",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional metadata about the generated query",
    )


class QueryBackend(ABC):
    """Abstract base for query backend adapters.

    Subclasses generate backend-specific query syntax from TranslatedQuery objects.
    """

    @property
    @abstractmethod
    def backend_name(self) -> str:
        """Name of this backend (e.g., 'splunk', 'elasticsearch', 'sql')."""

    @abstractmethod
    def generate(self, translated: TranslatedQuery) -> QueryResult:
        """Generate a backend-specific query from a translated query.

        Args:
            translated: The translated structured query.

        Returns:
            QueryResult with the generated query string.
        """

    def _format_datetime(self, dt: object) -> str:
        """Format a datetime for query use. Override per backend."""
        if hasattr(dt, "strftime"):
            return str(dt.strftime("%Y-%m-%dT%H:%M:%S"))
        return str(dt)


__all__ = [
    "QueryBackend",
    "QueryResult",
]
