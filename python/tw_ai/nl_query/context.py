"""Conversation context management for multi-turn NL query sessions.

Tracks the investigation session state to resolve references like
"that IP", "this user", and maintain query history.
"""

from __future__ import annotations

import re
from collections import deque
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from tw_ai.nl_query.entities import EntityType, ExtractedEntity


class ContextEntry(BaseModel):
    """An entry in the conversation context history."""

    model_config = ConfigDict(str_strip_whitespace=True)

    query: str = Field(description="The original query")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    entities: list[ExtractedEntity] = Field(
        default_factory=list, description="Entities from this query"
    )
    result_count: int = Field(default=0, description="Number of results returned")


# Reference patterns that point to previously mentioned entities
_REFERENCE_PATTERNS: dict[EntityType, list[re.Pattern[str]]] = {
    EntityType.IP_ADDRESS: [
        re.compile(r"\b(?:that|this|the|same)\s+(?:ip|ip address|address)\b", re.IGNORECASE),
        re.compile(r"\b(?:it|its)\b", re.IGNORECASE),
    ],
    EntityType.DOMAIN: [
        re.compile(r"\b(?:that|this|the|same)\s+(?:domain|site|website)\b", re.IGNORECASE),
    ],
    EntityType.USERNAME: [
        re.compile(r"\b(?:that|this|the|same)\s+(?:user|account|username)\b", re.IGNORECASE),
    ],
    EntityType.EMAIL: [
        re.compile(r"\b(?:that|this|the|same)\s+(?:email|sender|recipient)\b", re.IGNORECASE),
    ],
    EntityType.HASH_MD5: [
        re.compile(r"\b(?:that|this|the|same)\s+(?:hash|file hash|md5)\b", re.IGNORECASE),
    ],
    EntityType.HASH_SHA256: [
        re.compile(r"\b(?:that|this|the|same)\s+(?:hash|file hash|sha256)\b", re.IGNORECASE),
    ],
    EntityType.INCIDENT_ID: [
        re.compile(r"\b(?:that|this|the|same|current)\s+(?:incident|alert|case)\b", re.IGNORECASE),
    ],
}


class ConversationContext:
    """Tracks multi-turn conversation state for NL query sessions.

    Maintains a history of queries and their extracted entities to resolve
    references like "that IP" or "this user" in follow-up queries.
    """

    def __init__(
        self,
        max_history: int = 20,
        incident_id: str | None = None,
    ) -> None:
        """Initialize conversation context.

        Args:
            max_history: Maximum number of queries to keep in history.
            incident_id: ID of the currently viewed incident (if any).
        """
        self._history: deque[ContextEntry] = deque(maxlen=max_history)
        self._recent_entities: dict[EntityType, list[ExtractedEntity]] = {}
        self.incident_id: str | None = incident_id
        self.session_start: datetime = datetime.now(timezone.utc)

    @property
    def query_count(self) -> int:
        """Number of queries in this session."""
        return len(self._history)

    @property
    def recent_entities(self) -> dict[EntityType, list[ExtractedEntity]]:
        """Get recently mentioned entities by type."""
        return dict(self._recent_entities)

    @property
    def query_history(self) -> list[ContextEntry]:
        """Get the query history as a list."""
        return list(self._history)

    @property
    def last_query(self) -> ContextEntry | None:
        """Get the most recent query entry."""
        return self._history[-1] if self._history else None

    def update(
        self,
        query: str,
        entities: list[ExtractedEntity],
        result_count: int = 0,
    ) -> None:
        """Update context after a query.

        Args:
            query: The query that was executed.
            entities: Entities extracted from the query.
            result_count: Number of results returned.
        """
        entry = ContextEntry(
            query=query,
            entities=entities,
            result_count=result_count,
        )
        self._history.append(entry)

        # Update recent entities
        for entity in entities:
            if entity.entity_type not in self._recent_entities:
                self._recent_entities[entity.entity_type] = []
            # Prepend (most recent first), keep max 5 per type
            self._recent_entities[entity.entity_type].insert(0, entity)
            self._recent_entities[entity.entity_type] = self._recent_entities[entity.entity_type][
                :5
            ]

    def resolve_reference(self, query: str) -> tuple[str, list[ExtractedEntity]]:
        """Resolve entity references in a query using conversation context.

        Detects patterns like "that IP", "this user", etc., and replaces them
        with the most recently mentioned entity of that type.

        Args:
            query: The query with potential references.

        Returns:
            Tuple of (resolved query, list of resolved entities).
        """
        resolved_query = query
        resolved_entities: list[ExtractedEntity] = []

        for entity_type, patterns in _REFERENCE_PATTERNS.items():
            for pattern in patterns:
                match = pattern.search(resolved_query)
                if match:
                    # Find the most recent entity of this type
                    recent = self._recent_entities.get(entity_type)
                    if recent:
                        entity = recent[0]
                        # Replace the reference with the actual value
                        resolved_query = (
                            resolved_query[: match.start()]
                            + entity.value
                            + resolved_query[match.end() :]
                        )
                        resolved_entities.append(entity)
                        break  # Only resolve first match per type

        # Also resolve "current incident" to the incident_id
        if self.incident_id:
            current_pattern = re.compile(r"\b(?:current|this)\s+incident\b", re.IGNORECASE)
            match = current_pattern.search(resolved_query)
            if match:
                resolved_query = (
                    resolved_query[: match.start()]
                    + self.incident_id
                    + resolved_query[match.end() :]
                )

        return resolved_query, resolved_entities

    def get_entity_by_type(self, entity_type: EntityType) -> ExtractedEntity | None:
        """Get the most recent entity of a specific type.

        Args:
            entity_type: Type of entity to look up.

        Returns:
            Most recent entity of that type, or None.
        """
        recent = self._recent_entities.get(entity_type)
        return recent[0] if recent else None

    def clear(self) -> None:
        """Clear all conversation context."""
        self._history.clear()
        self._recent_entities.clear()
        self.incident_id = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize context state."""
        return {
            "incident_id": self.incident_id,
            "query_count": self.query_count,
            "session_start": self.session_start.isoformat(),
            "recent_entity_types": list(self._recent_entities.keys()),
            "history_length": len(self._history),
        }


__all__ = [
    "ConversationContext",
    "ContextEntry",
]
