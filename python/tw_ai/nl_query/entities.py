"""Entity extraction for cybersecurity-specific entities from natural language.

Extracts IPs, domains, hashes, usernames, date ranges, severity levels,
and MITRE technique IDs using regex patterns.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class EntityType(str, Enum):
    """Types of entities that can be extracted from security queries."""

    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    USERNAME = "username"
    EMAIL = "email"
    DATE_RANGE = "date_range"
    SEVERITY = "severity"
    MITRE_TECHNIQUE = "mitre_technique"
    INCIDENT_ID = "incident_id"
    PORT = "port"
    CVE = "cve"


class ExtractedEntity(BaseModel):
    """An entity extracted from a natural language query."""

    model_config = ConfigDict(str_strip_whitespace=True)

    entity_type: EntityType = Field(description="Type of extracted entity")
    value: str = Field(description="The extracted value")
    original_text: str = Field(description="Original text span that was matched")
    start: int = Field(ge=0, description="Start position in the query")
    end: int = Field(ge=0, description="End position in the query")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional entity metadata")


class DateRange(BaseModel):
    """A date range extracted from a query."""

    model_config = ConfigDict(str_strip_whitespace=True)

    start: datetime = Field(description="Start of the date range")
    end: datetime = Field(description="End of the date range")
    original_text: str = Field(default="", description="Original text that specified this range")

    @property
    def duration_seconds(self) -> float:
        """Duration of the range in seconds."""
        return (self.end - self.start).total_seconds()


# Regex patterns for entity extraction
_ENTITY_PATTERNS: dict[EntityType, re.Pattern[str]] = {
    EntityType.IP_ADDRESS: re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    ),
    EntityType.HASH_SHA256: re.compile(r"\b[a-fA-F0-9]{64}\b"),
    EntityType.HASH_SHA1: re.compile(r"\b[a-fA-F0-9]{40}\b"),
    EntityType.HASH_MD5: re.compile(r"\b[a-fA-F0-9]{32}\b"),
    EntityType.EMAIL: re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"),
    EntityType.MITRE_TECHNIQUE: re.compile(r"\bT\d{4}(?:\.\d{1,3})?\b"),
    EntityType.CVE: re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE),
    EntityType.INCIDENT_ID: re.compile(r"(?:\bINC-?\d+\b|(?<!\w)#\d+\b)"),
    EntityType.PORT: re.compile(r"\bport\s+(\d{1,5})\b", re.IGNORECASE),
}

# Domain pattern (applied after other patterns to avoid false positives)
_DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
    r"+(?:com|org|net|io|gov|edu|mil|co|uk|de|ru|cn|info|biz|xyz|top|"
    r"online|site|tech|club|app|dev|cloud)\b"
)

# Username pattern (e.g., user:jdoe, username jdoe, "jdoe")
_USERNAME_PATTERN = re.compile(r"(?:user(?:name)?[:\s]+)([a-zA-Z0-9._\-]+)", re.IGNORECASE)

# Severity keywords
_SEVERITY_KEYWORDS: dict[str, str] = {
    "critical": "critical",
    "crit": "critical",
    "high": "high",
    "medium": "medium",
    "med": "medium",
    "low": "low",
    "informational": "informational",
    "info": "informational",
}

_SEVERITY_PATTERN = re.compile(
    r"\b(?:severity|sev)\s*[:\s]?\s*(" + "|".join(_SEVERITY_KEYWORDS.keys()) + r")\b",
    re.IGNORECASE,
)

# Relative time patterns (e.g., "last 24 hours", "past 7 days")
_RELATIVE_TIME_PATTERN = re.compile(
    r"(?:last|past)\s+(\d+)\s+(minute|hour|day|week|month)s?",
    re.IGNORECASE,
)

# Absolute date patterns
_ABSOLUTE_DATE_PATTERN = re.compile(
    r"(\d{4}-\d{2}-\d{2})\s+(?:to|through|until)\s+(\d{4}-\d{2}-\d{2})"
)


class EntityExtractor:
    """Extracts structured entities from natural language security queries.

    Uses regex patterns for cybersecurity-specific entity recognition.
    """

    def __init__(self) -> None:
        """Initialize the entity extractor."""
        self._patterns = dict(_ENTITY_PATTERNS)

    def extract(self, query: str) -> list[ExtractedEntity]:
        """Extract all entities from a query.

        Args:
            query: The natural language query.

        Returns:
            List of extracted entities.
        """
        if not query or not query.strip():
            return []

        entities: list[ExtractedEntity] = []
        used_spans: set[tuple[int, int]] = set()

        # Extract entities in order of specificity (longer patterns first)
        # SHA-256 before SHA-1 before MD5 (by length)
        for entity_type in [
            EntityType.HASH_SHA256,
            EntityType.HASH_SHA1,
            EntityType.HASH_MD5,
            EntityType.IP_ADDRESS,
            EntityType.EMAIL,
            EntityType.MITRE_TECHNIQUE,
            EntityType.CVE,
            EntityType.INCIDENT_ID,
            EntityType.PORT,
        ]:
            pattern = self._patterns[entity_type]
            for match in pattern.finditer(query):
                span = (match.start(), match.end())
                if self._overlaps(span, used_spans):
                    continue

                value = match.group(1) if match.lastindex else match.group(0)

                # Validate specific types
                if entity_type == EntityType.IP_ADDRESS:
                    if not self._is_valid_ip(value):
                        continue
                elif entity_type == EntityType.PORT:
                    port_num = int(value)
                    if port_num > 65535:
                        continue

                entities.append(
                    ExtractedEntity(
                        entity_type=entity_type,
                        value=value,
                        original_text=match.group(0),
                        start=match.start(),
                        end=match.end(),
                    )
                )
                used_spans.add(span)

        # Extract domains (after emails to avoid overlap)
        email_spans = {(e.start, e.end) for e in entities if e.entity_type == EntityType.EMAIL}
        for match in _DOMAIN_PATTERN.finditer(query):
            span = (match.start(), match.end())
            if self._overlaps(span, used_spans) or self._overlaps(span, email_spans):
                continue
            entities.append(
                ExtractedEntity(
                    entity_type=EntityType.DOMAIN,
                    value=match.group(0),
                    original_text=match.group(0),
                    start=match.start(),
                    end=match.end(),
                )
            )
            used_spans.add(span)

        # Extract usernames
        for match in _USERNAME_PATTERN.finditer(query):
            span = (match.start(), match.end())
            if self._overlaps(span, used_spans):
                continue
            entities.append(
                ExtractedEntity(
                    entity_type=EntityType.USERNAME,
                    value=match.group(1),
                    original_text=match.group(0),
                    start=match.start(),
                    end=match.end(),
                )
            )
            used_spans.add(span)

        # Extract severity
        for match in _SEVERITY_PATTERN.finditer(query):
            span = (match.start(), match.end())
            if self._overlaps(span, used_spans):
                continue
            raw = match.group(1).lower()
            normalized = _SEVERITY_KEYWORDS.get(raw, raw)
            entities.append(
                ExtractedEntity(
                    entity_type=EntityType.SEVERITY,
                    value=normalized,
                    original_text=match.group(0),
                    start=match.start(),
                    end=match.end(),
                    metadata={"raw_value": raw},
                )
            )
            used_spans.add(span)

        return entities

    def extract_date_range(self, query: str) -> DateRange | None:
        """Extract a date range from a query.

        Supports relative ranges ("last 24 hours") and absolute ranges
        ("2024-01-01 to 2024-01-31").

        Args:
            query: The natural language query.

        Returns:
            DateRange if found, None otherwise.
        """
        if not query:
            return None

        # Try relative time first
        match = _RELATIVE_TIME_PATTERN.search(query)
        if match:
            amount = int(match.group(1))
            unit = match.group(2).lower()
            now = datetime.now(timezone.utc)

            delta_map = {
                "minute": timedelta(minutes=amount),
                "hour": timedelta(hours=amount),
                "day": timedelta(days=amount),
                "week": timedelta(weeks=amount),
                "month": timedelta(days=amount * 30),
            }
            delta = delta_map.get(unit)
            if delta:
                return DateRange(
                    start=now - delta,
                    end=now,
                    original_text=match.group(0),
                )

        # Try absolute date range
        match = _ABSOLUTE_DATE_PATTERN.search(query)
        if match:
            try:
                start = datetime.strptime(match.group(1), "%Y-%m-%d").replace(tzinfo=timezone.utc)
                end = datetime.strptime(match.group(2), "%Y-%m-%d").replace(
                    hour=23, minute=59, second=59, tzinfo=timezone.utc
                )
                return DateRange(
                    start=start,
                    end=end,
                    original_text=match.group(0),
                )
            except ValueError:
                pass

        return None

    @staticmethod
    def _is_valid_ip(ip: str) -> bool:
        """Validate an IP address."""
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        return all(0 <= int(p) <= 255 for p in parts)

    @staticmethod
    def _overlaps(
        span: tuple[int, int],
        existing: set[tuple[int, int]],
    ) -> bool:
        """Check if a span overlaps with any existing spans."""
        for ex_start, ex_end in existing:
            if span[0] < ex_end and span[1] > ex_start:
                return True
        return False


__all__ = [
    "EntityType",
    "ExtractedEntity",
    "DateRange",
    "EntityExtractor",
]
