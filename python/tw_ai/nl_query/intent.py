"""Intent classification for natural language security queries.

Classifies user queries into specific intents using keyword matching
and pattern rules (no LLM needed for classification).
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class QueryIntent(str, Enum):
    """Classification of a natural language query's intent."""

    SEARCH_INCIDENTS = "search_incidents"
    SEARCH_LOGS = "search_logs"
    LOOKUP_IOC = "lookup_ioc"
    EXPLAIN_INCIDENT = "explain_incident"
    COMPARE_INCIDENTS = "compare_incidents"
    TIMELINE_QUERY = "timeline_query"
    ASSET_LOOKUP = "asset_lookup"
    STATISTICS = "statistics"
    GENERAL_QUESTION = "general_question"


class IntentMatch(BaseModel):
    """Result of intent classification."""

    model_config = ConfigDict(str_strip_whitespace=True)

    intent: QueryIntent = Field(description="Classified intent")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence in the classification")
    matched_keywords: list[str] = Field(default_factory=list, description="Keywords that matched")
    matched_patterns: list[str] = Field(
        default_factory=list, description="Pattern names that matched"
    )


# Keyword groups for each intent
_INTENT_KEYWORDS: dict[QueryIntent, list[str]] = {
    QueryIntent.SEARCH_INCIDENTS: [
        "incident",
        "incidents",
        "alert",
        "alerts",
        "find incident",
        "search incident",
        "show incident",
        "list incident",
        "get incident",
        "open incident",
        "recent incident",
        "active incident",
    ],
    QueryIntent.SEARCH_LOGS: [
        "log",
        "logs",
        "event",
        "events",
        "search log",
        "find log",
        "show log",
        "siem",
        "audit log",
        "firewall log",
        "access log",
        "authentication log",
        "login log",
    ],
    QueryIntent.LOOKUP_IOC: [
        "ioc",
        "indicator",
        "lookup",
        "reputation",
        "threat intel",
        "virustotal",
        "malicious",
        "check ip",
        "check domain",
        "check hash",
        "is this ip",
        "is this domain",
    ],
    QueryIntent.EXPLAIN_INCIDENT: [
        "explain",
        "what happened",
        "describe",
        "tell me about",
        "what is this",
        "summarize",
        "summary",
        "detail",
        "walk me through",
        "break down",
    ],
    QueryIntent.COMPARE_INCIDENTS: [
        "compare",
        "difference",
        "similar to",
        "related to",
        "correlation",
        "correlate",
        "same as",
        "versus",
        "different from",
    ],
    QueryIntent.TIMELINE_QUERY: [
        "timeline",
        "chronological",
        "sequence",
        "when did",
        "time range",
        "between",
        "before",
        "after",
        "last hour",
        "last day",
        "last week",
        "past",
        "history",
        "over time",
    ],
    QueryIntent.ASSET_LOOKUP: [
        "asset",
        "host",
        "hostname",
        "server",
        "workstation",
        "endpoint",
        "machine",
        "device",
        "user account",
        "who owns",
        "which system",
        "what system",
    ],
    QueryIntent.STATISTICS: [
        "statistics",
        "stats",
        "count",
        "how many",
        "total",
        "average",
        "trend",
        "top",
        "most common",
        "distribution",
        "percentage",
        "rate",
        "frequency",
        "volume",
    ],
}

# Regex patterns for more precise intent detection
_INTENT_PATTERNS: dict[QueryIntent, list[tuple[str, re.Pattern[str]]]] = {
    QueryIntent.LOOKUP_IOC: [
        ("ip_address", re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")),
        ("md5_hash", re.compile(r"\b[a-fA-F0-9]{32}\b")),
        ("sha256_hash", re.compile(r"\b[a-fA-F0-9]{64}\b")),
        ("sha1_hash", re.compile(r"\b[a-fA-F0-9]{40}\b")),
        (
            "domain_lookup",
            re.compile(
                r"(?:lookup|check|search|reputation)\s+(?:for\s+)?[a-zA-Z0-9]"
                r"[a-zA-Z0-9\-]*\.[a-zA-Z]{2,}"
            ),
        ),
    ],
    QueryIntent.EXPLAIN_INCIDENT: [
        (
            "incident_id_explain",
            re.compile(
                r"(?:explain|describe|what happened|tell me about|summarize)\s+"
                r"(?:incident\s+)?(?:INC-?\d+|#\d+)"
            ),
        ),
    ],
    QueryIntent.COMPARE_INCIDENTS: [
        (
            "compare_ids",
            re.compile(
                r"compare\s+(?:incident\s+)?(?:INC-?\d+|#\d+)\s+"
                r"(?:and|with|to|vs)\s+(?:incident\s+)?(?:INC-?\d+|#\d+)"
            ),
        ),
    ],
    QueryIntent.TIMELINE_QUERY: [
        ("time_range", re.compile(r"(?:last|past)\s+\d+\s+(?:hour|day|week|month|minute)s?")),
        ("date_range", re.compile(r"\d{4}-\d{2}-\d{2}\s+(?:to|through|until)\s+\d{4}-\d{2}-\d{2}")),
    ],
    QueryIntent.STATISTICS: [
        ("count_query", re.compile(r"how\s+many\s+(?:incident|alert|event|log)s?")),
        ("top_n", re.compile(r"top\s+\d+")),
    ],
    QueryIntent.ASSET_LOOKUP: [
        (
            "asset_query",
            re.compile(r"(?:who\s+owns|what\s+is|info\s+(?:on|about))\s+(?:host|server|system)\s+"),
        ),
    ],
}


class IntentClassifier:
    """Classifies natural language queries into security investigation intents.

    Uses keyword matching and regex patterns for fast, deterministic classification
    without requiring an LLM call.
    """

    def __init__(
        self,
        custom_keywords: dict[QueryIntent, list[str]] | None = None,
    ) -> None:
        """Initialize the classifier.

        Args:
            custom_keywords: Optional additional keywords per intent.
        """
        self._keywords = dict(_INTENT_KEYWORDS)
        if custom_keywords:
            for intent, keywords in custom_keywords.items():
                existing = self._keywords.get(intent, [])
                self._keywords[intent] = existing + keywords

        self._patterns = dict(_INTENT_PATTERNS)

    def classify(self, query: str) -> IntentMatch:
        """Classify a natural language query.

        Args:
            query: The user's natural language query.

        Returns:
            IntentMatch with the classified intent and confidence.
        """
        if not query or not query.strip():
            return IntentMatch(
                intent=QueryIntent.GENERAL_QUESTION,
                confidence=0.0,
            )

        query_lower = query.lower().strip()
        scores: dict[QueryIntent, dict[str, Any]] = {}

        # Score each intent by keyword matches
        for intent, keywords in self._keywords.items():
            matched = []
            for kw in keywords:
                if kw.lower() in query_lower:
                    matched.append(kw)
            if matched:
                scores[intent] = {
                    "keyword_score": len(matched) / max(len(keywords), 1),
                    "matched_keywords": matched,
                    "matched_patterns": [],
                }

        # Boost scores with pattern matches
        for intent, patterns in self._patterns.items():
            for pattern_name, pattern in patterns:
                if pattern.search(query_lower) or pattern.search(query):
                    if intent not in scores:
                        scores[intent] = {
                            "keyword_score": 0.0,
                            "matched_keywords": [],
                            "matched_patterns": [],
                        }
                    scores[intent]["matched_patterns"].append(pattern_name)

        if not scores:
            return IntentMatch(
                intent=QueryIntent.GENERAL_QUESTION,
                confidence=0.5,
            )

        # Calculate final confidence for each intent
        best_intent = QueryIntent.GENERAL_QUESTION
        best_confidence = 0.0
        best_keywords: list[str] = []
        best_patterns: list[str] = []

        for intent, data in scores.items():
            keyword_score = data["keyword_score"]
            pattern_bonus = len(data["matched_patterns"]) * 0.3
            has_keywords = len(data["matched_keywords"]) > 0
            confidence = min(keyword_score + pattern_bonus, 1.0)

            # Pattern matches alone give at least 0.6 confidence
            if data["matched_patterns"] and confidence < 0.6:
                confidence = 0.6

            # Keyword-based intents get a tiebreaker boost over pattern-only intents
            # This ensures "search logs from 10.0.0.1" classifies as SEARCH_LOGS
            # rather than LOOKUP_IOC (which would match only on the IP pattern)
            if has_keywords and confidence <= best_confidence and not data["matched_patterns"]:
                pass  # Don't boost if it's only keywords with no advantage
            elif has_keywords and not best_keywords and confidence >= best_confidence - 0.1:
                # Prefer keyword matches over pattern-only matches at similar confidence
                confidence = max(confidence, best_confidence + 0.01)

            if confidence > best_confidence:
                best_confidence = confidence
                best_intent = intent
                best_keywords = data["matched_keywords"]
                best_patterns = data["matched_patterns"]

        return IntentMatch(
            intent=best_intent,
            confidence=round(min(best_confidence, 1.0), 2),
            matched_keywords=best_keywords,
            matched_patterns=best_patterns,
        )


__all__ = [
    "QueryIntent",
    "IntentMatch",
    "IntentClassifier",
]
