"""Natural language query engine for security investigation (Stage 4.1).

This module provides a natural language interface for querying security data:
- Intent classification for routing NL queries
- Entity extraction for cybersecurity-specific entities (IPs, domains, hashes, etc.)
- Query translation to structured search formats
- Backend adapters for Splunk, Elasticsearch, and SQL
- Conversation context tracking for multi-turn investigation
- Query audit logging and sanitization
- FastAPI endpoint for NL query service (requires fastapi)

Public API:
    - NLQueryTranslator: Main translator from NL to structured queries
    - IntentClassifier: Classify query intent
    - EntityExtractor: Extract security entities from text
    - ConversationContext: Track multi-turn conversation state
    - QueryAuditLog: Audit logging for queries
    - QuerySanitizer: Input sanitization
    - router: FastAPI router for NL query API (only when fastapi is installed)
"""

from tw_ai.nl_query.audit import (
    QueryAuditEntry,
    QueryAuditLog,
    QuerySanitizer,
)
from tw_ai.nl_query.context import ConversationContext
from tw_ai.nl_query.entities import (
    DateRange,
    EntityExtractor,
    EntityType,
    ExtractedEntity,
)
from tw_ai.nl_query.intent import (
    IntentClassifier,
    QueryIntent,
)
from tw_ai.nl_query.translator import (
    IncidentSearchQuery,
    IocLookupQuery,
    LogSearchQuery,
    NLQueryTranslator,
    QueryContext,
    StatisticsQuery,
    TimelineQuery,
    TranslatedQuery,
)

try:
    from tw_ai.nl_query.api import router
except ImportError:
    router = None

__all__ = [
    # API (requires fastapi)
    "router",
    # Intent classification
    "QueryIntent",
    "IntentClassifier",
    # Entity extraction
    "EntityType",
    "ExtractedEntity",
    "DateRange",
    "EntityExtractor",
    # Translation
    "NLQueryTranslator",
    "QueryContext",
    "TranslatedQuery",
    "IncidentSearchQuery",
    "LogSearchQuery",
    "IocLookupQuery",
    "TimelineQuery",
    "StatisticsQuery",
    # Conversation context
    "ConversationContext",
    # Audit
    "QueryAuditLog",
    "QueryAuditEntry",
    "QuerySanitizer",
]
