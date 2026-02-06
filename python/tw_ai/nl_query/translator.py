"""Query translation from natural language to structured search queries.

Translates NL queries into structured query objects that can be consumed
by backend adapters (Splunk, Elasticsearch, SQL).
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from tw_ai.nl_query.entities import DateRange, EntityExtractor, EntityType, ExtractedEntity
from tw_ai.nl_query.intent import IntentClassifier, IntentMatch, QueryIntent


class QueryContext(BaseModel):
    """Context for query translation."""

    model_config = ConfigDict(str_strip_whitespace=True)

    current_incident_id: str | None = Field(
        default=None, description="Currently viewed incident ID"
    )
    user_id: str | None = Field(default=None, description="ID of the querying user")
    default_time_range_hours: int = Field(
        default=24, description="Default time range in hours if none specified"
    )
    organization_id: str | None = Field(default=None, description="Organization context")


class IncidentSearchQuery(BaseModel):
    """Structured query for searching incidents."""

    model_config = ConfigDict(str_strip_whitespace=True)

    keywords: list[str] = Field(default_factory=list)
    severity: str | None = None
    date_range: DateRange | None = None
    indicators: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    limit: int = Field(default=20, ge=1, le=100)


class LogSearchQuery(BaseModel):
    """Structured query for searching logs/events."""

    model_config = ConfigDict(str_strip_whitespace=True)

    keywords: list[str] = Field(default_factory=list)
    source_ips: list[str] = Field(default_factory=list)
    dest_ips: list[str] = Field(default_factory=list)
    usernames: list[str] = Field(default_factory=list)
    date_range: DateRange | None = None
    event_types: list[str] = Field(default_factory=list)
    limit: int = Field(default=50, ge=1, le=1000)


class IocLookupQuery(BaseModel):
    """Structured query for IOC lookups."""

    model_config = ConfigDict(str_strip_whitespace=True)

    ioc_type: str = Field(description="Type of IOC (ip, domain, hash, email)")
    ioc_value: str = Field(description="Value to look up")
    sources: list[str] = Field(default_factory=list, description="Specific intel sources to query")


class TimelineQuery(BaseModel):
    """Structured query for timeline construction."""

    model_config = ConfigDict(str_strip_whitespace=True)

    incident_id: str | None = None
    entity_value: str | None = Field(
        default=None, description="Entity to build timeline for (IP, user, etc.)"
    )
    date_range: DateRange | None = None
    event_types: list[str] = Field(default_factory=list)


class StatisticsQuery(BaseModel):
    """Structured query for statistics/aggregations."""

    model_config = ConfigDict(str_strip_whitespace=True)

    metric: str = Field(description="What to measure (count, average, etc.)")
    group_by: str | None = Field(default=None, description="Field to group by")
    date_range: DateRange | None = None
    filters: dict[str, str] = Field(default_factory=dict)


class TranslatedQuery(BaseModel):
    """Result of translating a natural language query."""

    model_config = ConfigDict(str_strip_whitespace=True)

    original_query: str = Field(description="The original NL query")
    intent: IntentMatch = Field(description="Classified intent")
    entities: list[ExtractedEntity] = Field(default_factory=list, description="Extracted entities")
    date_range: DateRange | None = Field(default=None, description="Extracted date range")

    # One of these will be populated based on intent
    incident_search: IncidentSearchQuery | None = None
    log_search: LogSearchQuery | None = None
    ioc_lookup: IocLookupQuery | None = None
    timeline: TimelineQuery | None = None
    statistics: StatisticsQuery | None = None

    @property
    def structured_query(self) -> BaseModel | None:
        """Return the populated structured query."""
        if self.incident_search is not None:
            return self.incident_search
        if self.log_search is not None:
            return self.log_search
        if self.ioc_lookup is not None:
            return self.ioc_lookup
        if self.timeline is not None:
            return self.timeline
        if self.statistics is not None:
            return self.statistics
        return None


class NLQueryTranslator:
    """Translates natural language queries into structured search queries.

    Combines intent classification and entity extraction to produce
    backend-independent structured queries.
    """

    def __init__(
        self,
        intent_classifier: IntentClassifier | None = None,
        entity_extractor: EntityExtractor | None = None,
    ) -> None:
        """Initialize the translator.

        Args:
            intent_classifier: Optional custom intent classifier.
            entity_extractor: Optional custom entity extractor.
        """
        self._classifier = intent_classifier or IntentClassifier()
        self._extractor = entity_extractor or EntityExtractor()

    def translate(
        self,
        query: str,
        context: QueryContext | None = None,
    ) -> TranslatedQuery:
        """Translate a natural language query into a structured query.

        Args:
            query: The natural language query.
            context: Optional query context.

        Returns:
            TranslatedQuery with classified intent and structured query.
        """
        ctx = context or QueryContext()

        # Classify intent
        intent = self._classifier.classify(query)

        # Extract entities
        entities = self._extractor.extract(query)

        # Extract date range
        date_range = self._extractor.extract_date_range(query)

        # Build the appropriate structured query
        result = TranslatedQuery(
            original_query=query,
            intent=intent,
            entities=entities,
            date_range=date_range,
        )

        # Populate the typed query based on intent
        intent_type = intent.intent

        if intent_type == QueryIntent.SEARCH_INCIDENTS:
            result.incident_search = self._build_incident_search(query, entities, date_range)
        elif intent_type == QueryIntent.SEARCH_LOGS:
            result.log_search = self._build_log_search(query, entities, date_range)
        elif intent_type == QueryIntent.LOOKUP_IOC:
            result.ioc_lookup = self._build_ioc_lookup(entities, query)
        elif intent_type == QueryIntent.TIMELINE_QUERY:
            result.timeline = self._build_timeline(entities, date_range, ctx)
        elif intent_type == QueryIntent.STATISTICS:
            result.statistics = self._build_statistics(query, entities, date_range)
        elif intent_type == QueryIntent.EXPLAIN_INCIDENT:
            # For explain queries, build an incident search to find the incident
            result.incident_search = self._build_incident_search(query, entities, date_range)
        elif intent_type == QueryIntent.COMPARE_INCIDENTS:
            result.incident_search = self._build_incident_search(query, entities, date_range)
        elif intent_type == QueryIntent.ASSET_LOOKUP:
            result.log_search = self._build_log_search(query, entities, date_range)

        return result

    def _build_incident_search(
        self,
        query: str,
        entities: list[ExtractedEntity],
        date_range: DateRange | None,
    ) -> IncidentSearchQuery:
        """Build an incident search query."""
        keywords = self._extract_keywords(query, entities)
        severity = self._get_entity_value(entities, EntityType.SEVERITY)
        indicators = [
            e.value
            for e in entities
            if e.entity_type
            in (
                EntityType.IP_ADDRESS,
                EntityType.DOMAIN,
                EntityType.HASH_MD5,
                EntityType.HASH_SHA1,
                EntityType.HASH_SHA256,
                EntityType.EMAIL,
            )
        ]
        mitre = [e.value for e in entities if e.entity_type == EntityType.MITRE_TECHNIQUE]

        return IncidentSearchQuery(
            keywords=keywords,
            severity=severity,
            date_range=date_range,
            indicators=indicators,
            mitre_techniques=mitre,
        )

    def _build_log_search(
        self,
        query: str,
        entities: list[ExtractedEntity],
        date_range: DateRange | None,
    ) -> LogSearchQuery:
        """Build a log search query."""
        keywords = self._extract_keywords(query, entities)
        ips = [e.value for e in entities if e.entity_type == EntityType.IP_ADDRESS]
        usernames = [e.value for e in entities if e.entity_type == EntityType.USERNAME]

        return LogSearchQuery(
            keywords=keywords,
            source_ips=ips,
            usernames=usernames,
            date_range=date_range,
        )

    def _build_ioc_lookup(
        self,
        entities: list[ExtractedEntity],
        query: str,
    ) -> IocLookupQuery:
        """Build an IOC lookup query."""
        # Find the first IOC-type entity
        ioc_type_map = {
            EntityType.IP_ADDRESS: "ip",
            EntityType.DOMAIN: "domain",
            EntityType.HASH_MD5: "hash",
            EntityType.HASH_SHA1: "hash",
            EntityType.HASH_SHA256: "hash",
            EntityType.EMAIL: "email",
        }

        for entity in entities:
            if entity.entity_type in ioc_type_map:
                return IocLookupQuery(
                    ioc_type=ioc_type_map[entity.entity_type],
                    ioc_value=entity.value,
                )

        # Fallback: try to extract value from query
        return IocLookupQuery(
            ioc_type="unknown",
            ioc_value=query.strip(),
        )

    def _build_timeline(
        self,
        entities: list[ExtractedEntity],
        date_range: DateRange | None,
        context: QueryContext,
    ) -> TimelineQuery:
        """Build a timeline query."""
        incident_ids = [e.value for e in entities if e.entity_type == EntityType.INCIDENT_ID]
        # Use first IP or username as entity value
        entity_value = None
        for e in entities:
            if e.entity_type in (EntityType.IP_ADDRESS, EntityType.USERNAME, EntityType.DOMAIN):
                entity_value = e.value
                break

        return TimelineQuery(
            incident_id=incident_ids[0] if incident_ids else context.current_incident_id,
            entity_value=entity_value,
            date_range=date_range,
        )

    def _build_statistics(
        self,
        query: str,
        entities: list[ExtractedEntity],
        date_range: DateRange | None,
    ) -> StatisticsQuery:
        """Build a statistics query."""
        query_lower = query.lower()

        # Determine the metric
        metric = "count"
        if "average" in query_lower or "avg" in query_lower:
            metric = "average"
        elif "top" in query_lower:
            metric = "top"
        elif "trend" in query_lower:
            metric = "trend"
        elif "distribution" in query_lower:
            metric = "distribution"

        # Determine group_by
        group_by = None
        group_by_candidates = [
            ("severity", ["severity", "sev"]),
            ("type", ["type", "category", "kind"]),
            ("source", ["source", "origin"]),
            ("user", ["user", "analyst"]),
        ]
        for field_name, keywords in group_by_candidates:
            if any(kw in query_lower for kw in keywords):
                group_by = field_name
                break

        filters: dict[str, str] = {}
        severity = self._get_entity_value(entities, EntityType.SEVERITY)
        if severity:
            filters["severity"] = severity

        return StatisticsQuery(
            metric=metric,
            group_by=group_by,
            date_range=date_range,
            filters=filters,
        )

    @staticmethod
    def _extract_keywords(
        query: str,
        entities: list[ExtractedEntity],
    ) -> list[str]:
        """Extract meaningful keywords from the query, excluding entity values."""
        # Remove entity text spans from query
        clean = query
        for entity in sorted(entities, key=lambda e: e.start, reverse=True):
            clean = clean[: entity.start] + clean[entity.end :]

        # Remove common stop words and query words
        stop_words = {
            "show",
            "me",
            "find",
            "search",
            "get",
            "list",
            "the",
            "a",
            "an",
            "for",
            "with",
            "from",
            "in",
            "of",
            "to",
            "and",
            "or",
            "that",
            "this",
            "all",
            "any",
            "is",
            "are",
            "was",
            "were",
            "has",
            "have",
            "can",
            "could",
            "would",
            "should",
            "what",
            "where",
            "when",
            "how",
            "which",
            "who",
            "please",
            "i",
            "my",
        }

        words = clean.split()
        keywords = [
            w.strip(".,;:!?\"'()[]")
            for w in words
            if w.lower().strip(".,;:!?\"'()[]") not in stop_words
            and len(w.strip(".,;:!?\"'()[]")) > 1
        ]
        return keywords

    @staticmethod
    def _get_entity_value(
        entities: list[ExtractedEntity],
        entity_type: EntityType,
    ) -> str | None:
        """Get the first entity value of a given type."""
        for e in entities:
            if e.entity_type == entity_type:
                return e.value
        return None


__all__ = [
    "QueryContext",
    "IncidentSearchQuery",
    "LogSearchQuery",
    "IocLookupQuery",
    "TimelineQuery",
    "StatisticsQuery",
    "TranslatedQuery",
    "NLQueryTranslator",
]
