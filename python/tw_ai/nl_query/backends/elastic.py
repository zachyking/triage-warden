"""Elasticsearch KQL/EQL query backend.

Generates Kibana Query Language (KQL) queries from TranslatedQuery objects.
"""

from __future__ import annotations

from typing import Any

from tw_ai.nl_query.backends.base import QueryBackend, QueryResult
from tw_ai.nl_query.intent import QueryIntent
from tw_ai.nl_query.translator import TranslatedQuery


class ElasticBackend(QueryBackend):
    """Generates Elasticsearch KQL queries from structured queries."""

    def __init__(self, index_pattern: str = "security-*") -> None:
        """Initialize with default index pattern.

        Args:
            index_pattern: Elasticsearch index pattern.
        """
        self._index_pattern = index_pattern

    @property
    def backend_name(self) -> str:
        return "elasticsearch"

    def generate(self, translated: TranslatedQuery) -> QueryResult:
        """Generate a KQL query from the translated query."""
        intent = translated.intent.intent

        if intent == QueryIntent.SEARCH_INCIDENTS and translated.incident_search:
            return self._generate_incident_search(translated)
        elif intent == QueryIntent.SEARCH_LOGS and translated.log_search:
            return self._generate_log_search(translated)
        elif intent == QueryIntent.LOOKUP_IOC and translated.ioc_lookup:
            return self._generate_ioc_lookup(translated)
        elif intent == QueryIntent.TIMELINE_QUERY and translated.timeline:
            return self._generate_timeline(translated)
        elif intent == QueryIntent.STATISTICS and translated.statistics:
            return self._generate_statistics(translated)
        else:
            return self._generate_keyword_search(translated)

    def _generate_incident_search(self, translated: TranslatedQuery) -> QueryResult:
        q = translated.incident_search
        assert q is not None
        clauses: list[str] = []

        if q.severity:
            clauses.append(f"severity: {_escape_kql(q.severity)}")
        for indicator in q.indicators:
            clauses.append(f'"{_escape_kql(indicator)}"')
        for tech in q.mitre_techniques:
            clauses.append(f"mitre.technique.id: {_escape_kql(tech)}")
        for kw in q.keywords:
            clauses.append(f'"{_escape_kql(kw)}"')

        kql = " AND ".join(clauses) if clauses else "*"

        metadata: dict[str, Any] = {
            "index": self._index_pattern,
            "intent": "search_incidents",
        }
        if translated.date_range:
            metadata["time_range"] = {
                "gte": self._format_datetime(translated.date_range.start),
                "lte": self._format_datetime(translated.date_range.end),
            }

        return QueryResult(
            query_string=kql,
            query_type="KQL",
            metadata=metadata,
        )

    def _generate_log_search(self, translated: TranslatedQuery) -> QueryResult:
        q = translated.log_search
        assert q is not None
        clauses: list[str] = []

        for ip in q.source_ips:
            clauses.append(f"source.ip: {_escape_kql(ip)}")
        for ip in q.dest_ips:
            clauses.append(f"destination.ip: {_escape_kql(ip)}")
        for user in q.usernames:
            clauses.append(f"user.name: {_escape_kql(user)}")
        for kw in q.keywords:
            clauses.append(f'"{_escape_kql(kw)}"')

        kql = " AND ".join(clauses) if clauses else "*"

        metadata: dict[str, Any] = {
            "index": self._index_pattern,
            "intent": "search_logs",
        }
        if translated.date_range:
            metadata["time_range"] = {
                "gte": self._format_datetime(translated.date_range.start),
                "lte": self._format_datetime(translated.date_range.end),
            }

        return QueryResult(
            query_string=kql,
            query_type="KQL",
            metadata=metadata,
        )

    def _generate_ioc_lookup(self, translated: TranslatedQuery) -> QueryResult:
        q = translated.ioc_lookup
        assert q is not None
        field_map = {
            "ip": ["source.ip", "destination.ip"],
            "domain": ["dns.question.name", "url.domain"],
            "hash": ["file.hash.md5", "file.hash.sha256"],
            "email": ["email.from.address", "email.to.address"],
        }

        fields = field_map.get(q.ioc_type, [])
        if fields:
            clauses = [f"{f}: {_escape_kql(q.ioc_value)}" for f in fields]
            kql = " OR ".join(clauses)
        else:
            kql = f'"{_escape_kql(q.ioc_value)}"'

        return QueryResult(
            query_string=kql,
            query_type="KQL",
            metadata={
                "index": self._index_pattern,
                "intent": "lookup_ioc",
            },
        )

    def _generate_timeline(self, translated: TranslatedQuery) -> QueryResult:
        q = translated.timeline
        assert q is not None
        clauses: list[str] = []

        if q.incident_id:
            clauses.append(f"incident.id: {_escape_kql(q.incident_id)}")
        if q.entity_value:
            clauses.append(f'"{_escape_kql(q.entity_value)}"')

        kql = " AND ".join(clauses) if clauses else "*"

        metadata: dict[str, Any] = {
            "index": self._index_pattern,
            "intent": "timeline",
            "sort": [{"@timestamp": {"order": "asc"}}],
        }
        if translated.date_range:
            metadata["time_range"] = {
                "gte": self._format_datetime(translated.date_range.start),
                "lte": self._format_datetime(translated.date_range.end),
            }

        return QueryResult(
            query_string=kql,
            query_type="KQL",
            metadata=metadata,
        )

    def _generate_statistics(self, translated: TranslatedQuery) -> QueryResult:
        q = translated.statistics
        assert q is not None
        filter_clauses: list[str] = []

        for field_name, value in q.filters.items():
            filter_clauses.append(f"{field_name}: {_escape_kql(value)}")

        kql = " AND ".join(filter_clauses) if filter_clauses else "*"

        aggs: dict[str, Any] = {}
        if q.metric == "count" and q.group_by:
            aggs = {"group_stats": {"terms": {"field": q.group_by, "size": 20}}}
        elif q.metric == "top" and q.group_by:
            aggs = {
                "top_values": {
                    "terms": {"field": q.group_by, "size": 10, "order": {"_count": "desc"}}
                }
            }
        elif q.metric == "trend":
            aggs = {"trend": {"date_histogram": {"field": "@timestamp", "calendar_interval": "1d"}}}

        metadata: dict[str, Any] = {
            "index": self._index_pattern,
            "intent": "statistics",
            "aggregations": aggs,
        }
        if translated.date_range:
            metadata["time_range"] = {
                "gte": self._format_datetime(translated.date_range.start),
                "lte": self._format_datetime(translated.date_range.end),
            }

        return QueryResult(
            query_string=kql,
            query_type="KQL",
            metadata=metadata,
        )

    def _generate_keyword_search(self, translated: TranslatedQuery) -> QueryResult:
        parts: list[str] = []
        for entity in translated.entities:
            parts.append(f'"{_escape_kql(entity.value)}"')

        if not parts:
            clean = translated.original_query.strip()
            if clean:
                parts.append(f'"{_escape_kql(clean)}"')

        kql = " AND ".join(parts) if parts else "*"
        return QueryResult(
            query_string=kql,
            query_type="KQL",
            metadata={
                "index": self._index_pattern,
                "intent": "keyword_search",
            },
        )


def _escape_kql(value: str) -> str:
    """Escape special characters in KQL queries."""
    special = ["\\", '"', ":", "(", ")", "{", "}", "[", "]", "*", "?"]
    result = value
    for char in special:
        result = result.replace(char, f"\\{char}")
    return result


__all__ = ["ElasticBackend"]
