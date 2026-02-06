"""SQL query backend.

Generates parameterized SQL queries from TranslatedQuery objects.
Uses parameterized queries to prevent SQL injection.
"""

from __future__ import annotations

from typing import Any

from tw_ai.nl_query.backends.base import QueryBackend, QueryResult
from tw_ai.nl_query.intent import QueryIntent
from tw_ai.nl_query.translator import TranslatedQuery


class SQLBackend(QueryBackend):
    """Generates parameterized SQL queries from structured queries.

    All user-provided values are passed as parameters rather than
    interpolated into the query string, preventing SQL injection.
    """

    def __init__(
        self,
        incidents_table: str = "incidents",
        logs_table: str = "events",
        ioc_table: str = "indicators",
    ) -> None:
        """Initialize with table names.

        Args:
            incidents_table: Name of the incidents table.
            logs_table: Name of the events/logs table.
            ioc_table: Name of the IOC/indicators table.
        """
        self._incidents_table = incidents_table
        self._logs_table = logs_table
        self._ioc_table = ioc_table

    @property
    def backend_name(self) -> str:
        return "sql"

    def generate(self, translated: TranslatedQuery) -> QueryResult:
        """Generate a parameterized SQL query from the translated query."""
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
        conditions: list[str] = []
        params: dict[str, Any] = {}
        param_idx = 0

        if q.severity:
            conditions.append(f"severity = :p{param_idx}")
            params[f"p{param_idx}"] = q.severity
            param_idx += 1

        for indicator in q.indicators:
            conditions.append(f"indicators LIKE :p{param_idx}")
            params[f"p{param_idx}"] = f"%{indicator}%"
            param_idx += 1

        for tech in q.mitre_techniques:
            conditions.append(f"mitre_techniques LIKE :p{param_idx}")
            params[f"p{param_idx}"] = f"%{tech}%"
            param_idx += 1

        for kw in q.keywords:
            conditions.append(f"(summary LIKE :p{param_idx} OR description LIKE :p{param_idx})")
            params[f"p{param_idx}"] = f"%{kw}%"
            param_idx += 1

        if translated.date_range:
            conditions.append(f"created_at >= :p{param_idx}")
            params[f"p{param_idx}"] = translated.date_range.start.isoformat()
            param_idx += 1
            conditions.append(f"created_at <= :p{param_idx}")
            params[f"p{param_idx}"] = translated.date_range.end.isoformat()
            param_idx += 1

        where = " AND ".join(conditions) if conditions else "1=1"
        sql = (
            f"SELECT * FROM {self._incidents_table}"
            f" WHERE {where}"
            f" ORDER BY created_at DESC"
            f" LIMIT :limit"
        )
        params["limit"] = q.limit

        return QueryResult(
            query_string=sql,
            query_type="SQL",
            parameters=params,
            metadata={"table": self._incidents_table, "intent": "search_incidents"},
        )

    def _generate_log_search(self, translated: TranslatedQuery) -> QueryResult:
        q = translated.log_search
        assert q is not None
        conditions: list[str] = []
        params: dict[str, Any] = {}
        param_idx = 0

        for ip in q.source_ips:
            conditions.append(f"source_ip = :p{param_idx}")
            params[f"p{param_idx}"] = ip
            param_idx += 1

        for ip in q.dest_ips:
            conditions.append(f"dest_ip = :p{param_idx}")
            params[f"p{param_idx}"] = ip
            param_idx += 1

        for user in q.usernames:
            conditions.append(f"username = :p{param_idx}")
            params[f"p{param_idx}"] = user
            param_idx += 1

        for kw in q.keywords:
            conditions.append(f"message LIKE :p{param_idx}")
            params[f"p{param_idx}"] = f"%{kw}%"
            param_idx += 1

        if translated.date_range:
            conditions.append(f"timestamp >= :p{param_idx}")
            params[f"p{param_idx}"] = translated.date_range.start.isoformat()
            param_idx += 1
            conditions.append(f"timestamp <= :p{param_idx}")
            params[f"p{param_idx}"] = translated.date_range.end.isoformat()
            param_idx += 1

        where = " AND ".join(conditions) if conditions else "1=1"
        sql = (
            f"SELECT * FROM {self._logs_table}"
            f" WHERE {where}"
            f" ORDER BY timestamp DESC"
            f" LIMIT :limit"
        )
        params["limit"] = q.limit

        return QueryResult(
            query_string=sql,
            query_type="SQL",
            parameters=params,
            metadata={"table": self._logs_table, "intent": "search_logs"},
        )

    def _generate_ioc_lookup(self, translated: TranslatedQuery) -> QueryResult:
        q = translated.ioc_lookup
        assert q is not None
        conditions = ["value = :value"]
        params: dict[str, Any] = {"value": q.ioc_value}

        if q.ioc_type != "unknown":
            conditions.append("type = :type")
            params["type"] = q.ioc_type

        where = " AND ".join(conditions)
        sql = f"SELECT * FROM {self._ioc_table} WHERE {where}"

        return QueryResult(
            query_string=sql,
            query_type="SQL",
            parameters=params,
            metadata={"table": self._ioc_table, "intent": "lookup_ioc"},
        )

    def _generate_timeline(self, translated: TranslatedQuery) -> QueryResult:
        q = translated.timeline
        assert q is not None
        conditions: list[str] = []
        params: dict[str, Any] = {}
        param_idx = 0

        if q.incident_id:
            conditions.append(f"incident_id = :p{param_idx}")
            params[f"p{param_idx}"] = q.incident_id
            param_idx += 1

        if q.entity_value:
            conditions.append(
                f"(source_ip = :p{param_idx} OR dest_ip = :p{param_idx}"
                f" OR username = :p{param_idx})"
            )
            params[f"p{param_idx}"] = q.entity_value
            param_idx += 1

        if translated.date_range:
            conditions.append(f"timestamp >= :p{param_idx}")
            params[f"p{param_idx}"] = translated.date_range.start.isoformat()
            param_idx += 1
            conditions.append(f"timestamp <= :p{param_idx}")
            params[f"p{param_idx}"] = translated.date_range.end.isoformat()
            param_idx += 1

        where = " AND ".join(conditions) if conditions else "1=1"
        sql = f"SELECT * FROM {self._logs_table}" f" WHERE {where}" f" ORDER BY timestamp ASC"

        return QueryResult(
            query_string=sql,
            query_type="SQL",
            parameters=params,
            metadata={"table": self._logs_table, "intent": "timeline"},
        )

    def _generate_statistics(self, translated: TranslatedQuery) -> QueryResult:
        q = translated.statistics
        assert q is not None
        conditions: list[str] = []
        params: dict[str, Any] = {}
        param_idx = 0

        for field_name, value in q.filters.items():
            safe_field = _sanitize_column_name(field_name)
            conditions.append(f"{safe_field} = :p{param_idx}")
            params[f"p{param_idx}"] = value
            param_idx += 1

        if translated.date_range:
            conditions.append(f"created_at >= :p{param_idx}")
            params[f"p{param_idx}"] = translated.date_range.start.isoformat()
            param_idx += 1
            conditions.append(f"created_at <= :p{param_idx}")
            params[f"p{param_idx}"] = translated.date_range.end.isoformat()
            param_idx += 1

        where = " AND ".join(conditions) if conditions else "1=1"

        if q.metric == "count" and q.group_by:
            safe_group = _sanitize_column_name(q.group_by)
            sql = (
                f"SELECT {safe_group}, COUNT(*) as count"
                f" FROM {self._incidents_table}"
                f" WHERE {where}"
                f" GROUP BY {safe_group}"
                f" ORDER BY count DESC"
            )
        elif q.metric == "top" and q.group_by:
            safe_group = _sanitize_column_name(q.group_by)
            sql = (
                f"SELECT {safe_group}, COUNT(*) as count"
                f" FROM {self._incidents_table}"
                f" WHERE {where}"
                f" GROUP BY {safe_group}"
                f" ORDER BY count DESC"
                f" LIMIT 10"
            )
        elif q.metric == "trend":
            sql = (
                f"SELECT DATE(created_at) as date, COUNT(*) as count"
                f" FROM {self._incidents_table}"
                f" WHERE {where}"
                f" GROUP BY DATE(created_at)"
                f" ORDER BY date ASC"
            )
        else:
            sql = f"SELECT COUNT(*) as count" f" FROM {self._incidents_table}" f" WHERE {where}"

        return QueryResult(
            query_string=sql,
            query_type="SQL",
            parameters=params,
            metadata={"table": self._incidents_table, "intent": "statistics"},
        )

    def _generate_keyword_search(self, translated: TranslatedQuery) -> QueryResult:
        conditions: list[str] = []
        params: dict[str, Any] = {}
        param_idx = 0

        for entity in translated.entities:
            conditions.append(f"(summary LIKE :p{param_idx} OR description LIKE :p{param_idx})")
            params[f"p{param_idx}"] = f"%{entity.value}%"
            param_idx += 1

        if not conditions:
            clean = translated.original_query.strip()
            if clean:
                conditions.append(f"(summary LIKE :p{param_idx} OR description LIKE :p{param_idx})")
                params[f"p{param_idx}"] = f"%{clean}%"
                param_idx += 1

        where = " AND ".join(conditions) if conditions else "1=1"
        sql = (
            f"SELECT * FROM {self._incidents_table}"
            f" WHERE {where}"
            f" ORDER BY created_at DESC"
            f" LIMIT 20"
        )

        return QueryResult(
            query_string=sql,
            query_type="SQL",
            parameters=params,
            metadata={"table": self._incidents_table, "intent": "keyword_search"},
        )


def _sanitize_column_name(name: str) -> str:
    """Sanitize a column name to prevent injection via column identifiers.

    Only allows alphanumeric characters and underscores.
    """
    import re

    sanitized = re.sub(r"[^a-zA-Z0-9_]", "", name)
    if not sanitized:
        return "unknown"
    return sanitized


__all__ = ["SQLBackend"]
