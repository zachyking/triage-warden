"""Splunk SPL query backend.

Generates Splunk Processing Language (SPL) queries from TranslatedQuery objects.
"""

from __future__ import annotations

from tw_ai.nl_query.backends.base import QueryBackend, QueryResult
from tw_ai.nl_query.intent import QueryIntent
from tw_ai.nl_query.translator import TranslatedQuery


class SplunkBackend(QueryBackend):
    """Generates SPL queries from structured queries."""

    def __init__(self, index: str = "main") -> None:
        """Initialize with default Splunk index.

        Args:
            index: Default Splunk index to search.
        """
        self._index = index

    @property
    def backend_name(self) -> str:
        return "splunk"

    def generate(self, translated: TranslatedQuery) -> QueryResult:
        """Generate an SPL query from the translated query."""
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
        parts = [f'index="{self._index}" sourcetype="incident"']

        if q.severity:
            parts.append(f'severity="{q.severity}"')
        for indicator in q.indicators:
            parts.append(f'"{_escape_splunk(indicator)}"')
        for tech in q.mitre_techniques:
            parts.append(f'mitre_technique="{_escape_splunk(tech)}"')
        for kw in q.keywords:
            parts.append(f'"{_escape_splunk(kw)}"')

        spl = " ".join(parts)

        if translated.date_range:
            spl += (
                f' earliest="{self._format_datetime(translated.date_range.start)}"'
                f' latest="{self._format_datetime(translated.date_range.end)}"'
            )

        spl += f" | head {q.limit}"

        return QueryResult(
            query_string=spl,
            query_type="SPL",
            metadata={"index": self._index, "intent": "search_incidents"},
        )

    def _generate_log_search(self, translated: TranslatedQuery) -> QueryResult:
        q = translated.log_search
        assert q is not None
        parts = [f'index="{self._index}"']

        for ip in q.source_ips:
            parts.append(f'src_ip="{_escape_splunk(ip)}"')
        for ip in q.dest_ips:
            parts.append(f'dest_ip="{_escape_splunk(ip)}"')
        for user in q.usernames:
            parts.append(f'user="{_escape_splunk(user)}"')
        for kw in q.keywords:
            parts.append(f'"{_escape_splunk(kw)}"')

        spl = " ".join(parts)

        if translated.date_range:
            spl += (
                f' earliest="{self._format_datetime(translated.date_range.start)}"'
                f' latest="{self._format_datetime(translated.date_range.end)}"'
            )

        spl += f" | head {q.limit}"

        return QueryResult(
            query_string=spl,
            query_type="SPL",
            metadata={"index": self._index, "intent": "search_logs"},
        )

    def _generate_ioc_lookup(self, translated: TranslatedQuery) -> QueryResult:
        q = translated.ioc_lookup
        assert q is not None
        field_map = {
            "ip": "src_ip dest_ip",
            "domain": "domain dest_host",
            "hash": "file_hash md5 sha256",
            "email": "sender recipient",
        }

        fields = field_map.get(q.ioc_type, "")
        search_terms = []
        if fields:
            for field in fields.split():
                search_terms.append(f'{field}="{_escape_splunk(q.ioc_value)}"')
            ioc_search = " OR ".join(search_terms)
        else:
            ioc_search = f'"{_escape_splunk(q.ioc_value)}"'

        spl = f'index="{self._index}" ({ioc_search})'

        if translated.date_range:
            spl += (
                f' earliest="{self._format_datetime(translated.date_range.start)}"'
                f' latest="{self._format_datetime(translated.date_range.end)}"'
            )

        spl += " | stats count by sourcetype, src_ip, dest_ip, user"

        return QueryResult(
            query_string=spl,
            query_type="SPL",
            metadata={"index": self._index, "intent": "lookup_ioc"},
        )

    def _generate_timeline(self, translated: TranslatedQuery) -> QueryResult:
        q = translated.timeline
        assert q is not None
        parts = [f'index="{self._index}"']

        if q.incident_id:
            parts.append(f'incident_id="{_escape_splunk(q.incident_id)}"')
        if q.entity_value:
            parts.append(f'"{_escape_splunk(q.entity_value)}"')

        spl = " ".join(parts)

        if translated.date_range:
            spl += (
                f' earliest="{self._format_datetime(translated.date_range.start)}"'
                f' latest="{self._format_datetime(translated.date_range.end)}"'
            )

        spl += " | sort _time | table _time, sourcetype, src_ip, dest_ip, user, action"

        return QueryResult(
            query_string=spl,
            query_type="SPL",
            metadata={"index": self._index, "intent": "timeline"},
        )

    def _generate_statistics(self, translated: TranslatedQuery) -> QueryResult:
        q = translated.statistics
        assert q is not None
        parts = [f'index="{self._index}"']

        for field_name, value in q.filters.items():
            parts.append(f'{field_name}="{_escape_splunk(value)}"')

        spl = " ".join(parts)

        if translated.date_range:
            spl += (
                f' earliest="{self._format_datetime(translated.date_range.start)}"'
                f' latest="{self._format_datetime(translated.date_range.end)}"'
            )

        if q.metric == "count" and q.group_by:
            spl += f" | stats count by {q.group_by}"
        elif q.metric == "top" and q.group_by:
            spl += f" | top {q.group_by}"
        elif q.metric == "trend":
            spl += " | timechart count"
        elif q.metric == "distribution" and q.group_by:
            spl += f" | stats count by {q.group_by} | sort -count"
        else:
            spl += " | stats count"

        return QueryResult(
            query_string=spl,
            query_type="SPL",
            metadata={"index": self._index, "intent": "statistics"},
        )

    def _generate_keyword_search(self, translated: TranslatedQuery) -> QueryResult:
        parts = [f'index="{self._index}"']

        for entity in translated.entities:
            parts.append(f'"{_escape_splunk(entity.value)}"')

        if not translated.entities:
            # Fall back to raw query keywords
            clean = translated.original_query.strip()
            if clean:
                parts.append(f'"{_escape_splunk(clean)}"')

        spl = " ".join(parts)
        return QueryResult(
            query_string=spl,
            query_type="SPL",
            metadata={"index": self._index, "intent": "keyword_search"},
        )

    def _format_datetime(self, dt: object) -> str:
        if hasattr(dt, "strftime"):
            return str(dt.strftime("%m/%d/%Y:%H:%M:%S"))
        return str(dt)


def _escape_splunk(value: str) -> str:
    """Escape special characters in Splunk queries."""
    return value.replace("\\", "\\\\").replace('"', '\\"')


__all__ = ["SplunkBackend"]
