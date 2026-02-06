"""Tests for query translation."""

import pytest

from tw_ai.nl_query.entities import EntityType
from tw_ai.nl_query.intent import QueryIntent
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


@pytest.fixture
def translator() -> NLQueryTranslator:
    return NLQueryTranslator()


class TestNLQueryTranslator:
    def test_translate_incident_search(self, translator: NLQueryTranslator):
        result = translator.translate("show me critical incidents")
        assert result.intent.intent == QueryIntent.SEARCH_INCIDENTS
        assert result.incident_search is not None
        assert result.structured_query is not None

    def test_translate_log_search(self, translator: NLQueryTranslator):
        result = translator.translate("search authentication logs for user: admin")
        assert result.intent.intent == QueryIntent.SEARCH_LOGS
        assert result.log_search is not None
        assert "admin" in result.log_search.usernames

    def test_translate_ioc_lookup(self, translator: NLQueryTranslator):
        result = translator.translate("check IP 10.0.0.1")
        assert result.intent.intent == QueryIntent.LOOKUP_IOC
        assert result.ioc_lookup is not None
        assert result.ioc_lookup.ioc_value == "10.0.0.1"
        assert result.ioc_lookup.ioc_type == "ip"

    def test_translate_ioc_lookup_domain(self, translator: NLQueryTranslator):
        result = translator.translate("lookup reputation for evil.com")
        assert result.ioc_lookup is not None
        assert result.ioc_lookup.ioc_type == "domain"
        assert result.ioc_lookup.ioc_value == "evil.com"

    def test_translate_ioc_lookup_hash(self, translator: NLQueryTranslator):
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        result = translator.translate(f"is {md5} malicious")
        assert result.ioc_lookup is not None
        assert result.ioc_lookup.ioc_type == "hash"

    def test_translate_timeline(self, translator: NLQueryTranslator):
        result = translator.translate("show timeline for last 24 hours")
        assert result.intent.intent == QueryIntent.TIMELINE_QUERY
        assert result.timeline is not None
        assert result.date_range is not None

    def test_translate_statistics(self, translator: NLQueryTranslator):
        result = translator.translate("how many alerts total by severity")
        assert result.intent.intent == QueryIntent.STATISTICS
        assert result.statistics is not None
        assert result.statistics.metric == "count"

    def test_translate_statistics_top(self, translator: NLQueryTranslator):
        result = translator.translate("top 10 source IPs")
        assert result.statistics is not None
        assert result.statistics.metric == "top"

    def test_translate_with_context(self, translator: NLQueryTranslator):
        ctx = QueryContext(current_incident_id="INC-123", user_id="analyst1")
        result = translator.translate("show me the timeline", context=ctx)
        assert result.timeline is not None

    def test_translate_with_date_range(self, translator: NLQueryTranslator):
        result = translator.translate(
            "find incidents from 2024-01-01 to 2024-01-31"
        )
        assert result.date_range is not None
        assert result.date_range.start.year == 2024

    def test_translate_explain_incident(self, translator: NLQueryTranslator):
        result = translator.translate("explain incident INC-1234")
        assert result.intent.intent == QueryIntent.EXPLAIN_INCIDENT
        # Should build an incident search to find it
        assert result.incident_search is not None

    def test_translate_preserves_entities(self, translator: NLQueryTranslator):
        result = translator.translate("check 10.0.0.1 and T1566.001")
        entity_types = {e.entity_type for e in result.entities}
        assert EntityType.IP_ADDRESS in entity_types
        assert EntityType.MITRE_TECHNIQUE in entity_types

    def test_incident_search_with_severity(self, translator: NLQueryTranslator):
        result = translator.translate(
            "show me all recent incidents with severity: high"
        )
        assert result.incident_search is not None
        assert result.incident_search.severity == "high"

    def test_log_search_with_username(self, translator: NLQueryTranslator):
        result = translator.translate("search authentication logs for user: admin")
        assert result.log_search is not None
        assert "admin" in result.log_search.usernames


class TestTranslatedQuery:
    def test_structured_query_none_for_general(self, translator: NLQueryTranslator):
        result = translator.translate("hello world")
        # General questions don't produce structured queries
        assert result.intent.intent == QueryIntent.GENERAL_QUESTION

    def test_original_query_preserved(self, translator: NLQueryTranslator):
        query = "show me incidents"
        result = translator.translate(query)
        assert result.original_query == query


class TestQueryContext:
    def test_default_context(self):
        ctx = QueryContext()
        assert ctx.current_incident_id is None
        assert ctx.default_time_range_hours == 24

    def test_custom_context(self):
        ctx = QueryContext(
            current_incident_id="INC-42",
            user_id="analyst",
            default_time_range_hours=48,
        )
        assert ctx.current_incident_id == "INC-42"
        assert ctx.user_id == "analyst"
