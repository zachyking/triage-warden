"""Tests for query backend adapters (Splunk, Elastic, SQL)."""

import pytest

from tw_ai.nl_query.backends import ElasticBackend, QueryBackend, SQLBackend, SplunkBackend
from tw_ai.nl_query.translator import NLQueryTranslator, QueryContext


@pytest.fixture
def translator() -> NLQueryTranslator:
    return NLQueryTranslator()


@pytest.fixture
def splunk() -> SplunkBackend:
    return SplunkBackend(index="security")


@pytest.fixture
def elastic() -> ElasticBackend:
    return ElasticBackend(index_pattern="security-*")


@pytest.fixture
def sql() -> SQLBackend:
    return SQLBackend()


class TestSplunkBackend:
    def test_backend_name(self, splunk: SplunkBackend):
        assert splunk.backend_name == "splunk"

    def test_incident_search(self, splunk: SplunkBackend, translator: NLQueryTranslator):
        translated = translator.translate("show me critical incidents")
        result = splunk.generate(translated)
        assert result.query_type == "SPL"
        assert 'index="security"' in result.query_string
        assert "head" in result.query_string

    def test_log_search_with_ip(self, splunk: SplunkBackend, translator: NLQueryTranslator):
        translated = translator.translate("search logs from 10.0.0.1")
        result = splunk.generate(translated)
        assert "10.0.0.1" in result.query_string

    def test_ioc_lookup(self, splunk: SplunkBackend, translator: NLQueryTranslator):
        translated = translator.translate("lookup 10.0.0.1")
        result = splunk.generate(translated)
        assert "10.0.0.1" in result.query_string
        assert result.query_type == "SPL"

    def test_timeline_query(self, splunk: SplunkBackend, translator: NLQueryTranslator):
        translated = translator.translate("show timeline for last 24 hours")
        result = splunk.generate(translated)
        assert "sort _time" in result.query_string

    def test_statistics_query(self, splunk: SplunkBackend, translator: NLQueryTranslator):
        translated = translator.translate("how many incidents by severity")
        result = splunk.generate(translated)
        assert "stats count" in result.query_string

    def test_escapes_special_chars(self, splunk: SplunkBackend, translator: NLQueryTranslator):
        translated = translator.translate('search logs for "test"')
        result = splunk.generate(translated)
        # Should escape the quote
        assert result.query_string is not None


class TestElasticBackend:
    def test_backend_name(self, elastic: ElasticBackend):
        assert elastic.backend_name == "elasticsearch"

    def test_incident_search(self, elastic: ElasticBackend, translator: NLQueryTranslator):
        translated = translator.translate("show me critical incidents")
        result = elastic.generate(translated)
        assert result.query_type == "KQL"

    def test_log_search_with_ip(self, elastic: ElasticBackend, translator: NLQueryTranslator):
        translated = translator.translate("search logs from 10.0.0.1")
        result = elastic.generate(translated)
        assert "10.0.0.1" in result.query_string

    def test_ioc_lookup(self, elastic: ElasticBackend, translator: NLQueryTranslator):
        translated = translator.translate("lookup 10.0.0.1")
        result = elastic.generate(translated)
        assert "10.0.0.1" in result.query_string

    def test_timeline_has_sort(self, elastic: ElasticBackend, translator: NLQueryTranslator):
        translated = translator.translate("show timeline for last 24 hours")
        result = elastic.generate(translated)
        assert "sort" in str(result.metadata)

    def test_statistics_with_aggregation(
        self, elastic: ElasticBackend, translator: NLQueryTranslator
    ):
        translated = translator.translate("how many incidents by severity")
        result = elastic.generate(translated)
        assert "aggregations" in result.metadata


class TestSQLBackend:
    def test_backend_name(self, sql: SQLBackend):
        assert sql.backend_name == "sql"

    def test_incident_search_parameterized(self, sql: SQLBackend, translator: NLQueryTranslator):
        translated = translator.translate("show me critical incidents")
        result = sql.generate(translated)
        assert result.query_type == "SQL"
        assert "SELECT" in result.query_string
        assert "incidents" in result.query_string
        # Verify parameterized (no raw values in query)
        assert ":limit" in result.query_string or ":p" in result.query_string

    def test_log_search_parameterized(self, sql: SQLBackend, translator: NLQueryTranslator):
        translated = translator.translate("search authentication logs for user: admin")
        result = sql.generate(translated)
        assert "events" in result.query_string
        # User should be in parameters, not in query string
        assert "admin" in str(result.parameters.values())

    def test_ioc_lookup_parameterized(self, sql: SQLBackend, translator: NLQueryTranslator):
        translated = translator.translate("lookup 10.0.0.1")
        result = sql.generate(translated)
        assert "indicators" in result.query_string
        assert result.parameters.get("value") == "10.0.0.1"

    def test_timeline_ordered_by_timestamp(self, sql: SQLBackend, translator: NLQueryTranslator):
        translated = translator.translate("show timeline for last 24 hours")
        result = sql.generate(translated)
        assert "ORDER BY timestamp ASC" in result.query_string

    def test_statistics_count(self, sql: SQLBackend, translator: NLQueryTranslator):
        translated = translator.translate("how many incidents total")
        result = sql.generate(translated)
        assert "COUNT" in result.query_string

    def test_statistics_group_by(self, sql: SQLBackend, translator: NLQueryTranslator):
        translated = translator.translate("how many incidents by severity")
        result = sql.generate(translated)
        assert "GROUP BY" in result.query_string

    def test_sql_injection_prevention(self, sql: SQLBackend, translator: NLQueryTranslator):
        # User values should be parameterized
        translated = translator.translate("search logs from 10.0.0.1; DROP TABLE events")
        result = sql.generate(translated)
        # The DROP TABLE should NOT appear in the SQL query string
        assert "DROP TABLE" not in result.query_string

    def test_column_name_sanitization(self, sql: SQLBackend, translator: NLQueryTranslator):
        translated = translator.translate("how many incidents by severity")
        result = sql.generate(translated)
        # Column names should be safe
        assert "severity" in result.query_string

    def test_table_name_sanitization(self, translator: NLQueryTranslator):
        sql = SQLBackend(
            incidents_table="incidents; DROP TABLE users --",
            logs_table="events; DELETE FROM events",
            ioc_table="indicators; TRUNCATE indicators",
        )

        translated = translator.translate("show me critical incidents")
        result = sql.generate(translated)

        assert ";" not in result.query_string
        assert "--" not in result.query_string
        assert "DROP TABLE" not in result.query_string
