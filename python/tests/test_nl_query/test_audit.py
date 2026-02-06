"""Tests for query audit logging and sanitization."""

import pytest

from tw_ai.nl_query.audit import QueryAuditEntry, QueryAuditLog, QuerySanitizer
from tw_ai.nl_query.intent import QueryIntent


@pytest.fixture
def audit_log() -> QueryAuditLog:
    return QueryAuditLog()


@pytest.fixture
def sanitizer() -> QuerySanitizer:
    return QuerySanitizer()


class TestQueryAuditLog:
    def test_initial_state(self, audit_log: QueryAuditLog):
        assert audit_log.entry_count == 0

    def test_log_entry(self, audit_log: QueryAuditLog):
        entry = QueryAuditEntry(
            query_text="show incidents",
            intent=QueryIntent.SEARCH_INCIDENTS,
            user_id="analyst1",
        )
        audit_log.log(entry)
        assert audit_log.entry_count == 1

    def test_log_query_shorthand(self, audit_log: QueryAuditLog):
        entry = audit_log.log_query(
            query_text="search logs",
            intent=QueryIntent.SEARCH_LOGS,
            user_id="analyst1",
            execution_time_ms=150,
            result_count=42,
        )
        assert entry.query_text == "search logs"
        assert entry.execution_time_ms == 150
        assert audit_log.entry_count == 1

    def test_get_entries(self, audit_log: QueryAuditLog):
        audit_log.log_query("q1", QueryIntent.SEARCH_INCIDENTS)
        audit_log.log_query("q2", QueryIntent.SEARCH_LOGS)
        audit_log.log_query("q3", QueryIntent.LOOKUP_IOC)

        entries = audit_log.get_entries()
        assert len(entries) == 3
        # Most recent first
        assert entries[0].query_text == "q3"

    def test_get_entries_filter_by_user(self, audit_log: QueryAuditLog):
        audit_log.log_query("q1", QueryIntent.SEARCH_INCIDENTS, user_id="alice")
        audit_log.log_query("q2", QueryIntent.SEARCH_LOGS, user_id="bob")

        entries = audit_log.get_entries(user_id="alice")
        assert len(entries) == 1
        assert entries[0].user_id == "alice"

    def test_get_entries_filter_by_intent(self, audit_log: QueryAuditLog):
        audit_log.log_query("q1", QueryIntent.SEARCH_INCIDENTS)
        audit_log.log_query("q2", QueryIntent.SEARCH_LOGS)

        entries = audit_log.get_entries(intent=QueryIntent.SEARCH_LOGS)
        assert len(entries) == 1

    def test_get_entries_limit(self, audit_log: QueryAuditLog):
        for i in range(10):
            audit_log.log_query(f"q{i}", QueryIntent.SEARCH_INCIDENTS)

        entries = audit_log.get_entries(limit=3)
        assert len(entries) == 3

    def test_max_entries(self):
        log = QueryAuditLog(max_entries=5)
        for i in range(10):
            log.log_query(f"q{i}", QueryIntent.SEARCH_INCIDENTS)
        assert log.entry_count == 5

    def test_get_stats(self, audit_log: QueryAuditLog):
        audit_log.log_query("q1", QueryIntent.SEARCH_INCIDENTS, user_id="alice",
                           execution_time_ms=100)
        audit_log.log_query("q2", QueryIntent.SEARCH_LOGS, user_id="bob",
                           execution_time_ms=200)

        stats = audit_log.get_stats()
        assert stats["total_queries"] == 2
        assert stats["unique_users"] == 2
        assert stats["avg_execution_time_ms"] == 150.0
        assert stats["intent_distribution"]["search_incidents"] == 1

    def test_get_stats_empty(self, audit_log: QueryAuditLog):
        stats = audit_log.get_stats()
        assert stats["total_queries"] == 0
        assert stats["unique_users"] == 0

    def test_clear(self, audit_log: QueryAuditLog):
        audit_log.log_query("q1", QueryIntent.SEARCH_INCIDENTS)
        audit_log.clear()
        assert audit_log.entry_count == 0


class TestQuerySanitizer:
    def test_safe_query(self, sanitizer: QuerySanitizer):
        clean, warnings = sanitizer.sanitize("show me recent incidents")
        assert clean == "show me recent incidents"
        assert len(warnings) == 0

    def test_empty_query(self, sanitizer: QuerySanitizer):
        clean, warnings = sanitizer.sanitize("")
        assert clean == ""
        assert len(warnings) > 0

    def test_query_too_long(self):
        s = QuerySanitizer(max_query_length=50)
        clean, warnings = s.sanitize("a" * 100)
        assert len(clean) == 50
        assert any("truncated" in w for w in warnings)

    def test_query_too_short(self):
        s = QuerySanitizer(min_query_length=5)
        clean, warnings = s.sanitize("ab")
        assert clean == ""
        assert any("short" in w for w in warnings)

    def test_sql_union_injection(self, sanitizer: QuerySanitizer):
        clean, warnings = sanitizer.sanitize("test UNION SELECT * FROM users")
        assert "UNION SELECT" not in clean
        assert any("sql_union" in w for w in warnings)

    def test_sql_drop_injection(self, sanitizer: QuerySanitizer):
        clean, warnings = sanitizer.sanitize("test; DROP TABLE incidents")
        assert "DROP TABLE" not in clean
        assert any("sql_drop" in w for w in warnings)

    def test_script_tag_injection(self, sanitizer: QuerySanitizer):
        clean, warnings = sanitizer.sanitize("test <script>alert('xss')</script>")
        assert "<script" not in clean.lower()

    def test_command_injection(self, sanitizer: QuerySanitizer):
        clean, warnings = sanitizer.sanitize("test; rm -rf /")
        assert any("command_injection" in w for w in warnings)

    def test_is_safe_positive(self, sanitizer: QuerySanitizer):
        assert sanitizer.is_safe("show me incidents") is True

    def test_is_safe_negative_injection(self, sanitizer: QuerySanitizer):
        assert sanitizer.is_safe("UNION SELECT * FROM users") is False

    def test_is_safe_negative_empty(self, sanitizer: QuerySanitizer):
        assert sanitizer.is_safe("") is False

    def test_is_safe_negative_too_long(self):
        s = QuerySanitizer(max_query_length=10)
        assert s.is_safe("a" * 20) is False

    def test_control_characters_removed(self, sanitizer: QuerySanitizer):
        clean, _ = sanitizer.sanitize("test\x00\x01query")
        assert "\x00" not in clean
        assert "\x01" not in clean

    def test_null_byte_detection(self, sanitizer: QuerySanitizer):
        _, warnings = sanitizer.sanitize("test%00query")
        assert any("null_byte" in w for w in warnings)

    def test_sql_comment_detection(self, sanitizer: QuerySanitizer):
        _, warnings = sanitizer.sanitize("test -- drop table")
        assert any("sql_comment" in w for w in warnings)


class TestQueryAuditEntry:
    def test_creation(self):
        entry = QueryAuditEntry(
            query_text="test",
            intent=QueryIntent.SEARCH_INCIDENTS,
        )
        assert entry.user_id == "anonymous"
        assert entry.execution_time_ms == 0
        assert entry.result_count == 0
        assert entry.sanitized is False
