"""Tests for intent classification."""

import pytest

from tw_ai.nl_query.intent import IntentClassifier, IntentMatch, QueryIntent


@pytest.fixture
def classifier() -> IntentClassifier:
    return IntentClassifier()


class TestQueryIntent:
    def test_enum_values(self):
        assert QueryIntent.SEARCH_INCIDENTS == "search_incidents"
        assert QueryIntent.LOOKUP_IOC == "lookup_ioc"
        assert QueryIntent.STATISTICS == "statistics"

    def test_all_intents_exist(self):
        assert len(QueryIntent) == 9


class TestIntentClassifier:
    def test_empty_query_returns_general(self, classifier: IntentClassifier):
        result = classifier.classify("")
        assert result.intent == QueryIntent.GENERAL_QUESTION
        assert result.confidence == 0.0

    def test_whitespace_query_returns_general(self, classifier: IntentClassifier):
        result = classifier.classify("   ")
        assert result.intent == QueryIntent.GENERAL_QUESTION
        assert result.confidence == 0.0

    def test_search_incidents_by_keyword(self, classifier: IntentClassifier):
        result = classifier.classify("show me all recent incidents")
        assert result.intent == QueryIntent.SEARCH_INCIDENTS
        assert result.confidence > 0.0
        assert len(result.matched_keywords) > 0

    def test_search_logs_by_keyword(self, classifier: IntentClassifier):
        result = classifier.classify("search the authentication logs for failures")
        assert result.intent == QueryIntent.SEARCH_LOGS
        assert result.confidence > 0.0

    def test_lookup_ioc_by_ip_pattern(self, classifier: IntentClassifier):
        result = classifier.classify("check 192.168.1.100")
        assert result.intent == QueryIntent.LOOKUP_IOC
        assert "ip_address" in result.matched_patterns

    def test_lookup_ioc_by_hash_pattern(self, classifier: IntentClassifier):
        result = classifier.classify(
            "lookup a]b" * 2 + "abcdef1234567890abcdef1234567890"  # 32 hex chars
        )
        # The hash pattern should match
        result2 = classifier.classify("abcdef1234567890abcdef1234567890")
        assert result2.intent == QueryIntent.LOOKUP_IOC

    def test_explain_incident(self, classifier: IntentClassifier):
        result = classifier.classify("explain what happened in incident INC-1234")
        assert result.intent == QueryIntent.EXPLAIN_INCIDENT
        assert result.confidence > 0.0

    def test_compare_incidents(self, classifier: IntentClassifier):
        result = classifier.classify("compare incident INC-100 and INC-200")
        assert result.intent == QueryIntent.COMPARE_INCIDENTS

    def test_timeline_by_relative_time(self, classifier: IntentClassifier):
        result = classifier.classify("show me the timeline for the last 24 hours")
        assert result.intent == QueryIntent.TIMELINE_QUERY
        assert result.confidence > 0.0

    def test_asset_lookup(self, classifier: IntentClassifier):
        result = classifier.classify("what is host WORKSTATION-42")
        assert result.intent == QueryIntent.ASSET_LOOKUP

    def test_statistics_query(self, classifier: IntentClassifier):
        result = classifier.classify("how many incidents were critical last week")
        assert result.intent == QueryIntent.STATISTICS

    def test_statistics_top_query(self, classifier: IntentClassifier):
        result = classifier.classify("top 10 most common alert types")
        assert result.intent == QueryIntent.STATISTICS
        assert "top_n" in result.matched_patterns

    def test_general_question_fallback(self, classifier: IntentClassifier):
        result = classifier.classify("what is the meaning of life")
        assert result.intent == QueryIntent.GENERAL_QUESTION

    def test_custom_keywords(self):
        custom = {
            QueryIntent.SEARCH_INCIDENTS: ["vuln", "vulnerability"],
        }
        classifier = IntentClassifier(custom_keywords=custom)
        result = classifier.classify("find vulnerability reports")
        assert result.intent == QueryIntent.SEARCH_INCIDENTS

    def test_pattern_boost_confidence(self, classifier: IntentClassifier):
        # A query with both keyword and pattern match should have higher confidence
        result = classifier.classify("lookup IOC 192.168.1.1")
        assert result.confidence >= 0.6

    def test_intent_match_model(self):
        match = IntentMatch(
            intent=QueryIntent.SEARCH_INCIDENTS,
            confidence=0.8,
            matched_keywords=["incident"],
            matched_patterns=["incident_id_explain"],
        )
        assert match.intent == QueryIntent.SEARCH_INCIDENTS
        assert match.confidence == 0.8
