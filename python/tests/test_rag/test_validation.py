"""Tests for RAG query validation and injection prevention.

These tests verify that the validation layer properly blocks
query injection attacks against ChromaDB.
"""

from __future__ import annotations

import pytest

from tw_ai.rag.validation import (
    ALLOWED_CHROMADB_OPERATORS,
    DEFAULT_COLLECTION_SCHEMAS,
    MAX_FILTER_CONDITIONS,
    MAX_FILTER_DEPTH,
    MAX_LIST_ITEMS,
    MAX_QUERY_LENGTH,
    CollectionNotAllowedError,
    CollectionSchema,
    FilterTooComplexError,
    InvalidFilterKeyError,
    InvalidFilterOperatorError,
    InvalidFilterValueError,
    QueryTooLongError,
    QueryTooShortError,
    RAGQueryValidator,
    RAGValidationError,
    validate_rag_query,
)


class TestCollectionValidation:
    """Tests for collection name whitelist validation."""

    def test_valid_collection_allowed(self):
        """Test that valid collection names are accepted."""
        validator = RAGQueryValidator()

        for collection in DEFAULT_COLLECTION_SCHEMAS:
            result = validator.validate_collection(collection)
            assert result == collection

    def test_invalid_collection_rejected(self):
        """Test that unknown collections are rejected."""
        validator = RAGQueryValidator()

        with pytest.raises(CollectionNotAllowedError) as exc_info:
            validator.validate_collection("malicious_collection")

        assert "not allowed" in str(exc_info.value)
        assert exc_info.value.field == "collection"

    def test_collection_injection_path_traversal(self):
        """Test that path traversal in collection name is blocked."""
        validator = RAGQueryValidator()

        injection_patterns = [
            "../../../etc/passwd",
            "..\\..\\windows\\system32",
            "triage_incidents/../secrets",
            "triage_incidents%2F..%2Fsecrets",
        ]

        for pattern in injection_patterns:
            with pytest.raises(CollectionNotAllowedError):
                validator.validate_collection(pattern)

    def test_collection_injection_null_bytes(self):
        """Test that null byte injection is blocked."""
        validator = RAGQueryValidator()

        with pytest.raises(CollectionNotAllowedError):
            validator.validate_collection("triage_incidents\x00.evil")

    def test_collection_empty_string(self):
        """Test that empty collection name is rejected."""
        validator = RAGQueryValidator()

        with pytest.raises(CollectionNotAllowedError):
            validator.validate_collection("")

    def test_collection_whitespace_only(self):
        """Test that whitespace-only collection name is rejected."""
        validator = RAGQueryValidator()

        with pytest.raises(CollectionNotAllowedError):
            validator.validate_collection("   ")

    def test_custom_collection_schema(self):
        """Test adding custom collection schema."""
        validator = RAGQueryValidator()

        custom_schema = CollectionSchema(
            name="custom_collection",
            allowed_filter_keys=frozenset({"field1", "field2"}),
            key_types={"field1": str, "field2": int},
        )
        validator.add_collection_schema(custom_schema)

        # Should now be allowed
        result = validator.validate_collection("custom_collection")
        assert result == "custom_collection"


class TestQueryValidation:
    """Tests for query string validation."""

    def test_valid_query_accepted(self):
        """Test that valid queries are accepted."""
        validator = RAGQueryValidator()

        valid_queries = [
            "simple query",
            "What is the MITRE ATT&CK technique for phishing?",
            "Search for APT29 C2 infrastructure",
            "a",  # Single character is valid
        ]

        for query in valid_queries:
            result = validator.validate_query(query)
            assert result == query.strip()

    def test_query_too_long_rejected(self):
        """Test that overly long queries are rejected."""
        validator = RAGQueryValidator()

        long_query = "a" * (MAX_QUERY_LENGTH + 1)

        with pytest.raises(QueryTooLongError) as exc_info:
            validator.validate_query(long_query)

        assert "exceeds maximum" in str(exc_info.value)
        assert exc_info.value.field == "query"

    def test_query_empty_rejected(self):
        """Test that empty queries are rejected."""
        validator = RAGQueryValidator()

        with pytest.raises(QueryTooShortError):
            validator.validate_query("")

    def test_query_whitespace_only_rejected(self):
        """Test that whitespace-only queries are rejected."""
        validator = RAGQueryValidator()

        with pytest.raises(QueryTooShortError):
            validator.validate_query("   \t\n  ")

    def test_query_whitespace_trimmed(self):
        """Test that leading/trailing whitespace is trimmed."""
        validator = RAGQueryValidator()

        result = validator.validate_query("  phishing attack  ")
        assert result == "phishing attack"

    def test_custom_max_length(self):
        """Test custom max query length."""
        validator = RAGQueryValidator(max_query_length=100)

        # Should accept 100 chars
        result = validator.validate_query("a" * 100)
        assert len(result) == 100

        # Should reject 101 chars
        with pytest.raises(QueryTooLongError):
            validator.validate_query("a" * 101)


class TestTopKValidation:
    """Tests for top_k parameter validation."""

    def test_valid_top_k_accepted(self):
        """Test that valid top_k values are accepted."""
        validator = RAGQueryValidator()

        assert validator.validate_top_k(1) == 1
        assert validator.validate_top_k(10) == 10
        assert validator.validate_top_k(100) == 100

    def test_top_k_none_returns_default(self):
        """Test that None returns default value."""
        validator = RAGQueryValidator()

        result = validator.validate_top_k(None)
        assert result == 5

    def test_top_k_zero_rejected(self):
        """Test that zero top_k is rejected."""
        validator = RAGQueryValidator()

        with pytest.raises(ValueError):
            validator.validate_top_k(0)

    def test_top_k_negative_rejected(self):
        """Test that negative top_k is rejected."""
        validator = RAGQueryValidator()

        with pytest.raises(ValueError):
            validator.validate_top_k(-1)

    def test_top_k_over_max_clamped(self):
        """Test that top_k over max is clamped."""
        validator = RAGQueryValidator(max_top_k=50)

        result = validator.validate_top_k(1000)
        assert result == 50


class TestFilterValidation:
    """Tests for metadata filter validation."""

    def test_valid_filters_accepted(self):
        """Test that valid filters are accepted."""
        validator = RAGQueryValidator()

        filters = {"verdict": "true_positive", "severity": "high"}
        result = validator.validate_filters(filters, "triage_incidents")

        assert result == filters

    def test_none_filters_accepted(self):
        """Test that None filters return None."""
        validator = RAGQueryValidator()

        result = validator.validate_filters(None, "triage_incidents")
        assert result is None

    def test_empty_filters_return_none(self):
        """Test that empty filters return None."""
        validator = RAGQueryValidator()

        result = validator.validate_filters({}, "triage_incidents")
        assert result is None

    def test_invalid_filter_key_rejected(self):
        """Test that filter keys not in schema are rejected."""
        validator = RAGQueryValidator()

        filters = {"invalid_key": "value"}

        with pytest.raises(InvalidFilterKeyError) as exc_info:
            validator.validate_filters(filters, "triage_incidents")

        assert "invalid_key" in str(exc_info.value)
        assert "not allowed" in str(exc_info.value)

    def test_filter_key_injection_rejected(self):
        """Test that injection attempts via filter keys are blocked."""
        validator = RAGQueryValidator()

        injection_keys = [
            "$where",  # NoSQL injection
            "__proto__",  # Prototype pollution
            "constructor",
            "verdict; DROP TABLE",  # SQL injection
            "verdict\x00evil",  # Null byte
        ]

        for key in injection_keys:
            filters = {key: "value"}
            with pytest.raises((InvalidFilterKeyError, InvalidFilterOperatorError)):
                validator.validate_filters(filters, "triage_incidents")

    def test_valid_operators_accepted(self):
        """Test that valid ChromaDB operators are accepted."""
        validator = RAGQueryValidator()

        for operator in ["$eq", "$ne", "$gt", "$gte", "$lt", "$lte"]:
            filters = {"confidence": {operator: 50}}
            result = validator.validate_filters(filters, "triage_incidents")
            assert operator in result["confidence"]

    def test_invalid_operator_rejected(self):
        """Test that invalid operators are rejected."""
        validator = RAGQueryValidator()

        invalid_operators = [
            "$regex",  # NoSQL injection
            "$where",
            "$eval",
            "$function",
            "$expr",
            "$jsonSchema",
        ]

        for operator in invalid_operators:
            filters = {"verdict": {operator: "value"}}
            with pytest.raises(InvalidFilterOperatorError) as exc_info:
                validator.validate_filters(filters, "triage_incidents")

            assert operator in str(exc_info.value)

    def test_in_operator_list_validation(self):
        """Test that $in operator validates list values."""
        validator = RAGQueryValidator()

        # Valid list
        filters = {"verdict": {"$in": ["true_positive", "false_positive"]}}
        result = validator.validate_filters(filters, "triage_incidents")
        assert result == filters

        # Invalid: not a list
        filters = {"verdict": {"$in": "true_positive"}}
        with pytest.raises(InvalidFilterValueError):
            validator.validate_filters(filters, "triage_incidents")

    def test_in_operator_list_size_limit(self):
        """Test that $in operator enforces list size limit."""
        validator = RAGQueryValidator()

        # Too many items
        filters = {"verdict": {"$in": ["value"] * (MAX_LIST_ITEMS + 1)}}
        with pytest.raises(FilterTooComplexError):
            validator.validate_filters(filters, "triage_incidents")

    def test_logical_operators_accepted(self):
        """Test that logical operators ($and, $or) are accepted."""
        validator = RAGQueryValidator()

        filters = {
            "$and": [
                {"verdict": "true_positive"},
                {"severity": "high"},
            ]
        }
        result = validator.validate_filters(filters, "triage_incidents")
        assert result == filters

        filters = {
            "$or": [
                {"severity": "critical"},
                {"severity": "high"},
            ]
        }
        result = validator.validate_filters(filters, "triage_incidents")
        assert result == filters

    def test_filter_nesting_depth_limit(self):
        """Test that deeply nested filters are rejected."""
        validator = RAGQueryValidator()

        # Build deeply nested filter
        filters: dict = {"verdict": "true_positive"}
        for _ in range(MAX_FILTER_DEPTH + 1):
            filters = {"$and": [filters, {"severity": "high"}]}

        with pytest.raises(FilterTooComplexError) as exc_info:
            validator.validate_filters(filters, "triage_incidents")

        assert "too deep" in str(exc_info.value)

    def test_filter_condition_count_limit(self):
        """Test that too many conditions are rejected."""
        validator = RAGQueryValidator()

        # Build filter with many conditions
        conditions = [{"verdict": "true_positive"} for _ in range(MAX_FILTER_CONDITIONS + 1)]
        filters = {"$or": conditions}

        with pytest.raises(FilterTooComplexError) as exc_info:
            validator.validate_filters(filters, "triage_incidents")

        assert "too many conditions" in str(exc_info.value)

    def test_filter_value_type_validation(self):
        """Test that filter values are type-checked."""
        validator = RAGQueryValidator()

        # confidence should be int/float
        filters = {"confidence": "not_a_number"}
        with pytest.raises(InvalidFilterValueError):
            validator.validate_filters(filters, "triage_incidents")

        # is_subtechnique should be bool
        filters = {"is_subtechnique": "yes"}
        with pytest.raises(InvalidFilterValueError):
            validator.validate_filters(filters, "mitre_attack")

    def test_filter_string_sanitization(self):
        """Test that string values are sanitized."""
        validator = RAGQueryValidator()

        # Null bytes should be removed
        filters = {"verdict": "true_positive\x00evil"}
        result = validator.validate_filters(filters, "triage_incidents")
        assert "\x00" not in result["verdict"]

        # Control characters should be removed
        filters = {"verdict": "true_positive\x1f\x7f"}
        result = validator.validate_filters(filters, "triage_incidents")
        assert "\x1f" not in result["verdict"]
        assert "\x7f" not in result["verdict"]


class TestInjectionPatterns:
    """Tests for specific injection attack patterns."""

    def test_nosql_injection_operators(self):
        """Test that NoSQL injection operators are blocked."""
        validator = RAGQueryValidator()

        nosql_injections = [
            {"verdict": {"$regex": ".*"}},
            {"verdict": {"$where": "this.verdict == 'true_positive'"}},
            {"verdict": {"$expr": {"$eq": ["$verdict", "true_positive"]}}},
            {"$where": "function() { return true; }"},
        ]

        for filters in nosql_injections:
            with pytest.raises((InvalidFilterOperatorError, InvalidFilterKeyError)):
                validator.validate_filters(filters, "triage_incidents")

    def test_operator_confusion_attack(self):
        """Test that operator confusion attacks are blocked."""
        validator = RAGQueryValidator()

        # Attempt to use field name that looks like operator
        with pytest.raises(InvalidFilterOperatorError):
            validator.validate_filters({"$custom_op": "value"}, "triage_incidents")

    def test_prototype_pollution_attack(self):
        """Test that prototype pollution via filter keys is blocked."""
        validator = RAGQueryValidator()

        pollution_keys = [
            "__proto__",
            "constructor",
            "prototype",
            "__defineGetter__",
            "__defineSetter__",
        ]

        for key in pollution_keys:
            with pytest.raises(InvalidFilterKeyError):
                validator.validate_filters({key: "value"}, "triage_incidents")

    def test_unicode_bypass_attempt(self):
        """Test that unicode bypass attempts in collection names are blocked."""
        validator = RAGQueryValidator()

        # Unicode variations of collection names
        unicode_bypasses = [
            "triage_incidents\ufeff",  # BOM
            "\u200btriage_incidents",  # Zero-width space
            "triage\u2010incidents",  # Unicode hyphen
        ]

        for bypass in unicode_bypasses:
            with pytest.raises(CollectionNotAllowedError):
                validator.validate_collection(bypass)

    def test_chromadb_special_chars_in_values(self):
        """Test handling of ChromaDB special characters in values."""
        validator = RAGQueryValidator()

        # These should be sanitized but accepted
        special_char_values = [
            "value with\nnewline",
            "value\twith\ttabs",
            "value with 'quotes'",
            'value with "double quotes"',
        ]

        for value in special_char_values:
            filters = {"verdict": value}
            # Should not raise - values are sanitized
            result = validator.validate_filters(filters, "triage_incidents")
            # Control chars removed, but regular chars preserved
            assert result is not None


class TestValidateSearchRequest:
    """Tests for complete search request validation."""

    def test_valid_request_passes(self):
        """Test that a valid request passes all validation."""
        query, collection, top_k, filters = validate_rag_query(
            query="phishing attack",
            collection="triage_incidents",
            top_k=10,
            filters={"verdict": "true_positive"},
        )

        assert query == "phishing attack"
        assert collection == "triage_incidents"
        assert top_k == 10
        assert filters == {"verdict": "true_positive"}

    def test_invalid_collection_fails_fast(self):
        """Test that invalid collection fails before other validation."""
        with pytest.raises(CollectionNotAllowedError):
            validate_rag_query(
                query="phishing",
                collection="invalid_collection",
                top_k=10,
            )

    def test_invalid_query_fails(self):
        """Test that invalid query fails validation."""
        with pytest.raises(QueryTooShortError):
            validate_rag_query(
                query="",
                collection="triage_incidents",
            )

    def test_complex_injection_attempt(self):
        """Test a complex multi-vector injection attempt."""
        # Attacker tries multiple injection vectors at once
        with pytest.raises(RAGValidationError):
            validate_rag_query(
                query="a" * (MAX_QUERY_LENGTH + 1),  # DoS via long query
                collection="../secrets",  # Path traversal
                filters={
                    "$where": "malicious",  # NoSQL injection
                    "__proto__": {"polluted": True},  # Prototype pollution
                },
            )


class TestRetrievalServiceValidation:
    """Tests for validation integrated into RetrievalService."""

    def test_search_validates_inputs(self, retrieval_service):
        """Test that search method validates all inputs."""
        # Invalid collection should be rejected
        with pytest.raises(CollectionNotAllowedError):
            retrieval_service.search(
                query="test",
                collection="invalid_collection",
            )

    def test_search_validates_query_length(self, retrieval_service):
        """Test that search validates query length."""
        long_query = "a" * (MAX_QUERY_LENGTH + 1)

        with pytest.raises(QueryTooLongError):
            retrieval_service.search(
                query=long_query,
                collection="triage_incidents",
            )

    def test_search_validates_filters(self, retrieval_service):
        """Test that search validates filter keys."""
        with pytest.raises(InvalidFilterKeyError):
            retrieval_service.search(
                query="test",
                collection="triage_incidents",
                filters={"invalid_key": "value"},
            )

    def test_search_blocks_operator_injection(self, retrieval_service):
        """Test that search blocks operator injection in filters."""
        with pytest.raises(InvalidFilterOperatorError):
            retrieval_service.search(
                query="test",
                collection="triage_incidents",
                filters={"verdict": {"$regex": ".*"}},
            )

    def test_specialized_methods_use_validation(self, retrieval_service):
        """Test that specialized search methods also use validation."""
        # search_similar_incidents should validate
        with pytest.raises(QueryTooShortError):
            retrieval_service.search_similar_incidents(query="")

        # search_playbooks should validate
        with pytest.raises(QueryTooShortError):
            retrieval_service.search_playbooks(query="")

        # search_mitre_techniques should validate
        with pytest.raises(QueryTooShortError):
            retrieval_service.search_mitre_techniques(query="")

        # search_threat_intel should validate
        with pytest.raises(QueryTooShortError):
            retrieval_service.search_threat_intel(query="")
