"""Validation utilities for RAG query security.

Provides input validation and sanitization to prevent query injection attacks
against ChromaDB and other vector store backends.
"""

from __future__ import annotations

import re
from typing import Any

import structlog
from pydantic import BaseModel, ConfigDict, Field

logger = structlog.get_logger()

# =============================================================================
# Constants and Configuration
# =============================================================================

# Maximum query length to prevent DoS via massive queries
MAX_QUERY_LENGTH = 10_000

# Minimum query length for meaningful search
MIN_QUERY_LENGTH = 1

# Maximum number of results that can be requested
MAX_TOP_K = 100

# Maximum filter depth to prevent deeply nested filter attacks
MAX_FILTER_DEPTH = 3

# Maximum number of filter conditions
MAX_FILTER_CONDITIONS = 20

# Allowed ChromaDB operators for metadata filtering
ALLOWED_CHROMADB_OPERATORS = frozenset(
    {
        "$eq",
        "$ne",
        "$gt",
        "$gte",
        "$lt",
        "$lte",
        "$in",
        "$nin",
        "$and",
        "$or",
        "$contains",
    }
)

# Operators that require special validation (list values)
LIST_VALUE_OPERATORS = frozenset({"$in", "$nin"})

# Logical operators that combine conditions
LOGICAL_OPERATORS = frozenset({"$and", "$or"})

# Maximum items in $in/$nin lists
MAX_LIST_ITEMS = 50


# =============================================================================
# Collection Whitelist Schema
# =============================================================================


class CollectionSchema(BaseModel):
    """Schema defining allowed metadata fields for a collection."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(description="Collection name")
    allowed_filter_keys: frozenset[str] = Field(description="Allowed metadata filter keys")
    key_types: dict[str, type | tuple[type, ...]] = Field(
        default_factory=dict,
        description="Expected types for filter keys",
    )


# Default schemas for known collections
# These define what metadata fields can be filtered on
DEFAULT_COLLECTION_SCHEMAS: dict[str, CollectionSchema] = {
    "triage_incidents": CollectionSchema(
        name="triage_incidents",
        allowed_filter_keys=frozenset(
            {
                "verdict",
                "severity",
                "confidence",
                "alert_type",
                "alert_id",
                "technique_ids",
                "indicator_count",
                "created_at",
            }
        ),
        key_types={
            "verdict": str,
            "severity": str,
            "confidence": (int, float),
            "alert_type": str,
            "alert_id": str,
            "technique_ids": str,
            "indicator_count": (int, float),
            "created_at": str,
        },
    ),
    "security_playbooks": CollectionSchema(
        name="security_playbooks",
        allowed_filter_keys=frozenset(
            {
                "name",
                "version",
                "trigger_types",
                "stage_count",
                "has_branches",
                "created_at",
            }
        ),
        key_types={
            "name": str,
            "version": str,
            "trigger_types": str,
            "stage_count": (int, float),
            "has_branches": bool,
            "created_at": str,
        },
    ),
    "mitre_attack": CollectionSchema(
        name="mitre_attack",
        allowed_filter_keys=frozenset(
            {
                "technique_id",
                "name",
                "tactic",
                "is_subtechnique",
                "parent_technique_id",
                "keywords",
                "created_at",
            }
        ),
        key_types={
            "technique_id": str,
            "name": str,
            "tactic": str,
            "is_subtechnique": bool,
            "parent_technique_id": str,
            "keywords": str,
            "created_at": str,
        },
    ),
    "threat_intelligence": CollectionSchema(
        name="threat_intelligence",
        allowed_filter_keys=frozenset(
            {
                "indicator",
                "indicator_type",
                "verdict",
                "threat_actor",
                "confidence",
                "created_at",
            }
        ),
        key_types={
            "indicator": str,
            "indicator_type": str,
            "verdict": str,
            "threat_actor": str,
            "confidence": (int, float),
            "created_at": str,
        },
    ),
}


# =============================================================================
# Validation Errors
# =============================================================================


class RAGValidationError(ValueError):
    """Base exception for RAG validation errors."""

    def __init__(self, message: str, field: str | None = None) -> None:
        self.field = field
        super().__init__(message)


class CollectionNotAllowedError(RAGValidationError):
    """Raised when collection name is not in whitelist."""

    pass


class QueryTooLongError(RAGValidationError):
    """Raised when query exceeds maximum length."""

    pass


class QueryTooShortError(RAGValidationError):
    """Raised when query is too short."""

    pass


class InvalidFilterKeyError(RAGValidationError):
    """Raised when filter key is not in allowed schema."""

    pass


class InvalidFilterValueError(RAGValidationError):
    """Raised when filter value has wrong type."""

    pass


class InvalidFilterOperatorError(RAGValidationError):
    """Raised when filter contains invalid ChromaDB operator."""

    pass


class FilterTooComplexError(RAGValidationError):
    """Raised when filter exceeds complexity limits."""

    pass


# =============================================================================
# Validator Classes
# =============================================================================


class RAGQueryValidator:
    """Validates and sanitizes RAG queries for security.

    Provides defense-in-depth against query injection attacks:
    1. Collection name whitelist validation
    2. Query length limits
    3. Metadata filter key validation against schema
    4. Filter value type checking
    5. ChromaDB operator sanitization
    """

    def __init__(
        self,
        collection_schemas: dict[str, CollectionSchema] | None = None,
        max_query_length: int = MAX_QUERY_LENGTH,
        max_top_k: int = MAX_TOP_K,
    ) -> None:
        """Initialize validator.

        Args:
            collection_schemas: Mapping of collection names to their schemas.
                               If None, uses DEFAULT_COLLECTION_SCHEMAS.
            max_query_length: Maximum allowed query string length.
            max_top_k: Maximum number of results allowed.
        """
        self._collection_schemas = collection_schemas or DEFAULT_COLLECTION_SCHEMAS
        self._max_query_length = max_query_length
        self._max_top_k = max_top_k
        # Pre-compute allowed collection names for O(1) lookup
        self._allowed_collections = frozenset(self._collection_schemas.keys())

    @property
    def allowed_collections(self) -> frozenset[str]:
        """Get the set of allowed collection names."""
        return self._allowed_collections

    def add_collection_schema(self, schema: CollectionSchema) -> None:
        """Add or update a collection schema.

        Args:
            schema: The collection schema to add.
        """
        self._collection_schemas[schema.name] = schema
        self._allowed_collections = frozenset(self._collection_schemas.keys())

    def validate_collection(self, collection: str) -> str:
        """Validate collection name against whitelist.

        Args:
            collection: Collection name to validate.

        Returns:
            The validated collection name.

        Raises:
            CollectionNotAllowedError: If collection is not in whitelist.
        """
        if not collection or not isinstance(collection, str):
            raise CollectionNotAllowedError(
                "Collection name must be a non-empty string",
                field="collection",
            )

        # Normalize: strip whitespace, lowercase for comparison
        normalized = collection.strip()

        if normalized not in self._allowed_collections:
            logger.warning(
                "collection_not_allowed",
                collection=collection,
                allowed=list(self._allowed_collections),
            )
            raise CollectionNotAllowedError(
                f"Collection '{collection}' is not allowed. "
                f"Allowed collections: {sorted(self._allowed_collections)}",
                field="collection",
            )

        return normalized

    def validate_query(self, query: str) -> str:
        """Validate and sanitize query string.

        Args:
            query: Query text to validate.

        Returns:
            The validated query string.

        Raises:
            QueryTooLongError: If query exceeds maximum length.
            QueryTooShortError: If query is empty or too short.
        """
        if not isinstance(query, str):
            raise QueryTooShortError(
                "Query must be a string",
                field="query",
            )

        # Strip leading/trailing whitespace
        query = query.strip()

        if len(query) < MIN_QUERY_LENGTH:
            raise QueryTooShortError(
                f"Query must be at least {MIN_QUERY_LENGTH} character(s)",
                field="query",
            )

        if len(query) > self._max_query_length:
            logger.warning(
                "query_too_long",
                query_length=len(query),
                max_length=self._max_query_length,
            )
            raise QueryTooLongError(
                f"Query length ({len(query)}) exceeds maximum ({self._max_query_length})",
                field="query",
            )

        return query

    def validate_top_k(self, top_k: int | None) -> int:
        """Validate top_k parameter.

        Args:
            top_k: Number of results requested.

        Returns:
            Validated top_k value.

        Raises:
            ValueError: If top_k is invalid.
        """
        if top_k is None:
            return 5  # Default

        if not isinstance(top_k, int):
            raise ValueError("top_k must be an integer", "top_k")

        if top_k < 1:
            raise ValueError("top_k must be at least 1", "top_k")

        if top_k > self._max_top_k:
            logger.warning(
                "top_k_clamped",
                requested=top_k,
                max_allowed=self._max_top_k,
            )
            return self._max_top_k

        return top_k

    def validate_filters(
        self,
        filters: dict[str, Any] | None,
        collection: str,
    ) -> dict[str, Any] | None:
        """Validate and sanitize metadata filters.

        Args:
            filters: ChromaDB filter dict.
            collection: Collection name for schema lookup.

        Returns:
            Validated filters or None.

        Raises:
            InvalidFilterKeyError: If filter key is not allowed.
            InvalidFilterValueError: If filter value has wrong type.
            InvalidFilterOperatorError: If operator is not allowed.
            FilterTooComplexError: If filter exceeds complexity limits.
        """
        if filters is None:
            return None

        if not isinstance(filters, dict):
            raise InvalidFilterValueError(
                "Filters must be a dictionary",
                field="filters",
            )

        if not filters:
            return None

        schema = self._collection_schemas.get(collection)
        if schema is None:
            # Collection already validated; this shouldn't happen
            raise CollectionNotAllowedError(
                f"No schema found for collection '{collection}'",
                field="collection",
            )

        # Count total conditions to prevent DoS
        condition_count = self._count_conditions(filters)
        if condition_count > MAX_FILTER_CONDITIONS:
            raise FilterTooComplexError(
                f"Filter has too many conditions ({condition_count} > {MAX_FILTER_CONDITIONS})",
                field="filters",
            )

        # Recursively validate
        return self._validate_filter_dict(filters, schema, depth=0)

    def _count_conditions(self, filters: dict[str, Any], count: int = 0) -> int:
        """Count total number of conditions in filter tree."""
        for key, value in filters.items():
            if key in LOGICAL_OPERATORS:
                if isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            count = self._count_conditions(item, count)
            else:
                count += 1
        return count

    def _validate_filter_dict(
        self,
        filters: dict[str, Any],
        schema: CollectionSchema,
        depth: int,
    ) -> dict[str, Any]:
        """Recursively validate filter dictionary.

        Args:
            filters: Filter dict to validate.
            schema: Collection schema for key/type validation.
            depth: Current nesting depth.

        Returns:
            Validated filter dict.
        """
        if depth > MAX_FILTER_DEPTH:
            raise FilterTooComplexError(
                f"Filter nesting too deep (max {MAX_FILTER_DEPTH} levels)",
                field="filters",
            )

        validated = {}

        for key, value in filters.items():
            # Check if this is a logical operator
            if key in LOGICAL_OPERATORS:
                validated[key] = self._validate_logical_operator(key, value, schema, depth)
            elif key.startswith("$"):
                # Unknown operator
                allowed = sorted(ALLOWED_CHROMADB_OPERATORS)
                raise InvalidFilterOperatorError(
                    f"Unknown operator '{key}'. Allowed operators: {allowed}",
                    field="filters",
                )
            else:
                # Regular field filter
                validated[key] = self._validate_field_filter(key, value, schema)

        return validated

    def _validate_logical_operator(
        self,
        operator: str,
        value: Any,
        schema: CollectionSchema,
        depth: int,
    ) -> list[dict[str, Any]]:
        """Validate logical operator ($and, $or).

        Args:
            operator: The operator name.
            value: The operator value (should be list of dicts).
            schema: Collection schema.
            depth: Current nesting depth.

        Returns:
            Validated list of conditions.
        """
        if not isinstance(value, list):
            raise InvalidFilterValueError(
                f"Operator '{operator}' requires a list of conditions",
                field="filters",
            )

        validated = []
        for i, condition in enumerate(value):
            if not isinstance(condition, dict):
                raise InvalidFilterValueError(
                    f"Condition {i} in '{operator}' must be a dictionary",
                    field="filters",
                )
            validated.append(self._validate_filter_dict(condition, schema, depth + 1))

        return validated

    def _validate_field_filter(
        self,
        key: str,
        value: Any,
        schema: CollectionSchema,
    ) -> Any:
        """Validate a field filter.

        Args:
            key: Field name.
            value: Filter value (could be direct value or operator dict).
            schema: Collection schema.

        Returns:
            Validated filter value.
        """
        # Validate key is allowed
        if key not in schema.allowed_filter_keys:
            logger.warning(
                "invalid_filter_key",
                key=key,
                collection=schema.name,
                allowed=list(schema.allowed_filter_keys),
            )
            raise InvalidFilterKeyError(
                f"Filter key '{key}' is not allowed for collection '{schema.name}'. "
                f"Allowed keys: {sorted(schema.allowed_filter_keys)}",
                field="filters",
            )

        # Handle operator-based filters like {"$gt": 5}
        if isinstance(value, dict):
            return self._validate_operator_filter(key, value, schema)

        # Direct value filter (implicit $eq)
        return self._validate_filter_value(key, value, schema)

    def _validate_operator_filter(
        self,
        key: str,
        value: dict[str, Any],
        schema: CollectionSchema,
    ) -> dict[str, Any]:
        """Validate operator-based filter like {"$gt": 5}.

        Args:
            key: Field name.
            value: Operator dict.
            schema: Collection schema.

        Returns:
            Validated operator dict.
        """
        validated = {}

        for operator, op_value in value.items():
            if operator not in ALLOWED_CHROMADB_OPERATORS:
                raise InvalidFilterOperatorError(
                    f"Operator '{operator}' is not allowed. "
                    f"Allowed operators: {sorted(ALLOWED_CHROMADB_OPERATORS)}",
                    field="filters",
                )

            # Validate value based on operator type
            if operator in LIST_VALUE_OPERATORS:
                validated[operator] = self._validate_list_value(key, op_value, schema)
            elif operator in LOGICAL_OPERATORS:
                # Should not appear as field operator
                raise InvalidFilterOperatorError(
                    f"Operator '{operator}' cannot be used as field operator",
                    field="filters",
                )
            else:
                validated[operator] = self._validate_filter_value(key, op_value, schema)

        return validated

    def _validate_list_value(
        self,
        key: str,
        value: Any,
        schema: CollectionSchema,
    ) -> list[Any]:
        """Validate list value for $in/$nin operators.

        Args:
            key: Field name.
            value: List value.
            schema: Collection schema.

        Returns:
            Validated list.
        """
        if not isinstance(value, list):
            raise InvalidFilterValueError(
                f"Operator $in/$nin requires a list for field '{key}'",
                field="filters",
            )

        if len(value) > MAX_LIST_ITEMS:
            raise FilterTooComplexError(
                f"List for field '{key}' has too many items ({len(value)} > {MAX_LIST_ITEMS})",
                field="filters",
            )

        # Validate each item in the list
        return [self._validate_filter_value(key, item, schema) for item in value]

    def _validate_filter_value(
        self,
        key: str,
        value: Any,
        schema: CollectionSchema,
    ) -> Any:
        """Validate and sanitize a filter value.

        Args:
            key: Field name.
            value: Value to validate.
            schema: Collection schema.

        Returns:
            Validated value.
        """
        expected_type = schema.key_types.get(key)

        if expected_type is None:
            # No type constraint, allow any basic type
            if not isinstance(value, (str, int, float, bool)):
                raise InvalidFilterValueError(
                    f"Filter value for '{key}' must be a basic type (str, int, float, bool)",
                    field="filters",
                )
            return self._sanitize_value(value)

        if not isinstance(value, expected_type):
            raise InvalidFilterValueError(
                f"Filter value for '{key}' must be {expected_type}, got {type(value).__name__}",
                field="filters",
            )

        return self._sanitize_value(value)

    def _sanitize_value(self, value: Any) -> Any:
        """Sanitize a filter value.

        Removes or escapes potentially dangerous characters.

        Args:
            value: Value to sanitize.

        Returns:
            Sanitized value.
        """
        if isinstance(value, str):
            # Remove null bytes and control characters (except common whitespace)
            # These could potentially be used for injection
            sanitized = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", value)

            # Limit string length
            if len(sanitized) > 1000:
                sanitized = sanitized[:1000]

            return sanitized

        return value

    def validate_search_request(
        self,
        query: str,
        collection: str,
        top_k: int | None = None,
        filters: dict[str, Any] | None = None,
    ) -> tuple[str, str, int, dict[str, Any] | None]:
        """Validate a complete search request.

        This is the main entry point for validating RAG queries.

        Args:
            query: Query text.
            collection: Collection name.
            top_k: Number of results.
            filters: Metadata filters.

        Returns:
            Tuple of (validated_query, validated_collection, validated_top_k, validated_filters).

        Raises:
            RAGValidationError: If any validation fails.
        """
        validated_collection = self.validate_collection(collection)
        validated_query = self.validate_query(query)
        validated_top_k = self.validate_top_k(top_k)
        validated_filters = self.validate_filters(filters, validated_collection)

        logger.debug(
            "search_request_validated",
            collection=validated_collection,
            query_length=len(validated_query),
            top_k=validated_top_k,
            has_filters=validated_filters is not None,
        )

        return validated_query, validated_collection, validated_top_k, validated_filters


# =============================================================================
# Module-level validator instance
# =============================================================================

# Default validator instance for convenience
_default_validator: RAGQueryValidator | None = None


def get_default_validator() -> RAGQueryValidator:
    """Get or create the default validator instance."""
    global _default_validator
    if _default_validator is None:
        _default_validator = RAGQueryValidator()
    return _default_validator


def validate_rag_query(
    query: str,
    collection: str,
    top_k: int | None = None,
    filters: dict[str, Any] | None = None,
) -> tuple[str, str, int, dict[str, Any] | None]:
    """Convenience function to validate a RAG query using default validator.

    Args:
        query: Query text.
        collection: Collection name.
        top_k: Number of results.
        filters: Metadata filters.

    Returns:
        Tuple of validated parameters.
    """
    return get_default_validator().validate_search_request(query, collection, top_k, filters)
