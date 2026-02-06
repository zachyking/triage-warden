"""Query backend adapters for translating structured queries to backend-specific syntax."""

from tw_ai.nl_query.backends.base import QueryBackend, QueryResult
from tw_ai.nl_query.backends.elastic import ElasticBackend
from tw_ai.nl_query.backends.splunk import SplunkBackend
from tw_ai.nl_query.backends.sql import SQLBackend

__all__ = [
    "QueryBackend",
    "QueryResult",
    "SplunkBackend",
    "ElasticBackend",
    "SQLBackend",
]
