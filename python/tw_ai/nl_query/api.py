"""FastAPI endpoints for NL query service."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from tw_ai.nl_query.backends.elastic import ElasticBackend
from tw_ai.nl_query.backends.splunk import SplunkBackend
from tw_ai.nl_query.backends.sql import SQLBackend
from tw_ai.nl_query.translator import NLQueryTranslator, QueryContext

router = APIRouter(prefix="/api/nl", tags=["nl-query"])

# Backend registry
_BACKENDS: dict[str, type] = {
    "splunk": SplunkBackend,
    "elasticsearch": ElasticBackend,
    "sql": SQLBackend,
}


class NLQueryRequest(BaseModel):
    """Request for NL query translation."""

    query: str = Field(description="Natural language query")
    backend: str = Field(
        default="splunk", description="Target backend (splunk, elasticsearch, sql)"
    )
    context: dict[str, Any] = Field(default_factory=dict, description="Query context")


class NLQueryApiResponse(BaseModel):
    """Response from NL query translation."""

    query_string: str
    query_type: str
    intent: str
    confidence: float
    entities: list[dict[str, Any]]
    metadata: dict[str, Any] = Field(default_factory=dict)


@router.post("/query", response_model=NLQueryApiResponse)  # type: ignore[untyped-decorator]
async def translate_query(request: NLQueryRequest) -> NLQueryApiResponse:
    """Translate a natural language query to a backend-specific query."""
    # Validate backend
    if request.backend not in _BACKENDS:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown backend: {request.backend}. Available: {list(_BACKENDS.keys())}",
        )

    # Build context
    ctx = QueryContext(
        current_incident_id=request.context.get("current_incident_id"),
        user_id=request.context.get("user_id"),
    )

    # Translate
    translator = NLQueryTranslator()
    translated = translator.translate(request.query, ctx)

    # Generate backend query
    backend = _BACKENDS[request.backend]()
    result = backend.generate(translated)

    # Build response
    entities = [
        {
            "type": e.entity_type.value if hasattr(e.entity_type, "value") else str(e.entity_type),
            "value": e.value,
            "start": e.start,
            "end": e.end,
        }
        for e in translated.entities
    ]

    return NLQueryApiResponse(
        query_string=result.query_string,
        query_type=result.query_type,
        intent=(
            translated.intent.intent.value
            if hasattr(translated.intent.intent, "value")
            else str(translated.intent.intent)
        ),
        confidence=translated.intent.confidence,
        entities=entities,
        metadata=result.metadata,
    )
