"""FastAPI application for the triage service."""

from __future__ import annotations

import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import structlog
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

from tw_ai.triage_service.config import TriageServiceConfig, get_config
from tw_ai.triage_service.models import (
    EvidenceItemResponse,
    HealthResponse,
    IndicatorResponse,
    MITRETechniqueResponse,
    RecommendedActionResponse,
    StatusResponse,
    TriageErrorResponse,
    TriageServiceRequest,
    TriageServiceResponse,
)

logger = structlog.get_logger()

# Lazy-loaded agent components (expensive imports)
_agent = None
_tools = None
_llm = None


def _get_or_create_agent(config: TriageServiceConfig) -> Any:
    """Lazy-load and cache the ReAct agent and its dependencies."""
    global _agent, _tools, _llm

    if _agent is not None:
        return _agent

    from tw_ai.agents.react import ReActAgent
    from tw_ai.agents.tools import ToolRegistry

    _llm = config.create_llm_provider()
    _tools = ToolRegistry()
    _agent = ReActAgent(
        llm=_llm,
        tools=_tools,
        max_iterations=config.agent_max_iterations,
        max_tokens=config.agent_max_tokens,
        timeout_seconds=config.agent_timeout_seconds,
        enable_pii_redaction=True,
        enable_prompt_sanitization=True,
    )

    logger.info(
        "react_agent_created",
        provider=config.llm_provider,
        model=config.llm_model,
        max_iterations=config.agent_max_iterations,
    )
    return _agent


def _analysis_to_response(result: Any, execution_time: float) -> TriageServiceResponse:
    """Convert an AgentResult with TriageAnalysis to a TriageServiceResponse."""
    analysis = result.analysis

    indicators = [
        IndicatorResponse(
            type=ind.type,
            value=ind.value,
            verdict=ind.verdict,
            context=ind.context,
        )
        for ind in analysis.indicators
    ]

    techniques = [
        MITRETechniqueResponse(
            id=t.id,
            name=t.name,
            tactic=t.tactic,
            relevance=t.relevance,
        )
        for t in analysis.mitre_techniques
    ]

    actions = [
        RecommendedActionResponse(
            action=a.action,
            priority=a.priority,
            reason=a.reason,
            requires_approval=a.requires_approval,
        )
        for a in analysis.recommended_actions
    ]

    evidence = [
        EvidenceItemResponse(
            source_type=e.source_type,
            source_name=e.source_name,
            data_type=e.data_type,
            value=e.value,
            finding=e.finding,
            relevance=e.relevance,
            confidence=e.confidence,
        )
        for e in analysis.evidence
    ]

    return TriageServiceResponse(
        verdict=analysis.verdict,
        confidence=analysis.confidence / 100.0,  # model uses 0-100, API returns 0-1
        severity=analysis.severity,
        summary=analysis.summary,
        reasoning=analysis.reasoning,
        indicators=indicators,
        mitre_techniques=techniques,
        recommended_actions=actions,
        evidence=evidence,
        analyzed_by="react-agent",
        tokens_used=result.tokens_used,
        execution_time_seconds=execution_time,
    )


@asynccontextmanager
async def _lifespan_with_config(config: TriageServiceConfig) -> AsyncIterator[None]:
    logger.info(
        "triage_service_starting",
        provider=config.llm_provider,
        model=config.llm_model,
        llm_configured=config.is_llm_configured(),
    )
    yield
    logger.info("triage_service_shutting_down")


def create_app(config: TriageServiceConfig | None = None) -> FastAPI:
    """Create and configure the FastAPI application."""
    if config is None:
        config = get_config()

    @asynccontextmanager
    async def app_lifespan(_application: FastAPI) -> AsyncIterator[None]:
        async with _lifespan_with_config(config):
            yield

    application = FastAPI(
        title="Triage Warden AI Triage Service",
        description="HTTP wrapper around the ReAct security triage agent",
        version="0.1.1",
        lifespan=app_lifespan,
    )
    application.state.config = config

    @application.get("/health", response_model=HealthResponse)
    async def health() -> HealthResponse:
        return HealthResponse()

    @application.get("/api/triage/status", response_model=StatusResponse)
    async def status() -> StatusResponse:
        cfg: TriageServiceConfig = application.state.config
        return StatusResponse(
            ready=cfg.is_llm_configured(),
            llm_configured=cfg.is_llm_configured(),
            llm_provider=cfg.llm_provider,
            llm_model=cfg.llm_model,
        )

    @application.post("/api/triage", response_model=TriageServiceResponse)
    async def run_triage(request: TriageServiceRequest) -> Any:
        cfg: TriageServiceConfig = application.state.config

        if not cfg.is_llm_configured():
            raise HTTPException(
                status_code=503,
                detail="LLM provider not configured. Set TW_LLM_API_KEY or provider-specific key.",
            )

        start = time.time()

        try:
            agent = _get_or_create_agent(cfg)
        except Exception as exc:
            logger.error("agent_init_failed", error=str(exc))
            raise HTTPException(
                status_code=503,
                detail=f"Failed to initialize triage agent: {exc}",
            ) from exc

        # Build a TriageRequest dataclass from the HTTP request
        from tw_ai.agents.react import TriageRequest as AgentTriageRequest

        agent_request = AgentTriageRequest(
            alert_type=request.alert_type,
            alert_data=request.alert_data,
            context=request.context,
            priority=request.priority,
        )

        try:
            result = await agent.run(agent_request)
        except Exception as exc:
            execution_time = time.time() - start
            logger.error("triage_failed", error=str(exc), execution_time=execution_time)
            raise HTTPException(
                status_code=500,
                detail=f"Triage analysis failed: {exc}",
            ) from exc

        execution_time = time.time() - start

        if result.success and result.analysis:
            logger.info(
                "triage_complete",
                verdict=result.analysis.verdict,
                confidence=result.analysis.confidence,
                execution_time=execution_time,
                tokens_used=result.tokens_used,
            )
            return _analysis_to_response(result, execution_time)

        # Agent ran but did not produce a parseable analysis
        logger.warning(
            "triage_no_analysis",
            error=result.error,
            raw_output_len=len(result.raw_output or ""),
            execution_time=execution_time,
        )
        return JSONResponse(
            status_code=422,
            content=TriageErrorResponse(
                error="analysis_parse_failed",
                detail=result.error or "Agent did not produce a parseable analysis",
            ).model_dump(),
        )

    return application


# Module-level app instance for `uvicorn tw_ai.triage_service.app:app`
app = create_app()


if __name__ == "__main__":
    import uvicorn

    config = get_config()
    uvicorn.run(
        "tw_ai.triage_service.app:app",
        host=config.host,
        port=config.port,
        log_level="info",
    )
