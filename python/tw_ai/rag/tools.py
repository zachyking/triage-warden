"""RAG tools for agent integration.

Provides tools for the ReAct agent to search the security knowledge base:
- search_similar_incidents: Find past cases with similar patterns
- search_playbooks: Find relevant runbooks for the scenario
- search_mitre_techniques: Map behaviors to MITRE ATT&CK
- search_threat_intel: Search threat intelligence context
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from tw_ai.agents.tools import Tool, ToolRegistry
    from tw_ai.rag.retrieval import RetrievalService

logger = structlog.get_logger()


def create_rag_tools(retrieval: RetrievalService) -> list[Tool]:
    """Create RAG tools for agent integration.

    Args:
        retrieval: RetrievalService instance for queries.

    Returns:
        List of Tool instances for RAG operations.
    """
    from tw_ai.agents.tools import Tool, ToolResult

    tools: list[Tool] = []

    # =========================================================================
    # Tool 1: Search Similar Incidents
    # =========================================================================

    async def search_similar_incidents(
        query: str,
        top_k: int = 5,
        verdict: str | None = None,
        severity: str | None = None,
        alert_type: str | None = None,
    ) -> ToolResult:
        """Search for similar historical incidents.

        Args:
            query: Description of the current incident.
            top_k: Number of results to return.
            verdict: Filter by verdict (true_positive, false_positive, etc.)
            severity: Filter by severity level.
            alert_type: Filter by alert type.

        Returns:
            ToolResult with matching incidents.
        """
        start_time = time.perf_counter()

        try:
            response = retrieval.search_similar_incidents(
                query=query,
                top_k=top_k,
                verdict=verdict,
                severity=severity,
                alert_type=alert_type,
            )

            execution_time_ms = int((time.perf_counter() - start_time) * 1000)

            # Format results for agent consumption
            incidents = []
            for result in response.results:
                incidents.append(
                    {
                        "id": result.id,
                        "similarity": round(result.similarity, 3),
                        "verdict": result.metadata.get("verdict", "unknown"),
                        "severity": result.metadata.get("severity", "unknown"),
                        "confidence": result.metadata.get("confidence", 0),
                        "alert_type": result.metadata.get("alert_type", "unknown"),
                        "summary": result.content[:500] if result.content else "",
                    }
                )

            return ToolResult.ok(
                data={
                    "query": query,
                    "total_results": response.total_results,
                    "incidents": incidents,
                },
                execution_time_ms=execution_time_ms,
            )
        except Exception as e:
            execution_time_ms = int((time.perf_counter() - start_time) * 1000)
            logger.error("search_similar_incidents_failed", error=str(e))
            return ToolResult.fail(
                error=f"Incident search failed: {str(e)}",
                execution_time_ms=execution_time_ms,
            )

    tools.append(
        Tool(
            name="search_similar_incidents",
            description=(
                "Search historical triage incidents for similar cases. "
                "Useful for finding past incidents with similar patterns, verdicts, "
                "or indicators to inform current analysis decisions."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Incident description or pattern to search for",
                    },
                    "top_k": {
                        "type": "integer",
                        "description": "Number of results to return (default: 5)",
                        "default": 5,
                    },
                    "verdict": {
                        "type": "string",
                        "enum": ["true_positive", "false_positive", "suspicious", "inconclusive"],
                        "description": "Filter by incident verdict",
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low", "informational"],
                        "description": "Filter by severity level",
                    },
                    "alert_type": {
                        "type": "string",
                        "description": "Filter by alert type (e.g., 'phishing', 'malware')",
                    },
                },
                "required": ["query"],
            },
            handler=search_similar_incidents,
        )
    )

    # =========================================================================
    # Tool 2: Search Playbooks
    # =========================================================================

    async def search_playbooks(
        query: str,
        top_k: int = 3,
        trigger_type: str | None = None,
    ) -> ToolResult:
        """Search for relevant security playbooks.

        Args:
            query: Description of the scenario.
            top_k: Number of results to return.
            trigger_type: Filter by trigger type.

        Returns:
            ToolResult with matching playbooks.
        """
        start_time = time.perf_counter()

        try:
            response = retrieval.search_playbooks(
                query=query,
                top_k=top_k,
                trigger_type=trigger_type,
            )

            execution_time_ms = int((time.perf_counter() - start_time) * 1000)

            playbooks = []
            for result in response.results:
                playbooks.append(
                    {
                        "id": result.id,
                        "name": result.metadata.get("name", "unknown"),
                        "similarity": round(result.similarity, 3),
                        "version": result.metadata.get("version", "1.0"),
                        "stage_count": result.metadata.get("stage_count", 0),
                        "has_branches": result.metadata.get("has_branches", False),
                        "description": result.content[:500] if result.content else "",
                    }
                )

            return ToolResult.ok(
                data={
                    "query": query,
                    "total_results": response.total_results,
                    "playbooks": playbooks,
                },
                execution_time_ms=execution_time_ms,
            )
        except Exception as e:
            execution_time_ms = int((time.perf_counter() - start_time) * 1000)
            logger.error("search_playbooks_failed", error=str(e))
            return ToolResult.fail(
                error=f"Playbook search failed: {str(e)}",
                execution_time_ms=execution_time_ms,
            )

    tools.append(
        Tool(
            name="search_playbooks",
            description=(
                "Search security playbooks and runbooks for relevant procedures. "
                "Find playbooks that match the current alert type or scenario "
                "to guide response actions."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Description of the scenario or alert type",
                    },
                    "top_k": {
                        "type": "integer",
                        "description": "Number of results to return (default: 3)",
                        "default": 3,
                    },
                    "trigger_type": {
                        "type": "string",
                        "description": "Filter by playbook trigger type",
                    },
                },
                "required": ["query"],
            },
            handler=search_playbooks,
        )
    )

    # =========================================================================
    # Tool 3: Search MITRE Techniques
    # =========================================================================

    async def search_mitre_techniques(
        query: str,
        top_k: int = 5,
        tactic: str | None = None,
        include_subtechniques: bool = True,
    ) -> ToolResult:
        """Search for MITRE ATT&CK techniques.

        Args:
            query: Description of observed behavior.
            top_k: Number of results to return.
            tactic: Filter by MITRE tactic.
            include_subtechniques: Whether to include sub-techniques.

        Returns:
            ToolResult with matching techniques.
        """
        start_time = time.perf_counter()

        try:
            response = retrieval.search_mitre_techniques(
                query=query,
                top_k=top_k,
                tactic=tactic,
                include_subtechniques=include_subtechniques,
            )

            execution_time_ms = int((time.perf_counter() - start_time) * 1000)

            techniques = []
            for result in response.results:
                techniques.append(
                    {
                        "technique_id": result.metadata.get("technique_id", ""),
                        "name": result.metadata.get("name", ""),
                        "tactic": result.metadata.get("tactic", ""),
                        "similarity": round(result.similarity, 3),
                        "is_subtechnique": result.metadata.get("is_subtechnique", False),
                        "keywords": (
                            result.metadata.get("keywords", "").split(",")
                            if result.metadata.get("keywords")
                            else []
                        ),
                    }
                )

            return ToolResult.ok(
                data={
                    "query": query,
                    "total_results": response.total_results,
                    "techniques": techniques,
                },
                execution_time_ms=execution_time_ms,
            )
        except Exception as e:
            execution_time_ms = int((time.perf_counter() - start_time) * 1000)
            logger.error("search_mitre_techniques_failed", error=str(e))
            return ToolResult.fail(
                error=f"MITRE search failed: {str(e)}",
                execution_time_ms=execution_time_ms,
            )

    tools.append(
        Tool(
            name="search_mitre_techniques",
            description=(
                "Search MITRE ATT&CK techniques by behavior description. "
                "Maps observed attacker behaviors to MITRE ATT&CK framework techniques "
                "for threat classification and reporting."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Description of observed attacker behavior",
                    },
                    "top_k": {
                        "type": "integer",
                        "description": "Number of results to return (default: 5)",
                        "default": 5,
                    },
                    "tactic": {
                        "type": "string",
                        "description": "Filter by MITRE tactic (e.g., 'Initial Access')",
                    },
                    "include_subtechniques": {
                        "type": "boolean",
                        "description": "Include sub-techniques in results (default: true)",
                        "default": True,
                    },
                },
                "required": ["query"],
            },
            handler=search_mitre_techniques,
        )
    )

    # =========================================================================
    # Tool 4: Search Threat Intel
    # =========================================================================

    async def search_threat_intel(
        query: str,
        top_k: int = 5,
        indicator_type: str | None = None,
        verdict: str | None = None,
        threat_actor: str | None = None,
    ) -> ToolResult:
        """Search threat intelligence database.

        Args:
            query: Description or indicator to search.
            top_k: Number of results to return.
            indicator_type: Filter by indicator type.
            verdict: Filter by verdict.
            threat_actor: Filter by threat actor.

        Returns:
            ToolResult with matching threat intel.
        """
        start_time = time.perf_counter()

        try:
            response = retrieval.search_threat_intel(
                query=query,
                top_k=top_k,
                indicator_type=indicator_type,
                verdict=verdict,
                threat_actor=threat_actor,
            )

            execution_time_ms = int((time.perf_counter() - start_time) * 1000)

            intel = []
            for result in response.results:
                intel.append(
                    {
                        "id": result.id,
                        "indicator": result.metadata.get("indicator", ""),
                        "indicator_type": result.metadata.get("indicator_type", ""),
                        "verdict": result.metadata.get("verdict", "unknown"),
                        "threat_actor": result.metadata.get("threat_actor", ""),
                        "confidence": result.metadata.get("confidence", 0),
                        "similarity": round(result.similarity, 3),
                        "context": result.content[:500] if result.content else "",
                    }
                )

            return ToolResult.ok(
                data={
                    "query": query,
                    "total_results": response.total_results,
                    "intel": intel,
                },
                execution_time_ms=execution_time_ms,
            )
        except Exception as e:
            execution_time_ms = int((time.perf_counter() - start_time) * 1000)
            logger.error("search_threat_intel_failed", error=str(e))
            return ToolResult.fail(
                error=f"Threat intel search failed: {str(e)}",
                execution_time_ms=execution_time_ms,
            )

    tools.append(
        Tool(
            name="search_threat_intel",
            description=(
                "Search threat intelligence for context on indicators. "
                "Find information about IPs, domains, hashes, or threat actors "
                "from the threat intelligence knowledge base."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Indicator or description to search for",
                    },
                    "top_k": {
                        "type": "integer",
                        "description": "Number of results to return (default: 5)",
                        "default": 5,
                    },
                    "indicator_type": {
                        "type": "string",
                        "enum": ["ip", "domain", "url", "hash", "email", "other"],
                        "description": "Filter by indicator type",
                    },
                    "verdict": {
                        "type": "string",
                        "enum": ["malicious", "suspicious", "benign", "unknown"],
                        "description": "Filter by verdict",
                    },
                    "threat_actor": {
                        "type": "string",
                        "description": "Filter by threat actor name",
                    },
                },
                "required": ["query"],
            },
            handler=search_threat_intel,
        )
    )

    return tools


def register_rag_tools(registry: ToolRegistry, retrieval: RetrievalService) -> None:
    """Register RAG tools with an existing ToolRegistry.

    Args:
        registry: ToolRegistry to register tools with.
        retrieval: RetrievalService for queries.
    """
    tools = create_rag_tools(retrieval)
    for tool in tools:
        registry.register(tool)

    logger.info("rag_tools_registered", count=len(tools))
