"""RAG-Enhanced Analysis for security incident triage.

This module implements Task 2.3.4 from the AI Capabilities roadmap, providing
RAG (Retrieval-Augmented Generation) enhanced analysis that:

1. Retrieves similar past incidents from the vector store
2. Retrieves relevant playbooks for the current scenario
3. Retrieves matching MITRE ATT&CK techniques
4. Retrieves threat intelligence context
5. Builds enhanced context for the LLM analysis
6. Tracks citations and context used in the analysis

The RAG-enhanced analyzer wraps the ReAct agent and augments its prompts
with relevant organizational knowledge before analysis begins.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from tw_ai.agents.models import TriageAnalysis
    from tw_ai.agents.react import AgentResult, ReActAgent, TriageRequest
    from tw_ai.rag import RAGService
    from tw_ai.rag.config import RAGConfig
    from tw_ai.rag.models import QueryResult

logger = structlog.get_logger()


# =============================================================================
# Constants for Context Window Management
# =============================================================================

# Maximum tokens to allocate for RAG context in the prompt
MAX_RAG_CONTEXT_TOKENS = 2000

# Maximum characters per retrieved item (approximate, assuming ~4 chars/token)
MAX_INCIDENT_SUMMARY_CHARS = 500
MAX_PLAYBOOK_SUMMARY_CHARS = 400
MAX_MITRE_SUMMARY_CHARS = 200
MAX_THREAT_INTEL_CHARS = 300

# Result limits per collection
DEFAULT_SIMILAR_INCIDENTS_K = 3
DEFAULT_PLAYBOOKS_K = 2
DEFAULT_MITRE_TECHNIQUES_K = 3
DEFAULT_THREAT_INTEL_K = 3


# =============================================================================
# Context Source Tracking
# =============================================================================


class ContextSourceType(str, Enum):
    """Type of RAG context source."""

    SIMILAR_INCIDENT = "similar_incident"
    PLAYBOOK = "playbook"
    MITRE_TECHNIQUE = "mitre_technique"
    THREAT_INTEL = "threat_intel"


@dataclass
class ContextSource:
    """A single source of context used in RAG-enhanced analysis.

    Tracks where context came from for citation and audit purposes.
    """

    source_type: ContextSourceType
    document_id: str
    similarity_score: float
    content_summary: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "source_type": self.source_type.value,
            "document_id": self.document_id,
            "similarity_score": round(self.similarity_score, 3),
            "content_summary": self.content_summary,
            "metadata": self.metadata,
        }


@dataclass
class RAGContext:
    """Container for all RAG-retrieved context.

    Stores the retrieved documents and provides methods for:
    - Building context strings for LLM prompts
    - Tracking citations
    - Summarizing context usage
    """

    similar_incidents: list[ContextSource] = field(default_factory=list)
    playbooks: list[ContextSource] = field(default_factory=list)
    mitre_techniques: list[ContextSource] = field(default_factory=list)
    threat_intel: list[ContextSource] = field(default_factory=list)
    retrieval_time_ms: int = 0

    @property
    def total_sources(self) -> int:
        """Total number of context sources retrieved."""
        return (
            len(self.similar_incidents)
            + len(self.playbooks)
            + len(self.mitre_techniques)
            + len(self.threat_intel)
        )

    @property
    def is_empty(self) -> bool:
        """Check if no context was retrieved."""
        return self.total_sources == 0

    def all_sources(self) -> list[ContextSource]:
        """Get all context sources as a flat list."""
        return self.similar_incidents + self.playbooks + self.mitre_techniques + self.threat_intel

    def get_citation_summary(self) -> dict[str, Any]:
        """Get a summary of all citations for audit purposes."""
        return {
            "total_sources": self.total_sources,
            "retrieval_time_ms": self.retrieval_time_ms,
            "sources_by_type": {
                "similar_incidents": len(self.similar_incidents),
                "playbooks": len(self.playbooks),
                "mitre_techniques": len(self.mitre_techniques),
                "threat_intel": len(self.threat_intel),
            },
            "documents": [s.to_dict() for s in self.all_sources()],
        }

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return self.get_citation_summary()


# =============================================================================
# Context Builder
# =============================================================================


class RAGContextBuilder:
    """Builds context strings from retrieved RAG documents.

    Handles:
    - Truncation to fit context windows
    - Formatting for LLM consumption
    - Priority ordering of context
    """

    def __init__(
        self,
        max_tokens: int = MAX_RAG_CONTEXT_TOKENS,
        chars_per_token: int = 4,
    ) -> None:
        """Initialize the context builder.

        Args:
            max_tokens: Maximum tokens to use for RAG context.
            chars_per_token: Approximate characters per token for estimation.
        """
        self.max_tokens = max_tokens
        self.chars_per_token = chars_per_token
        self.max_chars = max_tokens * chars_per_token

    def build_context_string(self, rag_context: RAGContext) -> str:
        """Build a formatted context string for the LLM prompt.

        Args:
            rag_context: Retrieved RAG context.

        Returns:
            Formatted context string, truncated to fit within limits.
        """
        if rag_context.is_empty:
            return ""

        sections: list[str] = []
        remaining_chars = self.max_chars

        # Priority order: similar incidents > playbooks > MITRE > threat intel
        # Similar incidents are most valuable for learning from past decisions

        # 1. Similar incidents (highest priority)
        if rag_context.similar_incidents:
            section, used = self._build_incidents_section(
                rag_context.similar_incidents,
                remaining_chars,
            )
            if section:
                sections.append(section)
                remaining_chars -= used

        # 2. Relevant playbooks
        if rag_context.playbooks and remaining_chars > 200:
            section, used = self._build_playbooks_section(
                rag_context.playbooks,
                remaining_chars,
            )
            if section:
                sections.append(section)
                remaining_chars -= used

        # 3. MITRE techniques
        if rag_context.mitre_techniques and remaining_chars > 200:
            section, used = self._build_mitre_section(
                rag_context.mitre_techniques,
                remaining_chars,
            )
            if section:
                sections.append(section)
                remaining_chars -= used

        # 4. Threat intelligence
        if rag_context.threat_intel and remaining_chars > 200:
            section, used = self._build_threat_intel_section(
                rag_context.threat_intel,
                remaining_chars,
            )
            if section:
                sections.append(section)

        if not sections:
            return ""

        header = "## Organizational Context (Retrieved from Knowledge Base)\n"
        header += "Use this context to inform your analysis, "
        header += "but always verify against current evidence.\n\n"

        return header + "\n\n".join(sections)

    def _build_incidents_section(
        self,
        incidents: list[ContextSource],
        max_chars: int,
    ) -> tuple[str, int]:
        """Build the similar incidents section."""
        header = "### Similar Past Incidents\n"
        items: list[str] = []
        chars_used = len(header)

        for inc in incidents:
            verdict = inc.metadata.get("verdict", "unknown")
            severity = inc.metadata.get("severity", "unknown")
            confidence = inc.metadata.get("confidence", 0)

            item = (
                f"- **{inc.document_id}** (Similarity: {inc.similarity_score:.0%})\n"
                f"  Verdict: {verdict} | Severity: {severity} | Confidence: {confidence}%\n"
                f"  Summary: {inc.content_summary[:MAX_INCIDENT_SUMMARY_CHARS]}"
            )

            if chars_used + len(item) + 2 > max_chars:
                break

            items.append(item)
            chars_used += len(item) + 2

        if not items:
            return "", 0

        section = header + "\n".join(items)
        return section, len(section)

    def _build_playbooks_section(
        self,
        playbooks: list[ContextSource],
        max_chars: int,
    ) -> tuple[str, int]:
        """Build the playbooks section."""
        header = "### Relevant Playbooks\n"
        items: list[str] = []
        chars_used = len(header)

        for pb in playbooks:
            name = pb.metadata.get("name", "Unknown Playbook")
            version = pb.metadata.get("version", "1.0")

            item = (
                f"- **{name}** v{version} (Relevance: {pb.similarity_score:.0%})\n"
                f"  {pb.content_summary[:MAX_PLAYBOOK_SUMMARY_CHARS]}"
            )

            if chars_used + len(item) + 2 > max_chars:
                break

            items.append(item)
            chars_used += len(item) + 2

        if not items:
            return "", 0

        section = header + "\n".join(items)
        return section, len(section)

    def _build_mitre_section(
        self,
        techniques: list[ContextSource],
        max_chars: int,
    ) -> tuple[str, int]:
        """Build the MITRE techniques section."""
        header = "### Potentially Relevant MITRE ATT&CK Techniques\n"
        items: list[str] = []
        chars_used = len(header)

        for tech in techniques:
            tech_id = tech.metadata.get("technique_id", "")
            name = tech.metadata.get("name", "")
            tactic = tech.metadata.get("tactic", "")

            item = (
                f"- **{tech_id}**: {name} ({tactic}) " f"(Relevance: {tech.similarity_score:.0%})"
            )

            if chars_used + len(item) + 2 > max_chars:
                break

            items.append(item)
            chars_used += len(item) + 2

        if not items:
            return "", 0

        section = header + "\n".join(items)
        return section, len(section)

    def _build_threat_intel_section(
        self,
        intel: list[ContextSource],
        max_chars: int,
    ) -> tuple[str, int]:
        """Build the threat intelligence section."""
        header = "### Related Threat Intelligence\n"
        items: list[str] = []
        chars_used = len(header)

        for ti in intel:
            indicator = ti.metadata.get("indicator", "")
            ind_type = ti.metadata.get("indicator_type", "")
            verdict = ti.metadata.get("verdict", "unknown")

            item = (
                f"- **{ind_type}**: {indicator} (Verdict: {verdict})\n"
                f"  {ti.content_summary[:MAX_THREAT_INTEL_CHARS]}"
            )

            if chars_used + len(item) + 2 > max_chars:
                break

            items.append(item)
            chars_used += len(item) + 2

        if not items:
            return "", 0

        section = header + "\n".join(items)
        return section, len(section)


# =============================================================================
# RAG-Enhanced Analyzer
# =============================================================================


@dataclass
class RAGAnalysisConfig:
    """Configuration for RAG-enhanced analysis."""

    # Result limits
    similar_incidents_k: int = DEFAULT_SIMILAR_INCIDENTS_K
    playbooks_k: int = DEFAULT_PLAYBOOKS_K
    mitre_techniques_k: int = DEFAULT_MITRE_TECHNIQUES_K
    threat_intel_k: int = DEFAULT_THREAT_INTEL_K

    # Similarity thresholds
    min_incident_similarity: float = 0.4
    min_playbook_similarity: float = 0.3
    min_mitre_similarity: float = 0.3
    min_threat_intel_similarity: float = 0.3

    # Context window settings
    max_context_tokens: int = MAX_RAG_CONTEXT_TOKENS

    # Feature flags
    enable_similar_incidents: bool = True
    enable_playbooks: bool = True
    enable_mitre_techniques: bool = True
    enable_threat_intel: bool = True

    # Fallback behavior
    fallback_on_retrieval_error: bool = True  # Continue without RAG if retrieval fails


@dataclass
class RAGAnalysisResult:
    """Result from RAG-enhanced analysis.

    Extends the base AgentResult with RAG-specific information.
    """

    agent_result: AgentResult
    rag_context: RAGContext
    rag_enabled: bool = True
    retrieval_errors: list[str] = field(default_factory=list)

    @property
    def success(self) -> bool:
        """Whether the analysis was successful."""
        return self.agent_result.success

    @property
    def analysis(self) -> TriageAnalysis | None:
        """The triage analysis result."""
        return self.agent_result.analysis

    def get_metrics(self) -> dict[str, Any]:
        """Get metrics about the RAG-enhanced analysis."""
        return {
            "rag_enabled": self.rag_enabled,
            "total_context_sources": self.rag_context.total_sources,
            "retrieval_time_ms": self.rag_context.retrieval_time_ms,
            "agent_tokens_used": self.agent_result.tokens_used,
            "agent_execution_time_s": self.agent_result.execution_time_seconds,
            "retrieval_errors_count": len(self.retrieval_errors),
            "sources_used": {
                "similar_incidents": len(self.rag_context.similar_incidents),
                "playbooks": len(self.rag_context.playbooks),
                "mitre_techniques": len(self.rag_context.mitre_techniques),
                "threat_intel": len(self.rag_context.threat_intel),
            },
        }


class RAGEnhancedAnalyzer:
    """RAG-enhanced incident analyzer.

    Wraps the ReAct agent and augments its prompts with relevant context
    retrieved from the organizational knowledge base (vector store).

    Usage:
        rag_service = create_rag_service()
        agent = ReActAgent(llm, tools)
        analyzer = RAGEnhancedAnalyzer(agent, rag_service)

        result = await analyzer.analyze(triage_request)
    """

    def __init__(
        self,
        agent: ReActAgent,
        rag_service: RAGService,
        config: RAGAnalysisConfig | None = None,
    ) -> None:
        """Initialize the RAG-enhanced analyzer.

        Args:
            agent: ReAct agent for analysis.
            rag_service: RAG service for context retrieval.
            config: Optional configuration for RAG analysis.
        """
        self._agent = agent
        self._rag_service = rag_service
        self._config = config or RAGAnalysisConfig()
        self._context_builder = RAGContextBuilder(max_tokens=self._config.max_context_tokens)

        logger.info(
            "rag_enhanced_analyzer_initialized",
            similar_incidents_k=self._config.similar_incidents_k,
            playbooks_k=self._config.playbooks_k,
            max_context_tokens=self._config.max_context_tokens,
        )

    async def analyze(
        self,
        request: TriageRequest,
        incident_description: str | None = None,
    ) -> RAGAnalysisResult:
        """Perform RAG-enhanced triage analysis.

        Args:
            request: Triage request with alert data.
            incident_description: Optional description to use for RAG queries.
                                  If not provided, one will be generated from
                                  the request.

        Returns:
            RAGAnalysisResult with analysis and context citations.
        """
        start_time = time.time()

        # Generate incident description for RAG queries
        if incident_description is None:
            incident_description = self._generate_incident_description(request)

        # Retrieve RAG context
        rag_context, retrieval_errors = await self._retrieve_context(
            incident_description,
            alert_type=request.alert_type,
        )

        # Build context string for the agent
        context_string = self._context_builder.build_context_string(rag_context)

        # Augment the request with RAG context
        augmented_request = self._augment_request(request, context_string)

        # Run the agent
        agent_result = await self._agent.run(augmented_request)

        # Build result
        result = RAGAnalysisResult(
            agent_result=agent_result,
            rag_context=rag_context,
            rag_enabled=True,
            retrieval_errors=retrieval_errors,
        )

        total_time = time.time() - start_time

        logger.info(
            "rag_analysis_complete",
            success=result.success,
            total_context_sources=rag_context.total_sources,
            retrieval_time_ms=rag_context.retrieval_time_ms,
            agent_time_s=agent_result.execution_time_seconds,
            total_time_s=total_time,
            retrieval_errors=len(retrieval_errors),
        )

        return result

    async def analyze_without_rag(
        self,
        request: TriageRequest,
    ) -> RAGAnalysisResult:
        """Perform analysis without RAG enhancement.

        Useful for A/B testing RAG vs non-RAG analysis quality.

        Args:
            request: Triage request with alert data.

        Returns:
            RAGAnalysisResult with empty RAG context.
        """
        agent_result = await self._agent.run(request)

        return RAGAnalysisResult(
            agent_result=agent_result,
            rag_context=RAGContext(),
            rag_enabled=False,
            retrieval_errors=[],
        )

    async def _retrieve_context(
        self,
        description: str,
        alert_type: str | None = None,
    ) -> tuple[RAGContext, list[str]]:
        """Retrieve RAG context for the incident.

        Args:
            description: Incident description for similarity search.
            alert_type: Type of alert (e.g., "phishing", "malware").

        Returns:
            Tuple of (RAGContext, list of retrieval errors).
        """
        start_time = time.perf_counter()
        context = RAGContext()
        errors: list[str] = []

        # Retrieve similar incidents
        if self._config.enable_similar_incidents:
            try:
                context.similar_incidents = await self._retrieve_similar_incidents(
                    description, alert_type
                )
            except Exception as e:
                error_msg = f"Failed to retrieve similar incidents: {e}"
                errors.append(error_msg)
                logger.warning("rag_retrieval_error", source="incidents", error=str(e))

        # Retrieve playbooks
        if self._config.enable_playbooks:
            try:
                context.playbooks = await self._retrieve_playbooks(description, alert_type)
            except Exception as e:
                error_msg = f"Failed to retrieve playbooks: {e}"
                errors.append(error_msg)
                logger.warning("rag_retrieval_error", source="playbooks", error=str(e))

        # Retrieve MITRE techniques
        if self._config.enable_mitre_techniques:
            try:
                context.mitre_techniques = await self._retrieve_mitre_techniques(description)
            except Exception as e:
                error_msg = f"Failed to retrieve MITRE techniques: {e}"
                errors.append(error_msg)
                logger.warning("rag_retrieval_error", source="mitre", error=str(e))

        # Retrieve threat intelligence
        if self._config.enable_threat_intel:
            try:
                context.threat_intel = await self._retrieve_threat_intel(description)
            except Exception as e:
                error_msg = f"Failed to retrieve threat intel: {e}"
                errors.append(error_msg)
                logger.warning("rag_retrieval_error", source="threat_intel", error=str(e))

        context.retrieval_time_ms = int((time.perf_counter() - start_time) * 1000)

        logger.debug(
            "rag_context_retrieved",
            similar_incidents=len(context.similar_incidents),
            playbooks=len(context.playbooks),
            mitre_techniques=len(context.mitre_techniques),
            threat_intel=len(context.threat_intel),
            retrieval_time_ms=context.retrieval_time_ms,
        )

        return context, errors

    async def _retrieve_similar_incidents(
        self,
        description: str,
        alert_type: str | None = None,
    ) -> list[ContextSource]:
        """Retrieve similar past incidents."""
        response = self._rag_service.retrieval.search_similar_incidents(
            query=description,
            top_k=self._config.similar_incidents_k,
            alert_type=alert_type,
        )

        return [
            self._result_to_context_source(
                result,
                ContextSourceType.SIMILAR_INCIDENT,
            )
            for result in response.results
            if result.similarity >= self._config.min_incident_similarity
        ]

    async def _retrieve_playbooks(
        self,
        description: str,
        alert_type: str | None = None,
    ) -> list[ContextSource]:
        """Retrieve relevant playbooks."""
        response = self._rag_service.retrieval.search_playbooks(
            query=description,
            top_k=self._config.playbooks_k,
            trigger_type=alert_type,
        )

        return [
            self._result_to_context_source(
                result,
                ContextSourceType.PLAYBOOK,
            )
            for result in response.results
            if result.similarity >= self._config.min_playbook_similarity
        ]

    async def _retrieve_mitre_techniques(
        self,
        description: str,
    ) -> list[ContextSource]:
        """Retrieve potentially matching MITRE techniques."""
        response = self._rag_service.retrieval.search_mitre_techniques(
            query=description,
            top_k=self._config.mitre_techniques_k,
        )

        return [
            self._result_to_context_source(
                result,
                ContextSourceType.MITRE_TECHNIQUE,
            )
            for result in response.results
            if result.similarity >= self._config.min_mitre_similarity
        ]

    async def _retrieve_threat_intel(
        self,
        description: str,
    ) -> list[ContextSource]:
        """Retrieve related threat intelligence."""
        response = self._rag_service.retrieval.search_threat_intel(
            query=description,
            top_k=self._config.threat_intel_k,
        )

        return [
            self._result_to_context_source(
                result,
                ContextSourceType.THREAT_INTEL,
            )
            for result in response.results
            if result.similarity >= self._config.min_threat_intel_similarity
        ]

    def _result_to_context_source(
        self,
        result: QueryResult,
        source_type: ContextSourceType,
    ) -> ContextSource:
        """Convert a QueryResult to a ContextSource."""
        return ContextSource(
            source_type=source_type,
            document_id=result.id,
            similarity_score=result.similarity,
            content_summary=result.content or "",
            metadata=result.metadata or {},
        )

    def _generate_incident_description(self, request: TriageRequest) -> str:
        """Generate a description string from the triage request for RAG queries.

        Args:
            request: Triage request with alert data.

        Returns:
            A natural language description suitable for semantic search.
        """
        parts = [f"Security incident type: {request.alert_type}"]

        # Extract key fields from alert_data
        alert_data = request.alert_data

        # Common fields to include
        for key in ["summary", "description", "title", "subject", "message"]:
            if key in alert_data and alert_data[key]:
                parts.append(str(alert_data[key])[:500])
                break

        # Add source/sender info
        for key in ["source", "sender", "src_ip", "source_ip", "attacker_ip"]:
            if key in alert_data and alert_data[key]:
                parts.append(f"Source: {alert_data[key]}")
                break

        # Add target info
        for key in ["target", "recipient", "dst_ip", "dest_ip", "victim"]:
            if key in alert_data and alert_data[key]:
                parts.append(f"Target: {alert_data[key]}")
                break

        # Add any indicators
        if "indicators" in alert_data:
            indicators = alert_data["indicators"]
            if isinstance(indicators, list) and indicators:
                parts.append(f"Indicators: {', '.join(str(i) for i in indicators[:5])}")

        return " | ".join(parts)

    def _augment_request(
        self,
        request: TriageRequest,
        context_string: str,
    ) -> TriageRequest:
        """Augment the triage request with RAG context.

        Args:
            request: Original triage request.
            context_string: Built RAG context string.

        Returns:
            Augmented request with context added.
        """
        if not context_string:
            return request

        # Add RAG context to the request's context field
        augmented_context = dict(request.context) if request.context else {}
        augmented_context["_rag_context"] = context_string

        # Create new request with augmented context
        from tw_ai.agents.react import TriageRequest

        return TriageRequest(
            alert_type=request.alert_type,
            alert_data=request.alert_data,
            context=augmented_context,
            priority=request.priority,
            redact_pii=request.redact_pii,
            pii_redaction_mode=request.pii_redaction_mode,
            sanitize_for_injection=request.sanitize_for_injection,
        )


# =============================================================================
# Factory Functions
# =============================================================================


def create_rag_analyzer(
    agent: ReActAgent,
    rag_service: RAGService | None = None,
    rag_config: RAGConfig | None = None,
    analysis_config: RAGAnalysisConfig | None = None,
) -> RAGEnhancedAnalyzer:
    """Create a RAG-enhanced analyzer.

    Args:
        agent: ReAct agent for analysis.
        rag_service: RAG service. If not provided, one will be created.
        rag_config: RAG configuration for service creation.
        analysis_config: Configuration for RAG analysis.

    Returns:
        Configured RAGEnhancedAnalyzer instance.
    """
    if rag_service is None:
        from tw_ai.rag import create_rag_service

        rag_service = create_rag_service(rag_config)

    return RAGEnhancedAnalyzer(
        agent=agent,
        rag_service=rag_service,
        config=analysis_config,
    )


__all__ = [
    # Core classes
    "RAGEnhancedAnalyzer",
    "RAGAnalysisResult",
    "RAGAnalysisConfig",
    # Context tracking
    "RAGContext",
    "ContextSource",
    "ContextSourceType",
    # Builder
    "RAGContextBuilder",
    # Factory
    "create_rag_analyzer",
]
