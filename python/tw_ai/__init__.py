"""
tw_ai - AI components for Triage Warden

This package provides comprehensive AI capabilities for security triage automation:

Core Components:
    - LLM abstraction layer for multiple providers (OpenAI, Anthropic, etc.)
    - ReAct-style agentic reasoning for security triage
    - Tool system for enrichment and action execution

Stage 2 AI Capabilities:
    - RAG (Retrieval-Augmented Generation) for contextual knowledge retrieval
    - Evidence collection and structured citations
    - Hallucination detection for AI output validation
    - Action validation with guardrails
    - Few-shot learning with dynamic example selection
    - Investigation report generation

Analysis Utilities:
    - Email/phishing analysis
    - MITRE ATT&CK technique mapping
    - Security indicator extraction
    - Risk scoring

Submodules:
    - tw_ai.agents: ReAct agent, output parsing, evidence parsing, prompts
    - tw_ai.analysis: Security analysis utilities, RAG-enhanced analyzer
    - tw_ai.rag: Vector store, embeddings, retrieval, ingestion
    - tw_ai.validation: Hallucination detection, action validation
    - tw_ai.few_shot: Dynamic few-shot example selection
    - tw_ai.reports: Investigation report generation
    - tw_ai.llm: LLM provider abstraction

Example:
    Basic triage analysis::

        from tw_ai import ReActAgent, TriageAnalysis
        from tw_ai.rag import create_rag_service
        from tw_ai.validation import HallucinationDetector

        # Create RAG service for context retrieval
        rag = create_rag_service()

        # Run agent analysis
        agent = ReActAgent(llm_provider)
        result = await agent.run(incident_data)

        # Validate output
        detector = HallucinationDetector()
        warnings = detector.check(result.analysis, incident_data)
"""

__version__ = "0.1.0"

# Core LLM components
from tw_ai.agents.models import (
    EvidenceItem,
    Indicator,
    InvestigationStep,
    MITRETechnique,
    RecommendedAction,
    TriageAnalysis,
)
from tw_ai.agents.output_parser import (
    ParseError,
    parse_triage_analysis,
)

# Agent components
from tw_ai.agents.react import AgentResult, ReActAgent
from tw_ai.agents.tools import Tool, ToolRegistry

# Analysis components (Stage 2.3.4)
from tw_ai.analysis import (
    RAGContext,
    RAGEnhancedAnalyzer,
    create_rag_analyzer,
)

# Few-shot components (Stage 2.4.2)
from tw_ai.few_shot import (
    Example,
    FewShotSelector,
    create_few_shot_selector,
)
from tw_ai.llm.base import LLMProvider, LLMResponse, Message, ToolDefinition

# RAG components (Stage 2.3)
from tw_ai.rag import (
    RAGConfig,
    RAGService,
    create_rag_service,
)

# Report generation (Stage 2.1.3)
from tw_ai.reports import (
    InvestigationReport,
    InvestigationReportGenerator,
    ReportFormat,
)

# Validation components (Stage 2.4)
from tw_ai.validation import (
    ActionValidator,
    HallucinationDetector,
    HallucinationResult,
    ValidationDecision,
    ValidationResult,
)

__all__ = [
    # Version
    "__version__",
    # Core LLM
    "LLMProvider",
    "Message",
    "LLMResponse",
    "ToolDefinition",
    # Agent core
    "ReActAgent",
    "AgentResult",
    "Tool",
    "ToolRegistry",
    # Agent models
    "EvidenceItem",
    "Indicator",
    "InvestigationStep",
    "MITRETechnique",
    "RecommendedAction",
    "TriageAnalysis",
    # Output parsing
    "ParseError",
    "parse_triage_analysis",
    # RAG (Stage 2.3)
    "RAGConfig",
    "RAGService",
    "create_rag_service",
    # Validation (Stage 2.4)
    "HallucinationDetector",
    "HallucinationResult",
    "ActionValidator",
    "ValidationResult",
    "ValidationDecision",
    # Few-shot (Stage 2.4.2)
    "FewShotSelector",
    "Example",
    "create_few_shot_selector",
    # Analysis (Stage 2.3.4)
    "RAGEnhancedAnalyzer",
    "RAGContext",
    "create_rag_analyzer",
    # Reports (Stage 2.1.3)
    "InvestigationReportGenerator",
    "InvestigationReport",
    "ReportFormat",
]
