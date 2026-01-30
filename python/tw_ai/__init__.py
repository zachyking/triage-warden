"""
tw_ai - AI components for Triage Warden

This package provides:
- LLM abstraction layer for multiple providers
- ReAct-style agentic reasoning for security triage
- RAG-based knowledge retrieval
- Security analysis utilities
"""

__version__ = "0.1.0"

from tw_ai.agents.react import AgentResult, ReActAgent
from tw_ai.llm.base import LLMProvider, LLMResponse, Message, ToolDefinition

__all__ = [
    "LLMProvider",
    "Message",
    "LLMResponse",
    "ToolDefinition",
    "ReActAgent",
    "AgentResult",
]
