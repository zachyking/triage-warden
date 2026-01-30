# tw-ai

AI components for Triage Warden - LLM integration, agentic reasoning, and RAG.

## Overview

This package provides the Python-based AI components for Triage Warden:

- **LLM Abstraction**: Unified interface for OpenAI, Anthropic, and local models
- **ReAct Agents**: Reasoning + Acting loop for security triage
- **RAG**: Knowledge base for past incidents and security documentation
- **Analysis**: Security-specific analysis utilities

## Installation

```bash
pip install -e ".[dev]"
```

## Usage

```python
from tw_ai.llm import OpenAIProvider
from tw_ai.agents import ReActAgent

# Initialize LLM provider
provider = OpenAIProvider(model="gpt-4o")

# Create agent
agent = ReActAgent(provider=provider)

# Run triage
result = await agent.run(
    task="Analyze this phishing email",
    context={"email": email_data}
)
```

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run linting
ruff check tw_ai
black --check tw_ai

# Run tests
pytest
```
