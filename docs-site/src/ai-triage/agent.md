# Triage Agent

The AI agent that analyzes security incidents.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     Triage Agent                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │
│  │   Claude    │  │   Tools     │  │  Playbook   │     │
│  │   Model     │  │   (Bridge)  │  │   Engine    │     │
│  └─────────────┘  └─────────────┘  └─────────────┘     │
└─────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│                    Python Bridge                         │
│           (ThreatIntelBridge, SIEMBridge, etc.)         │
└─────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│                   Rust Connectors                        │
│        (VirusTotal, Splunk, CrowdStrike, etc.)          │
└─────────────────────────────────────────────────────────┘
```

## Agent Configuration

```python
# python/tw_ai/agents/config.py
class AgentConfig:
    model: str = "claude-sonnet-4-20250514"
    max_tokens: int = 4096
    temperature: float = 0.1
    max_tool_calls: int = 10
    timeout_seconds: int = 120
```

Environment variables:

```bash
TW_AI_PROVIDER=anthropic
TW_ANTHROPIC_API_KEY=your-key
TW_AI_MODEL=claude-sonnet-4-20250514
```

## Available Tools

The agent has access to these tools via the Python bridge:

| Tool | Purpose |
|------|---------|
| `parse_email` | Extract email components |
| `check_email_authentication` | Validate SPF/DKIM/DMARC |
| `lookup_sender_reputation` | Query sender reputation |
| `lookup_urls` | Check URL reputation |
| `lookup_attachments` | Check attachment hashes |
| `search_siem` | Query SIEM for related events |
| `get_host_info` | Get EDR host information |

## Agent Workflow

```python
async def triage(self, incident: Incident) -> Verdict:
    # 1. Load appropriate playbook
    playbook = self.load_playbook(incident.incident_type)

    # 2. Execute playbook steps (tools)
    context = {}
    for step in playbook.steps:
        result = await self.execute_step(step, incident, context)
        context[step.output] = result

    # 3. Build analysis prompt
    prompt = self.build_analysis_prompt(incident, context)

    # 4. Get AI verdict
    response = await self.client.messages.create(
        model=self.config.model,
        messages=[{"role": "user", "content": prompt}],
        max_tokens=self.config.max_tokens
    )

    # 5. Parse and return verdict
    return self.parse_verdict(response)
```

## System Prompt

The agent uses a specialized system prompt:

```
You are an expert security analyst assistant. Analyze the provided security
incident data and determine:

1. Classification: Is this malicious, suspicious, benign, or inconclusive?
2. Confidence: How certain are you (0.0 to 1.0)?
3. Category: What type of threat is this (phishing, malware, etc.)?
4. Reasoning: Explain your analysis step by step
5. Recommended Actions: What should be done to respond?

Use the tool results provided to inform your analysis. Be thorough but concise.
Cite specific evidence for your conclusions.
```

## Tool Calling

The agent can call tools during analysis:

```python
# Agent decides to check URL reputation
tool_result = await self.call_tool(
    name="lookup_urls",
    parameters={"urls": ["https://suspicious-site.com/login"]}
)

# Result used in analysis
# {
#   "results": [{
#     "url": "https://suspicious-site.com/login",
#     "malicious": true,
#     "categories": ["phishing"],
#     "confidence": 0.95
#   }]
# }
```

## Customizing the Agent

### Custom System Prompt

```python
agent = TriageAgent(
    system_prompt="""
    You are a SOC analyst specializing in email security.
    Focus on phishing indicators and BEC patterns.
    Always check sender authentication carefully.
    """
)
```

### Custom Tools

Register additional tools:

```python
@agent.tool
async def custom_lookup(domain: str) -> dict:
    """Look up domain in internal threat database."""
    return await internal_db.query(domain)
```

### Model Selection

```python
# Use different models for different scenarios
if incident.severity == "critical":
    agent = TriageAgent(model="claude-opus-4-20250514")
else:
    agent = TriageAgent(model="claude-sonnet-4-20250514")
```

## Error Handling

The agent handles failures gracefully:

```python
try:
    verdict = await agent.triage(incident)
except ToolError as e:
    # Tool failed - continue with available data
    verdict = await agent.triage_partial(incident, failed_tools=[e.tool])
except AIError as e:
    # AI call failed - return inconclusive
    verdict = Verdict.inconclusive(reason=str(e))
```

## Metrics

Agent metrics exported to Prometheus:

- `triage_duration_seconds` - Time to complete triage
- `triage_tool_calls_total` - Tool calls per triage
- `triage_verdict_total` - Verdicts by classification
- `triage_confidence_histogram` - Confidence score distribution
