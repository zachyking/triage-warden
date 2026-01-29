# Project: Stage 3 - LLM Integration & Agentic Reasoning

## Overview
Complete the AI-powered triage system by enhancing existing LLM providers, implementing real tool integrations via PyO3 bridge, creating comprehensive prompt templates for security triage, and building a production-ready ReAct agent with proper error handling, streaming support, and observability.

## Success Criteria
- [ ] All LLM providers (OpenAI, Anthropic, Local) pass integration tests with tool calling
- [ ] ReAct agent successfully triages sample phishing/malware alerts with >90% accuracy
- [ ] PyO3 bridge exposes all connector methods to Python with proper async handling
- [ ] Prompt templates produce consistent, high-quality triage analysis
- [ ] End-to-end test: Alert → Enrichment → Analysis → Proposed Actions

## Architecture Notes
- **Async Bridge**: Use `pyo3-asyncio` with tokio runtime for Rust↔Python async interop
- **Error Propagation**: Rust `ConnectorError` → Python exceptions with full context
- **Streaming**: Support streaming responses for real-time UI updates
- **Token Counting**: Use tiktoken for accurate token management
- **Caching**: LLM response caching for identical queries

## Interface Contracts

### Python → Rust (via PyO3)
```python
# tw_bridge module
def lookup_hash(hash: str) -> ThreatIntelResult
def lookup_ip(ip: str) -> ThreatIntelResult
def lookup_domain(domain: str) -> ThreatIntelResult
def search_siem(query: str, hours: int) -> SearchResults
def get_host_info(hostname: str) -> HostInfo
def create_ticket(request: dict) -> Ticket
```

### Agent Tool Interface
```python
@dataclass
class ToolResult:
    success: bool
    data: dict[str, Any]
    error: str | None = None
    execution_time_ms: int = 0
```

---

## Stage 3.1: PyO3 Bridge Enhancement
**Parallel capacity: 1 developer**
**Blocking:** Nothing
**Unlocks:** Stage 3.2 (Tools depend on bridge)

### Task 3.1.1: Implement Async PyO3 Bridge
**Estimated complexity:** L

**Description:**
Enhance the PyO3 bridge in `tw-bridge/src/lib.rs` to expose all connector methods to Python. This is the critical infrastructure that allows Python agents to call Rust connectors. Must handle async properly using pyo3-asyncio.

**Context:**
- Existing file: `tw-bridge/src/lib.rs` (placeholder methods)
- Connector traits: `crates/tw-connectors/src/traits.rs`
- Mock connectors for testing: `siem/mock.rs`, `edr/mock.rs`, `threat_intel/mock.rs`

**Acceptance Criteria:**
- [ ] PyO3 module exposes `ThreatIntelBridge` class with lookup_hash, lookup_ip, lookup_domain, lookup_url methods
- [ ] PyO3 module exposes `SIEMBridge` class with search, get_recent_alerts methods
- [ ] PyO3 module exposes `EDRBridge` class with get_host_info, isolate_host, get_detections methods
- [ ] PyO3 module exposes `TicketingBridge` class with create_ticket, update_ticket methods
- [ ] All methods properly convert Rust types to Python dicts
- [ ] Errors convert to Python exceptions with full context
- [ ] Async methods work with Python asyncio
- [ ] Unit tests verify all conversions

**Interface:**
- Inputs: Rust connector implementations
- Outputs: Python-callable module `tw_bridge`

**Notes:**
- Use `pyo3-asyncio` with tokio feature
- Consider using `pythonize` crate for serde→Python conversion
- Create a shared runtime that can be reused across calls

---

## Stage 3.2: Real Tool Implementations
**Parallel capacity: 3 developers**
**Blocking:** Task 3.1.1
**Unlocks:** Stage 3.3

### Task 3.2.1: Threat Intelligence Tools
**Estimated complexity:** M

**Description:**
Implement the threat intelligence tools that call through the PyO3 bridge to the Rust connectors. Replace the placeholder implementations in `python/tw_ai/agents/tools.py`.

**Context:**
- Existing file: `python/tw_ai/agents/tools.py` (has placeholders)
- Bridge will provide: `tw_bridge.ThreatIntelBridge`
- Mock data in Rust: EICAR hashes, known malicious IPs, test domains

**Acceptance Criteria:**
- [ ] `lookup_hash` tool calls bridge and returns formatted ThreatIntelResult
- [ ] `lookup_ip` tool calls bridge and returns formatted ThreatIntelResult
- [ ] `lookup_domain` tool calls bridge and returns formatted ThreatIntelResult
- [ ] All tools include execution timing in result
- [ ] Error handling converts bridge exceptions to ToolResult errors
- [ ] Tools work with mock connectors for testing
- [ ] Unit tests cover success and failure paths

**Interface:**
- Inputs: Indicator strings (hash, IP, domain)
- Outputs: `ToolResult` with threat intel data

---

### Task 3.2.2: SIEM Search Tools
**Estimated complexity:** M

**Description:**
Implement SIEM search tools that allow the agent to query security logs. Must handle time ranges and query building.

**Context:**
- Bridge will provide: `tw_bridge.SIEMBridge`
- Mock SIEM has sample events: login_failure, file_access, process_execution, network_connection

**Acceptance Criteria:**
- [ ] `search_siem` tool accepts query string and time range
- [ ] Tool formats results as readable event summaries
- [ ] Supports limiting result count
- [ ] Includes search statistics in response
- [ ] Error handling for query failures
- [ ] Unit tests with mock connector

**Interface:**
- Inputs: query (str), hours (int), limit (int)
- Outputs: `ToolResult` with events and stats

---

### Task 3.2.3: EDR and Host Tools
**Estimated complexity:** M

**Description:**
Implement EDR tools for host information, detections, and (eventually) containment actions.

**Context:**
- Bridge will provide: `tw_bridge.EDRBridge`
- Mock EDR has sample hosts with processes, network connections, detections

**Acceptance Criteria:**
- [ ] `get_host_info` tool returns host details, status, isolation state
- [ ] `get_detections` tool returns recent detections for a host
- [ ] `get_processes` tool returns recent process activity
- [ ] `get_network_connections` tool returns network activity
- [ ] All tools format output for LLM readability
- [ ] Unit tests with mock connector

**Interface:**
- Inputs: hostname (str), optional time range
- Outputs: `ToolResult` with host/detection/process data

---

## Stage 3.3: Prompt Engineering
**Parallel capacity: 2 developers**
**Blocking:** Nothing (can start in parallel with 3.1)
**Unlocks:** Stage 3.4

### Task 3.3.1: System Prompts and Templates
**Estimated complexity:** M

**Description:**
Create the prompt templates directory and implement system prompts for security triage. These define the agent's persona, capabilities, and output format.

**Context:**
- Create directory: `python/tw_ai/agents/prompts/`
- Reference: MITRE ATT&CK framework for technique mapping
- Target use cases: phishing, malware, suspicious login, network anomaly

**Acceptance Criteria:**
- [ ] Create `prompts/` directory structure
- [ ] `system.py` - Base system prompt defining analyst persona
- [ ] `phishing.py` - Phishing-specific triage prompt
- [ ] `malware.py` - Malware/EDR alert triage prompt
- [ ] `suspicious_login.py` - Account compromise triage prompt
- [ ] All prompts include MITRE ATT&CK context
- [ ] Prompts define clear output schema (JSON)
- [ ] Prompts include few-shot examples

**Interface:**
- Inputs: Alert context, enrichment data
- Outputs: Formatted prompt strings

**Notes:**
- Use Jinja2 or simple f-strings for templating
- Include chain-of-thought guidance in prompts
- Define confidence scoring criteria

---

### Task 3.3.2: Output Parsing and Validation
**Estimated complexity:** M

**Description:**
Create robust output parsing for LLM responses. The agent produces structured analysis that must be validated before use.

**Context:**
- Agent outputs: severity assessment, MITRE mapping, recommended actions, confidence scores
- Use Pydantic for validation

**Acceptance Criteria:**
- [ ] `TriageAnalysis` Pydantic model for structured output
- [ ] `ProposedAction` model for recommended actions
- [ ] Parser extracts JSON from markdown code blocks
- [ ] Validation with clear error messages
- [ ] Fallback parsing for partial/malformed output
- [ ] Unit tests for various output formats

**Interface:**
- Inputs: Raw LLM response string
- Outputs: Validated `TriageAnalysis` object

---

## Stage 3.4: ReAct Agent Enhancement
**Parallel capacity: 2 developers**
**Blocking:** Tasks 3.2.*, 3.3.*
**Unlocks:** Stage 3.5

### Task 3.4.1: Production ReAct Implementation
**Estimated complexity:** L

**Description:**
Enhance the ReAct agent in `python/tw_ai/agents/react.py` with proper error handling, token management, and observability.

**Context:**
- Existing file: `python/tw_ai/agents/react.py` (basic implementation)
- Must integrate with all tools from 3.2.*
- Must use prompts from 3.3.*

**Acceptance Criteria:**
- [ ] Configurable max iterations (default 10)
- [ ] Token counting and budget enforcement
- [ ] Proper tool error handling (retry logic, fallbacks)
- [ ] Structured logging with tracing spans
- [ ] Execution timeout support
- [ ] State persistence between steps for debugging
- [ ] Streaming callback support for UI updates
- [ ] Unit tests with mocked LLM and tools

**Interface:**
- Inputs: `TriageRequest` with alert data
- Outputs: `AgentResult` with analysis, actions, reasoning trace

---

### Task 3.4.2: Security Analysis Functions
**Estimated complexity:** M

**Description:**
Implement security-specific analysis functions used by the agent. These provide domain expertise encoding.

**Context:**
- Create: `python/tw_ai/analysis/security.py`
- Functions for: indicator extraction, MITRE mapping, severity calculation

**Acceptance Criteria:**
- [ ] `extract_indicators(text)` - Extract IPs, hashes, domains, emails from text
- [ ] `map_to_mitre(technique_name)` - Map descriptions to ATT&CK IDs
- [ ] `calculate_severity(factors)` - Compute severity score from multiple factors
- [ ] `identify_attack_pattern(events)` - Pattern recognition from event sequence
- [ ] All functions have comprehensive docstrings
- [ ] Unit tests with security domain test cases

**Interface:**
- Inputs: Raw text, event data, alert details
- Outputs: Structured security analysis objects

---

## Stage 3.5: Integration and Testing
**Parallel capacity: 2 developers**
**Blocking:** All previous stages
**Unlocks:** Stage 4 (Policy Engine)

### Task 3.5.1: End-to-End Integration Tests
**Estimated complexity:** M

**Description:**
Create comprehensive integration tests that exercise the full triage pipeline from alert to proposed actions.

**Context:**
- Use mock connectors throughout
- Test with realistic alert scenarios
- Verify output format compliance

**Acceptance Criteria:**
- [ ] Phishing email triage e2e test
- [ ] Malware detection triage e2e test
- [ ] Suspicious login triage e2e test
- [ ] Test with multiple LLM providers (mocked)
- [ ] Performance benchmarks for triage time
- [ ] Tests run in CI pipeline

**Interface:**
- Inputs: Sample alert payloads
- Outputs: Test reports, coverage metrics

---

### Task 3.5.2: Agent Evaluation Framework
**Estimated complexity:** M

**Description:**
Create an evaluation framework to measure agent quality on a test dataset.

**Context:**
- Create: `python/tw_ai/evaluation/`
- Metrics: accuracy, precision, recall, F1 for verdicts
- Qualitative: reasoning quality, action appropriateness

**Acceptance Criteria:**
- [ ] Test dataset with labeled examples (true positive, false positive, benign)
- [ ] Evaluation runner that processes test cases
- [ ] Metrics calculation and reporting
- [ ] Confusion matrix generation
- [ ] Comparison across LLM providers
- [ ] Baseline establishment for regression testing

**Interface:**
- Inputs: Test dataset path, agent configuration
- Outputs: Evaluation report with metrics

---

## Risk Register
| Risk | Impact | Mitigation |
|------|--------|------------|
| PyO3 async complexity | H | Start with sync bridge, add async layer |
| LLM provider differences | M | Comprehensive provider tests, fallback logic |
| Prompt brittleness | M | Few-shot examples, output validation |
| Token budget overruns | M | Hard limits, truncation strategies |
| Tool execution failures | M | Retry logic, graceful degradation |

## Open Questions
- [ ] Should we support streaming for all providers or just OpenAI initially?
- [ ] What's the target latency for a full triage cycle? (Propose: <60s)
- [ ] Do we need to support multiple concurrent triage requests?

---

## Dependency Graph
```
Stage 3.1 (PyO3 Bridge)
    └──▶ Stage 3.2 (Real Tools) [3 parallel tasks]
            └──▶ Stage 3.4 (ReAct Agent) [2 parallel tasks]
                    └──▶ Stage 3.5 (Integration) [2 parallel tasks]

Stage 3.3 (Prompts) [can run parallel with 3.1, 3.2]
    └──▶ Stage 3.4 (ReAct Agent)
```

**Maximum parallelization: 4 developers** (during Stages 3.2 + 3.3)
**Critical path: 3.1 → 3.2 → 3.4 → 3.5**
