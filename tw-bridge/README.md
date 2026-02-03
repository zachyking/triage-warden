# tw-bridge

Rust-Python bridge for Triage Warden connectors using PyO3.

## Overview

This crate provides Python bindings to the Rust connectors used by Triage Warden,
enabling the Python AI components to interact with security tooling through
high-performance Rust implementations.

## Building

```bash
# Install maturin
pip install maturin

# Build the wheel
maturin build --release

# Or install in development mode
maturin develop
```

## Usage

```python
from tw_bridge import ThreatIntelBridge, SIEMBridge, EDRBridge

# Create a threat intel bridge
ti = ThreatIntelBridge("mock")
result = ti.lookup_hash("44d88612fea8a8f36de82e1278abb02f")
print(result["verdict"])  # "malicious"

# Create a SIEM bridge
siem = SIEMBridge("mock")
results = siem.search("login_failure", 24)
print(f"Found {results['total_count']} events")
```

## Testing

```bash
# Build and install the wheel
maturin build --release
pip install target/wheels/*.whl

# Run tests
pytest python/tests -v
```

## Exposed Classes

- `PyTriageRequest` - Triage request data structure
- `PyTriageResult` - Triage result with verdict and confidence
- `PyThreatIntelResult` - Threat intelligence lookup result
- `BridgeConfig` - Configuration for bridges
- `ThreatIntelBridge` - Threat intelligence lookups (hashes, IPs, domains)
- `SIEMBridge` - SIEM search and alert retrieval
- `EDRBridge` - EDR host information
- `TicketingBridge` - Ticket creation and management
- `EmailBridge` - Email notifications
- `PolicyBridge` - Policy engine and kill switch status
