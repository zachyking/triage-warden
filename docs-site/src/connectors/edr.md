# EDR Connector

Integrate with Endpoint Detection and Response platforms for host information and response actions.

## Interface

```rust
#[async_trait]
pub trait EDRConnector: Connector {
    /// Get host information
    async fn get_host(&self, host_id: &str) -> ConnectorResult<HostInfo>;

    /// Search for hosts
    async fn search_hosts(&self, query: &str) -> ConnectorResult<Vec<HostInfo>>;

    /// Get recent detections for a host
    async fn get_detections(&self, host_id: &str) -> ConnectorResult<Vec<Detection>>;

    /// Isolate a host from the network
    async fn isolate_host(&self, host_id: &str) -> ConnectorResult<ActionResult>;

    /// Remove host isolation
    async fn unisolate_host(&self, host_id: &str) -> ConnectorResult<ActionResult>;

    /// Trigger a scan on the host
    async fn scan_host(&self, host_id: &str) -> ConnectorResult<ActionResult>;
}

pub struct HostInfo {
    pub id: String,
    pub hostname: String,
    pub platform: String,
    pub os_version: String,
    pub agent_version: String,
    pub last_seen: DateTime<Utc>,
    pub isolation_status: IsolationStatus,
    pub tags: Vec<String>,
}

pub struct Detection {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub severity: String,
    pub tactic: String,
    pub technique: String,
    pub description: String,
    pub process_name: Option<String>,
    pub file_path: Option<String>,
}
```

## CrowdStrike

### Configuration

```bash
TW_EDR_MODE=crowdstrike
TW_CROWDSTRIKE_CLIENT_ID=your-client-id
TW_CROWDSTRIKE_CLIENT_SECRET=your-client-secret
TW_CROWDSTRIKE_REGION=us-1  # us-1, us-2, eu-1, usgov-1
```

### API Scopes Required

The API client requires these scopes:
- `Hosts: Read` - Get host information
- `Hosts: Write` - Isolation actions
- `Detections: Read` - Get detections
- `Real Time Response: Write` - Scan actions

### OAuth2 Token Management

The connector automatically handles token refresh:

```rust
// Token refreshed automatically when expired
let connector = CrowdStrikeConnector::new(client_id, client_secret, region)?;

// All subsequent calls use valid token
let host = connector.get_host("abc123").await?;
```

### Example Usage

```rust
// Get host information
let host = connector.get_host("aid:abc123").await?;
println!("Hostname: {}", host.hostname);
println!("Last seen: {}", host.last_seen);

// Check for detections
let detections = connector.get_detections("aid:abc123").await?;
for d in detections {
    println!("{}: {} - {}", d.timestamp, d.severity, d.description);
}

// Isolate compromised host
let result = connector.isolate_host("aid:abc123").await?;
if result.success {
    println!("Host isolated successfully");
}
```

### Action Confirmation

Isolation and scan actions require policy approval. See [Policy Engine](../policy/README.md).

## Mock Connector

```bash
TW_EDR_MODE=mock
```

The mock provides sample hosts and detections for testing.

## Python Bridge

```python
from tw_bridge import EDRBridge

bridge = EDRBridge("crowdstrike")

# Get host info
host = bridge.get_host("aid:abc123")
print(f"Hostname: {host['hostname']}")
print(f"Platform: {host['platform']}")

# Get detections
detections = bridge.get_detections("aid:abc123")
for d in detections:
    print(f"{d['severity']}: {d['description']}")

# Isolate host (requires policy approval)
result = bridge.isolate_host("aid:abc123")
if result['success']:
    print("Host isolated")
```

## Response Actions

| Action | Description | Rollback |
|--------|-------------|----------|
| `isolate_host` | Network isolation | `unisolate_host` |
| `scan_host` | On-demand scan | N/A |

### Isolation Behavior

When isolated:
- Host cannot communicate on network
- Falcon agent maintains connection to cloud
- User may see isolation notification

## Rate Limits

| Endpoint | Limit |
|----------|-------|
| Host queries | 100/min |
| Detection queries | 50/min |
| Containment actions | 10/min |
