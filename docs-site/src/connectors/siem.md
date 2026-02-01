# SIEM Connector

Query SIEM platforms for log data, run searches, and correlate events.

## Interface

```rust
#[async_trait]
pub trait SIEMConnector: Connector {
    /// Run a search query
    async fn search(&self, query: &str, time_range: TimeRange) -> ConnectorResult<SearchResults>;

    /// Get events by ID
    async fn get_events(&self, event_ids: &[String]) -> ConnectorResult<Vec<SIEMEvent>>;

    /// Get related events (correlation)
    async fn get_related_events(
        &self,
        indicator: &str,
        indicator_type: IndicatorType,
        time_range: TimeRange,
    ) -> ConnectorResult<Vec<SIEMEvent>>;
}

pub struct SIEMEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub source: String,
    pub event_type: String,
    pub severity: String,
    pub raw_data: serde_json::Value,
}

pub struct SearchResults {
    pub events: Vec<SIEMEvent>,
    pub total_count: u64,
    pub search_id: String,
}
```

## Splunk

### Configuration

```bash
TW_SIEM_MODE=splunk
TW_SPLUNK_URL=https://splunk.company.com:8089
TW_SPLUNK_TOKEN=your-token-here
```

### Token Permissions

The Splunk token requires these capabilities:
- `search` - Run searches
- `list_inputs` - Health check
- `rest_access` - REST API access

### Example Searches

```rust
let connector = SplunkConnector::new(url, token)?;

// Search for events
let results = connector.search(
    r#"index=security sourcetype=firewall action=blocked"#,
    TimeRange::last_hours(24),
).await?;

// Find related events by IP
let related = connector.get_related_events(
    "192.168.1.100",
    IndicatorType::IpAddress,
    TimeRange::last_hours(1),
).await?;
```

### Search Query Translation

Common queries translated to SPL:

| Triage Warden Query | Splunk SPL |
|---------------------|------------|
| IP correlation | `index=* src_ip="{ip}" OR dest_ip="{ip}"` |
| User activity | `index=* user="{user}"` |
| Hash lookup | `index=* (file_hash="{hash}" OR sha256="{hash}")` |

### Performance Tips

- Use specific indexes in queries
- Limit time ranges when possible
- Use `| head 1000` to limit results

## Mock Connector

For testing:

```bash
TW_SIEM_MODE=mock
```

The mock returns sample security events matching the query pattern.

## Python Bridge

```python
from tw_bridge import SIEMBridge

bridge = SIEMBridge("splunk")

# Run a search
results = bridge.search(
    query='index=security action=blocked',
    hours=24
)

for event in results['events']:
    print(f"{event['timestamp']}: {event['source']}")

# Get related events
related = bridge.get_related_events(
    indicator="192.168.1.100",
    indicator_type="ip",
    hours=1
)
```

## Adding Custom SIEM

Implement the `SIEMConnector` trait:

```rust
pub struct ElasticSIEMConnector {
    client: elasticsearch::Elasticsearch,
}

#[async_trait]
impl SIEMConnector for ElasticSIEMConnector {
    async fn search(&self, query: &str, time_range: TimeRange) -> ConnectorResult<SearchResults> {
        // Translate to Elasticsearch DSL and execute
    }
    // ... implement other methods
}
```
