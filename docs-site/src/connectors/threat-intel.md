# Threat Intelligence Connector

Query threat intelligence services for reputation data on hashes, URLs, domains, and IP addresses.

## Interface

```rust
#[async_trait]
pub trait ThreatIntelConnector: Connector {
    /// Look up file hash reputation
    async fn lookup_hash(&self, hash: &str) -> ConnectorResult<ThreatReport>;

    /// Look up URL reputation
    async fn lookup_url(&self, url: &str) -> ConnectorResult<ThreatReport>;

    /// Look up domain reputation
    async fn lookup_domain(&self, domain: &str) -> ConnectorResult<ThreatReport>;

    /// Look up IP address reputation
    async fn lookup_ip(&self, ip: &str) -> ConnectorResult<ThreatReport>;
}

pub struct ThreatReport {
    pub indicator: String,
    pub indicator_type: IndicatorType,
    pub malicious: bool,
    pub confidence: f64,
    pub categories: Vec<String>,
    pub first_seen: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
    pub sources: Vec<ThreatSource>,
}
```

## VirusTotal

### Configuration

```bash
TW_THREAT_INTEL_MODE=virustotal
TW_VIRUSTOTAL_API_KEY=your-api-key-here
```

### Rate Limits

| Tier | Requests/Minute |
|------|-----------------|
| Free | 4 |
| Premium | 500+ |

The connector automatically handles rate limiting with exponential backoff.

### Supported Lookups

| Method | VT Endpoint | Notes |
|--------|-------------|-------|
| `lookup_hash` | `/files/{hash}` | MD5, SHA1, SHA256 |
| `lookup_url` | `/urls/{url_id}` | Base64-encoded URL |
| `lookup_domain` | `/domains/{domain}` | Domain reputation |
| `lookup_ip` | `/ip_addresses/{ip}` | IP reputation |

### Example Usage

```rust
let connector = VirusTotalConnector::new(api_key)?;

let report = connector.lookup_hash("44d88612fea8a8f36de82e1278abb02f").await?;
println!("Malicious: {}", report.malicious);
println!("Confidence: {:.2}", report.confidence);
println!("Categories: {:?}", report.categories);
```

### Response Mapping

VirusTotal detection ratios map to confidence scores:

| Detection Ratio | Confidence | Classification |
|-----------------|------------|----------------|
| 0% | 0.0 | Clean |
| 1-10% | 0.3 | Suspicious |
| 11-50% | 0.6 | Likely Malicious |
| 51-100% | 0.9 | Malicious |

## Mock Connector

For testing without external API calls:

```bash
TW_THREAT_INTEL_MODE=mock
```

The mock connector returns predictable results based on indicator patterns:

| Pattern | Result |
|---------|--------|
| Contains "malicious" | Malicious, confidence 0.95 |
| Contains "suspicious" | Suspicious, confidence 0.5 |
| Contains "clean" | Clean, confidence 0.1 |
| Default | Clean, confidence 0.2 |

## Python Bridge

Access from Python via the bridge:

```python
from tw_bridge import ThreatIntelBridge

# Create bridge (uses TW_THREAT_INTEL_MODE env var)
bridge = ThreatIntelBridge()

# Or specify mode explicitly
bridge = ThreatIntelBridge("virustotal")

# Lookup hash
result = bridge.lookup_hash("44d88612fea8a8f36de82e1278abb02f")
print(f"Malicious: {result['malicious']}")
print(f"Confidence: {result['confidence']}")

# Lookup URL
result = bridge.lookup_url("https://example.com/suspicious")

# Lookup domain
result = bridge.lookup_domain("malware-site.com")
```

## Caching

Results are cached to reduce API calls:

| Lookup Type | Cache Duration |
|-------------|----------------|
| Hash | 24 hours |
| URL | 1 hour |
| Domain | 6 hours |
| IP | 6 hours |

Cache is stored in the database and shared across instances.

## Adding Custom Providers

Implement the `ThreatIntelConnector` trait:

```rust
pub struct CustomThreatIntelConnector {
    client: reqwest::Client,
    api_key: String,
}

#[async_trait]
impl Connector for CustomThreatIntelConnector {
    fn name(&self) -> &str { "custom" }
    fn connector_type(&self) -> &str { "threat_intel" }
    // ... implement health_check, test_connection
}

#[async_trait]
impl ThreatIntelConnector for CustomThreatIntelConnector {
    async fn lookup_hash(&self, hash: &str) -> ConnectorResult<ThreatReport> {
        // Custom implementation
    }
    // ... implement other methods
}
```

See [Adding Connectors](../development/connectors.md) for full details.
