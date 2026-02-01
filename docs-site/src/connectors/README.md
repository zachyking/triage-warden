# Connectors

Connectors integrate Triage Warden with external security tools and services.

## Overview

Each connector type has a trait interface and multiple implementations:

| Type | Purpose | Implementations |
|------|---------|-----------------|
| Threat Intelligence | Hash/URL/domain reputation | VirusTotal, Mock |
| SIEM | Log queries and correlation | Splunk, Mock |
| EDR | Endpoint detection and response | CrowdStrike, Mock |
| Email Gateway | Email security operations | Microsoft 365, Mock |
| Ticketing | Incident ticket management | Jira, Mock |

## Configuration

Select connector implementations via environment variables:

```bash
# Use real connectors
TW_THREAT_INTEL_MODE=virustotal
TW_SIEM_MODE=splunk
TW_EDR_MODE=crowdstrike
TW_EMAIL_GATEWAY_MODE=m365
TW_TICKETING_MODE=jira

# Or use mocks for testing
TW_THREAT_INTEL_MODE=mock
TW_SIEM_MODE=mock
```

## Connector Trait

All connectors implement the base `Connector` trait:

```rust
#[async_trait]
pub trait Connector: Send + Sync {
    /// Unique identifier for this connector instance
    fn name(&self) -> &str;

    /// Type of connector (threat_intel, siem, edr, etc.)
    fn connector_type(&self) -> &str;

    /// Check connector health
    async fn health_check(&self) -> ConnectorResult<ConnectorHealth>;

    /// Test connection to the service
    async fn test_connection(&self) -> ConnectorResult<bool>;
}

pub enum ConnectorHealth {
    Healthy,
    Degraded { message: String },
    Unhealthy { message: String },
}
```

## Error Handling

Connectors return `ConnectorResult<T>` with detailed error types:

```rust
pub enum ConnectorError {
    /// Service returned an error
    RequestFailed(String),

    /// Resource not found
    NotFound(String),

    /// Authentication failed
    AuthenticationFailed(String),

    /// Rate limit exceeded
    RateLimited { retry_after: Option<Duration> },

    /// Network or connection error
    NetworkError(String),

    /// Invalid response from service
    InvalidResponse(String),
}
```

## Health Monitoring

Check connector health via the API:

```bash
curl http://localhost:8080/api/connectors/health

{
  "connectors": [
    { "name": "virustotal", "type": "threat_intel", "status": "healthy" },
    { "name": "splunk", "type": "siem", "status": "healthy" },
    { "name": "crowdstrike", "type": "edr", "status": "degraded", "message": "High latency" }
  ]
}
```

## Next Steps

- [Threat Intelligence](./threat-intel.md) - VirusTotal configuration
- [SIEM](./siem.md) - Splunk configuration
- [EDR](./edr.md) - CrowdStrike configuration
- [Email Gateway](./email-gateway.md) - Microsoft 365 configuration
- [Ticketing](./ticketing.md) - Jira configuration
