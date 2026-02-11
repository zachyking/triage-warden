# Attack Surface Integration

Correlate incidents with known vulnerabilities and external exposures using integrations with vulnerability scanners and attack surface monitoring platforms.

## Overview

The attack surface module (Stage 5.2) connects Triage Warden to:

- **Vulnerability scanners** -- Qualys, Tenable, and Rapid7 for known vulnerability data
- **Attack surface monitors** -- Censys and SecurityScorecard for external exposure discovery
- **Risk scoring** -- combined risk assessment using vulnerability and exposure data

## Vulnerability Scanners

### Supported Platforms

| Platform | Connector | Capabilities |
|----------|-----------|-------------|
| Qualys | `QualysConnector` | Asset vulns, scan results, CVE lookup, recent findings |
| Tenable | `TenableConnector` | Asset vulns, scan results, CVE lookup, recent findings |
| Rapid7 | `Rapid7Connector` | Asset vulns, scan results, CVE lookup, recent findings |

### VulnerabilityScanner Trait

All scanners implement the same trait, making them interchangeable:

```rust
pub trait VulnerabilityScanner: Connector {
    async fn get_vulnerabilities_for_asset(&self, asset_id: &str) -> Vec<Vulnerability>;
    async fn get_scan_results(&self, scan_id: &str) -> ScanResult;
    async fn get_recent_vulnerabilities(&self, since: DateTime, limit: Option<usize>) -> Vec<Vulnerability>;
    async fn get_vulnerability_by_cve(&self, cve_id: &str) -> Option<Vulnerability>;
}
```

### Vulnerability Data

Each vulnerability includes:

| Field | Description |
|-------|-------------|
| `cve_id` | CVE identifier (if assigned) |
| `severity` | Informational, Low, Medium, High, Critical |
| `cvss_score` | CVSS base score (0.0 - 10.0) |
| `affected_asset_ids` | Which assets are affected |
| `exploit_available` | Whether a public exploit exists |
| `patch_available` | Whether a vendor patch is available |
| `status` | Open, Remediated, Accepted, FalsePositive |

### Scan Results

Query scan results for summary data:

| Field | Description |
|-------|-------------|
| `total_hosts` | Number of hosts scanned |
| `vulnerabilities_found` | Total vulnerabilities discovered |
| `critical_count` | Critical severity findings |
| `high_count` | High severity findings |
| `status` | Pending, Running, Completed, Failed, Cancelled |

## Attack Surface Monitoring

### Supported Platforms

| Platform | Connector | Capabilities |
|----------|-----------|-------------|
| Censys | `CensysConnector` | Domain exposures, asset exposure, risk scoring |
| SecurityScorecard | `ScorecardConnector` | Domain exposures, asset exposure, risk scoring |

### AttackSurfaceMonitor Trait

```rust
pub trait AttackSurfaceMonitor: Connector {
    async fn get_exposures(&self, domain: &str) -> Vec<ExternalExposure>;
    async fn get_asset_exposure(&self, asset_id: &str) -> Vec<ExternalExposure>;
    async fn get_risk_score(&self, domain: &str) -> Option<f32>;
}
```

### Exposure Types

The system detects these categories of external exposure:

| Type | Description | Example |
|------|-------------|---------|
| `open_port` | Open network port with identified service | Port 22 running SSH |
| `expired_certificate` | TLS certificate past its expiry date | `example.com` cert expired |
| `weak_cipher` | Deprecated or weak TLS cipher in use | RC4 cipher detected |
| `exposed_service` | Publicly accessible service that may be unintended | Elasticsearch on public IP |
| `dns_issue` | DNS misconfiguration | Missing SPF record |
| `misconfigured_header` | Missing or incorrect HTTP security header | No X-Frame-Options |

Each exposure includes a risk score (0.0 to 100.0) and structured details.

## Risk Scoring

Risk scores from vulnerability scanners and ASM platforms are combined during incident triage to assess the exposure of affected assets. When the AI agent triages an incident involving a compromised host, it can check:

1. What known vulnerabilities exist on the host
2. Whether public exploits are available for those vulnerabilities
3. What external exposures exist for the host or its domain
4. The overall risk score for the affected domain

This context helps the agent make more accurate severity assessments and recommend appropriate response actions.

## Configuration

Add vulnerability scanner and ASM connectors in `config/default.yaml`:

```yaml
connectors:
  qualys:
    connector_type: qualys
    enabled: true
    base_url: https://qualysapi.qualys.com
    api_key: ${QUALYS_USERNAME}
    api_secret: ${QUALYS_PASSWORD}
    timeout_secs: 60

  censys:
    connector_type: censys
    enabled: true
    base_url: https://search.censys.io
    api_key: ${CENSYS_API_ID}
    api_secret: ${CENSYS_SECRET}
    timeout_secs: 30
```
