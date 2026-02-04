# Triage Warden Load Testing Tool

A Rust-based load testing tool for validating Triage Warden's Stage 1 performance requirements.

## Performance Requirements (Stage 1)

| Requirement | Target | Description |
|-------------|--------|-------------|
| Throughput | 10,000 alerts/day | ~7 alerts/minute sustained |
| P99 Latency | <500ms | 99th percentile response time |
| Cache Hit Rate | >80% | For repeated enrichment lookups |
| Error Rate | <1% | Under sustained load |

## Building

```bash
# From the repository root
cd tests/load
cargo build --release

# The binary will be at:
# target/release/tw-load-test
```

## Quick Start

```bash
# Run all tests against local instance
./tw-load-test --target http://localhost:8080 all

# Just check health
./tw-load-test --target http://localhost:8080 health

# Sustained load test (validates throughput)
./tw-load-test --target http://localhost:8080 sustained --rate 10 --duration 5

# Burst load test (validates P99 latency)
./tw-load-test --target http://localhost:8080 burst --concurrency 50 --requests 500

# Cache validation test
./tw-load-test --target http://localhost:8080 cache --requests 100 --unique-values 10
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `TW_TARGET_URL` | Base URL of Triage Warden API | `http://localhost:8080` |
| `TW_WEBHOOK_SECRET` | Secret for HMAC-SHA256 webhook signatures | (none) |
| `TW_API_KEY` | API key for authenticated endpoints | (none) |

### Command Line Options

```
tw-load-test [OPTIONS] <COMMAND>

Options:
  -t, --target <URL>           Target base URL [default: http://localhost:8080]
  -s, --webhook-secret <KEY>   Webhook secret for signing requests
  -k, --api-key <KEY>          API key for authenticated endpoints
  -v, --verbose                Enable verbose output
  -h, --help                   Print help
  -V, --version                Print version
```

## Test Scenarios

### 1. Sustained Load Test

Validates that the system can handle consistent traffic over time.

```bash
tw-load-test sustained [OPTIONS]

Options:
  -r, --rate <RATE>        Requests per minute [default: 10]
  -d, --duration <MINS>    Duration in minutes [default: 5]
```

**What it tests:**
- Webhook ingestion endpoint (`POST /api/webhooks/alerts`)
- Throughput stability over time
- Memory/resource leak detection (via duration)

**Success criteria:**
- Error rate < 1%
- P99 latency < 500ms

### 2. Burst Load Test

Validates system behavior under sudden load spikes.

```bash
tw-load-test burst [OPTIONS]

Options:
  -c, --concurrency <N>    Concurrent requests [default: 50]
  -r, --requests <N>       Total requests [default: 500]
```

**What it tests:**
- Concurrent request handling
- Connection pooling effectiveness
- P99 latency under load

**Success criteria:**
- Error rate < 1%
- P99 latency < 500ms (Stage 1 requirement)

### 3. Cache Validation Test

Validates caching effectiveness for repeated requests.

```bash
tw-load-test cache [OPTIONS]

Options:
  -r, --requests <N>       Total requests [default: 100]
  -u, --unique-values <N>  Unique values to cycle [default: 10]
```

**What it tests:**
- GET requests to incidents endpoint
- Latency consistency (indicates cache hits)
- Response time improvement with caching

**Note:** Actual cache hit rate should be verified via `/health/detailed` endpoint or Prometheus metrics (`tw_cache_hits_total` / `tw_cache_misses_total`).

### 4. Health Check

Quick validation of endpoint availability.

```bash
tw-load-test health
```

### 5. Full Suite (All Tests)

Runs all scenarios and produces a comprehensive report.

```bash
tw-load-test all [OPTIONS]

Options:
  -d, --duration <MINS>    Duration for sustained test [default: 2]
```

## Example Output

```
============================================================
  Triage Warden Load Testing Tool
============================================================
  Target: http://localhost:8080
  Webhook Secret: configured

Checking target availability...
[OK] Target is healthy

Starting Burst Load Test
  Concurrency: 50 simultaneous requests
  Total: 500 requests
 [00:00:05] [########################################] 500/500 (100%) Complete

============================================================
Burst Load Test Results
============================================================

Duration:                 5.23s
Total Requests:           500
Successful:               498
Failed:                   2
Throughput:               95.60 req/s
Error Rate:               0.40%

Latency Statistics (ms):
  Mean:                   52.34
  Std Dev:                18.72
  P50:                    48.00
  P95:                    89.00
  P99:                    142.00
  Max:                    287.00

Requirement Checks:
  [PASS] P99 latency < 500ms: 142.00ms
  [PASS] Error rate < 1%: 0.40%

Load test completed successfully.
```

## Integration with CI/CD

### GitHub Actions Example

```yaml
jobs:
  load-test:
    runs-on: ubuntu-latest
    services:
      triage-warden:
        image: ghcr.io/triage-warden/triage-warden:latest
        ports:
          - 8080:8080
    steps:
      - uses: actions/checkout@v4
      - name: Build load test tool
        working-directory: tests/load
        run: cargo build --release
      - name: Run load tests
        run: |
          ./target/release/tw-load-test \
            --target http://localhost:8080 \
            all --duration 1
```

### Docker Usage

```bash
# Build the load test image (if containerized)
docker build -t tw-load-test -f tests/load/Dockerfile .

# Run against a target
docker run --rm tw-load-test \
  --target http://host.docker.internal:8080 \
  burst --concurrency 50
```

## Webhook Signature

When `TW_WEBHOOK_SECRET` is set, the tool automatically signs requests using HMAC-SHA256:

```
X-Signature-256: sha256=<hex-encoded-signature>
```

This matches the signature format expected by the Triage Warden webhook endpoint.

## Interpreting Results

### Latency Percentiles

- **P50 (Median)**: Typical response time
- **P95**: Response time for 95% of requests
- **P99**: Response time for 99% of requests (Stage 1 target: <500ms)

### Throughput

- Measured in requests per second (req/s)
- Stage 1 target: ~7 alerts/minute = ~0.12 req/s sustained
- Higher throughput indicates headroom for growth

### Error Rate

- Percentage of failed requests
- Should be <1% for normal operation
- Common errors:
  - `HTTP 429`: Rate limit exceeded
  - `HTTP 503`: Service unavailable
  - `Connection refused`: Target not running

## Troubleshooting

### "Cannot reach target"

1. Verify Triage Warden is running: `curl http://localhost:8080/health`
2. Check firewall/network settings
3. Verify the correct port is exposed

### "HTTP 401 Unauthorized"

Set the webhook secret:
```bash
export TW_WEBHOOK_SECRET="your-secret-here"
tw-load-test burst
```

### "HTTP 429 Too Many Requests"

The rate limiter is working. Either:
- Reduce the request rate
- Increase rate limits in Triage Warden config
- Wait for the rate limit window to reset

### High Error Rate

1. Check Triage Warden logs for errors
2. Verify database connectivity
3. Check resource utilization (CPU, memory)
4. Review rate limit configuration

## Contributing

When adding new test scenarios:

1. Add a new variant to the `Commands` enum
2. Implement the test logic in `LoadTestRunner`
3. Update the CLI argument parsing
4. Document the new scenario in this README
