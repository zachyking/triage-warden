# Testing

Guide to testing Triage Warden.

## Test Structure

```
triage-warden/
├── crates/
│   ├── tw-api/src/
│   │   └── tests/           # API integration tests
│   ├── tw-core/src/
│   │   └── tests/           # Core unit tests
│   └── tw-actions/src/
│       └── tests/           # Action handler tests
└── python/
    └── tests/               # Python tests
```

## Running Tests

### All Tests

```bash
# Rust
cargo test

# Python
cd python && uv run pytest

# Everything
./scripts/test-all.sh
```

### Specific Tests

```bash
# Single crate
cargo test -p tw-api

# Single test
cargo test test_incident_creation

# Pattern match
cargo test incident

# With output
cargo test -- --nocapture
```

## Unit Tests

### Rust Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_incident_creation() {
        let incident = Incident::new(
            IncidentType::Phishing,
            Severity::High,
        );
        assert_eq!(incident.status, IncidentStatus::Open);
    }

    #[tokio::test]
    async fn test_async_operation() {
        let result = async_function().await;
        assert!(result.is_ok());
    }
}
```

### Python Unit Tests

```python
import pytest
from tw_ai.agents import TriageAgent

def test_agent_creation():
    agent = TriageAgent()
    assert agent.model == "claude-sonnet-4-20250514"

@pytest.mark.asyncio
async def test_triage():
    agent = TriageAgent()
    verdict = await agent.triage(mock_incident)
    assert verdict.classification in ["malicious", "benign"]
```

## Integration Tests

### API Integration Tests

```rust
#[tokio::test]
async fn test_incident_api() {
    let app = create_test_app().await;

    // Create incident
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/incidents")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"type":"phishing"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
}
```

### Database Tests

```rust
#[tokio::test]
async fn test_repository() {
    // Use in-memory SQLite
    let pool = create_test_pool().await;
    let repo = SqliteIncidentRepository::new(pool);

    let incident = repo.create(&new_incident).await.unwrap();
    let found = repo.get(incident.id).await.unwrap();

    assert_eq!(found.unwrap().id, incident.id);
}
```

## Test Fixtures

### Rust Fixtures

```rust
// tests/fixtures.rs
pub fn mock_incident() -> Incident {
    Incident {
        id: Uuid::new_v4(),
        incident_type: IncidentType::Phishing,
        severity: Severity::High,
        status: IncidentStatus::Open,
        raw_data: json!({"subject": "Test"}),
        ..Default::default()
    }
}
```

### Python Fixtures

```python
# tests/conftest.py
import pytest

@pytest.fixture
def mock_incident():
    return {
        "id": "test-123",
        "type": "phishing",
        "severity": "high",
        "raw_data": {"subject": "Test Email"}
    }

@pytest.fixture
def mock_connector():
    return MockThreatIntelConnector()
```

## Mocking

### Rust Mocking

```rust
use mockall::mock;

mock! {
    ThreatIntelConnector {}

    #[async_trait]
    impl ThreatIntelConnector for ThreatIntelConnector {
        async fn lookup_hash(&self, hash: &str) -> ConnectorResult<ThreatReport>;
    }
}

#[tokio::test]
async fn test_with_mock() {
    let mut mock = MockThreatIntelConnector::new();
    mock.expect_lookup_hash()
        .returning(|_| Ok(ThreatReport::clean()));

    let result = function_using_connector(&mock).await;
    assert!(result.is_ok());
}
```

### Python Mocking

```python
from unittest.mock import AsyncMock, patch

@pytest.mark.asyncio
async def test_with_mock():
    with patch("tw_ai.agents.tools.lookup_hash") as mock:
        mock.return_value = {"malicious": False}

        agent = TriageAgent()
        verdict = await agent.triage(mock_incident)

        mock.assert_called_once()
```

## Test Coverage

### Rust Coverage

```bash
cargo install cargo-tarpaulin
cargo tarpaulin --out Html
```

### Python Coverage

```bash
cd python
uv run pytest --cov=tw_ai --cov-report=html
```

## CI Testing

GitHub Actions runs tests on every PR:

```yaml
# .github/workflows/test.yml
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo test
      - run: cargo clippy -- -D warnings
```

## Test Data

### Evaluation Test Cases

Test cases for AI triage evaluation:

```yaml
# python/tw_ai/evaluation/test_cases/phishing.yaml
- name: obvious_phishing
  input:
    sender: "security@fake-bank.com"
    subject: "Urgent: Verify Account"
    urls: ["https://phishing-site.com/login"]
    auth_results: {spf: fail, dkim: fail}
  expected:
    classification: malicious
    min_confidence: 0.8
```

Run evaluation:

```bash
cd python
uv run pytest tests/test_evaluation.py
```
