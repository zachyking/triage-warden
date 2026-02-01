# Adding Connectors

Guide to implementing new connectors.

## Connector Architecture

Connectors follow a trait-based pattern:

```
Connector Trait (base)
    │
    ├── ThreatIntelConnector
    ├── SIEMConnector
    ├── EDRConnector
    ├── EmailGatewayConnector
    └── TicketingConnector
```

## Implementing a Connector

### 1. Create the File

```bash
touch crates/tw-connectors/src/threat_intel/my_provider.rs
```

### 2. Implement Base Trait

```rust
use crate::traits::{Connector, ConnectorError, ConnectorHealth, ConnectorResult};
use async_trait::async_trait;

pub struct MyProviderConnector {
    client: reqwest::Client,
    api_key: String,
    base_url: String,
}

impl MyProviderConnector {
    pub fn new(api_key: String) -> Result<Self, ConnectorError> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| ConnectorError::Configuration(e.to_string()))?;

        Ok(Self {
            client,
            api_key,
            base_url: "https://api.myprovider.com".to_string(),
        })
    }
}

#[async_trait]
impl Connector for MyProviderConnector {
    fn name(&self) -> &str {
        "my_provider"
    }

    fn connector_type(&self) -> &str {
        "threat_intel"
    }

    async fn health_check(&self) -> ConnectorResult<ConnectorHealth> {
        let response = self.client
            .get(format!("{}/health", self.base_url))
            .header("Authorization", format!("Bearer {}", self.api_key))
            .send()
            .await
            .map_err(|e| ConnectorError::NetworkError(e.to_string()))?;

        if response.status().is_success() {
            Ok(ConnectorHealth::Healthy)
        } else {
            Ok(ConnectorHealth::Unhealthy {
                message: "Health check failed".to_string(),
            })
        }
    }

    async fn test_connection(&self) -> ConnectorResult<bool> {
        match self.health_check().await? {
            ConnectorHealth::Healthy => Ok(true),
            _ => Ok(false),
        }
    }
}
```

### 3. Implement Specialized Trait

```rust
use crate::traits::{ThreatIntelConnector, ThreatReport, IndicatorType};

#[async_trait]
impl ThreatIntelConnector for MyProviderConnector {
    async fn lookup_hash(&self, hash: &str) -> ConnectorResult<ThreatReport> {
        let response = self.client
            .get(format!("{}/files/{}", self.base_url, hash))
            .header("Authorization", format!("Bearer {}", self.api_key))
            .send()
            .await
            .map_err(|e| ConnectorError::NetworkError(e.to_string()))?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(ThreatReport {
                indicator: hash.to_string(),
                indicator_type: IndicatorType::FileHash,
                malicious: false,
                confidence: 0.0,
                categories: vec![],
                first_seen: None,
                last_seen: None,
                sources: vec![],
            });
        }

        let data: ApiResponse = response.json().await
            .map_err(|e| ConnectorError::InvalidResponse(e.to_string()))?;

        Ok(self.convert_response(data))
    }

    async fn lookup_url(&self, url: &str) -> ConnectorResult<ThreatReport> {
        // Similar implementation
        todo!()
    }

    async fn lookup_domain(&self, domain: &str) -> ConnectorResult<ThreatReport> {
        // Similar implementation
        todo!()
    }

    async fn lookup_ip(&self, ip: &str) -> ConnectorResult<ThreatReport> {
        // Similar implementation
        todo!()
    }
}
```

### 4. Add to Module

```rust
// crates/tw-connectors/src/threat_intel/mod.rs
mod my_provider;
pub use my_provider::MyProviderConnector;
```

### 5. Register in Bridge

```rust
// tw-bridge/src/lib.rs
impl ThreatIntelBridge {
    pub fn new(mode: &str) -> PyResult<Self> {
        let connector: Arc<dyn ThreatIntelConnector + Send + Sync> = match mode {
            "virustotal" => Arc::new(VirusTotalConnector::new(
                std::env::var("TW_VIRUSTOTAL_API_KEY")
                    .map_err(|_| PyErr::new::<pyo3::exceptions::PyValueError, _>(
                        "TW_VIRUSTOTAL_API_KEY not set"
                    ))?
            )?),
            "my_provider" => Arc::new(MyProviderConnector::new(
                std::env::var("TW_MY_PROVIDER_API_KEY")
                    .map_err(|_| PyErr::new::<pyo3::exceptions::PyValueError, _>(
                        "TW_MY_PROVIDER_API_KEY not set"
                    ))?
            )?),
            _ => Arc::new(MockThreatIntelConnector::new("mock")),
        };

        Ok(Self { connector })
    }
}
```

## Error Handling

Use appropriate error types:

```rust
pub enum ConnectorError {
    /// Configuration issue
    Configuration(String),

    /// Network/connection error
    NetworkError(String),

    /// Authentication failed
    AuthenticationFailed(String),

    /// Resource not found
    NotFound(String),

    /// Rate limited
    RateLimited { retry_after: Option<Duration> },

    /// Invalid response from service
    InvalidResponse(String),

    /// Request failed
    RequestFailed(String),
}
```

## Rate Limiting

Implement rate limiting in your connector:

```rust
use governor::{Quota, RateLimiter};

pub struct MyProviderConnector {
    client: reqwest::Client,
    api_key: String,
    rate_limiter: RateLimiter<...>,
}

impl MyProviderConnector {
    async fn make_request(&self, url: &str) -> ConnectorResult<Response> {
        self.rate_limiter.until_ready().await;

        self.client.get(url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .send()
            .await
            .map_err(|e| ConnectorError::NetworkError(e.to_string()))
    }
}
```

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{MockServer, Mock, ResponseTemplate};
    use wiremock::matchers::{method, path};

    #[tokio::test]
    async fn test_lookup_hash() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/files/abc123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "malicious": true,
                "confidence": 0.95
            })))
            .mount(&mock_server)
            .await;

        let connector = MyProviderConnector::with_base_url(
            "test-key".to_string(),
            mock_server.uri(),
        );

        let result = connector.lookup_hash("abc123").await.unwrap();
        assert!(result.malicious);
    }
}
```

## Documentation

Document your connector:

```rust
//! MyProvider threat intelligence connector.
//!
//! # Configuration
//!
//! Set `TW_MY_PROVIDER_API_KEY` environment variable.
//!
//! # Example
//!
//! ```rust
//! let connector = MyProviderConnector::new(api_key)?;
//! let report = connector.lookup_hash("abc123").await?;
//! ```
```
