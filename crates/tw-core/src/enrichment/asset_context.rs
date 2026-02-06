//! Asset-aware enrichment context.
//!
//! Provides functions for enriching incidents with asset and identity context
//! from the context store, including severity adjustment based on asset criticality.

use crate::asset_store::{AssetStore, IdentityStore};
use crate::incident::{Incident, Severity};
use crate::models::{Criticality, IdentifierType};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Context about an asset involved in an incident.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetContext {
    /// ID of the matched asset.
    pub asset_id: Uuid,
    /// Name of the asset.
    pub asset_name: String,
    /// Business criticality of the asset.
    pub criticality: Criticality,
    /// Owner identity ID, if known.
    pub owner: Option<Uuid>,
    /// Deployment environment.
    pub environment: String,
}

/// Context about an identity involved in an incident.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityContext {
    /// ID of the matched identity.
    pub identity_id: Uuid,
    /// Display name of the identity.
    pub display_name: String,
    /// Risk score of the identity.
    pub risk_score: f32,
    /// Department of the identity.
    pub department: Option<String>,
}

/// Result of enriching an incident with asset/identity context.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AssetEnrichmentResult {
    /// Assets matched from the incident.
    pub assets: Vec<AssetContext>,
    /// Identities matched from the incident.
    pub identities: Vec<IdentityContext>,
    /// Adjusted severity based on asset criticality.
    pub adjusted_severity: Option<Severity>,
}

/// Enriches an incident with asset and identity context by extracting
/// identifiers (hostnames, IPs, usernames) from the incident's alert data
/// and looking them up in the stores.
pub async fn enrich_with_asset_context(
    incident: &Incident,
    asset_store: &dyn AssetStore,
    identity_store: &dyn IdentityStore,
) -> AssetEnrichmentResult {
    let mut result = AssetEnrichmentResult::default();
    let tenant_id = incident.tenant_id;

    // Extract identifiers from alert_data
    let hostnames = extract_string_fields(
        &incident.alert_data,
        &["hostname", "host", "computer_name", "device_name"],
    );
    let ips = extract_string_fields(
        &incident.alert_data,
        &[
            "src_ip",
            "dst_ip",
            "ip",
            "ip_address",
            "source_ip",
            "dest_ip",
        ],
    );
    let usernames = extract_string_fields(
        &incident.alert_data,
        &["username", "user", "email", "user_email", "account_name"],
    );

    // Look up assets by hostname
    for hostname in &hostnames {
        if let Ok(Some(asset)) = asset_store
            .find_by_identifier(tenant_id, &IdentifierType::Hostname, hostname)
            .await
        {
            result.assets.push(AssetContext {
                asset_id: asset.id,
                asset_name: asset.name.clone(),
                criticality: asset.criticality,
                owner: asset.owner,
                environment: format!("{}", asset.environment),
            });
        }
    }

    // Look up assets by IP
    for ip in &ips {
        if let Ok(Some(asset)) = asset_store
            .find_by_identifier(tenant_id, &IdentifierType::Ipv4, ip)
            .await
        {
            // Avoid duplicates
            if !result.assets.iter().any(|a| a.asset_id == asset.id) {
                result.assets.push(AssetContext {
                    asset_id: asset.id,
                    asset_name: asset.name.clone(),
                    criticality: asset.criticality,
                    owner: asset.owner,
                    environment: format!("{}", asset.environment),
                });
            }
        }
    }

    // Look up identities by username/email
    for username in &usernames {
        if let Ok(Some(identity)) = identity_store.find_by_identifier(tenant_id, username).await {
            result.identities.push(IdentityContext {
                identity_id: identity.id,
                display_name: identity.display_name.clone(),
                risk_score: identity.risk_score,
                department: identity.department.clone(),
            });
        }
    }

    // Adjust severity based on asset criticality
    result.adjusted_severity = adjust_severity(&incident.severity, &result.assets);

    result
}

/// Adjusts incident severity upward based on the highest-criticality asset involved.
///
/// Rules:
/// - Critical asset + Medium severity -> High
/// - Critical asset + High severity -> Critical
/// - High asset + Medium severity -> High
/// - Otherwise, no adjustment
pub fn adjust_severity(current_severity: &Severity, assets: &[AssetContext]) -> Option<Severity> {
    let max_criticality = assets.iter().map(|a| &a.criticality).max();

    match (max_criticality, current_severity) {
        (Some(Criticality::Critical), Severity::Medium) => Some(Severity::High),
        (Some(Criticality::Critical), Severity::High) => Some(Severity::Critical),
        (Some(Criticality::High), Severity::Medium) => Some(Severity::High),
        _ => None,
    }
}

/// Extracts string values from a JSON object by field names.
fn extract_string_fields(data: &serde_json::Value, field_names: &[&str]) -> Vec<String> {
    let mut values = Vec::new();
    if let Some(obj) = data.as_object() {
        for field in field_names {
            if let Some(value) = obj.get(*field) {
                if let Some(s) = value.as_str() {
                    if !s.is_empty() {
                        values.push(s.to_string());
                    }
                }
            }
        }
    }
    values
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset_store::{InMemoryAssetStore, InMemoryIdentityStore};
    use crate::incident::{Alert, AlertSource};
    use crate::models::{Asset, AssetIdentifier, AssetType, Environment, Identity, IdentityType};

    fn test_tenant() -> Uuid {
        Uuid::from_u128(0x12345678_1234_1234_1234_123456789012)
    }

    async fn setup_stores() -> (InMemoryAssetStore, InMemoryIdentityStore) {
        let asset_store = InMemoryAssetStore::new();
        let identity_store = InMemoryIdentityStore::new();
        let tenant = test_tenant();

        // Create a critical server
        let mut server = Asset::new(
            tenant,
            "prod-db-01".to_string(),
            AssetType::Database,
            Criticality::Critical,
            Environment::Production,
        );
        server.add_identifier(AssetIdentifier::new(
            IdentifierType::Hostname,
            "prod-db-01".to_string(),
            "cmdb".to_string(),
        ));
        server.add_identifier(AssetIdentifier::new(
            IdentifierType::Ipv4,
            "10.0.1.100".to_string(),
            "scanner".to_string(),
        ));
        asset_store.create(&server).await.unwrap();

        // Create a workstation
        let mut ws = Asset::new(
            tenant,
            "ws-001".to_string(),
            AssetType::Workstation,
            Criticality::Low,
            Environment::Production,
        );
        ws.add_identifier(AssetIdentifier::new(
            IdentifierType::Hostname,
            "ws-001".to_string(),
            "edr".to_string(),
        ));
        asset_store.create(&ws).await.unwrap();

        // Create a user identity
        let identity = Identity::new(
            tenant,
            IdentityType::User,
            "jdoe@corp.com".to_string(),
            "John Doe".to_string(),
        );
        identity_store.create(&identity).await.unwrap();

        (asset_store, identity_store)
    }

    fn create_incident_with_data(data: serde_json::Value) -> Incident {
        let alert = Alert {
            id: "test-alert".to_string(),
            source: AlertSource::Edr("CrowdStrike".to_string()),
            alert_type: "malware".to_string(),
            severity: Severity::Medium,
            title: "Test alert".to_string(),
            description: None,
            data,
            timestamp: chrono::Utc::now(),
            tags: vec![],
        };
        let mut incident = Incident::from_alert(alert);
        incident.tenant_id = test_tenant();
        incident
    }

    #[tokio::test]
    async fn test_enrich_with_hostname() {
        let (asset_store, identity_store) = setup_stores().await;

        let incident = create_incident_with_data(serde_json::json!({
            "hostname": "prod-db-01",
            "username": "jdoe@corp.com"
        }));

        let result = enrich_with_asset_context(&incident, &asset_store, &identity_store).await;

        assert_eq!(result.assets.len(), 1);
        assert_eq!(result.assets[0].asset_name, "prod-db-01");
        assert_eq!(result.assets[0].criticality, Criticality::Critical);

        assert_eq!(result.identities.len(), 1);
        assert_eq!(result.identities[0].display_name, "John Doe");
    }

    #[tokio::test]
    async fn test_enrich_with_ip() {
        let (asset_store, identity_store) = setup_stores().await;

        let incident = create_incident_with_data(serde_json::json!({
            "src_ip": "10.0.1.100"
        }));

        let result = enrich_with_asset_context(&incident, &asset_store, &identity_store).await;

        assert_eq!(result.assets.len(), 1);
        assert_eq!(result.assets[0].asset_name, "prod-db-01");
    }

    #[tokio::test]
    async fn test_enrich_no_duplicates() {
        let (asset_store, identity_store) = setup_stores().await;

        // Both hostname and IP point to the same asset
        let incident = create_incident_with_data(serde_json::json!({
            "hostname": "prod-db-01",
            "src_ip": "10.0.1.100"
        }));

        let result = enrich_with_asset_context(&incident, &asset_store, &identity_store).await;

        // Should only appear once despite matching on both hostname and IP
        assert_eq!(result.assets.len(), 1);
    }

    #[tokio::test]
    async fn test_enrich_no_match() {
        let (asset_store, identity_store) = setup_stores().await;

        let incident = create_incident_with_data(serde_json::json!({
            "hostname": "unknown-host",
            "username": "unknown@example.com"
        }));

        let result = enrich_with_asset_context(&incident, &asset_store, &identity_store).await;

        assert!(result.assets.is_empty());
        assert!(result.identities.is_empty());
        assert!(result.adjusted_severity.is_none());
    }

    #[tokio::test]
    async fn test_severity_adjustment_critical_asset_medium_severity() {
        let assets = vec![AssetContext {
            asset_id: Uuid::new_v4(),
            asset_name: "critical-server".to_string(),
            criticality: Criticality::Critical,
            owner: None,
            environment: "Production".to_string(),
        }];

        let adjusted = adjust_severity(&Severity::Medium, &assets);
        assert_eq!(adjusted, Some(Severity::High));
    }

    #[tokio::test]
    async fn test_severity_adjustment_critical_asset_high_severity() {
        let assets = vec![AssetContext {
            asset_id: Uuid::new_v4(),
            asset_name: "critical-server".to_string(),
            criticality: Criticality::Critical,
            owner: None,
            environment: "Production".to_string(),
        }];

        let adjusted = adjust_severity(&Severity::High, &assets);
        assert_eq!(adjusted, Some(Severity::Critical));
    }

    #[tokio::test]
    async fn test_severity_adjustment_high_asset_medium_severity() {
        let assets = vec![AssetContext {
            asset_id: Uuid::new_v4(),
            asset_name: "important-server".to_string(),
            criticality: Criticality::High,
            owner: None,
            environment: "Production".to_string(),
        }];

        let adjusted = adjust_severity(&Severity::Medium, &assets);
        assert_eq!(adjusted, Some(Severity::High));
    }

    #[tokio::test]
    async fn test_severity_no_adjustment_low_asset() {
        let assets = vec![AssetContext {
            asset_id: Uuid::new_v4(),
            asset_name: "dev-laptop".to_string(),
            criticality: Criticality::Low,
            owner: None,
            environment: "Development".to_string(),
        }];

        let adjusted = adjust_severity(&Severity::Medium, &assets);
        assert!(adjusted.is_none());
    }

    #[tokio::test]
    async fn test_severity_no_adjustment_already_critical() {
        let assets = vec![AssetContext {
            asset_id: Uuid::new_v4(),
            asset_name: "critical-server".to_string(),
            criticality: Criticality::Critical,
            owner: None,
            environment: "Production".to_string(),
        }];

        let adjusted = adjust_severity(&Severity::Critical, &assets);
        assert!(adjusted.is_none());
    }

    #[test]
    fn test_extract_string_fields() {
        let data = serde_json::json!({
            "hostname": "server-01",
            "src_ip": "192.168.1.1",
            "empty_field": "",
            "number_field": 42
        });

        let hostnames = extract_string_fields(&data, &["hostname", "computer_name"]);
        assert_eq!(hostnames, vec!["server-01"]);

        let ips = extract_string_fields(&data, &["src_ip", "dst_ip"]);
        assert_eq!(ips, vec!["192.168.1.1"]);

        // Empty string should be excluded
        let empty = extract_string_fields(&data, &["empty_field"]);
        assert!(empty.is_empty());

        // Non-string should be excluded
        let nums = extract_string_fields(&data, &["number_field"]);
        assert!(nums.is_empty());
    }

    #[test]
    fn test_asset_context_serialization() {
        let ctx = AssetContext {
            asset_id: Uuid::new_v4(),
            asset_name: "test-server".to_string(),
            criticality: Criticality::High,
            owner: None,
            environment: "Production".to_string(),
        };

        let json = serde_json::to_string(&ctx).unwrap();
        let deserialized: AssetContext = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.asset_name, "test-server");
    }

    #[test]
    fn test_identity_context_serialization() {
        let ctx = IdentityContext {
            identity_id: Uuid::new_v4(),
            display_name: "Jane Doe".to_string(),
            risk_score: 45.0,
            department: Some("Engineering".to_string()),
        };

        let json = serde_json::to_string(&ctx).unwrap();
        let deserialized: IdentityContext = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.display_name, "Jane Doe");
        assert_eq!(deserialized.risk_score, 45.0);
    }
}
