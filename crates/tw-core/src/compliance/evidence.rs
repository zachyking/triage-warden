//! Evidence tracking for compliance and audit requests.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Individual evidence item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceItem {
    pub id: Uuid,
    pub description: String,
    pub event_ref: Option<Uuid>,
    pub tags: Vec<String>,
    pub collected_at: DateTime<Utc>,
}

impl EvidenceItem {
    /// Creates an evidence item.
    pub fn new(description: impl Into<String>, event_ref: Option<Uuid>, tags: Vec<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            description: description.into(),
            event_ref,
            tags,
            collected_at: Utc::now(),
        }
    }
}

/// Chain-of-custody event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainOfCustodyEntry {
    pub timestamp: DateTime<Utc>,
    pub actor: String,
    pub action: String,
    pub notes: Option<String>,
}

/// Evidence package for auditor delivery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidencePackage {
    pub id: Uuid,
    pub name: String,
    pub request_id: Option<String>,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    pub evidence_items: Vec<EvidenceItem>,
    pub chain_of_custody: Vec<ChainOfCustodyEntry>,
    pub generated_at: DateTime<Utc>,
    pub checksum: String,
}

impl EvidencePackage {
    /// Creates a package and computes checksum.
    pub fn new(
        name: impl Into<String>,
        request_id: Option<String>,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        evidence_items: Vec<EvidenceItem>,
    ) -> Self {
        let generated_at = Utc::now();
        let mut package = Self {
            id: Uuid::new_v4(),
            name: name.into(),
            request_id,
            start,
            end,
            evidence_items,
            chain_of_custody: vec![ChainOfCustodyEntry {
                timestamp: generated_at,
                actor: "system".to_string(),
                action: "package_created".to_string(),
                notes: None,
            }],
            generated_at,
            checksum: String::new(),
        };
        package.checksum = package.compute_checksum();
        package
    }

    /// Adds custody event and refreshes checksum.
    pub fn add_custody_event(
        &mut self,
        actor: impl Into<String>,
        action: impl Into<String>,
        notes: Option<String>,
    ) {
        self.chain_of_custody.push(ChainOfCustodyEntry {
            timestamp: Utc::now(),
            actor: actor.into(),
            action: action.into(),
            notes,
        });
        self.checksum = self.compute_checksum();
    }

    /// Computes package checksum.
    pub fn compute_checksum(&self) -> String {
        let payload = serde_json::json!({
            "id": self.id,
            "name": self.name,
            "request_id": self.request_id,
            "start": self.start.to_rfc3339(),
            "end": self.end.to_rfc3339(),
            "evidence_items": self.evidence_items,
            "chain_of_custody": self.chain_of_custody,
            "generated_at": self.generated_at.to_rfc3339(),
        });
        let mut hasher = Sha256::new();
        hasher.update(serde_json::to_vec(&payload).unwrap_or_default());
        hex::encode(hasher.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_package_checksum_updates_after_custody_event() {
        let item = EvidenceItem::new("entry", None, vec!["soc2".to_string()]);
        let mut package = EvidencePackage::new("pkg", None, Utc::now(), Utc::now(), vec![item]);
        let original = package.checksum.clone();
        package.add_custody_event("auditor", "downloaded", None);
        assert_ne!(original, package.checksum);
    }
}
