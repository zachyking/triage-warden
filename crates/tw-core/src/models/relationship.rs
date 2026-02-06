//! Entity relationship model for the Asset & Identity Context Store.
//!
//! Relationships connect assets and identities, forming a graph that can be
//! traversed during incident enrichment to discover blast radius and context.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A relationship between two entities (assets or identities).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityRelationship {
    /// Unique identifier for this relationship.
    pub id: Uuid,
    /// Tenant that owns this relationship.
    pub tenant_id: Uuid,
    /// Source entity in the relationship.
    pub source_entity: EntityRef,
    /// Target entity in the relationship.
    pub target_entity: EntityRef,
    /// Type of relationship.
    pub relationship_type: RelationshipType,
    /// Confidence or strength of the relationship (0.0 - 1.0).
    pub strength: f32,
    /// Evidence or reasons supporting this relationship.
    pub evidence: Vec<String>,
    /// When this relationship was first observed.
    pub first_seen: DateTime<Utc>,
    /// When this relationship was last observed.
    pub last_seen: DateTime<Utc>,
}

impl EntityRelationship {
    /// Creates a new relationship between two entities.
    pub fn new(
        tenant_id: Uuid,
        source_entity: EntityRef,
        target_entity: EntityRef,
        relationship_type: RelationshipType,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            tenant_id,
            source_entity,
            target_entity,
            relationship_type,
            strength: 1.0,
            evidence: Vec::new(),
            first_seen: now,
            last_seen: now,
        }
    }

    /// Sets the strength of this relationship.
    pub fn with_strength(mut self, strength: f32) -> Self {
        self.strength = strength.clamp(0.0, 1.0);
        self
    }

    /// Adds evidence for this relationship.
    pub fn with_evidence(mut self, evidence: Vec<String>) -> Self {
        self.evidence = evidence;
        self
    }

    /// Updates the last_seen timestamp.
    pub fn touch(&mut self) {
        self.last_seen = Utc::now();
    }

    /// Returns true if this relationship involves the given entity.
    pub fn involves(&self, entity_type: &EntityType, entity_id: &Uuid) -> bool {
        (self.source_entity.entity_type == *entity_type && self.source_entity.id == *entity_id)
            || (self.target_entity.entity_type == *entity_type
                && self.target_entity.id == *entity_id)
    }
}

/// A reference to an entity (asset or identity) in a relationship.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct EntityRef {
    /// Type of entity.
    pub entity_type: EntityType,
    /// ID of the entity.
    pub id: Uuid,
}

impl EntityRef {
    /// Creates a reference to an asset.
    pub fn asset(id: Uuid) -> Self {
        Self {
            entity_type: EntityType::Asset,
            id,
        }
    }

    /// Creates a reference to an identity.
    pub fn identity(id: Uuid) -> Self {
        Self {
            entity_type: EntityType::Identity,
            id,
        }
    }
}

/// Type of entity in a relationship.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum EntityType {
    /// An infrastructure asset.
    Asset,
    /// A user or service identity.
    Identity,
}

impl std::fmt::Display for EntityType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EntityType::Asset => write!(f, "Asset"),
            EntityType::Identity => write!(f, "Identity"),
        }
    }
}

/// Type of relationship between entities.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum RelationshipType {
    /// Identity owns or is responsible for the asset.
    OwnerOf,
    /// Identity uses or has access to the asset.
    UsesAsset,
    /// Identity manages another identity.
    ManagesIdentity,
    /// Identity is a member of a group identity.
    MemberOf,
    /// Asset hosts or runs another asset (e.g., VM on hypervisor).
    Hosts,
    /// Asset connects to another asset over the network.
    ConnectsTo,
    /// Asset depends on another asset.
    DependsOn,
    /// Identity authenticated to an asset.
    AuthenticatedTo,
    /// Custom relationship type.
    Custom(String),
}

impl std::fmt::Display for RelationshipType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RelationshipType::OwnerOf => write!(f, "Owner Of"),
            RelationshipType::UsesAsset => write!(f, "Uses Asset"),
            RelationshipType::ManagesIdentity => write!(f, "Manages Identity"),
            RelationshipType::MemberOf => write!(f, "Member Of"),
            RelationshipType::Hosts => write!(f, "Hosts"),
            RelationshipType::ConnectsTo => write!(f, "Connects To"),
            RelationshipType::DependsOn => write!(f, "Depends On"),
            RelationshipType::AuthenticatedTo => write!(f, "Authenticated To"),
            RelationshipType::Custom(name) => write!(f, "Custom: {}", name),
        }
    }
}

/// Query helper for graph traversal.
pub struct RelationshipQuery {
    /// Entity to start from.
    pub entity_ref: EntityRef,
    /// Optional filter by relationship type.
    pub relationship_types: Option<Vec<RelationshipType>>,
    /// Maximum depth for graph traversal (default: 1).
    pub max_depth: u32,
    /// Minimum strength threshold.
    pub min_strength: f32,
}

impl RelationshipQuery {
    /// Creates a new query starting from the given entity.
    pub fn from_entity(entity_ref: EntityRef) -> Self {
        Self {
            entity_ref,
            relationship_types: None,
            max_depth: 1,
            min_strength: 0.0,
        }
    }

    /// Filters by specific relationship types.
    pub fn with_types(mut self, types: Vec<RelationshipType>) -> Self {
        self.relationship_types = Some(types);
        self
    }

    /// Sets the maximum traversal depth.
    pub fn with_max_depth(mut self, depth: u32) -> Self {
        self.max_depth = depth;
        self
    }

    /// Sets the minimum strength threshold.
    pub fn with_min_strength(mut self, strength: f32) -> Self {
        self.min_strength = strength;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relationship_creation() {
        let tenant_id = Uuid::new_v4();
        let asset_id = Uuid::new_v4();
        let identity_id = Uuid::new_v4();

        let rel = EntityRelationship::new(
            tenant_id,
            EntityRef::identity(identity_id),
            EntityRef::asset(asset_id),
            RelationshipType::OwnerOf,
        );

        assert!(!rel.id.is_nil());
        assert_eq!(rel.tenant_id, tenant_id);
        assert_eq!(rel.source_entity.entity_type, EntityType::Identity);
        assert_eq!(rel.target_entity.entity_type, EntityType::Asset);
        assert_eq!(rel.relationship_type, RelationshipType::OwnerOf);
        assert_eq!(rel.strength, 1.0);
    }

    #[test]
    fn test_relationship_involves() {
        let asset_id = Uuid::new_v4();
        let identity_id = Uuid::new_v4();

        let rel = EntityRelationship::new(
            Uuid::new_v4(),
            EntityRef::identity(identity_id),
            EntityRef::asset(asset_id),
            RelationshipType::UsesAsset,
        );

        assert!(rel.involves(&EntityType::Asset, &asset_id));
        assert!(rel.involves(&EntityType::Identity, &identity_id));
        assert!(!rel.involves(&EntityType::Asset, &Uuid::new_v4()));
    }

    #[test]
    fn test_relationship_with_strength() {
        let rel = EntityRelationship::new(
            Uuid::new_v4(),
            EntityRef::asset(Uuid::new_v4()),
            EntityRef::asset(Uuid::new_v4()),
            RelationshipType::ConnectsTo,
        )
        .with_strength(0.75);

        assert_eq!(rel.strength, 0.75);
    }

    #[test]
    fn test_relationship_with_evidence() {
        let rel = EntityRelationship::new(
            Uuid::new_v4(),
            EntityRef::identity(Uuid::new_v4()),
            EntityRef::asset(Uuid::new_v4()),
            RelationshipType::AuthenticatedTo,
        )
        .with_evidence(vec![
            "SSH login at 2024-01-01".to_string(),
            "RDP session at 2024-01-02".to_string(),
        ]);

        assert_eq!(rel.evidence.len(), 2);
    }

    #[test]
    fn test_entity_ref_constructors() {
        let id = Uuid::new_v4();

        let asset_ref = EntityRef::asset(id);
        assert_eq!(asset_ref.entity_type, EntityType::Asset);
        assert_eq!(asset_ref.id, id);

        let identity_ref = EntityRef::identity(id);
        assert_eq!(identity_ref.entity_type, EntityType::Identity);
        assert_eq!(identity_ref.id, id);
    }

    #[test]
    fn test_relationship_type_display() {
        assert_eq!(format!("{}", RelationshipType::OwnerOf), "Owner Of");
        assert_eq!(format!("{}", RelationshipType::ConnectsTo), "Connects To");
        assert_eq!(format!("{}", RelationshipType::DependsOn), "Depends On");
        assert_eq!(
            format!("{}", RelationshipType::Custom("VPN Tunnel".to_string())),
            "Custom: VPN Tunnel"
        );
    }

    #[test]
    fn test_entity_type_display() {
        assert_eq!(format!("{}", EntityType::Asset), "Asset");
        assert_eq!(format!("{}", EntityType::Identity), "Identity");
    }

    #[test]
    fn test_relationship_serialization() {
        let rel = EntityRelationship::new(
            Uuid::new_v4(),
            EntityRef::identity(Uuid::new_v4()),
            EntityRef::asset(Uuid::new_v4()),
            RelationshipType::OwnerOf,
        )
        .with_strength(0.9)
        .with_evidence(vec!["CMDB record".to_string()]);

        let json = serde_json::to_string(&rel).unwrap();
        let deserialized: EntityRelationship = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.id, rel.id);
        assert_eq!(deserialized.relationship_type, RelationshipType::OwnerOf);
        assert_eq!(deserialized.strength, 0.9);
        assert_eq!(deserialized.evidence.len(), 1);
    }

    #[test]
    fn test_relationship_query_builder() {
        let entity = EntityRef::asset(Uuid::new_v4());
        let query = RelationshipQuery::from_entity(entity)
            .with_types(vec![
                RelationshipType::ConnectsTo,
                RelationshipType::DependsOn,
            ])
            .with_max_depth(3)
            .with_min_strength(0.5);

        assert_eq!(query.max_depth, 3);
        assert_eq!(query.min_strength, 0.5);
        assert_eq!(query.relationship_types.as_ref().unwrap().len(), 2);
    }
}
