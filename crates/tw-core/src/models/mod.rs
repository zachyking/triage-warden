//! Data models for the Asset & Identity Context Store.
//!
//! This module provides the core data structures for tracking infrastructure
//! assets, user identities, and their relationships.

pub mod asset;
pub mod identity;
pub mod relationship;

pub use asset::{Asset, AssetIdentifier, AssetType, Criticality, Environment, IdentifierType};
pub use identity::{Identity, IdentityStatus, IdentityType};
pub use relationship::{
    EntityRef, EntityRelationship, EntityType, RelationshipQuery, RelationshipType,
};
