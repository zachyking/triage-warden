//! Granular role-based access control primitives.

pub mod access_review;
pub mod enforcement;
pub mod permission;
pub mod role;
pub mod sod;

pub use access_review::{
    AccessDecision, AccessDecisionOutcome, AccessReview, ReviewScope, ReviewStatus,
};
pub use enforcement::{AuthorizationDecision, AuthorizationRequest, PermissionEvaluator};
pub use permission::{Action, Constraint, ConstraintOp, Permission, Resource};
pub use role::{builtin_roles, RbacRole, RoleAssignment};
pub use sod::{default_sod_rules, SeparationOfDutiesRule, SodEnforcement, SodValidator};
