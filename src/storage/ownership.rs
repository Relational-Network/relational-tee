// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Ownership enforcement for stored resources.
//!
//! Every wallet (and, in the future, every data record) has an `owner_user_id`
//! that must match the JWT `sub` claim before access is granted.

use super::encrypted_fs::StorageError;

/// Trait for any resource that has an owner.
pub trait OwnedResource {
    /// The user ID that owns this resource (matches JWT `sub` claim).
    fn owner_user_id(&self) -> &str;
}

/// Extension trait that checks ownership against a caller's identity.
pub trait OwnershipEnforcer: OwnedResource {
    /// Verify that `user_sub` owns this resource.
    fn verify_ownership(&self, user_sub: &str) -> Result<(), StorageError>;
}

impl<T: OwnedResource> OwnershipEnforcer for T {
    fn verify_ownership(&self, user_sub: &str) -> Result<(), StorageError> {
        if self.owner_user_id() == user_sub {
            Ok(())
        } else {
            Err(StorageError::PermissionDenied {
                user_id: user_sub.to_string(),
                resource: format!("resource owned by {}", self.owner_user_id()),
            })
        }
    }
}
