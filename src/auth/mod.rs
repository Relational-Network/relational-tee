// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Authentication and permissions.
//!
//! Every authenticated route takes a [`Caller`]: the bearer token, validated
//! as an Entra ID access token ([`entra`]), mapped to the internal `user_id`
//! of its `(tid, oid)` (created at the first sign-in, then cached), with the
//! permissions its app roles grant. Handlers check the permission their
//! route needs; the ownership checks stay in the handlers.
//!
//! | Permission | Grants |
//! |---|---|
//! | `pools:read` | Pool detail, DRTs, schema, summary, revocations, issuance log, pools by wallet |
//! | `pools:create` | Creating a Malta pool |
//! | `pools:write` | Schema upload, initialise, issue, revoke (and pool ownership) |
//! | `wallets:read` | Wallet reads, balance, fee estimate, history |
//! | `users:read` | The users list and lookup by email |
//!
//! Wallet creation, deletion and sends, and the `/v1/admin/…` routes, need
//! the `Admin` role itself. `Admin` grants all five permissions; no role
//! grants none, which leaves `/v1/users/me` and the pool list.

pub mod entra;
pub mod jwks;

#[cfg(feature = "dev")]
pub mod dev_token;

use axum::extract::FromRequestParts;
use axum::http::{header, request::Parts};
use serde::Serialize;
use tracing::warn;
use utoipa::ToSchema;

use crate::error::ApiError;
use crate::state::AppState;
use crate::storage::identities::SignIn;

/// The app role that administers the pilot.
pub const ADMIN: &str = "Admin";

/// What a caller may do, as the dashboard names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
pub enum Permission {
    #[serde(rename = "pools:read")]
    PoolsRead,
    #[serde(rename = "pools:create")]
    PoolsCreate,
    #[serde(rename = "pools:write")]
    PoolsWrite,
    #[serde(rename = "wallets:read")]
    WalletsRead,
    #[serde(rename = "users:read")]
    UsersRead,
}

impl Permission {
    pub const ALL: [Permission; 5] = [
        Self::PoolsRead,
        Self::PoolsCreate,
        Self::PoolsWrite,
        Self::WalletsRead,
        Self::UsersRead,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::PoolsRead => "pools:read",
            Self::PoolsCreate => "pools:create",
            Self::PoolsWrite => "pools:write",
            Self::WalletsRead => "wallets:read",
            Self::UsersRead => "users:read",
        }
    }
}

/// The permissions `roles` grant.
pub fn permissions(roles: &[String]) -> Vec<Permission> {
    if roles.iter().any(|r| r == ADMIN) {
        Permission::ALL.to_vec()
    } else {
        Vec::new()
    }
}

/// An authenticated caller.
#[derive(Debug, Clone)]
pub struct Caller {
    /// The internal, pseudonymous ID every stored reference uses.
    pub user_id: String,
    pub email: String,
    pub display_name: String,
    pub roles: Vec<String>,
    pub permissions: Vec<Permission>,
}

impl Caller {
    /// 403 unless the caller has `permission`.
    pub fn require(&self, permission: Permission) -> Result<(), ApiError> {
        if self.permissions.contains(&permission) {
            Ok(())
        } else {
            Err(ApiError::forbidden(format!(
                "this needs the {} permission",
                permission.as_str()
            )))
        }
    }

    /// 403 unless the caller has the `Admin` role.
    pub fn require_admin(&self) -> Result<(), ApiError> {
        if self.roles.iter().any(|r| r == ADMIN) {
            Ok(())
        } else {
            Err(ApiError::forbidden("this needs the Admin role"))
        }
    }
}

impl FromRequestParts<AppState> for Caller {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| ApiError::unauthorized("missing authorization header"))?
            .strip_prefix("Bearer ")
            .ok_or_else(|| ApiError::unauthorized("invalid authorization header format"))?;
        let claims = state.auth.verify(token).await.map_err(|reason| {
            warn!(%reason, "Refused an access token");
            ApiError::unauthorized("invalid or expired token")
        })?;

        let email = claims.email.clone().unwrap_or_default();
        let display_name = claims.name.clone().unwrap_or_else(|| email.clone());
        let identity = state
            .storage
            .identities()
            .sign_in(&SignIn {
                tid: &claims.tid,
                oid: &claims.oid,
                email: &email,
                display_name: &display_name,
                roles: &claims.roles,
            })
            .await?;
        crate::audit::caller(&identity.user_id);
        tracing::Span::current().record("user_id", identity.user_id.as_str());
        state.limiter.check_user(&parts.method, &identity.user_id)?;

        Ok(Caller {
            permissions: permissions(&claims.roles),
            user_id: identity.user_id,
            email,
            display_name,
            roles: claims.roles,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_grants_every_permission_and_no_role_none() {
        let admin = permissions(&["Admin".into()]);
        assert_eq!(admin, Permission::ALL);
        assert!(permissions(&[]).is_empty());
        assert!(permissions(&["admin".into(), "Analyst".into()]).is_empty());
        assert_eq!(
            serde_json::to_value(admin).unwrap(),
            serde_json::json!([
                "pools:read",
                "pools:create",
                "pools:write",
                "wallets:read",
                "users:read"
            ])
        );
    }
}
