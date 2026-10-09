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
//! | `pools:read` | Pool detail, DRTs, schema, summary, revocations, issuance log, grants, pools by wallet |
//! | `pools:create` | Creating a Malta pool |
//! | `pools:write` | Initialise, issue, revoke, and grant and revoke analysts (and pool ownership) |
//! | `wallets:read` | Wallet reads, balance, fee estimate, history |
//! | `users:read` | The users list and lookup by email |
//! | `analyses:run` | Running a pool's analysis: with a grant, or as `Admin` |
//!
//! Wallet creation, deletion and sends, and the `/v1/admin/…` routes, need
//! the `Admin` role itself. `Admin` grants every permission. Every other
//! signed-in caller gets `analyses:run` and nothing else: Entra only says
//! who they are, and what they may run, and which rows, comes from their
//! grants, which the chain must show.
//!
//! An analysis shows `Admin` callers every row, and an analyst only the rows
//! their grant's targets give.

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
    #[serde(rename = "analyses:run")]
    AnalysesRun,
}

impl Permission {
    pub const ALL: [Permission; 6] = [
        Self::PoolsRead,
        Self::PoolsCreate,
        Self::PoolsWrite,
        Self::WalletsRead,
        Self::UsersRead,
        Self::AnalysesRun,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::PoolsRead => "pools:read",
            Self::PoolsCreate => "pools:create",
            Self::PoolsWrite => "pools:write",
            Self::WalletsRead => "wallets:read",
            Self::UsersRead => "users:read",
            Self::AnalysesRun => "analyses:run",
        }
    }
}

/// The permissions a signed-in caller with `roles` has: every one for
/// `Admin`, and otherwise `analyses:run`, which runs only what their grants
/// allow. No other role means anything.
pub fn permissions(roles: &[String]) -> Vec<Permission> {
    if roles.iter().any(|r| r == ADMIN) {
        Permission::ALL.to_vec()
    } else {
        vec![Permission::AnalysesRun]
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
    pub fn is_admin(&self) -> bool {
        self.roles.iter().any(|r| r == ADMIN)
    }

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
        if self.is_admin() {
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
    fn admin_grants_every_permission_and_anyone_else_runs_their_grants() {
        let admin = permissions(&["Admin".into()]);
        assert_eq!(admin, Permission::ALL);
        assert_eq!(
            permissions(&["Analyst".into(), "Admin".into()]),
            Permission::ALL
        );
        for roles in [
            vec![],
            vec!["Analyst".to_string()],
            vec!["admin".to_string()],
        ] {
            assert_eq!(permissions(&roles), [Permission::AnalysesRun], "{roles:?}");
        }
        assert_eq!(
            serde_json::to_value(admin).unwrap(),
            serde_json::json!([
                "pools:read",
                "pools:create",
                "pools:write",
                "wallets:read",
                "users:read",
                "analyses:run"
            ])
        );
    }
}
