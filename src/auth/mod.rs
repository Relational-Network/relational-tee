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
//! the `Admin` role itself. `Admin` grants every permission, `Analyst` only
//! `analyses:run`, and no role none, which leaves `/v1/users/me` and the
//! pool list.
//!
//! An analysis shows `Admin` callers every row, and an analyst only the rows
//! the employer-scope mapping gives their Entra groups
//! ([`Caller::row_scope`]).

pub mod entra;
pub mod jwks;

#[cfg(feature = "dev")]
pub mod dev_token;

use axum::extract::FromRequestParts;
use axum::http::{header, request::Parts};
use serde::Serialize;
use tracing::warn;
use utoipa::ToSchema;

use crate::analysis::table::Scope;
use crate::error::ApiError;
use crate::state::AppState;
use crate::storage::identities::SignIn;
use crate::storage::scopes::EmployerScopes;

pub use entra::Groups;

/// The app role that administers the pilot.
pub const ADMIN: &str = "Admin";

/// The app role that runs analyses through grants.
pub const ANALYST: &str = "Analyst";

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

/// The permissions `roles` grant.
pub fn permissions(roles: &[String]) -> Vec<Permission> {
    if roles.iter().any(|r| r == ADMIN) {
        Permission::ALL.to_vec()
    } else if roles.iter().any(|r| r == ANALYST) {
        vec![Permission::AnalysesRun]
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
    pub groups: Groups,
    pub permissions: Vec<Permission>,
}

impl Caller {
    pub fn is_admin(&self) -> bool {
        self.roles.iter().any(|r| r == ADMIN)
    }

    /// The rows of an analysis this caller may see: every row for `Admin`;
    /// otherwise the scopes `mapping` gives their groups. A caller whose
    /// groups are unknown, or none of whose groups is mapped, gets 403.
    pub fn row_scope(&self, mapping: &EmployerScopes) -> Result<Scope, ApiError> {
        if self.is_admin() {
            return Ok(Scope::All);
        }
        match &self.groups {
            Groups::Overage => Err(ApiError::forbidden(
                "your account is in more groups than an access token can list, so its \
                 employer scope is unknown; ask an admin",
            )
            .with_code("groups_overage")),
            Groups::Listed(groups) => mapping.rows_for(groups).ok_or_else(|| {
                ApiError::forbidden("none of your groups has an employer scope; ask an admin")
                    .with_code("no_employer_scope")
            }),
        }
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
            groups: claims.groups,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::storage::scopes::tests::{fixture, AIB_GROUP};

    #[test]
    fn admin_grants_every_permission_analyst_one_and_no_role_none() {
        let admin = permissions(&["Admin".into()]);
        assert_eq!(admin, Permission::ALL);
        assert_eq!(
            permissions(&["Analyst".into(), "Admin".into()]),
            Permission::ALL
        );
        assert_eq!(permissions(&["Analyst".into()]), [Permission::AnalysesRun]);
        assert!(permissions(&[]).is_empty());
        assert!(permissions(&["admin".into(), "analyst".into()]).is_empty());
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

    fn caller(roles: &[&str], groups: Groups) -> Caller {
        let roles: Vec<String> = roles.iter().map(|r| r.to_string()).collect();
        Caller {
            user_id: "u-1".into(),
            email: String::new(),
            display_name: String::new(),
            permissions: permissions(&roles),
            roles,
            groups,
        }
    }

    #[test]
    fn admins_see_every_row_and_analysts_only_their_groups_rows() {
        let mapping = EmployerScopes {
            version: 1,
            scopes: fixture(),
            ..Default::default()
        };
        let aib = Groups::Listed(vec![AIB_GROUP.into()]);
        assert_eq!(
            caller(&["Admin"], Groups::Overage)
                .row_scope(&mapping)
                .unwrap(),
            Scope::All
        );
        assert_eq!(
            caller(&["Admin"], Groups::Listed(vec![]))
                .row_scope(&EmployerScopes::default())
                .unwrap(),
            Scope::All
        );
        assert_eq!(
            caller(&["Analyst"], aib.clone())
                .row_scope(&mapping)
                .unwrap(),
            Scope::Only {
                employer_groups: ["AIB".to_string()].into(),
                employers: Default::default(),
            }
        );

        // Fail closed: unknown groups, unmapped groups, or no mapping.
        let refused = |caller: Caller, mapping: &EmployerScopes| {
            let e = caller.row_scope(mapping).unwrap_err();
            assert_eq!(e.status, axum::http::StatusCode::FORBIDDEN);
            e.code
        };
        assert_eq!(
            refused(caller(&["Analyst"], Groups::Overage), &mapping),
            "groups_overage"
        );
        assert_eq!(
            refused(
                caller(&["Analyst"], Groups::Listed(vec!["other".into()])),
                &mapping
            ),
            "no_employer_scope"
        );
        assert_eq!(
            refused(caller(&["Analyst"], aib), &EmployerScopes::default()),
            "no_employer_scope"
        );
    }
}
