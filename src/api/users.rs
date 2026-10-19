// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Users: the caller's own identity, and the known users for admins.
//!
//! - `GET /v1/users/me`: who the caller is and what they may do.
//! - `GET /v1/users`: every known user, with the pools each can open,
//!   paged by cursor.
//! - `GET /v1/users?email=`: the one user with that email, or 404.
//! - `POST /v1/users`: register someone an admin found in Entra, before
//!   their first sign-in, so they can be granted at once.
//!
//! Users become known at their first sign-in, or when an admin registers
//! them; the worker never queries Microsoft Graph: the dashboard finds
//! people there, and the first sign-in with that Entra object ID is theirs.

use std::collections::HashMap;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::auth::{Caller, Permission};
use crate::error::ApiError;
use crate::idempotency::{Idempotent, JsonBody};
use crate::state::AppState;
use crate::storage::identities::{Identity, Registered, Registration};

use super::page;

/// Response for `GET /v1/users/me`.
#[derive(Debug, Serialize, ToSchema)]
pub struct UserMeResponse {
    /// The internal, pseudonymous user ID.
    pub user_id: String,
    pub email: String,
    pub display_name: String,
    /// App roles from the access token, such as `Admin`.
    pub roles: Vec<String>,
    /// What those roles allow, as the dashboard gates its routes.
    pub permissions: Vec<Permission>,
}

/// Who the caller is and what they may do.
#[utoipa::path(
    get,
    path = "/v1/users/me",
    tag = "Users",
    summary = "Current user",
    description = "The caller's user ID, email, display name, app roles and permissions. Any authenticated caller, including one with no role.",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "The caller", body = UserMeResponse),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn get_me(caller: Caller) -> Json<UserMeResponse> {
    Json(UserMeResponse {
        user_id: caller.user_id,
        email: caller.email,
        display_name: caller.display_name,
        roles: caller.roles,
        permissions: caller.permissions,
    })
}

/// Query for `GET /v1/users`.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct UsersQuery {
    /// Find the one user with this email (case-insensitive) instead of
    /// listing.
    pub email: Option<String>,
    /// `next_cursor` from the previous page.
    pub cursor: Option<String>,
    /// Maximum number of users to return (default 50). Values above 200
    /// count as 200.
    #[param(minimum = 1, maximum = 200)]
    pub limit: Option<usize>,
}

/// A known user.
#[derive(Debug, Serialize, ToSchema)]
pub struct UserEntry {
    pub user_id: String,
    pub email: String,
    pub display_name: String,
    /// App roles as of the user's last sign-in.
    pub roles: Vec<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    /// Registered by an admin and not signed in yet.
    pub pending: bool,
}

impl From<Identity> for UserEntry {
    fn from(i: Identity) -> Self {
        Self {
            user_id: i.user_id,
            email: i.email,
            display_name: i.display_name,
            roles: i.roles,
            first_seen: i.first_seen,
            last_seen: i.last_seen,
            pending: i.pending,
        }
    }
}

/// Someone an admin found in Entra, to register before they sign in.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RegisterUserRequest {
    /// Their Entra object ID in the worker's tenant, as Microsoft Graph
    /// lists it: the `oid` their tokens will carry.
    #[schema(format = "uuid")]
    pub entra_object_id: String,
    /// Their email, if Entra has one; empty otherwise.
    #[serde(default)]
    pub email: String,
    pub display_name: String,
}

const MAX_TEXT: usize = 256;

/// A known user, with the pools they can open.
#[derive(Debug, Serialize, ToSchema)]
pub struct UserListEntry {
    #[serde(flatten)]
    pub user: UserEntry,
    /// The pools where they hold a grant that isn't revoked, by pool name,
    /// as the pool documents record it: the chain is checked when they open
    /// one, not here. Admins open every pool without one.
    pub pools: Vec<UserPool>,
}

/// A pool someone holds a grant in.
#[derive(Debug, Serialize, ToSchema)]
pub struct UserPool {
    pub pool_pda: String,
    pub pool_name: String,
    /// The pool's analysis.
    pub display_name: String,
    pub granted_at: DateTime<Utc>,
}

/// One page of known users, by email.
#[derive(Debug, Serialize, ToSchema)]
pub struct UsersResponse {
    pub users: Vec<UserListEntry>,
    /// Present when there's another page; pass it as `cursor`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// The user an email lookup found.
#[derive(Debug, Serialize, ToSchema)]
pub struct UserLookupResponse {
    pub user_id: String,
    pub email: String,
    pub display_name: String,
}

/// Register someone before their first sign-in.
#[utoipa::path(
    post,
    path = "/v1/users",
    tag = "Users",
    summary = "Register a user",
    description = "Make someone an admin found in Entra known before their first sign-in, under the internal `user_id` their first sign-in with that Entra object ID will then have, so they can be granted at once. Registering someone already known, registered or signed in, returns them unchanged. The worker trusts the object ID it's given: it doesn't call Microsoft Graph. Needs the `Admin` role and an Idempotency-Key.",
    security(("bearer_auth" = [])),
    params(
        ("Idempotency-Key" = String, Header, format = "uuid", description = "A UUID naming this user action; reuse it on every retry"),
    ),
    request_body = RegisterUserRequest,
    responses(
        (status = 200, description = "The user, `pending` until their first sign-in", body = UserEntry),
        (status = 400, description = "An object ID that isn't a UUID, text too long, or no Idempotency-Key"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Admin role required"),
        (status = 409, description = "Another user holds the email (`email_taken`)"),
        (status = 422, description = "The Idempotency-Key was used for a different request"),
    )
)]
pub async fn register_user(
    caller: Caller,
    request: Idempotent,
    State(state): State<AppState>,
    JsonBody {
        value: payload,
        bytes,
    }: JsonBody<RegisterUserRequest>,
) -> Result<Response, ApiError> {
    caller.require_admin()?;
    let mut op = open_or_replay!(state, &caller.user_id, request, &bytes);
    let oid = uuid::Uuid::parse_str(&payload.entra_object_id)
        .map_err(|_| ApiError::bad_request("entra_object_id must be a UUID"))?
        .to_string();
    let email = payload.email.trim();
    let display_name = payload.display_name.trim();
    if email.len() > MAX_TEXT || display_name.len() > MAX_TEXT {
        return Err(ApiError::bad_request(format!(
            "email and display_name hold at most {MAX_TEXT} bytes"
        )));
    }
    op.begin().await?;
    let registered = state
        .storage
        .identities()
        .register(&Registration {
            tid: state.auth.tenant_id(),
            oid: &oid,
            email,
            display_name,
            registered_by: &caller.user_id,
        })
        .await?;
    let identity = match registered {
        Registered::New(identity) => {
            tracing::info!(user_id = %identity.user_id, "User registered before signing in");
            identity
        }
        Registered::Known(identity) => identity,
        Registered::EmailTaken => {
            return Err(ApiError::conflict("another user already holds that email")
                .with_code("email_taken"))
        }
    };
    op.finish(StatusCode::OK, &UserEntry::from(identity)).await
}

/// A page of users, or with `email` the user found.
#[derive(Debug, Serialize, ToSchema)]
#[serde(untagged)]
pub enum UsersBody {
    Page(UsersResponse),
    Lookup(UserLookupResponse),
}

/// List known users, or find one by email.
#[utoipa::path(
    get,
    path = "/v1/users",
    tag = "Users",
    summary = "Users",
    description = "Without `email`: every known user, signed in or registered by an admin (`pending`), with their roles as of their last sign-in and the pools where they hold a grant that isn't revoked, sorted by email and paged by cursor, with no totals. With `email`: an exact, case-insensitive match, or 404 if nobody with that email is known. Needs `users:read`.",
    security(("bearer_auth" = [])),
    params(UsersQuery),
    responses(
        (status = 200, description = "A page of users, or with `email` the user found", body = UsersBody),
        (status = 400, description = "Invalid cursor"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Needs users:read"),
        (status = 404, description = "No user with that email"),
    )
)]
pub async fn list_users(
    caller: Caller,
    State(state): State<AppState>,
    Query(query): Query<UsersQuery>,
) -> Result<Json<UsersBody>, ApiError> {
    caller.require(Permission::UsersRead)?;
    let identities = state.storage.identities();

    if let Some(email) = &query.email {
        let found = identities
            .by_email(email)
            .await?
            .ok_or_else(|| ApiError::not_found("no user with that email is known"))?;
        return Ok(Json(UsersBody::Lookup(UserLookupResponse {
            user_id: found.user_id,
            email: found.email,
            display_name: found.display_name,
        })));
    }

    let mut all = identities.all().await?;
    all.sort_by(|a, b| {
        (a.email.to_lowercase(), &a.user_id).cmp(&(b.email.to_lowercase(), &b.user_id))
    });
    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let (users, next_cursor) = page(all, |i| i.user_id.as_str(), query.cursor.as_deref(), limit)?;
    let mut pools = pools_by_analyst(&state).await?;
    Ok(Json(UsersBody::Page(UsersResponse {
        users: users
            .into_iter()
            .map(|i| UserListEntry {
                pools: pools.remove(&i.user_id).unwrap_or_default(),
                user: i.into(),
            })
            .collect(),
        next_cursor,
    })))
}

/// Each analyst's pools, from the grants the pool documents hold that
/// aren't revoked: the same rule as an analyst's active grant.
async fn pools_by_analyst(state: &AppState) -> Result<HashMap<String, Vec<UserPool>>, ApiError> {
    let mut held: HashMap<String, Vec<UserPool>> = HashMap::new();
    for doc in state.storage.pools().all().await? {
        let Some(analysis) = doc.analysis.as_ref() else {
            continue;
        };
        for grant in &doc.grants {
            if grant.revoked.is_some() || grant.drt_name != analysis.analysis_id {
                continue;
            }
            held.entry(grant.analyst.clone())
                .or_default()
                .push(UserPool {
                    pool_pda: doc.pool_pda.clone(),
                    pool_name: doc.pool_name.clone(),
                    display_name: analysis.display_name.clone(),
                    granted_at: grant.granted_at,
                });
        }
    }
    for pools in held.values_mut() {
        pools.sort_by(|a, b| (&a.pool_name, &a.pool_pda).cmp(&(&b.pool_name, &b.pool_pda)));
    }
    Ok(held)
}
