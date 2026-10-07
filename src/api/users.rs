// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Users: the caller's own identity, and the known users for admins.
//!
//! - `GET /v1/users/me`: who the caller is and what they may do.
//! - `GET /v1/users`: every user who has signed in, paged by cursor.
//! - `GET /v1/users?email=`: the one user with that email, or 404.
//!
//! Users become known at their first sign-in; nothing queries Microsoft
//! Graph.

use axum::extract::{Query, State};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::auth::{Caller, Permission};
use crate::error::ApiError;
use crate::state::AppState;
use crate::storage::identities::Identity;

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
        }
    }
}

/// One page of known users, by email.
#[derive(Debug, Serialize, ToSchema)]
pub struct UsersResponse {
    pub users: Vec<UserEntry>,
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
    description = "Without `email`: every user who has signed in, with their roles as of their last sign-in, sorted by email and paged by cursor, with no totals. With `email`: an exact, case-insensitive match, or 404 if nobody with that email has signed in. Needs `users:read`.",
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
            .ok_or_else(|| ApiError::not_found("no user with that email has signed in"))?;
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
    Ok(Json(UsersBody::Page(UsersResponse {
        users: users.into_iter().map(UserEntry::from).collect(),
        next_cursor,
    })))
}
