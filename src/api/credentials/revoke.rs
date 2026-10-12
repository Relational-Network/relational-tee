// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Credential revocation endpoint.
//!
//! - `POST /v1/drt/pools/{pool_pda}/revoke` — revoke credential(s)

use std::collections::HashSet;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Response,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tracing::info;
use utoipa::ToSchema;

use crate::api::pools::{load_wallet_keypair, verify_pool_ownership};
use crate::auth::{Caller, Permission};
use crate::blockchain::drt::accounts::fetch_pool;
use crate::error::ApiError;
use crate::idempotency::{Idempotent, JsonBody};
use crate::state::AppState;
use crate::storage::pools::Revocation;
use crate::storage::Change;

use super::{parse_pda, pool_not_found};

/// The most credential IDs one request names.
const MAX_CREDENTIAL_IDS: usize = 1000;

/// The longest credential ID, in bytes: `initial`, or an upload's UUID.
const MAX_CREDENTIAL_ID_LEN: usize = 64;

/// The longest reason, in characters.
const MAX_REASON_CHARS: usize = 500;

// ============================================================================
// Request / Response types
// ============================================================================

/// Revocation request body.
#[derive(Debug, Deserialize, ToSchema)]
pub struct RevokeCredentialsRequest {
    /// Wallet ID of the pool owner.
    pub wallet_id: String,
    /// Credential record IDs to revoke (`initial`, or UUIDs from `/issue`
    /// responses), each 1 to 64 bytes.
    #[schema(min_items = 1, max_items = 1000)]
    pub credential_ids: Vec<String>,
    /// Optional reason for revocation.
    #[serde(default)]
    #[schema(max_length = 500)]
    pub reason: Option<String>,
}

/// Revocation response.
#[derive(Debug, Serialize, ToSchema)]
pub struct RevokeCredentialsResponse {
    /// Number of credentials revoked (each distinct ID counts once, whether
    /// or not it was already revoked).
    pub revoked: usize,
}

/// The distinct credential IDs `payload` names, in the order it first names
/// them, or why the request is refused.
fn distinct_ids(payload: &RevokeCredentialsRequest) -> Result<Vec<String>, ApiError> {
    let count = payload.credential_ids.len();
    if count == 0 || count > MAX_CREDENTIAL_IDS {
        return Err(ApiError::bad_request(format!(
            "credential_ids must name 1 to {MAX_CREDENTIAL_IDS} credentials"
        )));
    }
    if payload
        .credential_ids
        .iter()
        .any(|cid| cid.is_empty() || cid.len() > MAX_CREDENTIAL_ID_LEN)
    {
        return Err(ApiError::bad_request(format!(
            "each credential ID must be 1 to {MAX_CREDENTIAL_ID_LEN} bytes"
        )));
    }
    if payload
        .reason
        .as_ref()
        .is_some_and(|reason| reason.chars().count() > MAX_REASON_CHARS)
    {
        return Err(ApiError::bad_request(format!(
            "reason must be at most {MAX_REASON_CHARS} characters"
        )));
    }
    let mut seen = HashSet::new();
    Ok(payload
        .credential_ids
        .iter()
        .filter(|cid| seen.insert(cid.as_str()))
        .cloned()
        .collect())
}

// ============================================================================
// Handlers
// ============================================================================

/// Revoke credential(s) from a pool.
///
/// Each revocation is recorded in the pool's document, with who revoked it,
/// when and why. Revoking an already revoked credential changes nothing.
#[utoipa::path(
    post,
    path = "/v1/drt/pools/{pool_pda}/revoke",
    tag = "Credentials",
    summary = "Revoke credentials",
    description = "Revoke 1 to 1,000 credentials by record ID, with an optional reason of up to 500 characters. Revocations are recorded in the pool's document. Needs `pools:write`, and the caller's wallet must own the pool.",
    security(("bearer_auth" = [])),
    params(
        ("pool_pda" = String, Path, description = "Pool PDA address (base58)"),
        ("Idempotency-Key" = String, Header, format = "uuid", description = "A UUID naming this user action; reuse it on every retry"),
    ),
    request_body = RevokeCredentialsRequest,
    responses(
        (status = 200, description = "Credentials revoked", body = RevokeCredentialsResponse),
        (status = 400, description = "Validation error, or no Idempotency-Key"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Needs pools:write, or the caller's wallet doesn't own the pool"),
        (status = 404, description = "Pool or credential not found"),
        (status = 409, description = "The pool changed concurrently; retry"),
        (status = 422, description = "The Idempotency-Key was used for a different request"),
    )
)]
pub async fn revoke_credentials(
    caller: Caller,
    request: Idempotent,
    State(state): State<AppState>,
    Path(pool_pda_str): Path<String>,
    JsonBody {
        value: payload,
        bytes,
    }: JsonBody<RevokeCredentialsRequest>,
) -> Result<Response, ApiError> {
    caller.require(Permission::PoolsWrite)?;
    let mut op = open_or_replay!(state, &caller.user_id, request, &bytes);
    let credential_ids = distinct_ids(&payload)?;
    let pool_pda = parse_pda(&pool_pda_str)?;

    // Verify ownership.
    let (wallet, _) = load_wallet_keypair(&state, &payload.wallet_id, &caller.user_id).await?;
    let pool = fetch_pool(state.solana_client.rpc(), &pool_pda).await?;
    verify_pool_ownership(&pool, &wallet)?;

    let now = Utc::now();
    let mut newly_revoked = 0;
    op.begin().await?;
    state
        .storage
        .pools()
        .update(&pool_pda_str, |doc| {
            // Every credential must be an upload of this pool.
            if let Some(unknown) = credential_ids.iter().find(|c| doc.upload(c).is_none()) {
                return Err(ApiError::not_found(format!(
                    "credential record '{unknown}' not found in pool"
                )));
            }
            newly_revoked = 0;
            for cid in &credential_ids {
                if !doc.is_revoked(cid) {
                    doc.revocations.push(Revocation {
                        credential_id: cid.clone(),
                        revoked_by: caller.user_id.clone(),
                        revoked_at: now,
                        reason: payload.reason.clone(),
                    });
                    newly_revoked += 1;
                }
            }
            Ok(if newly_revoked == 0 {
                Change::Unchanged
            } else {
                Change::Changed
            })
        })
        .await?
        .ok_or_else(|| pool_not_found(&pool_pda_str))?;

    info!(
        pool = %pool_pda_str,
        count = credential_ids.len(),
        newly_revoked,
        "Credentials revoked"
    );

    crate::fault::point("recorded");
    op.finish(
        StatusCode::OK,
        &RevokeCredentialsResponse {
            revoked: credential_ids.len(),
        },
    )
    .await
}
