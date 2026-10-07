// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Analyst grants: a pool's owner gives an analyst access to the pool's
//! analysis, which burns one of its Execute DRTs, and can take it back.
//!
//! - `POST /v1/drt/pools/{pool_pda}/grant`        — grant an analyst access
//! - `POST /v1/drt/pools/{pool_pda}/revoke-grant` — revoke it
//! - `GET  /v1/drt/pools/{pool_pda}/grants`       — a pool's grants
//! - `GET  /v1/drt/me/analyses`                   — the analyses the caller may run
//!
//! A grant's commitment derives from the analyst, the pool and the
//! analysis, so every grant of one analyst to one analysis has the same
//! Grant PDA. Granting while a grant is active burns nothing. A revocation
//! ends access as soon as the pool document records it, then closes the
//! Grant PDA; the analyst can't be granted again until that close is
//! recorded, so each Grant PDA belongs to one grant at a time. A grant
//! staged before a revocation is never recorded after it.

use std::collections::HashMap;
use std::str::FromStr;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Response,
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use tracing::{info, warn};
use utoipa::ToSchema;

use crate::api::credentials::{decode_right_id, parse_pda, pool_not_found};
use crate::api::pools::{explorer_url, load_pool, signed, verify_pool_ownership};
use crate::audit;
use crate::auth::{Caller, Permission};
use crate::blockchain::drt::{
    accounts::fetch_pool,
    instructions::{build_grant_right, build_revoke_grant},
    pda::{derive_drt_config_pda, derive_grant_pda, derive_user_ata},
};
use crate::blockchain::signing::keypair_from_bytes_verified;
use crate::blockchain::spl_token::token_account_amount;
use crate::chain::{self, Effect};
use crate::error::ApiError;
use crate::idempotency::{Idempotent, JsonBody};
use crate::ids;
use crate::state::AppState;
use crate::storage::identities::Identity;
use crate::storage::pools::{DrtMetadata, Grant, GrantRevocation, PoolDoc, Recording};
use crate::storage::staged::{Saga, Staged};
use crate::storage::Change;

// ============================================================================
// Request / Response types
// ============================================================================

/// An analyst and one of the pool's analyses.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct GrantRequest {
    /// The analyst's `user_id`, as `GET /v1/users?email=` finds it.
    pub analyst_user_id: String,
    /// The pool's analysis: its `analysis_id`.
    pub analysis_id: String,
}

/// A grant.
#[derive(Debug, Serialize, ToSchema)]
pub struct GrantEntry {
    pub grant_id: String,
    pub analyst_user_id: String,
    /// The analyst's email and name as of their last sign-in.
    pub analyst_email: String,
    pub analyst_display_name: String,
    pub analysis_id: String,
    /// `active`, `revoking` (access has ended, and the Grant PDA's close
    /// hasn't been recorded yet: revoke again to finish it) or `revoked`.
    pub status: String,
    /// The `user_id` of the admin who granted it. Empty for a burn found
    /// on-chain that no request recorded, which a revocation recorded.
    pub granted_by: String,
    pub granted_at: DateTime<Utc>,
    /// The `grant_right` transaction that burned the Execute DRT.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explorer_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
    /// The `revoke_grant` transaction that closed the Grant PDA.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoke_signature: Option<String>,
}

/// A pool's grants, newest first.
#[derive(Debug, Serialize, ToSchema)]
pub struct GrantsResponse {
    pub pool_pda: String,
    pub grants: Vec<GrantEntry>,
}

/// An analysis the caller may run.
#[derive(Debug, Serialize, ToSchema)]
pub struct MyAnalysis {
    pub pool_pda: String,
    pub pool_name: String,
    pub analysis_id: String,
    pub display_name: String,
    /// `admin`: every row, with no grant; `grant`: the rows the caller's
    /// employer scope allows.
    pub access: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub granted_at: Option<DateTime<Utc>>,
}

/// The analyses the caller may run, by pool name.
#[derive(Debug, Serialize, ToSchema)]
pub struct MyAnalysesResponse {
    pub analyses: Vec<MyAnalysis>,
}

// ============================================================================
// Helpers
// ============================================================================

/// The pool's Execute DRT for `analysis_id`, or 404.
fn analysis_drt<'a>(doc: &'a PoolDoc, analysis_id: &str) -> Result<&'a DrtMetadata, ApiError> {
    doc.analysis
        .as_ref()
        .filter(|a| a.analysis_id == analysis_id)
        .and_then(|a| doc.drts.get(&a.analysis_id))
        .ok_or_else(|| ApiError::not_found(format!("this pool has no analysis {analysis_id:?}")))
}

/// The keypair of the caller's active wallet, which must own the pool:
/// only the owner holds its DRTs and may close its grants.
async fn owner_keypair(
    state: &AppState,
    caller: &Caller,
    pool_pda: &Pubkey,
) -> Result<Keypair, ApiError> {
    let wallet = crate::api::get_active_wallet_for_user(state, &caller.user_id).await?;
    let bytes = state
        .storage
        .wallets()
        .read_keypair(&wallet.wallet_id)
        .await?;
    let keypair = keypair_from_bytes_verified(&bytes, &wallet.public_address)?;
    let pool = fetch_pool(state.solana_client.rpc(), pool_pda).await?;
    verify_pool_ownership(&pool, &wallet)?;
    Ok(keypair)
}

fn rpc_error(e: impl std::fmt::Display) -> ApiError {
    ApiError::rpc_unavailable(format!("Solana RPC error: {e}"))
}

fn revocation_pending() -> ApiError {
    ApiError::conflict(
        "the analyst's last grant is revoked, but closing its Grant PDA hasn't been recorded; \
         revoke it again to finish, then grant",
    )
    .with_code("revocation_pending")
}

fn superseded() -> ApiError {
    ApiError::conflict("the analyst's grant was revoked after this request began; grant again")
        .with_code("grant_superseded")
}

fn entry(state: &AppState, grant: &Grant, analyst: Option<&Identity>) -> GrantEntry {
    let revoked = grant.revoked.as_ref();
    let signature = grant.signature.clone();
    GrantEntry {
        grant_id: grant.grant_id.clone(),
        analyst_user_id: grant.analyst.clone(),
        analyst_email: analyst.map(|i| i.email.clone()).unwrap_or_default(),
        analyst_display_name: analyst.map(|i| i.display_name.clone()).unwrap_or_default(),
        analysis_id: grant.drt_name.clone(),
        status: match revoked {
            None => "active",
            Some(r) if r.signature.is_none() => "revoking",
            Some(_) => "revoked",
        }
        .into(),
        granted_by: grant.granted_by.clone(),
        granted_at: grant.granted_at,
        explorer_url: signature.as_deref().map(|s| explorer_url(state, s)),
        signature,
        revoked_by: revoked.map(|r| r.revoked_by.clone()),
        revoked_at: revoked.map(|r| r.revoked_at),
        revoke_signature: revoked.and_then(|r| r.signature.clone()),
    }
}

// ============================================================================
// POST /v1/drt/pools/{pool_pda}/grant
// ============================================================================

/// Grant an analyst access to the pool's analysis.
///
/// Burns one Execute DRT under the analyst's commitment, staged first and
/// under the stored-transaction rule, so a retry never burns twice; then
/// records the grant in the pool document.
#[utoipa::path(
    post,
    path = "/v1/drt/pools/{pool_pda}/grant",
    tag = "Grants",
    summary = "Grant an analyst",
    description = "Give an analyst, who must have signed in, access to the pool's analysis: burn one of its Execute DRTs, then record the grant in the pool's document. An analyst with an active grant keeps it, and nothing is burned. Needs `pools:write` and pool ownership. Idempotent: retries with the same Idempotency-Key burn one DRT.",
    security(("bearer_auth" = [])),
    params(
        ("pool_pda" = String, Path, description = "Pool PDA address (base58)"),
        ("Idempotency-Key" = String, Header, format = "uuid", description = "A UUID naming this user action; reuse it on every retry"),
    ),
    request_body = GrantRequest,
    responses(
        (status = 200, description = "The grant", body = GrantEntry),
        (status = 400, description = "No Execute DRTs left (`supply_exhausted`), no Idempotency-Key, or Solana refused the burn (`transaction_rejected`)"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Not the pool's owner"),
        (status = 404, description = "Pool, analysis or analyst not found"),
        (status = 409, description = "The analyst's last revocation isn't finished (`revocation_pending`), or a revocation overtook this request (`grant_superseded`)"),
        (status = 422, description = "The Idempotency-Key was used for a different request"),
        (status = 503, description = "Solana RPC unavailable"),
    )
)]
pub async fn grant_analysis(
    caller: Caller,
    request: Idempotent,
    State(state): State<AppState>,
    Path(pool_pda_str): Path<String>,
    JsonBody {
        value: payload,
        bytes,
    }: JsonBody<GrantRequest>,
) -> Result<Response, ApiError> {
    caller.require(Permission::PoolsWrite)?;
    let mut op = open_or_replay!(state, &caller.user_id, request, &bytes);
    let pool_pda = parse_pda(&pool_pda_str)?;
    let doc = load_pool(&state, &pool_pda_str).await?;
    let drt = analysis_drt(&doc, &payload.analysis_id)?.clone();
    let analyst = state
        .storage
        .identities()
        .by_user_id(&payload.analyst_user_id)
        .await?
        .ok_or_else(|| ApiError::not_found("no user with that user_id has signed in"))?;
    let grant_id = ids::grant_id(&caller.user_id, &pool_pda_str, &request.key);
    audit::grant(&grant_id);

    // This request's grant, or another active one: nothing to burn.
    let existing = doc
        .grants
        .iter()
        .find(|g| g.grant_id == grant_id)
        .or_else(|| doc.active_grant(&analyst.user_id, &payload.analysis_id));
    if let Some(existing) = existing {
        return op
            .finish(StatusCode::OK, &entry(&state, existing, Some(&analyst)))
            .await;
    }
    let pending = doc
        .latest_grant(&analyst.user_id, &payload.analysis_id)
        .and_then(|g| g.revoked.as_ref())
        .is_some_and(|r| r.signature.is_none());
    if pending {
        return Err(revocation_pending());
    }

    let keypair = owner_keypair(&state, &caller, &pool_pda).await?;
    let right_id = decode_right_id(&drt.right_id_hex)?;
    let mint = Pubkey::from_str(&drt.mint)
        .map_err(|_| ApiError::internal("invalid mint pubkey in pool metadata"))?;
    let pool_uuid = decode_right_id(&doc.pool_uuid_hex)?;
    let commitment = state
        .commitments
        .commitment(&analyst.user_id, &pool_uuid, &right_id);
    let (grant_pda, _) = derive_grant_pda(&commitment);
    let rpc = state.solana_client.rpc();

    // Unless the burn already happened, the owner needs an Execute DRT.
    if !rpc
        .account_exists(&grant_pda, "finalized")
        .await
        .map_err(rpc_error)?
    {
        let ata = derive_user_ata(&keypair.pubkey(), &mint);
        let held = match rpc.get_account_data(&ata).await.map_err(rpc_error)? {
            Some(account) => token_account_amount(&account)
                .ok_or_else(|| ApiError::internal("the DRT account isn't a token account"))?,
            None => 0,
        };
        if held < 1 {
            return Err(ApiError::bad_request(format!(
                "no {} DRTs are left to grant",
                payload.analysis_id
            ))
            .with_code("supply_exhausted"));
        }
    }

    // ── STAGE ─────────────────────────────────────────────────────
    op.begin().await?;
    let staged = state
        .storage
        .sagas()
        .stage(
            &format!("grant-{grant_id}"),
            Staged {
                record: op.record_path().to_string(),
                staged_at: Utc::now(),
                saga: Saga::Grant {
                    pool_pda: pool_pda_str.clone(),
                    grant: Grant {
                        grant_id: grant_id.clone(),
                        analyst: analyst.user_id.clone(),
                        drt_name: payload.analysis_id.clone(),
                        commitment: hex::encode(commitment),
                        granted_by: caller.user_id.clone(),
                        granted_at: Utc::now(),
                        signature: None,
                        revoked: None,
                    },
                },
            },
        )
        .await?;
    let Saga::Grant { mut grant, .. } = staged.saga else {
        return Err(ApiError::internal(
            "another saga is staged under this grant",
        ));
    };
    match doc.recording(&grant) {
        Recording::Add => {}
        Recording::Present(present) => {
            return op
                .finish(StatusCode::OK, &entry(&state, present, Some(&analyst)))
                .await
        }
        Recording::Superseded(_) => return Err(superseded()),
    }
    // The staged grant is authoritative, so the burn is under its commitment.
    let commitment = grant
        .commitment_bytes()
        .ok_or_else(|| ApiError::internal("a staged grant has no commitment"))?;
    let (grant_pda, _) = derive_grant_pda(&commitment);
    crate::fault::point("staged");

    // ── BURN (irreversible, at most once) ─────────────────────────
    let (drt_config_pda, _) = derive_drt_config_pda(&pool_pda, &right_id);
    let ix = build_grant_right(
        &pool_pda,
        &drt_config_pda,
        &mint,
        &keypair.pubkey(),
        &commitment,
    );
    let signature = chain::run(
        &state.solana_client,
        &mut op,
        &Effect::Account(grant_pda),
        "finalized",
        signed(&keypair, std::slice::from_ref(&ix)),
    )
    .await?;
    audit::signature(&signature);

    // ── RECORD ────────────────────────────────────────────────────
    // If this fails, a retry with the same key, or the reconciler, adds it.
    grant.signature = Some(signature.clone());
    let doc = state
        .storage
        .pools()
        .update::<ApiError>(&pool_pda_str, |doc| {
            if doc.recording(&grant) != Recording::Add {
                return Ok(Change::Unchanged);
            }
            doc.grants.push(grant.clone());
            Ok(Change::Changed)
        })
        .await
        .inspect_err(|e| {
            warn!(pool = %pool_pda_str, grant_id = %grant_id, signature = %signature, error = %e,
                "Execute DRT burned; the grant waits for a retry");
        })?
        .ok_or_else(|| pool_not_found(&pool_pda_str))?;
    crate::fault::point("recorded");
    let recorded = match doc.recording(&grant) {
        Recording::Present(recorded) => recorded,
        Recording::Superseded(_) => return Err(superseded()),
        Recording::Add => return Err(ApiError::internal("the grant wasn't recorded")),
    };

    info!(
        pool = %pool_pda_str,
        grant_id = %recorded.grant_id,
        analysis = %payload.analysis_id,
        signature = %signature,
        "Analyst granted"
    );
    op.finish(StatusCode::OK, &entry(&state, recorded, Some(&analyst)))
        .await
}

// ============================================================================
// POST /v1/drt/pools/{pool_pda}/revoke-grant
// ============================================================================

/// Revoke an analyst's access to the pool's analysis.
///
/// Records the revocation first, which ends access at once, then closes
/// the Grant PDA under the stored-transaction rule and records that too.
#[utoipa::path(
    post,
    path = "/v1/drt/pools/{pool_pda}/revoke-grant",
    tag = "Grants",
    summary = "Revoke an analyst's grant",
    description = "End an analyst's access to the pool's analysis: record the revocation in the pool's document, which ends access at once, then close the Grant PDA on-chain (its rent returns to the pool's owner). If the analyst's last grant is already revoked, this finishes closing it, or returns it if it's closed. Needs `pools:write` and pool ownership. Idempotent.",
    security(("bearer_auth" = [])),
    params(
        ("pool_pda" = String, Path, description = "Pool PDA address (base58)"),
        ("Idempotency-Key" = String, Header, format = "uuid", description = "A UUID naming this user action; reuse it on every retry"),
    ),
    request_body = GrantRequest,
    responses(
        (status = 200, description = "The revoked grant", body = GrantEntry),
        (status = 400, description = "No Idempotency-Key, or Solana refused the close (`transaction_rejected`)"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Not the pool's owner"),
        (status = 404, description = "Pool or analysis not found, or the analyst has no grant (`no_grant`)"),
        (status = 409, description = "The pool changed concurrently; retry"),
        (status = 422, description = "The Idempotency-Key was used for a different request"),
        (status = 503, description = "Solana RPC unavailable"),
    )
)]
pub async fn revoke_grant(
    caller: Caller,
    request: Idempotent,
    State(state): State<AppState>,
    Path(pool_pda_str): Path<String>,
    JsonBody {
        value: payload,
        bytes,
    }: JsonBody<GrantRequest>,
) -> Result<Response, ApiError> {
    caller.require(Permission::PoolsWrite)?;
    let mut op = open_or_replay!(state, &caller.user_id, request, &bytes);
    let pool_pda = parse_pda(&pool_pda_str)?;
    let doc = load_pool(&state, &pool_pda_str).await?;
    let drt = analysis_drt(&doc, &payload.analysis_id)?.clone();
    let keypair = owner_keypair(&state, &caller, &pool_pda).await?;
    let analyst = state
        .storage
        .identities()
        .by_user_id(&payload.analyst_user_id)
        .await?;
    let (analyst_id, analysis_id) = (&payload.analyst_user_id, &payload.analysis_id);
    let revocation_id = ids::revocation_id(&caller.user_id, &pool_pda_str, &request.key);
    let right_id = decode_right_id(&drt.right_id_hex)?;
    let pool_uuid = decode_right_id(&doc.pool_uuid_hex)?;
    let commitment = state
        .commitments
        .commitment(analyst_id, &pool_uuid, &right_id);
    let is_mine = |g: &Grant| {
        g.revoked
            .as_ref()
            .is_some_and(|r| r.revocation_id == revocation_id)
    };
    let is_pending = |g: &Grant| g.revoked.as_ref().is_some_and(|r| r.signature.is_none());

    // A burn that no request recorded, such as one whose request died, is
    // revoked too, so the reconciler can't record it afterwards.
    let unrecorded = if doc.grants.iter().any(is_mine)
        || doc.active_grant(analyst_id, analysis_id).is_some()
        || doc
            .latest_grant(analyst_id, analysis_id)
            .is_some_and(is_pending)
    {
        false
    } else {
        let (grant_pda, _) = derive_grant_pda(&commitment);
        let rpc = state.solana_client.rpc();
        let exists = |level| rpc.account_exists(&grant_pda, level);
        if exists("finalized").await.map_err(rpc_error)? {
            true
        } else if exists("confirmed").await.map_err(rpc_error)? {
            return Err(ApiError::conflict(
                "a grant to this analyst is still settling on-chain; retry in a few seconds",
            )
            .with_code("grant_settling"));
        } else {
            false
        }
    };

    // ── RECORD THE REVOCATION ─────────────────────────────────────
    // This request's revocation if an attempt recorded it; else the active
    // grant; else the last grant, to finish or return its close.
    let revocation = GrantRevocation {
        revocation_id: revocation_id.clone(),
        revoked_by: caller.user_id.clone(),
        revoked_at: Utc::now(),
        signature: None,
    };
    let mut target = String::new();
    op.begin().await?;
    let doc = state
        .storage
        .pools()
        .update::<ApiError>(&pool_pda_str, |doc| {
            if let Some(grant) = doc.grants.iter().find(|g| is_mine(g)) {
                target = grant.grant_id.clone();
                return Ok(Change::Unchanged);
            }
            let active = doc.grants.iter_mut().find(|g| {
                &g.analyst == analyst_id && &g.drt_name == analysis_id && g.revoked.is_none()
            });
            if let Some(grant) = active {
                grant.revoked = Some(revocation.clone());
                target = grant.grant_id.clone();
                return Ok(Change::Changed);
            }
            let last = doc.latest_grant(analyst_id, analysis_id);
            match last {
                Some(last) if is_pending(last) || !unrecorded => {
                    target = last.grant_id.clone();
                    Ok(Change::Unchanged)
                }
                _ if unrecorded => {
                    target = revocation_id.clone();
                    doc.grants.push(Grant {
                        grant_id: revocation_id.clone(),
                        analyst: analyst_id.clone(),
                        drt_name: analysis_id.clone(),
                        commitment: hex::encode(commitment),
                        granted_by: String::new(),
                        granted_at: revocation.revoked_at,
                        signature: None,
                        revoked: Some(revocation.clone()),
                    });
                    Ok(Change::Changed)
                }
                _ => Err(
                    ApiError::not_found("the analyst has no grant to this analysis")
                        .with_code("no_grant"),
                ),
            }
        })
        .await?
        .ok_or_else(|| pool_not_found(&pool_pda_str))?;
    audit::grant(&target);
    let grant = doc
        .grants
        .iter()
        .find(|g| g.grant_id == target)
        .ok_or_else(|| ApiError::internal("the revoked grant vanished"))?;
    if grant
        .revoked
        .as_ref()
        .is_some_and(|r| r.signature.is_some())
    {
        return op
            .finish(StatusCode::OK, &entry(&state, grant, analyst.as_ref()))
            .await;
    }
    crate::fault::point("staged");

    // ── CLOSE THE GRANT PDA ───────────────────────────────────────
    let commitment = grant
        .commitment_bytes()
        .ok_or_else(|| ApiError::internal("a grant has no commitment"))?;
    let (grant_pda, _) = derive_grant_pda(&commitment);
    let (drt_config_pda, _) = derive_drt_config_pda(&pool_pda, &right_id);
    let ix = build_revoke_grant(&keypair.pubkey(), &pool_pda, &drt_config_pda, &commitment);
    let signature = chain::run(
        &state.solana_client,
        &mut op,
        &Effect::Closed(grant_pda),
        "finalized",
        signed(&keypair, std::slice::from_ref(&ix)),
    )
    .await?;
    audit::signature(&signature);

    let doc = state
        .storage
        .pools()
        .update::<ApiError>(&pool_pda_str, |doc| {
            let closing = doc
                .grants
                .iter_mut()
                .find(|g| g.grant_id == target)
                .and_then(|g| g.revoked.as_mut())
                .filter(|r| r.signature.is_none());
            match closing {
                Some(revoked) => {
                    revoked.signature = Some(signature.clone());
                    Ok(Change::Changed)
                }
                None => Ok(Change::Unchanged),
            }
        })
        .await?
        .ok_or_else(|| pool_not_found(&pool_pda_str))?;
    crate::fault::point("recorded");
    let grant = doc
        .grants
        .iter()
        .find(|g| g.grant_id == target)
        .ok_or_else(|| ApiError::internal("the revoked grant vanished"))?;

    info!(
        pool = %pool_pda_str,
        grant_id = %grant.grant_id,
        analysis = %payload.analysis_id,
        signature = %signature,
        "Analyst grant revoked"
    );
    op.finish(StatusCode::OK, &entry(&state, grant, analyst.as_ref()))
        .await
}

// ============================================================================
// GET /v1/drt/pools/{pool_pda}/grants
// ============================================================================

/// A pool's grants, newest first, active and revoked.
#[utoipa::path(
    get,
    path = "/v1/drt/pools/{pool_pda}/grants",
    tag = "Grants",
    summary = "List a pool's grants",
    description = "Every grant of the pool's analysis, active, being revoked or revoked, newest first, with each analyst's email and name as of their last sign-in. Needs `pools:read`.",
    security(("bearer_auth" = [])),
    params(
        ("pool_pda" = String, Path, description = "Pool PDA address (base58)"),
    ),
    responses(
        (status = 200, description = "The grants", body = GrantsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Needs pools:read"),
        (status = 404, description = "Pool not found"),
    )
)]
pub async fn list_grants(
    caller: Caller,
    State(state): State<AppState>,
    Path(pool_pda_str): Path<String>,
) -> Result<Json<GrantsResponse>, ApiError> {
    caller.require(Permission::PoolsRead)?;
    let doc = load_pool(&state, &pool_pda_str).await?;
    let identities: HashMap<String, Identity> = state
        .storage
        .identities()
        .all()
        .await?
        .into_iter()
        .map(|i| (i.user_id.clone(), i))
        .collect();
    let grants = doc
        .grants
        .iter()
        .rev()
        .map(|g| entry(&state, g, identities.get(&g.analyst)))
        .collect();
    Ok(Json(GrantsResponse {
        pool_pda: pool_pda_str,
        grants,
    }))
}

// ============================================================================
// GET /v1/drt/me/analyses
// ============================================================================

/// The analyses the caller may run.
#[utoipa::path(
    get,
    path = "/v1/drt/me/analyses",
    tag = "Grants",
    summary = "My analyses",
    description = "The analyses the caller may run, by pool name: for an admin every pool's, with every row; for an analyst those they hold an active grant to. Needs `analyses:run`.",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "The caller's analyses", body = MyAnalysesResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Needs analyses:run"),
    )
)]
pub async fn my_analyses(
    caller: Caller,
    State(state): State<AppState>,
) -> Result<Json<MyAnalysesResponse>, ApiError> {
    caller.require(Permission::AnalysesRun)?;
    let admin = caller.is_admin();
    let mut analyses: Vec<MyAnalysis> = state
        .storage
        .pools()
        .all()
        .await?
        .into_iter()
        .filter_map(|doc| {
            let analysis = doc.analysis.as_ref()?;
            let granted_at = if admin {
                None
            } else {
                Some(
                    doc.active_grant(&caller.user_id, &analysis.analysis_id)?
                        .granted_at,
                )
            };
            Some(MyAnalysis {
                pool_pda: doc.pool_pda.clone(),
                pool_name: doc.pool_name.clone(),
                analysis_id: analysis.analysis_id.clone(),
                display_name: analysis.display_name.clone(),
                access: if admin { "admin" } else { "grant" }.into(),
                granted_at,
            })
        })
        .collect();
    analyses.sort_by(|a, b| (&a.pool_name, &a.pool_pda).cmp(&(&b.pool_name, &b.pool_pda)));
    Ok(Json(MyAnalysesResponse { analyses }))
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::atomic::Ordering::SeqCst;

    use axum::body::Body;
    use axum::http::{header, Request};
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;
    use serde_json::{json, Value};

    use super::*;
    use crate::api::credentials::tests::{
        initial_upload, send, sign_in, worker, Admin, Worker, POOL_UUID,
    };
    use crate::auth::entra::mint::Spec;
    use crate::auth::entra::tests::{config, entra_key};
    use crate::blockchain::drt::types::{DISC_GRANT_RIGHT, DISC_REVOKE_GRANT};
    use crate::idempotency::{KEY_HEADER, REPLAYED_HEADER};
    use crate::storage::pools::AnalysisRef;

    pub(crate) const ANALYSIS: &str = "awards-report-v1";
    const EXECUTE_RIGHT_ID: [u8; 16] = [9; 16];

    fn execute_mint(pool_pda: &Pubkey) -> Pubkey {
        Pubkey::find_program_address(&[b"execute", pool_pda.as_ref()], &Pubkey::default()).0
    }

    /// A ready pool of `owner`'s whose analysis is the Awards Report, with
    /// `held` of its Execute DRTs in `owner`'s wallet.
    pub(crate) async fn analysis_pool(worker: &Worker, owner: &Admin, held: u64) -> Pubkey {
        let pool_pda = worker
            .pool(owner, Some(initial_upload(&owner.user_id)))
            .await;
        let url = crate::analysis::fetch::tests::AWARDS_REPORT_URL.to_string();
        let hash = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(
            crate::analysis::definition::tests::AWARDS_REPORT,
        ));
        worker
            .storage
            .pools()
            .update::<ApiError>(&pool_pda.to_string(), |doc| {
                doc.analysis = Some(AnalysisRef {
                    analysis_id: ANALYSIS.into(),
                    display_name: "Awards Report".into(),
                    code_repo_url: url.clone(),
                    code_hash_hex: hash.clone(),
                });
                doc.drts.insert(
                    ANALYSIS.into(),
                    DrtMetadata {
                        right_id_hex: hex::encode(EXECUTE_RIGHT_ID),
                        mint: execute_mint(&pool_pda).to_string(),
                        supply: 3,
                        code_repo_url: url.clone(),
                        code_hash_hex: hash.clone(),
                    },
                );
                Ok(Change::Changed)
            })
            .await
            .unwrap();
        worker.holds(owner, &execute_mint(&pool_pda), held);
        pool_pda
    }

    /// An analyst in `groups` who has signed in: their token and user ID.
    pub(crate) async fn analyst(
        app: &axum::Router,
        oid: &str,
        groups: &[&str],
    ) -> (String, String) {
        let mut spec = Spec::valid(&config());
        spec.oid = oid.into();
        spec.roles = vec!["Analyst".into()];
        spec.groups = groups.iter().map(|g| g.to_string()).collect();
        spec.email = Some(format!("{oid}@example.com"));
        let token = spec.sign(entra_key()).unwrap();
        let user_id = sign_in(app, &token).await;
        (token, user_id)
    }

    fn post(path: &str, token: &str, key: &str, body: &Value) -> Request<Body> {
        Request::post(path)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(&KEY_HEADER, key)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    fn get(path: &str, token: &str) -> Request<Body> {
        Request::get(path)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    }

    fn new_key() -> String {
        uuid::Uuid::new_v4().to_string()
    }

    fn grant_pda(worker: &Worker, analyst: &str) -> Pubkey {
        let commitment = worker
            .commitments
            .commitment(analyst, &POOL_UUID, &EXECUTE_RIGHT_ID);
        derive_grant_pda(&commitment).0
    }

    /// The DRT program call in the `n`th transaction sent: its discriminator
    /// and commitment.
    fn sent_call(worker: &Worker, n: usize) -> ([u8; 8], [u8; 32]) {
        let bytes = BASE64.decode(&worker.chain.sent()[n]).unwrap();
        let tx: solana_transaction::Transaction = bincode::deserialize(&bytes).unwrap();
        let keys = &tx.message.account_keys;
        let ix = tx
            .message
            .instructions
            .iter()
            .find(|ix| keys[usize::from(ix.program_id_index)] == crate::config::drt_program_id())
            .unwrap();
        (
            ix.data[..8].try_into().unwrap(),
            ix.data[8..40].try_into().unwrap(),
        )
    }

    #[tokio::test]
    async fn a_grant_burns_one_execute_drt_and_granting_again_burns_none() {
        let worker = worker();
        let owner = worker.admin("oid-owner").await;
        let pool_pda = analysis_pool(&worker, &owner, 2).await;
        let (analyst_token, analyst_id) = analyst(&worker.app, "oid-ana", &[]).await;
        worker.chain.lands.store(true, SeqCst);
        let path = format!("/v1/drt/pools/{pool_pda}/grant");
        let body = json!({ "analyst_user_id": analyst_id, "analysis_id": ANALYSIS });

        let key = new_key();
        let (status, _, granted) = send(&worker.app, post(&path, &owner.token, &key, &body)).await;
        assert_eq!(status, StatusCode::OK, "{granted}");
        assert_eq!(granted["status"], "active");
        assert_eq!(granted["analyst_email"], "oid-ana@example.com");
        assert_eq!(granted["granted_by"], owner.user_id.as_str());
        let commitment = worker
            .commitments
            .commitment(&analyst_id, &POOL_UUID, &EXECUTE_RIGHT_ID);
        assert_eq!(sent_call(&worker, 0), (DISC_GRANT_RIGHT, commitment));

        // A retry replays, and another grant finds the active one.
        let (status, headers, again) =
            send(&worker.app, post(&path, &owner.token, &key, &body)).await;
        assert_eq!((status, &again), (StatusCode::OK, &granted));
        assert_eq!(headers[&REPLAYED_HEADER], "true");
        let (status, _, second) =
            send(&worker.app, post(&path, &owner.token, &new_key(), &body)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(second["grant_id"], granted["grant_id"]);
        assert_eq!(worker.chain.sent().len(), 1, "one burn");

        let grants = format!("/v1/drt/pools/{pool_pda}/grants");
        let (_, _, list) = send(&worker.app, get(&grants, &owner.token)).await;
        assert_eq!(list["grants"], json!([granted]));
        let (_, _, mine) = send(&worker.app, get("/v1/drt/me/analyses", &analyst_token)).await;
        assert_eq!(
            mine["analyses"],
            json!([{
                "pool_pda": pool_pda.to_string(),
                "pool_name": "Sealed",
                "analysis_id": ANALYSIS,
                "display_name": "Awards Report",
                "access": "grant",
                "granted_at": granted["granted_at"],
            }])
        );
        let (_, _, all) = send(&worker.app, get("/v1/drt/me/analyses", &owner.token)).await;
        assert_eq!(all["analyses"][0]["access"], "admin");

        // Analysts neither grant nor list grants.
        let (status, _, _) =
            send(&worker.app, post(&path, &analyst_token, &new_key(), &body)).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _, _) = send(&worker.app, get(&grants, &analyst_token)).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn a_revocation_ends_access_at_once_and_a_regrant_waits_for_its_close() {
        let worker = worker();
        let owner = worker.admin("oid-owner").await;
        let pool_pda = analysis_pool(&worker, &owner, 2).await;
        let (_, analyst_id) = analyst(&worker.app, "oid-ana", &[]).await;
        worker.chain.lands.store(true, SeqCst);
        let grant_path = format!("/v1/drt/pools/{pool_pda}/grant");
        let revoke_path = format!("/v1/drt/pools/{pool_pda}/revoke-grant");
        let body = json!({ "analyst_user_id": analyst_id, "analysis_id": ANALYSIS });
        let (status, _, granted) = send(
            &worker.app,
            post(&grant_path, &owner.token, &new_key(), &body),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{granted}");
        let pda = grant_pda(&worker, &analyst_id);
        worker.chain.accounts.lock().unwrap().push(pda);

        // The close fails, but access has already ended.
        let refused = json!({ "InstructionError": [0, "Custom"] });
        *worker.chain.preflight.lock().unwrap() = Some(refused);
        let first_key = new_key();
        let (status, _, err) = send(
            &worker.app,
            post(&revoke_path, &owner.token, &first_key, &body),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{err}");
        assert_eq!(err["code"], "transaction_rejected");
        let doc = worker
            .storage
            .pools()
            .get(&pool_pda.to_string())
            .await
            .unwrap()
            .unwrap();
        assert!(doc.active_grant(&analyst_id, ANALYSIS).is_none());
        let grants = format!("/v1/drt/pools/{pool_pda}/grants");
        let (_, _, list) = send(&worker.app, get(&grants, &owner.token)).await;
        assert_eq!(list["grants"][0]["status"], "revoking");

        // Until the close is recorded, the analyst can't be granted again.
        let (status, _, err) = send(
            &worker.app,
            post(&grant_path, &owner.token, &new_key(), &body),
        )
        .await;
        assert_eq!(
            (status, err["code"].as_str()),
            (StatusCode::CONFLICT, Some("revocation_pending"))
        );

        // Another revocation finishes the close.
        *worker.chain.preflight.lock().unwrap() = None;
        let (status, _, revoked) = send(
            &worker.app,
            post(&revoke_path, &owner.token, &new_key(), &body),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{revoked}");
        assert_eq!(revoked["grant_id"], granted["grant_id"]);
        assert_eq!(revoked["status"], "revoked");
        assert!(revoked["revoke_signature"].is_string());
        let sent = worker.chain.sent();
        assert_eq!(sent_call(&worker, sent.len() - 1).0, DISC_REVOKE_GRANT);
        worker.chain.accounts.lock().unwrap().retain(|a| *a != pda);

        // The first revocation's retry finds its grant closed.
        let (status, _, retried) = send(
            &worker.app,
            post(&revoke_path, &owner.token, &first_key, &body),
        )
        .await;
        assert_eq!((status, &retried), (StatusCode::OK, &revoked));
        assert_eq!(
            worker.chain.sent().len(),
            sent.len(),
            "nothing more was sent"
        );

        // Now a grant burns again, as a new grant.
        let (status, _, regranted) = send(
            &worker.app,
            post(&grant_path, &owner.token, &new_key(), &body),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{regranted}");
        assert_eq!(regranted["status"], "active");
        assert_ne!(regranted["grant_id"], granted["grant_id"]);
        let (_, _, list) = send(&worker.app, get(&grants, &owner.token)).await;
        let statuses: Vec<_> = list["grants"]
            .as_array()
            .unwrap()
            .iter()
            .map(|g| g["status"].as_str().unwrap())
            .collect();
        assert_eq!(statuses, ["active", "revoked"], "newest first");
    }

    #[tokio::test]
    async fn a_burn_no_request_recorded_is_revoked_and_never_restored() {
        let worker = worker();
        let owner = worker.admin("oid-owner").await;
        let pool_pda = analysis_pool(&worker, &owner, 2).await;
        let (_, analyst_id) = analyst(&worker.app, "oid-ana", &[]).await;
        let commitment = worker
            .commitments
            .commitment(&analyst_id, &POOL_UUID, &EXECUTE_RIGHT_ID);

        // A grant request staged and burned, then died.
        let staged_at = Utc::now() - chrono::Duration::minutes(11);
        let lost = Grant {
            grant_id: "g-lost".into(),
            analyst: analyst_id.clone(),
            drt_name: ANALYSIS.into(),
            commitment: hex::encode(commitment),
            granted_by: owner.user_id.clone(),
            granted_at: staged_at,
            signature: None,
            revoked: None,
        };
        let saga = Saga::Grant {
            pool_pda: pool_pda.to_string(),
            grant: lost,
        };
        let staged = Staged {
            record: "idempotency/lost.json".into(),
            staged_at,
            saga,
        };
        worker
            .storage
            .sagas()
            .stage("grant-g-lost", staged)
            .await
            .unwrap();
        worker
            .chain
            .accounts
            .lock()
            .unwrap()
            .push(derive_grant_pda(&commitment).0);
        worker.chain.lands.store(true, SeqCst);

        let path = format!("/v1/drt/pools/{pool_pda}/revoke-grant");
        let body = json!({ "analyst_user_id": analyst_id, "analysis_id": ANALYSIS });
        let (status, _, revoked) =
            send(&worker.app, post(&path, &owner.token, &new_key(), &body)).await;
        assert_eq!(status, StatusCode::OK, "{revoked}");
        assert_eq!(revoked["status"], "revoked");
        assert_eq!(revoked["granted_by"], "");
        assert!(revoked.get("signature").is_none());
        assert_eq!(sent_call(&worker, 0), (DISC_REVOKE_GRANT, commitment));

        // The reconciler leaves the lost grant alone: the revocation came after it.
        let solana = crate::blockchain::fake::start(worker.chain.clone());
        let timing = crate::reconciler::Timing::default();
        let finished = crate::reconciler::reconcile(&worker.storage, &solana, timing.min_age)
            .await
            .unwrap();
        assert_eq!(finished, 0);
        let doc = worker
            .storage
            .pools()
            .get(&pool_pda.to_string())
            .await
            .unwrap()
            .unwrap();
        assert!(doc.active_grant(&analyst_id, ANALYSIS).is_none());
        assert_eq!(doc.grants.len(), 1);
    }

    #[tokio::test]
    async fn only_the_pool_owner_grants_and_only_to_someone_who_signed_in() {
        let worker = worker();
        let owner = worker.admin("oid-owner").await;
        let other = worker.admin("oid-other").await;
        let pool_pda = analysis_pool(&worker, &owner, 0).await;
        let (analyst_token, analyst_id) = analyst(&worker.app, "oid-ana", &[]).await;
        let path = format!("/v1/drt/pools/{pool_pda}/grant");
        let body = |analyst: &str, analysis: &str| json!({ "analyst_user_id": analyst, "analysis_id": analysis });
        for (token, body, status, code) in [
            (
                &other.token,
                body(&analyst_id, ANALYSIS),
                StatusCode::FORBIDDEN,
                "forbidden",
            ),
            (
                &analyst_token,
                body(&analyst_id, ANALYSIS),
                StatusCode::FORBIDDEN,
                "forbidden",
            ),
            (
                &owner.token,
                body("nobody", ANALYSIS),
                StatusCode::NOT_FOUND,
                "not_found",
            ),
            (
                &owner.token,
                body(&analyst_id, "mean"),
                StatusCode::NOT_FOUND,
                "not_found",
            ),
            (
                &owner.token,
                body(&analyst_id, ANALYSIS),
                StatusCode::BAD_REQUEST,
                "supply_exhausted",
            ),
        ] {
            let (got, _, err) = send(&worker.app, post(&path, token, &new_key(), &body)).await;
            assert_eq!(
                (got, err["code"].as_str()),
                (status, Some(code)),
                "{body}: {err}"
            );
        }

        let revoke = format!("/v1/drt/pools/{pool_pda}/revoke-grant");
        let request = post(
            &revoke,
            &owner.token,
            &new_key(),
            &body(&analyst_id, ANALYSIS),
        );
        let (status, _, err) = send(&worker.app, request).await;
        assert_eq!(
            (status, err["code"].as_str()),
            (StatusCode::NOT_FOUND, Some("no_grant"))
        );
        let request = post(
            &revoke,
            &other.token,
            &new_key(),
            &body(&analyst_id, ANALYSIS),
        );
        assert_eq!(send(&worker.app, request).await.0, StatusCode::FORBIDDEN);
        assert!(worker.chain.sent().is_empty());
    }
}
