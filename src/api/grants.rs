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
//! staged before a revocation is never recorded after it. Recording a grant
//! or a revocation, and changing a grant's targets, each make the pool's
//! next generation (see [`crate::generation`]).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::str::FromStr;
use std::sync::Arc;

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

use crate::analysis::definition::Definition;
use crate::analysis::table::{check_targets, Target};
use crate::api::credentials::{decode_right_id, parse_pda, pool_not_found};
use crate::api::pools::{explorer_url, load_pool, signed, verify_pool_ownership};
use crate::audit;
use crate::auth::{Caller, Permission};
use crate::blockchain::drt::{
    accounts::{fetch_grant_state, fetch_pool, GrantState},
    instructions::{build_grant_right, build_revoke_grant},
    pda::{derive_drt_config_pda, derive_grant_pda, derive_user_ata},
};
use crate::blockchain::signing::keypair_from_bytes_verified;
use crate::blockchain::spl_token::token_account_amount;
use crate::chain::{self, Effect};
use crate::error::ApiError;
use crate::generation;
use crate::idempotency::{Idempotent, JsonBody};
use crate::ids;
use crate::state::AppState;
use crate::storage::chain::Seen;
use crate::storage::identities::Identity;
use crate::storage::pools::{DrtMetadata, Grant, GrantRevocation, GrantScope, PoolDoc, Recording};
use crate::storage::staged::{Saga, Staged};
use crate::storage::Change;

// ============================================================================
// Request / Response types
// ============================================================================

/// An analyst, one of the pool's analyses, and the rows they see.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct GrantRequest {
    /// The analyst's `user_id`, as `GET /v1/users?email=` finds it.
    pub analyst_user_id: String,
    /// The pool's analysis: its `analysis_id`.
    pub analysis_id: String,
    /// What the analyst sees: the rows of any of these, such as employer
    /// group "Group A" and employer "Bank B". Keys are the analysis's scope
    /// keys, values as the data holds them.
    pub scope: Vec<Target>,
}

/// An analyst and one of the pool's analyses, and the grant to revoke.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RevokeGrantRequest {
    /// The analyst's `user_id`.
    pub analyst_user_id: String,
    /// The pool's analysis: its `analysis_id`.
    pub analysis_id: String,
    /// The grant to revoke, as `GET …/grants` lists it: only that grant is
    /// ever revoked or closed. Without it, the analyst's active grant, or
    /// else their last one, or a burn of theirs that no request recorded.
    #[serde(default)]
    pub grant_id: Option<String>,
}

/// New targets for an analyst's active grant.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct GrantScopeRequest {
    /// The grant to change, as `GET …/grants` lists it. A revision belongs
    /// to one grant: a later grant to the same analyst starts again at 1.
    pub grant_id: String,
    /// The analyst's `user_id`.
    pub analyst_user_id: String,
    /// The pool's analysis: its `analysis_id`.
    pub analysis_id: String,
    /// The grant's `scope_revision` the edit started from.
    pub revision: usize,
    /// What the analyst sees from now on.
    pub scope: Vec<Target>,
}

/// A target, with the CSV header of the column it restricts.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ScopeTarget {
    pub key: String,
    pub header: String,
    pub value: String,
}

/// Where a grant stands: `active`; `revoking` (access has ended, and the
/// Grant PDA's close hasn't been recorded yet: revoke again to finish it);
/// or `revoked`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum GrantStatus {
    Active,
    Revoking,
    Revoked,
}

/// What the chain last showed at a grant's Grant PDA: `live` (the program's
/// Grant for the pool's Execute DRT), `closed`, or `unknown` when it hasn't
/// been read and couldn't be.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum GrantOnChain {
    Live,
    Closed,
    Unknown,
}

/// How the caller runs an analysis: `admin`, every row, with no grant; or
/// `grant`, the rows their grant's employer scope allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Access {
    Admin,
    Grant,
}

/// One setting of a grant's targets.
#[derive(Debug, Serialize, ToSchema)]
pub struct ScopeChange {
    /// 1 for the targets the grant was made with.
    pub revision: usize,
    pub scope: Vec<ScopeTarget>,
    /// The `user_id` who set them.
    pub set_by: String,
    pub set_at: DateTime<Utc>,
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
    /// What the analyst sees now: the rows of any of these. Empty for a
    /// grant that sees none.
    pub scope: Vec<ScopeTarget>,
    /// How many times the targets were set; an edit names it.
    pub scope_revision: usize,
    /// Every setting of the targets, oldest first.
    pub scope_history: Vec<ScopeChange>,
    pub status: GrantStatus,
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
    /// The grant's Grant PDA, the on-chain receipt of its burn.
    pub grant_pda: String,
    pub on_chain: GrantOnChain,
    /// When the chain was last read for it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_at: Option<DateTime<Utc>>,
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
    pub access: Access,
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

/// The definition of `doc`'s analysis.
async fn analysis_definition(state: &AppState, doc: &PoolDoc) -> Result<Arc<Definition>, ApiError> {
    let analysis = doc
        .analysis
        .as_ref()
        .ok_or_else(|| ApiError::not_found("this pool has no analysis"))?;
    state
        .analyses
        .definition(&state.storage, &analysis.code_hash_hex)
        .await
}

fn invalid_scope(message: String) -> ApiError {
    ApiError::bad_request(message).with_code("invalid_scope")
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

fn address_taken() -> ApiError {
    ApiError::conflict(
        "this analyst's Grant PDA is taken by a DRT of another pool, so no burn can land there",
    )
    .with_code("grant_pda_taken")
}

fn superseded() -> ApiError {
    ApiError::conflict("the analyst's grant was revoked after this request began; grant again")
        .with_code("grant_superseded")
}

/// `404 no_grant`: the analyst has no such grant to revoke or change.
fn no_grant() -> ApiError {
    ApiError::not_found("the analyst has no such grant to this analysis").with_code("no_grant")
}

/// `grant_id` named a grant of another analyst or analysis.
fn grant_mismatch() -> ApiError {
    ApiError::bad_request("grant_id names a grant of another analyst or analysis")
        .with_code("grant_mismatch")
}

/// What the chain showed of a grant: its PDA, and the reading, if any.
type OnChain = (Pubkey, Option<Seen>);

/// Each scope key of a definition, and the CSV header of its column.
type Headers = BTreeMap<String, String>;

fn headers(def: &Definition) -> Headers {
    def.scope
        .iter()
        .map(|(key, column)| {
            let header = def.column(column).map_or(key, |c| &c.header);
            (key.clone(), header.clone())
        })
        .collect()
}

/// The headers of `doc`'s analysis's scope keys, if it has an analysis.
async fn pool_headers(state: &AppState, doc: &PoolDoc) -> Result<Headers, ApiError> {
    match &doc.analysis {
        Some(analysis) => {
            let def = state
                .analyses
                .definition(&state.storage, &analysis.code_hash_hex)
                .await?;
            Ok(headers(&def))
        }
        None => Ok(Headers::new()),
    }
}

fn described(targets: &BTreeSet<Target>, headers: &Headers) -> Vec<ScopeTarget> {
    targets
        .iter()
        .map(|t| ScopeTarget {
            key: t.key.clone(),
            header: headers.get(&t.key).unwrap_or(&t.key).clone(),
            value: t.value.clone(),
        })
        .collect()
}

fn entry(
    state: &AppState,
    grant: &Grant,
    analyst: Option<&Identity>,
    on_chain: Option<&OnChain>,
    headers: &Headers,
) -> GrantEntry {
    let revoked = grant.revoked.as_ref();
    let signature = grant.signature.clone();
    let seen = on_chain.and_then(|(_, seen)| *seen);
    GrantEntry {
        grant_id: grant.grant_id.clone(),
        analyst_user_id: grant.analyst.clone(),
        analyst_email: analyst.map(|i| i.email.clone()).unwrap_or_default(),
        analyst_display_name: analyst.map(|i| i.display_name.clone()).unwrap_or_default(),
        analysis_id: grant.drt_name.clone(),
        scope: grant
            .targets()
            .map(|t| described(t, headers))
            .unwrap_or_default(),
        scope_revision: grant.scope_revision(),
        scope_history: grant
            .scopes
            .iter()
            .enumerate()
            .map(|(i, s)| ScopeChange {
                revision: i + 1,
                scope: described(&s.targets, headers),
                set_by: s.set_by.clone(),
                set_at: s.set_at,
            })
            .collect(),
        status: match revoked {
            None => GrantStatus::Active,
            Some(r) if r.signature.is_none() => GrantStatus::Revoking,
            Some(_) => GrantStatus::Revoked,
        },
        granted_by: grant.granted_by.clone(),
        granted_at: grant.granted_at,
        explorer_url: signature.as_deref().map(|s| explorer_url(state, s)),
        signature,
        revoked_by: revoked.map(|r| r.revoked_by.clone()),
        revoked_at: revoked.map(|r| r.revoked_at),
        revoke_signature: revoked.and_then(|r| r.signature.clone()),
        grant_pda: grant
            .commitment_bytes()
            .map(|c| derive_grant_pda(&c).0.to_string())
            .unwrap_or_default(),
        on_chain: match seen {
            Some(seen) if seen.live => GrantOnChain::Live,
            Some(_) => GrantOnChain::Closed,
            None => GrantOnChain::Unknown,
        },
        verified_at: seen.map(|s| s.at),
    }
}

/// What the chain shows of `doc`'s grants, read again if the readings are
/// old.
async fn statuses(state: &AppState, doc: &PoolDoc) -> BTreeMap<String, OnChain> {
    state
        .grant_checks
        .statuses(&state.storage, &state.solana_client, doc)
        .await
}

/// Read the chain again for `doc`'s grants, after a burn or a close, so
/// every reading on this worker is current. A failure only means the next
/// request reads it.
async fn reread(state: &AppState, doc: &PoolDoc) -> BTreeMap<String, OnChain> {
    if let Err(e) = state
        .grant_checks
        .refresh(&state.storage, &state.solana_client, doc)
        .await
    {
        warn!(pool = %doc.pool_pda, error = %e, "Reading grants on-chain failed");
    }
    state
        .grant_checks
        .statuses(&state.storage, &state.solana_client, doc)
        .await
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
    let def = analysis_definition(&state, &doc).await?;
    let targets = check_targets(&def, &payload.scope).map_err(invalid_scope)?;
    let headers = headers(&def);
    let analyst = state
        .storage
        .identities()
        .by_user_id(&payload.analyst_user_id)
        .await?
        .ok_or_else(|| ApiError::not_found("no user with that user_id is known"))?;
    let grant_id = ids::grant_id(&caller.user_id, &pool_pda_str, &request.key);
    audit::grant(&grant_id);

    // This request's grant, or another active one: nothing to burn.
    let mine = doc.grants.iter().find(|g| g.grant_id == grant_id);
    let active = doc.active_grant(&analyst.user_id, &payload.analysis_id);
    if mine.is_none() && active.is_some_and(|g| g.targets() != Some(&targets)) {
        return Err(ApiError::conflict(
            "the analyst already has a grant to this analysis with other targets; change its scope instead",
        )
        .with_code("grant_active"));
    }
    if let Some(existing) = mine.or(active) {
        let on_chain = statuses(&state, &doc).await;
        let entry = entry(
            &state,
            existing,
            Some(&analyst),
            on_chain.get(&existing.grant_id),
            &headers,
        );
        return op.finish(StatusCode::OK, &entry).await;
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
    let (drt_config_pda, _) = derive_drt_config_pda(&pool_pda, &right_id);
    let rpc = state.solana_client.rpc();

    // Unless the burn already happened, the owner needs an Execute DRT.
    let on_chain = fetch_grant_state(rpc, &grant_pda, &drt_config_pda, "finalized")
        .await
        .map_err(rpc_error)?;
    if on_chain == GrantState::Foreign {
        return Err(address_taken());
    }
    if on_chain == GrantState::Absent {
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
                        staged_generation: Some(doc.generation),
                        signature: None,
                        revoked: None,
                        scopes: vec![GrantScope {
                            targets: targets.clone(),
                            set_by: caller.user_id.clone(),
                            set_at: Utc::now(),
                            change_id: grant_id.clone(),
                        }],
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
            let on_chain = statuses(&state, &doc).await;
            let entry = entry(
                &state,
                present,
                Some(&analyst),
                on_chain.get(&present.grant_id),
                &headers,
            );
            return op.finish(StatusCode::OK, &entry).await;
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
        &Effect::Grant {
            pda: grant_pda,
            drt_config: drt_config_pda,
        },
        "finalized",
        signed(&keypair, std::slice::from_ref(&ix)),
    )
    .await?;
    audit::signature(&signature);

    // ── RECORD ────────────────────────────────────────────────────
    // If this fails, a retry with the same key, or the reconciler, adds it.
    grant.signature = Some(signature.clone());
    let doc = generation::update(&state.storage, &state.solana_client, &pool_pda_str, |doc| {
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
    let on_chain = reread(&state, &doc).await;
    let entry = entry(
        &state,
        recorded,
        Some(&analyst),
        on_chain.get(&recorded.grant_id),
        &headers,
    );
    op.finish(StatusCode::OK, &entry).await
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
    description = "End an analyst's access to the pool's analysis: record the revocation in the pool's document, which ends access at once, then close the Grant PDA on-chain (its rent returns to the pool's owner). With `grant_id`, only that grant is revoked: if it's already revoked, this finishes closing it, or returns it if it's closed, and a later grant to the analyst is never touched. Without it, the analyst's active grant, or else their last one. Needs `pools:write` and pool ownership. Idempotent.",
    security(("bearer_auth" = [])),
    params(
        ("pool_pda" = String, Path, description = "Pool PDA address (base58)"),
        ("Idempotency-Key" = String, Header, format = "uuid", description = "A UUID naming this user action; reuse it on every retry"),
    ),
    request_body = RevokeGrantRequest,
    responses(
        (status = 200, description = "The revoked grant", body = GrantEntry),
        (status = 400, description = "No Idempotency-Key, `grant_id` names another analyst's or analysis's grant (`grant_mismatch`), or Solana refused the close (`transaction_rejected`)"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Not the pool's owner"),
        (status = 404, description = "Pool or analysis not found, or the analyst has no such grant (`no_grant`)"),
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
    }: JsonBody<RevokeGrantRequest>,
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
    let (drt_config_pda, _) = derive_drt_config_pda(&pool_pda, &right_id);
    let is_mine = |g: &Grant| {
        g.revoked
            .as_ref()
            .is_some_and(|r| r.revocation_id == revocation_id)
    };
    let is_pending = |g: &Grant| g.revoked.as_ref().is_some_and(|r| r.signature.is_none());

    // A burn that no request recorded, such as one whose request died, is
    // revoked too, so the reconciler can't record it afterwards. A request
    // that names its grant revokes only that one.
    let unrecorded = if payload.grant_id.is_some()
        || doc.grants.iter().any(is_mine)
        || doc.active_grant(analyst_id, analysis_id).is_some()
        || doc
            .latest_grant(analyst_id, analysis_id)
            .is_some_and(is_pending)
    {
        false
    } else {
        let (grant_pda, _) = derive_grant_pda(&commitment);
        let rpc = state.solana_client.rpc();
        let live = |level| async move {
            fetch_grant_state(rpc, &grant_pda, &drt_config_pda, level)
                .await
                .map(|s| s == GrantState::Live)
        };
        if live("finalized").await.map_err(rpc_error)? {
            true
        } else if live("confirmed").await.map_err(rpc_error)? {
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
        generation: None,
    };
    let mut target = String::new();
    op.begin().await?;
    let doc = generation::update(&state.storage, &state.solana_client, &pool_pda_str, |doc| {
        let revocation = GrantRevocation {
            generation: Some(doc.generation),
            ..revocation.clone()
        };
        if let Some(grant) = doc.grants.iter().find(|g| is_mine(g)) {
            target = grant.grant_id.clone();
            return Ok(Change::Unchanged);
        }
        if let Some(wanted) = &payload.grant_id {
            let grant = doc
                .grants
                .iter_mut()
                .find(|g| &g.grant_id == wanted)
                .ok_or_else(no_grant)?;
            if &grant.analyst != analyst_id || &grant.drt_name != analysis_id {
                return Err(grant_mismatch());
            }
            target = grant.grant_id.clone();
            if grant.revoked.is_some() {
                return Ok(Change::Unchanged);
            }
            grant.revoked = Some(revocation.clone());
            return Ok(Change::Changed);
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
                    staged_generation: None,
                    signature: None,
                    revoked: Some(revocation.clone()),
                    scopes: Vec::new(),
                });
                Ok(Change::Changed)
            }
            _ => Err(no_grant()),
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
        let on_chain = statuses(&state, &doc).await;
        let headers = pool_headers(&state, &doc).await?;
        let entry = entry(
            &state,
            grant,
            analyst.as_ref(),
            on_chain.get(&grant.grant_id),
            &headers,
        );
        return op.finish(StatusCode::OK, &entry).await;
    }
    crate::fault::point("staged");

    // ── CLOSE THE GRANT PDA ───────────────────────────────────────
    let commitment = grant
        .commitment_bytes()
        .ok_or_else(|| ApiError::internal("a grant has no commitment"))?;
    let (grant_pda, _) = derive_grant_pda(&commitment);
    let ix = build_revoke_grant(&keypair.pubkey(), &pool_pda, &drt_config_pda, &commitment);
    let signature = chain::run(
        &state.solana_client,
        &mut op,
        &Effect::Closed {
            pda: grant_pda,
            drt_config: drt_config_pda,
        },
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
    let on_chain = reread(&state, &doc).await;
    let headers = pool_headers(&state, &doc).await?;
    let entry = entry(
        &state,
        grant,
        analyst.as_ref(),
        on_chain.get(&grant.grant_id),
        &headers,
    );
    op.finish(StatusCode::OK, &entry).await
}

// ============================================================================
// POST /v1/drt/pools/{pool_pda}/grant-scope
// ============================================================================

/// Change which rows an analyst's active grant sees.
#[utoipa::path(
    post,
    path = "/v1/drt/pools/{pool_pda}/grant-scope",
    tag = "Grants",
    summary = "Change a grant's targets",
    description = "Set the targets of an analyst's active grant: from the next request on, the analyst sees the rows of any of them. Nothing is burned; like every change of who sees what, the edit mints one token of the pool's counter, so a restored older document can't undo it. The edit names the grant (`grant_id`) and its `scope_revision` it started from: an edit of a grant since revoked gets `409 grant_not_active`, even if the analyst was granted again; a stale revision gets `409 version_conflict`; and one that sets the targets the grant already has changes nothing. Every setting is kept in the grant's `scope_history`. Needs `pools:write` and pool ownership. Idempotent.",
    security(("bearer_auth" = [])),
    params(
        ("pool_pda" = String, Path, description = "Pool PDA address (base58)"),
        ("Idempotency-Key" = String, Header, format = "uuid", description = "A UUID naming this user action; reuse it on every retry"),
    ),
    request_body = GrantScopeRequest,
    responses(
        (status = 200, description = "The grant", body = GrantEntry),
        (status = 400, description = "Targets the analysis can't apply (`invalid_scope`), `grant_id` names another analyst's or analysis's grant (`grant_mismatch`), or no Idempotency-Key"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Not the pool's owner"),
        (status = 404, description = "Pool or analysis not found, or no such grant (`no_grant`)"),
        (status = 409, description = "The grant is revoked (`grant_not_active`), or its targets changed since `revision` (`version_conflict`)"),
        (status = 422, description = "The Idempotency-Key was used for a different request"),
    )
)]
pub async fn set_grant_scope(
    caller: Caller,
    request: Idempotent,
    State(state): State<AppState>,
    Path(pool_pda_str): Path<String>,
    JsonBody {
        value: payload,
        bytes,
    }: JsonBody<GrantScopeRequest>,
) -> Result<Response, ApiError> {
    caller.require(Permission::PoolsWrite)?;
    let mut op = open_or_replay!(state, &caller.user_id, request, &bytes);
    let doc = load_pool(&state, &pool_pda_str).await?;
    analysis_drt(&doc, &payload.analysis_id)?;
    // No chain step, so the owner is checked against the pool document.
    let wallet = crate::api::get_active_wallet_for_user(&state, &caller.user_id).await?;
    if wallet.wallet_id != doc.owner_wallet_id {
        return Err(ApiError::forbidden(
            "only the pool's owner changes its grants",
        ));
    }
    let def = analysis_definition(&state, &doc).await?;
    let targets = check_targets(&def, &payload.scope).map_err(invalid_scope)?;
    let (analyst_id, analysis_id) = (&payload.analyst_user_id, &payload.analysis_id);
    let change = GrantScope {
        targets,
        set_by: caller.user_id.clone(),
        set_at: Utc::now(),
        change_id: request.key.clone(),
    };

    op.begin().await?;
    crate::fault::point("staged");
    let mut target = String::new();
    let doc = generation::update(&state.storage, &state.solana_client, &pool_pda_str, |doc| {
        let grant = doc
            .grants
            .iter_mut()
            .find(|g| g.grant_id == payload.grant_id)
            .ok_or_else(no_grant)?;
        if &grant.analyst != analyst_id || &grant.drt_name != analysis_id {
            return Err(grant_mismatch());
        }
        target = grant.grant_id.clone();
        if grant.scopes.iter().any(|s| s.change_id == change.change_id) {
            return Ok(Change::Unchanged);
        }
        if grant.revoked.is_some() {
            return Err(ApiError::conflict(
                "the analyst's grant is revoked; grant them again to give them rows",
            )
            .with_code("grant_not_active"));
        }
        if grant.targets() == Some(&change.targets) {
            return Ok(Change::Unchanged);
        }
        if grant.scope_revision() != payload.revision {
            return Err(ApiError::conflict(format!(
                "the grant's targets changed after revision {}; reload them and edit again",
                payload.revision
            ))
            .with_code("version_conflict"));
        }
        grant.scopes.push(change.clone());
        Ok(Change::Changed)
    })
    .await?
    .ok_or_else(|| pool_not_found(&pool_pda_str))?;
    crate::fault::point("recorded");
    audit::grant(&target);
    let grant = doc
        .grants
        .iter()
        .find(|g| g.grant_id == target)
        .ok_or_else(|| ApiError::internal("the grant vanished"))?;
    let analyst = state.storage.identities().by_user_id(analyst_id).await?;
    let on_chain = statuses(&state, &doc).await;
    info!(
        pool = %pool_pda_str,
        grant_id = %grant.grant_id,
        revision = grant.scope_revision(),
        "Grant scope set"
    );
    let entry = entry(
        &state,
        grant,
        analyst.as_ref(),
        on_chain.get(&grant.grant_id),
        &headers(&def),
    );
    op.finish(StatusCode::OK, &entry).await
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
    description = "Every grant of the pool's analysis, active, being revoked or revoked, newest first, with each analyst's email and name as of their last sign-in, its Grant PDA, and what the chain last showed there (read again when that's over 5 minutes old). Needs `pools:read`.",
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
    let on_chain = statuses(&state, &doc).await;
    let headers = pool_headers(&state, &doc).await?;
    let grants = doc
        .grants
        .iter()
        .rev()
        .map(|g| {
            entry(
                &state,
                g,
                identities.get(&g.analyst),
                on_chain.get(&g.grant_id),
                &headers,
            )
        })
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
    description = "The analyses the caller may run, by pool name: for an admin every pool's, with every row; for anyone else those they hold an active grant to that the chain shows, none until they're granted. Any signed-in caller.",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "The caller's analyses", body = MyAnalysesResponse),
        (status = 401, description = "Unauthorized"),
        (status = 503, description = "The chain can't be read to check a grant (`rpc_unavailable`), a pool's last change is still being anchored or was made while the request ran (`pool_settling`, with Retry-After), or a pool's records are older than its on-chain generation (`pool_records_stale`)"),
    )
)]
pub async fn my_analyses(
    caller: Caller,
    State(state): State<AppState>,
) -> Result<Json<MyAnalysesResponse>, ApiError> {
    caller.require(Permission::AnalysesRun)?;
    let admin = caller.is_admin();
    let mut analyses = Vec::new();
    for doc in state.storage.pools().all().await? {
        let Some(analysis) = doc.analysis.as_ref() else {
            continue;
        };
        let granted_at = if admin {
            None
        } else {
            let Some(grant) = doc.active_grant(&caller.user_id, &analysis.analysis_id) else {
                continue;
            };
            // Only grants the chain shows; a reading the RPC can't give fails.
            let verified = state
                .grant_checks
                .verify(&state.storage, &state.solana_client, &doc, grant)
                .await;
            match verified {
                Ok(_) => Some(grant.granted_at),
                Err(e) if e.code == "grant_not_live" => continue,
                Err(e) => return Err(e),
            }
        };
        analyses.push(MyAnalysis {
            pool_pda: doc.pool_pda.clone(),
            pool_name: doc.pool_name.clone(),
            analysis_id: analysis.analysis_id.clone(),
            display_name: analysis.display_name.clone(),
            access: if admin { Access::Admin } else { Access::Grant },
            granted_at,
        });
    }
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
        let hash = worker
            .storage
            .scripts()
            .put(crate::analysis::definition::tests::AWARDS_REPORT.as_bytes())
            .await
            .unwrap();
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

    /// An analyst, who needs no app role, after signing in: their token
    /// and user ID.
    pub(crate) async fn analyst(app: &axum::Router, oid: &str) -> (String, String) {
        let mut spec = Spec::valid(&config());
        spec.oid = oid.into();
        spec.email = Some(format!("{oid}@example.com"));
        let token = spec.sign(entra_key()).unwrap();
        let user_id = sign_in(app, &token).await;
        (token, user_id)
    }

    /// A grant of the analysis to `analyst`, who sees employer group Group A.
    pub(crate) fn granting(analyst: &str) -> Value {
        json!({
            "analyst_user_id": analyst,
            "analysis_id": ANALYSIS,
            "scope": [{ "key": "employer_group", "value": "Group A" }],
        })
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

    /// The analysis pool's Execute DRT config.
    pub(crate) fn execute_drt_config(pool_pda: &Pubkey) -> Pubkey {
        derive_drt_config_pda(pool_pda, &EXECUTE_RIGHT_ID).0
    }

    fn grant_pda(worker: &Worker, analyst: &str) -> Pubkey {
        let commitment = worker
            .commitments
            .commitment(analyst, &POOL_UUID, &EXECUTE_RIGHT_ID);
        derive_grant_pda(&commitment).0
    }

    /// The DRT program calls sent, in order, each as its discriminator and
    /// commitment. The pool's generation anchors aren't among them.
    fn drt_calls(worker: &Worker) -> Vec<([u8; 8], [u8; 32])> {
        worker
            .chain
            .sent()
            .iter()
            .filter_map(|sent| {
                let bytes = BASE64.decode(sent).unwrap();
                let tx: solana_transaction::Transaction = bincode::deserialize(&bytes).unwrap();
                let keys = &tx.message.account_keys;
                let ix = tx.message.instructions.iter().find(|ix| {
                    keys[usize::from(ix.program_id_index)] == crate::config::drt_program_id()
                })?;
                Some((
                    ix.data[..8].try_into().unwrap(),
                    ix.data[8..40].try_into().unwrap(),
                ))
            })
            .collect()
    }

    /// The `n`th DRT program call sent.
    fn sent_call(worker: &Worker, n: usize) -> ([u8; 8], [u8; 32]) {
        drt_calls(worker)[n]
    }

    #[tokio::test]
    async fn a_grant_burns_one_execute_drt_and_granting_again_burns_none() {
        let worker = worker();
        let owner = worker.admin("oid-owner").await;
        let pool_pda = analysis_pool(&worker, &owner, 2).await;
        let (analyst_token, analyst_id) = analyst(&worker.app, "oid-ana").await;
        worker.chain.lands.store(true, SeqCst);
        let path = format!("/v1/drt/pools/{pool_pda}/grant");
        let body = granting(&analyst_id);

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
        assert_eq!(drt_calls(&worker).len(), 1, "one burn");
        let doc = worker
            .storage
            .pools()
            .get(&pool_pda.to_string())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(doc.generation, 1, "recording the grant was one change");
        assert_eq!(doc.grants[0].staged_generation, Some(0));

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
        let (_, analyst_id) = analyst(&worker.app, "oid-ana").await;
        worker.chain.lands.store(true, SeqCst);
        let grant_path = format!("/v1/drt/pools/{pool_pda}/grant");
        let revoke_path = format!("/v1/drt/pools/{pool_pda}/revoke-grant");
        let body = json!({ "analyst_user_id": analyst_id, "analysis_id": ANALYSIS });
        let grant_body = granting(&analyst_id);
        let (status, _, granted) = send(
            &worker.app,
            post(&grant_path, &owner.token, &new_key(), &grant_body),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{granted}");
        let pda = grant_pda(&worker, &analyst_id);
        worker.chain.grant(pda, execute_drt_config(&pool_pda));

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
            post(&grant_path, &owner.token, &new_key(), &grant_body),
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
        assert_eq!(drt_calls(&worker).last().unwrap().0, DISC_REVOKE_GRANT);
        worker.chain.close(&pda);

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
            post(&grant_path, &owner.token, &new_key(), &grant_body),
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
        let (_, analyst_id) = analyst(&worker.app, "oid-ana").await;
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
            staged_generation: None,
            signature: None,
            revoked: None,
            scopes: Vec::new(),
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
        worker.chain.grant(
            derive_grant_pda(&commitment).0,
            execute_drt_config(&pool_pda),
        );
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
        let (analyst_token, analyst_id) = analyst(&worker.app, "oid-ana").await;
        let path = format!("/v1/drt/pools/{pool_pda}/grant");
        let body = |analyst: &str, analysis: &str| {
            let mut body = granting(analyst);
            body["analysis_id"] = json!(analysis);
            body
        };
        let revoking =
            |analyst: &str| json!({ "analyst_user_id": analyst, "analysis_id": ANALYSIS });
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
        let request = post(&revoke, &owner.token, &new_key(), &revoking(&analyst_id));
        let (status, _, err) = send(&worker.app, request).await;
        assert_eq!(
            (status, err["code"].as_str()),
            (StatusCode::NOT_FOUND, Some("no_grant"))
        );
        let request = post(&revoke, &other.token, &new_key(), &revoking(&analyst_id));
        assert_eq!(send(&worker.app, request).await.0, StatusCode::FORBIDDEN);
        assert!(worker.chain.sent().is_empty());
    }

    #[tokio::test]
    async fn only_the_programs_grant_for_this_drt_counts_as_a_burn() {
        let worker = worker();
        let owner = worker.admin("oid-owner").await;
        let pool_pda = analysis_pool(&worker, &owner, 2).await;
        let (_, analyst_id) = analyst(&worker.app, "oid-ana").await;
        worker.chain.lands.store(true, SeqCst);
        let path = format!("/v1/drt/pools/{pool_pda}/grant");
        let body = granting(&analyst_id);
        let pda = grant_pda(&worker, &analyst_id);

        // Lamports someone sent to the address are no burn: the grant burns.
        worker.chain.accounts.lock().unwrap().push(pda);
        let (status, _, granted) =
            send(&worker.app, post(&path, &owner.token, &new_key(), &body)).await;
        assert_eq!(status, StatusCode::OK, "{granted}");
        assert_eq!(sent_call(&worker, 0).0, DISC_GRANT_RIGHT);

        // A Grant another pool's DRT made at the address takes it: no burn
        // of ours can land there.
        let (_, other_id) = analyst(&worker.app, "oid-bo").await;
        let taken = grant_pda(&worker, &other_id);
        worker.chain.grant(taken, Pubkey::new_unique());
        let body = granting(&other_id);
        let (status, _, refused) =
            send(&worker.app, post(&path, &owner.token, &new_key(), &body)).await;
        assert_eq!(status, StatusCode::CONFLICT, "{refused}");
        assert_eq!(refused["code"], "grant_pda_taken");
        assert_eq!(drt_calls(&worker).len(), 1, "nothing more was burned");
    }

    #[tokio::test]
    async fn a_grants_targets_change_without_a_burn_and_keep_their_history() {
        let worker = worker();
        let owner = worker.admin("oid-owner").await;
        let other = worker.admin("oid-other").await;
        let pool_pda = analysis_pool(&worker, &owner, 2).await;
        let (analyst_token, analyst_id) = analyst(&worker.app, "oid-ana").await;
        let (_, ungranted_id) = analyst(&worker.app, "oid-bo").await;
        worker.chain.lands.store(true, SeqCst);
        let grant_path = format!("/v1/drt/pools/{pool_pda}/grant");
        let scope_path = format!("/v1/drt/pools/{pool_pda}/grant-scope");

        // Targets are checked against the analysis.
        for scope in [
            json!([]),
            json!([{ "key": "region", "value": "Region E" }]),
            json!([{ "key": "employer", "value": " Bank B" }]),
        ] {
            let mut body = granting(&analyst_id);
            body["scope"] = scope.clone();
            let (status, _, err) = send(
                &worker.app,
                post(&grant_path, &owner.token, &new_key(), &body),
            )
            .await;
            assert_eq!(
                (status, err["code"].as_str()),
                (StatusCode::BAD_REQUEST, Some("invalid_scope")),
                "{scope}"
            );
        }
        let mut compound = granting(&analyst_id);
        compound["scope"] =
            json!([{ "key": "employer", "value": "Bank B", "employer_group": "Group B" }]);
        let (status, _, _) = send(
            &worker.app,
            post(&grant_path, &owner.token, &new_key(), &compound),
        )
        .await;
        assert!(status.is_client_error(), "{status}");
        assert!(worker.chain.sent().is_empty());

        let (status, _, granted) = send(
            &worker.app,
            post(
                &grant_path,
                &owner.token,
                &new_key(),
                &granting(&analyst_id),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{granted}");
        assert_eq!(granted["scope_revision"], 1);
        assert_eq!(
            granted["scope"],
            json!([{ "key": "employer_group", "header": "Employer Group", "value": "Group A" }])
        );
        assert_eq!(granted["on_chain"], "live");

        // Another grant with other targets is refused; the change is an edit.
        let mut elsewhere = granting(&analyst_id);
        elsewhere["scope"] = json!([{ "key": "employer", "value": "Bank B" }]);
        let (status, _, err) = send(
            &worker.app,
            post(&grant_path, &owner.token, &new_key(), &elsewhere),
        )
        .await;
        assert_eq!(
            (status, err["code"].as_str()),
            (StatusCode::CONFLICT, Some("grant_active"))
        );

        let grant_id = granted["grant_id"].clone();
        let change = |revision: usize, scope: Value| {
            json!({ "grant_id": grant_id, "analyst_user_id": analyst_id, "analysis_id": ANALYSIS,
                "revision": revision, "scope": scope })
        };
        let wider = json!([
            { "key": "employer_group", "value": "Group A" },
            { "key": "employer", "value": "Bank B" },
        ]);
        let key = new_key();
        let (status, _, changed) = send(
            &worker.app,
            post(&scope_path, &owner.token, &key, &change(1, wider.clone())),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{changed}");
        assert_eq!(changed["scope_revision"], 2);
        assert_eq!(changed["scope"].as_array().unwrap().len(), 2);
        let history = changed["scope_history"].as_array().unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0]["revision"], 1);
        assert_eq!(history[1]["set_by"], owner.user_id.as_str());
        assert_eq!(drt_calls(&worker).len(), 1, "only the grant burned");
        let doc = worker
            .storage
            .pools()
            .get(&pool_pda.to_string())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(doc.generation, 2, "the grant and the edit, each a change");

        // A retry replays; the same targets from a stale copy converge; other
        // targets from a stale copy are refused.
        let (status, headers, replayed) = send(
            &worker.app,
            post(&scope_path, &owner.token, &key, &change(1, wider.clone())),
        )
        .await;
        assert_eq!((status, &replayed), (StatusCode::OK, &changed));
        assert_eq!(headers[&REPLAYED_HEADER], "true");
        let (status, _, same) = send(
            &worker.app,
            post(&scope_path, &owner.token, &new_key(), &change(1, wider)),
        )
        .await;
        assert_eq!(
            (status, &same["scope_revision"]),
            (StatusCode::OK, &json!(2))
        );
        let narrower = json!([{ "key": "employer", "value": "Bank B" }]);
        let (status, _, err) = send(
            &worker.app,
            post(
                &scope_path,
                &owner.token,
                &new_key(),
                &change(1, narrower.clone()),
            ),
        )
        .await;
        assert_eq!(
            (status, err["code"].as_str()),
            (StatusCode::CONFLICT, Some("version_conflict"))
        );

        // Only the pool's owner edits, and only a grant that exists and is active.
        let (status, _, _) = send(
            &worker.app,
            post(
                &scope_path,
                &other.token,
                &new_key(),
                &change(2, narrower.clone()),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _, _) = send(
            &worker.app,
            post(
                &scope_path,
                &analyst_token,
                &new_key(),
                &change(2, narrower.clone()),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let mut nobody = change(1, narrower.clone());
        nobody["analyst_user_id"] = json!(ungranted_id);
        let (status, _, err) = send(
            &worker.app,
            post(&scope_path, &owner.token, &new_key(), &nobody),
        )
        .await;
        assert_eq!(
            (status, err["code"].as_str()),
            (StatusCode::BAD_REQUEST, Some("grant_mismatch"))
        );
        let mut unknown = change(1, narrower.clone());
        unknown["grant_id"] = json!("not-a-grant");
        let (status, _, err) = send(
            &worker.app,
            post(&scope_path, &owner.token, &new_key(), &unknown),
        )
        .await;
        assert_eq!(
            (status, err["code"].as_str()),
            (StatusCode::NOT_FOUND, Some("no_grant"))
        );

        let revoke = format!("/v1/drt/pools/{pool_pda}/revoke-grant");
        let body = json!({ "analyst_user_id": analyst_id, "analysis_id": ANALYSIS });
        let (status, _, _) =
            send(&worker.app, post(&revoke, &owner.token, &new_key(), &body)).await;
        assert_eq!(status, StatusCode::OK);
        let (status, _, err) = send(
            &worker.app,
            post(&scope_path, &owner.token, &new_key(), &change(2, narrower)),
        )
        .await;
        assert_eq!(
            (status, err["code"].as_str()),
            (StatusCode::CONFLICT, Some("grant_not_active"))
        );
    }

    #[tokio::test]
    async fn a_stale_edit_or_revocation_never_touches_a_later_grant() {
        let worker = worker();
        let owner = worker.admin("oid-owner").await;
        let pool_pda = analysis_pool(&worker, &owner, 3).await;
        let (_, analyst_id) = analyst(&worker.app, "oid-ana").await;
        worker.chain.lands.store(true, SeqCst);
        let path = |route: &str| format!("/v1/drt/pools/{pool_pda}/{route}");
        let call = |route: &str, body: &Value| {
            let request = post(&path(route), &owner.token, &new_key(), body);
            let app = worker.app.clone();
            async move { send(&app, request).await }
        };
        let (status, _, first) = call("grant", &granting(&analyst_id)).await;
        assert_eq!(status, StatusCode::OK, "{first}");

        // An edit and a revocation made against the first grant.
        let stale_edit = json!({ "grant_id": first["grant_id"], "analyst_user_id": analyst_id,
            "analysis_id": ANALYSIS, "revision": 1, "scope": [
                { "key": "employer_group", "value": "Group A" },
                { "key": "employer", "value": "Bank B" },
            ] });
        let revoke_first = json!({ "grant_id": first["grant_id"],
            "analyst_user_id": analyst_id, "analysis_id": ANALYSIS });
        let (status, _, revoked) = call("revoke-grant", &revoke_first).await;
        assert_eq!(status, StatusCode::OK, "{revoked}");
        assert_eq!(revoked["status"], "revoked");

        // The analyst is granted again, narrower: a new grant at revision 1.
        let mut narrower = granting(&analyst_id);
        narrower["scope"] = json!([{ "key": "employer", "value": "Bank B" }]);
        let (status, _, second) = call("grant", &narrower).await;
        assert_eq!(status, StatusCode::OK, "{second}");
        assert_ne!(second["grant_id"], first["grant_id"]);
        assert_eq!(second["scope_revision"], 1);

        // The stale edit names the revoked grant, and changes nothing.
        let (status, _, err) = call("grant-scope", &stale_edit).await;
        assert_eq!(
            (status, err["code"].as_str()),
            (StatusCode::CONFLICT, Some("grant_not_active")),
            "{err}"
        );
        // Revoking the first grant again returns it, closed as it was.
        let (status, _, again) = call("revoke-grant", &revoke_first).await;
        assert_eq!(status, StatusCode::OK, "{again}");
        assert_eq!(again["grant_id"], first["grant_id"]);
        let (_, _, listed) = send(&worker.app, get(&path("grants"), &owner.token)).await;
        let current = listed["grants"]
            .as_array()
            .unwrap()
            .iter()
            .find(|g| g["grant_id"] == second["grant_id"])
            .unwrap();
        assert_eq!(current["status"], "active");
        assert_eq!(current["scope"], second["scope"]);
        assert_eq!(current["on_chain"], "live");

        // A grant_id of one analyst's grant with another analyst is refused.
        let (_, other_id) = analyst(&worker.app, "oid-bo").await;
        let mut mismatched = stale_edit.clone();
        mismatched["grant_id"] = second["grant_id"].clone();
        mismatched["analyst_user_id"] = json!(other_id);
        let (status, _, err) = call("grant-scope", &mismatched).await;
        assert_eq!(
            (status, err["code"].as_str()),
            (StatusCode::BAD_REQUEST, Some("grant_mismatch"))
        );
        let mut revoke_mismatched = revoke_first.clone();
        revoke_mismatched["grant_id"] = second["grant_id"].clone();
        revoke_mismatched["analyst_user_id"] = json!(other_id);
        let (status, _, err) = call("revoke-grant", &revoke_mismatched).await;
        assert_eq!(
            (status, err["code"].as_str()),
            (StatusCode::BAD_REQUEST, Some("grant_mismatch"))
        );
    }

    #[tokio::test]
    async fn someone_registered_from_entra_can_be_granted_before_signing_in() {
        let worker = worker();
        let owner = worker.admin("oid-owner").await;
        let pool_pda = analysis_pool(&worker, &owner, 2).await;
        worker.chain.lands.store(true, SeqCst);
        let oid = "5d9a1f40-1b2c-4d3e-8f90-123456789abc";
        let register = |token: &str, body: Value| post("/v1/users", token, &new_key(), &body);
        let blair = json!({ "entra_object_id": oid.to_uppercase(), "email": "blair@example.com",
            "display_name": "Blair Bravo" });

        let (analyst_token, _) = analyst(&worker.app, "oid-ana").await;
        let (status, _, _) = send(&worker.app, register(&analyst_token, blair.clone())).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let mut bad = blair.clone();
        bad["entra_object_id"] = json!("not-a-uuid");
        let (status, _, _) = send(&worker.app, register(&owner.token, bad)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let (status, _, registered) =
            send(&worker.app, register(&owner.token, blair.clone())).await;
        assert_eq!(status, StatusCode::OK, "{registered}");
        assert_eq!(registered["pending"], true);
        let user_id = registered["user_id"].as_str().unwrap().to_string();
        let (status, _, again) = send(&worker.app, register(&owner.token, blair)).await;
        assert_eq!(
            (status, &again["user_id"]),
            (StatusCode::OK, &json!(user_id))
        );
        let other = json!({ "entra_object_id": "6d9a1f40-1b2c-4d3e-8f90-123456789abc",
            "email": "Blair@Example.com", "display_name": "Someone Else" });
        let (status, _, err) = send(&worker.app, register(&owner.token, other)).await;
        assert_eq!(
            (status, err["code"].as_str()),
            (StatusCode::CONFLICT, Some("email_taken"))
        );

        let path = format!("/v1/drt/pools/{pool_pda}/grant");
        let (status, _, granted) = send(
            &worker.app,
            post(&path, &owner.token, &new_key(), &granting(&user_id)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{granted}");
        assert_eq!(granted["analyst_email"], "blair@example.com");

        // Their first sign-in finds the grant waiting.
        let mut spec = Spec::valid(&config());
        spec.oid = oid.into();
        spec.email = Some("blair@example.com".into());
        let token = spec.sign(entra_key()).unwrap();
        assert_eq!(sign_in(&worker.app, &token).await, user_id);
        let (_, _, mine) = send(&worker.app, get("/v1/drt/me/analyses", &token)).await;
        assert_eq!(mine["analyses"].as_array().map(Vec::len), Some(1), "{mine}");
    }

    #[tokio::test]
    async fn the_users_list_shows_the_pools_each_person_holds_a_grant_in() {
        let worker = worker();
        let owner = worker.admin("oid-owner").await;
        let pool_pda = analysis_pool(&worker, &owner, 2).await;
        worker.chain.lands.store(true, SeqCst);
        let (_, ana) = analyst(&worker.app, "oid-ana").await;
        let blair = json!({ "entra_object_id": "5d9a1f40-1b2c-4d3e-8f90-123456789abc",
            "email": "blair@example.com", "display_name": "Blair Bravo" });
        let (status, _, registered) = send(
            &worker.app,
            post("/v1/users", &owner.token, &new_key(), &blair),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{registered}");
        let blair = registered["user_id"].as_str().unwrap().to_string();
        let grant_path = format!("/v1/drt/pools/{pool_pda}/grant");
        for analyst_id in [&ana, &blair] {
            let (status, _, granted) = send(
                &worker.app,
                post(&grant_path, &owner.token, &new_key(), &granting(analyst_id)),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{granted}");
        }
        let doc = worker
            .storage
            .pools()
            .get(&pool_pda.to_string())
            .await
            .unwrap()
            .unwrap();
        let pools_of = |list: &Value, user_id: &str| {
            list["users"]
                .as_array()
                .unwrap()
                .iter()
                .find(|u| u["user_id"] == user_id)
                .map(|u| u["pools"].clone())
                .unwrap()
        };

        let (status, _, list) = send(&worker.app, get("/v1/users", &owner.token)).await;
        assert_eq!(status, StatusCode::OK, "{list}");
        let held = pools_of(&list, &ana);
        assert_eq!(
            held,
            json!([{
                "pool_pda": pool_pda.to_string(),
                "pool_name": doc.pool_name,
                "display_name": "Awards Report",
                "granted_at": doc.active_grant(&ana, ANALYSIS).unwrap().granted_at,
            }])
        );
        // Granted before their first sign-in, they hold it already.
        assert_eq!(pools_of(&list, &blair).as_array().map(Vec::len), Some(1));
        // The owner opens the pool as an admin, without a grant.
        assert_eq!(pools_of(&list, &owner.user_id), json!([]));

        // A revocation takes the pool away at once, before its close.
        worker
            .chain
            .grant(grant_pda(&worker, &ana), execute_drt_config(&pool_pda));
        let revoke = json!({ "analyst_user_id": ana, "analysis_id": ANALYSIS });
        let revoke_path = format!("/v1/drt/pools/{pool_pda}/revoke-grant");
        let (status, _, revoked) = send(
            &worker.app,
            post(&revoke_path, &owner.token, &new_key(), &revoke),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{revoked}");
        let (_, _, list) = send(&worker.app, get("/v1/users", &owner.token)).await;
        assert_eq!(pools_of(&list, &ana), json!([]));
        assert_eq!(pools_of(&list, &blair).as_array().map(Vec::len), Some(1));
    }
}
