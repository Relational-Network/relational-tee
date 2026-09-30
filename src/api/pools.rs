// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! DRT pool API handlers (new `digital_rights_tokens` contract).
//!
//! - `POST /v1/drt/pools/malta`        — atomic create (CSV-driven pool + schema)
//! - `GET  /v1/drt/pools/{pool_pda}`   — pool info (chain + enclave metadata)

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Response,
    Json,
};
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;
use std::collections::BTreeMap;
use std::str::FromStr;
use tracing::info;

use crate::audit;
use crate::auth::{Caller, Permission};
use crate::blockchain::drt::{
    accounts::{fetch_drt_config, fetch_pool},
    instructions::{
        build_compute_budget_ix, build_create_pool, build_register_drt, build_seal_pool,
    },
    pda::{derive_drt_config_pda, derive_mint_pda, derive_pool_pda},
    types::*,
    validation::{validate_drt_requests, validate_pool_name, ResolvedDrt},
};
use crate::blockchain::signing::keypair_from_bytes_verified;
use crate::chain::{self, Effect};
use crate::data_validation::FieldSchema;
use crate::error::ApiError;
use crate::idempotency::{Idempotent, JsonBody};
use crate::ids;
use crate::state::AppState;
use crate::storage::pools::{DrtMetadata, PoolDoc, PoolKind};
use crate::storage::staged::{Saga, Staged};
use crate::storage::wallets::WalletMetadata;
use crate::store::Created;

// ============================================================================
// Shared helpers (also used by api/credentials/ and api/transactions.rs)
// ============================================================================

/// Load a wallet keypair, verifying ownership and active status.
pub(crate) async fn load_wallet_keypair(
    state: &AppState,
    wallet_id: &str,
    caller_sub: &str,
) -> Result<(WalletMetadata, Keypair), ApiError> {
    let wallet = super::load_wallet(state, wallet_id).await?;
    super::enforce_owner_active(&wallet, caller_sub)?;
    let keypair_bytes = state.storage.wallets().read_keypair(wallet_id).await?;
    let keypair = keypair_from_bytes_verified(&keypair_bytes, &wallet.public_address)?;
    Ok((wallet, keypair))
}

/// A transaction of `instructions` paid for and signed by `keypair`.
pub(crate) fn signed<'a>(
    keypair: &'a Keypair,
    instructions: &'a [Instruction],
) -> impl Fn(solana_hash::Hash) -> Transaction + 'a {
    move |blockhash| {
        let message = Message::new(instructions, Some(&keypair.pubkey()));
        Transaction::new(&[keypair], message, blockhash)
    }
}

/// Compare a wallet's Solana public address against `pool.owner`.
pub(crate) fn verify_pool_ownership(pool: &Pool, wallet: &WalletMetadata) -> Result<(), ApiError> {
    let owner = Pubkey::from_str(&wallet.public_address)
        .map_err(|_| ApiError::internal("invalid stored wallet address"))?;
    if pool.owner != owner {
        return Err(ApiError::forbidden("you are not the pool owner"));
    }
    Ok(())
}

/// Load a pool's document, or 404.
pub(crate) async fn load_pool(state: &AppState, pool_pda: &str) -> Result<PoolDoc, ApiError> {
    state.storage.pools().get(pool_pda).await?.ok_or_else(|| {
        ApiError::not_found(format!(
            "pool metadata not found for {pool_pda} — pool may need creation"
        ))
    })
}

pub(crate) fn explorer_url(state: &AppState, sig: &str) -> String {
    state.solana_client.network().explorer_tx_url(sig)
}

/// Validate the inline schema submitted on MALTA pool create.
///
/// If the caller did not supply a `schema_id`, the pool's UUID names it. The
/// schema id is an internal handle the dashboard does not surface, so the
/// operator never has to invent one.
fn parse_schema(
    req: &InlineSchemaRequest,
    pool_uuid: &[u8; 16],
) -> Result<(String, Vec<FieldSchema>), ApiError> {
    let schema_id = match req
        .schema_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(s) => {
            if s.len() > 128
                || !s
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            {
                return Err(ApiError::bad_request(
                    "schema_id must be 1-128 chars, alphanumeric + hyphen/underscore",
                ));
            }
            s.to_string()
        }
        None => uuid::Uuid::from_bytes(*pool_uuid).to_string(),
    };
    if req.fields.is_empty() {
        return Err(ApiError::bad_request("schema must have at least one field"));
    }
    let mut fields = Vec::with_capacity(req.fields.len());
    for f in &req.fields {
        if f.name.is_empty() {
            return Err(ApiError::bad_request("schema field name cannot be empty"));
        }
        let field_type: crate::data_validation::FieldType =
            serde_json::from_value(f.field_type.clone()).map_err(|e| {
                ApiError::bad_request(format!("invalid field_type for '{}': {e}", f.name))
            })?;
        fields.push(FieldSchema {
            name: f.name.clone(),
            field_type,
            nullable: f.nullable,
        });
    }
    Ok((schema_id, fields))
}

/// The one transaction that creates a pool: compute budget, `create_pool`,
/// `register_drt` for each DRT, then `seal_pool`.
fn pool_instructions(
    owner: &Pubkey,
    pool_pda: &Pubkey,
    pool_uuid: &[u8; 16],
    drts: &[(ResolvedDrt, [u8; 16])],
) -> Result<Vec<Instruction>, ApiError> {
    let mut ixs = Vec::with_capacity(3 + drts.len());
    ixs.push(build_compute_budget_ix(1_400_000));
    ixs.push(build_create_pool(owner, pool_pda, pool_uuid));
    for (d, rid) in drts {
        ixs.push(
            build_register_drt(
                owner,
                pool_pda,
                owner,
                rid,
                &d.code_repo_url,
                &d.code_hash,
                d.supply,
            )
            .map_err(ApiError::internal)?,
        );
    }
    ixs.push(build_seal_pool(owner, pool_pda));
    Ok(ixs)
}

// ============================================================================
// POST /v1/drt/pools/malta
// ============================================================================

/// Create a MALTA pool (CSV-driven, schema required).
///
/// The pool's UUID, and so its PDA, derives from the caller and the
/// `Idempotency-Key`. The pool document is staged first; the creating
/// transaction follows the stored-transaction rule, so a retry never creates
/// a second pool; then, once that transaction is finalized, the document is
/// written with the creation signature. Waiting for `finalized` means a
/// document never names a pool that a rolled-back block took away.
#[utoipa::path(
    post,
    path = "/v1/drt/pools/malta",
    tag = "DRT Pools",
    summary = "Create MALTA pool",
    description = "Atomically: create_pool + register_drt × N (always includes 'append') + seal_pool, then, once that transaction is finalized, store the pool's document with its inline schema. Idempotent: retries with the same Idempotency-Key create one pool.",
    security(("bearer_auth" = [])),
    params(
        ("Idempotency-Key" = String, Header, description = "A UUID naming this user action; reuse it on every retry"),
    ),
    request_body = CreateMaltaPoolRequest,
    responses(
        (status = 201, description = "Pool created", body = CreatePoolResponse),
        (status = 400, description = "Validation error, no Idempotency-Key, or Solana refused the transaction (`transaction_rejected`)"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 422, description = "The Idempotency-Key was used for a different request"),
        (status = 503, description = "RPC unavailable"),
    )
)]
pub async fn create_malta_pool(
    caller: Caller,
    request: Idempotent,
    State(state): State<AppState>,
    JsonBody {
        value: payload,
        bytes,
    }: JsonBody<CreateMaltaPoolRequest>,
) -> Result<Response, ApiError> {
    caller.require(Permission::PoolsCreate)?;
    let mut op = open_or_replay!(state, &caller.user_id, request, &bytes);

    validate_pool_name(&payload.pool_name)?;
    let resolved = validate_drt_requests(&payload.drts)?;
    if !resolved.iter().any(|d| d.name == APPEND_DRT_NAME) {
        return Err(ApiError::bad_request(
            "MALTA pools must include the 'append' DRT",
        ));
    }
    let pool_uuid = ids::pool_uuid(&caller.user_id, &request.key);
    let (schema_id, fields) = parse_schema(&payload.schema, &pool_uuid)?;
    let (wallet, keypair) =
        load_wallet_keypair(&state, &payload.wallet_id, &caller.user_id).await?;

    let (pool_pda, _bump) = derive_pool_pda(&pool_uuid);
    let pool_pda_str = pool_pda.to_string();
    let drts: Vec<(ResolvedDrt, [u8; 16])> = resolved
        .into_iter()
        .map(|d| {
            let rid = ids::right_id(&pool_uuid, &d.name);
            (d, rid)
        })
        .collect();
    let drt_records: BTreeMap<String, DrtMetadata> = drts
        .iter()
        .map(|(d, rid)| {
            let (mint_pda, _) = derive_mint_pda(&pool_pda, rid);
            (
                d.name.clone(),
                DrtMetadata {
                    right_id_hex: hex::encode(rid),
                    mint: mint_pda.to_string(),
                    supply: d.supply,
                    code_repo_url: d.code_repo_url.clone(),
                    code_hash_hex: hex::encode(d.code_hash),
                },
            )
        })
        .collect();
    let now = chrono::Utc::now();
    let doc = PoolDoc {
        pool_pda: pool_pda_str.clone(),
        pool_name: payload.pool_name.clone(),
        kind: PoolKind::Malta,
        pool_uuid_hex: hex::encode(pool_uuid),
        drts: drt_records,
        owner_wallet_id: wallet.wallet_id.clone(),
        owner_pubkey: wallet.public_address.clone(),
        schema_id,
        schema: fields,
        validation_mode: crate::data_validation::ValidationMode::HeadersOnly,
        created_by: caller.user_id.clone(),
        created_at: now,
        creation_signature: String::new(),
        initial: None,
        issuances: Vec::new(),
        revocations: Vec::new(),
    };

    // ── STAGE, then CREATE ON-CHAIN, then WRITE THE DOCUMENT ─────────
    op.begin().await?;
    let staged = state
        .storage
        .sagas()
        .stage(
            &format!("pool-{pool_pda_str}"),
            Staged {
                record: op.record_path().to_string(),
                staged_at: now,
                saga: Saga::Pool {
                    pool: Box::new(doc),
                },
            },
        )
        .await?;
    let Saga::Pool { pool } = staged.saga else {
        return Err(ApiError::internal("another saga is staged under this pool"));
    };
    let mut doc = *pool;
    crate::fault::point("staged");

    let owner = keypair.pubkey();
    let ixs = pool_instructions(&owner, &pool_pda, &pool_uuid, &drts)?;
    let signature = chain::run(
        &state.solana_client,
        &mut op,
        &Effect::Account(pool_pda),
        "finalized",
        signed(&keypair, &ixs),
    )
    .await?;
    audit::pool(&pool_pda_str);
    audit::signature(&signature);

    doc.creation_signature = signature.clone();
    let doc = match state.storage.pools().create(&doc).await? {
        Created::New(_) => doc,
        Created::AlreadyExists => load_pool(&state, &pool_pda_str).await?,
    };
    crate::fault::point("recorded");

    info!(
        signature = %doc.creation_signature,
        pool = %pool_pda_str,
        owner = %wallet.public_address,
        drts = doc.drts.len(),
        schema = %doc.schema_id,
        "MALTA pool created"
    );

    let response = CreatePoolResponse {
        signature: doc.creation_signature.clone(),
        signatures: vec![doc.creation_signature.clone()],
        pool_pda: pool_pda_str,
        pool_uuid: doc.pool_uuid_hex.clone(),
        mints: doc
            .drts
            .iter()
            .map(|(n, m)| (n.clone(), m.mint.clone()))
            .collect(),
        right_ids: doc
            .drts
            .iter()
            .map(|(n, m)| (n.clone(), m.right_id_hex.clone()))
            .collect(),
        explorer_url: explorer_url(&state, &doc.creation_signature),
    };
    op.finish(StatusCode::CREATED, &response).await
}

// ============================================================================
// GET /v1/drt/pools/{pool_pda}
// ============================================================================

/// Fetch pool info by PDA. Merges on-chain state with enclave metadata.
#[utoipa::path(
    get,
    path = "/v1/drt/pools/{pool_pda}",
    tag = "DRT Pools",
    summary = "Get DRT pool",
    description = "Returns pool state from chain + enclave metadata (name, kind, DRT list with supply/url/hash).",
    security(("bearer_auth" = [])),
    params(
        ("pool_pda" = String, Path, description = "Pool PDA address (base58)"),
    ),
    responses(
        (status = 200, description = "Pool info", body = PoolInfoResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Pool not found"),
        (status = 503, description = "RPC unavailable"),
    )
)]
pub async fn get_pool(
    caller: Caller,
    State(state): State<AppState>,
    Path(pool_pda_str): Path<String>,
) -> Result<Json<PoolInfoResponse>, ApiError> {
    caller.require(Permission::PoolsRead)?;
    let pool_pda = Pubkey::from_str(&pool_pda_str)
        .map_err(|_| ApiError::bad_request("invalid pool PDA address"))?;

    let pool = fetch_pool(state.solana_client.rpc(), &pool_pda).await?;
    let meta = state.storage.pools().get(&pool_pda_str).await?;

    let (name, kind, drts) = match &meta {
        Some(m) => {
            let drts: Vec<DrtConfigResponse> = m
                .drts
                .iter()
                .map(|(name, d)| DrtConfigResponse {
                    name: name.clone(),
                    right_id: d.right_id_hex.clone(),
                    mint: d.mint.clone(),
                    supply: d.supply,
                    code_repo_url: d.code_repo_url.clone(),
                    code_hash: d.code_hash_hex.clone(),
                })
                .collect();
            (m.pool_name.clone(), m.kind.as_str().to_string(), drts)
        }
        None => (String::new(), "unknown".to_string(), Vec::new()),
    };

    Ok(Json(PoolInfoResponse {
        pool_pda: pool_pda_str,
        pool_uuid: hex::encode(pool.uuid),
        name,
        kind,
        owner: pool.owner.to_string(),
        sealed: pool.sealed,
        drts,
    }))
}

// ============================================================================
// GET /v1/drt/pools/{pool_pda}/drt/{drt_name}
// ============================================================================

/// Fetch live on-chain `DrtConfig` for a registered DRT.
///
/// Useful as a sanity check that the pool document's `drts[name]` matches
/// what's actually on chain.
#[utoipa::path(
    get,
    path = "/v1/drt/pools/{pool_pda}/drt/{drt_name}",
    tag = "DRT Pools",
    summary = "Fetch on-chain DRT config",
    description = "Returns the live DrtConfig from chain for the given DRT name in the pool.",
    security(("bearer_auth" = [])),
    params(
        ("pool_pda" = String, Path, description = "Pool PDA address (base58)"),
        ("drt_name" = String, Path, description = "DRT name (e.g. 'append', 'mean')"),
    ),
    responses(
        (status = 200, description = "DRT config", body = DrtConfigResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Pool or DRT not found"),
        (status = 503, description = "RPC unavailable"),
    )
)]
pub async fn get_drt(
    caller: Caller,
    State(state): State<AppState>,
    Path((pool_pda_str, drt_name)): Path<(String, String)>,
) -> Result<Json<DrtConfigResponse>, ApiError> {
    caller.require(Permission::PoolsRead)?;
    let pool_pda = Pubkey::from_str(&pool_pda_str)
        .map_err(|_| ApiError::bad_request("invalid pool PDA address"))?;
    let meta = load_pool(&state, &pool_pda_str).await?;
    let drt_meta = meta
        .drts
        .get(&drt_name)
        .ok_or_else(|| ApiError::not_found(format!("DRT '{drt_name}' not found in pool")))?;

    let right_id = crate::api::credentials::decode_right_id(&drt_meta.right_id_hex)?;
    let (drt_config_pda, _) = derive_drt_config_pda(&pool_pda, &right_id);
    let cfg = fetch_drt_config(state.solana_client.rpc(), &drt_config_pda).await?;

    Ok(Json(DrtConfigResponse {
        name: drt_name,
        right_id: hex::encode(cfg.right_id),
        mint: cfg.mint.to_string(),
        supply: cfg.supply,
        code_repo_url: cfg.code_repo_url,
        code_hash: hex::encode(cfg.code_hash),
    }))
}
