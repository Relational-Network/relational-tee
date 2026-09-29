// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! DRT pool API handlers (new `digital_rights_tokens` contract).
//!
//! - `POST /v1/drt/pools/malta`        — atomic create (CSV-driven pool + schema)
//! - `GET  /v1/drt/pools/{pool_pda}`   — pool info (chain + enclave metadata)

use axum::{
    extract::{Path, State},
    Json,
};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use std::collections::BTreeMap;
use std::str::FromStr;
use tracing::info;

use crate::audit;
use crate::auth::AdminToken;
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
use crate::data_validation::FieldSchema;
use crate::error::ApiError;
use crate::state::AppState;
use crate::storage::pools::{DrtMetadata, PoolKind, PoolMetadata, PoolState};
use crate::storage::wallets::WalletMetadata;

// ============================================================================
// Shared helpers (also used by api/credentials.rs and api/admin.rs)
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

/// A transaction that failed.
pub(crate) struct SendFailure {
    pub error: ApiError,
    /// The signed transaction reached the RPC node, so it may still land.
    pub sent: Option<String>,
}

impl From<SendFailure> for ApiError {
    fn from(failure: SendFailure) -> Self {
        failure.error
    }
}

/// Sign, send and confirm a transaction; `commitment` is `"confirmed"` or
/// `"finalized"`. Returns its signature.
pub(crate) async fn sign_and_send(
    state: &AppState,
    keypair: &Keypair,
    instructions: Vec<solana_instruction::Instruction>,
    commitment: &str,
) -> Result<String, SendFailure> {
    let not_sent = |error| SendFailure { error, sent: None };
    let rpc = state.solana_client.rpc();
    let recent_blockhash = rpc.get_latest_blockhash().await.map_err(|e| {
        not_sent(ApiError::rpc_unavailable(format!(
            "blockhash fetch failed: {e}"
        )))
    })?;
    let message = solana_message::Message::new(&instructions, Some(&keypair.pubkey()));
    let tx = solana_transaction::Transaction::new(&[keypair], message, recent_blockhash);
    let signature = rpc.send_transaction(&tx).await.map_err(|e| {
        not_sent(ApiError::rpc_unavailable(format!(
            "transaction send failed: {e}"
        )))
    })?;
    let sig_str = signature.to_string();
    if let Err(error) = state
        .solana_client
        .await_confirmation(&signature, commitment)
        .await
    {
        return Err(SendFailure {
            error,
            sent: Some(sig_str),
        });
    }
    Ok(sig_str)
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

/// Load a pool's metadata, or 404.
pub(crate) async fn load_pool_meta(
    state: &AppState,
    pool_pda: &str,
) -> Result<PoolMetadata, ApiError> {
    state.storage.pools().get(pool_pda).await?.ok_or_else(|| {
        ApiError::not_found(format!(
            "pool metadata not found for {pool_pda} — pool may need creation"
        ))
    })
}

pub(crate) fn explorer_url(state: &AppState, sig: &str) -> String {
    state.solana_client.network().explorer_tx_url(sig)
}

fn new_uuid_bytes() -> [u8; 16] {
    *uuid::Uuid::new_v4().as_bytes()
}

/// Validate the inline schema submitted on MALTA pool create.
///
/// If the caller did not supply a `schema_id`, generate a stable UUID. The
/// schema id is an internal handle the dashboard does not surface, so the
/// operator never has to invent one.
fn parse_schema(req: &InlineSchemaRequest) -> Result<(String, Vec<FieldSchema>), ApiError> {
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
        None => uuid::Uuid::new_v4().to_string(),
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

// ============================================================================
// Core create-pool logic.
// ============================================================================

struct CreatedPool {
    pool_pda: Pubkey,
    pool_uuid: [u8; 16],
    signatures: Vec<String>,
    drts: BTreeMap<String, DrtMetadata>,
}

async fn create_pool_atomic(
    state: &AppState,
    owner_keypair: &Keypair,
    drts: &[ResolvedDrt],
) -> Result<CreatedPool, ApiError> {
    let owner_pk = owner_keypair.pubkey();
    let pool_uuid = new_uuid_bytes();
    let (pool_pda, _bump) = derive_pool_pda(&pool_uuid);

    let mut drt_records: BTreeMap<String, DrtMetadata> = BTreeMap::new();
    let mut right_ids: Vec<[u8; 16]> = Vec::with_capacity(drts.len());
    for d in drts {
        let rid = new_uuid_bytes();
        right_ids.push(rid);
        let (mint_pda, _) = derive_mint_pda(&pool_pda, &rid);
        drt_records.insert(
            d.name.clone(),
            DrtMetadata {
                right_id_hex: hex::encode(rid),
                mint: mint_pda.to_string(),
                supply: d.supply,
                code_repo_url: d.code_repo_url.clone(),
                code_hash_hex: hex::encode(d.code_hash),
            },
        );
    }

    // Build instructions: compute_budget + create_pool + (register_drt ×N) + seal_pool.
    let mut ixs = Vec::with_capacity(3 + drts.len());
    ixs.push(build_compute_budget_ix(1_400_000));
    ixs.push(build_create_pool(&owner_pk, &pool_pda, &pool_uuid));
    for (d, rid) in drts.iter().zip(right_ids.iter()) {
        ixs.push(
            build_register_drt(
                &owner_pk,
                &pool_pda,
                &owner_pk,
                rid,
                &d.code_repo_url,
                &d.code_hash,
                d.supply,
            )
            .map_err(ApiError::internal)?,
        );
    }
    ixs.push(build_seal_pool(&owner_pk, &pool_pda));

    let sig = sign_and_send(state, owner_keypair, ixs, "confirmed").await?;

    Ok(CreatedPool {
        pool_pda,
        pool_uuid,
        signatures: vec![sig],
        drts: drt_records,
    })
}

/// What a new pool row records beyond its on-chain state.
struct NewPool<'a> {
    pool_pda: &'a str,
    pool_name: &'a str,
    pool_uuid_hex: &'a str,
    drts: BTreeMap<String, DrtMetadata>,
    owner: &'a WalletMetadata,
    schema_id: String,
    schema: Vec<FieldSchema>,
}

/// Store a newly created pool.
async fn persist_pool_metadata(
    state: &AppState,
    new: NewPool<'_>,
) -> Result<PoolMetadata, ApiError> {
    let meta = PoolMetadata {
        pool_pda: new.pool_pda.to_string(),
        pool_name: new.pool_name.to_string(),
        kind: PoolKind::Malta,
        pool_uuid_hex: new.pool_uuid_hex.to_string(),
        drts: new.drts,
        owner_wallet_id: new.owner.wallet_id.clone(),
        owner_pubkey: Some(new.owner.public_address.clone()),
        schema_id: new.schema_id,
        schema: new.schema,
        validation_mode: crate::data_validation::ValidationMode::HeadersOnly,
        state: PoolState::NeedsInit,
        created_onchain_at: chrono::Utc::now(),
        initialized_at: None,
        version: 0,
    };
    state.storage.pools().create(&meta).await?;
    Ok(meta)
}

// ============================================================================
// POST /v1/drt/pools/malta
// ============================================================================

/// Create a MALTA pool (CSV-driven, schema required).
#[utoipa::path(
    post,
    path = "/v1/drt/pools/malta",
    tag = "DRT Pools",
    summary = "Create MALTA pool",
    description = "Atomically: create_pool + register_drt × N (always includes 'append') + seal_pool, then persist the inline schema.",
    security(("bearer_auth" = [])),
    request_body = CreateMaltaPoolRequest,
    responses(
        (status = 201, description = "Pool created", body = CreatePoolResponse),
        (status = 400, description = "Validation error"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 503, description = "RPC unavailable"),
    )
)]
pub async fn create_malta_pool(
    AdminToken(token): AdminToken,
    State(state): State<AppState>,
    Json(payload): Json<CreateMaltaPoolRequest>,
) -> Result<(axum::http::StatusCode, Json<CreatePoolResponse>), ApiError> {
    validate_pool_name(&payload.pool_name)?;
    let resolved = validate_drt_requests(&payload.drts)?;
    if !resolved.iter().any(|d| d.name == APPEND_DRT_NAME) {
        return Err(ApiError::bad_request(
            "MALTA pools must include the 'append' DRT",
        ));
    }
    let (schema_id, fields) = parse_schema(&payload.schema)?;

    let (wallet, keypair) = load_wallet_keypair(&state, &payload.wallet_id, &token.sub).await?;

    let created = create_pool_atomic(&state, &keypair, &resolved).await?;

    let pool_pda_str = created.pool_pda.to_string();
    let pool_uuid_hex = hex::encode(created.pool_uuid);
    let final_sig = created.signatures.last().cloned().unwrap_or_default();

    let meta = persist_pool_metadata(
        &state,
        NewPool {
            pool_pda: &pool_pda_str,
            pool_name: &payload.pool_name,
            pool_uuid_hex: &pool_uuid_hex,
            drts: created.drts.clone(),
            owner: &wallet,
            schema_id: schema_id.clone(),
            schema: fields,
        },
    )
    .await?;

    info!(
        signature = %final_sig,
        pool = %pool_pda_str,
        owner = %wallet.public_address,
        drts = meta.drts.len(),
        schema = %schema_id,
        "MALTA pool created"
    );
    audit::pool(&pool_pda_str);
    audit::signature(&final_sig);

    Ok((
        axum::http::StatusCode::CREATED,
        Json(CreatePoolResponse {
            signature: final_sig.clone(),
            signatures: created.signatures,
            pool_pda: pool_pda_str,
            pool_uuid: pool_uuid_hex,
            mints: created
                .drts
                .iter()
                .map(|(n, m)| (n.clone(), m.mint.clone()))
                .collect(),
            right_ids: created
                .drts
                .iter()
                .map(|(n, m)| (n.clone(), m.right_id_hex.clone()))
                .collect(),
            explorer_url: explorer_url(&state, &final_sig),
        }),
    ))
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
    crate::auth::AnalystToken(_token): crate::auth::AnalystToken,
    State(state): State<AppState>,
    Path(pool_pda_str): Path<String>,
) -> Result<Json<PoolInfoResponse>, ApiError> {
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
            (
                m.pool_name.clone(),
                match m.kind {
                    PoolKind::Malta => "malta",
                }
                .to_string(),
                drts,
            )
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
/// Useful as a sanity check that the enclave's cached `pool_meta.drts[name]`
/// matches what's actually on chain.
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
    crate::auth::AnalystToken(_token): crate::auth::AnalystToken,
    State(state): State<AppState>,
    Path((pool_pda_str, drt_name)): Path<(String, String)>,
) -> Result<Json<DrtConfigResponse>, ApiError> {
    let pool_pda = Pubkey::from_str(&pool_pda_str)
        .map_err(|_| ApiError::bad_request("invalid pool PDA address"))?;
    let meta = load_pool_meta(&state, &pool_pda_str).await?;
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
