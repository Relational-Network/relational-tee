// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! DRT pool API handlers (new `digital_rights_tokens` contract).
//!
//! - `POST /v1/drt/pools/malta`        — atomic create (CSV-driven pool + schema)
//! - `POST /v1/drt/pools/iob-erp`      — atomic create (ERP pool, no schema)
//! - `GET  /v1/drt/pools/{pool_pda}`   — pool info (chain + enclave metadata)
//! - `GET  /v1/drt/events/{signature}` — parsed tx events

use axum::{
    extract::{Path, State},
    Json,
};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use std::collections::BTreeMap;
use std::str::FromStr;
use tracing::{info, warn};

use crate::auth::AdminToken;
use crate::blockchain::drt::{
    accounts::{fetch_drt_config, fetch_pool},
    events::{parse_events_from_signature, parse_events_from_signature_with_commitment, DrtEvent},
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
use crate::storage::audit::AuditEventType;
use crate::storage::ownership::OwnershipEnforcer;
use crate::storage::pool_metadata::{DrtMetadata, PoolKind, PoolMetadata, PoolState};
use crate::storage::repository::wallets::{WalletMetadata, WalletRepository, WalletStatus};

// ============================================================================
// Shared helpers (also used by api/credentials.rs and api/admin.rs)
// ============================================================================

/// Load a wallet keypair, verifying ownership and active status.
pub(crate) fn load_wallet_keypair(
    repo: &WalletRepository<'_>,
    wallet_id: &str,
    caller_sub: &str,
) -> Result<(WalletMetadata, Keypair), ApiError> {
    let wallet = repo.get(wallet_id)?;
    wallet.verify_ownership(caller_sub)?;
    if wallet.status == WalletStatus::Deleted {
        return Err(ApiError::not_found(format!("wallet {wallet_id} not found")));
    }
    if wallet.status == WalletStatus::Suspended {
        return Err(ApiError::forbidden(format!(
            "wallet {wallet_id} is suspended"
        )));
    }
    let keypair_bytes = repo.read_keypair(wallet_id)?;
    let keypair = keypair_from_bytes_verified(&keypair_bytes, &wallet.public_address)?;
    Ok((wallet, keypair))
}

/// Sign + send + parse events. `commitment` is `"confirmed"` or `"finalized"`.
pub(crate) async fn sign_send_and_parse(
    state: &AppState,
    keypair: &Keypair,
    instructions: Vec<solana_instruction::Instruction>,
    commitment: &str,
) -> Result<(String, Vec<DrtEvent>), ApiError> {
    let rpc = state.solana_client.rpc();
    let recent_blockhash = rpc
        .get_latest_blockhash()
        .await
        .map_err(|e| ApiError::service_unavailable(format!("blockhash fetch failed: {e}")))?;
    let message = solana_message::Message::new(&instructions, Some(&keypair.pubkey()));
    let tx = solana_transaction::Transaction::new(&[keypair], message, recent_blockhash);
    let signature = rpc
        .send_transaction(&tx)
        .await
        .map_err(|e| ApiError::service_unavailable(format!("transaction send failed: {e}")))?;
    state
        .solana_client
        .await_confirmation(&signature, commitment)
        .await?;
    let sig_str = signature.to_string();
    let events = parse_events_from_signature_with_commitment(rpc, &sig_str, commitment)
        .await
        .unwrap_or_default();
    Ok((sig_str, events))
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

/// Load pool metadata from enclave storage.
pub(crate) fn load_pool_meta(state: &AppState, pool_pda: &str) -> Result<PoolMetadata, ApiError> {
    let path = state.storage.paths().pool_meta(pool_pda);
    state.storage.read_json::<PoolMetadata>(&path).map_err(|_| {
        ApiError::not_found(format!(
            "pool metadata not found for {pool_pda} — pool may need creation"
        ))
    })
}

pub(crate) fn explorer_url(state: &AppState, sig: &str) -> String {
    state.solana_client.network().explorer_tx_url(sig)
}

/// Build the on-chain provenance block embedded in every audit `details` JSON.
///
/// `chain.events` is the unmodified Anchor decode — what an auditor would get
/// by replaying the signature against chain state. `chain.labels` is an
/// **off-chain** convenience map (pool name, DRT name lookups by right_id /
/// mint / drt_config PDA, the owner's wallet) so the dashboard can render
/// human-meaningful aliases without polluting the on-chain section. Auditors
/// ignore `labels` and verify against `events`.
pub(crate) fn chain_section(
    signatures: &[String],
    events: &[DrtEvent],
    labels: serde_json::Value,
) -> serde_json::Value {
    let decoded: Vec<_> = events.iter().map(DrtEvent::to_response).collect();
    serde_json::json!({
        "program_id": crate::config::DRT_PROGRAM_ID_STR,
        "tx_signatures": signatures,
        "events": decoded,
        "labels": labels,
    })
}

/// Build an id→human-name map for a pool — DRT names keyed by right_id (hex),
/// mint pubkey, and drt_config PDA. Use [`chain_section`] with the result.
///
/// `extra` lets callers inject additional id→label pairs (e.g. commitment hash
/// → record_id for credential issuance / revocation events) before merging.
pub(crate) fn pool_labels(
    meta: &crate::storage::pool_metadata::PoolMetadata,
    extra: Option<serde_json::Map<String, serde_json::Value>>,
) -> serde_json::Value {
    let mut id_to_name: serde_json::Map<String, serde_json::Value> = extra.unwrap_or_default();
    let pool_pk = Pubkey::from_str(&meta.pool_pda).ok();
    for (name, drt) in &meta.drts {
        let nm = serde_json::Value::String(name.clone());
        id_to_name.insert(drt.right_id_hex.clone(), nm.clone());
        id_to_name.insert(drt.mint.clone(), nm.clone());
        if let (Some(pk), Ok(rid_bytes)) = (pool_pk, hex::decode(&drt.right_id_hex)) {
            if let Ok(rid) = <[u8; 16]>::try_from(rid_bytes.as_slice()) {
                let (config, _) = derive_drt_config_pda(&pk, &rid);
                id_to_name.insert(config.to_string(), nm);
            }
        }
    }
    if let Some(owner) = meta.owner_pubkey.as_ref() {
        id_to_name
            .entry(owner.clone())
            .or_insert_with(|| serde_json::Value::String("pool owner".to_string()));
    }
    id_to_name
        .entry(meta.pool_pda.clone())
        .or_insert_with(|| serde_json::Value::String(meta.pool_name.clone()));
    serde_json::json!({
        "pool_name": meta.pool_name,
        "owner_wallet": meta.owner_pubkey,
        "id_to_name": id_to_name,
    })
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
// Core create-pool logic shared by both endpoints.
// ============================================================================

struct CreatedPool {
    pool_pda: Pubkey,
    pool_uuid: [u8; 16],
    signatures: Vec<String>,
    drts: BTreeMap<String, DrtMetadata>,
    events: Vec<DrtEvent>,
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

    let (sig, events) = sign_send_and_parse(state, owner_keypair, ixs, "confirmed").await?;

    Ok(CreatedPool {
        pool_pda,
        pool_uuid,
        signatures: vec![sig],
        drts: drt_records,
        events,
    })
}

#[allow(clippy::too_many_arguments)]
fn persist_pool_metadata(
    state: &AppState,
    pool_pda: &str,
    pool_name: &str,
    kind: PoolKind,
    pool_uuid_hex: &str,
    drts: BTreeMap<String, DrtMetadata>,
    owner_wallet_id: &str,
    owner_pubkey: &str,
    schema_id: &str,
    validation_mode: crate::data_validation::ValidationMode,
) -> Result<PoolMetadata, ApiError> {
    let paths = state.storage.paths();
    let dataset_dir = paths.pool_dataset_dir(pool_pda);
    state
        .storage
        .create_dir(&dataset_dir)
        .map_err(|e| ApiError::internal(format!("failed to create pool directory: {e}")))?;

    let meta = PoolMetadata {
        pool_pda: pool_pda.to_string(),
        pool_name: pool_name.to_string(),
        kind,
        pool_uuid_hex: pool_uuid_hex.to_string(),
        drts,
        owner_wallet_id: owner_wallet_id.to_string(),
        owner_pubkey: Some(owner_pubkey.to_string()),
        schema_id: schema_id.to_string(),
        validation_mode,
        state: PoolState::NeedsInit,
        created_onchain_at: chrono::Utc::now(),
        initialized_at: None,
        last_issue_at: None,
        total_credentials: 0,
        revoked_count: 0,
    };
    state
        .storage
        .write_json(paths.pool_meta(pool_pda), &meta)
        .map_err(|e| ApiError::internal(format!("failed to write pool metadata: {e}")))?;
    if let Err(e) = state.tx_db.upsert_pool_meta(&meta) {
        warn!(pool = %pool_pda, error = %e, "Failed to write pool meta to redb");
    }
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
    let resolved = validate_drt_requests(&payload.drts, /* allow_append */ true)?;
    if !resolved.iter().any(|d| d.name == APPEND_DRT_NAME) {
        return Err(ApiError::bad_request(
            "MALTA pools must include the 'append' DRT",
        ));
    }
    let (schema_id, fields) = parse_schema(&payload.schema)?;

    let repo = WalletRepository::new(&state.storage);
    let (wallet, keypair) = load_wallet_keypair(&repo, &payload.wallet_id, &token.sub)?;

    let created = create_pool_atomic(&state, &keypair, &resolved).await?;

    let pool_pda_str = created.pool_pda.to_string();
    let pool_uuid_hex = hex::encode(created.pool_uuid);
    let final_sig = created.signatures.last().cloned().unwrap_or_default();

    let meta = persist_pool_metadata(
        &state,
        &pool_pda_str,
        &payload.pool_name,
        PoolKind::Malta,
        &pool_uuid_hex,
        created.drts.clone(),
        &wallet.wallet_id,
        &wallet.public_address,
        &schema_id,
        crate::data_validation::ValidationMode::HeadersOnly,
    )?;

    crate::data_validation::save_pool_schema(state.storage.paths(), &pool_pda_str, &fields)
        .map_err(ApiError::internal)?;

    info!(
        signature = %final_sig,
        pool = %pool_pda_str,
        owner = %wallet.public_address,
        drts = meta.drts.len(),
        schema = %schema_id,
        "MALTA pool created"
    );

    let evt = crate::storage::audit::AuditEvent::new(AuditEventType::PoolCreated)
        .with_user(&token.sub)
        .with_resource("drt_pool", &pool_pda_str)
        .with_pool_pda(&pool_pda_str)
        .with_details(serde_json::json!({
            "kind": "malta",
            "pool_name": payload.pool_name,
            "pool_uuid": pool_uuid_hex,
            "tx_signatures": created.signatures,
            "schema_id": schema_id,
            "drt_count": meta.drts.len(),
            "chain": chain_section(&created.signatures, &created.events, pool_labels(&meta, None)),
        }));
    crate::storage::audit::AuditRepository::new(&state.storage)
        .with_tx_db(&state.tx_db)
        .log(&evt)
        .await;

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
// POST /v1/drt/pools/iob-erp
// ============================================================================

/// Create an IOB ERP pool (Jitterbit-driven, no schema, no `append`).
#[utoipa::path(
    post,
    path = "/v1/drt/pools/iob-erp",
    tag = "DRT Pools",
    summary = "Create IOB ERP pool",
    description = "Atomically: create_pool + register_drt × N + seal_pool. Append DRT is rejected — IOB ERP pools are populated by Jitterbit, not via the dashboard upload path.",
    security(("bearer_auth" = [])),
    request_body = CreateIobErpPoolRequest,
    responses(
        (status = 201, description = "Pool created", body = CreatePoolResponse),
        (status = 400, description = "Validation error"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 503, description = "RPC unavailable"),
    )
)]
pub async fn create_iob_erp_pool(
    AdminToken(token): AdminToken,
    State(state): State<AppState>,
    Json(payload): Json<CreateIobErpPoolRequest>,
) -> Result<(axum::http::StatusCode, Json<CreatePoolResponse>), ApiError> {
    validate_pool_name(&payload.pool_name)?;
    let resolved = validate_drt_requests(&payload.drts, /* allow_append */ false)?;

    let repo = WalletRepository::new(&state.storage);
    let (wallet, keypair) = load_wallet_keypair(&repo, &payload.wallet_id, &token.sub)?;

    let created = create_pool_atomic(&state, &keypair, &resolved).await?;

    let pool_pda_str = created.pool_pda.to_string();
    let pool_uuid_hex = hex::encode(created.pool_uuid);
    let final_sig = created.signatures.last().cloned().unwrap_or_default();

    let meta = persist_pool_metadata(
        &state,
        &pool_pda_str,
        &payload.pool_name,
        PoolKind::IobErp,
        &pool_uuid_hex,
        created.drts.clone(),
        &wallet.wallet_id,
        &wallet.public_address,
        "",
        crate::data_validation::ValidationMode::None,
    )?;

    info!(
        signature = %final_sig,
        pool = %pool_pda_str,
        owner = %wallet.public_address,
        drts = meta.drts.len(),
        "IOB ERP pool created"
    );

    let evt = crate::storage::audit::AuditEvent::new(AuditEventType::PoolCreated)
        .with_user(&token.sub)
        .with_resource("drt_pool", &pool_pda_str)
        .with_pool_pda(&pool_pda_str)
        .with_details(serde_json::json!({
            "kind": "iob_erp",
            "pool_name": payload.pool_name,
            "pool_uuid": pool_uuid_hex,
            "tx_signatures": created.signatures,
            "drt_count": meta.drts.len(),
            "chain": chain_section(&created.signatures, &created.events, pool_labels(&meta, None)),
        }));
    crate::storage::audit::AuditRepository::new(&state.storage)
        .with_tx_db(&state.tx_db)
        .log(&evt)
        .await;

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
    let meta = load_pool_meta(&state, &pool_pda_str).ok();

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
                    PoolKind::IobErp => "iob_erp",
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
    let meta = load_pool_meta(&state, &pool_pda_str)?;
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

// ============================================================================
// GET /v1/drt/events/{signature}
// ============================================================================

/// Parse DRT events from a transaction signature.
#[utoipa::path(
    get,
    path = "/v1/drt/events/{signature}",
    tag = "DRT Pools",
    summary = "Get DRT events from transaction",
    description = "Fetch a confirmed transaction and parse any DRT contract events from its logs.",
    security(("bearer_auth" = [])),
    params(
        ("signature" = String, Path, description = "Transaction signature (base58)"),
    ),
    responses(
        (status = 200, description = "Parsed events", body = TxEventsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Transaction not found"),
        (status = 503, description = "RPC unavailable"),
    )
)]
pub async fn get_tx_events(
    crate::auth::AnalystToken(_token): crate::auth::AnalystToken,
    State(state): State<AppState>,
    Path(signature): Path<String>,
) -> Result<Json<TxEventsResponse>, ApiError> {
    let events = parse_events_from_signature(state.solana_client.rpc(), &signature).await?;
    Ok(Json(TxEventsResponse {
        signature,
        events: events.iter().map(|e| e.to_response()).collect(),
    }))
}
