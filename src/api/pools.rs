// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! DRT pool API handlers (new `digital_rights_tokens` contract).
//!
//! - `POST /v1/drt/pools/malta` — atomic create (pool + its analysis)

use axum::{extract::State, http::StatusCode, response::Response};
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
use sha2::{Digest, Sha256};

use crate::analysis::definition::Definition;
use crate::analysis::fetch::{check_url, FetchError};
use crate::blockchain::drt::{
    instructions::{
        build_compute_budget_ix, build_create_pool, build_register_drt, build_seal_pool,
    },
    pda::{derive_mint_pda, derive_pool_pda},
    types::*,
    validation::{parse_code_hash, validate_drt_requests, validate_pool_name, ResolvedDrt},
};
use crate::blockchain::signing::keypair_from_bytes_verified;
use crate::chain::{self, Effect};
use crate::error::ApiError;
use crate::idempotency::{Idempotent, JsonBody};
use crate::ids;
use crate::state::AppState;
use crate::storage::pools::{AnalysisRef, DrtMetadata, PoolDoc, PoolKind};
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

/// The analysis definition at `url`, which must hash to `hash`: stored by an
/// earlier attempt, or else fetched. Either way it is checked, then stored.
async fn load_definition(
    state: &AppState,
    url: &str,
    hash: &[u8; 32],
) -> Result<Definition, ApiError> {
    let bytes = match state.storage.scripts().get(&hex::encode(hash)).await? {
        Some(bytes) => bytes,
        None => {
            let bytes = state.fetcher.fetch(url).await.map_err(|e| match e {
                FetchError::Refused(m) => {
                    ApiError::bad_request(format!("the analysis couldn't be fetched: {m}"))
                }
                FetchError::Unavailable(m) => {
                    ApiError::service_unavailable(format!("the analysis couldn't be fetched: {m}"))
                }
            })?;
            if Sha256::digest(&bytes).as_slice() != hash {
                return Err(ApiError::bad_request(format!(
                    "the file at {url} doesn't hash to code_hash_hex"
                )));
            }
            bytes
        }
    };
    let definition = Definition::parse(&bytes)
        .map_err(|e| ApiError::bad_request(format!("the analysis isn't valid: {e}")))?;
    state.storage.scripts().put(&bytes).await?;
    Ok(definition)
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

/// Create a MALTA pool whose analysis is the definition at
/// `analysis.code_repo_url`.
///
/// The definition must hash to `analysis.code_hash_hex` and be a valid
/// analysis; its columns are the pool's schema. The pool's UUID, and so its
/// PDA, derives from the caller and the `Idempotency-Key`. The pool document
/// is staged first; the creating
/// transaction follows the stored-transaction rule, so a retry never creates
/// a second pool; then, once that transaction is finalized, the document is
/// written with the creation signature. Waiting for `finalized` means a
/// document never names a pool that a rolled-back block took away.
#[utoipa::path(
    post,
    path = "/v1/drt/pools/malta",
    tag = "DRT Pools",
    summary = "Create MALTA pool",
    description = "Fetch the analysis definition from its allowlisted GitHub URL and check it against code_hash_hex; then, atomically, create_pool + register_drt for 'append' and for the analysis + seal_pool; once that transaction is finalized, store the pool's document, whose schema is the definition's columns. Idempotent: retries with the same Idempotency-Key create one pool.",
    security(("bearer_auth" = [])),
    params(
        ("Idempotency-Key" = String, Header, format = "uuid", description = "A UUID naming this user action; reuse it on every retry"),
    ),
    request_body = CreateMaltaPoolRequest,
    responses(
        (status = 201, description = "Pool created", body = CreatePoolResponse),
        (status = 400, description = "Validation error, a definition that can't be fetched, doesn't match its hash or isn't valid, no Idempotency-Key, or Solana refused the transaction (`transaction_rejected`)"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 422, description = "The Idempotency-Key was used for a different request"),
        (status = 503, description = "RPC unavailable, or GitHub couldn't be reached"),
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
    let analysis = &payload.analysis;
    check_url(&analysis.code_repo_url).map_err(|e| ApiError::bad_request(e.to_string()))?;
    let code_hash = parse_code_hash(&analysis.code_hash_hex)?;
    if code_hash == [0; 32] {
        return Err(ApiError::bad_request(
            "code_hash_hex must be the definition's SHA-256",
        ));
    }
    let (wallet, keypair) =
        load_wallet_keypair(&state, &payload.wallet_id, &caller.user_id).await?;
    let definition = load_definition(&state, &analysis.code_repo_url, &code_hash).await?;
    let resolved = validate_drt_requests(&[
        DrtRequest {
            name: APPEND_DRT_NAME.to_string(),
            supply: payload.append_supply,
            code_repo_url: None,
            code_hash_hex: None,
        },
        DrtRequest {
            name: definition.analysis_id.clone(),
            supply: analysis.supply,
            code_repo_url: Some(analysis.code_repo_url.clone()),
            code_hash_hex: Some(hex::encode(code_hash)),
        },
    ])?;
    let pool_uuid = ids::pool_uuid(&caller.user_id, &request.key);

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
        schema_id: definition.analysis_id.clone(),
        schema: definition.schema(),
        analysis: Some(AnalysisRef {
            analysis_id: definition.analysis_id.clone(),
            display_name: definition.display_name.clone(),
            code_repo_url: analysis.code_repo_url.clone(),
            code_hash_hex: hex::encode(code_hash),
        }),
        created_by: caller.user_id.clone(),
        created_at: now,
        creation_signature: String::new(),
        initial: None,
        issuances: Vec::new(),
        revocations: Vec::new(),
        grants: Vec::new(),
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
