// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Credential issuance endpoint.
//!
//! - `POST /v1/drt/pools/{pool_pda}/issue` — issue credentials (append-DRT gated)

use axum::{
    extract::{Multipart, Path, State},
    http::StatusCode,
    response::Response,
};
use chrono::Utc;
use serde::Serialize;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use std::str::FromStr;
use tracing::{info, warn};
use utoipa::ToSchema;

use super::{
    count_csv_rows, decode_right_id, parse_pda, pool_not_found, sha256_hex, validation_failed,
};
use crate::api::pools::{load_pool, signed, verify_pool_ownership};
use crate::audit;
use crate::auth::{Caller, Permission};
use crate::blockchain::drt::{
    accounts::fetch_pool,
    instructions::build_grant_right,
    pda::{compute_commitment, derive_drt_config_pda, derive_grant_pda, derive_user_ata},
    types::APPEND_DRT_NAME,
};
use crate::chain::{self, Effect};
use crate::error::ApiError;
use crate::handlers::{open_sealed_csv, validate_payload};
use crate::idempotency::Idempotent;
use crate::ids;
use crate::seal::SealedUploadForm;
use crate::state::AppState;
use crate::storage::pools::{PoolState, Upload};
use crate::storage::staged::{Saga, Staged};
use crate::storage::Change;

// ============================================================================
// Response types
// ============================================================================

/// Response for credential issuance.
#[derive(Debug, Serialize, ToSchema)]
pub struct IssueCredentialsResponse {
    /// UUID of the stored credential record.
    pub record_id: String,
    /// Number of credential rows issued.
    pub rows_issued: u64,
    /// Transaction signature of the append DRT redemption.
    pub redeem_signature: String,
    /// Updated total row count for the pool (count of CSV rows uploaded).
    pub total_rows: u64,
    /// Solana Explorer URL for the redeem transaction.
    pub explorer_url: String,
}

// ============================================================================
// Handlers
// ============================================================================

/// Issue credentials to a pool (append-DRT gated).
///
/// Stores the dataset, stages the upload, burns 1 append DRT on-chain, then
/// adds the upload, with the burn's signature, to the pool's issuance log.
/// The upload's ID derives from the caller, the pool and the
/// `Idempotency-Key`, and fixes the grant commitment, so the burn follows
/// the stored-transaction rule and a retry never burns a second DRT.
#[utoipa::path(
    post,
    path = "/v1/drt/pools/{pool_pda}/issue",
    tag = "Credentials",
    summary = "Issue credentials",
    description = "Issue credentials by redeeming an append DRT and storing the sealed CSV data. Validates ownership, DRT balance and the CSV schema, stores the dataset, burns 1 append DRT, then records the upload in the pool's issuance log. Idempotent: retries with the same Idempotency-Key burn one DRT. The CSV is sealed with HPKE to the transport key from `GET /v1/attestation`, with this request's AAD.",
    security(("bearer_auth" = [])),
    params(
        ("pool_pda" = String, Path, description = "Pool PDA address (base58)"),
        ("Idempotency-Key" = String, Header, description = "A UUID naming this user action; reuse it on every retry"),
    ),
    request_body(content = SealedUploadForm, content_type = "multipart/form-data"),
    responses(
        (status = 200, description = "Credentials issued", body = IssueCredentialsResponse),
        (status = 400, description = "Validation error, insufficient DRTs, no Idempotency-Key, or the sealed payload doesn't open (`sealed_payload_invalid`)"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Pool not found"),
        (status = 409, description = "The pool changed concurrently; retry"),
        (status = 422, description = "The Idempotency-Key was used for a different request"),
        (status = 503, description = "Solana RPC unavailable"),
    )
)]
pub async fn issue_credentials(
    caller: Caller,
    request: Idempotent,
    State(state): State<AppState>,
    Path(pool_pda_str): Path<String>,
    multipart: Multipart,
) -> Result<Response, ApiError> {
    caller.require(Permission::PoolsWrite)?;
    // ── VALIDATION (reversible, cheap) ────────────────────────────

    // Open the sealed CSV first: the fingerprint covers the plaintext.
    let csv_bytes = open_sealed_csv(&state.transport, &caller, &request, multipart).await?;
    let mut op = open_or_replay!(state, &caller.user_id, request, &csv_bytes);
    let pool_pda = parse_pda(&pool_pda_str)?;

    // The pool must be ready.
    let doc = load_pool(&state, &pool_pda_str).await?;
    if doc.state() != PoolState::Ready {
        return Err(ApiError::bad_request(
            "pool not initialized — call /initialize first",
        ));
    }

    // An earlier attempt already recorded this upload: only the response is missing.
    let record_id = ids::upload_id(&caller.user_id, &pool_pda_str, &request.key);
    if let Some(done) = doc.upload(&record_id) {
        let signature = done.signature.clone().unwrap_or_default();
        let response = IssueCredentialsResponse {
            record_id: done.record_id.clone(),
            rows_issued: done.rows,
            explorer_url: state.solana_client.network().explorer_tx_url(&signature),
            redeem_signature: signature,
            total_rows: doc.totals().rows,
        };
        return op.finish(StatusCode::OK, &response).await;
    }

    // The append DRT's right_id and mint are only in the pool's document.
    let append_meta = doc
        .drts
        .get(APPEND_DRT_NAME)
        .ok_or_else(|| ApiError::internal("pool metadata missing 'append' DRT"))?;
    let append_right_id = decode_right_id(&append_meta.right_id_hex)?;
    let append_mint = Pubkey::from_str(&append_meta.mint)
        .map_err(|_| ApiError::internal("invalid mint pubkey in pool metadata"))?;
    let (drt_config_pda, _) = derive_drt_config_pda(&pool_pda, &append_right_id);

    // Decode the pool uuid for the commitment hash.
    let pool_uuid = decode_right_id(&doc.pool_uuid_hex)?;

    // Load the caller's own wallet: only the pool's owner can issue.
    let caller_wallet = crate::api::get_active_wallet_for_user(&state, &caller.user_id).await?;
    let keypair_bytes = state
        .storage
        .wallets()
        .read_keypair(&caller_wallet.wallet_id)
        .await?;
    let keypair = crate::blockchain::signing::keypair_from_bytes_verified(
        &keypair_bytes,
        &caller_wallet.public_address,
    )?;

    // Fetch on-chain pool for ownership check.
    let pool = fetch_pool(state.solana_client.rpc(), &pool_pda).await?;
    verify_pool_ownership(&pool, &caller_wallet)?;

    // The commitment is unique per upload (record_id || pool_uuid ||
    // append_right_id), and its Grant PDA is the on-chain receipt.
    let commitment = compute_commitment(&record_id, &pool_uuid, &append_right_id);
    let (grant_pda, _) = derive_grant_pda(&commitment);
    let burned = state
        .solana_client
        .rpc()
        .account_exists(&grant_pda, "confirmed")
        .await
        .map_err(|e| ApiError::rpc_unavailable(format!("Solana RPC error: {e}")))?;

    // Check the admin holds ≥1 append DRT, unless this upload's burn
    // already happened: then a retry completes after the last DRT is gone.
    if !burned {
        let user_ata = derive_user_ata(&keypair.pubkey(), &append_mint);
        let user_balance = match state
            .solana_client
            .rpc()
            .get_token_account_balance(&user_ata)
            .await
        {
            Ok(b) => b.amount.parse::<u64>().unwrap_or(0),
            Err(_) => 0,
        };
        if user_balance < 1 {
            return Err(ApiError::bad_request(
                "append DRT supply exhausted — pool needs to be re-registered",
            ));
        }
    }

    // Validate CSV against pool's schema.
    let summary = validate_payload(&doc.schema, &pool_pda_str, &csv_bytes, doc.validation_mode)?;
    if !summary.valid {
        return Err(validation_failed(summary.errors.len()));
    }

    let row_count = count_csv_rows(&csv_bytes);

    // ── STORE THE DATASET, STAGE THE UPLOAD ───────────────────────

    op.begin().await?;
    state
        .storage
        .pools()
        .put_dataset(&pool_pda_str, &record_id, &csv_bytes)
        .await?;
    let staged = state
        .storage
        .sagas()
        .stage(
            &format!("issue-{record_id}"),
            Staged {
                record: op.record_path().to_string(),
                staged_at: Utc::now(),
                saga: Saga::Issue {
                    pool_pda: pool_pda_str.clone(),
                    upload: Upload {
                        record_id: record_id.clone(),
                        upload_id: record_id.clone(),
                        sha256: sha256_hex(&csv_bytes),
                        rows: row_count,
                        uploaded_by: caller.user_id.clone(),
                        uploaded_at: Utc::now(),
                        signature: None,
                        commitment: Some(hex::encode(commitment)),
                    },
                },
            },
        )
        .await?;
    let Saga::Issue { mut upload, .. } = staged.saga else {
        return Err(ApiError::internal(
            "another saga is staged under this upload",
        ));
    };
    audit::upload(&record_id, row_count);

    // ── BURN (irreversible, at most once) ─────────────────────────

    let ix = build_grant_right(
        &pool_pda,
        &drt_config_pda,
        &append_mint,
        &keypair.pubkey(),
        &commitment,
    );
    let sig_str = chain::run(
        &state.solana_client,
        &mut op,
        &Effect::Account(grant_pda),
        "finalized",
        signed(&keypair, std::slice::from_ref(&ix)),
    )
    .await?;
    audit::signature(&sig_str);

    // ── RECORD ────────────────────────────────────────────────────

    // If this fails, a retry with the same key, or the reconciler, adds the entry.
    upload.signature = Some(sig_str.clone());
    let doc = state
        .storage
        .pools()
        .update::<ApiError>(&pool_pda_str, |doc| {
            if doc.upload(&upload.record_id).is_some() {
                return Ok(Change::Unchanged);
            }
            doc.issuances.push(upload.clone());
            Ok(Change::Changed)
        })
        .await
        .inspect_err(|e| {
            warn!(pool = %pool_pda_str, record_id = %record_id, redeem_sig = %sig_str, error = %e,
                "DRT burned; the issuance entry waits for a retry");
        })?
        .ok_or_else(|| pool_not_found(&pool_pda_str))?;

    let total_rows = doc.totals().rows;
    let explorer_url = state.solana_client.network().explorer_tx_url(&sig_str);

    info!(
        pool = %pool_pda_str,
        record_id = %record_id,
        rows = row_count,
        redeem_sig = %sig_str,
        total = total_rows,
        "Credentials issued"
    );

    op.finish(
        StatusCode::OK,
        &IssueCredentialsResponse {
            record_id,
            rows_issued: row_count,
            redeem_signature: sig_str,
            total_rows,
            explorer_url,
        },
    )
    .await
}
