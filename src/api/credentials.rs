// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Credential issuance, revocation, and pool discovery endpoints.
//!
//! - `POST /v1/drt/pools/{pool_pda}/schema`     — replace the pool's schema
//! - `GET  /v1/drt/pools/{pool_pda}/schema`     — the pool's schema
//! - `POST /v1/drt/pools/{pool_pda}/initialize` — seed initial dataset
//! - `POST /v1/drt/pools/{pool_pda}/issue`      — issue credentials (append-DRT gated)
//! - `POST /v1/drt/pools/{pool_pda}/revoke`     — revoke credential(s)
//! - `GET  /v1/drt/pools/{pool_pda}/revocations` — list revocations
//! - `GET  /v1/drt/pools/{pool_pda}/summary`    — pool metadata + on-chain state
//! - `GET  /v1/drt/pools/by-wallet/{wallet_id}` — list pools owned by wallet
//! - `GET  /v1/drt/pools/list`                  — list all pools (marketplace discovery)
//! - `GET  /v1/drt/pools/{pool_pda}/issuance-log` — list per-issuance records
//!
//! Everything here reads or changes the pool document (see
//! [`crate::storage::pools`]). Lists page in memory: pass `next_cursor`
//! back as `cursor`.

use axum::{
    extract::{Multipart, Path, Query, State},
    http::StatusCode,
    response::Response,
    Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use std::str::FromStr;
use tracing::{info, warn};
use utoipa::{IntoParams, ToSchema};

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
use crate::handlers::{parse_csv_payload, validate_payload};
use crate::idempotency::{Idempotent, JsonBody};
use crate::ids;
use crate::state::AppState;
use crate::storage::pools::{PoolDoc, PoolState, Revocation, Upload, INITIAL};
use crate::storage::staged::{Saga, Staged};
use crate::storage::Change;
use crate::tee::KeyName;
use sha2::{Digest, Sha256};

use super::pools::{load_pool, load_wallet_keypair, signed, verify_pool_ownership};
use super::{page, CursorQuery};

// ============================================================================
// Request / Response types
// ============================================================================

/// Response for pool initialization.
#[derive(Debug, Serialize, ToSchema)]
pub struct InitializePoolResponse {
    /// Number of credential rows stored.
    pub rows: u64,
    /// Record ID of the stored dataset.
    pub record_id: String,
    /// Pool lifecycle state after initialization.
    pub state: String,
}

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

/// Revocation request body.
#[derive(Debug, Deserialize, ToSchema)]
pub struct RevokeCredentialsRequest {
    /// Wallet ID of the pool owner.
    pub wallet_id: String,
    /// Credential record IDs to revoke (`initial`, or UUIDs from `/issue` responses).
    pub credential_ids: Vec<String>,
    /// Optional reason for revocation.
    #[serde(default)]
    pub reason: Option<String>,
}

/// Revocation response.
#[derive(Debug, Serialize, ToSchema)]
pub struct RevokeCredentialsResponse {
    /// Number of credentials revoked (each distinct ID counts once, whether
    /// or not it was already revoked).
    pub revoked: usize,
}

/// Single revocation entry.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RevocationEntry {
    pub credential_id: String,
    pub revoked_by: String,
    pub revoked_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// One page of a pool's revocations, in credential ID order.
#[derive(Debug, Serialize, ToSchema)]
pub struct RevocationsResponse {
    pub pool_pda: String,
    pub revocations: Vec<RevocationEntry>,
    /// Present when there's another page; pass it as `cursor`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

fn default_limit() -> usize {
    50
}

/// Pool summary response (enclave metadata + on-chain state).
#[derive(Debug, Serialize, ToSchema)]
pub struct PoolSummaryResponse {
    pub pool_pda: String,
    pub pool_name: String,
    pub owner: String,
    pub schema_id: String,
    pub validation_mode: crate::data_validation::ValidationMode,
    pub state: String,
    /// Total CSV rows that have been uploaded into this pool across all
    /// initialize + issue calls.
    pub total_rows: u64,
    pub revoked_count: u64,
    pub created_at: String,
    /// The `user_id` who created the pool.
    pub created_by: String,
    /// The transaction that created, registered and sealed the pool.
    pub creation_signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initialized_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_issue_at: Option<String>,
    /// On-chain DRT configuration.
    pub drts: Vec<DrtConfigResponseCompact>,
}

/// Compact DRT config for the summary endpoint.
#[derive(Debug, Serialize, ToSchema)]
pub struct DrtConfigResponseCompact {
    pub drt_type: String,
    /// Total tokens minted at registration (the original supply).
    pub supply: u64,
    /// Tokens still in circulation (i.e. not yet burned/redeemed).
    /// Best-effort: if the SPL RPC call fails this falls back to `supply`.
    pub remaining_supply: u64,
    pub mint: String,
}

/// Single pool entry in the list response.
#[derive(Debug, Serialize, ToSchema)]
pub struct PoolListEntry {
    pub pool_pda: String,
    pub pool_name: String,
    pub total_rows: u64,
    pub revoked_count: u64,
    pub schema_id: String,
    pub state: String,
    pub created_at: String,
}

/// One page of the pools a wallet owns.
#[derive(Debug, Serialize, ToSchema)]
pub struct PoolsByWalletResponse {
    pub wallet_id: String,
    pub pools: Vec<PoolListEntry>,
    /// Present when there's another page; pass it as `cursor`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// DRT entry for marketplace listing (compact, no mint/hash details).
#[derive(Debug, Serialize, ToSchema)]
pub struct MarketplaceDrtEntry {
    pub drt_type: String,
    /// Total tokens minted at registration.
    pub supply: u64,
    /// Tokens still in circulation. Best-effort RPC lookup.
    pub remaining_supply: u64,
}

/// Pool entry for the marketplace "browse all" listing.
#[derive(Debug, Serialize, ToSchema)]
pub struct MarketplacePoolEntry {
    pub pool_pda: String,
    pub pool_name: String,
    pub kind: String,
    pub owner: String,
    pub schema_id: String,
    pub state: String,
    pub total_rows: u64,
    pub revoked_count: u64,
    pub created_at: String,
    pub drt_count: usize,
    pub drts: Vec<MarketplaceDrtEntry>,
}

/// One page of all pools, filtered and sorted.
#[derive(Debug, Serialize, ToSchema)]
pub struct AllPoolsResponse {
    pub pools: Vec<MarketplacePoolEntry>,
    /// Present when there's another page; pass it as `cursor` with the same
    /// filters and sort.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// Query parameters for the list-all-pools endpoint.
#[derive(Debug, Deserialize, IntoParams)]
pub struct ListAllPoolsQuery {
    /// Filter by pool state: `ready` or `needs_init`.
    #[serde(default)]
    pub state: Option<String>,
    /// Case-insensitive search on pool name.
    #[serde(default)]
    pub search: Option<String>,
    /// Sort order: `created_desc` (default), `created_asc`, `name_asc`, `credentials_desc`.
    #[serde(default = "default_sort")]
    pub sort: String,
    /// Page size (default 50, max 100).
    #[serde(default = "default_limit")]
    pub limit: usize,
    /// `next_cursor` from the previous page.
    #[serde(default)]
    pub cursor: Option<String>,
}

fn default_sort() -> String {
    "created_desc".to_string()
}

/// Single upload in the issuance log: the initialisation or an issuance.
#[derive(Debug, Serialize, ToSchema)]
pub struct IssuanceRecord {
    pub record_id: String,
    pub uploaded_by: String,
    pub rows: u64,
    pub uploaded_at: String,
    /// The append-DRT burn, for an issuance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redeem_tx_signature: Option<String>,
}

/// One page of a pool's issuance log, newest first.
#[derive(Debug, Serialize, ToSchema)]
pub struct IssuanceLogResponse {
    pub pool_pda: String,
    pub records: Vec<IssuanceRecord>,
    /// Present when there's another page; pass it as `cursor`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// Request body for uploading a schema definition.
#[derive(Debug, Deserialize, ToSchema)]
pub struct UploadSchemaRequest {
    /// Schema ID label (e.g. `"pilot_v1"`). Must match the pool's `schema_id`.
    pub schema_id: String,
    /// Schema field definitions.
    pub fields: Vec<crate::data_validation::FieldSchema>,
}

/// Response for schema upload.
#[derive(Debug, Serialize, ToSchema)]
pub struct UploadSchemaResponse {
    /// The schema ID that was saved.
    pub schema_id: String,
    /// Number of fields in the schema.
    pub field_count: usize,
}

/// Response for `GET /v1/drt/pools/{pool_pda}/schema`.
#[derive(Debug, Serialize, ToSchema)]
pub struct GetSchemaResponse {
    pub pool_pda: String,
    pub schema_id: String,
    pub fields: Vec<crate::data_validation::FieldSchema>,
}

// ============================================================================
// Helpers
// ============================================================================

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Decode a 32-char hex string into 16 raw bytes. Used for right_id and pool_uuid.
pub(crate) fn decode_right_id(hex: &str) -> Result<[u8; 16], ApiError> {
    if hex.len() != 32 {
        return Err(ApiError::internal("expected 32-char hex (16 bytes)"));
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| ApiError::internal("invalid hex in 16-byte id"))?;
    }
    Ok(out)
}

/// Count CSV rows (excluding header).
fn count_csv_rows(csv_bytes: &[u8]) -> u64 {
    let text = String::from_utf8_lossy(csv_bytes);
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    if lines.len() > 1 {
        (lines.len() - 1) as u64 // subtract header
    } else {
        0
    }
}

fn validation_failed(errors: usize) -> ApiError {
    ApiError::bad_request(format!("CSV validation failed: {errors} error(s)"))
        .with_code("validation_failed")
}

fn pool_not_found(pool_pda: &str) -> ApiError {
    ApiError::not_found(format!("pool metadata not found for {pool_pda}"))
}

fn parse_pda(pool_pda: &str) -> Result<Pubkey, ApiError> {
    Pubkey::from_str(pool_pda).map_err(|_| ApiError::bad_request("invalid pool PDA address"))
}

// ============================================================================
// Handlers
// ============================================================================

/// Upload a schema definition for a pool.
///
/// Replaces the schema stored with the pool, which `/initialize` and
/// `/issue` validate CSV data against. Uploading the same schema again
/// changes nothing.
#[utoipa::path(
    post,
    path = "/v1/drt/pools/{pool_pda}/schema",
    tag = "Credentials",
    summary = "Upload schema for pool",
    description = "Upload a CSV schema definition for the pool. The schema is stored with the pool and used for CSV validation during pool initialization and credential issuance.",
    security(("bearer_auth" = [])),
    params(
        ("pool_pda" = String, Path, description = "Pool PDA address (base58)"),
        ("Idempotency-Key" = String, Header, description = "A UUID naming this user action; reuse it on every retry"),
    ),
    request_body = UploadSchemaRequest,
    responses(
        (status = 200, description = "Schema saved", body = UploadSchemaResponse),
        (status = 400, description = "Invalid schema, or no Idempotency-Key"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Not pool owner"),
        (status = 404, description = "Pool not found"),
        (status = 409, description = "The pool changed concurrently; retry"),
        (status = 422, description = "The Idempotency-Key was used for a different request"),
    )
)]
pub async fn upload_schema(
    caller: Caller,
    request: Idempotent,
    State(state): State<AppState>,
    Path(pool_pda_str): Path<String>,
    JsonBody {
        value: payload,
        bytes,
    }: JsonBody<UploadSchemaRequest>,
) -> Result<Response, ApiError> {
    caller.require(Permission::PoolsWrite)?;
    let mut op = open_or_replay!(state, &caller.user_id, request, &bytes);
    let pool_pda = parse_pda(&pool_pda_str)?;

    // Validate schema_id is a safe identifier.
    if payload.schema_id.is_empty()
        || payload.schema_id.len() > 128
        || !payload
            .schema_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(ApiError::bad_request(
            "schema_id must be 1-128 characters, alphanumeric with hyphens/underscores only",
        ));
    }

    if payload.fields.is_empty() {
        return Err(ApiError::bad_request("schema must have at least one field"));
    }

    // Fetch on-chain pool to verify it exists and get ownership.
    let pool = fetch_pool(state.solana_client.rpc(), &pool_pda).await?;
    let wallet = super::get_active_wallet_for_user(&state, &caller.user_id).await?;
    verify_pool_ownership(&pool, &wallet)?;

    op.begin().await?;
    state
        .storage
        .pools()
        .update(&pool_pda_str, |doc| {
            if doc.schema_id != payload.schema_id {
                return Err(ApiError::bad_request(format!(
                    "pool's schema_id is '{}', but you are uploading '{}'",
                    doc.schema_id, payload.schema_id
                )));
            }
            if doc.schema == payload.fields {
                return Ok(Change::Unchanged);
            }
            doc.schema = payload.fields.clone();
            Ok(Change::Changed)
        })
        .await?
        .ok_or_else(|| pool_not_found(&pool_pda_str))?;

    let field_count = payload.fields.len();
    info!(
        pool = %pool_pda_str,
        schema_id = %payload.schema_id,
        fields = field_count,
        "Schema uploaded and persisted"
    );

    op.finish(
        StatusCode::OK,
        &UploadSchemaResponse {
            schema_id: payload.schema_id,
            field_count,
        },
    )
    .await
}

/// Get a pool's stored schema.
#[utoipa::path(
    get,
    path = "/v1/drt/pools/{pool_pda}/schema",
    tag = "Credentials",
    summary = "Get pool schema",
    description = "Returns the schema stored with the pool. 404 if it has none.",
    security(("bearer_auth" = [])),
    params(
        ("pool_pda" = String, Path, description = "Pool PDA address (base58)"),
    ),
    responses(
        (status = 200, description = "Schema returned", body = GetSchemaResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Pool or schema not found"),
    )
)]
pub async fn get_schema(
    caller: Caller,
    State(state): State<AppState>,
    Path(pool_pda_str): Path<String>,
) -> Result<Json<GetSchemaResponse>, ApiError> {
    caller.require(Permission::PoolsRead)?;
    let doc = load_pool(&state, &pool_pda_str).await?;
    if doc.schema.is_empty() {
        return Err(ApiError::not_found(format!(
            "no schema uploaded yet for pool {pool_pda_str} — POST one to /v1/drt/pools/{{pda}}/schema"
        )));
    }

    Ok(Json(GetSchemaResponse {
        pool_pda: pool_pda_str,
        schema_id: doc.schema_id,
        fields: doc.schema,
    }))
}

/// Seed the initial dataset for a pool.
///
/// The pool must be in `needs_init` state. No append DRT is required —
/// this is the initial seeding by the pool creator. The dataset is stored,
/// then the pool document records it as the initial upload, which makes
/// the pool `ready`. The upload's ID derives from the caller, the pool and
/// the `Idempotency-Key`, so a retry finds its own earlier upload.
#[utoipa::path(
    post,
    path = "/v1/drt/pools/{pool_pda}/initialize",
    tag = "Credentials",
    summary = "Initialize pool dataset",
    description = "Seed the initial credential dataset for a pool. Requires the pool to be in `needs_init` state. No DRT required — only the pool creator can call this.",
    security(("bearer_auth" = [])),
    params(
        ("pool_pda" = String, Path, description = "Pool PDA address (base58)"),
        ("Idempotency-Key" = String, Header, description = "A UUID naming this user action; reuse it on every retry"),
    ),
    responses(
        (status = 200, description = "Dataset initialized", body = InitializePoolResponse),
        (status = 400, description = "Validation error, pool already initialized, or no Idempotency-Key"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Not pool owner"),
        (status = 404, description = "Pool not found"),
        (status = 409, description = "Another upload initialized the pool first"),
        (status = 422, description = "The Idempotency-Key was used for a different request"),
    )
)]
pub async fn initialize_pool(
    caller: Caller,
    request: Idempotent,
    State(state): State<AppState>,
    Path(pool_pda_str): Path<String>,
    multipart: Multipart,
) -> Result<Response, ApiError> {
    caller.require(Permission::PoolsWrite)?;
    // Parse and decrypt the CSV payload; the fingerprint covers the plaintext.
    let parsed = parse_csv_payload(state.keys.get(KeyName::Transport), multipart).await?;
    let mut op = open_or_replay!(state, &caller.user_id, request, &parsed.csv_bytes);
    let pool_pda = parse_pda(&pool_pda_str)?;

    // Fetch on-chain pool to verify it exists and get ownership.
    let pool = fetch_pool(state.solana_client.rpc(), &pool_pda).await?;
    let wallet = super::get_active_wallet_for_user(&state, &caller.user_id).await?;
    verify_pool_ownership(&pool, &wallet)?;

    let doc = load_pool(&state, &pool_pda_str).await?;
    let upload_id = ids::upload_id(&caller.user_id, &pool_pda_str, &request.key);
    let ours = doc
        .initial
        .as_ref()
        .is_some_and(|u| u.upload_id == upload_id);
    if !ours {
        if doc.state() != PoolState::NeedsInit {
            return Err(ApiError::bad_request(
                "pool is already initialized — use /issue to add credentials",
            ));
        }
        let summary = validate_payload(
            &doc.schema,
            &pool_pda_str,
            &parsed.csv_bytes,
            doc.validation_mode,
        )?;
        if !summary.valid {
            return Err(validation_failed(summary.errors.len()));
        }
    }

    let upload = Upload {
        record_id: INITIAL.to_string(),
        upload_id,
        sha256: sha256_hex(&parsed.csv_bytes),
        rows: count_csv_rows(&parsed.csv_bytes),
        uploaded_by: caller.user_id.clone(),
        uploaded_at: Utc::now(),
        signature: None,
        commitment: None,
    };
    op.begin().await?;
    if !ours {
        state
            .storage
            .pools()
            .put_dataset(&pool_pda_str, &upload.upload_id, &parsed.csv_bytes)
            .await?;
        state
            .storage
            .pools()
            .update(&pool_pda_str, |doc| match &doc.initial {
                None => {
                    doc.initial = Some(upload.clone());
                    Ok(Change::Changed)
                }
                Some(initial) if initial.upload_id == upload.upload_id => Ok(Change::Unchanged),
                Some(_) => Err(ApiError::conflict(
                    "another upload already initialized this pool — use /issue to add credentials",
                )),
            })
            .await?
            .ok_or_else(|| pool_not_found(&pool_pda_str))?;
    }
    audit::upload(INITIAL, upload.rows);

    info!(
        pool = %pool_pda_str,
        rows = upload.rows,
        schema = %doc.schema_id,
        "Pool dataset initialized"
    );

    op.finish(
        StatusCode::OK,
        &InitializePoolResponse {
            rows: upload.rows,
            record_id: INITIAL.to_string(),
            state: PoolState::Ready.as_str().to_string(),
        },
    )
    .await
}

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
    description = "Issue credentials by redeeming an append DRT and storing the encrypted CSV data. Validates ownership, DRT balance and the CSV schema, stores the dataset, burns 1 append DRT, then records the upload in the pool's issuance log. Idempotent: retries with the same Idempotency-Key burn one DRT.",
    security(("bearer_auth" = [])),
    params(
        ("pool_pda" = String, Path, description = "Pool PDA address (base58)"),
        ("Idempotency-Key" = String, Header, description = "A UUID naming this user action; reuse it on every retry"),
    ),
    responses(
        (status = 200, description = "Credentials issued", body = IssueCredentialsResponse),
        (status = 400, description = "Validation error, insufficient DRTs, or no Idempotency-Key"),
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

    // Parse and decrypt the CSV payload; the fingerprint covers the plaintext.
    let parsed = parse_csv_payload(state.keys.get(KeyName::Transport), multipart).await?;
    let mut op = open_or_replay!(state, &caller.user_id, request, &parsed.csv_bytes);
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
    let caller_wallet = super::get_active_wallet_for_user(&state, &caller.user_id).await?;
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
    let summary = validate_payload(
        &doc.schema,
        &pool_pda_str,
        &parsed.csv_bytes,
        doc.validation_mode,
    )?;
    if !summary.valid {
        return Err(validation_failed(summary.errors.len()));
    }

    let row_count = count_csv_rows(&parsed.csv_bytes);

    // ── STORE THE DATASET, STAGE THE UPLOAD ───────────────────────

    op.begin().await?;
    state
        .storage
        .pools()
        .put_dataset(&pool_pda_str, &record_id, &parsed.csv_bytes)
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
                        sha256: sha256_hex(&parsed.csv_bytes),
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

/// Revoke credential(s) from a pool.
///
/// Each revocation is recorded in the pool's document, with who revoked it,
/// when and why. Revoking an already revoked credential changes nothing.
#[utoipa::path(
    post,
    path = "/v1/drt/pools/{pool_pda}/revoke",
    tag = "Credentials",
    summary = "Revoke credentials",
    description = "Revoke one or more credentials by record ID. Revocations are recorded in the pool's document. Admin only.",
    security(("bearer_auth" = [])),
    params(
        ("pool_pda" = String, Path, description = "Pool PDA address (base58)"),
        ("Idempotency-Key" = String, Header, description = "A UUID naming this user action; reuse it on every retry"),
    ),
    request_body = RevokeCredentialsRequest,
    responses(
        (status = 200, description = "Credentials revoked", body = RevokeCredentialsResponse),
        (status = 400, description = "Validation error, or no Idempotency-Key"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Not pool owner"),
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
    if payload.credential_ids.is_empty() {
        return Err(ApiError::bad_request("credential_ids must not be empty"));
    }
    let pool_pda = parse_pda(&pool_pda_str)?;

    // Verify ownership.
    let (wallet, _) = load_wallet_keypair(&state, &payload.wallet_id, &caller.user_id).await?;
    let pool = fetch_pool(state.solana_client.rpc(), &pool_pda).await?;
    verify_pool_ownership(&pool, &wallet)?;

    let mut credential_ids: Vec<String> = Vec::with_capacity(payload.credential_ids.len());
    for cid in &payload.credential_ids {
        if !credential_ids.contains(cid) {
            credential_ids.push(cid.clone());
        }
    }

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

    op.finish(
        StatusCode::OK,
        &RevokeCredentialsResponse {
            revoked: credential_ids.len(),
        },
    )
    .await
}

/// List revocation entries for a pool.
#[utoipa::path(
    get,
    path = "/v1/drt/pools/{pool_pda}/revocations",
    tag = "Credentials",
    summary = "List revocations",
    description = "List a pool's revocations in credential ID order, one cursor page at a time. Admin only.",
    security(("bearer_auth" = [])),
    params(
        ("pool_pda" = String, Path, description = "Pool PDA address (base58)"),
        CursorQuery,
    ),
    responses(
        (status = 200, description = "Revocation list", body = RevocationsResponse),
        (status = 400, description = "Invalid cursor"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Pool not found"),
    )
)]
pub async fn list_revocations(
    caller: Caller,
    State(state): State<AppState>,
    Path(pool_pda_str): Path<String>,
    Query(query): Query<CursorQuery>,
) -> Result<Json<RevocationsResponse>, ApiError> {
    // Anyone who may read pools can view revocations (no ownership check).
    caller.require(Permission::PoolsRead)?;
    let mut revocations = load_pool(&state, &pool_pda_str).await?.revocations;
    revocations.sort_by(|a, b| a.credential_id.cmp(&b.credential_id));
    let (items, next_cursor) = page(
        revocations,
        |r| &r.credential_id,
        query.cursor.as_deref(),
        query.clamped_limit(),
    )?;

    Ok(Json(RevocationsResponse {
        pool_pda: pool_pda_str,
        revocations: items
            .into_iter()
            .map(|r| RevocationEntry {
                credential_id: r.credential_id,
                revoked_by: r.revoked_by,
                revoked_at: r.revoked_at.to_rfc3339(),
                reason: r.reason,
            })
            .collect(),
        next_cursor,
    }))
}

/// Get pool summary (enclave metadata + on-chain state).
#[utoipa::path(
    get,
    path = "/v1/drt/pools/{pool_pda}/summary",
    tag = "Credentials",
    summary = "Pool summary",
    description = "Combined view of the pool's document (who created it, with the creation signature; totals) and its on-chain DRT state.",
    security(("bearer_auth" = [])),
    params(
        ("pool_pda" = String, Path, description = "Pool PDA address (base58)"),
    ),
    responses(
        (status = 200, description = "Pool summary", body = PoolSummaryResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Pool not found"),
    )
)]
pub async fn pool_summary(
    caller: Caller,
    State(state): State<AppState>,
    Path(pool_pda_str): Path<String>,
) -> Result<Json<PoolSummaryResponse>, ApiError> {
    caller.require(Permission::PoolsRead)?;
    let pool_pda = parse_pda(&pool_pda_str)?;
    let doc = load_pool(&state, &pool_pda_str).await?;
    let pool = fetch_pool(state.solana_client.rpc(), &pool_pda).await?;

    // `remaining_supply` is a best-effort RPC lookup that falls back to the
    // recorded supply.
    let mut drts: Vec<DrtConfigResponseCompact> = Vec::with_capacity(doc.drts.len());
    for (name, d) in doc.drts.iter() {
        let remaining_supply = match Pubkey::from_str(&d.mint) {
            Ok(mint_pk) => match state.solana_client.rpc().get_token_supply(&mint_pk).await {
                Ok(amt) => amt.amount.parse::<u64>().unwrap_or(d.supply),
                Err(_) => d.supply,
            },
            Err(_) => d.supply,
        };
        drts.push(DrtConfigResponseCompact {
            drt_type: name.clone(),
            supply: d.supply,
            remaining_supply,
            mint: d.mint.clone(),
        });
    }

    let totals = doc.totals();
    Ok(Json(PoolSummaryResponse {
        state: doc.state().as_str().to_string(),
        initialized_at: doc.initial.as_ref().map(|u| u.uploaded_at.to_rfc3339()),
        pool_pda: pool_pda_str,
        pool_name: doc.pool_name,
        owner: pool.owner.to_string(),
        schema_id: doc.schema_id,
        validation_mode: doc.validation_mode,
        total_rows: totals.rows,
        revoked_count: totals.revoked,
        created_at: doc.created_at.to_rfc3339(),
        created_by: doc.created_by,
        creation_signature: doc.creation_signature,
        last_issue_at: totals.last_issue_at.map(|d| d.to_rfc3339()),
        drts,
    }))
}

fn list_entry(doc: &PoolDoc) -> PoolListEntry {
    let totals = doc.totals();
    PoolListEntry {
        pool_pda: doc.pool_pda.clone(),
        pool_name: doc.pool_name.clone(),
        total_rows: totals.rows,
        revoked_count: totals.revoked,
        schema_id: doc.schema_id.clone(),
        state: doc.state().as_str().to_string(),
        created_at: doc.created_at.to_rfc3339(),
    }
}

/// List pools owned by a specific wallet.
#[utoipa::path(
    get,
    path = "/v1/drt/pools/by-wallet/{wallet_id}",
    tag = "Credentials",
    summary = "List pools by wallet",
    description = "List the pools a wallet owns, in pool PDA order, one cursor page at a time. The caller must own the wallet.",
    security(("bearer_auth" = [])),
    params(
        ("wallet_id" = String, Path, description = "Wallet UUID"),
        CursorQuery,
    ),
    responses(
        (status = 200, description = "Pool list", body = PoolsByWalletResponse),
        (status = 400, description = "Invalid cursor"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Not wallet owner"),
    )
)]
pub async fn list_pools_by_wallet(
    caller: Caller,
    State(state): State<AppState>,
    Path(wallet_id): Path<String>,
    Query(query): Query<CursorQuery>,
) -> Result<Json<PoolsByWalletResponse>, ApiError> {
    caller.require(Permission::PoolsRead)?;
    // Verify wallet ownership.
    let wallet = super::load_wallet(&state, &wallet_id).await?;
    super::enforce_owner(&wallet, &caller.user_id)?;

    let owned: Vec<PoolDoc> = state
        .storage
        .pools()
        .all()
        .await?
        .into_iter()
        .filter(|p| p.owner_wallet_id == wallet_id)
        .collect();
    let (items, next_cursor) = page(
        owned,
        |p| &p.pool_pda,
        query.cursor.as_deref(),
        query.clamped_limit(),
    )?;

    Ok(Json(PoolsByWalletResponse {
        wallet_id,
        pools: items.iter().map(list_entry).collect(),
        next_cursor,
    }))
}

/// List all pools managed by the worker (marketplace discovery).
///
/// Filters, searches and sorts every pool, then returns one cursor page.
/// Accessible by any authenticated user.
#[utoipa::path(
    get,
    path = "/v1/drt/pools/list",
    tag = "Credentials",
    summary = "List all pools",
    description = "Browse all credential pools. Supports filtering by state, search by name, sorting, and cursor pagination.",
    security(("bearer_auth" = [])),
    params(ListAllPoolsQuery),
    responses(
        (status = 200, description = "Pool list", body = AllPoolsResponse),
        (status = 400, description = "Invalid cursor"),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn list_all_pools(
    _caller: Caller,
    State(state): State<AppState>,
    Query(query): Query<ListAllPoolsQuery>,
) -> Result<Json<AllPoolsResponse>, ApiError> {
    let search = query.search.as_deref().map(str::to_lowercase);
    let mut entries: Vec<MarketplacePoolEntry> = Vec::new();
    for doc in state.storage.pools().all().await? {
        let state_str = doc.state().as_str();
        if query.state.as_deref().is_some_and(|s| s != state_str) {
            continue;
        }
        if search
            .as_deref()
            .is_some_and(|s| !doc.pool_name.to_lowercase().contains(s))
        {
            continue;
        }

        let totals = doc.totals();
        // `remaining_supply == supply` keeps this listing off the RPC; the
        // per-pool summary looks up the live remaining supply.
        let pool_drts: Vec<MarketplaceDrtEntry> = doc
            .drts
            .iter()
            .map(|(name, d)| MarketplaceDrtEntry {
                drt_type: name.clone(),
                supply: d.supply,
                remaining_supply: d.supply,
            })
            .collect();
        entries.push(MarketplacePoolEntry {
            kind: doc.kind.as_str().to_string(),
            owner: doc.owner_pubkey.clone(),
            state: state_str.to_string(),
            total_rows: totals.rows,
            revoked_count: totals.revoked,
            created_at: doc.created_at.to_rfc3339(),
            drt_count: pool_drts.len(),
            drts: pool_drts,
            pool_pda: doc.pool_pda,
            pool_name: doc.pool_name,
            schema_id: doc.schema_id,
        });
    }

    // Sort, with the PDA as a tiebreaker so pages are stable.
    match query.sort.as_str() {
        "created_asc" => entries.sort_by(|a, b| {
            (a.created_at.as_str(), a.pool_pda.as_str()).cmp(&(&b.created_at, &b.pool_pda))
        }),
        "name_asc" => entries.sort_by(|a, b| {
            (a.pool_name.to_lowercase(), &a.pool_pda)
                .cmp(&(b.pool_name.to_lowercase(), &b.pool_pda))
        }),
        "credentials_desc" => entries.sort_by(|a, b| {
            (std::cmp::Reverse(a.total_rows), &a.pool_pda)
                .cmp(&(std::cmp::Reverse(b.total_rows), &b.pool_pda))
        }),
        _ => entries.sort_by(|a, b| {
            (b.created_at.as_str(), b.pool_pda.as_str()).cmp(&(&a.created_at, &a.pool_pda))
        }),
    }

    // The cursor names the last pool of the previous page.
    let (pools, next_cursor) = page(
        entries,
        |e| &e.pool_pda,
        query.cursor.as_deref(),
        query.limit.clamp(1, 100),
    )?;

    Ok(Json(AllPoolsResponse { pools, next_cursor }))
}

/// List per-issuance records for a pool (issuance log).
#[utoipa::path(
    get,
    path = "/v1/drt/pools/{pool_pda}/issuance-log",
    tag = "Credentials",
    summary = "Pool issuance log",
    description = "A pool's uploads (initialisation and issuances, with each burn's signature), newest first, one cursor page at a time. Admin only.",
    security(("bearer_auth" = [])),
    params(
        ("pool_pda" = String, Path, description = "Pool PDA address (base58)"),
        CursorQuery,
    ),
    responses(
        (status = 200, description = "Issuance log", body = IssuanceLogResponse),
        (status = 400, description = "Invalid cursor"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Pool not found"),
    )
)]
pub async fn get_issuance_log(
    caller: Caller,
    State(state): State<AppState>,
    Path(pool_pda_str): Path<String>,
    Query(query): Query<CursorQuery>,
) -> Result<Json<IssuanceLogResponse>, ApiError> {
    // Anyone who may read pools can view the issuance log (no ownership check).
    caller.require(Permission::PoolsRead)?;
    let doc = load_pool(&state, &pool_pda_str).await?;
    let newest_first: Vec<Upload> = doc.uploads().rev().cloned().collect();
    let (items, next_cursor) = page(
        newest_first,
        |u| &u.record_id,
        query.cursor.as_deref(),
        query.clamped_limit(),
    )?;

    Ok(Json(IssuanceLogResponse {
        pool_pda: pool_pda_str,
        records: items
            .into_iter()
            .map(|u| IssuanceRecord {
                record_id: u.record_id,
                uploaded_by: u.uploaded_by,
                rows: u.rows,
                uploaded_at: u.uploaded_at.to_rfc3339(),
                redeem_tx_signature: u.signature,
            })
            .collect(),
        next_cursor,
    }))
}
