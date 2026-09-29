// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Credential issuance, revocation, and pool discovery endpoints.
//!
//! - `POST /v1/drt/pools/{pool_pda}/initialize` — seed initial dataset
//! - `POST /v1/drt/pools/{pool_pda}/issue`      — issue credentials (append-DRT gated)
//! - `POST /v1/drt/pools/{pool_pda}/revoke`     — revoke credential(s)
//! - `GET  /v1/drt/pools/{pool_pda}/revocations` — list revocations
//! - `GET  /v1/drt/pools/{pool_pda}/audit`      — pool-scoped audit log
//! - `GET  /v1/drt/pools/{pool_pda}/summary`    — pool metadata + on-chain state
//! - `GET  /v1/drt/pools/by-wallet/{wallet_id}` — list pools owned by wallet
//! - `GET  /v1/drt/pools/list`                  — list all pools (marketplace discovery)
//! - `GET  /v1/drt/pools/{pool_pda}/issuance-log` — list per-issuance records
//!
//! Lists page with signed cursors: pass `next_cursor` back as `cursor`.

use axum::{
    extract::{Multipart, Path, Query, State},
    Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use std::str::FromStr;
use tracing::{info, warn};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::auth::AdminToken;
use crate::blockchain::drt::{
    accounts::fetch_pool,
    instructions::build_grant_right,
    pda::{compute_commitment, derive_drt_config_pda, derive_user_ata},
    types::APPEND_DRT_NAME,
};
use crate::error::ApiError;
use crate::handlers::{parse_csv_payload, validate_payload};
use crate::state::AppState;
use crate::storage::audit::{AuditEvent, AuditEventType, AuditEventView, AuditFilter};
use crate::storage::pools::{Change, PoolKind, PoolMetadata, PoolState};
use crate::storage::records::{RecordMeta, RecordStatus, StageOutcome};
use crate::storage::store::Continuation;
use crate::tee::KeyName;
use sha2::{Digest, Sha256};

use super::pools::{
    load_pool_meta, load_wallet_keypair, sign_send_and_parse, verify_pool_ownership,
};
use super::CursorQuery;

/// A staged initialisation younger than this is assumed to be in progress.
const STAGED_INIT_TIMEOUT: chrono::Duration = chrono::Duration::minutes(10);

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
    /// Credential record IDs to revoke (UUIDs from `/issue` responses).
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

/// Pool-scoped audit query parameters.
#[derive(Debug, Deserialize, IntoParams)]
pub struct PoolAuditQuery {
    /// Maximum number of events to return (default 50, max 200).
    #[serde(default = "default_limit")]
    pub limit: usize,
    /// `next_cursor` from the previous page, with the same filters.
    #[serde(default)]
    pub cursor: Option<String>,
    /// Filter to events of this type (snake_case, e.g. `credential_issued`).
    /// Repeatable via comma-separated values (e.g. `pool_created,credential_issued`).
    #[serde(default)]
    pub event_type: Option<String>,
    /// Filter to events with `user_id` equal to this (exact match).
    #[serde(default)]
    pub actor: Option<String>,
    /// Filter to `success=true` (`ok`) or `success=false` (`failed`).
    /// Anything else (empty / missing) returns both.
    #[serde(default)]
    pub status: Option<String>,
    /// Inclusive RFC-3339 lower bound on `timestamp`.
    #[serde(default)]
    pub from: Option<String>,
    /// Inclusive RFC-3339 upper bound on `timestamp`.
    #[serde(default)]
    pub to: Option<String>,
}

fn default_limit() -> usize {
    50
}

/// One page of a pool's audit events, newest first.
#[derive(Debug, Serialize, ToSchema)]
pub struct PoolAuditResponse {
    pub pool_pda: String,
    pub events: Vec<AuditEventView>,
    /// Present when there's another page; pass it as `cursor`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initialized_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_issue_at: Option<String>,
    /// On-chain DRT configuration.
    pub drts: Vec<DrtConfigResponseCompact>,
    /// Recent audit events (last 10).
    pub recent_events: Vec<AuditEventView>,
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

/// Single issuance record in the issuance log.
#[derive(Debug, Serialize, ToSchema)]
pub struct IssuanceRecord {
    pub record_id: String,
    pub uploaded_by: String,
    pub rows: u64,
    pub uploaded_at: String,
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

/// Committed datasets stay immutable for this long.
fn retain_until() -> chrono::DateTime<Utc> {
    Utc::now() + chrono::Duration::days(crate::config::DATASET_RETENTION_DAYS)
}

/// A pool's totals, computed from its committed records and revocations.
struct PoolTotals {
    rows: u64,
    revoked: u64,
    last_issue_at: Option<chrono::DateTime<Utc>>,
}

async fn pool_totals(state: &AppState, pool_pda: &str) -> Result<PoolTotals, ApiError> {
    let records = state.storage.records().totals(pool_pda).await?;
    Ok(PoolTotals {
        rows: records.rows,
        revoked: state.storage.revocations().count(pool_pda).await?,
        last_issue_at: records.last_issue_at,
    })
}

fn kind_str(kind: PoolKind) -> &'static str {
    match kind {
        PoolKind::Malta => "malta",
    }
}

fn validation_failed(errors: usize) -> ApiError {
    ApiError::bad_request(format!("CSV validation failed: {errors} error(s)"))
        .with_code("validation_failed")
}

fn initialization_in_progress() -> ApiError {
    ApiError::conflict("pool initialization is already in progress — retry shortly")
        .with_code("initialization_in_progress")
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
    ),
    request_body = UploadSchemaRequest,
    responses(
        (status = 200, description = "Schema saved", body = UploadSchemaResponse),
        (status = 400, description = "Invalid schema"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Not pool owner"),
        (status = 404, description = "Pool not found"),
        (status = 409, description = "The pool changed concurrently; retry"),
    )
)]
pub async fn upload_schema(
    AdminToken(token): AdminToken,
    State(state): State<AppState>,
    Path(pool_pda_str): Path<String>,
    Json(payload): Json<UploadSchemaRequest>,
) -> Result<Json<UploadSchemaResponse>, ApiError> {
    // Validate the pool PDA format.
    let pool_pda = Pubkey::from_str(&pool_pda_str)
        .map_err(|_| ApiError::bad_request("invalid pool PDA address"))?;

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
    let wallet = super::get_active_wallet_for_user(&state, &token.sub).await?;
    verify_pool_ownership(&pool, &wallet)?;

    let fields_json = serde_json::to_value(&payload.fields)?;
    state
        .storage
        .pools()
        .update(&pool_pda_str, |meta| {
            if meta.schema_id != payload.schema_id {
                return Err(ApiError::bad_request(format!(
                    "pool's schema_id is '{}', but you are uploading '{}'",
                    meta.schema_id, payload.schema_id
                )));
            }
            if serde_json::to_value(&meta.schema).ok().as_ref() == Some(&fields_json) {
                return Ok(Change::Unchanged);
            }
            meta.schema = payload.fields.clone();
            Ok(Change::Changed)
        })
        .await?
        .ok_or_else(|| {
            ApiError::not_found(format!("pool metadata not found for {pool_pda_str}"))
        })?;

    let field_count = payload.fields.len();
    info!(
        pool = %pool_pda_str,
        schema_id = %payload.schema_id,
        fields = field_count,
        "Schema uploaded and persisted"
    );

    let audit_event = AuditEvent::new(AuditEventType::SchemaUploaded)
        .with_user(&token.sub)
        .with_resource("schema", &payload.schema_id)
        .with_pool_pda(&pool_pda_str)
        .with_details(serde_json::json!({
            "pool_pda": pool_pda_str,
            "schema_id": payload.schema_id,
            "field_count": field_count,
        }));
    state.storage.audit().log(audit_event).await;

    Ok(Json(UploadSchemaResponse {
        schema_id: payload.schema_id,
        field_count,
    }))
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
    crate::auth::AnalystToken(_token): crate::auth::AnalystToken,
    State(state): State<AppState>,
    Path(pool_pda_str): Path<String>,
) -> Result<Json<GetSchemaResponse>, ApiError> {
    let meta = load_pool_meta(&state, &pool_pda_str).await?;
    if meta.schema.is_empty() {
        return Err(ApiError::not_found(format!(
            "no schema uploaded yet for pool {pool_pda_str} — POST one to /v1/drt/pools/{{pda}}/schema"
        )));
    }

    Ok(Json(GetSchemaResponse {
        pool_pda: pool_pda_str,
        schema_id: meta.schema_id,
        fields: meta.schema,
    }))
}

/// Seed the initial dataset for a pool.
///
/// The pool must be in `needs_init` state. No append DRT is required —
/// this is the initial seeding by the pool creator. The dataset is staged,
/// committed, and then the pool moves to `ready`; a retry after an
/// interruption finishes the job.
#[utoipa::path(
    post,
    path = "/v1/drt/pools/{pool_pda}/initialize",
    tag = "Credentials",
    summary = "Initialize pool dataset",
    description = "Seed the initial credential dataset for a pool. Requires the pool to be in `needs_init` state. No DRT required — only the pool creator can call this.",
    security(("bearer_auth" = [])),
    params(
        ("pool_pda" = String, Path, description = "Pool PDA address (base58)"),
    ),
    responses(
        (status = 200, description = "Dataset initialized", body = InitializePoolResponse),
        (status = 400, description = "Validation error or pool already initialized"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Not pool owner"),
        (status = 404, description = "Pool not found"),
        (status = 409, description = "Initialization in progress, or a different initial dataset is already stored"),
    )
)]
pub async fn initialize_pool(
    AdminToken(token): AdminToken,
    State(state): State<AppState>,
    Path(pool_pda_str): Path<String>,
    multipart: Multipart,
) -> Result<Json<InitializePoolResponse>, ApiError> {
    // Parse and decrypt the CSV payload.
    let parsed = parse_csv_payload(state.keys.get(KeyName::Transport), multipart).await?;

    // Validate the pool PDA format.
    let pool_pda = Pubkey::from_str(&pool_pda_str)
        .map_err(|_| ApiError::bad_request("invalid pool PDA address"))?;

    // Fetch on-chain pool to verify it exists and get ownership.
    let pool = fetch_pool(state.solana_client.rpc(), &pool_pda).await?;
    let wallet = super::get_active_wallet_for_user(&state, &token.sub).await?;
    verify_pool_ownership(&pool, &wallet)?;

    let meta = load_pool_meta(&state, &pool_pda_str).await?;
    if meta.state != PoolState::NeedsInit {
        return Err(ApiError::bad_request(
            "pool is already initialized — use /issue to add credentials",
        ));
    }

    // Validate CSV against the pool's schema.
    let summary = validate_payload(
        &meta.schema,
        &pool_pda_str,
        &parsed.csv_bytes,
        meta.validation_mode,
    )?;
    if !summary.valid {
        return Err(validation_failed(summary.errors.len()));
    }

    let record = RecordMeta {
        record_id: "initial".to_string(),
        sha256: sha256_hex(&parsed.csv_bytes),
        rows: count_csv_rows(&parsed.csv_bytes),
        uploaded_by: token.sub.clone(),
        uploaded_at: Utc::now(),
        status: RecordStatus::Staged,
        redeem_tx_signature: None,
        commitment: None,
        committed_at: None,
    };

    // One `initial` record per pool: stage it, or finish the one an
    // interrupted request left behind.
    let records = state.storage.records();
    let mut outcome = records
        .stage(&pool_pda_str, record.clone(), &parsed.csv_bytes)
        .await?;
    if let StageOutcome::Exists(existing) = &outcome {
        if existing.status == RecordStatus::Staged {
            if Utc::now() - existing.uploaded_at < STAGED_INIT_TIMEOUT {
                return Err(initialization_in_progress());
            }
            warn!(pool = %pool_pda_str, "Discarding an abandoned initialization");
            records.discard_abandoned(&pool_pda_str, "initial").await?;
            outcome = records
                .stage(&pool_pda_str, record.clone(), &parsed.csv_bytes)
                .await?;
        }
    }
    let committed = match outcome {
        StageOutcome::Staged(staged) => {
            records
                .commit(&pool_pda_str, staged, None, None, retain_until())
                .await?
        }
        StageOutcome::Exists(existing) if existing.status == RecordStatus::Committed => existing,
        StageOutcome::Exists(_) => return Err(initialization_in_progress()),
    };

    // Move the pool to ready.
    let now = Utc::now();
    let mut transitioned = false;
    state
        .storage
        .pools()
        .update::<ApiError>(&pool_pda_str, |m| {
            if m.state == PoolState::Ready {
                return Ok(Change::Unchanged);
            }
            m.state = PoolState::Ready;
            m.initialized_at = Some(now);
            transitioned = true;
            Ok(Change::Changed)
        })
        .await?
        .ok_or_else(|| {
            ApiError::not_found(format!("pool metadata not found for {pool_pda_str}"))
        })?;

    if committed.sha256 != record.sha256 {
        return Err(ApiError::conflict(
            "an earlier request already stored a different initial dataset for this pool",
        ));
    }

    if transitioned {
        let audit_event = AuditEvent::new(AuditEventType::DatasetInitialized)
            .with_user(&token.sub)
            .with_resource("drt_pool", &pool_pda_str)
            .with_pool_pda(&pool_pda_str)
            .with_details(serde_json::json!({
                "pool_pda": pool_pda_str,
                "record_id": committed.record_id,
                "row_count": committed.rows,
                "schema_id": meta.schema_id,
                "state_transition": "needs_init -> ready"
            }));
        state.storage.audit().log(audit_event).await;
    }

    info!(
        pool = %pool_pda_str,
        rows = committed.rows,
        schema = %meta.schema_id,
        "Pool dataset initialized"
    );

    Ok(Json(InitializePoolResponse {
        rows: committed.rows,
        record_id: committed.record_id,
        state: PoolState::Ready.as_str().to_string(),
    }))
}

/// Issue credentials to a pool (append-DRT gated).
///
/// Stages the dataset, burns 1 append DRT on-chain, then commits the record.
/// If the burn never reached the chain the staged dataset is removed; if it
/// did but wasn't confirmed, the record stays staged for reconciliation.
#[utoipa::path(
    post,
    path = "/v1/drt/pools/{pool_pda}/issue",
    tag = "Credentials",
    summary = "Issue credentials",
    description = "Issue credentials by redeeming an append DRT and storing the encrypted CSV data. Validates ownership, DRT balance and the CSV schema, stages the dataset, burns 1 append DRT, then commits the record.",
    security(("bearer_auth" = [])),
    params(
        ("pool_pda" = String, Path, description = "Pool PDA address (base58)"),
    ),
    responses(
        (status = 200, description = "Credentials issued", body = IssueCredentialsResponse),
        (status = 400, description = "Validation error or insufficient DRTs"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Pool not found"),
        (status = 503, description = "Solana RPC unavailable"),
    )
)]
pub async fn issue_credentials(
    AdminToken(token): AdminToken,
    State(state): State<AppState>,
    Path(pool_pda_str): Path<String>,
    multipart: Multipart,
) -> Result<Json<IssueCredentialsResponse>, ApiError> {
    // ── VALIDATION (reversible, cheap) ────────────────────────────

    // Parse and decrypt the CSV payload.
    let parsed = parse_csv_payload(state.keys.get(KeyName::Transport), multipart).await?;

    let pool_pda = Pubkey::from_str(&pool_pda_str)
        .map_err(|_| ApiError::bad_request("invalid pool PDA address"))?;

    // Load pool metadata — must be in Ready state.
    let meta = load_pool_meta(&state, &pool_pda_str).await?;
    if meta.state != PoolState::Ready {
        return Err(ApiError::bad_request(
            "pool not initialized — call /initialize first",
        ));
    }

    // The append DRT's right_id and mint are only in the pool's metadata.
    let append_meta = meta
        .drts
        .get(APPEND_DRT_NAME)
        .ok_or_else(|| ApiError::internal("pool metadata missing 'append' DRT"))?;
    let append_right_id = decode_right_id(&append_meta.right_id_hex)?;
    let append_mint = Pubkey::from_str(&append_meta.mint)
        .map_err(|_| ApiError::internal("invalid mint pubkey in pool metadata"))?;
    let (drt_config_pda, _) = derive_drt_config_pda(&pool_pda, &append_right_id);

    // Decode the pool uuid for the commitment hash.
    let pool_uuid = decode_right_id(&meta.pool_uuid_hex)?;

    // Load caller's wallet (admin only — endpoint is `AdminToken`-gated).
    let caller_wallet = super::get_active_wallet_for_user(&state, &token.sub).await?;
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

    // Check the admin holds ≥1 append DRT.
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

    // Validate CSV against pool's schema.
    let summary = validate_payload(
        &meta.schema,
        &pool_pda_str,
        &parsed.csv_bytes,
        meta.validation_mode,
    )?;
    if !summary.valid {
        return Err(validation_failed(summary.errors.len()));
    }

    let row_count = count_csv_rows(&parsed.csv_bytes);

    // ── STAGE ─────────────────────────────────────────────────────

    // The commitment is unique per upload (record_id || pool_uuid ||
    // append_right_id), and its Grant PDA is the on-chain receipt.
    let record_id = Uuid::new_v4().to_string();
    let commitment = compute_commitment(&record_id, &pool_uuid, &append_right_id);
    let records = state.storage.records();
    let staged = match records
        .stage(
            &pool_pda_str,
            RecordMeta {
                record_id: record_id.clone(),
                sha256: sha256_hex(&parsed.csv_bytes),
                rows: row_count,
                uploaded_by: token.sub.clone(),
                uploaded_at: Utc::now(),
                status: RecordStatus::Staged,
                redeem_tx_signature: None,
                commitment: None,
                committed_at: None,
            },
            &parsed.csv_bytes,
        )
        .await?
    {
        StageOutcome::Staged(staged) => staged,
        StageOutcome::Exists(_) => return Err(ApiError::internal("record ID collision")),
    };

    // ── BURN (irreversible) ───────────────────────────────────────

    let ix = build_grant_right(
        &pool_pda,
        &drt_config_pda,
        &append_mint,
        &keypair.pubkey(),
        &commitment,
    );
    let (sig_str, events) = match sign_send_and_parse(&state, &keypair, vec![ix], "finalized").await
    {
        Ok(result) => result,
        Err(failure) => {
            match &failure.sent {
                // Nothing reached the chain, so no DRT was burned.
                None => {
                    if let Err(e) = records.discard(&pool_pda_str, &staged).await {
                        warn!(pool = %pool_pda_str, record_id = %record_id, error = %e,
                                "Couldn't discard a staged record");
                    }
                }
                Some(sig) => warn!(pool = %pool_pda_str, record_id = %record_id, sig = %sig,
                        "Append-DRT burn sent but not confirmed; the record stays staged for reconciliation"),
            }
            return Err(failure.error);
        }
    };

    let chain = |meta: &PoolMetadata| {
        let mut extra = serde_json::Map::new();
        extra.insert(
            hex::encode(commitment),
            serde_json::Value::String(format!("upload {record_id}")),
        );
        crate::api::pools::chain_section(
            std::slice::from_ref(&sig_str),
            &events,
            crate::api::pools::pool_labels(meta, Some(extra)),
        )
    };

    // ── COMMIT ────────────────────────────────────────────────────

    if let Err(e) = records
        .commit(
            &pool_pda_str,
            staged,
            Some(sig_str.clone()),
            Some(hex::encode(commitment)),
            retain_until(),
        )
        .await
    {
        warn!(pool = %pool_pda_str, record_id = %record_id, redeem_sig = %sig_str, error = %e,
            "DRT burned but the record couldn't be committed");
        let mut fail_event = AuditEvent::new(AuditEventType::CredentialIssuanceFailed)
            .with_user(&token.sub)
            .with_resource("drt_pool", &pool_pda_str)
            .with_pool_pda(&pool_pda_str)
            .with_details(serde_json::json!({
                "pool_pda": pool_pda_str,
                "record_id": record_id,
                "redeem_tx_sig": sig_str,
                "error": e.to_string(),
                "chain": chain(&meta),
            }));
        fail_event.success = false;
        state.storage.audit().log(fail_event).await;
        return Err(ApiError::internal(format!(
            "the append DRT was burned (sig: {sig_str}) but the record couldn't be committed; it stays staged for reconciliation"
        )));
    }

    let totals = pool_totals(&state, &pool_pda_str).await?;

    let audit_event = AuditEvent::new(AuditEventType::CredentialIssued)
        .with_user(&token.sub)
        .with_resource("drt_pool", &pool_pda_str)
        .with_pool_pda(&pool_pda_str)
        .with_details(serde_json::json!({
            "pool_pda": pool_pda_str,
            "record_id": record_id,
            "row_count": row_count,
            "redeem_tx_sig": sig_str,
            "total_credentials": totals.rows,
            "chain": chain(&meta),
        }));
    state.storage.audit().log(audit_event).await;

    let explorer_url = state.solana_client.network().explorer_tx_url(&sig_str);

    info!(
        pool = %pool_pda_str,
        record_id = %record_id,
        rows = row_count,
        redeem_sig = %sig_str,
        total = totals.rows,
        "Credentials issued"
    );

    Ok(Json(IssueCredentialsResponse {
        record_id,
        rows_issued: row_count,
        redeem_signature: sig_str,
        total_rows: totals.rows,
        explorer_url,
    }))
}

/// Revoke credential(s) from a pool.
///
/// Each revocation is appended to the pool's revocation log, then indexed.
/// Revoking an already revoked credential changes nothing.
#[utoipa::path(
    post,
    path = "/v1/drt/pools/{pool_pda}/revoke",
    tag = "Credentials",
    summary = "Revoke credentials",
    description = "Revoke one or more credentials by record ID. Revocations go to the pool's append-only revocation log. Admin only.",
    security(("bearer_auth" = [])),
    params(
        ("pool_pda" = String, Path, description = "Pool PDA address (base58)"),
    ),
    request_body = RevokeCredentialsRequest,
    responses(
        (status = 200, description = "Credentials revoked", body = RevokeCredentialsResponse),
        (status = 400, description = "Validation error"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Not pool owner"),
        (status = 404, description = "Pool or credential not found"),
    )
)]
pub async fn revoke_credentials(
    AdminToken(token): AdminToken,
    State(state): State<AppState>,
    Path(pool_pda_str): Path<String>,
    Json(payload): Json<RevokeCredentialsRequest>,
) -> Result<Json<RevokeCredentialsResponse>, ApiError> {
    if payload.credential_ids.is_empty() {
        return Err(ApiError::bad_request("credential_ids must not be empty"));
    }

    let pool_pda = Pubkey::from_str(&pool_pda_str)
        .map_err(|_| ApiError::bad_request("invalid pool PDA address"))?;

    // Verify ownership.
    let (wallet, _) = load_wallet_keypair(&state, &payload.wallet_id, &token.sub).await?;
    let pool = fetch_pool(state.solana_client.rpc(), &pool_pda).await?;
    verify_pool_ownership(&pool, &wallet)?;
    load_pool_meta(&state, &pool_pda_str).await?;

    let mut credential_ids: Vec<String> = Vec::with_capacity(payload.credential_ids.len());
    for cid in &payload.credential_ids {
        if !credential_ids.contains(cid) {
            credential_ids.push(cid.clone());
        }
    }

    // Every credential must be a committed record of this pool.
    for cid in &credential_ids {
        match state.storage.records().get(&pool_pda_str, cid).await? {
            Some(record) if record.status == RecordStatus::Committed => {}
            _ => {
                return Err(ApiError::not_found(format!(
                    "credential record '{cid}' not found in pool"
                )))
            }
        }
    }

    let mut newly_revoked = 0;
    for cid in &credential_ids {
        if state
            .storage
            .revocations()
            .revoke(&pool_pda_str, cid, &token.sub, payload.reason.as_deref())
            .await?
        {
            newly_revoked += 1;
        }
    }

    let audit_event = AuditEvent::new(AuditEventType::CredentialRevoked)
        .with_user(&token.sub)
        .with_resource("drt_pool", &pool_pda_str)
        .with_pool_pda(&pool_pda_str)
        .with_details(serde_json::json!({
            "pool_pda": pool_pda_str,
            "credential_ids": credential_ids,
            "revoked_count": newly_revoked,
            "reason": payload.reason
        }));
    state.storage.audit().log(audit_event).await;

    info!(
        pool = %pool_pda_str,
        count = credential_ids.len(),
        newly_revoked,
        "Credentials revoked"
    );

    Ok(Json(RevokeCredentialsResponse {
        revoked: credential_ids.len(),
    }))
}

/// List revocation entries for a pool.
#[utoipa::path(
    get,
    path = "/v1/drt/pools/{pool_pda}/revocations",
    tag = "Credentials",
    summary = "List revocations",
    description = "List a pool's revocations, one cursor page at a time. Admin only.",
    security(("bearer_auth" = [])),
    params(
        ("pool_pda" = String, Path, description = "Pool PDA address (base58)"),
        CursorQuery,
    ),
    responses(
        (status = 200, description = "Revocation list", body = RevocationsResponse),
        (status = 400, description = "Invalid cursor"),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn list_revocations(
    AdminToken(_token): AdminToken,
    State(state): State<AppState>,
    Path(pool_pda_str): Path<String>,
    Query(query): Query<CursorQuery>,
) -> Result<Json<RevocationsResponse>, ApiError> {
    // Any admin can view revocations (no ownership check).
    let scope = format!("revocations:{pool_pda_str}");
    let page = state.storage.page_from(&scope, query.cursor.as_deref())?;
    let got = state
        .storage
        .revocations()
        .list(&pool_pda_str, query.clamped_limit(), page)
        .await?;

    Ok(Json(RevocationsResponse {
        pool_pda: pool_pda_str,
        revocations: got
            .items
            .into_iter()
            .map(|r| RevocationEntry {
                credential_id: r.credential_id,
                revoked_by: r.revoked_by,
                revoked_at: r.revoked_at.to_rfc3339(),
                reason: r.reason,
            })
            .collect(),
        next_cursor: got
            .next
            .map(|next| state.storage.sign_cursor(&scope, &next)),
    }))
}

/// Query pool-scoped audit events.
///
/// Reads the pool's audit index, newest first, verifying every event.
/// Filters apply in storage; `cursor` continues a previous page.
#[utoipa::path(
    get,
    path = "/v1/drt/pools/{pool_pda}/audit",
    tag = "Credentials",
    summary = "Pool audit log",
    description = "Audit events for one pool, newest first, one cursor page at a time. Every event is verified; `hmac_valid: false` marks one that failed. Admin only.",
    security(("bearer_auth" = [])),
    params(
        ("pool_pda" = String, Path, description = "Pool PDA address (base58)"),
        PoolAuditQuery,
    ),
    responses(
        (status = 200, description = "Audit events", body = PoolAuditResponse),
        (status = 400, description = "Invalid filter or cursor"),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn pool_audit(
    crate::auth::AnalystToken(_token): crate::auth::AnalystToken,
    State(state): State<AppState>,
    Path(pool_pda_str): Path<String>,
    Query(query): Query<PoolAuditQuery>,
) -> Result<Json<PoolAuditResponse>, ApiError> {
    // Any admin can view audit events (no ownership check).
    let time = |value: &Option<String>, name: &str| {
        value
            .as_deref()
            .map(|s| {
                chrono::DateTime::parse_from_rfc3339(s)
                    .map(|d| d.with_timezone(&Utc))
                    .map_err(|_| ApiError::bad_request(format!("{name} must be an RFC 3339 time")))
            })
            .transpose()
    };
    let filter = AuditFilter {
        event_types: query
            .event_type
            .as_deref()
            .map(|s| {
                s.split(',')
                    .map(str::trim)
                    .filter(|t| !t.is_empty())
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default(),
        actor: query.actor.clone().filter(|a| !a.is_empty()),
        success: match query.status.as_deref() {
            Some("ok" | "success") => Some(true),
            Some("failed" | "error") => Some(false),
            _ => None,
        },
        from: time(&query.from, "from")?,
        to: time(&query.to, "to")?,
    };

    // The cursor is bound to the pool and the filters it was issued for.
    let scope = format!(
        "audit:{pool_pda_str}:{}:{}:{}:{}:{}",
        query.event_type.as_deref().unwrap_or(""),
        query.actor.as_deref().unwrap_or(""),
        query.status.as_deref().unwrap_or(""),
        query.from.as_deref().unwrap_or(""),
        query.to.as_deref().unwrap_or(""),
    );
    let page = state.storage.page_from(&scope, query.cursor.as_deref())?;
    let got = state
        .storage
        .audit()
        .pool_events(&pool_pda_str, &filter, query.limit.clamp(1, 200), page)
        .await?;

    Ok(Json(PoolAuditResponse {
        pool_pda: pool_pda_str,
        events: got.items,
        next_cursor: got
            .next
            .map(|next| state.storage.sign_cursor(&scope, &next)),
    }))
}

/// Get pool summary (enclave metadata + on-chain state + recent events).
#[utoipa::path(
    get,
    path = "/v1/drt/pools/{pool_pda}/summary",
    tag = "Credentials",
    summary = "Pool summary",
    description = "Combined view of pool enclave metadata, on-chain DRT state, and recent audit events.",
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
    crate::auth::AnalystToken(_token): crate::auth::AnalystToken,
    State(state): State<AppState>,
    Path(pool_pda_str): Path<String>,
) -> Result<Json<PoolSummaryResponse>, ApiError> {
    let pool_pda = Pubkey::from_str(&pool_pda_str)
        .map_err(|_| ApiError::bad_request("invalid pool PDA address"))?;

    let meta = load_pool_meta(&state, &pool_pda_str).await?;
    let pool = fetch_pool(state.solana_client.rpc(), &pool_pda).await?;

    // DRT configs live only in the pool's metadata. `remaining_supply` is a
    // best-effort RPC lookup that falls back to the recorded supply.
    let mut drts: Vec<DrtConfigResponseCompact> = Vec::with_capacity(meta.drts.len());
    for (name, d) in meta.drts.iter() {
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

    // The pool's 10 most recent audit events.
    let recent_events = state
        .storage
        .audit()
        .pool_events(&pool_pda_str, &AuditFilter::default(), 10, None)
        .await?
        .items;
    let totals = pool_totals(&state, &pool_pda_str).await?;

    Ok(Json(PoolSummaryResponse {
        pool_pda: pool_pda_str,
        pool_name: meta.pool_name,
        owner: pool.owner.to_string(),
        schema_id: meta.schema_id,
        validation_mode: meta.validation_mode,
        state: meta.state.as_str().to_string(),
        total_rows: totals.rows,
        revoked_count: totals.revoked,
        created_at: meta.created_onchain_at.to_rfc3339(),
        initialized_at: meta.initialized_at.map(|d| d.to_rfc3339()),
        last_issue_at: totals.last_issue_at.map(|d| d.to_rfc3339()),
        drts,
        recent_events,
    }))
}

/// List pools owned by a specific wallet.
#[utoipa::path(
    get,
    path = "/v1/drt/pools/by-wallet/{wallet_id}",
    tag = "Credentials",
    summary = "List pools by wallet",
    description = "List the pools a wallet owns, one cursor page at a time. The caller must own the wallet.",
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
    crate::auth::UserToken(token): crate::auth::UserToken,
    State(state): State<AppState>,
    Path(wallet_id): Path<String>,
    Query(query): Query<CursorQuery>,
) -> Result<Json<PoolsByWalletResponse>, ApiError> {
    // Verify wallet ownership.
    let wallet = super::load_wallet(&state, &wallet_id).await?;
    super::enforce_owner(&wallet, &token.sub)?;

    let scope = format!("pools-by-wallet:{wallet_id}");
    let page = state.storage.page_from(&scope, query.cursor.as_deref())?;
    let got = state
        .storage
        .pools()
        .owned_by(&wallet_id, query.clamped_limit(), page)
        .await?;

    let mut pools = Vec::with_capacity(got.items.len());
    for meta in got.items {
        let totals = pool_totals(&state, &meta.pool_pda).await?;
        pools.push(PoolListEntry {
            state: meta.state.as_str().to_string(),
            created_at: meta.created_onchain_at.to_rfc3339(),
            pool_pda: meta.pool_pda,
            pool_name: meta.pool_name,
            total_rows: totals.rows,
            revoked_count: totals.revoked,
            schema_id: meta.schema_id,
        });
    }

    Ok(Json(PoolsByWalletResponse {
        wallet_id,
        pools,
        next_cursor: got
            .next
            .map(|next| state.storage.sign_cursor(&scope, &next)),
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
    crate::auth::ReadOnlyToken(_token): crate::auth::ReadOnlyToken,
    State(state): State<AppState>,
    Query(query): Query<ListAllPoolsQuery>,
) -> Result<Json<AllPoolsResponse>, ApiError> {
    let search = query.search.as_deref().map(str::to_lowercase);
    let mut entries: Vec<MarketplacePoolEntry> = Vec::new();
    for meta in state.storage.pools().all().await? {
        let state_str = meta.state.as_str();
        if query.state.as_deref().is_some_and(|s| s != state_str) {
            continue;
        }
        if search
            .as_deref()
            .is_some_and(|s| !meta.pool_name.to_lowercase().contains(s))
        {
            continue;
        }

        let totals = pool_totals(&state, &meta.pool_pda).await?;
        // `remaining_supply == supply` keeps this listing off the RPC; the
        // per-pool summary looks up the live remaining supply.
        let pool_drts: Vec<MarketplaceDrtEntry> = meta
            .drts
            .iter()
            .map(|(name, d)| MarketplaceDrtEntry {
                drt_type: name.clone(),
                supply: d.supply,
                remaining_supply: d.supply,
            })
            .collect();
        entries.push(MarketplacePoolEntry {
            kind: kind_str(meta.kind).to_string(),
            owner: meta
                .owner_pubkey
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
            state: state_str.to_string(),
            total_rows: totals.rows,
            revoked_count: totals.revoked,
            created_at: meta.created_onchain_at.to_rfc3339(),
            drt_count: pool_drts.len(),
            drts: pool_drts,
            pool_pda: meta.pool_pda,
            pool_name: meta.pool_name,
            schema_id: meta.schema_id,
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
    let scope = format!(
        "pools:{}:{}:{}",
        query.state.as_deref().unwrap_or(""),
        query.search.as_deref().unwrap_or(""),
        query.sort
    );
    let start = match state.storage.page_from(&scope, query.cursor.as_deref())? {
        Some(Continuation(last)) => entries
            .iter()
            .position(|e| e.pool_pda == last)
            .map_or(entries.len(), |i| i + 1),
        None => 0,
    };
    let limit = query.limit.clamp(1, 100);
    let end = (start + limit).min(entries.len());
    let next_cursor = (end < entries.len()).then(|| {
        state
            .storage
            .sign_cursor(&scope, &Continuation(entries[end - 1].pool_pda.clone()))
    });
    let pools = entries.drain(start..end).collect();

    Ok(Json(AllPoolsResponse { pools, next_cursor }))
}

/// List per-issuance records for a pool (issuance log).
#[utoipa::path(
    get,
    path = "/v1/drt/pools/{pool_pda}/issuance-log",
    tag = "Credentials",
    summary = "Pool issuance log",
    description = "A pool's committed uploads (initialisation and issuances), newest first, one cursor page at a time. Admin only.",
    security(("bearer_auth" = [])),
    params(
        ("pool_pda" = String, Path, description = "Pool PDA address (base58)"),
        CursorQuery,
    ),
    responses(
        (status = 200, description = "Issuance log", body = IssuanceLogResponse),
        (status = 400, description = "Invalid cursor"),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn get_issuance_log(
    AdminToken(_token): AdminToken,
    State(state): State<AppState>,
    Path(pool_pda_str): Path<String>,
    Query(query): Query<CursorQuery>,
) -> Result<Json<IssuanceLogResponse>, ApiError> {
    // Any admin can view issuance log (no ownership check).
    let scope = format!("issuance-log:{pool_pda_str}");
    let page = state.storage.page_from(&scope, query.cursor.as_deref())?;
    let got = state
        .storage
        .records()
        .log(&pool_pda_str, query.clamped_limit(), page)
        .await?;

    Ok(Json(IssuanceLogResponse {
        pool_pda: pool_pda_str,
        records: got
            .items
            .into_iter()
            .map(|r| IssuanceRecord {
                record_id: r.record_id,
                uploaded_by: r.uploaded_by,
                rows: r.rows,
                uploaded_at: r.uploaded_at.to_rfc3339(),
                redeem_tx_signature: r.redeem_tx_signature,
            })
            .collect(),
        next_cursor: got
            .next
            .map(|next| state.storage.sign_cursor(&scope, &next)),
    }))
}
