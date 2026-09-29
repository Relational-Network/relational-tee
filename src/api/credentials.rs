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
//! - `GET  /v1/drt/pools`                       — list all pools (marketplace discovery)
//! - `GET  /v1/drt/pools/{pool_pda}/issuance-log` — list per-issuance records

use axum::{
    extract::{Multipart, Path, Query, State},
    Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use std::str::FromStr;
use std::sync::Arc;
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
use crate::storage::audit::{AuditEvent, AuditEventType, AuditRepository};
use crate::storage::pool_metadata::{PoolKind, PoolMetadata, PoolState};
use crate::storage::repository::wallets::WalletRepository;
use sha2::{Digest, Sha256};

use super::pools::{load_wallet_keypair, sign_send_and_parse, verify_pool_ownership};

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
    /// Number of credentials revoked.
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

/// Revocation list response.
#[derive(Debug, Serialize, ToSchema)]
pub struct RevocationsResponse {
    pub pool_pda: String,
    pub revocations: Vec<RevocationEntry>,
    pub total: usize,
}

/// Pool-scoped audit query parameters.
#[derive(Debug, Deserialize, IntoParams)]
pub struct PoolAuditQuery {
    /// Maximum number of events to return (default: 50).
    #[serde(default = "default_limit")]
    pub limit: usize,
    /// Offset for pagination (default: 0).
    #[serde(default)]
    pub offset: usize,
    /// Filter to events of this type (snake_case, e.g. `right_granted`).
    /// Repeatable via comma-separated values (e.g. `right_granted,right_revoked`).
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

/// Pool-scoped audit response.
#[derive(Debug, Serialize, ToSchema)]
pub struct PoolAuditResponse {
    pub pool_pda: String,
    pub events: Vec<AuditEvent>,
    pub total: usize,
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
    pub recent_events: Vec<AuditEvent>,
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

/// List pools by wallet response.
#[derive(Debug, Serialize, ToSchema)]
pub struct PoolsByWalletResponse {
    pub wallet_id: String,
    pub pools: Vec<PoolListEntry>,
    pub total: usize,
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

/// Response for listing all pools (marketplace discovery).
#[derive(Debug, Serialize, ToSchema)]
pub struct AllPoolsResponse {
    pub pools: Vec<MarketplacePoolEntry>,
    pub total: u64,
    pub limit: u64,
    pub offset: u64,
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
    #[serde(default = "default_limit_u64")]
    pub limit: u64,
    /// Pagination offset.
    #[serde(default)]
    pub offset: u64,
}

fn default_sort() -> String {
    "created_desc".to_string()
}

fn default_limit_u64() -> u64 {
    50
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

/// Response for the issuance log endpoint.
#[derive(Debug, Serialize, ToSchema)]
pub struct IssuanceLogResponse {
    pub pool_pda: String,
    pub records: Vec<IssuanceRecord>,
    pub total: usize,
}

/// Request body for uploading a schema definition.
#[derive(Debug, Deserialize, ToSchema)]
pub struct UploadSchemaRequest {
    /// Schema ID label (e.g. `"pilot_v1"`). Used to reference this schema in pool metadata.
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

/// Queryable issuance metadata. Persisted **only to redb** (`ISSUANCE_RECORDS`);
/// surfaced by `get_issuance_log`. The on-disk CSV has a separate slim sidecar
/// (`DatasetAnchor`) so that the encrypted-FS file can be tamper-checked without
/// loading the redb store.
#[derive(Debug, Serialize, Deserialize)]
struct DatasetFileMeta {
    record_id: String,
    uploaded_by: String,
    rows: u64,
    uploaded_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    redeem_tx_signature: Option<String>,
}

/// Slim on-disk sidecar for a `{record_id}.csv` file.
///
/// Contains only the fields needed to (a) verify the encrypted CSV blob has not
/// been swapped or truncated by the host, and (b) tie the file back to its
/// on-chain `RightGranted` event. All queryable fields (uploader, row count,
/// timestamp) live in redb under `ISSUANCE_RECORDS`.
#[derive(Debug, Serialize, Deserialize)]
struct DatasetAnchor {
    /// `record_id` (matches the CSV filename stem).
    record_id: String,
    /// SHA-256 of the raw CSV bytes, hex-encoded.
    sha256: String,
    /// Hex-encoded 32-byte grant commitment from `grant_right`.
    /// `None` for the `initial` upload (no DRT burned).
    #[serde(skip_serializing_if = "Option::is_none")]
    commitment: Option<String>,
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

// ============================================================================
// Helpers
// ============================================================================

/// Acquire the per-pool mutex from the DashMap. Creates a new entry if absent.
fn acquire_pool_lock(state: &AppState, pool_pda: &str) -> Arc<tokio::sync::Mutex<()>> {
    state
        .pool_locks
        .entry(pool_pda.to_string())
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone()
}

/// Load pool metadata from enclave storage, returning a helpful error if missing.
fn load_pool_meta(state: &AppState, pool_pda: &str) -> Result<PoolMetadata, ApiError> {
    let meta_path = state.storage.paths().pool_meta(pool_pda);
    state
        .storage
        .read_json::<PoolMetadata>(&meta_path)
        .map_err(|_| {
            ApiError::not_found(format!(
                "pool metadata not found for {pool_pda} — pool may need initialization"
            ))
        })
}

/// Save pool metadata back to storage.
fn save_pool_meta(state: &AppState, pool_pda: &str, meta: &PoolMetadata) -> Result<(), ApiError> {
    let meta_path = state.storage.paths().pool_meta(pool_pda);
    state
        .storage
        .write_json(&meta_path, meta)
        .map_err(|e| ApiError::internal(format!("failed to write pool metadata: {e}")))
}

/// Recover pool directory structure if it was lost after on-chain creation.
/// Returns true if recovery was needed.
fn ensure_pool_dirs(state: &AppState, pool_pda: &str) -> Result<bool, ApiError> {
    let dataset_dir = state.storage.paths().pool_dataset_dir(pool_pda);
    if state.storage.exists(&dataset_dir) {
        return Ok(false);
    }
    state
        .storage
        .create_dir(&dataset_dir)
        .map_err(|e| ApiError::internal(format!("failed to create pool directory: {e}")))?;
    Ok(true)
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

// ============================================================================
// Handlers
// ============================================================================

/// Upload a schema definition for a pool.
///
/// Persists the schema to `/data/schemas/{schema_id}.json` so that subsequent
/// `/initialize` and `/issue` calls can validate CSV data against it.
/// Must be called after on-chain pool creation and before `/initialize`.
#[utoipa::path(
    post,
    path = "/v1/drt/pools/{pool_pda}/schema",
    tag = "Credentials",
    summary = "Upload schema for pool",
    description = "Upload a CSV schema definition to the enclave. The schema is persisted under /data/schemas/ and used for CSV validation during pool initialization and credential issuance.",
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
    )
)]
pub async fn upload_schema(
    AdminToken(token): AdminToken,
    State(state): State<AppState>,
    Path(pool_pda_str): Path<String>,
    Json(payload): Json<UploadSchemaRequest>,
) -> Result<Json<UploadSchemaResponse>, ApiError> {
    use crate::blockchain::drt::accounts::fetch_pool;
    use solana_pubkey::Pubkey;

    // Validate the pool PDA format.
    let pool_pda = Pubkey::from_str(&pool_pda_str)
        .map_err(|_| ApiError::bad_request("invalid pool PDA address"))?;

    // Validate schema_id is a safe identifier (prevent path traversal).
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

    // Verify caller is pool owner (O(1) via redb wallet index).
    let wallet = super::get_active_wallet_for_user(&state, &token.sub)?;
    verify_pool_ownership(&pool, &wallet)?;

    // Verify pool metadata references this schema_id.
    let meta = load_pool_meta(&state, &pool_pda_str)?;
    if meta.schema_id != payload.schema_id {
        return Err(ApiError::bad_request(format!(
            "pool's schema_id is '{}', but you are uploading '{}'",
            meta.schema_id, payload.schema_id
        )));
    }

    // Save schema under the pool's directory so two pools can share a schema_id
    // without overwriting each other.
    let field_count = payload.fields.len();
    crate::data_validation::save_pool_schema(state.storage.paths(), &pool_pda_str, &payload.fields)
        .map_err(ApiError::internal)?;

    info!(
        pool = %pool_pda_str,
        schema_id = %payload.schema_id,
        fields = field_count,
        "Schema uploaded and persisted"
    );

    // Log audit event.
    let audit_event = AuditEvent::new(AuditEventType::SchemaUploaded)
        .with_user(&token.sub)
        .with_resource("schema", &payload.schema_id)
        .with_pool_pda(&pool_pda_str)
        .with_details(serde_json::json!({
            "pool_pda": pool_pda_str,
            "schema_id": payload.schema_id,
            "field_count": field_count,
        }));
    AuditRepository::new(&state.storage)
        .with_tx_db(&state.tx_db)
        .log(&audit_event)
        .await;

    Ok(Json(UploadSchemaResponse {
        schema_id: payload.schema_id,
        field_count,
    }))
}

/// Response for `GET /v1/drt/pools/{pool_pda}/schema`.
#[derive(Debug, Serialize, ToSchema)]
pub struct GetSchemaResponse {
    pub pool_pda: String,
    pub schema_id: String,
    pub fields: Vec<crate::data_validation::FieldSchema>,
}

/// Get a pool's stored schema.
#[utoipa::path(
    get,
    path = "/v1/drt/pools/{pool_pda}/schema",
    tag = "Credentials",
    summary = "Get pool schema",
    description = "Returns the schema previously uploaded for the pool. 404 if no schema has been uploaded yet.",
    security(("bearer_auth" = [])),
    params(
        ("pool_pda" = String, Path, description = "Pool PDA address (base58)"),
    ),
    responses(
        (status = 200, description = "Schema returned", body = GetSchemaResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Schema not uploaded"),
    )
)]
pub async fn get_schema(
    crate::auth::AnalystToken(_token): crate::auth::AnalystToken,
    State(state): State<AppState>,
    Path(pool_pda_str): Path<String>,
) -> Result<Json<GetSchemaResponse>, ApiError> {
    let meta = load_pool_meta(&state, &pool_pda_str)?;
    let fields = crate::data_validation::load_pool_schema(state.storage.paths(), &pool_pda_str)
        .ok_or_else(|| {
            ApiError::not_found(format!(
                "no schema uploaded yet for pool {pool_pda_str} — POST one to /v1/drt/pools/{{pda}}/schema"
            ))
        })?;

    Ok(Json(GetSchemaResponse {
        pool_pda: pool_pda_str,
        schema_id: meta.schema_id,
        fields,
    }))
}

/// Seed the initial dataset for a pool.
///
/// The pool must be in `needs_init` state. No append DRT is required —
/// this is the initial seeding by the pool creator.
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
    )
)]
pub async fn initialize_pool(
    AdminToken(token): AdminToken,
    State(state): State<AppState>,
    Path(pool_pda_str): Path<String>,
    multipart: Multipart,
) -> Result<Json<InitializePoolResponse>, ApiError> {
    // Parse and decrypt the CSV payload.
    let parsed = parse_csv_payload(multipart).await?;

    // Validate the pool PDA format.
    let pool_pda = Pubkey::from_str(&pool_pda_str)
        .map_err(|_| ApiError::bad_request("invalid pool PDA address"))?;

    // Fetch on-chain pool to verify it exists and get ownership.
    let pool = fetch_pool(state.solana_client.rpc(), &pool_pda).await?;

    // Load wallet for ownership verification (O(1) via redb index).
    let wallet = super::get_active_wallet_for_user(&state, &token.sub)?;

    // Verify caller owns the on-chain pool.
    verify_pool_ownership(&pool, &wallet)?;

    // Ensure pool dirs exist (idempotent recovery).
    let recovered = ensure_pool_dirs(&state, &pool_pda_str)?;
    if recovered {
        warn!(pool = %pool_pda_str, "Recovered pool directory structure");
    }

    // Load pool metadata. Recovery from on-chain state alone is not possible
    // with the new contract (DRT names + right_ids live only in enclave
    // metadata) — the create endpoint is the only path that writes them.
    let mut meta = load_pool_meta(&state, &pool_pda_str)?;

    // Verify pool is in `needs_init` state.
    if meta.state != PoolState::NeedsInit {
        return Err(ApiError::bad_request(
            "pool is already initialized — use /issue to add credentials",
        ));
    }

    // IOB ERP pools are populated by Jitterbit — uploads via the dashboard
    // are intentionally rejected.
    if meta.kind == PoolKind::IobErp {
        return Err(ApiError::conflict(
            "IOB ERP pools cannot be initialised via dashboard upload",
        ));
    }

    // Validate CSV against the pool's schema.
    let summary = validate_payload(
        state.storage.paths(),
        &pool_pda_str,
        &parsed.csv_bytes,
        meta.validation_mode,
    )?;
    if !summary.valid {
        return Err(ApiError::bad_request(format!(
            "CSV validation failed: {} error(s)",
            summary.errors.len()
        )));
    }

    let row_count = count_csv_rows(&parsed.csv_bytes);
    let record_id = "initial".to_string();

    // Store the CSV dataset.
    let dataset_dir = state.storage.paths().pool_dataset_dir(&pool_pda_str);
    let csv_path = dataset_dir.join("initial.csv");
    let meta_file_path = dataset_dir.join("initial.meta.json");

    state
        .storage
        .write_raw(&csv_path, &parsed.csv_bytes)
        .map_err(|e| ApiError::internal(format!("failed to write initial dataset: {e}")))?;

    let file_meta = DatasetFileMeta {
        record_id: record_id.clone(),
        uploaded_by: token.sub.clone(),
        rows: row_count,
        uploaded_at: Utc::now().to_rfc3339(),
        redeem_tx_signature: None,
    };
    let anchor = DatasetAnchor {
        record_id: record_id.clone(),
        sha256: sha256_hex(&parsed.csv_bytes),
        commitment: None,
    };
    state
        .storage
        .write_json(&meta_file_path, &anchor)
        .map_err(|e| ApiError::internal(format!("failed to write dataset anchor: {e}")))?;

    // Update pool metadata.
    meta.state = PoolState::Ready;
    meta.initialized_at = Some(Utc::now());
    meta.total_credentials = row_count;
    save_pool_meta(&state, &pool_pda_str, &meta)?;

    // Dual-write: update pool meta in redb.
    if let Err(e) = state.tx_db.upsert_pool_meta(&meta) {
        warn!(pool = %pool_pda_str, error = %e, "Failed to update pool meta in redb");
    }
    // Dual-write: store initial issuance record in redb.
    if let Ok(json_bytes) = serde_json::to_vec(&file_meta) {
        if let Err(e) = state.tx_db.upsert_issuance_record(
            &pool_pda_str,
            &record_id,
            Utc::now().timestamp(),
            &json_bytes,
        ) {
            warn!(pool = %pool_pda_str, error = %e, "Failed to write initial issuance to redb");
        }
    }

    // Log audit event.
    let audit_event = AuditEvent::new(AuditEventType::DatasetInitialized)
        .with_user(&token.sub)
        .with_resource("drt_pool", &pool_pda_str)
        .with_details(serde_json::json!({
            "pool_pda": pool_pda_str,
            "record_id": record_id,
            "row_count": row_count,
            "schema_id": meta.schema_id,
            "state_transition": "needs_init -> ready"
        }));
    AuditRepository::new(&state.storage)
        .with_tx_db(&state.tx_db)
        .log(&audit_event)
        .await;

    info!(
        pool = %pool_pda_str,
        rows = row_count,
        schema = %meta.schema_id,
        "Pool dataset initialized"
    );

    Ok(Json(InitializePoolResponse {
        rows: row_count,
        record_id,
        state: "ready".to_string(),
    }))
}

/// Issue credentials to a pool (append-DRT gated).
///
/// Burns 1 append DRT on-chain, then stores the encrypted CSV dataset
/// in the pool's directory.
#[utoipa::path(
    post,
    path = "/v1/drt/pools/{pool_pda}/issue",
    tag = "Credentials",
    summary = "Issue credentials",
    description = "Issue credentials by redeeming an append DRT and storing encrypted CSV data. Validates ownership, DRT balance, CSV schema, then burns 1 append DRT and stores the dataset.",
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
    let parsed = parse_csv_payload(multipart).await?;

    let pool_pda = Pubkey::from_str(&pool_pda_str)
        .map_err(|_| ApiError::bad_request("invalid pool PDA address"))?;

    // Load pool metadata — must be in Ready state, MALTA kind.
    let meta = load_pool_meta(&state, &pool_pda_str)?;
    if meta.state != PoolState::Ready {
        return Err(ApiError::bad_request(
            "pool not initialized — call /initialize first",
        ));
    }
    if meta.kind == PoolKind::IobErp {
        return Err(ApiError::conflict(
            "IOB ERP pools do not accept credential issuance",
        ));
    }

    // Pull the append DRT's right_id + mint from enclave metadata
    // (the new contract doesn't carry DRT configs inline on the Pool).
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
    let caller_wallet = super::get_active_wallet_for_user(&state, &token.sub)?;
    let repo = WalletRepository::new(&state.storage);
    let keypair_bytes = repo.read_keypair(&caller_wallet.wallet_id)?;
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
        state.storage.paths(),
        &pool_pda_str,
        &parsed.csv_bytes,
        meta.validation_mode,
    )?;
    if !summary.valid {
        return Err(ApiError::bad_request(format!(
            "CSV validation failed: {} error(s)",
            summary.errors.len()
        )));
    }

    let row_count = count_csv_rows(&parsed.csv_bytes);

    // ── ACQUIRE POOL LOCK ─────────────────────────────────────────
    let lock = acquire_pool_lock(&state, &pool_pda_str);
    let _guard = lock.lock().await;

    // ── IRREVERSIBLE OPERATIONS ───────────────────────────────────

    // 1. Burn 1 append DRT on-chain via grant_right. The commitment is unique
    //    per upload (record_id || pool_uuid || append_right_id) and the Grant
    //    PDA serves as a permanent on-chain receipt for the upload event.
    let record_id = Uuid::new_v4().to_string();
    let commitment = compute_commitment(&record_id, &pool_uuid, &append_right_id);
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
        Err(e) => {
            // DRT not burned — clean failure.
            return Err(e);
        }
    };

    // 2. Store CSV dataset.
    let dataset_dir = state.storage.paths().pool_dataset_dir(&pool_pda_str);
    let csv_path = dataset_dir.join(format!("{record_id}.csv"));
    let meta_file_path = dataset_dir.join(format!("{record_id}.meta.json"));

    if let Err(e) = state.storage.write_raw(&csv_path, &parsed.csv_bytes) {
        // DRT was burned but file write failed — audit log this edge case.
        warn!(
            pool = %pool_pda_str,
            record_id = %record_id,
            redeem_sig = %sig_str,
            error = %e,
            "DRT burned but file write failed"
        );
        let fail_event = AuditEvent::new(AuditEventType::CredentialIssuanceFailed)
            .with_user(&token.sub)
            .with_resource("drt_pool", &pool_pda_str)
            .with_details(serde_json::json!({
                "pool_pda": pool_pda_str,
                "record_id": record_id,
                "redeem_tx_sig": sig_str,
                "error": e.to_string(),
                "chain": crate::api::pools::chain_section(
                    std::slice::from_ref(&sig_str),
                    &events,
                    {
                        let mut extra = serde_json::Map::new();
                        extra.insert(
                            hex::encode(commitment),
                            serde_json::Value::String(format!("upload {record_id}")),
                        );
                        crate::api::pools::pool_labels(&meta, Some(extra))
                    },
                ),
            }));
        AuditRepository::new(&state.storage)
            .with_tx_db(&state.tx_db)
            .log(&fail_event)
            .await;

        return Err(ApiError::internal(format!(
            "DRT burned (sig: {sig_str}) but file write failed — contact admin for recovery"
        )));
    }

    let file_meta = DatasetFileMeta {
        record_id: record_id.clone(),
        uploaded_by: token.sub.clone(),
        rows: row_count,
        uploaded_at: Utc::now().to_rfc3339(),
        redeem_tx_signature: Some(sig_str.clone()),
    };
    let anchor = DatasetAnchor {
        record_id: record_id.clone(),
        sha256: sha256_hex(&parsed.csv_bytes),
        commitment: Some(hex::encode(commitment)),
    };
    // Best-effort anchor write — the redb dual-write below is authoritative
    // for queryable fields; the sidecar is a tamper-evidence anchor only.
    if let Err(e) = state.storage.write_json(&meta_file_path, &anchor) {
        warn!(
            pool = %pool_pda_str,
            record_id = %record_id,
            error = %e,
            "Failed to write dataset anchor"
        );
    }

    // 3. Update pool.meta.json.
    let mut updated_meta = load_pool_meta(&state, &pool_pda_str)?;
    updated_meta.total_credentials += row_count;
    updated_meta.last_issue_at = Some(Utc::now());
    save_pool_meta(&state, &pool_pda_str, &updated_meta)?;

    // Dual-write: update pool meta + store issuance record in redb.
    if let Err(e) = state.tx_db.upsert_pool_meta(&updated_meta) {
        warn!(pool = %pool_pda_str, error = %e, "Failed to update pool meta in redb");
    }
    if let Ok(json_bytes) = serde_json::to_vec(&file_meta) {
        if let Err(e) = state.tx_db.upsert_issuance_record(
            &pool_pda_str,
            &record_id,
            Utc::now().timestamp(),
            &json_bytes,
        ) {
            warn!(pool = %pool_pda_str, error = %e, "Failed to write issuance record to redb");
        }
    }

    // 4. Audit log.
    let audit_event = AuditEvent::new(AuditEventType::CredentialIssued)
        .with_user(&token.sub)
        .with_resource("drt_pool", &pool_pda_str)
        .with_details(serde_json::json!({
            "pool_pda": pool_pda_str,
            "record_id": record_id,
            "row_count": row_count,
            "redeem_tx_sig": sig_str,
            "total_credentials": updated_meta.total_credentials,
            "chain": crate::api::pools::chain_section(
                std::slice::from_ref(&sig_str),
                &events,
                {
                    let mut extra = serde_json::Map::new();
                    extra.insert(
                        hex::encode(commitment),
                        serde_json::Value::String(format!("upload {record_id}")),
                    );
                    crate::api::pools::pool_labels(&updated_meta, Some(extra))
                },
            ),
        }));
    AuditRepository::new(&state.storage)
        .with_tx_db(&state.tx_db)
        .log(&audit_event)
        .await;

    let explorer_url = state.solana_client.network().explorer_tx_url(&sig_str);

    info!(
        pool = %pool_pda_str,
        record_id = %record_id,
        rows = row_count,
        redeem_sig = %sig_str,
        total = updated_meta.total_credentials,
        "Credentials issued"
    );

    Ok(Json(IssueCredentialsResponse {
        record_id,
        rows_issued: row_count,
        redeem_signature: sig_str,
        total_rows: updated_meta.total_credentials,
        explorer_url,
    }))
}

/// Revoke credential(s) from a pool.
///
/// Appends revocation entries to the pool's `revocations.jsonl` sidecar file.
/// This is an enclave-side soft revocation — on-chain revocation may be added later.
#[utoipa::path(
    post,
    path = "/v1/drt/pools/{pool_pda}/revoke",
    tag = "Credentials",
    summary = "Revoke credentials",
    description = "Revoke one or more credentials by record ID. Writes revocation entries to the pool's sidecar file. Admin only.",
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
    let repo = WalletRepository::new(&state.storage);
    let (wallet, _) = load_wallet_keypair(&repo, &payload.wallet_id, &token.sub)?;

    let pool = fetch_pool(state.solana_client.rpc(), &pool_pda).await?;
    verify_pool_ownership(&pool, &wallet)?;

    // Verify pool metadata exists.
    let _meta = load_pool_meta(&state, &pool_pda_str)?;

    // Verify each credential_id references an existing dataset file.
    let dataset_dir = state.storage.paths().pool_dataset_dir(&pool_pda_str);
    for cid in &payload.credential_ids {
        let csv_path = if cid == "initial" {
            dataset_dir.join("initial.csv")
        } else {
            dataset_dir.join(format!("{cid}.csv"))
        };
        if !state.storage.exists(&csv_path) {
            return Err(ApiError::not_found(format!(
                "credential record '{cid}' not found in pool"
            )));
        }
    }

    // Append revocation entries to JSONL file.
    let revocations_path = state.storage.paths().pool_revocations(&pool_pda_str);
    let now = Utc::now().to_rfc3339();
    let mut lines = String::new();
    for cid in &payload.credential_ids {
        let entry = RevocationEntry {
            credential_id: cid.clone(),
            revoked_by: token.sub.clone(),
            revoked_at: now.clone(),
            reason: payload.reason.clone(),
        };
        let json = serde_json::to_string(&entry)
            .map_err(|e| ApiError::internal(format!("failed to serialize revocation: {e}")))?;
        lines.push_str(&json);
        lines.push('\n');
    }

    // Append to file (create if missing).
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&revocations_path)
        .map_err(|e| ApiError::internal(format!("failed to open revocations file: {e}")))?;
    file.write_all(lines.as_bytes())
        .map_err(|e| ApiError::internal(format!("failed to write revocations: {e}")))?;

    // Update pool metadata.
    let revoked_count = payload.credential_ids.len();
    let mut updated_meta = load_pool_meta(&state, &pool_pda_str)?;
    updated_meta.revoked_count += revoked_count as u64;
    save_pool_meta(&state, &pool_pda_str, &updated_meta)?;

    // Dual-write: revocations + updated pool meta to redb.
    if let Err(e) = state.tx_db.upsert_pool_meta(&updated_meta) {
        warn!(pool = %pool_pda_str, error = %e, "Failed to update pool meta in redb");
    }
    for cid in &payload.credential_ids {
        let entry = RevocationEntry {
            credential_id: cid.clone(),
            revoked_by: token.sub.clone(),
            revoked_at: now.clone(),
            reason: payload.reason.clone(),
        };
        if let Ok(json_bytes) = serde_json::to_vec(&entry) {
            if let Err(e) = state
                .tx_db
                .upsert_revocation(&pool_pda_str, cid, &json_bytes)
            {
                warn!(pool = %pool_pda_str, credential = %cid, error = %e, "Failed to write revocation to redb");
            }
        }
    }

    // Audit log.
    let audit_event = AuditEvent::new(AuditEventType::CredentialRevoked)
        .with_user(&token.sub)
        .with_resource("drt_pool", &pool_pda_str)
        .with_details(serde_json::json!({
            "pool_pda": pool_pda_str,
            "credential_ids": payload.credential_ids,
            "revoked_count": revoked_count,
            "reason": payload.reason
        }));
    AuditRepository::new(&state.storage)
        .with_tx_db(&state.tx_db)
        .log(&audit_event)
        .await;

    info!(
        pool = %pool_pda_str,
        count = revoked_count,
        "Credentials revoked"
    );

    Ok(Json(RevokeCredentialsResponse {
        revoked: revoked_count,
    }))
}

/// List revocation entries for a pool.
#[utoipa::path(
    get,
    path = "/v1/drt/pools/{pool_pda}/revocations",
    tag = "Credentials",
    summary = "List revocations",
    description = "List revocation entries for a pool with pagination. Admin only.",
    security(("bearer_auth" = [])),
    params(
        ("pool_pda" = String, Path, description = "Pool PDA address (base58)"),
        super::PaginationQuery,
    ),
    responses(
        (status = 200, description = "Revocation list", body = RevocationsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Pool not found"),
    )
)]
pub async fn list_revocations(
    AdminToken(_token): AdminToken,
    State(state): State<AppState>,
    Path(pool_pda_str): Path<String>,
    Query(pagination): Query<super::PaginationQuery>,
) -> Result<Json<RevocationsResponse>, ApiError> {
    // Any admin can view revocations (no ownership check).

    // Read revocations from redb (O(k) prefix scan).
    let limit = pagination.clamped_limit();
    let raw_entries = state
        .tx_db
        .list_revocations(&pool_pda_str, limit, pagination.offset)
        .map_err(|e| ApiError::internal(format!("failed to query revocations: {e}")))?;

    let entries: Vec<RevocationEntry> = raw_entries
        .into_iter()
        .filter_map(|val| serde_json::from_value(val).ok())
        .collect();

    // Get actual total count (not page length) for pagination.
    let total = state
        .tx_db
        .count_revocations(&pool_pda_str)
        .unwrap_or(entries.len());

    Ok(Json(RevocationsResponse {
        pool_pda: pool_pda_str,
        revocations: entries,
        total,
    }))
}

/// Query pool-scoped audit events.
///
/// Scans daily JSONL files from pool creation to now, filtering by pool PDA.
/// Supports pagination via `limit` and `offset` query parameters.
#[utoipa::path(
    get,
    path = "/v1/drt/pools/{pool_pda}/audit",
    tag = "Credentials",
    summary = "Pool audit log",
    description = "Query audit events scoped to a specific pool. Iterates daily JSONL files and filters by pool PDA. Admin only.",
    security(("bearer_auth" = [])),
    params(
        ("pool_pda" = String, Path, description = "Pool PDA address (base58)"),
        PoolAuditQuery,
    ),
    responses(
        (status = 200, description = "Audit events", body = PoolAuditResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Pool not found"),
    )
)]
pub async fn pool_audit(
    crate::auth::AnalystToken(_token): crate::auth::AnalystToken,
    State(state): State<AppState>,
    Path(pool_pda_str): Path<String>,
    Query(query): Query<PoolAuditQuery>,
) -> Result<Json<PoolAuditResponse>, ApiError> {
    // Any admin can view audit events (no ownership check).

    let limit = query.limit.min(200);
    let has_filters = query.event_type.is_some()
        || query.actor.is_some()
        || query.status.is_some()
        || query.from.is_some()
        || query.to.is_some();

    // If filters are present, over-fetch from redb and post-filter — the
    // per-pool volume is small (hundreds at pilot scale). If no filters,
    // the original limit/offset path through redb is faithful.
    let fetch_limit = if has_filters { 1_000 } else { limit };
    let fetch_offset = if has_filters { 0 } else { query.offset };

    let raw_events = state
        .tx_db
        .list_audit_by_resource(&pool_pda_str, fetch_limit, fetch_offset)
        .map_err(|e| ApiError::internal(format!("failed to query audit events: {e}")))?;

    let event_type_filter: Option<Vec<String>> = query.event_type.as_ref().map(|s| {
        s.split(',')
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
            .collect()
    });

    let from_ts = query
        .from
        .as_deref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|d| d.with_timezone(&chrono::Utc));
    let to_ts = query
        .to
        .as_deref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|d| d.with_timezone(&chrono::Utc));

    let filtered: Vec<AuditEvent> = raw_events
        .into_iter()
        .filter(|e| {
            if let Some(types) = &event_type_filter {
                let kind = serde_json::to_value(&e.event_type)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_owned))
                    .unwrap_or_default();
                if !types.iter().any(|t| t == &kind) {
                    return false;
                }
            }
            if let Some(actor) = query.actor.as_deref() {
                if e.user_id.as_deref() != Some(actor) {
                    return false;
                }
            }
            if let Some(status) = query.status.as_deref() {
                match status {
                    "ok" | "success" if !e.success => return false,
                    "failed" | "error" if e.success => return false,
                    _ => {}
                }
            }
            if let Some(from) = from_ts {
                if e.timestamp < from {
                    return false;
                }
            }
            if let Some(to) = to_ts {
                if e.timestamp > to {
                    return false;
                }
            }
            true
        })
        .collect();

    let total_filtered = filtered.len();
    let page: Vec<AuditEvent> = if has_filters {
        filtered
            .into_iter()
            .skip(query.offset)
            .take(limit)
            .collect()
    } else {
        filtered
    };

    // When no filters are active the redb count is the authoritative total;
    // with filters we report the count of matching rows we scanned (capped
    // at fetch_limit).
    let total = if has_filters {
        total_filtered
    } else {
        state
            .tx_db
            .count_audit_by_resource(&pool_pda_str)
            .unwrap_or(0)
    };

    Ok(Json(PoolAuditResponse {
        pool_pda: pool_pda_str,
        events: page,
        total,
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

    // Load enclave metadata.
    let meta = load_pool_meta(&state, &pool_pda_str)?;

    // Fetch on-chain pool.
    let pool = fetch_pool(state.solana_client.rpc(), &pool_pda).await?;

    // Build DRT list from enclave metadata (the new contract doesn't carry
    // DRT configs inline on the Pool account). We do a best-effort SPL
    // token-supply RPC for each mint to compute `remaining_supply`. If the
    // RPC fails for a particular mint we transparently fall back to the
    // recorded supply so the dashboard always renders something sensible.
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

    // Recent audit events (last 10 for this pool, from redb).
    let recent_events: Vec<AuditEvent> = state
        .tx_db
        .list_audit_by_resource(&pool_pda_str, 10, 0)
        .unwrap_or_default();

    let state_str = match meta.state {
        PoolState::NeedsInit => "needs_init",
        PoolState::Ready => "ready",
    };

    Ok(Json(PoolSummaryResponse {
        pool_pda: pool_pda_str,
        pool_name: meta.pool_name,
        owner: pool.owner.to_string(),
        schema_id: meta.schema_id,
        validation_mode: meta.validation_mode,
        state: state_str.to_string(),
        total_rows: meta.total_credentials,
        revoked_count: meta.revoked_count,
        created_at: meta.created_onchain_at.to_rfc3339(),
        initialized_at: meta.initialized_at.map(|d| d.to_rfc3339()),
        last_issue_at: meta.last_issue_at.map(|d| d.to_rfc3339()),
        drts,
        recent_events,
    }))
}

/// List pools owned by a specific wallet.
///
/// Scans the enclave's `/data/pools/` directory for pools where the
/// `owner_wallet_id` matches. Enclave-side discovery only — no on-chain indexing.
#[utoipa::path(
    get,
    path = "/v1/drt/pools/by-wallet/{wallet_id}",
    tag = "Credentials",
    summary = "List pools by wallet",
    description = "List pools owned by a specific wallet with pagination. Reads from enclave storage.",
    security(("bearer_auth" = [])),
    params(
        ("wallet_id" = String, Path, description = "Wallet UUID"),
        super::PaginationQuery,
    ),
    responses(
        (status = 200, description = "Pool list", body = PoolsByWalletResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Not wallet owner"),
    )
)]
pub async fn list_pools_by_wallet(
    crate::auth::UserToken(token): crate::auth::UserToken,
    State(state): State<AppState>,
    Path(wallet_id): Path<String>,
    Query(pagination): Query<super::PaginationQuery>,
) -> Result<Json<PoolsByWalletResponse>, ApiError> {
    // Verify wallet ownership.
    let repo = WalletRepository::new(&state.storage);
    let wallet = repo.get(&wallet_id)?;
    crate::storage::ownership::OwnershipEnforcer::verify_ownership(&wallet, &token.sub)?;

    // O(k) lookup via redb index (no dir scan).
    let metas = state
        .tx_db
        .list_pools_by_owner(&wallet_id)
        .map_err(|e| ApiError::internal(format!("failed to query pools by owner: {e}")))?;

    let total = metas.len();

    let pools: Vec<PoolListEntry> = metas
        .into_iter()
        .skip(pagination.offset)
        .take(pagination.clamped_limit())
        .map(|meta| {
            let state_str = match meta.state {
                PoolState::NeedsInit => "needs_init",
                PoolState::Ready => "ready",
            };
            PoolListEntry {
                pool_pda: meta.pool_pda,
                pool_name: meta.pool_name,
                total_rows: meta.total_credentials,
                revoked_count: meta.revoked_count,
                schema_id: meta.schema_id,
                state: state_str.to_string(),
                created_at: meta.created_onchain_at.to_rfc3339(),
            }
        })
        .collect();

    Ok(Json(PoolsByWalletResponse {
        wallet_id,
        pools,
        total,
    }))
}

/// List all pools managed by the enclave (marketplace discovery).
///
/// Scans `/data/pools/` and returns all pools with optional filtering,
/// search, sorting, and pagination. Accessible by any authenticated user.
#[utoipa::path(
    get,
    path = "/v1/drt/pools/list",
    tag = "Credentials",
    summary = "List all pools",
    description = "Browse all credential pools managed by the enclave. Supports filtering by state, search by name, sorting, and pagination.",
    security(("bearer_auth" = [])),
    params(ListAllPoolsQuery),
    responses(
        (status = 200, description = "Pool list", body = AllPoolsResponse),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn list_all_pools(
    crate::auth::ReadOnlyToken(_token): crate::auth::ReadOnlyToken,
    State(state): State<AppState>,
    Query(query): Query<ListAllPoolsQuery>,
) -> Result<Json<AllPoolsResponse>, ApiError> {
    // Read all pool metadata from redb (no dir scan).
    let all_metas = state
        .tx_db
        .list_all_pool_metas()
        .map_err(|e| ApiError::internal(format!("failed to list pool metadata: {e}")))?;

    let mut entries: Vec<MarketplacePoolEntry> = Vec::new();
    for meta in all_metas {
        let state_str = match meta.state {
            PoolState::NeedsInit => "needs_init",
            PoolState::Ready => "ready",
        };

        // Apply state filter.
        if let Some(ref filter_state) = query.state {
            if state_str != filter_state.as_str() {
                continue;
            }
        }

        // Apply search filter (case-insensitive on pool name).
        if let Some(ref search) = query.search {
            if !meta
                .pool_name
                .to_lowercase()
                .contains(&search.to_lowercase())
            {
                continue;
            }
        }

        // Resolve owner pubkey: use stored value or fall back to "unknown".
        let owner = meta
            .owner_pubkey
            .clone()
            .unwrap_or_else(|| "unknown".to_string());

        // Build DRT list from enclave metadata (avoids per-pool chain RPC).
        // For the marketplace listing we report `remaining_supply == supply`
        // to keep this endpoint cheap; the per-pool summary endpoint hits the
        // RPC for the live remaining supply.
        let pool_drts: Vec<MarketplaceDrtEntry> = meta
            .drts
            .iter()
            .map(|(name, d)| MarketplaceDrtEntry {
                drt_type: name.clone(),
                supply: d.supply,
                remaining_supply: d.supply,
            })
            .collect();

        let drt_count = pool_drts.len();

        let kind_str = match meta.kind {
            PoolKind::Malta => "malta",
            PoolKind::IobErp => "iob_erp",
        }
        .to_string();
        entries.push(MarketplacePoolEntry {
            pool_pda: meta.pool_pda,
            pool_name: meta.pool_name,
            kind: kind_str,
            owner,
            schema_id: meta.schema_id,
            state: state_str.to_string(),
            total_rows: meta.total_credentials,
            revoked_count: meta.revoked_count,
            created_at: meta.created_onchain_at.to_rfc3339(),
            drt_count,
            drts: pool_drts,
        });
    }

    // Sort.
    match query.sort.as_str() {
        "created_asc" => entries.sort_by(|a, b| a.created_at.cmp(&b.created_at)),
        "name_asc" => {
            entries.sort_by(|a, b| a.pool_name.to_lowercase().cmp(&b.pool_name.to_lowercase()))
        }
        "credentials_desc" => entries.sort_by(|a, b| b.total_rows.cmp(&a.total_rows)),
        _ => entries.sort_by(|a, b| b.created_at.cmp(&a.created_at)), // created_desc
    }

    let total = entries.len() as u64;
    let limit = query.limit.min(100);
    let offset = query.offset.min(total);
    let page: Vec<MarketplacePoolEntry> = entries
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .collect();

    Ok(Json(AllPoolsResponse {
        pools: page,
        total,
        limit,
        offset,
    }))
}

/// List per-issuance records for a pool (issuance log).
///
/// Scans the pool's dataset directory for `*.meta.json` files and returns
/// each upload record with row count, uploader, timestamp, and tx signature.
/// Includes the initial dataset record.
#[utoipa::path(
    get,
    path = "/v1/drt/pools/{pool_pda}/issuance-log",
    tag = "Credentials",
    summary = "Pool issuance log",
    description = "List credential issuance records for a pool with pagination. Admin only (pool owner).",
    security(("bearer_auth" = [])),
    params(
        ("pool_pda" = String, Path, description = "Pool PDA address (base58)"),
        super::PaginationQuery,
    ),
    responses(
        (status = 200, description = "Issuance log", body = IssuanceLogResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Pool not found"),
    )
)]
pub async fn get_issuance_log(
    AdminToken(_token): AdminToken,
    State(state): State<AppState>,
    Path(pool_pda_str): Path<String>,
    Query(pagination): Query<super::PaginationQuery>,
) -> Result<Json<IssuanceLogResponse>, ApiError> {
    // Any admin can view issuance log (no ownership check).

    // Read issuance records from redb (already sorted newest-first by key design).
    let limit = pagination.clamped_limit();
    let raw_records = state
        .tx_db
        .list_issuance_records(&pool_pda_str, limit, pagination.offset)
        .map_err(|e| ApiError::internal(format!("failed to query issuance records: {e}")))?;

    let records: Vec<IssuanceRecord> = raw_records
        .into_iter()
        .filter_map(|val| {
            Some(IssuanceRecord {
                record_id: val.get("record_id")?.as_str()?.to_string(),
                uploaded_by: val.get("uploaded_by")?.as_str()?.to_string(),
                rows: val.get("rows")?.as_u64()?,
                uploaded_at: val.get("uploaded_at")?.as_str()?.to_string(),
                redeem_tx_signature: val
                    .get("redeem_tx_signature")
                    .and_then(|v| v.as_str().map(|s| s.to_string())),
            })
        })
        .collect();

    // Get actual total count (not page length) for pagination.
    let total = state
        .tx_db
        .count_issuance_records(&pool_pda_str)
        .unwrap_or(records.len());

    Ok(Json(IssuanceLogResponse {
        pool_pda: pool_pda_str,
        records,
        total,
    }))
}
