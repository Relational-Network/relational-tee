// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Pool initialisation endpoint.
//!
//! - `POST /v1/drt/pools/{pool_pda}/initialize` — seed initial dataset

use axum::{
    extract::{Multipart, Path, State},
    http::StatusCode,
    response::Response,
};
use chrono::Utc;
use serde::Serialize;
use tracing::info;
use utoipa::ToSchema;

use crate::api::pools::{load_pool, verify_pool_ownership};
use crate::audit;
use crate::auth::{Caller, Permission};
use crate::blockchain::drt::accounts::fetch_pool;
use crate::error::ApiError;
use crate::handlers::{parse_csv_payload, validate_payload};
use crate::idempotency::Idempotent;
use crate::ids;
use crate::state::AppState;
use crate::storage::pools::{PoolState, Upload, INITIAL};
use crate::storage::Change;
use crate::tee::KeyName;

use super::{count_csv_rows, parse_pda, pool_not_found, sha256_hex, validation_failed};

// ============================================================================
// Response types
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

// ============================================================================
// Handlers
// ============================================================================

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
    let wallet = crate::api::get_active_wallet_for_user(&state, &caller.user_id).await?;
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
