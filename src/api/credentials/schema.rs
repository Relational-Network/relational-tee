// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Pool schema endpoints.
//!
//! - `POST /v1/drt/pools/{pool_pda}/schema` — replace the pool's schema
//! - `GET  /v1/drt/pools/{pool_pda}/schema` — the pool's schema

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Response,
    Json,
};
use serde::{Deserialize, Serialize};
use tracing::info;
use utoipa::ToSchema;

use crate::api::pools::{load_pool, verify_pool_ownership};
use crate::auth::{Caller, Permission};
use crate::blockchain::drt::accounts::fetch_pool;
use crate::error::ApiError;
use crate::idempotency::{Idempotent, JsonBody};
use crate::state::AppState;
use crate::storage::Change;

use super::{parse_pda, pool_not_found};

// ============================================================================
// Request / Response types
// ============================================================================

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
    let wallet = crate::api::get_active_wallet_for_user(&state, &caller.user_id).await?;
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
