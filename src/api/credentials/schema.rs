// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! `GET /v1/drt/pools/{pool_pda}/schema`: the pool's schema, which its
//! analysis definition sets when the pool is created.

use axum::{
    extract::{Path, State},
    Json,
};
use serde::Serialize;
use utoipa::ToSchema;

use crate::api::pools::load_pool;
use crate::auth::{Caller, Permission};
use crate::error::ApiError;
use crate::state::AppState;

/// Response for `GET /v1/drt/pools/{pool_pda}/schema`.
#[derive(Debug, Serialize, ToSchema)]
pub struct GetSchemaResponse {
    pub pool_pda: String,
    /// The analysis whose columns these are.
    pub schema_id: String,
    /// Every upload must have exactly these headers.
    pub fields: Vec<crate::data_validation::FieldSchema>,
}

/// Get a pool's schema.
#[utoipa::path(
    get,
    path = "/v1/drt/pools/{pool_pda}/schema",
    tag = "Credentials",
    summary = "Get pool schema",
    description = "Returns the pool's schema: the columns of its analysis definition. Every upload must have exactly these headers, with dates as DD/MM/YYYY. 404 if the pool has none.",
    security(("bearer_auth" = [])),
    params(
        ("pool_pda" = String, Path, description = "Pool PDA address (base58)"),
    ),
    responses(
        (status = 200, description = "Schema returned", body = GetSchemaResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Needs pools:read"),
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
            "pool {pool_pda_str} has no schema"
        )));
    }

    Ok(Json(GetSchemaResponse {
        pool_pda: pool_pda_str,
        schema_id: doc.schema_id,
        fields: doc.schema,
    }))
}
