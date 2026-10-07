// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Pool read endpoints.
//!
//! - `GET /v1/drt/pools/{pool_pda}/revocations` — list revocations
//! - `GET /v1/drt/pools/{pool_pda}/summary` — pool metadata + on-chain state
//! - `GET /v1/drt/pools/list` — list all pools (marketplace discovery)
//! - `GET /v1/drt/pools/{pool_pda}/issuance-log` — list per-issuance records
//!
//! Lists page in memory: pass `next_cursor` back as `cursor`.

use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use solana_pubkey::Pubkey;
use std::str::FromStr;
use utoipa::{IntoParams, ToSchema};

use crate::api::pools::load_pool;
use crate::api::{page, CursorQuery};
use crate::auth::{Caller, Permission};
use crate::blockchain::drt::accounts::fetch_pool;
use crate::error::ApiError;
use crate::state::AppState;
use crate::storage::pools::Upload;

use super::parse_pda;

// ============================================================================
// Request / Response types
// ============================================================================

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
    /// The analysis the pool's Execute DRT pins; none for pools created
    /// before analyses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub analysis: Option<crate::storage::pools::AnalysisRef>,
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

// ============================================================================
// Handlers
// ============================================================================

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
        analysis: doc.analysis,
        total_rows: totals.rows,
        revoked_count: totals.revoked,
        created_at: doc.created_at.to_rfc3339(),
        created_by: doc.created_by,
        creation_signature: doc.creation_signature,
        last_issue_at: totals.last_issue_at.map(|d| d.to_rfc3339()),
        drts,
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
