// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Admin endpoints.
//!
//! All endpoints require the `Admin` role.
//!
//! - `GET  /v1/admin/wallet-stats`              — aggregate stats
//! - `GET  /v1/admin/wallets`                   — list all wallets (any owner)
//! - `POST /v1/admin/wallets/{id}/suspend`      — suspend a wallet
//! - `POST /v1/admin/wallets/{id}/activate`     — reactivate a wallet
//! - `GET  /v1/admin/analysis-log`              — a pool's analysis requests on a day
//!
//! The employer-scope mapping's endpoints are in [`super::employer_scopes`].

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Response,
    Json,
};
use serde::{Deserialize, Serialize};
use tracing::info;
use utoipa::{IntoParams, ToSchema};

use crate::auth::Caller;
use crate::error::ApiError;
use crate::idempotency::{Idempotent, Operation};
use crate::state::AppState;
use crate::storage::analysis_log::AnalysisRecord;
use crate::storage::wallets::{WalletResponse, WalletStatus};

use super::{load_wallet, page, CursorQuery};

// ============================================================================
// Response types
// ============================================================================

/// Aggregate wallet statistics.
#[derive(Debug, Serialize, ToSchema)]
pub struct WalletStatsResponse {
    pub total_wallets: usize,
    pub active_wallets: usize,
    pub suspended_wallets: usize,
    pub deleted_wallets: usize,
}

/// One page of all wallets (admin view).
#[derive(Debug, Serialize, ToSchema)]
pub struct AdminListWalletsResponse {
    pub wallets: Vec<AdminWalletEntry>,
    /// Present when there's another page; pass it as `cursor`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// Extended wallet info visible to admins.
#[derive(Debug, Serialize, ToSchema)]
pub struct AdminWalletEntry {
    #[serde(flatten)]
    pub wallet: WalletResponse,
    /// Owner user ID (visible to admins).
    pub owner_user_id: String,
}

/// Generic status response for suspend/activate.
#[derive(Debug, Serialize, ToSchema)]
pub struct WalletStatusChangeResponse {
    pub wallet_id: String,
    pub new_status: String,
}

/// Which analysis requests to list.
#[derive(Debug, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
pub struct AnalysisLogQuery {
    /// The pool whose analysis requests to list.
    pub pool_pda: String,
    /// The UTC day, as `YYYY-MM-DD`.
    pub date: String,
}

/// A pool's analysis requests on one day, oldest first.
#[derive(Debug, Serialize, ToSchema)]
pub struct AnalysisLogResponse {
    pub pool_pda: String,
    pub date: String,
    pub records: Vec<AnalysisRecord>,
}

// ============================================================================
// Handlers
// ============================================================================

/// Move a non-deleted wallet to `status` (compare-and-swap; already being
/// there counts as success).
async fn set_status(
    state: &AppState,
    op: &mut Operation<'_>,
    wallet_id: &str,
    status: WalletStatus,
    action: &str,
) -> Result<(), ApiError> {
    let wallet = load_wallet(state, wallet_id).await?;
    if wallet.status == WalletStatus::Deleted {
        return Err(ApiError::bad_request(format!(
            "cannot {action} a deleted wallet"
        )));
    }
    op.begin().await?;
    state
        .storage
        .wallets()
        .set_status(wallet_id, status)
        .await?
        .ok_or_else(|| ApiError::not_found(format!("wallet {wallet_id} not found")))?;
    Ok(())
}

/// Get aggregate wallet statistics.
#[utoipa::path(
    get,
    path = "/v1/admin/wallet-stats",
    tag = "Admin",
    summary = "Wallet statistics",
    description = "Returns aggregate counts of wallets by status. Admin only.",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Stats", body = WalletStatsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Admin role required"),
    )
)]
pub async fn get_wallet_stats(
    caller: Caller,
    State(state): State<AppState>,
) -> Result<Json<WalletStatsResponse>, ApiError> {
    caller.require_admin()?;
    let all = state.storage.wallets().all().await?;

    let active = all
        .iter()
        .filter(|w| w.status == WalletStatus::Active)
        .count();
    let suspended = all
        .iter()
        .filter(|w| w.status == WalletStatus::Suspended)
        .count();
    let deleted = all
        .iter()
        .filter(|w| w.status == WalletStatus::Deleted)
        .count();

    Ok(Json(WalletStatsResponse {
        total_wallets: all.len(),
        active_wallets: active,
        suspended_wallets: suspended,
        deleted_wallets: deleted,
    }))
}

/// List all wallets (all users, all statuses).
#[utoipa::path(
    get,
    path = "/v1/admin/wallets",
    tag = "Admin",
    summary = "List all wallets (admin)",
    description = "Returns all wallets across all users, in wallet ID order, one cursor page at a time. Admin only.",
    security(("bearer_auth" = [])),
    params(CursorQuery),
    responses(
        (status = 200, description = "All wallets", body = AdminListWalletsResponse),
        (status = 400, description = "Invalid cursor"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Admin role required"),
    )
)]
pub async fn list_all_wallets(
    caller: Caller,
    State(state): State<AppState>,
    Query(query): Query<CursorQuery>,
) -> Result<Json<AdminListWalletsResponse>, ApiError> {
    caller.require_admin()?;
    let (wallets, next_cursor) = page(
        state.storage.wallets().all().await?,
        |w| &w.wallet_id,
        query.cursor.as_deref(),
        query.clamped_limit(),
    )?;
    let entries: Vec<AdminWalletEntry> = wallets
        .into_iter()
        .map(|w| AdminWalletEntry {
            owner_user_id: w.owner_user_id.clone(),
            wallet: WalletResponse::from(w),
        })
        .collect();

    Ok(Json(AdminListWalletsResponse {
        wallets: entries,
        next_cursor,
    }))
}

/// Suspend a wallet (admin action).
#[utoipa::path(
    post,
    path = "/v1/admin/wallets/{wallet_id}/suspend",
    tag = "Admin",
    summary = "Suspend wallet",
    description = "Suspend a wallet, preventing the owner from transacting. Admin only.",
    security(("bearer_auth" = [])),
    params(
        ("wallet_id" = String, Path, description = "Wallet UUID"),
        ("Idempotency-Key" = String, Header, description = "A UUID naming this user action; reuse it on every retry"),
    ),
    responses(
        (status = 200, description = "Wallet suspended", body = WalletStatusChangeResponse),
        (status = 400, description = "Deleted wallet, or no Idempotency-Key"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Admin role required"),
        (status = 404, description = "Wallet not found"),
        (status = 422, description = "The Idempotency-Key was used for a different request"),
    )
)]
pub async fn suspend_wallet(
    caller: Caller,
    request: Idempotent,
    State(state): State<AppState>,
    Path(wallet_id): Path<String>,
) -> Result<Response, ApiError> {
    caller.require_admin()?;
    let mut op = open_or_replay!(state, &caller.user_id, request, b"");
    set_status(
        &state,
        &mut op,
        &wallet_id,
        WalletStatus::Suspended,
        "suspend",
    )
    .await?;

    info!(
        wallet_id = %wallet_id,
        admin = %caller.user_id,
        "Wallet suspended by admin"
    );

    op.finish(
        StatusCode::OK,
        &WalletStatusChangeResponse {
            wallet_id,
            new_status: "suspended".to_string(),
        },
    )
    .await
}

/// Reactivate a suspended wallet (admin action).
#[utoipa::path(
    post,
    path = "/v1/admin/wallets/{wallet_id}/activate",
    tag = "Admin",
    summary = "Activate wallet",
    description = "Reactivate a suspended wallet. Admin only.",
    security(("bearer_auth" = [])),
    params(
        ("wallet_id" = String, Path, description = "Wallet UUID"),
        ("Idempotency-Key" = String, Header, description = "A UUID naming this user action; reuse it on every retry"),
    ),
    responses(
        (status = 200, description = "Wallet activated", body = WalletStatusChangeResponse),
        (status = 400, description = "Deleted wallet, or no Idempotency-Key"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Admin role required"),
        (status = 404, description = "Wallet not found"),
        (status = 422, description = "The Idempotency-Key was used for a different request"),
    )
)]
pub async fn activate_wallet(
    caller: Caller,
    request: Idempotent,
    State(state): State<AppState>,
    Path(wallet_id): Path<String>,
) -> Result<Response, ApiError> {
    caller.require_admin()?;
    let mut op = open_or_replay!(state, &caller.user_id, request, b"");
    set_status(
        &state,
        &mut op,
        &wallet_id,
        WalletStatus::Active,
        "activate",
    )
    .await?;

    info!(
        wallet_id = %wallet_id,
        admin = %caller.user_id,
        "Wallet activated by admin"
    );

    op.finish(
        StatusCode::OK,
        &WalletStatusChangeResponse {
            wallet_id,
            new_status: "active".to_string(),
        },
    )
    .await
}

/// A pool's analysis requests on one day.
#[utoipa::path(
    get,
    path = "/v1/admin/analysis-log",
    tag = "Admin",
    summary = "Analysis log",
    description = "The sealed record of every options, search and query request to the pool's analysis on one UTC day, oldest first: who asked, through which grant, the filters, sort and page, how many rows went back, and the outcome. Admin only.",
    security(("bearer_auth" = [])),
    params(AnalysisLogQuery),
    responses(
        (status = 200, description = "The records", body = AnalysisLogResponse),
        (status = 400, description = "The date isn't YYYY-MM-DD"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Admin role required"),
    )
)]
pub async fn get_analysis_log(
    caller: Caller,
    State(state): State<AppState>,
    Query(query): Query<AnalysisLogQuery>,
) -> Result<Json<AnalysisLogResponse>, ApiError> {
    caller.require_admin()?;
    let canonical = chrono::NaiveDate::parse_from_str(&query.date, "%Y-%m-%d")
        .is_ok_and(|d| d.format("%Y-%m-%d").to_string() == query.date);
    if !canonical {
        return Err(ApiError::bad_request("date must be YYYY-MM-DD"));
    }
    let records = state
        .storage
        .analysis_log()
        .on(&query.pool_pda, &query.date)
        .await?;
    Ok(Json(AnalysisLogResponse {
        pool_pda: query.pool_pda,
        date: query.date,
        records,
    }))
}
