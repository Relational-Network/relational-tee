// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Admin endpoints for the wallet service.
//!
//! All endpoints require `AdminToken` (admin role).
//!
//! - `GET  /v1/admin/wallet-stats`              — aggregate stats
//! - `GET  /v1/admin/wallets`                   — list all wallets (any owner)
//! - `POST /v1/admin/wallets/{id}/suspend`      — suspend a wallet
//! - `POST /v1/admin/wallets/{id}/activate`     — reactivate a wallet

use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::Serialize;
use tracing::info;
use utoipa::ToSchema;

use crate::auth::AdminToken;
use crate::error::ApiError;
use crate::state::AppState;
use crate::storage::wallets::{WalletResponse, WalletStatus};

use super::{load_wallet, CursorQuery};

/// The cursor scope of the admin wallet list.
const WALLETS_SCOPE: &str = "wallets";

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

// ============================================================================
// Handlers
// ============================================================================

/// Move a non-deleted wallet to `status` (compare-and-swap; already being
/// there counts as success).
async fn set_status(
    state: &AppState,
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
    AdminToken(_token): AdminToken,
    State(state): State<AppState>,
) -> Result<Json<WalletStatsResponse>, ApiError> {
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
    description = "Returns all wallets across all users, one cursor page at a time. Admin only.",
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
    AdminToken(_token): AdminToken,
    State(state): State<AppState>,
    Query(query): Query<CursorQuery>,
) -> Result<Json<AdminListWalletsResponse>, ApiError> {
    let page = state
        .storage
        .page_from(WALLETS_SCOPE, query.cursor.as_deref())?;
    let got = state
        .storage
        .wallets()
        .list(query.clamped_limit(), page)
        .await?;
    let entries: Vec<AdminWalletEntry> = got
        .items
        .into_iter()
        .map(|w| AdminWalletEntry {
            owner_user_id: w.owner_user_id.clone(),
            wallet: WalletResponse::from(w),
        })
        .collect();

    Ok(Json(AdminListWalletsResponse {
        wallets: entries,
        next_cursor: got
            .next
            .map(|next| state.storage.sign_cursor(WALLETS_SCOPE, &next)),
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
    ),
    responses(
        (status = 200, description = "Wallet suspended", body = WalletStatusChangeResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Admin role required"),
        (status = 404, description = "Wallet not found"),
    )
)]
pub async fn suspend_wallet(
    AdminToken(token): AdminToken,
    State(state): State<AppState>,
    Path(wallet_id): Path<String>,
) -> Result<Json<WalletStatusChangeResponse>, ApiError> {
    set_status(&state, &wallet_id, WalletStatus::Suspended, "suspend").await?;

    info!(
        wallet_id = %wallet_id,
        admin = %token.sub,
        "Wallet suspended by admin"
    );

    Ok(Json(WalletStatusChangeResponse {
        wallet_id,
        new_status: "suspended".to_string(),
    }))
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
    ),
    responses(
        (status = 200, description = "Wallet activated", body = WalletStatusChangeResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Admin role required"),
        (status = 404, description = "Wallet not found"),
    )
)]
pub async fn activate_wallet(
    AdminToken(token): AdminToken,
    State(state): State<AppState>,
    Path(wallet_id): Path<String>,
) -> Result<Json<WalletStatusChangeResponse>, ApiError> {
    set_status(&state, &wallet_id, WalletStatus::Active, "activate").await?;

    info!(
        wallet_id = %wallet_id,
        admin = %token.sub,
        "Wallet activated by admin"
    );

    Ok(Json(WalletStatusChangeResponse {
        wallet_id,
        new_status: "active".to_string(),
    }))
}
