// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Wallet API endpoint handlers.
//!
//! Each sub-module groups related endpoints. The [`wallet_router`] function
//! assembles all routes into a single Axum sub-router that is merged into
//! the application root.

pub mod admin;
pub mod balance;
pub mod credentials;
pub mod pools;
pub mod transactions;
pub mod users;
pub mod wallets;

use axum::{
    routing::{get, post},
    Router,
};
use serde::Deserialize;
use utoipa::IntoParams;

use crate::error::ApiError;
use crate::state::AppState;
use crate::storage::wallets::{WalletMetadata, WalletStatus};

// ============================================================================
// Shared pagination query
// ============================================================================

fn default_page_limit() -> usize {
    50
}

/// Cursor pagination: pass the previous response's `next_cursor` as
/// `cursor` to get the next page. Cursors are signed, and any worker
/// accepts them.
#[derive(Debug, Deserialize, IntoParams)]
pub struct CursorQuery {
    /// `next_cursor` from the previous page; omit for the first page.
    pub cursor: Option<String>,
    /// Maximum number of items to return (default 50, max 200).
    #[serde(default = "default_page_limit")]
    pub limit: usize,
}

impl CursorQuery {
    /// Clamp limit to `[1, 200]`.
    pub fn clamped_limit(&self) -> usize {
        self.limit.clamp(1, 200)
    }
}

/// Reject callers who don't own the wallet.
pub(crate) fn enforce_owner(wallet: &WalletMetadata, caller_sub: &str) -> Result<(), ApiError> {
    if wallet.owner_user_id != caller_sub {
        tracing::warn!(wallet_id = %wallet.wallet_id, caller = %caller_sub, "Caller doesn't own the wallet");
        return Err(ApiError::forbidden("you do not own this resource"));
    }
    Ok(())
}

/// Load a wallet, or 404.
pub(crate) async fn load_wallet(
    state: &AppState,
    wallet_id: &str,
) -> Result<WalletMetadata, ApiError> {
    state
        .storage
        .wallets()
        .get(wallet_id)
        .await?
        .ok_or_else(|| ApiError::not_found(format!("wallet {wallet_id} not found")))
}

/// Check that the caller owns the wallet and the wallet is not deleted/suspended.
///
/// Shared helper used by balance, transaction, and other wallet-scoped endpoints.
pub(crate) fn enforce_owner_active(
    wallet: &WalletMetadata,
    caller_sub: &str,
) -> Result<(), ApiError> {
    enforce_owner(wallet, caller_sub)?;
    if wallet.status == WalletStatus::Deleted {
        return Err(ApiError::not_found(format!(
            "wallet {} not found",
            wallet.wallet_id
        )));
    }
    if wallet.status == WalletStatus::Suspended {
        return Err(ApiError::forbidden(format!(
            "wallet {} is suspended",
            wallet.wallet_id
        )));
    }
    Ok(())
}

/// Resolve the active wallet for a user through the owner index.
///
/// Returns `(WalletMetadata)` if the user has an active wallet,
/// or an `ApiError` if no wallet found or wallet is not active.
pub(crate) async fn get_active_wallet_for_user(
    state: &AppState,
    user_id: &str,
) -> Result<WalletMetadata, ApiError> {
    let wallets = state.storage.wallets();
    let meta = match wallets.wallet_id_for_owner(user_id).await? {
        Some(wallet_id) => wallets.get(&wallet_id).await?,
        None => None,
    }
    .ok_or_else(|| ApiError::bad_request("no wallet found for user"))?;

    if meta.status != WalletStatus::Active {
        return Err(ApiError::bad_request("wallet is not active"));
    }

    Ok(meta)
}

/// Build the wallet-service routes (nested under `/v1`).
pub fn wallet_router() -> Router<AppState> {
    Router::new()
        // ── User identity ───────────────────────────────────────
        .route("/v1/users/me", get(users::get_me))
        // ── Wallet CRUD ─────────────────────────────────────────
        .route("/v1/wallets", get(wallets::list_wallets))
        .route("/v1/wallets", post(wallets::create_wallet))
        .route("/v1/wallets/{wallet_id}", get(wallets::get_wallet))
        .route(
            "/v1/wallets/{wallet_id}",
            axum::routing::delete(wallets::delete_wallet),
        )
        // ── Balance ─────────────────────────────────────────────
        .route("/v1/wallets/{wallet_id}/balance", get(balance::get_balance))
        // ── Transactions ────────────────────────────────────────
        .route(
            "/v1/wallets/{wallet_id}/estimate",
            post(transactions::estimate_fee),
        )
        .route(
            "/v1/wallets/{wallet_id}/send",
            post(transactions::send_transaction),
        )
        .route(
            "/v1/wallets/{wallet_id}/transactions",
            get(transactions::list_transactions),
        )
        .route(
            "/v1/wallets/{wallet_id}/transactions/{signature}",
            get(transactions::get_transaction_status),
        )
        // ── Admin ───────────────────────────────────────────────
        .route("/v1/admin/wallet-stats", get(admin::get_wallet_stats))
        .route("/v1/admin/wallets", get(admin::list_all_wallets))
        .route(
            "/v1/admin/wallets/{wallet_id}/suspend",
            post(admin::suspend_wallet),
        )
        .route(
            "/v1/admin/wallets/{wallet_id}/activate",
            post(admin::activate_wallet),
        )
}

/// Build the DRT pool routes (nested under `/v1/drt`).
pub fn drt_router() -> Router<AppState> {
    Router::new()
        // ── Atomic create (new contract) ─────────────────────────
        .route("/v1/drt/pools/malta", post(pools::create_malta_pool))
        // ── Pool info ────────────────────────────────────────────
        .route("/v1/drt/pools/{pool_pda}", get(pools::get_pool))
        // ── On-chain DRT inspection ──────────────────────────────
        .route(
            "/v1/drt/pools/{pool_pda}/drt/{drt_name}",
            get(pools::get_drt),
        )
        // ── Schema upload ────────────────────────────────────────
        .route(
            "/v1/drt/pools/{pool_pda}/schema",
            post(credentials::upload_schema).get(credentials::get_schema),
        )
        // ── Credential issuance ─────────────────────────────────
        .route(
            "/v1/drt/pools/{pool_pda}/initialize",
            post(credentials::initialize_pool),
        )
        .route(
            "/v1/drt/pools/{pool_pda}/issue",
            post(credentials::issue_credentials),
        )
        .route(
            "/v1/drt/pools/{pool_pda}/revoke",
            post(credentials::revoke_credentials),
        )
        .route(
            "/v1/drt/pools/{pool_pda}/revocations",
            get(credentials::list_revocations),
        )
        .route(
            "/v1/drt/pools/{pool_pda}/summary",
            get(credentials::pool_summary),
        )
        .route(
            "/v1/drt/pools/{pool_pda}/issuance-log",
            get(credentials::get_issuance_log),
        )
        .route(
            "/v1/drt/pools/by-wallet/{wallet_id}",
            get(credentials::list_pools_by_wallet),
        )
        // ── Marketplace discovery ────────────────────────────────
        .route("/v1/drt/pools/list", get(credentials::list_all_pools))
}
