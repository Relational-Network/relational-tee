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
use crate::storage::ownership::OwnershipEnforcer;
use crate::storage::repository::wallets::{WalletMetadata, WalletRepository, WalletStatus};

// ============================================================================
// Shared pagination query
// ============================================================================

/// Reusable pagination query parameters (limit + offset).
#[derive(Debug, Deserialize, IntoParams)]
pub struct PaginationQuery {
    /// Maximum number of items to return (default 50, max 200).
    #[serde(default = "default_page_limit")]
    pub limit: usize,
    /// Offset for pagination (default 0).
    #[serde(default)]
    pub offset: usize,
}

fn default_page_limit() -> usize {
    50
}

impl PaginationQuery {
    /// Clamp limit to `[1, 200]`.
    pub fn clamped_limit(&self) -> usize {
        self.limit.clamp(1, 200)
    }
}

/// Check that the caller owns the wallet and the wallet is not deleted/suspended.
///
/// Shared helper used by balance, transaction, and other wallet-scoped endpoints.
pub(crate) fn enforce_owner_active(
    wallet: &WalletMetadata,
    caller_sub: &str,
) -> Result<(), ApiError> {
    wallet.verify_ownership(caller_sub)?;
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

/// Resolve the active wallet for a user via the O(1) redb index.
///
/// Returns `(WalletMetadata)` if the user has an active wallet,
/// or an `ApiError` if no wallet found or wallet is not active.
pub(crate) fn get_active_wallet_for_user(
    state: &AppState,
    user_id: &str,
) -> Result<WalletMetadata, ApiError> {
    let wallet_id = state
        .tx_db
        .get_wallet_id_by_owner(user_id)?
        .ok_or_else(|| ApiError::bad_request("no wallet found for user"))?;

    let repo = WalletRepository::new(&state.storage);
    let meta = repo.get(&wallet_id)?;

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
        .route("/v1/admin/audit/events", get(admin::query_audit_logs))
        .route(
            "/v1/admin/wallets/{wallet_id}/suspend",
            post(admin::suspend_wallet),
        )
        .route(
            "/v1/admin/wallets/{wallet_id}/activate",
            post(admin::activate_wallet),
        )
        .route("/v1/admin/log-role-change", post(admin::log_role_change))
}

/// Build the DRT pool routes (nested under `/v1/drt`).
pub fn drt_router() -> Router<AppState> {
    Router::new()
        // ── Atomic create (new contract) ─────────────────────────
        .route("/v1/drt/pools/malta", post(pools::create_malta_pool))
        .route("/v1/drt/pools/iob-erp", post(pools::create_iob_erp_pool))
        // ── Pool info ────────────────────────────────────────────
        .route("/v1/drt/pools/{pool_pda}", get(pools::get_pool))
        // ── On-chain DRT inspection ──────────────────────────────
        .route(
            "/v1/drt/pools/{pool_pda}/drt/{drt_name}",
            get(pools::get_drt),
        )
        // ── Admin grant lifecycle ────────────────────────────────
        .route("/v1/drt/pools/{pool_pda}/grant", post(admin::grant_right))
        .route(
            "/v1/drt/pools/{pool_pda}/revoke-grant",
            post(admin::revoke_grant),
        )
        .route(
            "/v1/drt/pools/{pool_pda}/grant/{analyst_id}/{drt_name}",
            get(admin::get_grant_status),
        )
        // ── Grant listing (access list + analyst view) ───────────
        .route(
            "/v1/drt/pools/{pool_pda}/grants",
            get(admin::list_pool_grants),
        )
        .route("/v1/drt/me/grants", get(admin::list_my_grants))
        // ── Events ───────────────────────────────────────────────
        .route("/v1/drt/events/{signature}", get(pools::get_tx_events)) // ── Schema upload ────────────────────────────────────────
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
            "/v1/drt/pools/{pool_pda}/audit",
            get(credentials::pool_audit),
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
