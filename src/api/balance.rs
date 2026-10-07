// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Balance query endpoints.
//!
//! - `GET /v1/wallets/{id}/balance` — the wallet's native SOL balance

use axum::{
    extract::{Path, State},
    Json,
};
use serde::Serialize;
use utoipa::ToSchema;

use crate::auth::{Caller, Permission};
use crate::blockchain::types::TokenBalance;
use crate::error::ApiError;
use crate::state::AppState;

use super::{enforce_owner_active, load_wallet};

// ============================================================================
// Response types
// ============================================================================

/// A wallet's balance: one entry, its native SOL.
#[derive(Debug, Serialize, ToSchema)]
pub struct BalanceResponse {
    pub wallet_id: String,
    pub address: String,
    pub network: String,
    pub balances: Vec<TokenBalance>,
}

// ============================================================================
// Handlers
// ============================================================================

/// Get a wallet's native SOL balance.
#[utoipa::path(
    get,
    path = "/v1/wallets/{wallet_id}/balance",
    tag = "Balance",
    summary = "Get wallet balance",
    description = "Returns the wallet's native SOL balance. SPL tokens the wallet holds, such as its pools' DRTs, aren't listed.",
    security(("bearer_auth" = [])),
    params(
        ("wallet_id" = String, Path, format = "uuid", description = "Wallet UUID"),
    ),
    responses(
        (status = 200, description = "Balance info", body = BalanceResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Not the wallet owner"),
        (status = 404, description = "Wallet not found"),
        (status = 503, description = "Solana RPC unavailable"),
    )
)]
pub async fn get_balance(
    caller: Caller,
    State(state): State<AppState>,
    Path(wallet_id): Path<String>,
) -> Result<Json<BalanceResponse>, ApiError> {
    caller.require(Permission::WalletsRead)?;
    let wallet = load_wallet(&state, &wallet_id).await?;
    enforce_owner_active(&wallet, &caller.user_id)?;

    // Fetch native SOL balance.
    let sol_balance = state
        .solana_client
        .get_native_balance(&wallet.public_address)
        .await?;

    Ok(Json(BalanceResponse {
        wallet_id,
        address: wallet.public_address,
        network: state.solana_client.network().name.to_string(),
        balances: vec![sol_balance],
    }))
}
