// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Balance query endpoints.
//!
//! - `GET /v1/wallets/{id}/balance` — full balance (native + SPL)

use axum::{
    extract::{Path, State},
    Json,
};
use serde::Serialize;
use utoipa::ToSchema;

use crate::auth::UserToken;
use crate::blockchain::types::TokenBalance;
use crate::error::ApiError;
use crate::state::AppState;
use crate::storage::repository::wallets::WalletRepository;

use super::enforce_owner_active;

// ============================================================================
// Response types
// ============================================================================

/// Full balance response (native SOL + known SPL tokens).
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

/// Get full balance for a wallet (native SOL; SPL expansion in future).
#[utoipa::path(
    get,
    path = "/v1/wallets/{wallet_id}/balance",
    tag = "Balance",
    summary = "Get wallet balance",
    description = "Returns native SOL balance (and SPL token balances in future) for a wallet.",
    security(("bearer_auth" = [])),
    params(
        ("wallet_id" = String, Path, description = "Wallet UUID"),
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
    UserToken(token): UserToken,
    State(state): State<AppState>,
    Path(wallet_id): Path<String>,
) -> Result<Json<BalanceResponse>, ApiError> {
    let repo = WalletRepository::new(&state.storage);
    let wallet = repo.get(&wallet_id)?;
    enforce_owner_active(&wallet, &token.sub)?;

    // Fetch native SOL balance.
    let sol_balance = state
        .solana_client
        .get_native_balance(&wallet.public_address)
        .await?;

    // TODO: extend with SPL token queries (configured mint list).

    Ok(Json(BalanceResponse {
        wallet_id,
        address: wallet.public_address,
        network: state.solana_client.network().name.to_string(),
        balances: vec![sol_balance],
    }))
}
