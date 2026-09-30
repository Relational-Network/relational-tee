// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Transaction endpoints.
//!
//! - `POST /v1/wallets/{id}/estimate`              — estimate transfer fee
//! - `POST /v1/wallets/{id}/send`                  — sign & broadcast transfer
//! - `GET  /v1/wallets/{id}/transactions`           — list tx history
//! - `GET  /v1/wallets/{id}/transactions/{sig}`     — single tx status
//!
//! History is read from Solana on demand (see [`crate::history`]).

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Response,
    Json,
};
use serde::{Deserialize, Serialize};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use std::str::FromStr;
use tracing::info;
use utoipa::{IntoParams, ToSchema};

use crate::audit;
use crate::auth::{Caller, Permission};
use crate::blockchain::signing::keypair_from_bytes_verified;
use crate::blockchain::transactions::native_transfer;
use crate::chain::{self, Effect};
use crate::error::ApiError;
use crate::history::{WalletRef, WalletTransaction};
use crate::idempotency::{Idempotent, JsonBody};
use crate::state::AppState;

use super::pools::signed;
use super::{enforce_owner_active, load_wallet};

// ============================================================================
// Request / Response types
// ============================================================================

/// Request for fee estimation.
#[derive(Debug, Deserialize, ToSchema)]
pub struct EstimateFeeRequest {
    /// Recipient Solana address (base58).
    pub recipient: String,
    /// Amount in lamports (for native SOL) or smallest units (SPL).
    pub amount: u64,
}

/// Fee estimation response.
#[derive(Debug, Serialize, ToSchema)]
pub struct EstimateFeeResponse {
    /// Estimated fee in lamports.
    pub estimated_fee_lamports: u64,
    /// Human-readable fee ("0.000005 SOL").
    pub estimated_fee_sol: String,
}

/// Request to send a transaction.
#[derive(Debug, Deserialize, ToSchema)]
pub struct SendTransactionRequest {
    /// Recipient Solana address (base58).
    pub recipient: String,
    /// Amount in lamports (for native SOL).
    pub amount: u64,
    /// Token type: `"native"` or `"spl:{mint_address}"`. Default: `"native"`.
    #[serde(default = "default_token")]
    pub token: String,
    /// SPL token decimals (only required when `token` starts with `spl:`).
    #[serde(default)]
    pub decimals: Option<u8>,
}

fn default_token() -> String {
    "native".to_string()
}

/// Send transaction response.
#[derive(Debug, Serialize, ToSchema)]
pub struct SendTransactionResponse {
    /// Base58-encoded transaction signature.
    pub signature: String,
    /// Solana Explorer URL.
    pub explorer_url: String,
    /// Wallet that sent the transaction.
    pub wallet_id: String,
}

/// Query params for listing transactions.
#[derive(Debug, Deserialize, IntoParams)]
pub struct ListTransactionsQuery {
    /// `next_cursor` from the previous page: the last signature it showed.
    pub cursor: Option<String>,
    /// Max items per page (default 20, max 100).
    pub limit: Option<usize>,
}

/// One page of a wallet's history, newest first.
#[derive(Debug, Serialize, ToSchema)]
pub struct ListTransactionsResponse {
    pub transactions: Vec<WalletTransaction>,
    /// Present when the page is full; pass it as `cursor` for the next one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// Single transaction status response.
#[derive(Debug, Serialize, ToSchema)]
pub struct TransactionStatusResponse {
    pub transaction: WalletTransaction,
}

// ============================================================================
// Handlers
// ============================================================================

/// Estimate the transfer fee.
#[utoipa::path(
    post,
    path = "/v1/wallets/{wallet_id}/estimate",
    tag = "Transactions",
    summary = "Estimate fee",
    description = "Estimate the network fee for a SOL transfer.",
    security(("bearer_auth" = [])),
    params(
        ("wallet_id" = String, Path, description = "Wallet UUID"),
    ),
    request_body = EstimateFeeRequest,
    responses(
        (status = 200, description = "Fee estimate", body = EstimateFeeResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Wallet not found"),
        (status = 422, description = "Invalid address"),
        (status = 503, description = "RPC unavailable"),
    )
)]
pub async fn estimate_fee(
    caller: Caller,
    State(state): State<AppState>,
    Path(wallet_id): Path<String>,
    Json(payload): Json<EstimateFeeRequest>,
) -> Result<Json<EstimateFeeResponse>, ApiError> {
    caller.require(Permission::WalletsRead)?;
    let wallet = load_wallet(&state, &wallet_id).await?;
    enforce_owner_active(&wallet, &caller.user_id)?;

    let from = Pubkey::from_str(&wallet.public_address)
        .map_err(|_| ApiError::internal("stored address is invalid"))?;
    let to = Pubkey::from_str(&payload.recipient)
        .map_err(|_| ApiError::unprocessable("invalid recipient address"))?;

    let fee = state
        .solana_client
        .estimate_fee(&from, &to, payload.amount)
        .await?;

    let fee_sol = fee as f64 / 1_000_000_000.0;

    Ok(Json(EstimateFeeResponse {
        estimated_fee_lamports: fee,
        estimated_fee_sol: format!("{fee_sol:.9} SOL"),
    }))
}

/// Sign and broadcast a transaction from the wallet.
///
/// The transfer follows the stored-transaction rule, so retries with the
/// same `Idempotency-Key` send it at most once.
#[utoipa::path(
    post,
    path = "/v1/wallets/{wallet_id}/send",
    tag = "Transactions",
    summary = "Send transaction",
    description = "Sign a transfer with the wallet's private key (inside the worker) and broadcast to Solana. Idempotent: retries with the same Idempotency-Key send one transfer.",
    security(("bearer_auth" = [])),
    params(
        ("wallet_id" = String, Path, description = "Wallet UUID"),
        ("Idempotency-Key" = String, Header, description = "A UUID naming this user action; reuse it on every retry"),
    ),
    request_body = SendTransactionRequest,
    responses(
        (status = 200, description = "Transaction sent", body = SendTransactionResponse),
        (status = 400, description = "Invalid request, or no Idempotency-Key"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Wallet not found"),
        (status = 422, description = "Invalid address or amount, or the Idempotency-Key was used for a different request"),
        (status = 503, description = "RPC unavailable"),
    )
)]
pub async fn send_transaction(
    caller: Caller,
    request: Idempotent,
    State(state): State<AppState>,
    Path(wallet_id): Path<String>,
    JsonBody {
        value: payload,
        bytes,
    }: JsonBody<SendTransactionRequest>,
) -> Result<Response, ApiError> {
    caller.require_admin()?;
    let mut op = open_or_replay!(state, &caller.user_id, request, &bytes);
    let wallet = load_wallet(&state, &wallet_id).await?;
    enforce_owner_active(&wallet, &caller.user_id)?;

    let recipient = Pubkey::from_str(&payload.recipient)
        .map_err(|_| ApiError::unprocessable("invalid recipient address"))?;

    if payload.amount == 0 {
        return Err(ApiError::bad_request("amount must be greater than zero"));
    }

    // Load keypair (never leaves the worker) and verify it matches the wallet.
    let keypair_bytes = state.storage.wallets().read_keypair(&wallet_id).await?;
    let keypair = keypair_from_bytes_verified(&keypair_bytes, &wallet.public_address)?;
    let owner = keypair.pubkey();

    let instructions = if payload.token == "native" {
        native_transfer(&owner, &recipient, payload.amount)
    } else if let Some(mint) = payload.token.strip_prefix("spl:") {
        let decimals = payload
            .decimals
            .ok_or_else(|| ApiError::bad_request("decimals required for SPL transfers"))?;
        state
            .solana_client
            .spl_transfer(&owner, &recipient, mint, payload.amount, decimals)
            .await?
    } else {
        return Err(ApiError::bad_request(
            "invalid token type — use \"native\" or \"spl:{mint}\"",
        ));
    };

    op.begin().await?;
    let signature = chain::run(
        &state.solana_client,
        &mut op,
        &Effect::Transfer,
        "confirmed",
        signed(&keypair, &instructions),
    )
    .await?;

    info!(
        wallet_id = %wallet_id,
        signature = %signature,
        recipient = %payload.recipient,
        amount = payload.amount,
        "Transaction sent"
    );
    audit::signature(&signature);
    state.history.invalidate(&wallet.public_address);
    state.history.invalidate(&payload.recipient);

    let response = SendTransactionResponse {
        explorer_url: state.solana_client.network().explorer_tx_url(&signature),
        signature,
        wallet_id,
    };
    op.finish(StatusCode::OK, &response).await
}

/// List transaction history for a wallet.
#[utoipa::path(
    get,
    path = "/v1/wallets/{wallet_id}/transactions",
    tag = "Transactions",
    summary = "List transactions",
    description = "The wallet's history, read from Solana, newest first. The cursor is the last signature of the previous page.",
    security(("bearer_auth" = [])),
    params(
        ("wallet_id" = String, Path, description = "Wallet UUID"),
        ListTransactionsQuery,
    ),
    responses(
        (status = 200, description = "Transaction list", body = ListTransactionsResponse),
        (status = 400, description = "Invalid cursor"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Wallet not found"),
        (status = 503, description = "Solana RPC unavailable"),
    )
)]
pub async fn list_transactions(
    caller: Caller,
    State(state): State<AppState>,
    Path(wallet_id): Path<String>,
    Query(query): Query<ListTransactionsQuery>,
) -> Result<Json<ListTransactionsResponse>, ApiError> {
    caller.require(Permission::WalletsRead)?;
    let wallet = load_wallet(&state, &wallet_id).await?;
    enforce_owner_active(&wallet, &caller.user_id)?;

    let limit = query.limit.unwrap_or(20).clamp(1, 100);
    let cursor = query.cursor.as_deref().filter(|c| !c.is_empty());
    let page = state
        .history
        .page(
            &state.solana_client,
            &WalletRef {
                wallet_id: &wallet_id,
                address: &wallet.public_address,
            },
            cursor,
            limit,
        )
        .await?;

    Ok(Json(ListTransactionsResponse {
        transactions: page.items,
        next_cursor: page.next_cursor,
    }))
}

/// Get a single transaction by signature.
#[utoipa::path(
    get,
    path = "/v1/wallets/{wallet_id}/transactions/{signature}",
    tag = "Transactions",
    summary = "Get transaction",
    description = "One transaction that touches the wallet, read from Solana by its signature.",
    security(("bearer_auth" = [])),
    params(
        ("wallet_id" = String, Path, description = "Wallet UUID"),
        ("signature" = String, Path, description = "Transaction signature (base58)"),
    ),
    responses(
        (status = 200, description = "Transaction details", body = TransactionStatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Transaction not found"),
    )
)]
pub async fn get_transaction_status(
    caller: Caller,
    State(state): State<AppState>,
    Path((wallet_id, signature)): Path<(String, String)>,
) -> Result<Json<TransactionStatusResponse>, ApiError> {
    caller.require(Permission::WalletsRead)?;
    let wallet = load_wallet(&state, &wallet_id).await?;
    enforce_owner_active(&wallet, &caller.user_id)?;

    // Only transactions that touch this wallet are visible.
    let transaction = state
        .history
        .transaction(
            &state.solana_client,
            &WalletRef {
                wallet_id: &wallet_id,
                address: &wallet.public_address,
            },
            &signature,
        )
        .await?
        .ok_or_else(|| {
            ApiError::not_found(format!(
                "transaction {signature} not found for wallet {wallet_id}"
            ))
        })?;

    Ok(Json(TransactionStatusResponse { transaction }))
}
