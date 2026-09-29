// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Transaction endpoints.
//!
//! - `POST /v1/wallets/{id}/estimate`              — estimate transfer fee
//! - `POST /v1/wallets/{id}/send`                  — sign & broadcast transfer
//! - `GET  /v1/wallets/{id}/transactions`           — list tx history
//! - `GET  /v1/wallets/{id}/transactions/{sig}`     — single tx status

use axum::{
    extract::{Path, Query, State},
    Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use solana_pubkey::Pubkey;
use std::str::FromStr;
use tracing::{info, warn};
use utoipa::{IntoParams, ToSchema};

use crate::audit_log;
use crate::auth::UserToken;
use crate::blockchain::signing::keypair_from_bytes_verified;
use crate::error::ApiError;
use crate::indexer;
use crate::state::AppState;
use crate::storage::audit::AuditEventType;
use crate::storage::repository::transactions::{StoredTransaction, TokenType, TxStatus};
use crate::storage::repository::wallets::WalletRepository;

use super::enforce_owner_active;

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
    /// Cursor for pagination (opaque string from previous response).
    pub cursor: Option<String>,
    /// Max items per page (default 20, max 100).
    pub limit: Option<usize>,
}

/// Single transaction in the list.
#[derive(Debug, Serialize, ToSchema)]
pub struct TransactionEntry {
    #[serde(flatten)]
    pub tx: StoredTransaction,
    /// Whether the wallet was sender or receiver.
    pub direction: String,
}

/// Paginated transaction list response.
#[derive(Debug, Serialize, ToSchema)]
pub struct ListTransactionsResponse {
    pub transactions: Vec<TransactionEntry>,
    /// If present, pass as `cursor` in the next request to get more results.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// Single transaction status response.
#[derive(Debug, Serialize, ToSchema)]
pub struct TransactionStatusResponse {
    pub transaction: StoredTransaction,
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
    UserToken(token): UserToken,
    State(state): State<AppState>,
    Path(wallet_id): Path<String>,
    Json(payload): Json<EstimateFeeRequest>,
) -> Result<Json<EstimateFeeResponse>, ApiError> {
    let repo = WalletRepository::new(&state.storage);
    let wallet = repo.get(&wallet_id)?;
    enforce_owner_active(&wallet, &token.sub)?;

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
#[utoipa::path(
    post,
    path = "/v1/wallets/{wallet_id}/send",
    tag = "Transactions",
    summary = "Send transaction",
    description = "Sign a transfer with the wallet's private key (inside SGX) and broadcast to Solana.",
    security(("bearer_auth" = [])),
    params(
        ("wallet_id" = String, Path, description = "Wallet UUID"),
    ),
    request_body = SendTransactionRequest,
    responses(
        (status = 200, description = "Transaction sent", body = SendTransactionResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Wallet not found"),
        (status = 422, description = "Invalid address or amount"),
        (status = 503, description = "RPC unavailable"),
    )
)]
pub async fn send_transaction(
    UserToken(token): UserToken,
    State(state): State<AppState>,
    Path(wallet_id): Path<String>,
    Json(payload): Json<SendTransactionRequest>,
) -> Result<Json<SendTransactionResponse>, ApiError> {
    let repo = WalletRepository::new(&state.storage);
    let wallet = repo.get(&wallet_id)?;
    enforce_owner_active(&wallet, &token.sub)?;

    // Validate recipient.
    let _ = Pubkey::from_str(&payload.recipient)
        .map_err(|_| ApiError::unprocessable("invalid recipient address"))?;

    if payload.amount == 0 {
        return Err(ApiError::bad_request("amount must be greater than zero"));
    }

    // Load keypair (never leaves SGX memory) and verify it matches the wallet.
    let keypair_bytes = repo.read_keypair(&wallet_id)?;
    let keypair = keypair_from_bytes_verified(&keypair_bytes, &wallet.public_address)?;

    // Determine token type and send.
    let (result, token_type) = if payload.token == "native" {
        let r = state
            .solana_client
            .send_native(&keypair, &payload.recipient, payload.amount)
            .await?;
        (r, TokenType::Native)
    } else if let Some(mint) = payload.token.strip_prefix("spl:") {
        let decimals = payload
            .decimals
            .ok_or_else(|| ApiError::bad_request("decimals required for SPL transfers"))?;
        let r = state
            .solana_client
            .send_spl_token(&keypair, &payload.recipient, mint, payload.amount, decimals)
            .await?;
        (r, TokenType::SplToken(mint.to_string()))
    } else {
        return Err(ApiError::bad_request(
            "invalid token type — use \"native\" or \"spl:{mint}\"",
        ));
    };

    info!(
        wallet_id = %wallet_id,
        signature = %result.signature,
        recipient = %payload.recipient,
        amount = payload.amount,
        "Transaction sent"
    );

    // Store transaction in database.
    {
        let now = Utc::now();
        let stored = StoredTransaction {
            signature: result.signature.clone(),
            wallet_id: wallet_id.clone(),
            counterparty_wallet_id: None,
            from: wallet.public_address.clone(),
            to: payload.recipient.clone(),
            amount: payload.amount.to_string(),
            amount_lamports: Some(payload.amount),
            token: token_type,
            network: state.solana_client.network().name.to_string(),
            status: TxStatus::Confirmed,
            slot: None,
            fee_lamports: None,
            explorer_url: result.explorer_url.clone(),
            created_at: now,
            updated_at: now,
        };

        let directions = vec![
            (wallet.public_address.clone(), "sent"),
            (payload.recipient.clone(), "received"),
        ];

        if let Err(e) = state.tx_db.upsert_transaction(&stored, &directions) {
            tracing::warn!(error = %e, "Failed to save transaction to db");
        }

        // Invalidate tx cache for sender wallet.
        state.tx_cache.invalidate(&wallet.public_address);
    }

    audit_log!(
        &state.storage,
        &state.tx_db,
        AuditEventType::TransactionBroadcast,
        &token.sub,
        "wallet",
        &wallet_id
    );

    Ok(Json(SendTransactionResponse {
        signature: result.signature,
        explorer_url: result.explorer_url,
        wallet_id,
    }))
}

/// List transaction history for a wallet.
#[utoipa::path(
    get,
    path = "/v1/wallets/{wallet_id}/transactions",
    tag = "Transactions",
    summary = "List transactions",
    description = "Cursor-paginated transaction history for a wallet.",
    security(("bearer_auth" = [])),
    params(
        ("wallet_id" = String, Path, description = "Wallet UUID"),
        ListTransactionsQuery,
    ),
    responses(
        (status = 200, description = "Transaction list", body = ListTransactionsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Wallet not found"),
    )
)]
pub async fn list_transactions(
    UserToken(token): UserToken,
    State(state): State<AppState>,
    Path(wallet_id): Path<String>,
    Query(query): Query<ListTransactionsQuery>,
) -> Result<Json<ListTransactionsResponse>, ApiError> {
    let repo = WalletRepository::new(&state.storage);
    let wallet = repo.get(&wallet_id)?;
    enforce_owner_active(&wallet, &token.sub)?;

    let limit = query.limit.unwrap_or(20).min(100);
    let is_first_page = query.cursor.is_none();

    // Serve from cache when the caller requests the first page (no cursor).
    if is_first_page {
        if let Some(cached) = state.tx_cache.get_first_page(&wallet.public_address) {
            let transactions: Vec<TransactionEntry> = cached
                .into_iter()
                .take(limit)
                .map(|(tx, direction)| TransactionEntry { tx, direction })
                .collect();
            return Ok(Json(ListTransactionsResponse {
                transactions,
                next_cursor: None,
            }));
        }
    }

    // Pull fresh tx signatures for this wallet on demand.
    if let Err(e) = indexer::poller::sync_address_once(
        state.solana_client.as_ref(),
        state.tx_db.as_ref(),
        &state.tx_cache,
        &wallet.public_address,
        &wallet_id,
    )
    .await
    {
        warn!(
            wallet_id = %wallet_id,
            address = %wallet.public_address,
            error = %e,
            "On-demand transaction sync failed"
        );
    }

    let (entries, next_cursor) = state
        .tx_db
        .list_by_wallet(&wallet.public_address, query.cursor.as_deref(), limit)
        .map_err(|e| ApiError::internal(format!("tx database error: {e}")))?;

    // Populate cache for first-page results so subsequent identical requests
    // are served without hitting redb.
    if is_first_page {
        state
            .tx_cache
            .put_first_page(&wallet.public_address, entries.clone());
    }

    let transactions: Vec<TransactionEntry> = entries
        .into_iter()
        .map(|(tx, direction)| TransactionEntry { tx, direction })
        .collect();

    Ok(Json(ListTransactionsResponse {
        transactions,
        next_cursor,
    }))
}

/// Get a single transaction by signature.
#[utoipa::path(
    get,
    path = "/v1/wallets/{wallet_id}/transactions/{signature}",
    tag = "Transactions",
    summary = "Get transaction",
    description = "Get details of a single transaction by its signature.",
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
    UserToken(token): UserToken,
    State(state): State<AppState>,
    Path((wallet_id, signature)): Path<(String, String)>,
) -> Result<Json<TransactionStatusResponse>, ApiError> {
    let repo = WalletRepository::new(&state.storage);
    let wallet = repo.get(&wallet_id)?;
    enforce_owner_active(&wallet, &token.sub)?;

    // Refresh this wallet before looking up the requested signature.
    if let Err(e) = indexer::poller::sync_address_once(
        state.solana_client.as_ref(),
        state.tx_db.as_ref(),
        &state.tx_cache,
        &wallet.public_address,
        &wallet_id,
    )
    .await
    {
        warn!(
            wallet_id = %wallet_id,
            address = %wallet.public_address,
            error = %e,
            "On-demand transaction sync failed"
        );
    }

    let tx = state
        .tx_db
        .get_transaction(&signature)
        .map_err(|e| ApiError::internal(format!("tx database error: {e}")))?
        .ok_or_else(|| ApiError::not_found(format!("transaction {signature} not found")))?;

    // Ensure the transaction belongs to this wallet.
    if tx.wallet_id != wallet_id {
        return Err(ApiError::not_found(format!(
            "transaction {signature} not found for wallet {wallet_id}"
        )));
    }

    Ok(Json(TransactionStatusResponse { transaction: tx }))
}
