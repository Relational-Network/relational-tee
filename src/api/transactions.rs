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
use crate::storage::transactions::{StoredTransaction, TokenType, TxStatus};
use crate::storage::tx_cache::FirstPage;

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
    /// `next_cursor` from the previous page; any worker accepts it.
    pub cursor: Option<String>,
    /// Max items per page (default 20, max 100).
    pub limit: Option<usize>,
}

/// The cursor scope of a wallet's transaction list.
fn tx_scope(wallet_id: &str) -> String {
    format!("tx:{wallet_id}")
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
    let wallet = load_wallet(&state, &wallet_id).await?;
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
    description = "Sign a transfer with the wallet's private key (inside the worker) and broadcast to Solana.",
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
    let wallet = load_wallet(&state, &wallet_id).await?;
    enforce_owner_active(&wallet, &token.sub)?;

    // Validate recipient.
    let _ = Pubkey::from_str(&payload.recipient)
        .map_err(|_| ApiError::unprocessable("invalid recipient address"))?;

    if payload.amount == 0 {
        return Err(ApiError::bad_request("amount must be greater than zero"));
    }

    // Load keypair (never leaves the worker) and verify it matches the wallet.
    let keypair_bytes = state.storage.wallets().read_keypair(&wallet_id).await?;
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

        // The recipient's history gets it too when it's one of our wallets.
        let recipient_wallet = state
            .storage
            .wallets()
            .wallet_id_for_address(&payload.recipient)
            .await
            .unwrap_or_else(|e| {
                warn!(error = %e, "Recipient wallet lookup failed");
                None
            });
        let mut histories = vec![(wallet_id.clone(), "sent")];
        histories.extend(recipient_wallet.map(|id| (id, "received")));
        for (history, direction) in histories {
            if let Err(e) = state
                .storage
                .transactions()
                .upsert(&history, &stored, direction)
                .await
            {
                warn!(error = %e, wallet_id = %history, "Failed to store the transaction");
            }
            state.tx_cache.invalidate(&history);
        }
    }

    audit_log!(
        state,
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
    let wallet = load_wallet(&state, &wallet_id).await?;
    enforce_owner_active(&wallet, &token.sub)?;

    let limit = query.limit.unwrap_or(20).clamp(1, 100);
    let scope = tx_scope(&wallet_id);
    let page = state.storage.page_from(&scope, query.cursor.as_deref())?;
    let is_first_page = page.is_none();

    // Serve from cache when the caller requests the first page (no cursor).
    if is_first_page {
        if let Some(cached) = state.tx_cache.get_first_page(&wallet_id, limit) {
            return Ok(Json(ListTransactionsResponse {
                transactions: cached
                    .items
                    .into_iter()
                    .map(|(tx, direction)| TransactionEntry { tx, direction })
                    .collect(),
                next_cursor: cached.next_cursor,
            }));
        }

        // Pull fresh tx signatures for this wallet on demand.
        if let Err(e) = indexer::poller::sync_address_once(
            state.solana_client.as_ref(),
            &state.storage,
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
    }

    let got = state
        .storage
        .transactions()
        .list(&wallet_id, limit, page)
        .await?;
    let next_cursor = got
        .next
        .as_ref()
        .map(|next| state.storage.sign_cursor(&scope, next));

    // Populate cache for first-page results so subsequent identical requests
    // are served without a storage query.
    if is_first_page {
        state.tx_cache.put_first_page(
            &wallet_id,
            FirstPage {
                limit,
                items: got.items.clone(),
                next_cursor: next_cursor.clone(),
            },
        );
    }

    let transactions: Vec<TransactionEntry> = got
        .items
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
    let wallet = load_wallet(&state, &wallet_id).await?;
    enforce_owner_active(&wallet, &token.sub)?;

    // Refresh this wallet before looking up the requested signature.
    if let Err(e) = indexer::poller::sync_address_once(
        state.solana_client.as_ref(),
        &state.storage,
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

    // Only transactions in this wallet's own history are visible.
    let (tx, _) = state
        .storage
        .transactions()
        .get(&wallet_id, &signature)
        .await?
        .ok_or_else(|| {
            ApiError::not_found(format!(
                "transaction {signature} not found for wallet {wallet_id}"
            ))
        })?;

    Ok(Json(TransactionStatusResponse { transaction: tx }))
}
