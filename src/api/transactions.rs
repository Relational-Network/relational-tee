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
use chrono::Utc;
use serde::{Deserialize, Serialize};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use std::str::FromStr;
use tracing::info;
use utoipa::{IntoParams, ToSchema};

use crate::audit;
use crate::auth::{Caller, Permission};
use crate::blockchain::signing::keypair_from_bytes_verified;
use crate::blockchain::spl_token::spl_transfer;
use crate::blockchain::transactions::{create_receipt, native_transfer, receipt_address};
use crate::chain;
use crate::error::ApiError;
use crate::history::{WalletRef, WalletTransaction};
use crate::idempotency::{Idempotent, JsonBody};
use crate::ids;
use crate::state::AppState;
use crate::storage::receipts::Receipt;

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
    /// What the transfer's receipt holds, besides the amount and the fee,
    /// until it comes back to the wallet 8 days later.
    pub deposit_lamports: u64,
    /// Human-readable deposit ("0.000890880 SOL").
    pub deposit_sol: String,
}

/// `lamports` as SOL, to nine decimals, for display.
fn sol(lamports: u64) -> String {
    format!("{:.9} SOL", lamports as f64 / 1_000_000_000.0)
}

/// Request to send a transaction.
#[derive(Debug, Deserialize, ToSchema)]
pub struct SendTransactionRequest {
    /// Recipient Solana address (base58).
    pub recipient: String,
    /// Amount in lamports for native SOL, or in the token's smallest units.
    #[schema(minimum = 1)]
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
#[into_params(parameter_in = Query)]
pub struct ListTransactionsQuery {
    /// `next_cursor` from the previous page: the last signature it showed.
    pub cursor: Option<String>,
    /// Max items per page (default 20). Values above 100 count as 100.
    #[param(minimum = 1, maximum = 100)]
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
    description = "Estimate the network fee for a SOL transfer, and the deposit its receipt holds until it comes back to the wallet 8 days later.",
    security(("bearer_auth" = [])),
    params(
        ("wallet_id" = String, Path, format = "uuid", description = "Wallet UUID"),
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
    let deposit = state.solana_client.receipt_deposit().await?;

    Ok(Json(EstimateFeeResponse {
        estimated_fee_lamports: fee,
        estimated_fee_sol: sol(fee),
        deposit_lamports: deposit,
        deposit_sol: sol(deposit),
    }))
}

/// 400 `drt_not_transferable` if `mint` is any pool's Execute DRT. Analysis
/// grants are burns of those DRTs, and the program lets whoever holds one
/// burn it into a Grant, so they stay in their pool owner's wallet, whose
/// key only the worker holds: then every analysis Grant on-chain is one the
/// worker made.
async fn refuse_execute_drts(state: &AppState, mint: &str) -> Result<(), ApiError> {
    let Ok(mint) = Pubkey::from_str(mint) else {
        return Ok(());
    };
    let execute = state.storage.pools().all().await?.into_iter().any(|doc| {
        doc.analysis
            .as_ref()
            .and_then(|a| doc.drts.get(&a.analysis_id))
            .is_some_and(|drt| Pubkey::from_str(&drt.mint).ok() == Some(mint))
    });
    if execute {
        return Err(ApiError::bad_request(
            "a pool's Execute DRTs stay in its owner's wallet: grant analysts instead",
        )
        .with_code("drt_not_transferable"));
    }
    Ok(())
}

/// Sign and broadcast a transaction from the wallet.
///
/// The transfer creates a receipt in the same transaction, at an address the
/// request derives, so Solana lets at most one copy succeed, and retries
/// with the same `Idempotency-Key` find out from it whether it happened.
#[utoipa::path(
    post,
    path = "/v1/wallets/{wallet_id}/send",
    tag = "Transactions",
    summary = "Send transaction",
    description = "Sign a transfer with the wallet's private key (inside the worker) and broadcast to Solana. The transaction also creates the transfer's receipt, an account holding a deposit (see `POST …/estimate`) that comes back to the wallet 8 days later; Solana refuses a second transaction that creates the same receipt. Idempotent: retries with the same Idempotency-Key, for 7 days, send one transfer.",
    security(("bearer_auth" = [])),
    params(
        ("wallet_id" = String, Path, format = "uuid", description = "Wallet UUID"),
        ("Idempotency-Key" = String, Header, format = "uuid", description = "A UUID naming this user action; reuse it on every retry"),
    ),
    request_body = SendTransactionRequest,
    responses(
        (status = 200, description = "Transaction sent", body = SendTransactionResponse),
        (status = 400, description = "An amount of zero, an invalid token, a pool's Execute DRT (`drt_not_transferable`), no Idempotency-Key, Solana refused the transaction (`transaction_rejected`), or another transaction holds the receipt address, so the transfer didn't happen (`receipt_taken`)"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Wallet not found"),
        (status = 422, description = "An invalid recipient address, or the Idempotency-Key was used for a different request"),
        (status = 502, description = "The receipt exists, but no Solana node reports the transaction that made it (`transfer_outcome_unknown`): check the signature in the message on an explorer before sending again"),
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
    if let Some(mint) = payload.token.strip_prefix("spl:") {
        refuse_execute_drts(&state, mint).await?;
    }

    // Load keypair (never leaves the worker) and verify it matches the wallet.
    let keypair_bytes = state.storage.wallets().read_keypair(&wallet_id).await?;
    let keypair = keypair_from_bytes_verified(&keypair_bytes, &wallet.public_address)?;
    let owner = keypair.pubkey();

    let transfer = if payload.token == "native" {
        native_transfer(&owner, &recipient, payload.amount)
    } else if let Some(mint) = payload.token.strip_prefix("spl:") {
        let decimals = payload
            .decimals
            .ok_or_else(|| ApiError::bad_request("decimals required for SPL transfers"))?;
        spl_transfer(&owner, &recipient, mint, payload.amount, decimals)?
    } else {
        return Err(ApiError::bad_request(
            "invalid token type — use \"native\" or \"spl:{mint}\"",
        ));
    };
    // The receipt comes first: a refusal to create it is then this
    // transaction's instruction 0.
    let seed = ids::receipt_seed(&caller.user_id, &wallet_id, &request.key);
    let receipt = receipt_address(&owner, &seed)?;
    let deposit = state.solana_client.receipt_deposit().await?;
    let mut instructions = vec![create_receipt(&owner, &receipt, &seed, deposit)];
    instructions.extend(transfer);

    op.begin().await?;
    state
        .storage
        .receipts()
        .record(&Receipt {
            seed,
            wallet_id: wallet_id.clone(),
            address: receipt.to_string(),
            record: op.record_path().to_string(),
            created_at: Utc::now(),
            swept_at: None,
            sweep_signature: None,
        })
        .await?;
    let signature = chain::run_transfer(
        &state.solana_client,
        &mut op,
        &receipt,
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
    crate::fault::point("recorded");
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
        ("wallet_id" = String, Path, format = "uuid", description = "Wallet UUID"),
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
        ("wallet_id" = String, Path, format = "uuid", description = "Wallet UUID"),
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

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering::SeqCst;

    use axum::body::Body;
    use axum::http::{header, Request, StatusCode};
    use serde_json::json;

    use crate::api::credentials::tests::{send, worker};
    use crate::api::grants::tests::{analysis_pool, ANALYSIS};
    use crate::blockchain::drt::types::APPEND_DRT_NAME;
    use crate::idempotency::KEY_HEADER;
    use crate::storage::receipts::Receipt;

    #[tokio::test]
    async fn a_pools_execute_drts_stay_in_its_owners_wallet() {
        let worker = worker();
        let owner = worker.admin("oid-owner").await;
        let pool_pda = analysis_pool(&worker, &owner, 2).await;
        worker.chain.lands.store(true, SeqCst);
        let doc = worker
            .storage
            .pools()
            .get(&pool_pda.to_string())
            .await
            .unwrap()
            .unwrap();
        let send_drt = |name: &str| {
            let body = json!({
                "recipient": solana_pubkey::Pubkey::new_unique().to_string(),
                "amount": 1,
                "token": format!("spl:{}", doc.drts[name].mint),
                "decimals": 0,
            });
            Request::post(format!("/v1/wallets/{}/send", owner.wallet_id))
                .header(header::AUTHORIZATION, format!("Bearer {}", owner.token))
                .header(&KEY_HEADER, uuid::Uuid::new_v4().to_string())
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap()
        };

        let (status, _, refused) = send(&worker.app, send_drt(ANALYSIS)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
        assert_eq!(refused["code"], "drt_not_transferable");
        assert!(worker.chain.sent().is_empty());

        let (status, _, sent) = send(&worker.app, send_drt(APPEND_DRT_NAME)).await;
        assert_eq!(status, StatusCode::OK, "append DRTs still send: {sent}");
        assert_eq!(worker.chain.sent().len(), 1);
    }

    #[tokio::test]
    async fn a_send_makes_its_receipt_once_and_the_estimate_names_the_deposit() {
        use crate::blockchain::fake::RECEIPT_DEPOSIT;
        use crate::blockchain::transactions::receipt_address;

        let worker = worker();
        let owner = worker.admin("oid-owner").await;
        worker.chain.lands.store(true, SeqCst);
        let recipient = solana_pubkey::Pubkey::new_unique().to_string();
        let post = |route: &str, key: Option<&str>| {
            let mut request = Request::post(format!("/v1/wallets/{}/{route}", owner.wallet_id))
                .header(header::AUTHORIZATION, format!("Bearer {}", owner.token))
                .header(header::CONTENT_TYPE, "application/json");
            if let Some(key) = key {
                request = request.header(&KEY_HEADER, key);
            }
            let body = json!({ "recipient": recipient, "amount": 5 });
            request.body(Body::from(body.to_string())).unwrap()
        };

        let (status, _, estimate) = send(&worker.app, post("estimate", None)).await;
        assert_eq!(status, StatusCode::OK, "{estimate}");
        assert_eq!(estimate["deposit_lamports"], RECEIPT_DEPOSIT);
        assert_eq!(estimate["deposit_sol"], "0.000890880 SOL");

        let key = uuid::Uuid::new_v4().to_string();
        let (status, _, sent) = send(&worker.app, post("send", Some(&key))).await;
        assert_eq!(status, StatusCode::OK, "{sent}");
        let seed = crate::ids::receipt_seed(&owner.user_id, &owner.wallet_id, &key);
        let receipt = receipt_address(&owner.address, &seed).unwrap();
        assert!(worker.chain.exists(&receipt));
        let recorded = || async {
            worker
                .storage
                .state()
                .list_json::<Receipt>("receipts/", |_| true)
                .await
                .unwrap()
        };
        let receipts = recorded().await;
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].address, receipt.to_string());
        // Its request's idempotency record is still there, so it isn't due.
        let later = chrono::Utc::now() + chrono::Duration::minutes(1);
        assert!(worker
            .storage
            .receipts()
            .due(later)
            .await
            .unwrap()
            .is_empty());

        // A retry replays; a new action is a new transfer with a receipt of
        // its own.
        let (status, _, again) = send(&worker.app, post("send", Some(&key))).await;
        assert_eq!((status, &again), (StatusCode::OK, &sent));
        assert_eq!(worker.chain.sent().len(), 1);
        let (status, _, other) = send(
            &worker.app,
            post("send", Some(&uuid::Uuid::new_v4().to_string())),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{other}");
        assert_ne!(other["signature"], sent["signature"]);
        assert_eq!(recorded().await.len(), 2);
    }
}
