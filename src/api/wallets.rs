// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Wallet CRUD endpoints.
//!
//! - `POST /v1/wallets`           — create a new wallet
//! - `GET  /v1/wallets`           — list caller's wallets
//! - `GET  /v1/wallets/{id}`      — get wallet details
//! - `DELETE /v1/wallets/{id}`    — soft-delete a wallet

use axum::{
    extract::{Path, State},
    Json,
};
use serde::{Deserialize, Serialize};
use tracing::info;
use utoipa::ToSchema;

use crate::audit_log;
use crate::auth::UserToken;
use crate::blockchain::signing::generate_solana_keypair;
use crate::error::ApiError;
use crate::state::AppState;
use crate::storage::audit::AuditEventType;
use crate::storage::repository::wallets::{
    WalletMetadata, WalletRepository, WalletResponse, WalletStatus,
};

// ============================================================================
// Request / Response types
// ============================================================================

/// Request body for creating a wallet.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateWalletRequest {
    /// Optional human-readable label (max 64 chars).
    #[serde(default)]
    pub label: Option<String>,
}

/// Response after creating a wallet.
#[derive(Debug, Serialize, ToSchema)]
pub struct CreateWalletResponse {
    pub wallet: WalletResponse,
    /// Solana explorer URL for the new address.
    pub explorer_url: String,
}

/// Paginated list of wallets.
#[derive(Debug, Serialize, ToSchema)]
pub struct ListWalletsResponse {
    pub wallets: Vec<WalletResponse>,
    pub total: usize,
}

/// Envelope for a single wallet.
#[derive(Debug, Serialize, ToSchema)]
pub struct GetWalletResponse {
    pub wallet: WalletResponse,
}

/// Response after soft-deleting a wallet.
#[derive(Debug, Serialize, ToSchema)]
pub struct DeleteWalletResponse {
    pub status: String,
    pub wallet_id: String,
}

// ============================================================================
// Handlers
// ============================================================================

/// Create a new Solana wallet (Ed25519 keypair generated inside the enclave).
#[utoipa::path(
    post,
    path = "/v1/wallets",
    tag = "Wallets",
    summary = "Create wallet",
    description = "Generate a new Solana keypair inside SGX, store encrypted on disk, return public address.",
    security(("bearer_auth" = [])),
    request_body = CreateWalletRequest,
    responses(
        (status = 201, description = "Wallet created", body = CreateWalletResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 503, description = "Storage unavailable"),
    )
)]
pub async fn create_wallet(
    UserToken(token): UserToken,
    State(state): State<AppState>,
    Json(payload): Json<CreateWalletRequest>,
) -> Result<(axum::http::StatusCode, Json<CreateWalletResponse>), ApiError> {
    // Validate label length.
    if let Some(ref label) = payload.label {
        if label.len() > 64 {
            return Err(ApiError::bad_request("label must be at most 64 characters"));
        }
    }

    // Generate Ed25519 keypair.
    let (keypair_bytes, public_address) = generate_solana_keypair()?;
    let wallet_id = uuid::Uuid::new_v4().to_string();

    let metadata = WalletMetadata {
        wallet_id: wallet_id.clone(),
        owner_user_id: token.sub.clone(),
        public_address: public_address.clone(),
        created_at: chrono::Utc::now(),
        status: WalletStatus::Active,
        label: payload.label,
    };

    // Persist wallet to encrypted storage.
    let repo = WalletRepository::new(&state.storage);
    repo.create(&metadata, &keypair_bytes)?;

    // Register address→wallet mapping for the tx indexer.
    if let Err(e) = state.tx_db.register_address(&public_address, &wallet_id) {
        tracing::warn!(error = %e, "Failed to register address in tx database");
    }

    // Register owner→wallet mapping (enforces 1-wallet-per-user).
    match state.tx_db.register_wallet_owner(&token.sub, &wallet_id) {
        Ok(()) => {}
        Err(crate::storage::tx_database::TxDbError::DuplicateWallet(existing)) => {
            return Err(ApiError::bad_request(format!(
                "user already has a wallet: {existing}"
            )));
        }
        Err(e) => {
            tracing::warn!(error = %e, "Failed to register wallet owner in tx database");
        }
    }

    info!(
        wallet_id = %wallet_id,
        address = %public_address,
        owner = %token.sub,
        "Wallet created"
    );

    audit_log!(
        &state.storage,
        &state.tx_db,
        AuditEventType::WalletCreated,
        &token.sub,
        "wallet",
        &wallet_id
    );

    let explorer_url = state
        .solana_client
        .network()
        .explorer_address_url(&public_address);

    let response = CreateWalletResponse {
        wallet: WalletResponse::from(metadata),
        explorer_url,
    };

    Ok((axum::http::StatusCode::CREATED, Json(response)))
}

/// List the authenticated user's wallets.
#[utoipa::path(
    get,
    path = "/v1/wallets",
    tag = "Wallets",
    summary = "List wallets",
    description = "List all non-deleted wallets belonging to the authenticated user.",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Wallet list", body = ListWalletsResponse),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn list_wallets(
    UserToken(token): UserToken,
    State(state): State<AppState>,
) -> Result<Json<ListWalletsResponse>, ApiError> {
    let repo = WalletRepository::new(&state.storage);

    // O(1) lookup via redb index instead of O(W) filesystem scan.
    let wallets = match state.tx_db.get_wallet_id_by_owner(&token.sub)? {
        Some(wallet_id) => match repo.get(&wallet_id) {
            Ok(meta) if meta.status != WalletStatus::Deleted => vec![meta],
            _ => Vec::new(),
        },
        None => Vec::new(),
    };

    let total = wallets.len();
    let wallet_responses: Vec<WalletResponse> =
        wallets.into_iter().map(WalletResponse::from).collect();

    Ok(Json(ListWalletsResponse {
        wallets: wallet_responses,
        total,
    }))
}

/// Get a single wallet by ID (must be owned by the caller).
#[utoipa::path(
    get,
    path = "/v1/wallets/{wallet_id}",
    tag = "Wallets",
    summary = "Get wallet",
    description = "Returns wallet details. The caller must own the wallet.",
    security(("bearer_auth" = [])),
    params(
        ("wallet_id" = String, Path, description = "Wallet UUID"),
    ),
    responses(
        (status = 200, description = "Wallet details", body = GetWalletResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Not the wallet owner"),
        (status = 404, description = "Wallet not found"),
    )
)]
pub async fn get_wallet(
    UserToken(token): UserToken,
    State(state): State<AppState>,
    Path(wallet_id): Path<String>,
) -> Result<Json<GetWalletResponse>, ApiError> {
    let repo = WalletRepository::new(&state.storage);
    let metadata = repo.get_owned(&wallet_id, &token.sub)?;

    if metadata.status == WalletStatus::Deleted {
        return Err(ApiError::not_found(format!("wallet {wallet_id} not found")));
    }

    Ok(Json(GetWalletResponse {
        wallet: WalletResponse::from(metadata),
    }))
}

/// Soft-delete a wallet (marks as deleted, keypair preserved).
#[utoipa::path(
    delete,
    path = "/v1/wallets/{wallet_id}",
    tag = "Wallets",
    summary = "Delete wallet",
    description = "Soft-deletes a wallet. The keypair is preserved for potential recovery.",
    security(("bearer_auth" = [])),
    params(
        ("wallet_id" = String, Path, description = "Wallet UUID"),
    ),
    responses(
        (status = 200, description = "Wallet deleted", body = DeleteWalletResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Not the wallet owner"),
        (status = 404, description = "Wallet not found"),
    )
)]
pub async fn delete_wallet(
    UserToken(token): UserToken,
    State(state): State<AppState>,
    Path(wallet_id): Path<String>,
) -> Result<Json<DeleteWalletResponse>, ApiError> {
    let repo = WalletRepository::new(&state.storage);
    repo.get_owned(&wallet_id, &token.sub)?;

    repo.soft_delete(&wallet_id)?;

    // Remove owner → wallet mapping so user can create a new wallet.
    if let Err(e) = state.tx_db.remove_wallet_owner(&token.sub) {
        tracing::warn!(error = %e, "Failed to remove wallet owner from tx database");
    }

    info!(
        wallet_id = %wallet_id,
        owner = %token.sub,
        "Wallet soft-deleted"
    );

    audit_log!(
        &state.storage,
        &state.tx_db,
        AuditEventType::WalletDeleted,
        &token.sub,
        "wallet",
        &wallet_id
    );

    Ok(Json(DeleteWalletResponse {
        status: "deleted".to_string(),
        wallet_id,
    }))
}
