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
    http::StatusCode,
    response::Response,
    Json,
};
use serde::{Deserialize, Serialize};
use tracing::info;
use utoipa::ToSchema;

use crate::audit;
use crate::auth::{Caller, Permission};
use crate::blockchain::signing::{generate_solana_keypair, keypair_from_bytes};
use crate::error::ApiError;
use crate::idempotency::{Idempotent, JsonBody};
use crate::ids;
use crate::state::AppState;
use crate::storage::wallets::{CreateOutcome, NewKeypair, WalletResponse, WalletStatus};

use super::{enforce_owner, load_wallet};

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

/// The caller's wallets (at most one).
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
///
/// The wallet's ID derives from the caller and the `Idempotency-Key`; a
/// retry reuses the keypair an earlier attempt stored.
#[utoipa::path(
    post,
    path = "/v1/wallets",
    tag = "Wallets",
    summary = "Create wallet",
    description = "Generate a new Solana keypair inside the worker, store it encrypted, and return its public address. A user has at most one wallet.",
    security(("bearer_auth" = [])),
    params(
        ("Idempotency-Key" = String, Header, description = "A UUID naming this user action; reuse it on every retry"),
    ),
    request_body = CreateWalletRequest,
    responses(
        (status = 201, description = "Wallet created", body = CreateWalletResponse),
        (status = 400, description = "Invalid request, or no Idempotency-Key"),
        (status = 401, description = "Unauthorized"),
        (status = 409, description = "The user already has a wallet"),
        (status = 422, description = "The Idempotency-Key was used for a different request"),
        (status = 503, description = "Storage unavailable"),
    )
)]
pub async fn create_wallet(
    caller: Caller,
    request: Idempotent,
    State(state): State<AppState>,
    JsonBody {
        value: payload,
        bytes,
    }: JsonBody<CreateWalletRequest>,
) -> Result<Response, ApiError> {
    caller.require_admin()?;
    let mut op = open_or_replay!(state, &caller.user_id, request, &bytes);

    // Validate label length.
    if let Some(ref label) = payload.label {
        if label.len() > 64 {
            return Err(ApiError::bad_request("label must be at most 64 characters"));
        }
    }

    // Generate Ed25519 keypair.
    let (keypair_bytes, public_address) = generate_solana_keypair()?;
    let keypair = NewKeypair {
        bytes: zeroize::Zeroizing::new(keypair_bytes),
        address: public_address,
    };
    let wallet_id = ids::wallet_id(&caller.user_id, &request.key);

    op.begin().await?;
    let address_of = |bytes: &[u8]| {
        use solana_signer::Signer;
        keypair_from_bytes(bytes)
            .ok()
            .map(|k| k.pubkey().to_string())
    };
    let wallet = match state
        .storage
        .wallets()
        .create(
            &caller.user_id,
            &wallet_id,
            payload.label,
            keypair,
            address_of,
        )
        .await?
    {
        CreateOutcome::Created(wallet) => wallet,
        CreateOutcome::OwnerHasWallet(existing) => {
            return Err(
                ApiError::conflict(format!("user already has a wallet: {existing}"))
                    .with_code("wallet_exists"),
            );
        }
    };

    info!(
        wallet_id = %wallet_id,
        address = %wallet.public_address,
        owner = %caller.user_id,
        "Wallet created"
    );
    audit::wallet(&wallet_id);

    let explorer_url = state
        .solana_client
        .network()
        .explorer_address_url(&wallet.public_address);

    let response = CreateWalletResponse {
        wallet: WalletResponse::from(wallet),
        explorer_url,
    };

    crate::fault::point("recorded");
    op.finish(StatusCode::CREATED, &response).await
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
    caller: Caller,
    State(state): State<AppState>,
) -> Result<Json<ListWalletsResponse>, ApiError> {
    caller.require(Permission::WalletsRead)?;
    let wallets = state.storage.wallets();
    let mine = match wallets.wallet_id_for_owner(&caller.user_id).await? {
        Some(wallet_id) => wallets
            .get(&wallet_id)
            .await?
            .filter(|w| w.status != WalletStatus::Deleted && w.owner_user_id == caller.user_id),
        None => None,
    };

    let wallet_responses: Vec<WalletResponse> =
        mine.into_iter().map(WalletResponse::from).collect();

    Ok(Json(ListWalletsResponse {
        total: wallet_responses.len(),
        wallets: wallet_responses,
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
    caller: Caller,
    State(state): State<AppState>,
    Path(wallet_id): Path<String>,
) -> Result<Json<GetWalletResponse>, ApiError> {
    caller.require(Permission::WalletsRead)?;
    let metadata = load_wallet(&state, &wallet_id).await?;
    enforce_owner(&metadata, &caller.user_id)?;

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
        ("Idempotency-Key" = String, Header, description = "A UUID naming this user action; reuse it on every retry"),
    ),
    responses(
        (status = 200, description = "Wallet deleted", body = DeleteWalletResponse),
        (status = 400, description = "No Idempotency-Key"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Not the wallet owner"),
        (status = 404, description = "Wallet not found"),
        (status = 422, description = "The Idempotency-Key was used for a different request"),
    )
)]
pub async fn delete_wallet(
    caller: Caller,
    request: Idempotent,
    State(state): State<AppState>,
    Path(wallet_id): Path<String>,
) -> Result<Response, ApiError> {
    caller.require_admin()?;
    let mut op = open_or_replay!(state, &caller.user_id, request, b"");
    let wallet = load_wallet(&state, &wallet_id).await?;
    enforce_owner(&wallet, &caller.user_id)?;

    op.begin().await?;
    state.storage.wallets().soft_delete(&wallet).await?;

    info!(
        wallet_id = %wallet_id,
        owner = %caller.user_id,
        "Wallet soft-deleted"
    );

    op.finish(
        StatusCode::OK,
        &DeleteWalletResponse {
            status: "deleted".to_string(),
            wallet_id,
        },
    )
    .await
}
