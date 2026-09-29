// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Extended application state with wallet service dependencies.

use std::sync::Arc;

use crate::auth::JwksCache;
use crate::blockchain::SolanaClient;
use crate::storage::tx_cache::TxCache;
use crate::storage::tx_database::TxDatabase;
use crate::storage::EncryptedStorage;

/// Shared application state passed to every handler via Axum's `State` extractor.
#[derive(Clone)]
pub struct AppState {
    // ── Auth (existing) ─────────────────────────────────────────
    /// Expected `aud` claim.
    pub audience: String,
    /// Cached AVS JWKS keys for token verification.
    pub jwks_cache: Arc<tokio::sync::RwLock<Option<JwksCache>>>,

    // ── Wallet service ──────────────────────────────────────────
    /// Encrypted filesystem for wallet metadata + keypairs.
    pub storage: Arc<EncryptedStorage>,
    /// Solana RPC client.
    pub solana_client: Arc<SolanaClient>,
    /// Embedded transaction database (redb). Required — enclave panics if init fails.
    pub tx_db: Arc<TxDatabase>,
    /// LRU cache for first-page tx queries.
    pub tx_cache: Arc<TxCache>,

    // ── Pool concurrency ────────────────────────────────────────
    /// Per-pool mutexes to serialize issuance operations on `pool.meta.json`.
    pub pool_locks: Arc<dashmap::DashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}
