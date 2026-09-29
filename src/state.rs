// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Shared application state.

use std::sync::Arc;

use crate::attestation::Attestation;
use crate::auth::JwksCache;
use crate::blockchain::SolanaClient;
use crate::storage::tx_cache::TxCache;
use crate::storage::tx_database::TxDatabase;
use crate::storage::{EncryptedStorage, Storage};
use crate::tee::WorkerKeys;

/// Shared application state passed to every handler via Axum's `State` extractor.
#[derive(Clone)]
pub struct AppState {
    /// The worker's released keys.
    pub keys: Arc<WorkerKeys>,
    /// The cached attestation token for the transport key.
    pub attestation: Arc<Attestation>,

    // ── Auth (existing) ─────────────────────────────────────────
    /// Expected `aud` claim.
    pub audience: String,
    /// Cached AVS JWKS keys for token verification.
    pub jwks_cache: Arc<tokio::sync::RwLock<Option<JwksCache>>>,

    // ── Storage ─────────────────────────────────────────────────
    /// Encrypted Blob and Table storage: wallets, transactions, audit.
    pub storage: Arc<Storage>,
    /// Local files for pool metadata and datasets.
    pub files: Arc<EncryptedStorage>,
    /// Embedded database (redb) for pool indexes.
    pub tx_db: Arc<TxDatabase>,

    // ── Chain ───────────────────────────────────────────────────
    /// Solana RPC client.
    pub solana_client: Arc<SolanaClient>,
    /// LRU cache for first-page tx queries.
    pub tx_cache: Arc<TxCache>,

    // ── Pool concurrency ────────────────────────────────────────
    /// Per-pool mutexes to serialize issuance operations on `pool.meta.json`.
    pub pool_locks: Arc<dashmap::DashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}
