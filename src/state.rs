// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Shared application state.

use std::sync::Arc;

use crate::attestation::Attestation;
use crate::auth::JwksCache;
use crate::blockchain::SolanaClient;
use crate::health::Health;
use crate::history::History;
use crate::storage::Storage;
use crate::tee::WorkerKeys;

/// Shared application state passed to every handler via Axum's `State` extractor.
#[derive(Clone)]
pub struct AppState {
    /// The worker's released keys.
    pub keys: Arc<WorkerKeys>,
    /// The cached attestation token for the transport key.
    pub attestation: Arc<Attestation>,
    /// Readiness state, kept current in the background.
    pub health: Arc<Health>,

    // ── Auth (existing) ─────────────────────────────────────────
    /// Expected `aud` claim.
    pub audience: String,
    /// Cached AVS JWKS keys for token verification.
    pub jwks_cache: Arc<tokio::sync::RwLock<Option<JwksCache>>>,

    // ── Storage ─────────────────────────────────────────────────
    /// Encrypted Blob and Table storage.
    pub storage: Arc<Storage>,

    // ── Chain ───────────────────────────────────────────────────
    /// Solana RPC client.
    pub solana_client: Arc<SolanaClient>,
    /// Wallet history pages and parsed transactions, read from the chain.
    pub history: Arc<History>,
}

#[cfg(test)]
impl AppState {
    /// A worker with test keys, in-memory storage, and a Solana client that
    /// nothing answers.
    pub fn for_tests() -> Self {
        use crate::health::Certificate;
        use crate::tee::KeyName;

        let keys = Arc::new(crate::tee::tests::test_keys());
        let attestation = Arc::new(Attestation::new(&keys.get(KeyName::Transport).current));
        let certificate = Certificate::File {
            not_after: Some(chrono::Utc::now() + chrono::Duration::days(30)),
        };
        let health = Arc::new(Health::new(&keys, certificate));
        let unreachable = "http://127.0.0.1:9";
        Self {
            keys,
            attestation,
            health,
            audience: crate::config::AVS_AUDIENCE.to_string(),
            jwks_cache: Arc::new(tokio::sync::RwLock::new(None)),
            storage: Arc::new(crate::storage::tests::memory_storage()),
            solana_client: Arc::new(SolanaClient::new(
                unreachable,
                crate::blockchain::types::devnet_config(unreachable),
            )),
            history: Arc::new(History::new(8, std::time::Duration::from_secs(30), 8)),
        }
    }
}
