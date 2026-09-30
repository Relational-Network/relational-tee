// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Shared application state.

use std::sync::Arc;

use crate::attestation::Attestation;
use crate::auth::entra::Verifier;
use crate::blockchain::drt::pda::Commitments;
use crate::blockchain::SolanaClient;
use crate::edge::Limiter;
use crate::health::Health;
use crate::history::History;
use crate::reference_values::ReferenceValues;
use crate::seal::TransportKeys;
use crate::storage::Storage;

/// Shared application state passed to every handler via Axum's `State` extractor.
#[derive(Clone)]
pub struct AppState {
    /// The transport key versions sealed uploads open with.
    pub transport: Arc<TransportKeys>,
    /// The cached attestation token for the transport key.
    pub attestation: Arc<Attestation>,
    /// The environment's signed manifest of approved workloads.
    pub reference_values: Arc<ReferenceValues>,
    /// Readiness state, kept current in the background.
    pub health: Arc<Health>,

    // ── Auth ────────────────────────────────────────────────────
    /// Validates Entra ID access tokens.
    pub auth: Arc<Verifier>,

    // ── Edge ────────────────────────────────────────────────────
    /// The one origin CORS allows.
    pub dashboard_origin: Arc<str>,
    /// Per-IP and per-user rate limits.
    pub limiter: Arc<Limiter>,

    // ── Storage ─────────────────────────────────────────────────
    /// Sealed documents in Blob storage.
    pub storage: Arc<Storage>,

    // ── Chain ───────────────────────────────────────────────────
    /// Solana RPC client.
    pub solana_client: Arc<SolanaClient>,
    /// Grant commitments, under the environment's `commitment-key`.
    pub commitments: Arc<Commitments>,
    /// Wallet history pages and parsed transactions, read from the chain.
    pub history: Arc<History>,
}

#[cfg(test)]
impl AppState {
    /// A worker with test keys, storage in a temporary directory, and a
    /// Solana client that nothing answers.
    pub fn for_tests() -> Self {
        use crate::health::Certificate;
        use crate::tee::KeyName;

        let keys = crate::tee::tests::test_keys();
        let current = &keys.get(KeyName::Transport).current;
        let attestation = Arc::new(Attestation::new(current));
        let transport = Arc::new(TransportKeys::new(
            current.clone(),
            Arc::new(crate::tee::tests::Versions(Default::default())),
        ));
        let reference_values = Arc::new(ReferenceValues::new(
            Arc::new(crate::store::files::LocalFiles::temporary()),
            "dev",
            transport.clone(),
        ));
        let certificate = Certificate::TlsKey(crate::tls::tests::serving());
        let health = Arc::new(Health::new(&keys, certificate));
        let unreachable = "http://127.0.0.1:9";
        Self {
            transport,
            attestation,
            reference_values,
            health,
            auth: Arc::new(crate::auth::entra::tests::verifier()),
            dashboard_origin: "http://localhost:5173".into(),
            limiter: Arc::new(Limiter::new(&crate::config::RateLimits {
                ip_per_second: 1000,
                ip_burst: 1000,
                user_mutations_per_second: 1000,
            })),
            storage: Arc::new(crate::storage::tests::files_storage()),
            solana_client: Arc::new(SolanaClient::new(
                unreachable,
                crate::blockchain::types::devnet_config(unreachable),
            )),
            commitments: Arc::new(Commitments::derive(&keys.get(KeyName::Commitment).current)),
            history: Arc::new(History::new(8, std::time::Duration::from_secs(30), 8)),
        }
    }
}
