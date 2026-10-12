// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Thin wrapper around [`JsonRpcClient`] for common Solana queries.

use solana_pubkey::Pubkey;
use std::str::FromStr;
use tracing::debug;

use super::rpc::JsonRpcClient;
use super::types::{NetworkConfig, TokenBalance};
use crate::error::ApiError;

/// Async Solana RPC client wrapper.
///
/// Uses `confirmed` commitment (single confirmation, ~400ms) instead of
/// `finalized` (32 confirmations, ~15-30s).  This is safe for reads and
/// virtually all DRT operations on devnet/mainnet.
pub struct SolanaClient {
    pub(crate) rpc: JsonRpcClient,
    pub(crate) network: NetworkConfig,
    /// What a transfer's receipt account holds, once asked.
    receipt_deposit: tokio::sync::OnceCell<u64>,
}

impl SolanaClient {
    /// Create a new client for the given RPC URL and network.
    ///
    /// Defaults to `confirmed` commitment for fast transaction confirmation.
    pub fn new(rpc_url: &str, network: NetworkConfig) -> Self {
        Self {
            rpc: JsonRpcClient::new(rpc_url, "confirmed"),
            network,
            receipt_deposit: tokio::sync::OnceCell::new(),
        }
    }

    /// The lamports a transfer's receipt account holds: the rent-exempt
    /// minimum for an account with no data, which the network sets.
    pub async fn receipt_deposit(&self) -> Result<u64, ApiError> {
        self.receipt_deposit
            .get_or_try_init(|| async {
                self.rpc
                    .get_minimum_balance_for_rent_exemption(0)
                    .await
                    .map_err(|e| ApiError::rpc_unavailable(format!("rent lookup failed: {e}")))
            })
            .await
            .copied()
    }

    /// Get the network configuration.
    pub fn network(&self) -> &NetworkConfig {
        &self.network
    }

    /// Reference to the inner RPC client.
    pub fn rpc(&self) -> &JsonRpcClient {
        &self.rpc
    }

    /// Get native SOL balance for an address.
    pub async fn get_native_balance(&self, address: &str) -> Result<TokenBalance, ApiError> {
        let pubkey = Pubkey::from_str(address)
            .map_err(|_| ApiError::bad_request(format!("invalid Solana address: {address}")))?;
        let lamports = self
            .rpc
            .get_balance(&pubkey)
            .await
            .map_err(|e| ApiError::rpc_unavailable(format!("Solana RPC error: {e}")))?;
        debug!(address, lamports, "Fetched SOL balance");

        let sol = lamports as f64 / 1_000_000_000.0;
        Ok(TokenBalance {
            token: "SOL".to_string(),
            mint: String::new(),
            raw_amount: lamports.to_string(),
            ui_amount: format!("{sol:.9}"),
            decimals: 9,
        })
    }
}
