// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Solana network configuration and shared types.

use serde::{Deserialize, Serialize};

/// Network configuration for Solana cluster.
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub name: &'static str,
    pub rpc_url: String,
    pub explorer_url: &'static str,
    pub explorer_suffix: &'static str,
}

impl NetworkConfig {
    /// Construct a Solana Explorer URL for a transaction signature.
    pub fn explorer_tx_url(&self, signature: &str) -> String {
        format!(
            "{}/tx/{}{}",
            self.explorer_url, signature, self.explorer_suffix
        )
    }

    /// Construct a Solana Explorer URL for an address.
    pub fn explorer_address_url(&self, address: &str) -> String {
        format!(
            "{}/address/{}{}",
            self.explorer_url, address, self.explorer_suffix
        )
    }
}

/// Predefined devnet config.
pub fn devnet_config(rpc_url: &str) -> NetworkConfig {
    NetworkConfig {
        name: "Solana Devnet",
        rpc_url: rpc_url.to_string(),
        explorer_url: "https://explorer.solana.com",
        explorer_suffix: "?cluster=devnet",
    }
}

/// Predefined mainnet config.
pub fn mainnet_config(rpc_url: &str) -> NetworkConfig {
    NetworkConfig {
        name: "Solana Mainnet",
        rpc_url: rpc_url.to_string(),
        explorer_url: "https://explorer.solana.com",
        explorer_suffix: "",
    }
}

/// Build a NetworkConfig from the hardcoded config constants.
pub fn network_config_from_env() -> NetworkConfig {
    let rpc_url = crate::config::SOLANA_RPC_URL;
    let network = crate::config::SOLANA_NETWORK;
    match network {
        "mainnet" | "mainnet-beta" => mainnet_config(rpc_url),
        _ => devnet_config(rpc_url),
    }
}

/// Token balance response.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TokenBalance {
    /// Human-readable token name (e.g., "SOL", "USDC").
    pub token: String,
    /// Mint address (empty string for native SOL).
    pub mint: String,
    /// Raw amount in smallest units (lamports for SOL).
    pub raw_amount: String,
    /// Human-readable formatted amount with decimals.
    pub ui_amount: String,
    /// Number of decimal places.
    pub decimals: u8,
}

/// Result of a submitted transaction.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SendResult {
    /// Base58-encoded transaction signature.
    pub signature: String,
    /// Solana Explorer URL for this transaction.
    pub explorer_url: String,
}
