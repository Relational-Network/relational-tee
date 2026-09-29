// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Pool metadata persisted in the enclave's encrypted filesystem.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::data_validation::ValidationMode;

/// Operational shape of the pool.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolKind {
    /// CSV-driven pool. Admin uploads CSVs; schema mandatory, headers-only validation.
    #[default]
    Malta,
    /// ERP-driven pool. Data arrives via Jitterbit; no `append` DRT.
    IobErp,
}

/// Pool lifecycle state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolState {
    NeedsInit,
    Ready,
}

/// Per-DRT bookkeeping inside [`PoolMetadata`]. Mirrors what we put on-chain
/// during `register_drt` so the dashboard never has to call the chain just to
/// render a pool detail or list page.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrtMetadata {
    /// 16-byte right_id (hex).
    pub right_id_hex: String,
    /// Mint pubkey (base58).
    pub mint: String,
    /// Supply minted at registration.
    pub supply: u64,
    /// Script URL (empty for `append`).
    pub code_repo_url: String,
    /// SHA-256 of the script as hex (zero for `append`).
    pub code_hash_hex: String,
}

/// Enclave-side metadata for a DRT pool. Stored at
/// `/data/pools/{pool_pda}/pool.meta.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolMetadata {
    /// Pool PDA (base58-encoded Solana address).
    pub pool_pda: String,
    /// Human-readable pool name (not on-chain).
    pub pool_name: String,
    /// Operational shape of the pool.
    #[serde(default)]
    pub kind: PoolKind,
    /// 16-byte pool UUID (hex). Matches the seed used to derive `pool_pda`.
    #[serde(default)]
    pub pool_uuid_hex: String,
    /// DRT name → on-chain configuration (right_id, mint, supply, code).
    #[serde(default)]
    pub drts: BTreeMap<String, DrtMetadata>,
    /// Wallet ID of the pool owner (enclave-side wallet, not Solana pubkey).
    pub owner_wallet_id: String,
    /// Solana public key of the pool owner (base58).
    #[serde(default)]
    pub owner_pubkey: Option<String>,
    /// Schema id label (MALTA only — empty string for IOB ERP).
    pub schema_id: String,
    /// CSV validation strictness.
    #[serde(default)]
    pub validation_mode: ValidationMode,
    /// Current lifecycle state.
    pub state: PoolState,
    pub created_onchain_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initialized_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_issue_at: Option<DateTime<Utc>>,
    pub total_credentials: u64,
    pub revoked_count: u64,
}
