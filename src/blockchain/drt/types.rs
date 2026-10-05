// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! DRT types matching the deployed `digital_rights_tokens` contract
//! (`8N5hVnK81rWhwfhxt9LfjrbeVT83Jjgy4dKyy4q6HKjk`).

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use solana_pubkey::Pubkey;
use std::collections::BTreeMap;
use utoipa::ToSchema;

// ============================================================================
// Constants
// ============================================================================

/// Deployed program id (devnet). Canonical source: [`crate::config::DRT_PROGRAM_ID_STR`].
#[allow(unused_imports)]
pub use crate::config::DRT_PROGRAM_ID_STR;

/// SPL Token program (legacy). The new contract uses SPL Token v1, not Token-2022.
pub const TOKEN_PROGRAM_ID_STR: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

/// Associated Token Program.
pub const ASSOCIATED_TOKEN_PROGRAM_ID_STR: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";

/// System program.
pub const SYSTEM_PROGRAM_ID_STR: &str = "11111111111111111111111111111111";

/// Rent sysvar.
pub const RENT_SYSVAR_ID_STR: &str = "SysvarRent111111111111111111111111111111111";

/// Logical name of the append-style DRT (no code, zero hash, admin-only).
pub const APPEND_DRT_NAME: &str = "append";

// ── Discriminators re-exported from idl_generated ───────────────

pub use super::idl_generated::{
    DISC_CREATE_POOL, DISC_DRT_CONFIG_ACCOUNT, DISC_GRANT_RIGHT, DISC_POOL_ACCOUNT,
    DISC_REGISTER_DRT, DISC_REVOKE_GRANT, DISC_SEAL_POOL,
};

// ── Limits ──────────────────────────────────────────────────────

pub const MAX_POOL_NAME_LEN: usize = 64;
pub const MAX_DRT_NAME_LEN: usize = 32;
pub const MAX_CODE_REPO_URL_LEN: usize = 256;
pub const MAX_DRTS_PER_POOL: usize = 8;
pub const MAX_SUPPLY: u64 = 1_000_000_000;

// ============================================================================
// On-chain Borsh account types
// ============================================================================

/// On-chain `Pool` account (8-byte discriminator stripped externally).
#[derive(Debug, Clone, BorshDeserialize, BorshSerialize)]
pub struct Pool {
    pub uuid: [u8; 16],
    pub owner: Pubkey,
    pub created_at: i64,
    pub sealed: bool,
    pub bump: u8,
}

/// On-chain `DrtConfig` account.
#[derive(Debug, Clone, BorshDeserialize, BorshSerialize)]
pub struct DrtConfig {
    pub pool: Pubkey,
    pub right_id: [u8; 16],
    pub mint: Pubkey,
    pub supply: u64,
    pub code_hash: [u8; 32],
    pub code_repo_url: String,
    pub created_at: i64,
    pub bump: u8,
}

// ============================================================================
// API request / response types
// ============================================================================

/// One DRT to register inside a pool: `append`, which has no code, or the
/// pool's analysis, with its definition's URL and hash.
#[derive(Debug, Clone)]
pub struct DrtRequest {
    pub name: String,
    /// Token supply minted to the admin's wallet at registration.
    pub supply: u64,
    pub code_repo_url: Option<String>,
    /// SHA-256 of the code as a 64-char hex string. Zero/empty for `append`.
    pub code_hash_hex: Option<String>,
}

/// The analysis a new pool's Execute DRT pins.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AnalysisRequest {
    /// The definition's raw URL, under
    /// `https://raw.githubusercontent.com/relational-network/`.
    pub code_repo_url: String,
    /// SHA-256 of the definition, as 64 hex characters.
    pub code_hash_hex: String,
    /// Execute DRTs minted to the admin's wallet: one per analyst grant.
    pub supply: u64,
}

/// MALTA pool create request. The analysis's definition is also the pool's
/// schema.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateMaltaPoolRequest {
    pub wallet_id: String,
    pub pool_name: String,
    /// Append DRTs minted to the admin's wallet: one per issuance.
    pub append_supply: u64,
    pub analysis: AnalysisRequest,
}

/// Atomic create-pool response.
#[derive(Debug, Serialize, ToSchema)]
pub struct CreatePoolResponse {
    /// Final transaction signature (last in the bundle).
    pub signature: String,
    /// All transaction signatures, in submission order.
    pub signatures: Vec<String>,
    /// Pool PDA address (base58).
    pub pool_pda: String,
    /// 16-byte pool UUID (hex).
    pub pool_uuid: String,
    /// Map of DRT name → mint pubkey (base58).
    pub mints: BTreeMap<String, String>,
    /// Map of DRT name → right_id (hex).
    pub right_ids: BTreeMap<String, String>,
    /// Solana Explorer URL for the final signature.
    pub explorer_url: String,
}

/// API view of a DrtConfig.
#[derive(Debug, Serialize, ToSchema)]
pub struct DrtConfigResponse {
    pub name: String,
    pub right_id: String,
    pub mint: String,
    pub supply: u64,
    pub code_repo_url: String,
    pub code_hash: String,
}

/// API view of a Pool.
#[derive(Debug, Serialize, ToSchema)]
pub struct PoolInfoResponse {
    pub pool_pda: String,
    pub pool_uuid: String,
    pub name: String,
    pub kind: String,
    pub owner: String,
    pub sealed: bool,
    pub drts: Vec<DrtConfigResponse>,
}
