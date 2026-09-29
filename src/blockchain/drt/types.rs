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
    DISC_CREATE_POOL, DISC_DRT_CONFIG_ACCOUNT, DISC_DRT_REGISTERED, DISC_GRANT_ACCOUNT,
    DISC_GRANT_RIGHT, DISC_POOL_ACCOUNT, DISC_POOL_CREATED, DISC_POOL_SEALED, DISC_REGISTER_DRT,
    DISC_REVOKE_GRANT, DISC_RIGHT_GRANTED, DISC_RIGHT_REVOKED, DISC_SEAL_POOL,
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

/// On-chain `Grant` account.
#[derive(Debug, Clone, BorshDeserialize, BorshSerialize)]
pub struct Grant {
    pub drt_config: Pubkey,
    pub granted_at: i64,
    pub bump: u8,
}

// ============================================================================
// API request / response types
// ============================================================================

/// One DRT to register inside a pool. Caller supplies supply and — for any
/// non-`append` DRT — the script URL and hash that the enclave will verify
/// at grant time.
///
/// The frontend pre-fills these from its own curated list; the operator can
/// override them. The server validates lengths and the append-specific rule
/// (no URL, zero hash).
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct DrtRequest {
    /// Human-readable name (`"append"`, `"mean"`, `"variance"`, …).
    pub name: String,
    /// Token supply minted to the admin's wallet at registration.
    pub supply: u64,
    /// Public URL of the script the enclave will run when this right is granted.
    /// Empty/absent for `append`.
    #[serde(default)]
    pub code_repo_url: Option<String>,
    /// SHA-256 of the script as a 64-char hex string. Zero/empty for `append`.
    #[serde(default)]
    pub code_hash_hex: Option<String>,
}

/// Field of a CSV schema (mirrors [`crate::data_validation::FieldSchema`]).
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct SchemaFieldRequest {
    pub name: String,
    pub field_type: serde_json::Value,
    #[serde(default)]
    pub nullable: bool,
}

/// Inline schema submitted with a MALTA pool create request.
///
/// `schema_id` is optional: if absent or empty the server generates a UUID.
/// The dashboard never asks the user for it — schemas are an internal
/// implementation detail of the pool, so we don't burden the operator with
/// inventing an identifier.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct InlineSchemaRequest {
    #[serde(default)]
    pub schema_id: Option<String>,
    pub fields: Vec<SchemaFieldRequest>,
}

/// MALTA pool create request. Schema is mandatory.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateMaltaPoolRequest {
    pub wallet_id: String,
    pub pool_name: String,
    pub drts: Vec<DrtRequest>,
    pub schema: InlineSchemaRequest,
}

/// IOB ERP pool create request. No schema; `append` DRT not allowed.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateIobErpPoolRequest {
    pub wallet_id: String,
    pub pool_name: String,
    pub drts: Vec<DrtRequest>,
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

/// Admin grant-right request — burns 1 admin-held DRT and writes a Grant PDA
/// keyed by `sha256(analyst_id ‖ pool_uuid ‖ right_id)`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct GrantRightRequest {
    pub wallet_id: String,
    /// DRT name to grant (must exist in the pool).
    pub drt_name: String,
    /// Analyst identifier (e.g. Clerk `sub`). Never persisted on-chain.
    pub analyst_id: String,
}

/// Admin revoke-grant request — closes the Grant PDA matching the commitment.
#[derive(Debug, Deserialize, ToSchema)]
pub struct RevokeGrantRequest {
    pub wallet_id: String,
    pub drt_name: String,
    pub analyst_id: String,
}

/// Single-signature grant/revoke response.
#[derive(Debug, Serialize, ToSchema)]
pub struct GrantResponse {
    pub signature: String,
    pub explorer_url: String,
    /// The commitment hash recorded on-chain (hex).
    pub commitment_hex: String,
    /// The Grant PDA address (base58).
    pub grant_pda: String,
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

// ============================================================================
// Event API response types
// ============================================================================

/// Wrapper for event list from a transaction.
#[derive(Debug, Serialize, ToSchema)]
pub struct TxEventsResponse {
    pub signature: String,
    pub events: Vec<DrtEventResponse>,
}

/// Single event in API format.
#[derive(Debug, Serialize, ToSchema)]
#[serde(tag = "type")]
pub enum DrtEventResponse {
    #[serde(rename = "pool_created")]
    PoolCreated {
        pool: String,
        uuid: String,
        owner: String,
        created_at: i64,
    },
    #[serde(rename = "drt_registered")]
    DrtRegistered {
        pool: String,
        drt_config: String,
        mint: String,
        right_id: String,
        supply: u64,
        code_hash: String,
        created_at: i64,
    },
    #[serde(rename = "right_granted")]
    RightGranted {
        pool: String,
        drt_config: String,
        commitment: String,
        granted_at: i64,
    },
    #[serde(rename = "right_revoked")]
    RightRevoked {
        pool: String,
        drt_config: String,
        commitment: String,
        revoked_at: i64,
    },
    #[serde(rename = "pool_sealed")]
    PoolSealed { pool: String, sealed_at: i64 },
}
