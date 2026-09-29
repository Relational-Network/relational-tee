// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! PDA derivation for the `digital_rights_tokens` program.
//!
//! Seeds must match the on-chain Anchor program exactly:
//! - Pool: `["pool", pool_uuid (16 bytes)]`
//! - DrtConfig: `["drt", pool_pda, right_id (16 bytes)]`
//! - Mint: `["mint", pool_pda, right_id (16 bytes)]`
//! - Grant: `["grant", commitment (32 bytes)]`

use solana_pubkey::Pubkey;
use std::str::FromStr;
use std::sync::OnceLock;

use super::types::{ASSOCIATED_TOKEN_PROGRAM_ID_STR, TOKEN_PROGRAM_ID_STR};
use crate::config::drt_program_id;

/// Derive the Pool PDA from a 16-byte uuid.
pub fn derive_pool_pda(pool_uuid: &[u8; 16]) -> (Pubkey, u8) {
    let program_id = drt_program_id();
    Pubkey::find_program_address(&[b"pool", pool_uuid.as_ref()], &program_id)
}

/// Derive the DrtConfig PDA.
pub fn derive_drt_config_pda(pool: &Pubkey, right_id: &[u8; 16]) -> (Pubkey, u8) {
    let program_id = drt_program_id();
    Pubkey::find_program_address(&[b"drt", pool.as_ref(), right_id.as_ref()], &program_id)
}

/// Derive the DRT Mint PDA.
pub fn derive_mint_pda(pool: &Pubkey, right_id: &[u8; 16]) -> (Pubkey, u8) {
    let program_id = drt_program_id();
    Pubkey::find_program_address(&[b"mint", pool.as_ref(), right_id.as_ref()], &program_id)
}

/// Derive the Grant PDA for a given commitment.
pub fn derive_grant_pda(commitment: &[u8; 32]) -> (Pubkey, u8) {
    let program_id = drt_program_id();
    Pubkey::find_program_address(&[b"grant", commitment.as_ref()], &program_id)
}

/// Derive an Associated Token Account for the legacy SPL Token program.
///
/// Seeds: `[holder, TOKEN_PROGRAM, mint]` under the ATA program.
pub fn derive_user_ata(holder: &Pubkey, mint: &Pubkey) -> Pubkey {
    static TOKEN_PROGRAM: OnceLock<Pubkey> = OnceLock::new();
    static ATA_PROGRAM: OnceLock<Pubkey> = OnceLock::new();
    let token_program = TOKEN_PROGRAM.get_or_init(|| {
        Pubkey::from_str(TOKEN_PROGRAM_ID_STR).expect("valid SPL Token program ID")
    });
    let ata_program = ATA_PROGRAM.get_or_init(|| {
        Pubkey::from_str(ASSOCIATED_TOKEN_PROGRAM_ID_STR).expect("valid ATA program ID")
    });
    Pubkey::find_program_address(
        &[holder.as_ref(), token_program.as_ref(), mint.as_ref()],
        ata_program,
    )
    .0
}

/// Compute the commitment hash `sha256(analyst_id || pool_uuid || right_id)`.
pub fn compute_commitment(analyst_id: &str, pool_uuid: &[u8; 16], right_id: &[u8; 16]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(analyst_id.as_bytes());
    hasher.update(pool_uuid);
    hasher.update(right_id);
    hasher.finalize().into()
}
