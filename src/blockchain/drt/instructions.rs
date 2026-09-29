// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Raw Solana instruction builders for the `digital_rights_tokens` program.
//!
//! Each function returns a `solana_instruction::Instruction` ready to be
//! included in a transaction. No `anchor-client` dependency — we build the
//! instruction data directly with the 8-byte Anchor discriminator followed by
//! Borsh-serialized arguments.

use borsh::BorshSerialize;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use std::str::FromStr;
use std::sync::OnceLock;

use super::pda::{derive_drt_config_pda, derive_grant_pda, derive_mint_pda, derive_user_ata};
use super::types::*;
use crate::config::drt_program_id;

// ============================================================================
// Helpers
// ============================================================================

fn system_program_id() -> Pubkey {
    static ID: OnceLock<Pubkey> = OnceLock::new();
    *ID.get_or_init(|| Pubkey::from_str(SYSTEM_PROGRAM_ID_STR).expect("valid system program ID"))
}

fn token_program_id() -> Pubkey {
    static ID: OnceLock<Pubkey> = OnceLock::new();
    *ID.get_or_init(|| Pubkey::from_str(TOKEN_PROGRAM_ID_STR).expect("valid SPL Token program ID"))
}

fn associated_token_program_id() -> Pubkey {
    static ID: OnceLock<Pubkey> = OnceLock::new();
    *ID.get_or_init(|| {
        Pubkey::from_str(ASSOCIATED_TOKEN_PROGRAM_ID_STR).expect("valid ATA program ID")
    })
}

fn rent_sysvar_id() -> Pubkey {
    static ID: OnceLock<Pubkey> = OnceLock::new();
    *ID.get_or_init(|| Pubkey::from_str(RENT_SYSVAR_ID_STR).expect("valid rent sysvar ID"))
}

/// Build a `ComputeBudgetProgram::SetComputeUnitLimit` instruction.
pub fn build_compute_budget_ix(units: u32) -> Instruction {
    static COMPUTE_BUDGET_ID: OnceLock<Pubkey> = OnceLock::new();
    let program_id = *COMPUTE_BUDGET_ID.get_or_init(|| {
        Pubkey::from_str("ComputeBudget111111111111111111111111111111")
            .expect("valid ComputeBudget program ID")
    });
    let mut data = vec![2u8]; // SetComputeUnitLimit
    data.extend_from_slice(&units.to_le_bytes());
    Instruction {
        program_id,
        accounts: vec![],
        data,
    }
}

// ============================================================================
// create_pool
// ============================================================================

/// Build the `create_pool` instruction.
///
/// Accounts (in IDL order): owner (writable, signer), pool (PDA, writable),
/// system_program.
pub fn build_create_pool(owner: &Pubkey, pool_pda: &Pubkey, pool_uuid: &[u8; 16]) -> Instruction {
    let mut data = Vec::with_capacity(8 + 16);
    data.extend_from_slice(&DISC_CREATE_POOL);
    data.extend_from_slice(pool_uuid);

    let accounts = vec![
        AccountMeta::new(*owner, true),
        AccountMeta::new(*pool_pda, false),
        AccountMeta::new_readonly(system_program_id(), false),
    ];

    Instruction {
        program_id: drt_program_id(),
        accounts,
        data,
    }
}

// ============================================================================
// register_drt
// ============================================================================

/// Build the `register_drt` instruction.
///
/// Accounts (in IDL order): owner (writable, signer), pool, drt_config
/// (writable), mint (writable), holder, holder_ata (writable), token_program,
/// associated_token_program, system_program, rent.
pub fn build_register_drt(
    owner: &Pubkey,
    pool_pda: &Pubkey,
    holder: &Pubkey,
    right_id: &[u8; 16],
    code_repo_url: &str,
    code_hash: &[u8; 32],
    supply: u64,
) -> Result<Instruction, String> {
    let (drt_config_pda, _) = derive_drt_config_pda(pool_pda, right_id);
    let (mint_pda, _) = derive_mint_pda(pool_pda, right_id);
    let holder_ata = derive_user_ata(holder, &mint_pda);

    let mut data = Vec::new();
    data.extend_from_slice(&DISC_REGISTER_DRT);
    data.extend_from_slice(right_id);
    code_repo_url
        .to_string()
        .serialize(&mut data)
        .map_err(|e| format!("Borsh serialize code_repo_url: {e}"))?;
    data.extend_from_slice(code_hash);
    data.extend_from_slice(&supply.to_le_bytes());

    let accounts = vec![
        AccountMeta::new(*owner, true),
        AccountMeta::new_readonly(*pool_pda, false),
        AccountMeta::new(drt_config_pda, false),
        AccountMeta::new(mint_pda, false),
        AccountMeta::new_readonly(*holder, false),
        AccountMeta::new(holder_ata, false),
        AccountMeta::new_readonly(token_program_id(), false),
        AccountMeta::new_readonly(associated_token_program_id(), false),
        AccountMeta::new_readonly(system_program_id(), false),
        AccountMeta::new_readonly(rent_sysvar_id(), false),
    ];

    Ok(Instruction {
        program_id: drt_program_id(),
        accounts,
        data,
    })
}

// ============================================================================
// grant_right
// ============================================================================

/// Build the `grant_right` instruction (burns 1 token + creates Grant PDA).
///
/// Accounts (in IDL order): pool, drt_config, mint (writable), holder
/// (writable, signer), holder_ata (writable), grant (writable, PDA from
/// commitment), token_program, system_program.
pub fn build_grant_right(
    pool_pda: &Pubkey,
    drt_config_pda: &Pubkey,
    mint: &Pubkey,
    holder: &Pubkey,
    commitment: &[u8; 32],
) -> Instruction {
    let holder_ata = derive_user_ata(holder, mint);
    let (grant_pda, _) = derive_grant_pda(commitment);

    let mut data = Vec::with_capacity(8 + 32);
    data.extend_from_slice(&DISC_GRANT_RIGHT);
    data.extend_from_slice(commitment);

    let accounts = vec![
        AccountMeta::new_readonly(*pool_pda, false),
        AccountMeta::new_readonly(*drt_config_pda, false),
        AccountMeta::new(*mint, false),
        AccountMeta::new(*holder, true),
        AccountMeta::new(holder_ata, false),
        AccountMeta::new(grant_pda, false),
        AccountMeta::new_readonly(token_program_id(), false),
        AccountMeta::new_readonly(system_program_id(), false),
    ];

    Instruction {
        program_id: drt_program_id(),
        accounts,
        data,
    }
}

// ============================================================================
// revoke_grant
// ============================================================================

/// Build the `revoke_grant` instruction.
///
/// Accounts (in IDL order): owner (writable, signer), pool, drt_config, grant
/// (writable).
pub fn build_revoke_grant(
    owner: &Pubkey,
    pool_pda: &Pubkey,
    drt_config_pda: &Pubkey,
    commitment: &[u8; 32],
) -> Instruction {
    let (grant_pda, _) = derive_grant_pda(commitment);

    let mut data = Vec::with_capacity(8 + 32);
    data.extend_from_slice(&DISC_REVOKE_GRANT);
    data.extend_from_slice(commitment);

    let accounts = vec![
        AccountMeta::new(*owner, true),
        AccountMeta::new_readonly(*pool_pda, false),
        AccountMeta::new_readonly(*drt_config_pda, false),
        AccountMeta::new(grant_pda, false),
    ];

    Instruction {
        program_id: drt_program_id(),
        accounts,
        data,
    }
}

// ============================================================================
// seal_pool
// ============================================================================

/// Build the `seal_pool` instruction.
///
/// Accounts (in IDL order): owner (signer), pool (writable).
pub fn build_seal_pool(owner: &Pubkey, pool_pda: &Pubkey) -> Instruction {
    let data = DISC_SEAL_POOL.to_vec();

    let accounts = vec![
        AccountMeta::new_readonly(*owner, true),
        AccountMeta::new(*pool_pda, false),
    ];

    Instruction {
        program_id: drt_program_id(),
        accounts,
        data,
    }
}
