// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! SPL token transfers.
//!
//! Inline implementations of ATA derivation, ATA creation, and
//! `TransferChecked` instruction building — replaces the heavy
//! `spl-token` (~260 deps) and `spl-associated-token-account` (~481 deps)
//! crates with ~40 lines of deterministic instruction construction.

use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use std::str::FromStr;
use std::sync::OnceLock;

use crate::error::ApiError;

// ── Well-known program IDs ──────────────────────────────────────────

const SPL_TOKEN_PROGRAM_ID_STR: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const ATA_PROGRAM_ID_STR: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
const SYSTEM_PROGRAM_ID_STR: &str = "11111111111111111111111111111111";

fn spl_token_program_id() -> &'static Pubkey {
    static ID: OnceLock<Pubkey> = OnceLock::new();
    ID.get_or_init(|| Pubkey::from_str(SPL_TOKEN_PROGRAM_ID_STR).expect("valid SPL Token ID"))
}

fn ata_program_id() -> &'static Pubkey {
    static ID: OnceLock<Pubkey> = OnceLock::new();
    ID.get_or_init(|| Pubkey::from_str(ATA_PROGRAM_ID_STR).expect("valid ATA program ID"))
}

fn system_program_id() -> &'static Pubkey {
    static ID: OnceLock<Pubkey> = OnceLock::new();
    ID.get_or_init(|| Pubkey::from_str(SYSTEM_PROGRAM_ID_STR).expect("valid system program ID"))
}

// ── Inline SPL helpers ──────────────────────────────────────────────

/// Derive the Associated Token Account address for `wallet` + `mint`
/// under the standard SPL Token program.
///
/// Seeds: `[wallet, TOKEN_PROGRAM, mint]` under ATA program.
fn get_associated_token_address(wallet: &Pubkey, mint: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(
        &[
            wallet.as_ref(),
            spl_token_program_id().as_ref(),
            mint.as_ref(),
        ],
        ata_program_id(),
    )
    .0
}

/// Build an instruction that creates an Associated Token Account unless it
/// already exists.
///
/// ATA program instruction `1` = CreateIdempotent. A send's transaction is
/// stored and resent until it lands, so it can't depend on whether the
/// account existed when it was built.
fn create_ata_instruction(funder: &Pubkey, wallet: &Pubkey, mint: &Pubkey) -> Instruction {
    let ata = get_associated_token_address(wallet, mint);
    Instruction {
        program_id: *ata_program_id(),
        accounts: vec![
            AccountMeta::new(*funder, true),
            AccountMeta::new(ata, false),
            AccountMeta::new_readonly(*wallet, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new_readonly(*system_program_id(), false),
            AccountMeta::new_readonly(*spl_token_program_id(), false),
        ],
        data: vec![1],
    }
}

/// Build an SPL Token `TransferChecked` instruction.
///
/// Instruction tag 12, data layout: `[12u8, amount:u64 LE, decimals:u8]`.
fn transfer_checked_instruction(
    source: &Pubkey,
    mint: &Pubkey,
    destination: &Pubkey,
    authority: &Pubkey,
    amount: u64,
    decimals: u8,
) -> Instruction {
    let mut data = Vec::with_capacity(10);
    data.push(12u8);
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(decimals);

    Instruction {
        program_id: *spl_token_program_id(),
        accounts: vec![
            AccountMeta::new(*source, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new(*destination, false),
            AccountMeta::new_readonly(*authority, true),
        ],
        data,
    }
}

/// The instructions for an SPL transfer from `owner` to `recipient`,
/// creating the recipient's token account first if it doesn't exist.
pub fn spl_transfer(
    owner: &Pubkey,
    recipient: &Pubkey,
    mint_address: &str,
    amount: u64,
    decimals: u8,
) -> Result<Vec<Instruction>, ApiError> {
    let mint = Pubkey::from_str(mint_address)
        .map_err(|_| ApiError::unprocessable("invalid mint address"))?;
    let from_ata = get_associated_token_address(owner, &mint);
    let to_ata = get_associated_token_address(recipient, &mint);
    Ok(vec![
        create_ata_instruction(owner, recipient, &mint),
        transfer_checked_instruction(&from_ata, &mint, &to_ata, owner, amount, decimals),
    ])
}

/// The amount an SPL token account holds: the little-endian `u64` after its
/// mint and owner (bytes 64 to 72).
pub fn token_account_amount(data: &[u8]) -> Option<u64> {
    Some(u64::from_le_bytes(data.get(64..72)?.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_transfer_creates_the_recipients_token_account_only_if_it_is_missing() {
        let [owner, recipient, mint] = [1u8, 2, 3].map(|n| Pubkey::new_from_array([n; 32]));
        let instructions = spl_transfer(&owner, &recipient, &mint.to_string(), 5, 6).unwrap();
        let [create, transfer] = instructions.as_slice() else {
            panic!("a create and a transfer: {instructions:?}");
        };
        let to_ata = get_associated_token_address(&recipient, &mint);
        assert_eq!(create.program_id, *ata_program_id());
        assert_eq!(create.data, [1], "CreateIdempotent");
        assert_eq!(create.accounts[1].pubkey, to_ata);
        assert_eq!(transfer.accounts[2].pubkey, to_ata);
        assert_eq!(
            transfer.data,
            [&[12][..], &5u64.to_le_bytes(), &[6]].concat()
        );
    }

    #[test]
    fn reads_the_amount_after_the_mint_and_owner() {
        let mut account = vec![0u8; 165];
        account[64..72].copy_from_slice(&7u64.to_le_bytes());
        assert_eq!(token_account_amount(&account), Some(7));
        assert_eq!(token_account_amount(&account[..70]), None);
    }
}
