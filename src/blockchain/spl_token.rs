// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! SPL token balance queries and transfers.
//!
//! Inline implementations of ATA derivation, ATA creation, and
//! `TransferChecked` instruction building — replaces the heavy
//! `spl-token` (~260 deps) and `spl-associated-token-account` (~481 deps)
//! crates with ~40 lines of deterministic instruction construction.

use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use std::str::FromStr;
use std::sync::OnceLock;
use tracing::info;

use super::client::SolanaClient;
use super::types::SendResult;
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

/// Build an instruction to create an Associated Token Account.
///
/// ATA program instruction discriminator `0` = Create.
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
        data: vec![0], // Create
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

// ── SolanaClient impl ───────────────────────────────────────────────

impl SolanaClient {
    /// Send SPL tokens from `keypair` to `recipient`.
    pub async fn send_spl_token(
        &self,
        keypair: &Keypair,
        recipient: &str,
        mint_address: &str,
        amount: u64,
        decimals: u8,
    ) -> Result<SendResult, ApiError> {
        let to_pubkey = Pubkey::from_str(recipient)
            .map_err(|_| ApiError::unprocessable(format!("invalid recipient: {recipient}")))?;
        let mint = Pubkey::from_str(mint_address)
            .map_err(|_| ApiError::unprocessable("invalid mint address"))?;

        let from_ata = get_associated_token_address(&keypair.pubkey(), &mint);
        let to_ata = get_associated_token_address(&to_pubkey, &mint);

        let mut instructions = Vec::new();

        // Create ATA for recipient if it doesn't exist.
        let to_ata_exists = self
            .rpc
            .get_account_data(&to_ata)
            .await
            .map(|opt| opt.is_some())
            .unwrap_or(false);
        if !to_ata_exists {
            instructions.push(create_ata_instruction(&keypair.pubkey(), &to_pubkey, &mint));
        }

        // SPL transfer instruction.
        instructions.push(transfer_checked_instruction(
            &from_ata,
            &mint,
            &to_ata,
            &keypair.pubkey(),
            amount,
            decimals,
        ));

        let recent_blockhash =
            self.rpc.get_latest_blockhash().await.map_err(|e| {
                ApiError::service_unavailable(format!("blockhash fetch failed: {e}"))
            })?;

        let message = solana_message::Message::new(&instructions, Some(&keypair.pubkey()));
        let tx = solana_transaction::Transaction::new(&[keypair], message, recent_blockhash);

        let signature =
            self.rpc.send_transaction(&tx).await.map_err(|e| {
                ApiError::service_unavailable(format!("SPL transfer send failed: {e}"))
            })?;

        self.await_confirmation(&signature, "confirmed").await?;

        let sig_str = signature.to_string();
        info!(signature = %sig_str, to = %recipient, mint = %mint_address, amount, "SPL transfer sent");

        Ok(SendResult {
            explorer_url: self.network.explorer_tx_url(&sig_str),
            signature: sig_str,
        })
    }
}
