// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! The stored-transaction rule, for every chain write an idempotent request
//! makes: creating a pool, burning an append DRT, sending a transfer.
//!
//! 1. Before sending, the step stores its signed transaction and last valid
//!    block height in the request's idempotency record, by compare-and-swap.
//!    An attempt that loses that race uses the transaction the winner stored.
//! 2. Every later attempt resends that same transaction, which Solana
//!    deduplicates by signature.
//! 3. A new transaction replaces it only after the block height has passed
//!    and the effect is still absent, both checked at `finalized`: at
//!    `confirmed`, a transaction in a block that is still settling could be
//!    missed, and replacing it could produce a second effect.
//!
//! So attempts with the same key, on any workers, produce at most one effect.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use solana_hash::Hash;
use solana_pubkey::Pubkey;
use solana_transaction::Transaction;

use crate::blockchain::transactions::reached;
use crate::blockchain::SolanaClient;
use crate::error::ApiError;
use crate::idempotency::{Operation, StoredTx};

/// What a chain step's effect is, so a retry can tell whether it happened.
pub enum Effect {
    /// An account the transaction creates: a pool, or a Grant PDA.
    Account(Pubkey),
    /// The transaction itself, for a transfer.
    Transfer,
}

fn rpc_error(what: &str) -> impl FnOnce(crate::blockchain::rpc::RpcError) -> ApiError + '_ {
    move |e| ApiError::rpc_unavailable(format!("{what}: {e}"))
}

/// Sign a fresh transaction with the latest blockhash.
async fn sign(
    solana: &SolanaClient,
    build: &impl Fn(Hash) -> Transaction,
) -> Result<StoredTx, ApiError> {
    let (blockhash, last_valid_block_height) = solana
        .rpc()
        .get_latest_blockhash()
        .await
        .map_err(rpc_error("blockhash fetch failed"))?;
    let tx = build(blockhash);
    let bytes = bincode::serialize(&tx)
        .map_err(|e| ApiError::internal(format!("serializing a transaction: {e}")))?;
    Ok(StoredTx {
        transaction: BASE64.encode(bytes),
        signature: tx.signatures[0].to_string(),
        last_valid_block_height,
    })
}

/// The signature that created `account` (its oldest), for an effect that
/// exists without a stored transaction.
async fn creating_signature(
    solana: &SolanaClient,
    account: &Pubkey,
    commitment: &str,
) -> Result<String, ApiError> {
    const PAGE: usize = 1000;
    let mut oldest: Option<String> = None;
    loop {
        let page = solana
            .rpc()
            .get_signatures_for_address(account, oldest.as_deref(), None, Some(PAGE), commitment)
            .await
            .map_err(rpc_error("signature lookup failed"))?;
        let full = page.len() == PAGE;
        if let Some(last) = page.into_iter().last() {
            oldest = Some(last.signature);
        }
        if !full {
            break;
        }
    }
    oldest.ok_or_else(|| ApiError::rpc_unavailable(format!("no transaction created {account}")))
}

/// Run one chain step under the stored-transaction rule and return the
/// signature of the transaction that made its effect, once that has
/// reached `commitment`.
pub async fn run(
    solana: &SolanaClient,
    op: &mut Operation<'_>,
    effect: &Effect,
    commitment: &str,
    build: impl Fn(Hash) -> Transaction,
) -> Result<String, ApiError> {
    let rpc = solana.rpc();
    if let Effect::Account(account) = effect {
        let exists = rpc
            .account_exists(account, commitment)
            .await
            .map_err(rpc_error("account lookup failed"))?;
        if exists {
            return match op.stored_tx() {
                Some(stored) => Ok(stored.signature.clone()),
                None => creating_signature(solana, account, commitment).await,
            };
        }
    }

    let to_send = match op.stored_tx().cloned() {
        None => {
            let fresh = sign(solana, &build).await?;
            op.store_tx(fresh, None).await?
        }
        Some(stored) => {
            // The finalized height is read first: if it's past the stored
            // transaction's last valid height, any block that could hold the
            // transaction is already finalized, so the lookups below see it.
            let height = rpc
                .get_block_height("finalized")
                .await
                .map_err(rpc_error("block height lookup failed"))?;
            let status = rpc
                .signature_status(&stored.signature)
                .await
                .map_err(rpc_error("status lookup failed"))?;
            match status {
                Some(s) if s.err.is_none() => {
                    if !reached(&s, commitment) {
                        solana
                            .await_confirmation(&stored.signature, commitment)
                            .await?;
                    }
                    return Ok(stored.signature);
                }
                // A finalized failure can never succeed, so it may be replaced.
                Some(s) if reached(&s, "finalized") => {
                    let fresh = sign(solana, &build).await?;
                    op.store_tx(fresh, Some(&stored.signature)).await?
                }
                Some(_) => {
                    return Err(ApiError::rpc_unavailable("transaction failed on-chain"));
                }
                None if height <= stored.last_valid_block_height => stored,
                None => {
                    if let Effect::Account(account) = effect {
                        let exists = rpc
                            .account_exists(account, "finalized")
                            .await
                            .map_err(rpc_error("account lookup failed"))?;
                        if exists {
                            return creating_signature(solana, account, "finalized").await;
                        }
                    }
                    let fresh = sign(solana, &build).await?;
                    op.store_tx(fresh, Some(&stored.signature)).await?
                }
            }
        }
    };

    rpc.send_encoded_transaction(&to_send.transaction)
        .await
        .map_err(rpc_error("transaction send failed"))?;
    solana
        .await_confirmation(&to_send.signature, commitment)
        .await?;
    Ok(to_send.signature)
}
