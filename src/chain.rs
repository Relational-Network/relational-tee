// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! The stored-transaction rule, for every chain write an idempotent request
//! makes: creating a pool, burning a DRT, closing a grant, sending a
//! transfer.
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
use tracing::warn;

use crate::blockchain::rpc::RpcError;
use crate::blockchain::transactions::reached;
use crate::blockchain::SolanaClient;
use crate::error::ApiError;
use crate::idempotency::{Operation, StoredTx};

/// What a chain step's effect is, so a retry can tell whether it happened.
pub enum Effect {
    /// An account the transaction creates: a pool, or a Grant PDA.
    Account(Pubkey),
    /// An account the transaction closes: a revoked Grant PDA.
    Closed(Pubkey),
    /// The transaction itself, for a transfer.
    Transfer,
}

impl Effect {
    /// The effect's signature if it has happened, as seen at `commitment`.
    async fn done(
        &self,
        solana: &SolanaClient,
        stored: Option<&str>,
        commitment: &str,
    ) -> Result<Option<String>, ApiError> {
        let (account, created) = match self {
            Self::Account(account) => (account, true),
            Self::Closed(account) => (account, false),
            Self::Transfer => return Ok(None),
        };
        let exists = solana
            .rpc()
            .account_exists(account, commitment)
            .await
            .map_err(rpc_error("account lookup failed"))?;
        Ok(match (created, exists) {
            (true, true) => Some(creating_signature(solana, stored, account, commitment).await?),
            (false, false) => Some(closing_signature(solana, stored, account, commitment).await?),
            _ => None,
        })
    }
}

fn rpc_error(what: &str) -> impl FnOnce(RpcError) -> ApiError + '_ {
    move |e| ApiError::rpc_unavailable(format!("{what}: {e}"))
}

/// A send's failure. When the node's preflight simulation fails for a
/// lasting reason, such as a wallet short of SOL for the fee or rent, the
/// request is at fault; a retry with the same key still sends the stored
/// transaction, and succeeds once the reason is gone.
fn send_failed(e: RpcError) -> ApiError {
    let Some(reason) = e.rejection() else {
        return ApiError::rpc_unavailable(format!("transaction send failed: {e}"));
    };
    warn!(%reason, "Solana refused a transaction in preflight");
    let message = e
        .message
        .strip_prefix("Transaction simulation failed: ")
        .unwrap_or(&e.message);
    ApiError::bad_request(format!("Solana refused the transaction: {message}"))
        .with_code("transaction_rejected")
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

/// The signature of the transaction that created `account`, which exists:
/// `stored` if that transaction succeeded, or else the oldest successful
/// transaction that touched the account.
pub async fn creating_signature(
    solana: &SolanaClient,
    stored: Option<&str>,
    account: &Pubkey,
    commitment: &str,
) -> Result<String, ApiError> {
    const PAGE: usize = 1000;
    let rpc = solana.rpc();
    if let Some(signature) = stored {
        let status = rpc
            .signature_status(signature)
            .await
            .map_err(rpc_error("status lookup failed"))?;
        if status.is_some_and(|s| s.err.is_none()) {
            return Ok(signature.to_string());
        }
    }
    let mut before: Option<String> = None;
    let mut oldest: Option<String> = None;
    loop {
        let page = rpc
            .get_signatures_for_address(account, before.as_deref(), None, Some(PAGE), commitment)
            .await
            .map_err(rpc_error("signature lookup failed"))?;
        let full = page.len() == PAGE;
        before = page.last().map(|s| s.signature.clone());
        if let Some(succeeded) = page.into_iter().rfind(|s| s.err.is_none()) {
            oldest = Some(succeeded.signature);
        }
        if !full {
            break;
        }
    }
    oldest.ok_or_else(|| ApiError::rpc_unavailable(format!("no transaction created {account}")))
}

/// The signature of the transaction that closed `account`, which existed
/// and is gone: `stored` if that transaction succeeded, or else the newest
/// successful transaction that touched the account.
async fn closing_signature(
    solana: &SolanaClient,
    stored: Option<&str>,
    account: &Pubkey,
    commitment: &str,
) -> Result<String, ApiError> {
    let rpc = solana.rpc();
    if let Some(signature) = stored {
        let status = rpc
            .signature_status(signature)
            .await
            .map_err(rpc_error("status lookup failed"))?;
        if status.is_some_and(|s| s.err.is_none()) {
            return Ok(signature.to_string());
        }
    }
    rpc.get_signatures_for_address(account, None, None, Some(100), commitment)
        .await
        .map_err(rpc_error("signature lookup failed"))?
        .into_iter()
        .find(|s| s.err.is_none())
        .map(|s| s.signature)
        .ok_or_else(|| ApiError::rpc_unavailable(format!("no transaction closed {account}")))
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
    let stored = op.stored_tx().map(|s| s.signature.clone());
    if let Some(signature) = effect.done(solana, stored.as_deref(), commitment).await? {
        return Ok(signature);
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
                    if let Some(signature) = effect.done(solana, None, "finalized").await? {
                        return Ok(signature);
                    }
                    let fresh = sign(solana, &build).await?;
                    op.store_tx(fresh, Some(&stored.signature)).await?
                }
            }
        }
    };

    crate::fault::point("tx_stored");
    rpc.send_encoded_transaction(&to_send.transaction)
        .await
        .map_err(send_failed)?;
    crate::fault::point("tx_sent");
    solana
        .await_confirmation(&to_send.signature, commitment)
        .await?;
    crate::fault::point("tx_confirmed");
    Ok(to_send.signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::pools::signed;
    use crate::blockchain::fake::{self, FakeChain, VALID_FOR};
    use crate::blockchain::transactions::native_transfer;
    use crate::idempotency::{Idempotent, Opened};
    use crate::storage::tests::files_storage;
    use crate::storage::Storage;
    use axum::http::StatusCode;
    use serde_json::json;
    use solana_instruction::Instruction;
    use solana_keypair::Keypair;
    use solana_signer::Signer;
    use std::sync::atomic::Ordering::SeqCst;
    use std::sync::Arc;

    const KEY: &str = "0f8fad5b-d9cb-469f-a165-70867728950e";

    struct Setup {
        storage: Storage,
        chain: Arc<FakeChain>,
        solana: SolanaClient,
        keypair: Keypair,
        transfer: Vec<Instruction>,
    }

    fn setup() -> Setup {
        let chain = Arc::new(FakeChain::default());
        chain.block_height.store(100, SeqCst);
        let keypair = Keypair::new();
        let transfer = native_transfer(&keypair.pubkey(), &Pubkey::new_from_array([9; 32]), 1);
        Setup {
            storage: files_storage(),
            solana: fake::start(chain.clone()),
            chain,
            keypair,
            transfer,
        }
    }

    impl Setup {
        async fn open(&self) -> Operation<'_> {
            let request =
                Idempotent::post(KEY, "/v1/wallets/{wallet_id}/send", "/v1/wallets/w/send");
            match Operation::open(&self.storage, "user-1", &request, b"{}").await {
                Ok(Opened::Run(op)) => op,
                _ => panic!("a new request"),
            }
        }

        /// An earlier attempt signed and stored its transaction, then died.
        async fn stored_then_died(&self) -> StoredTx {
            let mut op = self.open().await;
            let tx = sign(&self.solana, &signed(&self.keypair, &self.transfer))
                .await
                .unwrap();
            op.store_tx(tx, None).await.unwrap()
        }

        async fn retry(&self, effect: &Effect, commitment: &str) -> (String, StoredTx) {
            let mut op = self.open().await;
            let build = signed(&self.keypair, &self.transfer);
            let signature = run(&self.solana, &mut op, effect, commitment, build)
                .await
                .unwrap();
            let stored = self.open().await.stored_tx().cloned().unwrap();
            (signature, stored)
        }
    }

    #[tokio::test]
    async fn a_retry_resends_the_stored_transaction_while_it_can_land() {
        let s = setup();
        let first = s.stored_then_died().await;
        s.chain.lands.store(true, SeqCst);
        s.chain
            .block_height
            .store(first.last_valid_block_height, SeqCst);

        let (signature, stored) = s.retry(&Effect::Transfer, "confirmed").await;
        assert_eq!(signature, first.signature);
        assert_eq!(stored, first);
        assert_eq!(s.chain.sent(), [first.transaction]);
    }

    #[tokio::test]
    async fn an_expired_transaction_whose_effect_is_absent_is_replaced() {
        let s = setup();
        let first = s.stored_then_died().await;
        s.chain.lands.store(true, SeqCst);
        s.chain.block_height.store(100 + VALID_FOR + 1, SeqCst);

        let pool = Effect::Account(Pubkey::new_from_array([3; 32]));
        let (signature, stored) = s.retry(&pool, "confirmed").await;
        assert_ne!(signature, first.signature);
        assert_eq!(stored.signature, signature, "the replacement is stored");
        assert_eq!(s.chain.sent(), [stored.transaction]);
    }

    #[tokio::test]
    async fn an_effect_that_exists_is_never_sent_again() {
        let s = setup();
        let first = s.stored_then_died().await;
        s.chain.land(&first.signature, true);
        let grant = Pubkey::new_from_array([4; 32]);
        s.chain.accounts.lock().unwrap().push(grant);
        s.chain.block_height.store(100 + VALID_FOR + 1, SeqCst);

        let (signature, _) = s.retry(&Effect::Account(grant), "finalized").await;
        assert_eq!(signature, first.signature);
        assert!(s.chain.sent().is_empty());
    }

    #[tokio::test]
    async fn a_closed_account_is_never_closed_again() {
        let grant = Pubkey::new_from_array([5; 32]);

        // The stored close landed, and the account is gone.
        let s = setup();
        let first = s.stored_then_died().await;
        s.chain.land(&first.signature, true);
        let (signature, _) = s.retry(&Effect::Closed(grant), "finalized").await;
        assert_eq!(signature, first.signature);
        assert!(s.chain.sent().is_empty());

        // The stored close expired unsent, but another closed the account:
        // the newest successful transaction that touched it.
        let s = setup();
        s.stored_then_died().await;
        s.chain.block_height.store(100 + VALID_FOR + 1, SeqCst);
        let failed = json!({ "InstructionError": [0, "Custom"] });
        *s.chain.history.lock().unwrap() = vec![
            json!({ "signature": "sig-failed", "err": failed }),
            json!({ "signature": "sig-close", "err": null }),
            json!({ "signature": "sig-grant", "err": null }),
        ];
        let (signature, _) = s.retry(&Effect::Closed(grant), "finalized").await;
        assert_eq!(signature, "sig-close");
        assert!(s.chain.sent().is_empty());

        // While the account exists, the close is sent.
        let s = setup();
        s.chain.accounts.lock().unwrap().push(grant);
        s.chain.lands.store(true, SeqCst);
        let mut op = s.open().await;
        let build = signed(&s.keypair, &s.transfer);
        let signature = run(
            &s.solana,
            &mut op,
            &Effect::Closed(grant),
            "finalized",
            build,
        )
        .await
        .unwrap();
        assert_eq!(s.chain.sent().len(), 1);
        assert_eq!(op.stored_tx().unwrap().signature, signature);
    }

    #[tokio::test]
    async fn a_landed_transfer_is_final_and_a_failed_one_is_replaced() {
        let s = setup();
        let first = s.stored_then_died().await;
        s.chain.land(&first.signature, true);
        let (signature, _) = s.retry(&Effect::Transfer, "confirmed").await;
        assert_eq!(signature, first.signature);
        assert!(s.chain.sent().is_empty());

        let s = setup();
        let first = s.stored_then_died().await;
        s.chain.land(&first.signature, false);
        s.chain.lands.store(true, SeqCst);
        let (signature, stored) = s.retry(&Effect::Transfer, "confirmed").await;
        assert_ne!(signature, first.signature);
        assert_eq!(s.chain.sent(), [stored.transaction]);
    }

    #[tokio::test]
    async fn a_send_the_preflight_refuses_is_rejected_and_a_retry_resends_it() {
        let s = setup();
        let attempt = || async {
            let mut op = s.open().await;
            let build = signed(&s.keypair, &s.transfer);
            run(&s.solana, &mut op, &Effect::Transfer, "confirmed", build).await
        };

        let rent = json!({ "InsufficientFundsForRent": { "account_index": 0 } });
        *s.chain.preflight.lock().unwrap() = Some(rent.clone());
        let refused = attempt().await.unwrap_err();
        assert_eq!(
            (refused.status, refused.code),
            (StatusCode::BAD_REQUEST, "transaction_rejected")
        );
        assert_eq!(
            refused.message,
            format!("Solana refused the transaction: {rent}")
        );

        // A node that doesn't know the blockhash may just be behind.
        *s.chain.preflight.lock().unwrap() = Some(json!("BlockhashNotFound"));
        let behind = attempt().await.unwrap_err();
        assert_eq!(
            (behind.status, behind.code),
            (StatusCode::SERVICE_UNAVAILABLE, "rpc_unavailable")
        );

        *s.chain.preflight.lock().unwrap() = None;
        s.chain.lands.store(true, SeqCst);
        let (signature, stored) = s.retry(&Effect::Transfer, "confirmed").await;
        assert_eq!(signature, stored.signature);
        assert_eq!(s.chain.sent(), vec![stored.transaction; 3]);
    }
}
