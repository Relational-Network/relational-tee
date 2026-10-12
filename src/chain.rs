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
//! A transfer leaves nothing of its own on-chain, so it creates a receipt in
//! the same transaction ([`run_transfer`]): the chain then refuses a second
//! copy, and the receipt is the effect a retry checks. A pool's generation
//! keeps its transaction in the pool's document instead (see
//! [`crate::generation`]), so any worker can finish it.

use std::future::Future;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use solana_hash::Hash;
use solana_pubkey::Pubkey;
use solana_transaction::Transaction;
use tracing::{error, warn};

use crate::blockchain::counter;
use crate::blockchain::drt::accounts::{fetch_grant_state, is_pool, GrantState};
use crate::blockchain::rpc::RpcError;
use crate::blockchain::transactions::{is_receipt, reached};
use crate::blockchain::SolanaClient;
use crate::error::ApiError;
use crate::idempotency::{Operation, StoredTx};

/// Where a chain step keeps its signed transaction between attempts.
pub trait TxSlot {
    /// The transaction stored so far, if any.
    fn stored(&self) -> Option<&StoredTx>;

    /// Store `fresh`, replacing the transaction whose signature is
    /// `replaces`. If another attempt stored a different one first, that one
    /// is returned instead, and must be used.
    fn store(
        &mut self,
        fresh: StoredTx,
        replaces: Option<&str>,
    ) -> impl Future<Output = Result<StoredTx, ApiError>> + Send;
}

impl TxSlot for Operation<'_> {
    fn stored(&self) -> Option<&StoredTx> {
        self.stored_tx()
    }

    async fn store(
        &mut self,
        fresh: StoredTx,
        replaces: Option<&str>,
    ) -> Result<StoredTx, ApiError> {
        self.store_tx(fresh, replaces).await
    }
}

/// What a chain step's effect is, so a retry can tell whether it happened.
/// Each is checked by what the program made, not by an account merely
/// existing: anyone can send lamports to an address, which makes an
/// account there.
pub enum Effect {
    /// The pool the transaction creates: the program's `Pool` account.
    Pool(Pubkey),
    /// A burn: the program's Grant at `pda` for `drt_config`.
    Grant { pda: Pubkey, drt_config: Pubkey },
    /// A Grant PDA the transaction closes: once its `drt_config` Grant is
    /// gone.
    Closed { pda: Pubkey, drt_config: Pubkey },
    /// A pool's generation: once the `counter` mint `owner` mints shows at
    /// least `generation`.
    Generation {
        counter: Pubkey,
        owner: Pubkey,
        generation: u64,
    },
}

impl Effect {
    /// Whether the effect has happened, as seen at `commitment`.
    pub async fn happened(
        &self,
        solana: &SolanaClient,
        commitment: &str,
    ) -> Result<bool, ApiError> {
        let rpc = solana.rpc();
        let lookup = rpc_error("account lookup failed");
        Ok(match self {
            Self::Pool(pda) => is_pool(
                rpc.get_account(pda, commitment)
                    .await
                    .map_err(lookup)?
                    .as_ref(),
            ),
            Self::Grant { pda, drt_config } => {
                fetch_grant_state(rpc, pda, drt_config, commitment)
                    .await
                    .map_err(lookup)?
                    == GrantState::Live
            }
            Self::Closed { pda, drt_config } => {
                fetch_grant_state(rpc, pda, drt_config, commitment)
                    .await
                    .map_err(lookup)?
                    != GrantState::Live
            }
            Self::Generation {
                counter,
                owner,
                generation,
            } => {
                let account = rpc.get_account(counter, commitment).await.map_err(lookup)?;
                counter::generation(account.as_ref(), owner).map_err(ApiError::internal)?
                    >= *generation
            }
        })
    }

    /// The account the effect is about.
    fn account(&self) -> &Pubkey {
        match self {
            Self::Pool(pda) | Self::Grant { pda, .. } | Self::Closed { pda, .. } => pda,
            Self::Generation { counter, .. } => counter,
        }
    }

    /// The effect's signature if it has happened, as seen at `commitment`.
    async fn done(
        &self,
        solana: &SolanaClient,
        stored: Option<&str>,
        commitment: &str,
    ) -> Result<Option<String>, ApiError> {
        let account = self.account();
        if !self.happened(solana, commitment).await? {
            return Ok(None);
        }
        Ok(Some(match self {
            Self::Closed { .. } => closing_signature(solana, stored, account, commitment).await?,
            // Only one transaction per generation is ever signed and kept.
            Self::Generation { .. } => stored.unwrap_or_default().to_string(),
            _ => creating_signature(solana, stored, account, commitment).await?,
        }))
    }
}

/// An RPC failure as `503 rpc_unavailable`, saying `what` failed.
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

/// A transfer's receipt address holds an account this request's transfer
/// didn't make, so the transfer didn't happen and can't.
fn receipt_taken() -> ApiError {
    ApiError::bad_request(
        "another transaction holds this transfer's receipt address, so the transfer didn't \
         happen; send it again as a new transfer",
    )
    .with_code("receipt_taken")
}

/// A transfer's receipt exists, but no node reports the transaction that
/// should have made it: by now only an RPC that has dropped its history,
/// or an account another transaction made there, leaves that.
fn outcome_unknown(signature: &str) -> ApiError {
    error!(alert = "transfer_outcome_unknown", %signature,
        "A transfer's receipt exists, but no node reports its transaction");
    ApiError::bad_gateway(format!(
        "this transfer's receipt exists, but no Solana node reports its transaction \
         {signature}; check it on an explorer before sending again"
    ))
    .with_code("transfer_outcome_unknown")
}

/// A transfer's send failure. Its receipt is its first instruction, and the
/// System program's error 0 is "account already in use".
fn transfer_send_failed(e: RpcError) -> ApiError {
    let taken = serde_json::json!({ "InstructionError": [0, { "Custom": 0 }] });
    if e.rejection() == Some(&taken) {
        return receipt_taken();
    }
    send_failed(e)
}

/// Send `tx` and wait until it has reached `commitment`; `failed` explains
/// a send the node refused.
async fn send_and_confirm(
    solana: &SolanaClient,
    tx: &StoredTx,
    commitment: &str,
    failed: fn(RpcError) -> ApiError,
) -> Result<String, ApiError> {
    crate::fault::point("tx_stored");
    solana
        .rpc()
        .send_encoded_transaction(&tx.transaction)
        .await
        .map_err(failed)?;
    crate::fault::point("tx_sent");
    solana.await_confirmation(&tx.signature, commitment).await?;
    crate::fault::point("tx_confirmed");
    Ok(tx.signature.clone())
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
    const MAX_PAGES: usize = 50;
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
    for pages in 1.. {
        if pages > MAX_PAGES {
            return Err(ApiError::internal(format!(
                "{account} has too many transactions to find the one that created it"
            )));
        }
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
    op: &mut impl TxSlot,
    effect: &Effect,
    commitment: &str,
    build: impl Fn(Hash) -> Transaction,
) -> Result<String, ApiError> {
    let rpc = solana.rpc();
    let stored = op.stored().map(|s| s.signature.clone());
    if let Some(signature) = effect.done(solana, stored.as_deref(), commitment).await? {
        return Ok(signature);
    }

    let to_send = match op.stored().cloned() {
        None => {
            let fresh = sign(solana, &build).await?;
            op.store(fresh, None).await?
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
                    op.store(fresh, Some(&stored.signature)).await?
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
                    op.store(fresh, Some(&stored.signature)).await?
                }
            }
        }
    };
    send_and_confirm(solana, &to_send, commitment, send_failed).await
}

/// Run a transfer under the stored-transaction rule and return its
/// signature once it has reached `commitment`. Every transaction `build`
/// makes must create the receipt at `receipt` (see
/// [`crate::blockchain::transactions`]), so the chain lets at most one of
/// them succeed. A transaction that can no longer land, and whose receipt
/// is absent at `finalized`, is replaced; a receipt that this request's
/// transaction didn't make stops the transfer.
pub async fn run_transfer(
    solana: &SolanaClient,
    op: &mut Operation<'_>,
    receipt: &Pubkey,
    commitment: &str,
    build: impl Fn(Hash) -> Transaction,
) -> Result<String, ApiError> {
    let rpc = solana.rpc();
    let receipt_exists = |level: &'static str| async move {
        rpc.get_account(receipt, level)
            .await
            .map(|account| is_receipt(account.as_ref()))
            .map_err(rpc_error("account lookup failed"))
    };
    let to_send = match op.stored_tx().cloned() {
        // Sent without looking first: where another account holds the
        // receipt address, the node's preflight refuses it.
        None => {
            let fresh = sign(solana, &build).await?;
            op.store_tx(fresh, None).await?
        }
        Some(stored) => {
            // As in `run`: the finalized height first, so a lookup after it
            // sees any block that could hold the stored transaction.
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
                // It failed for good; a receipt there is another's.
                Some(s) if reached(&s, "finalized") => {
                    if receipt_exists("finalized").await? {
                        return Err(receipt_taken());
                    }
                    let fresh = sign(solana, &build).await?;
                    op.store_tx(fresh, Some(&stored.signature)).await?
                }
                Some(_) => {
                    return Err(ApiError::rpc_unavailable("transaction failed on-chain"));
                }
                None if height <= stored.last_valid_block_height => stored,
                // It can never land, and no node reports it: without its
                // receipt it didn't happen, and a replacement is safe.
                None => {
                    if receipt_exists("finalized").await? {
                        return Err(outcome_unknown(&stored.signature));
                    }
                    let fresh = sign(solana, &build).await?;
                    op.store_tx(fresh, Some(&stored.signature)).await?
                }
            }
        }
    };
    send_and_confirm(solana, &to_send, commitment, transfer_send_failed).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::pools::signed;
    use crate::blockchain::fake::{self, FakeChain, RECEIPT_DEPOSIT, VALID_FOR};
    use crate::blockchain::transactions::{create_receipt, native_transfer, receipt_address};
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
    const SEED: &str = "133dfaefa5935294a19687842fc22601";

    struct Setup {
        storage: Storage,
        chain: Arc<FakeChain>,
        solana: SolanaClient,
        keypair: Keypair,
        /// A transfer of 1 lamport, which creates `receipt` first.
        transfer: Vec<Instruction>,
        receipt: Pubkey,
    }

    fn setup() -> Setup {
        let chain = Arc::new(FakeChain::default());
        chain.block_height.store(100, SeqCst);
        let keypair = Keypair::new();
        let wallet = keypair.pubkey();
        let receipt = receipt_address(&wallet, SEED).unwrap();
        let mut transfer = vec![create_receipt(&wallet, &receipt, SEED, RECEIPT_DEPOSIT)];
        transfer.extend(native_transfer(
            &wallet,
            &Pubkey::new_from_array([9; 32]),
            1,
        ));
        Setup {
            storage: files_storage(),
            solana: fake::start(chain.clone()),
            chain,
            keypair,
            transfer,
            receipt,
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

        /// One attempt at the transfer.
        async fn transfer(&self) -> Result<String, ApiError> {
            let mut op = self.open().await;
            let build = signed(&self.keypair, &self.transfer);
            run_transfer(&self.solana, &mut op, &self.receipt, "confirmed", build).await
        }

        async fn stored(&self) -> StoredTx {
            self.open().await.stored_tx().cloned().unwrap()
        }

        /// How many transactions landed, and how many of them succeeded.
        fn landed(&self) -> (usize, usize) {
            let landed = self.chain.landed.lock().unwrap();
            (landed.len(), landed.iter().filter(|(_, ok)| *ok).count())
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

        let signature = s.transfer().await.unwrap();
        assert_eq!(signature, first.signature);
        assert_eq!(s.stored().await, first);
        assert_eq!(s.chain.sent(), [first.transaction]);
        assert!(s.chain.exists(&s.receipt));
    }

    /// The stored transfer landed, then no node could report it once it had
    /// expired. Its receipt says it happened, so nothing is sent again; and
    /// a second copy sent regardless couldn't succeed.
    #[tokio::test]
    async fn an_expired_transfer_that_no_node_reports_is_judged_by_its_receipt() {
        let s = setup();
        let first = s.stored_then_died().await;
        s.chain.lands.store(true, SeqCst);
        s.solana
            .rpc()
            .send_encoded_transaction(&first.transaction)
            .await
            .unwrap();
        s.chain.landed.lock().unwrap().clear();
        s.chain
            .block_height
            .store(first.last_valid_block_height + 1, SeqCst);
        let unknown = s.transfer().await.unwrap_err();
        assert_eq!(
            (unknown.status, unknown.code),
            (StatusCode::BAD_GATEWAY, "transfer_outcome_unknown")
        );
        assert!(unknown.message.contains(&first.signature));
        assert_eq!(s.chain.sent().len(), 1, "no second transfer");

        let mut op = s.open().await;
        let again = sign(&s.solana, &signed(&s.keypair, &s.transfer))
            .await
            .unwrap();
        let again = op.store_tx(again, Some(&first.signature)).await.unwrap();
        s.solana
            .rpc()
            .send_encoded_transaction(&again.transaction)
            .await
            .unwrap();
        assert_eq!(s.landed(), (1, 0), "the chain refuses a second receipt");

        // Expired without landing, with no receipt: a replacement is sent.
        let s = setup();
        let first = s.stored_then_died().await;
        s.chain.lands.store(true, SeqCst);
        s.chain.block_height.store(100 + VALID_FOR + 1, SeqCst);
        let signature = s.transfer().await.unwrap();
        assert_ne!(signature, first.signature);
        assert_eq!(s.chain.sent(), [s.stored().await.transaction]);
        assert_eq!(s.landed(), (1, 1));
    }

    #[tokio::test]
    async fn a_receipt_another_transaction_made_stops_the_transfer() {
        let taken = |e: ApiError| {
            assert_eq!(
                (e.status, e.code),
                (StatusCode::BAD_REQUEST, "receipt_taken")
            );
        };
        // Lamports sent to the receipt address before the first attempt: the
        // node's preflight refuses the transfer.
        let s = setup();
        s.chain.accounts.lock().unwrap().push(s.receipt);
        *s.chain.preflight.lock().unwrap() =
            Some(json!({ "InstructionError": [0, { "Custom": 0 }] }));
        taken(s.transfer().await.unwrap_err());

        // The stored transfer failed for good, and the receipt exists: it's
        // another transaction's, and nothing replaces the transfer.
        let s = setup();
        let first = s.stored_then_died().await;
        s.chain.land(&first.signature, false);
        s.chain.accounts.lock().unwrap().push(s.receipt);
        s.chain.lands.store(true, SeqCst);
        taken(s.transfer().await.unwrap_err());
        assert!(s.chain.sent().is_empty());
    }

    #[tokio::test]
    async fn concurrent_attempts_send_one_transfer() {
        let s = setup();
        s.chain.lands.store(true, SeqCst);
        let (a, b) = tokio::join!(s.transfer(), s.transfer());
        let (a, b) = (a.unwrap(), b.unwrap());
        assert_eq!(a, b);
        let stored = s.stored().await;
        assert_eq!(stored.signature, a);
        assert!(s.chain.sent().iter().all(|tx| *tx == stored.transaction));
        assert_eq!(s.landed(), (1, 1));
    }

    #[tokio::test]
    async fn an_expired_transaction_whose_effect_is_absent_is_replaced() {
        let s = setup();
        let first = s.stored_then_died().await;
        s.chain.lands.store(true, SeqCst);
        s.chain.block_height.store(100 + VALID_FOR + 1, SeqCst);

        let pool = Effect::Pool(Pubkey::new_from_array([3; 32]));
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
        let pda = Pubkey::new_from_array([4; 32]);
        let drt_config = Pubkey::new_from_array([6; 32]);
        s.chain.grant(pda, drt_config);
        s.chain.block_height.store(100 + VALID_FOR + 1, SeqCst);

        let burn = Effect::Grant { pda, drt_config };
        let (signature, _) = s.retry(&burn, "finalized").await;
        assert_eq!(signature, first.signature);
        assert!(s.chain.sent().is_empty());
    }

    #[tokio::test]
    async fn only_the_programs_account_counts_as_an_effect() {
        let pda = Pubkey::new_from_array([4; 32]);
        let drt_config = Pubkey::new_from_array([6; 32]);
        let burn = Effect::Grant { pda, drt_config };
        let pool = Effect::Pool(pda);
        for (what, effect) in [("burn", &burn), ("pool", &pool)] {
            // Lamports sent to the address make an account there that the
            // program didn't make: the burn or the pool is still to do.
            let s = setup();
            let first = s.stored_then_died().await;
            s.chain.accounts.lock().unwrap().push(pda);
            s.chain.lands.store(true, SeqCst);
            s.chain.block_height.store(100 + VALID_FOR + 1, SeqCst);
            let (signature, stored) = s.retry(effect, "finalized").await;
            assert_ne!(signature, first.signature, "the {what} is sent anew");
            assert_eq!(s.chain.sent(), [stored.transaction]);
        }

        // A Grant for another DRT isn't this burn.
        let s = setup();
        s.chain.grant(pda, Pubkey::new_from_array([7; 32]));
        assert!(!burn.happened(&s.solana, "finalized").await.unwrap());
        assert!(Effect::Closed { pda, drt_config }
            .happened(&s.solana, "finalized")
            .await
            .unwrap());
        s.chain.grant(pda, drt_config);
        assert!(burn.happened(&s.solana, "finalized").await.unwrap());
        s.chain.pool(pda, Pubkey::new_unique());
        assert!(pool.happened(&s.solana, "finalized").await.unwrap());
    }

    #[tokio::test]
    async fn a_closed_account_is_never_closed_again() {
        let pda = Pubkey::new_from_array([5; 32]);
        let drt_config = Pubkey::new_from_array([6; 32]);
        let close = Effect::Closed { pda, drt_config };

        // The stored close landed, and the account is gone.
        let s = setup();
        let first = s.stored_then_died().await;
        s.chain.land(&first.signature, true);
        let (signature, _) = s.retry(&close, "finalized").await;
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
        let (signature, _) = s.retry(&close, "finalized").await;
        assert_eq!(signature, "sig-close");
        assert!(s.chain.sent().is_empty());

        // While the Grant exists, the close is sent.
        let s = setup();
        s.chain.grant(pda, drt_config);
        s.chain.lands.store(true, SeqCst);
        let mut op = s.open().await;
        let build = signed(&s.keypair, &s.transfer);
        let signature = run(&s.solana, &mut op, &close, "finalized", build)
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
        let signature = s.transfer().await.unwrap();
        assert_eq!(signature, first.signature);
        assert!(s.chain.sent().is_empty());

        let s = setup();
        let first = s.stored_then_died().await;
        s.chain.land(&first.signature, false);
        s.chain.lands.store(true, SeqCst);
        let signature = s.transfer().await.unwrap();
        assert_ne!(signature, first.signature);
        assert_eq!(s.chain.sent(), [s.stored().await.transaction]);
    }

    #[tokio::test]
    async fn a_send_the_preflight_refuses_is_rejected_and_a_retry_resends_it() {
        let s = setup();
        let attempt = || s.transfer();

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
        let signature = attempt().await.unwrap();
        let stored = s.stored().await;
        assert_eq!(signature, stored.signature);
        assert_eq!(s.chain.sent(), vec![stored.transaction; 3]);
    }
}
