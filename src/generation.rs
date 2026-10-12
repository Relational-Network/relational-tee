// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! A pool's generation: how many access changes its document has made,
//! anchored on-chain so a restored older document is refused.
//!
//! Every change that decides what an analyst may see (recording a grant or
//! a grant's revocation, changing a grant's targets, revoking credentials)
//! makes the document's next generation, and mints one token of the pool's
//! counter (see [`crate::blockchain::counter`]), whose supply only the
//! owner's wallet can raise. An analyst request is answered only while the
//! document's generation is the counter's: a document behind the counter
//! was restored from before a change and is refused, until an operator
//! restores the latest.
//!
//! A change is written first, with the signed transaction that takes the
//! counter to its generation (the anchor), then the anchor is sent. Until
//! it lands the pool is settling: analyst requests get `503 pool_settling`,
//! and any worker can finish the anchor under the stored-transaction rule,
//! as the next change, a request that finds the pool settling, and the
//! reconciler do. One anchor is signed and kept per generation, until the
//! next change, so a worker that comes late resends it, and the counter
//! rises by exactly one for each.

use std::str::FromStr;

use solana_pubkey::Pubkey;
use solana_signer::Signer;
use tracing::{error, info, warn};

use crate::api::pools::signed;
use crate::blockchain::counter::{self, counter_address, MINT_SIZE};
use crate::blockchain::signing::keypair_from_bytes_verified;
use crate::blockchain::SolanaClient;
use crate::chain::{self, Effect, TxSlot};
use crate::error::ApiError;
use crate::idempotency::StoredTx;
use crate::storage::pools::PoolDoc;
use crate::storage::{Change, Storage, StoreError};

/// How many times a change starts again after another change got in first.
const ATTEMPTS: usize = 4;

/// Seconds a client waits while a pool settles.
const SETTLING_RETRY_SECS: u64 = 2;

/// `503 pool_settling`: the pool's last change is still being anchored.
pub fn settling() -> ApiError {
    let mut e = ApiError::service_unavailable(
        "the pool's last change is still being anchored on-chain; retry shortly",
    )
    .with_code("pool_settling");
    e.retry_after = Some(SETTLING_RETRY_SECS);
    e
}

/// The pool made a change while a request ran on an earlier document: the
/// request starts again from the latest.
pub fn changed() -> ApiError {
    let mut e =
        ApiError::service_unavailable("the pool changed while this request ran; retry shortly")
            .with_code("pool_settling");
    e.retry_after = Some(SETTLING_RETRY_SECS);
    e
}

/// Whether the pool's stored document has made a change since `doc`.
pub async fn changed_since(storage: &Storage, doc: &PoolDoc) -> Result<bool, ApiError> {
    Ok(storage
        .pools()
        .get(&doc.pool_pda)
        .await?
        .is_some_and(|latest| latest.generation > doc.generation))
}

/// Refuse to answer from `doc` if the pool has made a change since: a
/// revocation recorded while a request ran holds for its answer too.
pub async fn still_current(storage: &Storage, doc: &PoolDoc) -> Result<(), ApiError> {
    if changed_since(storage, doc).await? {
        Err(changed())
    } else {
        Ok(())
    }
}

/// `503 pool_records_stale`, with an alert: `doc` is behind the counter's
/// generation `chain`, so it was restored from before a change.
fn stale(doc: &PoolDoc, chain: u64) -> ApiError {
    error!(
        alert = "pool_records_stale",
        pool = %doc.pool_pda,
        document = doc.generation,
        chain,
        "A pool's document is older than its on-chain generation: it was restored from before a change"
    );
    ApiError::service_unavailable(
        "the pool's records are older than its on-chain generation; an operator must restore them",
    )
    .with_code("pool_records_stale")
}

/// Whether `doc` may be answered from while its counter shows `chain`.
pub fn check(doc: &PoolDoc, chain: u64) -> Result<(), ApiError> {
    match doc.generation {
        g if g == chain => Ok(()),
        g if g < chain => Err(stale(doc, chain)),
        g if g == chain + 1 => Err(settling()),
        _ => Err(ApiError::internal(format!(
            "pool {}'s document is {} generations ahead of its counter",
            doc.pool_pda,
            doc.generation - chain
        ))),
    }
}

/// The pool's owner, whose wallet mints its counter.
fn owner(doc: &PoolDoc) -> Result<Pubkey, ApiError> {
    Pubkey::from_str(&doc.owner_pubkey)
        .map_err(|_| ApiError::internal("a pool document has an invalid owner"))
}

/// What the pool's counter shows now, at `commitment`.
pub async fn on_chain(
    solana: &SolanaClient,
    doc: &PoolDoc,
    commitment: &str,
) -> Result<u64, ApiError> {
    let owner = owner(doc)?;
    let account = solana
        .rpc()
        .get_account(&counter_address(&owner, &doc.pool_pda)?, commitment)
        .await
        .map_err(|e| ApiError::rpc_unavailable(format!("reading the pool's counter: {e}")))?;
    counter::generation(account.as_ref(), &owner).map_err(ApiError::internal)
}

/// The anchor of one generation, kept in the pool's document.
struct Anchor<'a> {
    storage: &'a Storage,
    pool_pda: &'a str,
    generation: u64,
    stored: Option<StoredTx>,
}

impl TxSlot for Anchor<'_> {
    fn stored(&self) -> Option<&StoredTx> {
        self.stored.as_ref()
    }

    async fn store(
        &mut self,
        fresh: StoredTx,
        replaces: Option<&str>,
    ) -> Result<StoredTx, ApiError> {
        let generation = self.generation;
        let mut kept = None;
        self.storage
            .pools()
            .update::<ApiError>(self.pool_pda, |doc| {
                if doc.generation != generation {
                    return Err(ApiError::conflict(
                        "the pool changed while its last change was anchored; retry",
                    ));
                }
                match &doc.anchor {
                    Some(held) if Some(held.signature.as_str()) != replaces => {
                        kept = Some(held.clone());
                        Ok(Change::Unchanged)
                    }
                    _ => {
                        doc.anchor = Some(fresh.clone());
                        kept = Some(fresh.clone());
                        Ok(Change::Changed)
                    }
                }
            })
            .await?
            .ok_or_else(|| ApiError::not_found("the pool's document is gone"))?;
        let kept = kept.ok_or_else(|| ApiError::internal("no anchor was kept"))?;
        self.stored = Some(kept.clone());
        Ok(kept)
    }
}

/// Record that the counter shows `generation`, unless the document has
/// moved on. The anchor stays.
async fn mark_anchored(storage: &Storage, pool_pda: &str, generation: u64) -> Result<(), ApiError> {
    storage
        .pools()
        .update::<StoreError>(pool_pda, |doc| {
            if doc.generation == generation && doc.anchored < generation {
                doc.anchored = generation;
                Ok(Change::Changed)
            } else {
                Ok(Change::Unchanged)
            }
        })
        .await?;
    Ok(())
}

/// Take the pool's counter to `doc.generation`, by its anchor, and record
/// that it's there.
async fn anchor(storage: &Storage, solana: &SolanaClient, doc: &PoolDoc) -> Result<(), ApiError> {
    let owner = owner(doc)?;
    let generation = doc.generation;
    let bytes = storage.wallets().read_keypair(&doc.owner_wallet_id).await?;
    let keypair = keypair_from_bytes_verified(&bytes, &doc.owner_pubkey)?;
    let rent = if generation == 1 {
        solana
            .rpc()
            .get_minimum_balance_for_rent_exemption(MINT_SIZE as usize)
            .await
            .map_err(|e| ApiError::rpc_unavailable(format!("rent lookup failed: {e}")))?
    } else {
        0
    };
    let instructions = counter::bump(&keypair.pubkey(), &doc.pool_pda, generation, rent)?;
    let mut slot = Anchor {
        storage,
        pool_pda: &doc.pool_pda,
        generation,
        stored: doc.anchor.clone(),
    };
    let effect = Effect::Generation {
        counter: counter_address(&owner, &doc.pool_pda)?,
        owner,
        generation,
    };
    chain::run(
        solana,
        &mut slot,
        &effect,
        "confirmed",
        signed(&keypair, &instructions),
    )
    .await?;
    info!(pool = %doc.pool_pda, generation, "Anchored a pool's generation");
    mark_anchored(storage, &doc.pool_pda, generation).await
}

/// Bring the counter up to `doc`'s generation if the document's last change
/// is still settling, and record when it's there. A document behind the
/// counter is refused.
pub async fn settle(
    storage: &Storage,
    solana: &SolanaClient,
    doc: &PoolDoc,
) -> Result<(), ApiError> {
    let chain = on_chain(solana, doc, "confirmed").await?;
    match check(doc, chain) {
        Err(e) if e.code == "pool_settling" => anchor(storage, solana, doc).await,
        Ok(()) if doc.anchored < doc.generation => {
            mark_anchored(storage, &doc.pool_pda, doc.generation).await
        }
        result => result,
    }
}

/// Apply `change` to the pool's document as its next generation, and anchor
/// that generation; `change` sees `doc.generation` as the one it makes. A
/// change that changes nothing makes no generation. Returns the document
/// as changed, or `None` if there is none.
pub async fn update(
    storage: &Storage,
    solana: &SolanaClient,
    pool_pda: &str,
    mut change: impl FnMut(&mut PoolDoc) -> Result<Change, ApiError>,
) -> Result<Option<PoolDoc>, ApiError> {
    for _ in 0..ATTEMPTS {
        let Some(doc) = storage.pools().get(pool_pda).await? else {
            return Ok(None);
        };
        settle(storage, solana, &doc).await?;
        let settled = doc.generation;
        let mut moved = false;
        let mut made = false;
        let changed = storage
            .pools()
            .update::<ApiError>(pool_pda, |doc| {
                if doc.generation != settled {
                    // Another change got in first: settle it, then start again.
                    moved = true;
                    return Ok(Change::Unchanged);
                }
                doc.generation = settled + 1;
                match change(doc)? {
                    Change::Unchanged => {
                        doc.generation = settled;
                        made = false;
                        Ok(Change::Unchanged)
                    }
                    Change::Changed => {
                        doc.anchor = None;
                        made = true;
                        Ok(Change::Changed)
                    }
                }
            })
            .await?;
        if moved {
            continue;
        }
        let Some(doc) = changed else {
            return Ok(None);
        };
        if made {
            if let Err(e) = anchor(storage, solana, &doc).await {
                warn!(pool = %pool_pda, generation = doc.generation, error = %e,
                    "A change is recorded, and its anchor waits for a retry or the reconciler");
                return Err(e);
            }
        }
        return Ok(Some(doc));
    }
    Err(StoreError::Contended.into())
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::blockchain::fake::{self, FakeChain};
    use crate::reconciler::settle_pools;
    use crate::storage::pools::tests::pool;
    use crate::storage::tests::files_storage;

    /// A pool whose owner's wallet `storage` holds, on a fake chain.
    pub(crate) struct Setup {
        pub storage: Arc<Storage>,
        pub chain: Arc<FakeChain>,
        pub solana: Arc<SolanaClient>,
        pub doc: PoolDoc,
        pub counter: Pubkey,
    }

    pub(crate) async fn setup() -> Setup {
        let storage = Arc::new(files_storage());
        let chain = Arc::new(FakeChain::default());
        chain.lands.store(true, std::sync::atomic::Ordering::SeqCst);
        chain
            .block_height
            .store(100, std::sync::atomic::Ordering::SeqCst);
        let (wallet_id, owner) = crate::storage::wallets::tests::wallet(&storage).await;
        let mut doc = pool("P1", &wallet_id);
        doc.owner_pubkey = owner.to_string();
        storage.pools().create(&doc).await.unwrap();
        Setup {
            counter: counter_address(&owner, "P1").unwrap(),
            storage,
            solana: Arc::new(fake::start(chain.clone())),
            chain,
            doc,
        }
    }

    impl Setup {
        pub(crate) async fn change(&self, name: &str) -> Result<PoolDoc, ApiError> {
            update(&self.storage, &self.solana, "P1", |doc| {
                doc.pool_name = name.to_string();
                Ok(Change::Changed)
            })
            .await
            .map(|doc| doc.unwrap())
        }

        pub(crate) async fn stored(&self) -> PoolDoc {
            self.storage.pools().get("P1").await.unwrap().unwrap()
        }
    }

    #[tokio::test]
    async fn each_change_is_one_generation_and_one_token() {
        let s = setup().await;
        assert_eq!(on_chain(&s.solana, &s.doc, "confirmed").await.unwrap(), 0);
        for (i, name) in ["one", "two", "three"].iter().enumerate() {
            let doc = s.change(name).await.unwrap();
            assert_eq!(doc.generation, i as u64 + 1);
            assert_eq!(s.chain.supply(&s.counter), Some(i as u64 + 1));
            let stored = s.stored().await;
            assert_eq!(stored.anchored, i as u64 + 1, "recorded once it lands");
            assert!(stored.anchor.is_some(), "kept for a worker that comes late");
        }
        // A change that changes nothing makes no generation.
        let same = update(&s.storage, &s.solana, "P1", |_| Ok(Change::Unchanged))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(same.generation, 3);
        assert_eq!(s.chain.supply(&s.counter), Some(3));
        assert!(check(&same, 3).is_ok());
    }

    #[tokio::test]
    async fn a_change_whose_anchor_never_landed_is_finished_by_the_next() {
        let s = setup().await;
        s.change("one").await.unwrap();
        // The next change is written, and its anchor doesn't get through.
        s.chain
            .preflight
            .lock()
            .unwrap()
            .replace(serde_json::json!("BlockhashNotFound"));
        assert!(s.change("two").await.is_err());
        s.chain.preflight.lock().unwrap().take();
        let pending = s.stored().await;
        assert_eq!(
            (
                pending.generation,
                pending.anchored,
                pending.anchor.is_some()
            ),
            (2, 1, true)
        );
        assert_eq!(
            check(&pending, 1).unwrap_err().code,
            "pool_settling",
            "analysts wait"
        );

        // The next change finishes it first, then makes its own.
        let doc = s.change("three").await.unwrap();
        assert_eq!(doc.generation, 3);
        assert_eq!(s.chain.supply(&s.counter), Some(3), "one token each");
    }

    #[tokio::test]
    async fn an_expired_anchor_is_replaced_once_and_counted_once() {
        let s = setup().await;
        s.change("one").await.unwrap();
        s.chain
            .preflight
            .lock()
            .unwrap()
            .replace(serde_json::json!("BlockhashNotFound"));
        assert!(s.change("two").await.is_err(), "stored, but it never lands");
        s.chain.preflight.lock().unwrap().take();
        let first = s.stored().await.anchor.unwrap();
        // Past its last valid block height: it can never land.
        s.chain.block_height.store(
            first.last_valid_block_height + 1,
            std::sync::atomic::Ordering::SeqCst,
        );
        let pending = s.stored().await;
        let (a, b) = tokio::join!(
            settle(&s.storage, &s.solana, &pending),
            settle(&s.storage, &s.solana, &pending)
        );
        assert!(a.is_ok() || b.is_ok(), "{a:?} {b:?}");
        settle(&s.storage, &s.solana, &s.stored().await)
            .await
            .unwrap();
        assert_eq!(
            s.chain.supply(&s.counter),
            Some(2),
            "replaced, and counted once"
        );
        let settled = s.stored().await;
        assert_eq!(settled.anchored, 2);
        assert_ne!(
            settled.anchor.unwrap().signature,
            first.signature,
            "the replacement is kept"
        );
        let landed: Vec<_> = s.chain.landed.lock().unwrap().clone();
        assert!(
            !landed.iter().any(|(sig, _)| *sig == first.signature),
            "the expired one never landed"
        );
    }

    #[tokio::test]
    async fn an_answer_waits_for_a_change_made_while_its_request_ran() {
        let s = setup().await;
        let read = s.stored().await;
        assert!(still_current(&s.storage, &read).await.is_ok());
        s.change("one").await.unwrap();
        let refused = still_current(&s.storage, &read).await.unwrap_err();
        assert_eq!(
            (refused.code, refused.retry_after),
            ("pool_settling", Some(2))
        );
        assert!(still_current(&s.storage, &s.stored().await).await.is_ok());
    }

    #[tokio::test]
    async fn a_worker_that_comes_late_gets_the_landed_anchor_back() {
        let s = setup().await;
        s.change("one").await.unwrap();
        let landed = s.stored().await.anchor.unwrap();
        // A worker that read the counter before the anchor landed stores the
        // anchor it signed only now.
        let mut slot = Anchor {
            storage: &s.storage,
            pool_pda: "P1",
            generation: 1,
            stored: None,
        };
        let late = StoredTx {
            transaction: String::new(),
            signature: "late".into(),
            last_valid_block_height: 0,
        };
        let kept = slot.store(late, None).await.unwrap();
        assert_eq!(kept.signature, landed.signature, "resent, not signed again");
        assert_eq!(s.chain.supply(&s.counter), Some(1));
    }

    #[tokio::test]
    async fn the_reconciler_settles_what_a_worker_left_unrecorded() {
        let s = setup().await;
        s.change("one").await.unwrap();
        // A worker stopped after its anchor landed, before recording it.
        s.storage
            .pools()
            .update::<StoreError>("P1", |doc| {
                doc.anchored = 0;
                Ok(Change::Changed)
            })
            .await
            .unwrap();
        assert_eq!(settle_pools(&s.storage, &s.solana).await.unwrap(), 1);
        assert_eq!(s.stored().await.anchored, 1);
        assert_eq!(
            settle_pools(&s.storage, &s.solana).await.unwrap(),
            0,
            "and passes over it after"
        );

        // Another stopped after writing its change, before storing an anchor.
        s.storage
            .pools()
            .update::<StoreError>("P1", |doc| {
                doc.generation = 2;
                doc.anchor = None;
                Ok(Change::Changed)
            })
            .await
            .unwrap();
        assert_eq!(settle_pools(&s.storage, &s.solana).await.unwrap(), 1);
        let doc = s.stored().await;
        assert_eq!((doc.generation, doc.anchored), (2, 2));
        assert_eq!(s.chain.supply(&s.counter), Some(2));
    }

    #[tokio::test]
    async fn a_restored_older_document_is_refused_and_can_change_nothing() {
        let s = setup().await;
        s.change("one").await.unwrap();
        let before = s.stored().await;
        s.change("two").await.unwrap();
        // A storage administrator restores the document from before the
        // second change.
        let (_, etag) = s
            .storage
            .state()
            .get_json::<PoolDoc>("pools/P1.json")
            .await
            .unwrap()
            .unwrap();
        s.storage
            .state()
            .replace_json("pools/P1.json", &before, &etag)
            .await
            .unwrap();
        let chain = on_chain(&s.solana, &before, "confirmed").await.unwrap();
        assert_eq!(
            check(&before, chain).unwrap_err().code,
            "pool_records_stale"
        );
        let refused = s.change("three").await.unwrap_err();
        assert_eq!(refused.code, "pool_records_stale");
        assert_eq!(s.chain.supply(&s.counter), Some(2));
    }

    #[tokio::test]
    async fn lamports_sent_to_the_counter_first_dont_stop_it() {
        let s = setup().await;
        s.chain.accounts.lock().unwrap().push(s.counter);
        assert_eq!(on_chain(&s.solana, &s.doc, "confirmed").await.unwrap(), 0);
        assert_eq!(s.change("one").await.unwrap().generation, 1);
        assert_eq!(s.chain.supply(&s.counter), Some(1));
    }

    /// On the real programs: lamports someone sent to the counter's address
    /// first don't stop the first change, each change is exactly one token,
    /// and a restored older document is refused.
    #[tokio::test]
    #[ignore = "needs a surfnet: run `just chain-test`"]
    async fn surfnet_anchors_each_generation_once() {
        use crate::blockchain::surfnet;
        let storage = files_storage();
        let solana = surfnet::client();
        let (wallet_id, owner) = crate::storage::wallets::tests::wallet(&storage).await;
        surfnet::fund(&owner, 10_000_000_000).await;
        let pool_pda = Pubkey::new_unique().to_string();
        let mut doc = pool(&pool_pda, &wallet_id);
        doc.owner_pubkey = owner.to_string();
        storage.pools().create(&doc).await.unwrap();
        let counter = counter_address(&owner, &pool_pda).unwrap();
        surfnet::fund(&counter, 890_880).await;
        assert_eq!(on_chain(&solana, &doc, "confirmed").await.unwrap(), 0);

        for n in 1..=3 {
            let changed = update(&storage, &solana, &pool_pda, |doc| {
                doc.pool_name = format!("v{n}");
                Ok(Change::Changed)
            })
            .await
            .unwrap()
            .unwrap();
            assert_eq!(changed.generation, n);
            assert_eq!(on_chain(&solana, &changed, "confirmed").await.unwrap(), n);
        }
        let doc = storage.pools().get(&pool_pda).await.unwrap().unwrap();
        assert_eq!(doc.anchored, 3, "every anchor landed");
        settle(&storage, &solana, &doc).await.unwrap();
        assert_eq!(on_chain(&solana, &doc, "confirmed").await.unwrap(), 3);

        let mut restored = doc;
        restored.generation = 2;
        let chain = on_chain(&solana, &restored, "confirmed").await.unwrap();
        assert_eq!(
            check(&restored, chain).unwrap_err().code,
            "pool_records_stale"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_changes_take_one_generation_each() {
        let s = Arc::new(setup().await);
        let changes: Vec<_> = (0..4)
            .map(|i| {
                let s = s.clone();
                tokio::spawn(async move { s.change(&format!("name-{i}")).await })
            })
            .collect();
        let mut made = 0;
        for change in changes {
            if change.await.unwrap().is_ok() {
                made += 1;
            }
        }
        let doc = s.stored().await;
        assert!(made >= 1);
        assert_eq!(
            s.chain.supply(&s.counter),
            Some(doc.generation),
            "no double count"
        );
        assert!(check(&doc, doc.generation).is_ok());
    }
}
