// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! The reconciler finishes chain sagas whose request stopped after the
//! chain step and that no client retried.
//!
//! Every worker runs it every 5 minutes. It lists `staged/`, and for each
//! saga older than 10 minutes whose on-chain effect exists at `finalized`
//! but whose document lacks it, it writes the pool document or adds the
//! issuance or grant entry, with the signature from the saga's idempotency
//! record. A grant revoked after the saga was staged wins over it, so a
//! grant is never restored. It never deletes or undoes anything. Each of
//! its writes is create-only, or a compare-and-swap that adds a missing
//! entry, so any number of workers can run it at once. Dev builds can
//! shorten both times, so the fault suite needn't wait 15 minutes.
//!
//! The same pass returns transfer receipts' deposits to their wallets once
//! [`RECEIPTS_KEPT`] has passed and their requests' idempotency records are
//! gone: a receipt is what refuses a second copy of its transfer, so it
//! stays while a retry could still come.

use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use chrono::{DateTime, TimeDelta, Utc};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use tracing::{debug, info, warn};

use crate::api::credentials::decode_right_id;
use crate::api::pools::signed;
use crate::blockchain::drt::pda::{derive_drt_config_pda, derive_grant_pda};
use crate::blockchain::drt::types::APPEND_DRT_NAME;
use crate::blockchain::signing::keypair_from_bytes_verified;
use crate::blockchain::transactions::{is_receipt, receipt_address, sweep_receipt};
use crate::blockchain::SolanaClient;
use crate::chain::{creating_signature, Effect};
use crate::error::ApiError;
use crate::idempotency::stored_signature;
use crate::storage::pools::{PoolDoc, Recording};
use crate::storage::receipts::Receipt;
use crate::storage::staged::{Saga, Staged};
use crate::storage::{Change, Storage};
use crate::store::Created;

/// The least time a transfer's receipt stays: a day longer than a storage
/// lifecycle rule keeps idempotency records. The sweep also waits for the
/// record itself to be gone.
pub const RECEIPTS_KEPT: Duration = Duration::from_secs(8 * 24 * 60 * 60);

/// The most receipts one sweep transaction returns.
const SWEEP_BATCH: usize = 8;

/// A wallet with less than this can't pay a sweep's fee, so it isn't tried.
const SWEEP_FEE_LAMPORTS: u64 = 5_000;

/// When the reconciler runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timing {
    /// How often each worker reconciles.
    pub interval: Duration,
    /// A younger saga may still have its request running.
    pub min_age: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(5 * 60),
            min_age: Duration::from_secs(10 * 60),
        }
    }
}

/// Reconcile every `timing.interval`.
pub fn spawn(storage: Arc<Storage>, solana: Arc<SolanaClient>, timing: Timing) {
    crate::work::supervise("reconciler", move || {
        let (storage, solana) = (storage.clone(), solana.clone());
        async move {
            loop {
                tokio::time::sleep(timing.interval).await;
                match reconcile(&storage, &solana, timing.min_age).await {
                    Ok(0) => {}
                    Ok(finished) => info!(finished, "Finished abandoned sagas"),
                    Err(e) => warn!(error = %e, "Reconciling staged sagas failed"),
                }
                let kept = TimeDelta::from_std(RECEIPTS_KEPT).unwrap_or(TimeDelta::MAX);
                match sweep_receipts(&storage, &solana, Utc::now() - kept).await {
                    Ok(0) => {}
                    Ok(swept) => info!(swept, "Swept transfer receipts"),
                    Err(e) => warn!(error = %e, "Sweeping transfer receipts failed"),
                }
            }
        }
    });
}

/// Return the deposits of the receipts created before `before`, whose
/// requests' idempotency records are gone, to their wallets, a transaction
/// for each few, and mark them swept. A receipt that isn't there, because
/// its transfer never landed or another worker swept it, is marked swept
/// too. Returns how many it marked.
pub async fn sweep_receipts(
    storage: &Storage,
    solana: &SolanaClient,
    before: DateTime<Utc>,
) -> Result<usize, ApiError> {
    let mut by_wallet: BTreeMap<String, Vec<Receipt>> = BTreeMap::new();
    for receipt in storage.receipts().due(before).await? {
        by_wallet
            .entry(receipt.wallet_id.clone())
            .or_default()
            .push(receipt);
    }
    let mut swept = 0;
    for (wallet_id, receipts) in by_wallet {
        match sweep_wallet(storage, solana, &wallet_id, &receipts).await {
            Ok(n) => swept += n,
            Err(e) => warn!(wallet_id = %wallet_id, error = %e,
                "A wallet's transfer receipts couldn't be swept"),
        }
    }
    Ok(swept)
}

async fn sweep_wallet(
    storage: &Storage,
    solana: &SolanaClient,
    wallet_id: &str,
    receipts: &[Receipt],
) -> Result<usize, ApiError> {
    let wallet = storage
        .wallets()
        .get(wallet_id)
        .await?
        .ok_or_else(|| ApiError::internal("a receipt's wallet is gone"))?;
    let bytes = storage.wallets().read_keypair(wallet_id).await?;
    let keypair = keypair_from_bytes_verified(&bytes, &wallet.public_address)?;
    let owner = keypair.pubkey();
    let rpc = solana.rpc();
    let rpc_error = |e| ApiError::rpc_unavailable(format!("sweeping receipts: {e}"));
    if rpc.get_balance(&owner).await.map_err(rpc_error)? < SWEEP_FEE_LAMPORTS {
        debug!(wallet_id, "A wallet can't pay to sweep its receipts yet");
        return Ok(0);
    }
    let mut swept = 0;
    for batch in receipts.chunks(SWEEP_BATCH) {
        let addresses = batch
            .iter()
            .map(|r| receipt_address(&owner, &r.seed))
            .collect::<Result<Vec<_>, _>>()?;
        let (_, accounts) = rpc
            .get_multiple_accounts(&addresses, "finalized")
            .await
            .map_err(rpc_error)?;
        let mut held = Vec::new();
        let mut instructions = Vec::new();
        for ((receipt, address), account) in batch.iter().zip(&addresses).zip(&accounts) {
            match account {
                Some(a) if is_receipt(Some(a)) && a.lamports > 0 => {
                    instructions.push(sweep_receipt(&owner, address, &receipt.seed, a.lamports));
                    held.push(receipt);
                }
                _ => {
                    storage.receipts().swept(&receipt.seed, None).await?;
                    swept += 1;
                }
            }
        }
        if instructions.is_empty() {
            continue;
        }
        let (blockhash, _) = rpc.get_latest_blockhash().await.map_err(rpc_error)?;
        let tx = signed(&keypair, &instructions)(blockhash);
        let encoded = bincode::serialize(&tx)
            .map(|bytes| BASE64.encode(bytes))
            .map_err(|e| ApiError::internal(format!("serializing a sweep: {e}")))?;
        rpc.send_encoded_transaction(&encoded)
            .await
            .map_err(rpc_error)?;
        let signature = tx.signatures[0].to_string();
        solana.await_confirmation(&signature, "confirmed").await?;
        for receipt in held {
            storage
                .receipts()
                .swept(&receipt.seed, Some(&signature))
                .await?;
            swept += 1;
        }
    }
    Ok(swept)
}

/// One pass over `staged/`, finishing sagas at least `min_age` old. Returns
/// how many it finished.
pub async fn reconcile(
    storage: &Storage,
    solana: &SolanaClient,
    min_age: Duration,
) -> Result<usize, ApiError> {
    let min_age = TimeDelta::from_std(min_age).unwrap_or(TimeDelta::MAX);
    let mut finished = 0;
    for staged in storage.sagas().all().await? {
        if Utc::now() - staged.staged_at < min_age {
            continue;
        }
        match finish(storage, solana, &staged).await {
            Ok(true) => finished += 1,
            Ok(false) => {}
            Err(e) => warn!(saga = %describe(&staged.saga), error = %e,
                "An abandoned saga couldn't be finished"),
        }
    }
    Ok(finished)
}

fn describe(saga: &Saga) -> String {
    match saga {
        Saga::Pool { pool } => format!("pool {}", pool.pool_pda),
        Saga::Issue { pool_pda, upload } => format!("issue {} in {pool_pda}", upload.record_id),
        Saga::Grant { pool_pda, grant } => format!("grant {} in {pool_pda}", grant.grant_id),
    }
}

/// Finish `staged` if its effect exists and its document lacks it.
/// Returns whether it wrote anything.
async fn finish(
    storage: &Storage,
    solana: &SolanaClient,
    staged: &Staged,
) -> Result<bool, ApiError> {
    match &staged.saga {
        Saga::Pool { pool } => {
            if storage.pools().get(&pool.pool_pda).await?.is_some() {
                return Ok(false);
            }
            let pda = Pubkey::from_str(&pool.pool_pda)
                .map_err(|_| ApiError::internal("a staged pool has an invalid PDA"))?;
            let effect = Effect::Pool(pda);
            let Some(signature) =
                effect_signature(storage, solana, &staged.record, &effect).await?
            else {
                return Ok(false);
            };
            let mut doc = (**pool).clone();
            doc.creation_signature = signature;
            Ok(matches!(
                storage.pools().create(&doc).await?,
                Created::New(_)
            ))
        }
        Saga::Issue { pool_pda, upload } => {
            let Some(doc) = storage.pools().get(pool_pda).await? else {
                return Ok(false);
            };
            if doc.upload(&upload.record_id).is_some() {
                return Ok(false);
            }
            let commitment = upload
                .commitment_bytes()
                .ok_or_else(|| ApiError::internal("a staged issuance has no commitment"))?;
            let effect = burn(&doc, APPEND_DRT_NAME, &commitment)?;
            let Some(signature) =
                effect_signature(storage, solana, &staged.record, &effect).await?
            else {
                return Ok(false);
            };
            let mut entry = upload.clone();
            entry.signature = Some(signature);
            let mut added = false;
            storage
                .pools()
                .update::<ApiError>(pool_pda, |doc| {
                    added = doc.upload(&entry.record_id).is_none();
                    if !added {
                        return Ok(Change::Unchanged);
                    }
                    doc.issuances.push(entry.clone());
                    Ok(Change::Changed)
                })
                .await?;
            Ok(added)
        }
        Saga::Grant { pool_pda, grant } => {
            let Some(doc) = storage.pools().get(pool_pda).await? else {
                return Ok(false);
            };
            if doc.recording(grant) != Recording::Add {
                return Ok(false);
            }
            let commitment = grant
                .commitment_bytes()
                .ok_or_else(|| ApiError::internal("a staged grant has no commitment"))?;
            let effect = burn(&doc, &grant.drt_name, &commitment)?;
            let Some(signature) =
                effect_signature(storage, solana, &staged.record, &effect).await?
            else {
                return Ok(false);
            };
            let mut entry = grant.clone();
            entry.signature = Some(signature);
            let mut added = false;
            storage
                .pools()
                .update::<ApiError>(pool_pda, |doc| {
                    added = doc.recording(&entry) == Recording::Add;
                    if !added {
                        return Ok(Change::Unchanged);
                    }
                    doc.grants.push(entry.clone());
                    Ok(Change::Changed)
                })
                .await?;
            Ok(added)
        }
    }
}

/// The burn of one of `doc`'s `drt_name` DRTs under `commitment`.
fn burn(doc: &PoolDoc, drt_name: &str, commitment: &[u8; 32]) -> Result<Effect, ApiError> {
    let pool = Pubkey::from_str(&doc.pool_pda)
        .map_err(|_| ApiError::internal("a pool document has an invalid PDA"))?;
    let drt = doc
        .drts
        .get(drt_name)
        .ok_or_else(|| ApiError::internal(format!("the pool has no {drt_name} DRT")))?;
    let right_id = decode_right_id(&drt.right_id_hex)?;
    Ok(Effect::Grant {
        pda: derive_grant_pda(commitment).0,
        drt_config: derive_drt_config_pda(&pool, &right_id).0,
    })
}

/// The signature that made `effect`, an account the program created, if it
/// has happened at `finalized`.
async fn effect_signature(
    storage: &Storage,
    solana: &SolanaClient,
    record: &str,
    effect: &Effect,
) -> Result<Option<String>, ApiError> {
    let (Effect::Pool(account) | Effect::Grant { pda: account, .. }) = effect else {
        return Err(ApiError::internal("the reconciler finishes only creations"));
    };
    if !effect.happened(solana, "finalized").await? {
        return Ok(None);
    }
    let stored = stored_signature(storage, record).await?;
    creating_signature(solana, stored.as_deref(), account, "finalized")
        .await
        .map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::fake::{self, FakeChain};
    use crate::idempotency::{Idempotent, Opened, Operation, StoredTx};
    use crate::storage::pools::tests::{grant, pool, upload};
    use crate::storage::pools::GrantRevocation;
    use crate::storage::tests::files_storage;
    use serde_json::json;

    fn old() -> chrono::DateTime<Utc> {
        Utc::now() - TimeDelta::minutes(11)
    }

    /// The pool the burn tests use, on chain at a real address.
    const P1: Pubkey = Pubkey::new_from_array([11; 32]);

    /// Each DRT's right ID in [`drt_pool`].
    fn right_id(name: &str) -> [u8; 16] {
        [name.len() as u8; 16]
    }

    /// The DRT config of [`drt_pool`]'s `name` DRT.
    fn drt_config(name: &str) -> Pubkey {
        derive_drt_config_pda(&P1, &right_id(name)).0
    }

    /// A pool document at [`P1`] with an append DRT and the analysis's.
    fn drt_pool() -> PoolDoc {
        let mut doc = pool(&P1.to_string(), "w1");
        for name in [APPEND_DRT_NAME, "awards-report-v1"] {
            doc.drts.insert(
                name.into(),
                crate::storage::pools::DrtMetadata {
                    right_id_hex: hex::encode(right_id(name)),
                    mint: Pubkey::new_unique().to_string(),
                    supply: 5,
                    code_repo_url: String::new(),
                    code_hash_hex: hex::encode([0; 32]),
                },
            );
        }
        doc
    }

    #[tokio::test]
    async fn old_receipts_go_back_to_their_wallet_and_young_ones_stay() {
        use crate::storage::wallets::NewKeypair;
        use std::sync::atomic::Ordering::SeqCst;

        let storage = files_storage();
        let chain = Arc::new(FakeChain::default());
        let solana = fake::start(chain.clone());
        chain.lands.store(true, SeqCst);
        let keypair = solana_keypair::Keypair::new();
        let owner = keypair.pubkey();
        let wallet = NewKeypair {
            bytes: zeroize::Zeroizing::new(keypair.to_bytes().to_vec()),
            address: owner.to_string(),
        };
        storage
            .wallets()
            .create("u-1", "w-1", None, wallet, |_| None)
            .await
            .unwrap();
        let at = |seed: &str| receipt_address(&owner, seed).unwrap();
        let receipt = |seed: &str, created_at| Receipt {
            seed: seed.into(),
            wallet_id: "w-1".into(),
            address: at(seed).to_string(),
            record: format!("idempotency/u-1/{seed}.json"),
            created_at,
            swept_at: None,
            sweep_signature: None,
        };
        // Two old receipts on-chain, an old one whose transfer never landed,
        // and a young one.
        let old = Utc::now() - TimeDelta::days(9);
        for (seed, created_at, on_chain) in [
            ("s1", old, true),
            ("s2", old, true),
            ("s3", old, false),
            ("s4", Utc::now(), true),
        ] {
            storage
                .receipts()
                .record(&receipt(seed, created_at))
                .await
                .unwrap();
            if on_chain {
                chain.accounts.lock().unwrap().push(at(seed));
            }
        }
        let before = Utc::now() - TimeDelta::days(8);

        // A wallet that can't pay the sweep's fee isn't tried.
        assert_eq!(sweep_receipts(&storage, &solana, before).await.unwrap(), 0);
        assert!(chain.sent().is_empty());

        chain.balance.store(1_000_000, SeqCst);
        assert_eq!(sweep_receipts(&storage, &solana, before).await.unwrap(), 3);
        assert_eq!(chain.sent().len(), 1, "one transaction for the wallet");
        assert!(!chain.exists(&at("s1")) && !chain.exists(&at("s2")));
        assert!(chain.exists(&at("s4")), "a young receipt stays");
        assert!(storage.receipts().due(before).await.unwrap().is_empty());
        assert_eq!(sweep_receipts(&storage, &solana, before).await.unwrap(), 0);
        assert_eq!(chain.sent().len(), 1);
    }

    #[tokio::test]
    async fn an_abandoned_issuance_gets_its_entry_once_its_burn_exists() {
        let storage = files_storage();
        storage.pools().create(&drt_pool()).await.unwrap();

        // A request stored its burn, then died before recording the upload.
        let request = Idempotent::post(
            "0f8fad5b-d9cb-469f-a165-70867728950e",
            "/v1/drt/pools/{pool_pda}/issue",
            "/v1/drt/pools/P1/issue",
        );
        let Opened::Run(mut op) = Operation::open(&storage, "user-1", &request, b"id\n1\n")
            .await
            .unwrap()
        else {
            panic!("a new request");
        };
        let burn = StoredTx {
            transaction: "AA==".into(),
            signature: "sig-burn".into(),
            last_valid_block_height: 1,
        };
        op.store_tx(burn, None).await.unwrap();

        let mut grants = Vec::new();
        for (record_id, staged_at) in [("r-old", old()), ("r-young", Utc::now())] {
            let commitment = [record_id.len() as u8; 32];
            grants.push(derive_grant_pda(&commitment).0);
            let mut entry = upload(record_id, 2);
            entry.commitment = Some(hex::encode(commitment));
            let saga = Saga::Issue {
                pool_pda: P1.to_string(),
                upload: entry,
            };
            let staged = Staged {
                record: op.record_path().into(),
                staged_at,
                saga,
            };
            storage
                .sagas()
                .stage(&format!("issue-{record_id}"), staged)
                .await
                .unwrap();
        }
        let chain = Arc::new(FakeChain::default());
        for pda in grants {
            chain.grant(pda, drt_config(APPEND_DRT_NAME));
        }
        chain.land("sig-burn", true);
        let solana = fake::start(chain);

        assert_eq!(
            reconcile(&storage, &solana, Timing::default().min_age)
                .await
                .unwrap(),
            1
        );
        let doc = storage.pools().get(&P1.to_string()).await.unwrap().unwrap();
        let entries: Vec<_> = doc
            .issuances
            .iter()
            .map(|u| (u.record_id.as_str(), u.signature.as_deref()))
            .collect();
        assert_eq!(
            entries,
            [("r-old", Some("sig-burn"))],
            "the young saga waits"
        );

        // Another pass, on any worker, changes nothing.
        assert_eq!(
            reconcile(&storage, &solana, Timing::default().min_age)
                .await
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn an_abandoned_grant_is_recorded_unless_a_revocation_came_after() {
        let storage = files_storage();
        storage.pools().create(&drt_pool()).await.unwrap();
        let request = Idempotent::post(
            "0f8fad5b-d9cb-469f-a165-70867728950e",
            "/v1/drt/pools/{pool_pda}/grant",
            "/v1/drt/pools/P1/grant",
        );
        let Opened::Run(mut op) = Operation::open(&storage, "admin-1", &request, b"{}")
            .await
            .unwrap()
        else {
            panic!("a new request");
        };
        let burn = StoredTx {
            transaction: "AA==".into(),
            signature: "sig-grant".into(),
            last_valid_block_height: 1,
        };
        op.store_tx(burn, None).await.unwrap();

        // Two grant requests burned, then died; Bo's access was revoked
        // after his was staged.
        let mut grant_pdas = Vec::new();
        for (grant_id, analyst) in [("g-ana", "ana"), ("g-bo", "bo")] {
            let mut entry = grant(grant_id, analyst, 11);
            entry.signature = None;
            grant_pdas.push(derive_grant_pda(&entry.commitment_bytes().unwrap()).0);
            let staged = Staged {
                record: op.record_path().into(),
                staged_at: old(),
                saga: Saga::Grant {
                    pool_pda: P1.to_string(),
                    grant: entry,
                },
            };
            storage
                .sagas()
                .stage(&format!("grant-{grant_id}"), staged)
                .await
                .unwrap();
        }
        storage
            .pools()
            .update::<ApiError>(&P1.to_string(), |doc| {
                let mut earlier = grant("g-bo-earlier", "bo", 20);
                earlier.revoked = Some(GrantRevocation {
                    revocation_id: "r-bo".into(),
                    revoked_by: "alice".into(),
                    revoked_at: Utc::now() - TimeDelta::minutes(5),
                    signature: Some("sig-close".into()),
                });
                doc.grants.push(earlier);
                Ok(Change::Changed)
            })
            .await
            .unwrap();
        let chain = Arc::new(FakeChain::default());
        for pda in grant_pdas {
            chain.grant(pda, drt_config("awards-report-v1"));
        }
        chain.land("sig-grant", true);
        let solana = fake::start(chain);

        assert_eq!(
            reconcile(&storage, &solana, Timing::default().min_age)
                .await
                .unwrap(),
            1
        );
        let doc = storage.pools().get(&P1.to_string()).await.unwrap().unwrap();
        let ana = doc.active_grant("ana", "awards-report-v1").unwrap();
        assert_eq!(
            (ana.grant_id.as_str(), ana.signature.as_deref()),
            ("g-ana", Some("sig-grant"))
        );
        assert!(ana.targets().is_some(), "the staged targets are recorded");
        assert!(doc.active_grant("bo", "awards-report-v1").is_none());
        assert_eq!(
            reconcile(&storage, &solana, Timing::default().min_age)
                .await
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn an_abandoned_pool_is_written_only_if_it_exists_on_chain() {
        let storage = files_storage();
        let on_chain = Pubkey::new_from_array([1; 32]);
        let never_created = Pubkey::new_from_array([2; 32]);
        for pda in [on_chain, never_created] {
            let mut doc = pool(&pda.to_string(), "w1");
            doc.creation_signature = String::new();
            let staged = Staged {
                record: "idempotency/user-1/lost.json".into(),
                staged_at: old(),
                saga: Saga::Pool {
                    pool: Box::new(doc),
                },
            };
            storage
                .sagas()
                .stage(&format!("pool-{pda}"), staged)
                .await
                .unwrap();
        }
        // No record survives, so the creating transaction comes from the
        // account's history: the oldest that succeeded.
        let failed = json!({ "InstructionError": [0, "Custom"] });
        let chain = Arc::new(FakeChain::default());
        chain.pool(on_chain, Pubkey::new_unique());
        *chain.history.lock().unwrap() = vec![
            json!({ "signature": "sig-later", "err": null }),
            json!({ "signature": "sig-create", "err": null }),
            json!({ "signature": "sig-failed", "err": failed }),
        ];
        let solana = fake::start(chain);

        assert_eq!(
            reconcile(&storage, &solana, Timing::default().min_age)
                .await
                .unwrap(),
            1
        );
        let doc = storage
            .pools()
            .get(&on_chain.to_string())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(doc.creation_signature, "sig-create");
        let absent = storage.pools().get(&never_created.to_string()).await;
        assert!(absent.unwrap().is_none());
    }
}
