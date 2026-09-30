// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! The reconciler finishes chain sagas whose request stopped after the
//! chain step and that no client retried.
//!
//! Every worker runs it every 5 minutes. It lists `staged/`, and for each
//! saga older than 10 minutes whose on-chain effect exists at `finalized`
//! but whose document lacks it, it writes the pool document or adds the
//! issuance entry, with the signature from the saga's idempotency record.
//! It never deletes or undoes anything. Each of its writes is create-only,
//! or a compare-and-swap that adds a missing entry, so any number of
//! workers can run it at once. Dev builds can shorten both times, so the
//! fault suite needn't wait 15 minutes.

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use chrono::{TimeDelta, Utc};
use solana_pubkey::Pubkey;
use tracing::{info, warn};

use crate::blockchain::drt::pda::derive_grant_pda;
use crate::blockchain::SolanaClient;
use crate::chain::creating_signature;
use crate::error::ApiError;
use crate::idempotency::stored_signature;
use crate::storage::staged::{Saga, Staged};
use crate::storage::{Change, Storage};
use crate::store::Created;

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
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(timing.interval).await;
            match reconcile(&storage, &solana, timing.min_age).await {
                Ok(0) => {}
                Ok(finished) => info!(finished, "Finished abandoned sagas"),
                Err(e) => warn!(error = %e, "Reconciling staged sagas failed"),
            }
        }
    });
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
            let Some(signature) = effect_signature(storage, solana, &staged.record, &pda).await?
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
            let (grant_pda, _) = derive_grant_pda(&commitment);
            let Some(signature) =
                effect_signature(storage, solana, &staged.record, &grant_pda).await?
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
    }
}

/// The signature that created `account`, if it exists at `finalized`.
async fn effect_signature(
    storage: &Storage,
    solana: &SolanaClient,
    record: &str,
    account: &Pubkey,
) -> Result<Option<String>, ApiError> {
    let exists = solana
        .rpc()
        .account_exists(account, "finalized")
        .await
        .map_err(|e| ApiError::rpc_unavailable(format!("account lookup failed: {e}")))?;
    if !exists {
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
    use crate::storage::pools::tests::{pool, upload};
    use crate::storage::tests::files_storage;
    use serde_json::json;

    fn old() -> chrono::DateTime<Utc> {
        Utc::now() - TimeDelta::minutes(11)
    }

    #[tokio::test]
    async fn an_abandoned_issuance_gets_its_entry_once_its_burn_exists() {
        let storage = files_storage();
        storage.pools().create(&pool("P1", "w1")).await.unwrap();

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
                pool_pda: "P1".into(),
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
        *chain.accounts.lock().unwrap() = grants;
        chain.land("sig-burn", true);
        let solana = fake::start(chain);

        assert_eq!(
            reconcile(&storage, &solana, Timing::default().min_age)
                .await
                .unwrap(),
            1
        );
        let doc = storage.pools().get("P1").await.unwrap().unwrap();
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
        *chain.accounts.lock().unwrap() = vec![on_chain];
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
