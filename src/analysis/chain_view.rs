// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Whether the chain shows an analyst's grant: the program's Grant at the
//! grant's PDA, for the pool's Execute DRT config.
//!
//! Every analyst request needs both an active grant in the pool document
//! and the chain showing it. The chain is read on demand, never on a timer,
//! one batched call per pool:
//!
//! - a reading younger than `refresh` is used as it is;
//! - an older one, within `grace`, is used while the pool is read again in
//!   the background, one refresh at a time per pool;
//! - a grant with no reading, not even a stored one, or one past `grace`,
//!   is read before answering, and if the RPC fails the request fails.
//!
//! Only the pool's owner can close a Grant PDA, the owner's key never
//! leaves the worker, and the worker records every revocation in the pool
//! document before it closes the PDA. So while the RPC is down the chain
//! can't take access away behind the worker's back, and `grace` bounds only
//! how long a restored older pool document could go unnoticed. A reading
//! counts for a grant only if it's no older than the grant, so a grant made
//! again after a revocation is read afresh.

use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use chrono::{DateTime, TimeDelta, Utc};
use solana_pubkey::Pubkey;
use tracing::warn;

use crate::api::credentials::decode_right_id;
use crate::blockchain::drt::accounts::{grant_state, GrantState};
use crate::blockchain::drt::pda::{derive_drt_config_pda, derive_grant_pda};
use crate::blockchain::rpc::{RpcError, MAX_MULTIPLE_ACCOUNTS};
use crate::blockchain::SolanaClient;
use crate::error::ApiError;
use crate::storage::chain::{merge, Seen, Views};
use crate::storage::pools::{Grant, PoolDoc};
use crate::storage::Storage;

/// How long readings are trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timing {
    /// A reading younger than this is used without reading the chain.
    pub refresh: Duration,
    /// A reading older than this isn't used at all, even while the RPC is
    /// down.
    pub grace: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            refresh: Duration::from_secs(5 * 60),
            grace: Duration::from_secs(24 * 60 * 60),
        }
    }
}

/// After a failed background read, how long a pool waits before another.
const BACKOFF: Duration = Duration::from_secs(60);

/// Seconds a client waits after the RPC's rate limit.
const RATE_LIMITED_RETRY_SECS: u64 = 5;

#[derive(Default)]
struct PoolState {
    views: Views,
    /// Whether the stored views have been read into `views`.
    loaded: bool,
    refreshing: bool,
    failed_at: Option<DateTime<Utc>>,
    /// When an analyst last used the pool.
    used_at: Option<DateTime<Utc>>,
}

/// Grant readings, per pool.
pub struct GrantChecks {
    timing: Timing,
    pools: Mutex<HashMap<String, PoolState>>,
}

impl Default for GrantChecks {
    fn default() -> Self {
        Self::new(Timing::default())
    }
}

/// A grant's PDA and the DRT config its Grant must name.
struct Expected {
    pda: Pubkey,
    drt_config: Pubkey,
}

fn expected(doc: &PoolDoc, grant: &Grant) -> Result<Expected, ApiError> {
    let pool = Pubkey::from_str(&doc.pool_pda)
        .map_err(|_| ApiError::internal("a pool document has an invalid PDA"))?;
    let drt = doc
        .drts
        .get(&grant.drt_name)
        .ok_or_else(|| ApiError::internal(format!("the pool has no {} DRT", grant.drt_name)))?;
    let commitment = grant
        .commitment_bytes()
        .ok_or_else(|| ApiError::internal("a grant has no commitment"))?;
    Ok(Expected {
        pda: derive_grant_pda(&commitment).0,
        drt_config: derive_drt_config_pda(&pool, &decode_right_id(&drt.right_id_hex)?).0,
    })
}

/// The grants of `doc` whose PDAs a read covers: those not yet closed.
fn open_grants(doc: &PoolDoc) -> impl Iterator<Item = &Grant> {
    doc.grants
        .iter()
        .filter(|g| g.revoked.as_ref().is_none_or(|r| r.signature.is_none()))
}

fn age(now: DateTime<Utc>, at: DateTime<Utc>) -> Duration {
    (now - at).to_std().unwrap_or_default()
}

fn rpc_error(e: RpcError) -> ApiError {
    let mut error = ApiError::rpc_unavailable(format!("reading grants on-chain: {e}"));
    if e.rate_limited() {
        error.retry_after = Some(RATE_LIMITED_RETRY_SECS);
    }
    error
}

fn not_live() -> ApiError {
    ApiError::forbidden(
        "your grant isn't on-chain: the pool's owner revoked it or must grant it again",
    )
    .with_code("grant_not_live")
}

impl GrantChecks {
    pub fn new(timing: Timing) -> Self {
        Self {
            timing,
            pools: Mutex::default(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, PoolState>> {
        self.pools.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Read the pool's stored views into memory, once per worker. A failed
    /// read is retried next time.
    async fn load(&self, storage: &Storage, pool_pda: &str) {
        if self.lock().get(pool_pda).is_some_and(|p| p.loaded) {
            return;
        }
        match storage.chain_views().get(pool_pda).await {
            Ok(stored) => {
                let mut pools = self.lock();
                let pool = pools.entry(pool_pda.to_string()).or_default();
                merge(&mut pool.views, &stored);
                pool.loaded = true;
            }
            Err(e) => warn!(pool = %pool_pda, error = %e, "Couldn't read stored grant readings"),
        }
    }

    /// The reading of `grant`'s PDA that counts for it, if there is one.
    fn reading(&self, pool_pda: &str, pda: &Pubkey, grant: &Grant) -> Option<Seen> {
        self.lock()
            .get(pool_pda)?
            .views
            .get(&pda.to_string())
            .filter(|seen| seen.at >= grant.granted_at)
            .copied()
    }

    /// Check that the chain shows `grant`, an active grant of `doc`, and
    /// return the reading that did. A closed or foreign Grant PDA is
    /// `403 grant_not_live`; an RPC that can't answer when a reading is
    /// needed is `503 rpc_unavailable`.
    pub async fn verify(
        self: &Arc<Self>,
        storage: &Arc<Storage>,
        solana: &Arc<SolanaClient>,
        doc: &PoolDoc,
        grant: &Grant,
    ) -> Result<Seen, ApiError> {
        let want = expected(doc, grant)?;
        self.load(storage, &doc.pool_pda).await;
        let now = Utc::now();
        if let Some(pool) = self.lock().get_mut(&doc.pool_pda) {
            pool.used_at = Some(now);
        }
        let seen = match self.reading(&doc.pool_pda, &want.pda, grant) {
            Some(seen) if age(now, seen.at) < self.timing.refresh => seen,
            Some(seen) if age(now, seen.at) < self.timing.grace => {
                self.refresh_in_background(storage, solana, doc);
                seen
            }
            _ => {
                let read = self.refresh(storage, solana, doc).await?;
                *read
                    .get(&want.pda.to_string())
                    .ok_or_else(|| ApiError::internal("the grant wasn't read"))?
            }
        };
        if seen.live {
            Ok(seen)
        } else {
            Err(not_live())
        }
    }

    /// Read every open grant of `doc` from the chain, remember what it
    /// showed, store it, and return it.
    pub async fn refresh(
        &self,
        storage: &Storage,
        solana: &SolanaClient,
        doc: &PoolDoc,
    ) -> Result<Views, ApiError> {
        let wanted: Vec<Expected> = open_grants(doc)
            .map(|g| expected(doc, g))
            .collect::<Result<_, _>>()?;
        let mut read = Views::new();
        for chunk in wanted.chunks(MAX_MULTIPLE_ACCOUNTS) {
            let pdas: Vec<Pubkey> = chunk.iter().map(|w| w.pda).collect();
            let (slot, accounts) = solana
                .rpc()
                .get_multiple_accounts(&pdas, "confirmed")
                .await
                .map_err(rpc_error)?;
            let at = Utc::now();
            for (w, account) in chunk.iter().zip(accounts) {
                let live = grant_state(account.as_ref(), &w.drt_config) == GrantState::Live;
                read.insert(w.pda.to_string(), Seen { live, slot, at });
            }
        }
        {
            let mut pools = self.lock();
            let pool = pools.entry(doc.pool_pda.clone()).or_default();
            merge(&mut pool.views, &read);
            pool.failed_at = None;
        }
        if let Err(e) = storage.chain_views().merge(&doc.pool_pda, &read).await {
            warn!(pool = %doc.pool_pda, error = %e, "Couldn't store grant readings");
        }
        Ok(read)
    }

    /// [`Self::refresh`] in the background, unless one is running for the
    /// pool or the last one failed within [`BACKOFF`].
    fn refresh_in_background(
        self: &Arc<Self>,
        storage: &Arc<Storage>,
        solana: &Arc<SolanaClient>,
        doc: &PoolDoc,
    ) {
        {
            let mut pools = self.lock();
            let pool = pools.entry(doc.pool_pda.clone()).or_default();
            let backing_off = pool
                .failed_at
                .is_some_and(|at| age(Utc::now(), at) < BACKOFF);
            if pool.refreshing || backing_off {
                return;
            }
            pool.refreshing = true;
        }
        let (checks, storage, solana, doc) =
            (self.clone(), storage.clone(), solana.clone(), doc.clone());
        tokio::spawn(async move {
            let result = checks.refresh(&storage, &solana, &doc).await;
            let mut pools = checks.lock();
            let pool = pools.entry(doc.pool_pda.clone()).or_default();
            pool.refreshing = false;
            if let Err(e) = result {
                pool.failed_at = Some(Utc::now());
                warn!(pool = %doc.pool_pda, error = %e,
                    "Reading grants on-chain failed; the last reading stands");
            }
        });
    }

    /// What the chain showed of each of `doc`'s grants, by grant ID, for
    /// people to read: readings older than `refresh` are read again, and
    /// if that fails the older ones, or none, are returned.
    pub async fn statuses(
        &self,
        storage: &Storage,
        solana: &SolanaClient,
        doc: &PoolDoc,
    ) -> BTreeMap<String, (Pubkey, Option<Seen>)> {
        self.load(storage, &doc.pool_pda).await;
        let now = Utc::now();
        let stale = open_grants(doc).any(|g| {
            expected(doc, g).is_ok_and(|w| {
                self.reading(&doc.pool_pda, &w.pda, g)
                    .is_none_or(|seen| age(now, seen.at) >= self.timing.refresh)
            })
        });
        if stale {
            if let Err(e) = self.refresh(storage, solana, doc).await {
                warn!(pool = %doc.pool_pda, error = %e, "Reading grants on-chain failed");
            }
        }
        doc.grants
            .iter()
            .filter_map(|g| {
                let w = expected(doc, g).ok()?;
                let seen = self.reading(&doc.pool_pda, &w.pda, g);
                Some((g.grant_id.clone(), (w.pda, seen)))
            })
            .collect()
    }

    /// The oldest reading of a pool an analyst used within `refresh`, which
    /// shows on `/health` how far the readings in use trail the chain.
    pub fn oldest_in_use(&self) -> Option<DateTime<Utc>> {
        let now = Utc::now();
        let recent = TimeDelta::from_std(self.timing.refresh).unwrap_or(TimeDelta::MAX);
        self.lock()
            .values()
            .filter(|p| p.used_at.is_some_and(|at| now - at < recent))
            .flat_map(|p| p.views.values().map(|seen| seen.at))
            .min()
    }

    /// Put `seen` in memory for `pda`, as a test's earlier reading.
    #[cfg(test)]
    pub fn remember(&self, pool_pda: &str, pda: &Pubkey, seen: Seen) {
        let mut pools = self.lock();
        let pool = pools.entry(pool_pda.to_string()).or_default();
        pool.views.insert(pda.to_string(), seen);
        pool.loaded = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::fake::{self, FakeChain};
    use crate::storage::pools::tests::{grant, pool};
    use crate::storage::pools::DrtMetadata;
    use crate::storage::tests::two_workers;

    const POOL: Pubkey = Pubkey::new_from_array([21; 32]);
    const RIGHT_ID: [u8; 16] = [9; 16];
    const READ: &str = "getMultipleAccounts";

    struct Setup {
        checks: Arc<GrantChecks>,
        storage: Arc<Storage>,
        other: Arc<Storage>,
        chain: Arc<FakeChain>,
        solana: Arc<SolanaClient>,
        doc: PoolDoc,
        grant: Grant,
        pda: Pubkey,
        drt_config: Pubkey,
    }

    fn setup(timing: Timing) -> Setup {
        let (storage, other, _) = two_workers();
        let mut doc = pool(&POOL.to_string(), "w1");
        let drt = DrtMetadata {
            right_id_hex: hex::encode(RIGHT_ID),
            mint: Pubkey::new_unique().to_string(),
            supply: 3,
            code_repo_url: String::new(),
            code_hash_hex: hex::encode([0; 32]),
        };
        doc.drts.insert("awards-report-v1".into(), drt);
        // Made two days ago, so earlier readings in the tests count for it.
        let grant = grant("g-ana", "ana", 2 * 24 * 60);
        doc.grants.push(grant.clone());
        let pda = derive_grant_pda(&grant.commitment_bytes().unwrap()).0;
        let drt_config = derive_drt_config_pda(&POOL, &RIGHT_ID).0;
        let chain = Arc::new(FakeChain::default());
        chain.grant(pda, drt_config);
        Setup {
            checks: Arc::new(GrantChecks::new(timing)),
            storage: Arc::new(storage),
            other: Arc::new(other),
            solana: Arc::new(fake::start(chain.clone())),
            chain,
            doc,
            grant,
            pda,
            drt_config,
        }
    }

    impl Setup {
        async fn verify(&self) -> Result<Seen, ApiError> {
            self.checks
                .verify(&self.storage, &self.solana, &self.doc, &self.grant)
                .await
        }

        fn remember(&self, live: bool, ago: TimeDelta) {
            let seen = Seen {
                live,
                slot: 1,
                at: Utc::now() - ago,
            };
            self.checks.remember(&self.doc.pool_pda, &self.pda, seen);
        }
    }

    #[tokio::test]
    async fn a_fresh_reading_is_used_without_reading_the_chain() {
        let s = setup(Timing::default());
        let seen = s.verify().await.unwrap();
        assert!(seen.live);
        assert_eq!(seen.slot, 1);
        assert_eq!(s.chain.called(READ), 1);
        s.verify().await.unwrap();
        s.verify().await.unwrap();
        assert_eq!(
            s.chain.called(READ),
            1,
            "no read while the reading is fresh"
        );
    }

    #[tokio::test]
    async fn only_the_programs_grant_for_the_pools_drt_is_live() {
        // Closed, lamports sent to the address, or another DRT's Grant.
        for state in ["closed", "lamports", "foreign"] {
            let s = setup(Timing::default());
            match state {
                "closed" => s.chain.close(&s.pda),
                "lamports" => {
                    s.chain.close(&s.pda);
                    s.chain.accounts.lock().unwrap().push(s.pda);
                }
                _ => s.chain.grant(s.pda, Pubkey::new_unique()),
            }
            let e = s.verify().await.unwrap_err();
            assert_eq!(e.code, "grant_not_live", "{state}");
        }
        let s = setup(Timing::default());
        assert_ne!(s.drt_config, Pubkey::default());
        assert!(s.verify().await.unwrap().live);
    }

    #[tokio::test]
    async fn a_stale_reading_serves_and_is_read_again_once_in_the_background() {
        let s = setup(Timing::default());
        s.remember(true, TimeDelta::minutes(6));
        // Several requests at once start one background read.
        let (a, b, c) = tokio::join!(s.verify(), s.verify(), s.verify());
        assert!(a.is_ok() && b.is_ok() && c.is_ok());
        for _ in 0..50 {
            if s.chain.called(READ) > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(s.chain.called(READ), 1);
        // The background read is remembered, so the next request is fresh.
        s.verify().await.unwrap();
        assert_eq!(s.chain.called(READ), 1);
    }

    #[tokio::test]
    async fn while_the_rpc_is_down_readings_serve_until_the_grace_runs_out() {
        let s = setup(Timing::default());
        *s.chain.refuse_reads.lock().unwrap() = Some(503);
        s.remember(true, TimeDelta::hours(23));
        assert!(s.verify().await.unwrap().live);

        s.remember(true, TimeDelta::hours(25));
        let e = s.verify().await.unwrap_err();
        assert_eq!((e.status.as_u16(), e.code), (503, "rpc_unavailable"));

        // A grant read for the first time can't be, so it fails too.
        let fresh = setup(Timing::default());
        *fresh.chain.refuse_reads.lock().unwrap() = Some(503);
        assert_eq!(fresh.verify().await.unwrap_err().code, "rpc_unavailable");
    }

    #[tokio::test]
    async fn a_rate_limited_read_keeps_the_last_reading_or_asks_the_client_to_wait() {
        let s = setup(Timing::default());
        *s.chain.refuse_reads.lock().unwrap() = Some(429);
        let e = s.verify().await.unwrap_err();
        assert_eq!(e.code, "rpc_unavailable");
        assert_eq!(e.retry_after, Some(RATE_LIMITED_RETRY_SECS));

        s.remember(true, TimeDelta::hours(1));
        assert!(s.verify().await.is_ok(), "the last reading stands");
    }

    #[tokio::test]
    async fn a_worker_that_starts_during_an_outage_uses_the_stored_readings() {
        let s = setup(Timing::default());
        s.verify().await.unwrap();
        *s.chain.refuse_reads.lock().unwrap() = Some(503);

        // Another worker, sharing the storage, with nothing in memory.
        let restarted = Arc::new(GrantChecks::default());
        let seen = restarted
            .verify(&s.other, &s.solana, &s.doc, &s.grant)
            .await
            .unwrap();
        assert!(seen.live);
    }

    #[tokio::test]
    async fn a_reading_older_than_the_grant_is_read_again() {
        // The grant was revoked and closed, then made again: the reading of
        // the closed PDA predates the new grant, so it doesn't count.
        let mut s = setup(Timing::default());
        s.remember(false, TimeDelta::minutes(2));
        s.grant.granted_at = Utc::now() - TimeDelta::minutes(1);
        s.doc.grants = vec![s.grant.clone()];
        assert!(s.verify().await.unwrap().live);
        assert_eq!(s.chain.called(READ), 1);
    }

    #[tokio::test]
    async fn statuses_say_what_the_chain_showed_or_nothing() {
        let s = setup(Timing::default());
        let shown = s.checks.statuses(&s.storage, &s.solana, &s.doc).await;
        assert!(shown["g-ana"].1.unwrap().live);

        let down = setup(Timing::default());
        *down.chain.refuse_reads.lock().unwrap() = Some(503);
        let shown = down
            .checks
            .statuses(&down.storage, &down.solana, &down.doc)
            .await;
        assert_eq!(shown["g-ana"], (down.pda, None), "unknown, not an error");
    }
}
