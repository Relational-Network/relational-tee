// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! What the chain last showed of each pool's analysis grants, sealed at
//! `chain/grants/{pool_pda}.json`, so a worker that starts while the RPC is
//! down still knows which grants it verified. It's derived data: deleting
//! it costs only RPC calls.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{id, Storage, StoreError};
use crate::store::{Created, Replaced};

/// What the chain showed at one Grant PDA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Seen {
    /// Whether the program's Grant for the pool's DRT config was there.
    pub live: bool,
    /// The slot the RPC answered at.
    pub slot: u64,
    /// When the worker read it.
    pub at: DateTime<Utc>,
}

/// Each Grant PDA of a pool, base58, and what the chain showed there.
pub type Views = BTreeMap<String, Seen>;

/// Merge `newer` into `views`, keeping the reading of the higher slot for
/// each PDA. Returns whether anything changed.
pub fn merge(views: &mut Views, newer: &Views) -> bool {
    let mut changed = false;
    for (pda, seen) in newer {
        let keep = views.get(pda).is_some_and(|old| old.slot > seen.slot);
        if !keep && views.get(pda) != Some(seen) {
            views.insert(pda.clone(), *seen);
            changed = true;
        }
    }
    changed
}

fn path(pool_pda: &str) -> Result<String, StoreError> {
    let pool = id(pool_pda).ok_or_else(|| StoreError::Invalid("invalid pool PDA".into()))?;
    Ok(format!("chain/grants/{pool}.json"))
}

/// Chain views storage.
pub struct ChainViews<'a> {
    s: &'a Storage,
}

impl<'a> ChainViews<'a> {
    pub(crate) fn new(s: &'a Storage) -> Self {
        Self { s }
    }

    /// The pool's stored views, empty if none were stored.
    pub async fn get(&self, pool_pda: &str) -> Result<Views, StoreError> {
        Ok(self
            .s
            .state()
            .get_json(&path(pool_pda)?)
            .await?
            .map(|(views, _)| views)
            .unwrap_or_default())
    }

    /// Merge `newer` into the pool's stored views, by compare-and-swap.
    /// A reading never replaces one of a higher slot, so a stale writer,
    /// or a restored older file, can't undo a newer reading.
    pub async fn merge(&self, pool_pda: &str, newer: &Views) -> Result<(), StoreError> {
        let path = path(pool_pda)?;
        let state = self.s.state();
        for _ in 0..4 {
            let (mut views, etag) = match state.get_json::<Views>(&path).await? {
                Some((views, etag)) => (views, Some(etag)),
                None => (Views::new(), None),
            };
            if !merge(&mut views, newer) {
                return Ok(());
            }
            let written = match etag {
                None => matches!(state.create_json(&path, &views).await?, Created::New(_)),
                Some(etag) => matches!(
                    state.replace_json(&path, &views, &etag).await?,
                    Replaced::Done(_)
                ),
            };
            if written {
                return Ok(());
            }
        }
        Err(StoreError::Contended)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::tests::two_workers;

    fn seen(live: bool, slot: u64) -> Seen {
        Seen {
            live,
            slot,
            at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn a_reading_never_replaces_one_of_a_higher_slot() {
        let (a, b, _) = two_workers();
        let pool = "Pool1";
        assert!(a.chain_views().get(pool).await.unwrap().is_empty());

        let first = Views::from([("g1".into(), seen(true, 10)), ("g2".into(), seen(true, 10))]);
        a.chain_views().merge(pool, &first).await.unwrap();
        // A lagging node's answer, then a newer one.
        let lagging = Views::from([("g1".into(), seen(false, 9))]);
        b.chain_views().merge(pool, &lagging).await.unwrap();
        let newer = Views::from([("g2".into(), seen(false, 11))]);
        b.chain_views().merge(pool, &newer).await.unwrap();

        let stored = a.chain_views().get(pool).await.unwrap();
        assert_eq!(
            (stored["g1"].live, stored["g1"].slot),
            (true, 10),
            "kept the higher slot"
        );
        assert_eq!((stored["g2"].live, stored["g2"].slot), (false, 11));
    }
}
