// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! A least-recently-used cache bounded by bytes, in which concurrent misses
//! for one key share a single load.

use std::future::Future;
use std::hash::Hash;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use lru::LruCache;
use tokio::sync::OnceCell;

/// How much memory a cached value holds.
pub trait Weigh {
    fn bytes(&self) -> usize;
}

struct Inner<K: Hash + Eq, V> {
    entries: LruCache<K, Arc<OnceCell<Arc<V>>>>,
    /// The bytes of the loaded values in `entries`.
    bytes: usize,
}

pub struct Cache<K: Hash + Eq, V> {
    budget: usize,
    inner: Mutex<Inner<K, V>>,
}

impl<K: Hash + Eq + Clone, V: Weigh> Cache<K, V> {
    pub fn new(budget: usize) -> Self {
        Self {
            budget,
            inner: Mutex::new(Inner {
                entries: LruCache::unbounded(),
                bytes: 0,
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner<K, V>> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The value for `key`, loaded by `load` if it isn't cached. Concurrent
    /// callers for one key wait on the first one's load; if that fails, the
    /// next one loads. Loading past the budget evicts the least recently
    /// used values, but never the one just loaded.
    pub async fn get_or_load<E, F, Fut>(&self, key: K, load: F) -> Result<Arc<V>, E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<V, E>>,
    {
        let cell = self
            .lock()
            .entries
            .get_or_insert(key.clone(), || Arc::new(OnceCell::new()))
            .clone();
        let mut loaded_here = false;
        let value = cell
            .get_or_try_init(|| async {
                loaded_here = true;
                load().await.map(Arc::new)
            })
            .await?
            .clone();
        if loaded_here {
            let mut inner = self.lock();
            // An eviction may have dropped the entry while it loaded.
            if inner
                .entries
                .peek(&key)
                .is_some_and(|cached| Arc::ptr_eq(cached, &cell))
            {
                inner.bytes += value.bytes();
                self.evict(&mut inner, &key);
            }
        }
        Ok(value)
    }

    fn evict(&self, inner: &mut Inner<K, V>, keep: &K) {
        while inner.bytes > self.budget {
            let oldest = inner
                .entries
                .iter()
                .rev()
                .find(|(key, cell)| *key != keep && cell.initialized())
                .map(|(key, _)| key.clone());
            let Some(oldest) = oldest else { break };
            if let Some(cell) = inner.entries.pop(&oldest) {
                let freed = cell.get().map_or(0, |value| value.bytes());
                inner.bytes = inner.bytes.saturating_sub(freed);
            }
        }
    }

    /// The bytes cached and the number of entries.
    #[cfg(test)]
    pub fn usage(&self) -> (usize, usize) {
        let inner = self.lock();
        (inner.bytes, inner.entries.len())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};

    use super::*;

    struct Blob(usize);

    impl Weigh for Blob {
        fn bytes(&self) -> usize {
            self.0
        }
    }

    #[tokio::test]
    async fn concurrent_misses_share_one_load() {
        let cache = Cache::<&str, Blob>::new(100);
        let loads = AtomicUsize::new(0);
        let load = || async {
            loads.fetch_add(1, SeqCst);
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            Ok::<_, ()>(Blob(10))
        };
        let results =
            futures_util::future::join_all((0..10).map(|_| cache.get_or_load("a", load))).await;
        assert!(results.iter().all(|r| r.as_ref().is_ok_and(|b| b.0 == 10)));
        assert_eq!(loads.load(SeqCst), 1);
        assert_eq!(cache.usage(), (10, 1));
    }

    #[tokio::test]
    async fn a_failed_load_is_retried_and_the_budget_evicts_the_oldest() {
        let cache = Cache::<&str, Blob>::new(25);
        let failed = cache
            .get_or_load("a", || async { Err::<Blob, _>("down") })
            .await;
        assert_eq!(failed.err(), Some("down"));
        cache
            .get_or_load("a", || async { Ok::<_, ()>(Blob(10)) })
            .await
            .unwrap();
        cache
            .get_or_load("b", || async { Ok::<_, ()>(Blob(10)) })
            .await
            .unwrap();
        // Using `a` makes `b` the oldest, which `c` then evicts.
        cache
            .get_or_load("a", || async { Err::<Blob, ()>(()) })
            .await
            .unwrap();
        cache
            .get_or_load("c", || async { Ok::<_, ()>(Blob(10)) })
            .await
            .unwrap();
        assert_eq!(cache.usage(), (20, 2));
        let reloaded = AtomicUsize::new(0);
        cache
            .get_or_load("b", || async {
                reloaded.fetch_add(1, SeqCst);
                Ok::<_, ()>(Blob(10))
            })
            .await
            .unwrap();
        assert_eq!(reloaded.load(SeqCst), 1, "b was evicted");

        // A value over the whole budget is still returned, and kept until
        // the next load.
        let huge = cache
            .get_or_load("d", || async { Ok::<_, ()>(Blob(99)) })
            .await
            .unwrap();
        assert_eq!(huge.0, 99);
        assert_eq!(cache.usage(), (99, 1));
    }
}
