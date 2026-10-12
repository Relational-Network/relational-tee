// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! A least-recently-used cache bounded by bytes and entries, in which
//! concurrent misses for one key share a single load. A load that fails or
//! is cancelled leaves nothing behind, and a value larger than the whole
//! budget is returned but not kept. What a value holds of the worker's
//! memory is the value's own reservation (see [`crate::budget`]), which
//! outlives its eviction while callers still hold it.

use std::future::Future;
use std::hash::Hash;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use lru::LruCache;
use tokio::sync::OnceCell;

/// How much memory a cached value holds.
pub trait Weigh {
    /// Its size in bytes, as the cache's budget counts it.
    fn bytes(&self) -> usize;
}

type Cell<V> = Arc<OnceCell<Arc<V>>>;

struct Entry<V> {
    cell: Cell<V>,
    /// What [`Inner::bytes`] counts for it: none until its loader counts
    /// the loaded value, and until then it isn't evicted.
    bytes: Option<usize>,
}

struct Inner<K: Hash + Eq, V> {
    entries: LruCache<K, Entry<V>>,
    /// The bytes counted in `entries`.
    bytes: usize,
}

pub struct Cache<K: Hash + Eq, V> {
    budget: usize,
    max_entries: usize,
    inner: Mutex<Inner<K, V>>,
}

/// Removes a load's empty cell if its load didn't finish: it failed, or the
/// caller stopped waiting.
struct Unfinished<'a, K: Hash + Eq + Clone, V: Weigh> {
    cache: &'a Cache<K, V>,
    key: &'a K,
    cell: &'a Cell<V>,
    loading: &'a AtomicBool,
}

impl<K: Hash + Eq + Clone, V: Weigh> Drop for Unfinished<'_, K, V> {
    fn drop(&mut self) {
        if self.loading.load(Ordering::SeqCst) && !self.cell.initialized() {
            self.cache.forget(self.key, self.cell);
        }
    }
}

impl<K: Hash + Eq + Clone, V: Weigh> Cache<K, V> {
    /// An empty cache that keeps at most `budget` bytes and `max_entries`
    /// values.
    pub fn new(budget: usize, max_entries: usize) -> Self {
        Self {
            budget,
            max_entries,
            inner: Mutex::new(Inner {
                entries: LruCache::unbounded(),
                bytes: 0,
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner<K, V>> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Remove `key`'s entry if it is still `cell`.
    fn forget(&self, key: &K, cell: &Cell<V>) {
        let mut inner = self.lock();
        if inner
            .entries
            .peek(key)
            .is_some_and(|entry| Arc::ptr_eq(&entry.cell, cell))
        {
            if let Some(entry) = inner.entries.pop(key) {
                inner.bytes = inner.bytes.saturating_sub(entry.bytes.unwrap_or(0));
            }
        }
    }

    /// The value for `key`, loaded by `load` if it isn't cached. Concurrent
    /// callers for one key wait on the first one's load; if that fails, the
    /// next one loads. Loading past the budget evicts the least recently
    /// used values, but never the one just loaded, unless it alone is over
    /// the budget.
    pub async fn get_or_load<E, F, Fut>(&self, key: K, load: F) -> Result<Arc<V>, E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<V, E>>,
    {
        let cell = self
            .lock()
            .entries
            .get_or_insert(key.clone(), || Entry {
                cell: Arc::new(OnceCell::new()),
                bytes: None,
            })
            .cell
            .clone();
        let loading = AtomicBool::new(false);
        let unfinished = Unfinished {
            cache: self,
            key: &key,
            cell: &cell,
            loading: &loading,
        };
        let value = cell
            .get_or_try_init(|| async {
                loading.store(true, Ordering::SeqCst);
                load().await.map(Arc::new)
            })
            .await?
            .clone();
        drop(unfinished);
        if loading.load(Ordering::SeqCst) {
            if value.bytes() > self.budget {
                self.forget(&key, &cell);
                return Ok(value);
            }
            let mut guard = self.lock();
            let inner = &mut *guard;
            // A failed load before this one may have dropped the entry.
            if let Some(entry) = inner
                .entries
                .peek_mut(&key)
                .filter(|entry| Arc::ptr_eq(&entry.cell, &cell))
            {
                entry.bytes = Some(value.bytes());
                inner.bytes += value.bytes();
                self.evict(inner, &key);
            }
        }
        Ok(value)
    }

    /// Drop the least recently used entries, never `keep`, until the cache
    /// is within its budget and entry count. Entries still loading aren't
    /// counted yet, so they stay.
    fn evict(&self, inner: &mut Inner<K, V>, keep: &K) {
        while inner.bytes > self.budget || inner.entries.len() > self.max_entries {
            let oldest = inner
                .entries
                .iter()
                .rev()
                .find(|(key, entry)| *key != keep && entry.bytes.is_some())
                .map(|(key, _)| key.clone());
            let Some(oldest) = oldest else { break };
            if let Some(entry) = inner.entries.pop(&oldest) {
                inner.bytes = inner.bytes.saturating_sub(entry.bytes.unwrap_or(0));
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
    use std::time::Duration;

    use super::*;

    struct Blob(usize);

    impl Weigh for Blob {
        fn bytes(&self) -> usize {
            self.0
        }
    }

    #[tokio::test]
    async fn concurrent_misses_share_one_load() {
        let cache = Cache::<&str, Blob>::new(100, 10);
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
        let cache = Cache::<&str, Blob>::new(25, 10);
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

        // A value over the whole budget is returned, but not kept, and
        // takes nothing else with it.
        let huge = cache
            .get_or_load("d", || async { Ok::<_, ()>(Blob(99)) })
            .await
            .unwrap();
        assert_eq!(huge.0, 99);
        assert_eq!(cache.usage(), (20, 2));
    }

    #[tokio::test]
    async fn failed_and_cancelled_loads_leave_nothing_behind() {
        let cache = Cache::<usize, Blob>::new(25, 10);
        for key in 0..1000 {
            assert!(cache
                .get_or_load(key, || async { Err::<Blob, ()>(()) })
                .await
                .is_err());
        }
        assert_eq!(cache.usage(), (0, 0));

        // A load whose caller stops waiting.
        let stalled = cache.get_or_load(1, || async {
            std::future::pending::<()>().await;
            Ok::<_, ()>(Blob(1))
        });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), stalled)
                .await
                .is_err()
        );
        assert_eq!(cache.usage(), (0, 0));
    }

    #[tokio::test]
    async fn an_evicted_value_holds_its_memory_until_its_last_owner_drops_it() {
        struct Held(crate::budget::Reservation);
        impl Weigh for Held {
            fn bytes(&self) -> usize {
                self.0.bytes()
            }
        }
        const UNIT: usize = 64 << 10;
        let memory = crate::budget::Budget::new(10 * UNIT);
        let cache = Cache::<&str, Held>::new(UNIT, 10);
        let load = || async { memory.reserve(UNIT, Duration::ZERO).await.map(Held) };
        let a = cache.get_or_load("a", load).await.unwrap();
        let b = cache.get_or_load("b", load).await.unwrap();
        assert_eq!(cache.usage(), (UNIT, 1), "b evicted a");
        assert_eq!(memory.available(), 8 * UNIT, "a is still in use");
        drop(a);
        assert_eq!(memory.available(), 9 * UNIT);
        drop(b);
        assert_eq!(memory.available(), 9 * UNIT, "b is still cached");
    }

    #[tokio::test]
    async fn entries_are_bounded_too() {
        let cache = Cache::<usize, Blob>::new(1000, 3);
        for key in 0..10 {
            cache
                .get_or_load(key, || async { Ok::<_, ()>(Blob(1)) })
                .await
                .unwrap();
        }
        assert_eq!(cache.usage(), (3, 3));
    }
}
