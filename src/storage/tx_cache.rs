// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Per-worker LRU cache of each wallet's first transaction page.
//!
//! Avoids a Table query on every `/v1/wallets/{id}/transactions` request for
//! the first page. Syncs and sends invalidate a wallet's entry; entries also
//! expire after a short TTL, which bounds how stale another worker's writes
//! can look.

use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::transactions::StoredTransaction;

/// A cached first page: the page size it was read with, its transactions
/// and directions, and the cursor for the next page.
#[derive(Clone)]
pub struct FirstPage {
    pub limit: usize,
    pub items: Vec<(StoredTransaction, String)>,
    pub next_cursor: Option<String>,
}

struct CacheEntry {
    page: FirstPage,
    inserted_at: Instant,
}

/// Thread-safe LRU cache with TTL, keyed by wallet ID.
pub struct TxCache {
    cache: Mutex<LruCache<String, CacheEntry>>,
    ttl: Duration,
}

impl TxCache {
    /// Create a new cache with the given capacity and TTL.
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            cache: Mutex::new(LruCache::new(
                NonZeroUsize::new(capacity).expect("cache capacity must be > 0"),
            )),
            ttl,
        }
    }

    /// The cached first page for a wallet, if it was read with `limit`.
    pub fn get_first_page(&self, wallet_id: &str, limit: usize) -> Option<FirstPage> {
        let mut cache = match self.cache.lock() {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "TxCache mutex poisoned in get_first_page");
                return None;
            }
        };
        let entry = cache.get(wallet_id)?;
        if entry.inserted_at.elapsed() > self.ttl {
            cache.pop(wallet_id);
            return None;
        }
        (entry.page.limit == limit).then(|| entry.page.clone())
    }

    /// Cache the first page for a wallet.
    pub fn put_first_page(&self, wallet_id: &str, page: FirstPage) {
        match self.cache.lock() {
            Ok(mut cache) => {
                cache.put(
                    wallet_id.to_string(),
                    CacheEntry {
                        page,
                        inserted_at: Instant::now(),
                    },
                );
            }
            Err(e) => {
                tracing::warn!(error = %e, "TxCache mutex poisoned in put_first_page");
            }
        }
    }

    /// Drop a wallet's cached page.
    pub fn invalidate(&self, wallet_id: &str) {
        match self.cache.lock() {
            Ok(mut cache) => {
                cache.pop(wallet_id);
            }
            Err(e) => {
                tracing::warn!(error = %e, "TxCache mutex poisoned in invalidate");
            }
        }
    }
}
