// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! LRU cache for first-page transaction lookups per wallet address.
//!
//! Avoids hitting redb on every `/v1/wallets/{id}/transactions` request for the
//! first page. The indexer invalidates entries when new transactions arrive.

use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::repository::transactions::StoredTransaction;

/// A cached first-page result.
struct CacheEntry {
    txs: Vec<(StoredTransaction, String)>,
    inserted_at: Instant,
}

/// Thread-safe LRU cache with TTL.
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

    /// Get the cached first page for a wallet address.
    pub fn get_first_page(&self, wallet_address: &str) -> Option<Vec<(StoredTransaction, String)>> {
        let mut cache = match self.cache.lock() {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "TxCache mutex poisoned in get_first_page");
                return None;
            }
        };
        let entry = cache.get(wallet_address)?;
        if entry.inserted_at.elapsed() > self.ttl {
            cache.pop(wallet_address);
            return None;
        }
        Some(entry.txs.clone())
    }

    /// Cache the first page for a wallet address.
    pub fn put_first_page(&self, wallet_address: &str, txs: Vec<(StoredTransaction, String)>) {
        match self.cache.lock() {
            Ok(mut cache) => {
                cache.put(
                    wallet_address.to_string(),
                    CacheEntry {
                        txs,
                        inserted_at: Instant::now(),
                    },
                );
            }
            Err(e) => {
                tracing::warn!(error = %e, "TxCache mutex poisoned in put_first_page");
            }
        }
    }

    /// Invalidate cached data for a wallet address (called by the indexer).
    pub fn invalidate(&self, wallet_address: &str) {
        match self.cache.lock() {
            Ok(mut cache) => {
                cache.pop(wallet_address);
            }
            Err(e) => {
                tracing::warn!(error = %e, "TxCache mutex poisoned in invalidate");
            }
        }
    }
}
