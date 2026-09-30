// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Entra ID's signing keys, cached.
//!
//! The keys are fetched from the tenant's JWKS endpoint and cached for 24
//! hours. Only one fetch runs at a time: concurrent requests that need keys
//! wait for it. A token naming a key the cache doesn't hold triggers a
//! refresh, at most once a minute, so Entra's key rollover is picked up
//! without letting unknown `kid`s drive a fetch per request. If a refresh
//! fails, the keys already held keep working.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use futures_util::future::BoxFuture;
use jsonwebtoken::DecodingKey;
use serde::Deserialize;
use tokio::sync::{Mutex, RwLock};
use tokio::time::Instant;
use tracing::{info, warn};

use crate::http_client::HttpClient;

/// How long fetched keys are trusted without a refresh.
pub const CACHE_TTL: Duration = Duration::from_secs(24 * 3600);
/// The shortest interval between refreshes caused by an unknown `kid`.
pub const UNKNOWN_KID_INTERVAL: Duration = Duration::from_secs(60);

/// Where signing keys come from.
pub trait KeySource: Send + Sync {
    fn fetch(&self) -> BoxFuture<'_, Result<HashMap<String, DecodingKey>, String>>;
}

#[derive(Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Deserialize)]
struct Jwk {
    kty: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default, rename = "use")]
    usage: Option<String>,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
}

/// The RSA signing keys in a JWKS document, by `kid`. Keys for another
/// use, of another type, or without a `kid` are skipped.
pub fn parse_jwks(body: &[u8]) -> Result<HashMap<String, DecodingKey>, String> {
    let jwks: Jwks = serde_json::from_slice(body).map_err(|e| format!("JWKS isn't valid: {e}"))?;
    let mut keys = HashMap::new();
    for jwk in jwks.keys {
        let (Some(kid), Some(n), Some(e)) = (jwk.kid, jwk.n, jwk.e) else {
            continue;
        };
        if jwk.kty != "RSA" || jwk.usage.as_deref().is_some_and(|u| u != "sig") {
            continue;
        }
        match DecodingKey::from_rsa_components(&n, &e) {
            Ok(key) => {
                keys.insert(kid, key);
            }
            Err(err) => warn!(kid = %kid, error = %err, "Skipping a JWKS key that doesn't parse"),
        }
    }
    Ok(keys)
}

/// A JWKS endpoint over HTTPS.
pub struct HttpKeySource {
    url: String,
    client: HttpClient,
}

impl HttpKeySource {
    pub fn new(url: String) -> Self {
        Self {
            url,
            client: HttpClient::new().with_timeout(Duration::from_secs(10)),
        }
    }
}

impl KeySource for HttpKeySource {
    fn fetch(&self) -> BoxFuture<'_, Result<HashMap<String, DecodingKey>, String>> {
        Box::pin(async move {
            let response = self
                .client
                .get(&self.url)
                .await
                .map_err(|e| format!("fetching {}: {e}", self.url))?;
            if !response.is_success() {
                return Err(format!("{} answered {}", self.url, response.status()));
            }
            parse_jwks(response.body())
        })
    }
}

#[derive(Default)]
struct Cached {
    keys: HashMap<String, DecodingKey>,
    /// When the keys were last fetched successfully.
    fetched_at: Option<Instant>,
    /// When a fetch was last attempted, successful or not.
    attempted_at: Option<Instant>,
}

impl Cached {
    fn fresh(&self, now: Instant) -> bool {
        self.fetched_at
            .is_some_and(|at| now.duration_since(at) < CACHE_TTL)
    }

    fn may_refresh_for_unknown_kid(&self, now: Instant) -> bool {
        self.attempted_at
            .is_none_or(|at| now.duration_since(at) >= UNKNOWN_KID_INTERVAL)
    }
}

/// The signing keys, cached, with single-flight refresh.
pub struct KeySet {
    source: Arc<dyn KeySource>,
    cached: RwLock<Cached>,
    refreshing: Mutex<()>,
}

impl KeySet {
    pub fn new(source: Arc<dyn KeySource>) -> Self {
        Self {
            source,
            cached: RwLock::new(Cached::default()),
            refreshing: Mutex::new(()),
        }
    }

    /// The key named `kid`, refreshing the cache if it's stale, or if it
    /// doesn't hold `kid` and no refresh ran in the last minute.
    pub async fn get(&self, kid: &str) -> Option<DecodingKey> {
        if let Some(key) = self.lookup(kid, false).await {
            return Some(key);
        }
        let _flight = self.refreshing.lock().await;
        // Another request may have refreshed while this one waited.
        if let Some(key) = self.lookup(kid, false).await {
            return Some(key);
        }
        let now = Instant::now();
        let needed = {
            let cached = self.cached.read().await;
            !cached.fresh(now) || cached.may_refresh_for_unknown_kid(now)
        };
        if needed {
            self.refresh(now).await;
        }
        self.lookup(kid, true).await
    }

    /// `kid` from the cache: only while fresh, unless `stale_ok`.
    async fn lookup(&self, kid: &str, stale_ok: bool) -> Option<DecodingKey> {
        let cached = self.cached.read().await;
        if !stale_ok && !cached.fresh(Instant::now()) {
            return None;
        }
        cached.keys.get(kid).cloned()
    }

    async fn refresh(&self, now: Instant) {
        let fetched = self.source.fetch().await;
        let mut cached = self.cached.write().await;
        cached.attempted_at = Some(now);
        match fetched {
            Ok(keys) => {
                info!(keys = keys.len(), "Fetched Entra ID signing keys");
                cached.keys = keys;
                cached.fetched_at = Some(now);
            }
            Err(e) => warn!(error = %e, held = cached.keys.len(),
                "Fetching Entra ID signing keys failed; keeping the keys held"),
        }
    }

    /// How long ago the keys were fetched, for `/health`.
    pub async fn age(&self) -> Option<Duration> {
        self.cached
            .read()
            .await
            .fetched_at
            .map(|at| Instant::now().duration_since(at))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A source that serves fixed keys and counts its fetches.
    pub(crate) struct Fixed {
        pub keys: std::sync::Mutex<HashMap<String, DecodingKey>>,
        pub fetches: AtomicUsize,
        pub fail: std::sync::atomic::AtomicBool,
    }

    impl Fixed {
        pub(crate) fn new(keys: HashMap<String, DecodingKey>) -> Arc<Self> {
            Arc::new(Self {
                keys: std::sync::Mutex::new(keys),
                fetches: AtomicUsize::new(0),
                fail: std::sync::atomic::AtomicBool::new(false),
            })
        }
    }

    impl KeySource for Fixed {
        fn fetch(&self) -> BoxFuture<'_, Result<HashMap<String, DecodingKey>, String>> {
            Box::pin(async move {
                self.fetches.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(20)).await;
                if self.fail.load(Ordering::SeqCst) {
                    return Err("unreachable".into());
                }
                Ok(self.keys.lock().unwrap().clone())
            })
        }
    }

    fn key() -> DecodingKey {
        DecodingKey::from_secret(b"k")
    }

    #[tokio::test(start_paused = true)]
    async fn concurrent_requests_share_one_fetch_and_unknown_kids_refresh_once_a_minute() {
        let source = Fixed::new(HashMap::from([("a".to_string(), key())]));
        let set = Arc::new(KeySet::new(source.clone()));
        let lookups = (0..10).map(|_| {
            let set = set.clone();
            tokio::spawn(async move { set.get("a").await.is_some() })
        });
        for found in futures_util::future::join_all(lookups).await {
            assert!(found.unwrap());
        }
        assert_eq!(source.fetches.load(Ordering::SeqCst), 1);

        // An unknown kid refreshes once, then not again within the minute.
        assert!(set.get("b").await.is_none());
        assert!(set.get("b").await.is_none());
        assert_eq!(
            source.fetches.load(Ordering::SeqCst),
            1,
            "fetched a moment ago"
        );
        tokio::time::advance(UNKNOWN_KID_INTERVAL).await;
        source.keys.lock().unwrap().insert("b".into(), key());
        assert!(set.get("b").await.is_some(), "rolled-over key picked up");
        assert_eq!(source.fetches.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn keys_are_refetched_after_a_day_and_kept_when_that_fails() {
        let source = Fixed::new(HashMap::from([("a".to_string(), key())]));
        let set = KeySet::new(source.clone());
        assert!(set.get("a").await.is_some());
        tokio::time::advance(CACHE_TTL).await;
        source.fail.store(true, Ordering::SeqCst);
        assert!(
            set.get("a").await.is_some(),
            "stale keys serve while Entra is down"
        );
        assert_eq!(source.fetches.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn only_rsa_signing_keys_with_a_kid_are_kept() {
        let body = serde_json::json!({ "keys": [
            { "kty": "RSA", "use": "sig", "kid": "k1", "n": "sXch", "e": "AQAB" },
            { "kty": "RSA", "use": "enc", "kid": "k2", "n": "sXch", "e": "AQAB" },
            { "kty": "EC", "kid": "k3", "crv": "P-256", "x": "AA", "y": "AA" },
            { "kty": "RSA", "n": "sXch", "e": "AQAB" },
        ]});
        let keys = parse_jwks(body.to_string().as_bytes()).unwrap();
        assert_eq!(keys.keys().collect::<Vec<_>>(), ["k1"]);
        assert!(parse_jwks(b"not json").is_err());
    }
}
