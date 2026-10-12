// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Entra ID's signing keys, cached.
//!
//! The keys are fetched from the tenant's JWKS endpoint and cached for 24
//! hours. One fetch runs at a time, in a task of its own, and every request
//! that needs its result waits for that one fetch, failed or not; a request
//! that gives up doesn't cancel it. A key the cache holds keeps working
//! while a refresh runs, and, if refreshes fail, until 72 hours after the
//! last one that succeeded. A token naming a key the cache doesn't hold
//! triggers a refresh at most once a minute, so Entra's key rollover is
//! picked up without letting unknown `kid`s drive a fetch per request.
//! After a failed fetch the next waits 5 seconds, doubling to 5 minutes
//! while they keep failing, however stale the keys are.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use futures_util::future::BoxFuture;
use jsonwebtoken::DecodingKey;
use serde::Deserialize;
use tokio::sync::watch;
use tokio::time::Instant;
use tracing::{info, warn};

use crate::http_client::HttpClient;

/// How long fetched keys are trusted without a refresh.
pub const CACHE_TTL: Duration = Duration::from_secs(24 * 3600);
/// How long after the last successful fetch held keys still verify tokens,
/// while refreshes fail.
pub const MAX_KEY_AGE: Duration = Duration::from_secs(72 * 3600);
/// The shortest interval between refreshes caused by an unknown `kid`.
pub const UNKNOWN_KID_INTERVAL: Duration = Duration::from_secs(60);
/// The wait after a failed fetch, at first and at most.
pub const RETRY_WAIT: (Duration, Duration) = (Duration::from_secs(5), Duration::from_secs(300));

/// Where signing keys come from.
pub trait KeySource: Send + Sync {
    /// The current signing keys, by `kid`.
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
    /// Keys from the JWKS document at `url`, which must answer within 10
    /// seconds and with at most 1 MiB.
    pub fn new(url: String) -> Self {
        Self {
            url,
            client: HttpClient::new()
                .with_timeout(Duration::from_secs(10))
                .with_max_body(1 << 20),
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
    /// When the last fetch started, and how many in a row have failed.
    attempted_at: Option<Instant>,
    failures: u32,
    refreshing: bool,
}

impl Cached {
    /// How long ago the keys were fetched, if they ever were.
    fn age(&self, now: Instant) -> Option<Duration> {
        self.fetched_at.map(|at| now.duration_since(at))
    }

    /// Whether the keys are recent enough that no refresh is due.
    fn fresh(&self, now: Instant) -> bool {
        self.age(now).is_some_and(|age| age < CACHE_TTL)
    }

    /// `kid`, unless the keys are too old to trust.
    fn key(&self, kid: &str, now: Instant) -> Option<DecodingKey> {
        let usable = self.age(now).is_some_and(|age| age < MAX_KEY_AGE);
        self.keys.get(kid).filter(|_| usable).cloned()
    }

    /// Whether a fetch may start now: none is running, the last one's
    /// failure has been waited out, and, if the keys are fresh, the last
    /// one was over a minute ago.
    fn may_fetch(&self, now: Instant) -> bool {
        let Some(at) = self.attempted_at else {
            return true;
        };
        let since = now.duration_since(at);
        if self.refreshing || since < crate::work::backoff(self.failures, RETRY_WAIT) {
            return false;
        }
        !self.fresh(now) || since >= UNKNOWN_KID_INTERVAL
    }
}

/// The signing keys, cached, with single-flight refresh.
pub struct KeySet {
    source: Arc<dyn KeySource>,
    cached: Arc<Mutex<Cached>>,
    /// How many fetches have finished, successful or not.
    finished: watch::Sender<u64>,
}

impl KeySet {
    /// A key set that fetches its keys from `source` when first asked.
    pub fn new(source: Arc<dyn KeySource>) -> Self {
        Self {
            source,
            cached: Arc::default(),
            finished: watch::Sender::new(0),
        }
    }

    /// The cached keys, even after a panic while another caller held them.
    fn lock(&self) -> MutexGuard<'_, Cached> {
        self.cached.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The key named `kid`. A fresh key is returned at once, and so is a
    /// stale one while a refresh runs in the background. Without one, this
    /// waits for a refresh, if one is running or may start.
    pub async fn get(&self, kid: &str) -> Option<DecodingKey> {
        let mut finished = self.finished.subscribe();
        let seen = *finished.borrow_and_update();
        let now = Instant::now();
        let (key, fresh, started) = {
            let mut cached = self.lock();
            let key = cached.key(kid, now);
            let fresh = cached.fresh(now);
            let started = (key.is_none() || !fresh) && self.start_fetch(&mut cached, now);
            (key, fresh, started || cached.refreshing)
        };
        match key {
            Some(key) => Some(key),
            None if started => {
                // One fetch serves every waiter, whatever its outcome.
                let _ = finished.wait_for(|n| *n > seen).await;
                self.lock().key(kid, Instant::now())
            }
            None => {
                if fresh {
                    warn!(kid, "A token names a signing key Entra ID didn't list");
                }
                None
            }
        }
    }

    /// Start a fetch in a task of its own, if one may start now.
    fn start_fetch(&self, cached: &mut Cached, now: Instant) -> bool {
        if !cached.may_fetch(now) {
            return false;
        }
        cached.refreshing = true;
        cached.attempted_at = Some(now);
        let (source, shared, finished) = (
            self.source.clone(),
            self.cached.clone(),
            self.finished.clone(),
        );
        tokio::spawn(async move {
            let fetched = source.fetch().await;
            {
                let mut cached = shared.lock().unwrap_or_else(PoisonError::into_inner);
                cached.refreshing = false;
                match fetched {
                    Ok(keys) => {
                        info!(keys = keys.len(), "Fetched Entra ID signing keys");
                        cached.keys = keys;
                        cached.fetched_at = Some(now);
                        cached.failures = 0;
                    }
                    Err(e) => {
                        cached.failures = cached.failures.saturating_add(1);
                        warn!(error = %e, held = cached.keys.len(), failures = cached.failures,
                            "Fetching Entra ID signing keys failed; keeping the keys held");
                    }
                }
            }
            finished.send_modify(|n| *n += 1);
        });
        true
    }

    /// How long ago the keys were fetched, for `/health`.
    pub async fn age(&self) -> Option<Duration> {
        self.lock().age(Instant::now())
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

    /// Long enough for a fetch, which takes 20 ms, to finish.
    async fn settle() {
        tokio::time::sleep(Duration::from_millis(50)).await;
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
            "a stale key serves at once while the refresh runs"
        );
        settle().await;
        assert_eq!(source.fetches.load(Ordering::SeqCst), 2);
        assert!(set.get("a").await.is_some(), "and after it fails");

        // Until the keys are too old to trust.
        tokio::time::advance(MAX_KEY_AGE - CACHE_TTL).await;
        assert!(set.get("a").await.is_none());
        source.fail.store(false, Ordering::SeqCst);
        tokio::time::advance(RETRY_WAIT.1).await;
        assert!(
            set.get("a").await.is_some(),
            "a fetch that works restores them"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_failing_upstream_is_fetched_once_for_every_caller_then_backed_off() {
        let source = Fixed::new(HashMap::from([("a".to_string(), key())]));
        source.fail.store(true, Ordering::SeqCst);
        let set = Arc::new(KeySet::new(source.clone()));
        let fetches = || source.fetches.load(Ordering::SeqCst);
        let callers = (0..100).map(|_| {
            let set = set.clone();
            tokio::spawn(async move { set.get("a").await.is_some() })
        });
        let started = Instant::now();
        for found in futures_util::future::join_all(callers).await {
            assert!(!found.unwrap());
        }
        assert_eq!(fetches(), 1, "one fetch answered all hundred");
        assert!(started.elapsed() < Duration::from_millis(100));

        // Its failure holds for the next 5 seconds, then 10, then 20.
        assert!(set.get("a").await.is_none());
        assert_eq!(fetches(), 1);
        for (wait, expected) in [(5, 2), (5, 2), (5, 3), (10, 3), (10, 4)] {
            tokio::time::advance(Duration::from_secs(wait)).await;
            assert!(set.get("a").await.is_none());
            settle().await;
            assert_eq!(fetches(), expected, "after {wait} more seconds");
        }
        source.fail.store(false, Ordering::SeqCst);
        tokio::time::advance(RETRY_WAIT.1).await;
        assert!(set.get("a").await.is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn a_caller_that_gives_up_leaves_the_fetch_running() {
        let source = Fixed::new(HashMap::from([("a".to_string(), key())]));
        let set = KeySet::new(source.clone());
        let impatient = tokio::time::timeout(Duration::from_millis(1), set.get("a")).await;
        assert!(impatient.is_err());
        settle().await;
        assert!(set.get("a").await.is_some());
        assert_eq!(source.fetches.load(Ordering::SeqCst), 1);
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
