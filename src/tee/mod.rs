// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Key release and attestation: the only code that depends on the TEE.
//!
//! Workers obtain their keys through a [`KeyProvider`] and attestation tokens
//! for clients through an [`AttestationProvider`]. In production both are the
//! SKR sidecar in the same confidential container group
//! ([`skr::SkrSidecar`]), which releases a key only if the group's attested
//! policy matches the key's release policy. Dev builds add
//! [`local::LocalDev`], which reads dev keys from files and signs dev tokens.

use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tracing::{info, warn};
use zeroize::Zeroizing;

#[cfg(feature = "dev")]
pub mod dev_keys;
#[cfg(feature = "dev")]
pub mod dev_maa;
#[cfg(feature = "dev")]
pub mod fake_skr;
#[cfg(feature = "dev")]
pub mod local;
pub mod skr;

/// A boxed future, so the provider traits can be used as trait objects.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The keys every worker holds. Each serves one protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum KeyName {
    /// Recipient key for sealed uploads, shared by every worker.
    Transport,
    /// Input to every storage key derivation; never used directly.
    StorageRoot,
    /// The TLS server key.
    Tls,
    /// Input to the commitment key derivation; never used directly.
    Commitment,
}

impl KeyName {
    pub const ALL: [KeyName; 4] = [
        KeyName::Transport,
        KeyName::StorageRoot,
        KeyName::Tls,
        KeyName::Commitment,
    ];

    /// The key's name in Key Vault, and the stem of its dev key file.
    pub const fn as_str(self) -> &'static str {
        match self {
            KeyName::Transport => "transport-key",
            KeyName::StorageRoot => "storage-root",
            KeyName::Tls => "tls-key",
            KeyName::Commitment => "commitment-key",
        }
    }
}

impl fmt::Display for KeyName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a key couldn't be released.
#[derive(Debug)]
pub struct KeyError {
    pub message: String,
    /// Whether trying again can help (the sidecar or Key Vault may recover,
    /// a release policy may be mid-update); a missing dev key file can't.
    pub retryable: bool,
}

impl KeyError {
    pub fn retryable(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            retryable: true,
        }
    }

    pub fn fatal(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            retryable: false,
        }
    }
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for KeyError {}

/// One version of a released EC P-256 private key. The scalar is zeroized
/// when the key is dropped, and the key is never logged or persisted.
pub struct EcKey {
    secret: SecretKey,
}

impl EcKey {
    #[cfg(any(test, feature = "dev"))]
    pub fn new(secret: SecretKey) -> Self {
        Self { secret }
    }

    /// Parse a private JWK (`kty` EC, `crv` P-256, with `d`). If `x` and `y`
    /// are present they must match `d`.
    pub fn from_jwk(jwk: &Value) -> Result<Self, KeyError> {
        let field = |name: &str| jwk.get(name).and_then(Value::as_str);
        if field("kty") != Some("EC") || field("crv") != Some("P-256") {
            return Err(KeyError::fatal("released key isn't an EC P-256 JWK"));
        }
        let d = field("d").ok_or_else(|| KeyError::fatal("released JWK has no private part"))?;
        let d = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(d)
                .map_err(|_| KeyError::fatal("released JWK has an invalid d"))?,
        );
        let secret = SecretKey::from_slice(&d)
            .map_err(|_| KeyError::fatal("released JWK has an invalid d"))?;
        let key = Self { secret };
        if let (Some(x), Some(y)) = (field("x"), field("y")) {
            let (px, py) = key.public_coordinates();
            if x != px || y != py {
                return Err(KeyError::fatal(
                    "released JWK's public part doesn't match d",
                ));
            }
        }
        Ok(key)
    }

    pub fn secret(&self) -> &SecretKey {
        &self.secret
    }

    pub fn public_key(&self) -> PublicKey {
        self.secret.public_key()
    }

    /// The base64url `x` and `y` coordinates of the public key.
    fn public_coordinates(&self) -> (String, String) {
        let point = self.public_key().to_encoded_point(false);
        let bytes = point.as_bytes();
        (
            URL_SAFE_NO_PAD.encode(&bytes[1..33]),
            URL_SAFE_NO_PAD.encode(&bytes[33..65]),
        )
    }

    /// The RFC 7638 JWK thumbprint of the public key, base64url-encoded.
    pub fn thumbprint(&self) -> String {
        let (x, y) = self.public_coordinates();
        // RFC 7638: the required members only, sorted, with no whitespace.
        let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
        URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
    }

    /// The public key as a JWK whose `kid` is its thumbprint.
    pub fn public_jwk(&self) -> Value {
        let (x, y) = self.public_coordinates();
        serde_json::json!({ "kty": "EC", "crv": "P-256", "x": x, "y": y, "kid": self.thumbprint() })
    }
}

/// A released key: its current version and, while it rotates, the previous one.
pub struct ReleasedKey {
    pub current: EcKey,
    pub previous: Option<EcKey>,
}

impl ReleasedKey {
    /// The current version first, then the previous one.
    pub fn versions(&self) -> impl Iterator<Item = &EcKey> {
        std::iter::once(&self.current).chain(self.previous.as_ref())
    }
}

/// Releases the worker's keys.
pub trait KeyProvider: Send + Sync {
    /// Release the current version of a named key; rotating keys also return the previous version.
    fn release(&self, key: KeyName) -> BoxFuture<'_, Result<ReleasedKey, KeyError>>;
}

/// Why an attestation token couldn't be obtained.
#[derive(Debug)]
pub struct AttestError(pub String);

impl fmt::Display for AttestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for AttestError {}

/// Obtains attestation tokens that clients can verify.
pub trait AttestationProvider: Send + Sync {
    /// Return an MAA token whose `x-ms-runtime` claim carries `runtime_data`.
    fn attest<'a>(&'a self, runtime_data: &'a Value) -> BoxFuture<'a, Result<String, AttestError>>;
}

/// The four keys, released at startup and held in memory for the process
/// lifetime.
pub struct WorkerKeys {
    keys: BTreeMap<KeyName, ReleasedKey>,
}

impl WorkerKeys {
    /// Release every key. Transient failures are retried with jittered
    /// backoff, 10 attempts over about 5 minutes per key; the caller exits
    /// when this fails, so the platform restarts the worker.
    pub async fn release_all(provider: &dyn KeyProvider) -> Result<Self, KeyError> {
        let mut keys = BTreeMap::new();
        for name in KeyName::ALL {
            let key = release_with_retry(provider, name).await?;
            if name == KeyName::Transport {
                info!(key = %name, kid = %key.current.thumbprint(), "Key released");
            } else {
                info!(key = %name, "Key released");
            }
            keys.insert(name, key);
        }
        Ok(Self { keys })
    }

    pub fn get(&self, name: KeyName) -> &ReleasedKey {
        self.keys
            .get(&name)
            .expect("release_all holds every key name")
    }
}

const RELEASE_ATTEMPTS: u32 = 10;
const FIRST_RETRY_DELAY: Duration = Duration::from_secs(2);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(64);

async fn release_with_retry(
    provider: &dyn KeyProvider,
    name: KeyName,
) -> Result<ReleasedKey, KeyError> {
    let mut delay = FIRST_RETRY_DELAY;
    let mut attempt = 1;
    loop {
        match provider.release(name).await {
            Ok(key) => return Ok(key),
            Err(e) if !e.retryable || attempt == RELEASE_ATTEMPTS => {
                return Err(KeyError {
                    message: format!("releasing {name} failed after {attempt} attempt(s): {e}"),
                    retryable: false,
                });
            }
            Err(e) => {
                let wait = jittered(delay);
                warn!(key = %name, attempt, retry_in_ms = wait.as_millis() as u64, error = %e,
                    "Key release failed; retrying");
                tokio::time::sleep(wait).await;
                delay = (delay * 2).min(MAX_RETRY_DELAY);
                attempt += 1;
            }
        }
    }
}

/// `delay` scaled by a random factor between 0.75 and 1.25.
fn jittered(delay: Duration) -> Duration {
    use p256::elliptic_curve::rand_core::{OsRng, RngCore};
    let factor = 0.75 + (OsRng.next_u32() as f64 / u32::MAX as f64) * 0.5;
    delay.mul_f64(factor)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use p256::elliptic_curve::rand_core::OsRng;

    /// A fixed P-256 key, so tests that derive from it are reproducible.
    pub(crate) fn fixed_key(seed: u8) -> EcKey {
        let mut bytes = [0u8; 32];
        bytes[31] = seed;
        bytes[0] = 0x42;
        EcKey::new(SecretKey::from_slice(&bytes).expect("valid scalar"))
    }

    fn private_jwk(key: &EcKey) -> Value {
        let mut jwk = key.public_jwk();
        jwk["d"] = Value::String(URL_SAFE_NO_PAD.encode(key.secret().to_bytes()));
        jwk
    }

    #[test]
    fn jwk_round_trips_and_rejects_mismatched_public_parts() {
        let key = EcKey::new(SecretKey::random(&mut OsRng));
        let parsed = EcKey::from_jwk(&private_jwk(&key)).expect("valid JWK");
        assert_eq!(parsed.public_key(), key.public_key());

        let mut wrong = private_jwk(&key);
        wrong["x"] = private_jwk(&fixed_key(9))["x"].clone();
        assert!(EcKey::from_jwk(&wrong).is_err());

        let mut public_only = private_jwk(&key);
        public_only.as_object_mut().unwrap().remove("d");
        assert!(EcKey::from_jwk(&public_only).is_err());

        let mut rsa = private_jwk(&key);
        rsa["kty"] = serde_json::json!("RSA");
        assert!(EcKey::from_jwk(&rsa).is_err());
    }

    #[test]
    fn thumbprint_is_rfc7638_over_the_required_members() {
        let key = fixed_key(1);
        let jwk = key.public_jwk();
        let canonical = format!(
            r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
            jwk["x"].as_str().unwrap(),
            jwk["y"].as_str().unwrap()
        );
        let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()));
        assert_eq!(key.thumbprint(), expected);
        assert_eq!(jwk["kid"], serde_json::json!(expected));
        assert_ne!(fixed_key(2).thumbprint(), expected);
    }

    struct Flaky {
        failures_left: std::sync::atomic::AtomicU32,
        retryable: bool,
    }

    impl KeyProvider for Flaky {
        fn release(&self, _key: KeyName) -> BoxFuture<'_, Result<ReleasedKey, KeyError>> {
            Box::pin(async move {
                use std::sync::atomic::Ordering;
                if self.failures_left.load(Ordering::SeqCst) > 0 {
                    self.failures_left.fetch_sub(1, Ordering::SeqCst);
                    return Err(KeyError {
                        message: "sidecar not up yet".into(),
                        retryable: self.retryable,
                    });
                }
                Ok(ReleasedKey {
                    current: fixed_key(1),
                    previous: None,
                })
            })
        }
    }

    #[tokio::test(start_paused = true)]
    async fn release_retries_transient_failures_but_not_fatal_ones() {
        let flaky = Flaky {
            failures_left: 3.into(),
            retryable: true,
        };
        let keys = WorkerKeys::release_all(&flaky).await.expect("recovers");
        assert_eq!(keys.keys.len(), KeyName::ALL.len());

        let broken = Flaky {
            failures_left: 1.into(),
            retryable: false,
        };
        assert!(WorkerKeys::release_all(&broken).await.is_err());
    }
}
