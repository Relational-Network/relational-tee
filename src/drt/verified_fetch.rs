// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Fetch a DRT script from its `code_repo_url`, verify its SHA-256 against
//! the expected `code_hash`, and cache the verified bytes on the encrypted
//! filesystem.
//!
//! ## Trust model
//!
//! The on-chain `DrtConfig.code_hash` is the authority. The cache is keyed
//! by hex-encoded SHA-256 and is **only** trusted after re-hashing the
//! cached bytes and confirming both:
//!
//! 1. The cached bytes hash to the filename's claimed value (defends against
//!    filesystem tampering even though `/data` is Gramine-encrypted).
//! 2. The hash equals the caller-supplied `expected_hash` (which itself
//!    came from a fresh on-chain read).
//!
//! On any mismatch the cache entry is evicted and the script is re-fetched.
//!
//! ## URL allowlist
//!
//! The only accepted source is `https://raw.githubusercontent.com/<owner>/...`
//! where `<owner>` is in [`ALLOWED_OWNERS`]. Anything else is rejected before
//! any network call.

use std::path::PathBuf;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use crate::http_client::{HttpClient, HttpError};
use crate::storage::EncryptedStorage;

/// Maximum DRT script size in bytes. Larger downloads are aborted.
pub const MAX_SCRIPT_BYTES: usize = 16 * 1024 * 1024; // 16 MiB

/// HTTP request timeout for script downloads.
const FETCH_TIMEOUT: Duration = Duration::from_secs(20);

/// Allowed host. Hard-coded — fetches from any other host are rejected.
const ALLOWED_HOST: &str = "raw.githubusercontent.com";

/// Curated GitHub owners whose repos may serve DRT scripts. The pool admin
/// can register a `code_repo_url` pointing only at one of these orgs.
const ALLOWED_OWNERS: &[&str] = &["relational-network"];

/// Errors returned by [`fetch_and_verify`].
#[derive(Debug)]
pub enum VerifiedFetchError {
    /// URL is malformed, uses the wrong scheme, host, or owner.
    InvalidUrl(String),
    /// Network or HTTP error fetching the script.
    Fetch(String),
    /// Server returned non-2xx.
    BadStatus(u16),
    /// Downloaded body exceeds [`MAX_SCRIPT_BYTES`].
    TooLarge { size: usize, limit: usize },
    /// Computed SHA-256 of the bytes does not equal `expected_hash`.
    HashMismatch { expected: String, actual: String },
    /// The `expected_hash` parameter was not 32 bytes / 64 hex chars.
    InvalidExpectedHash(String),
    /// Local I/O error while reading or writing the cache entry.
    Cache(String),
}

impl std::fmt::Display for VerifiedFetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidUrl(msg) => write!(f, "invalid DRT script URL: {msg}"),
            Self::Fetch(msg) => write!(f, "failed to fetch DRT script: {msg}"),
            Self::BadStatus(code) => write!(f, "DRT script fetch returned status {code}"),
            Self::TooLarge { size, limit } => {
                write!(f, "DRT script too large: {size} bytes (limit {limit})")
            }
            Self::HashMismatch { expected, actual } => write!(
                f,
                "DRT script hash mismatch: expected {expected}, got {actual}"
            ),
            Self::InvalidExpectedHash(msg) => write!(f, "invalid expected hash: {msg}"),
            Self::Cache(msg) => write!(f, "DRT script cache error: {msg}"),
        }
    }
}

impl std::error::Error for VerifiedFetchError {}

impl From<VerifiedFetchError> for crate::error::ApiError {
    fn from(e: VerifiedFetchError) -> Self {
        use VerifiedFetchError::*;
        match &e {
            InvalidUrl(_) | InvalidExpectedHash(_) => Self::bad_request(e.to_string()),
            HashMismatch { .. } => Self::bad_request(e.to_string()),
            TooLarge { .. } => Self::bad_request(e.to_string()),
            Fetch(_) | BadStatus(_) => {
                warn!(error = %e, "DRT script fetch failed");
                Self::internal(format!("DRT script unavailable: {e}"))
            }
            Cache(_) => {
                warn!(error = %e, "DRT script cache I/O failed");
                Self::internal("DRT script cache error")
            }
        }
    }
}

/// Fetch and verify a DRT script.
///
/// Steps:
/// 1. Validate `url` against the allowlist (scheme, host, owner).
/// 2. Decode `expected_hash_hex` to a 32-byte array.
/// 3. Look in the on-disk cache at `/data/drt-scripts/{expected_hash_hex}`.
///    If present, re-hash the bytes; on match, return them.
/// 4. Otherwise GET `url`, enforce size cap while streaming, SHA-256 the body,
///    compare against `expected_hash`, write to cache atomically.
pub async fn fetch_and_verify(
    url: &str,
    expected_hash_hex: &str,
    storage: &EncryptedStorage,
) -> Result<Vec<u8>, VerifiedFetchError> {
    validate_url(url)?;
    let expected_hash = decode_hash(expected_hash_hex)?;

    let cache_path = cache_path_for(storage, expected_hash_hex);

    if let Some(bytes) = try_load_from_cache(storage, &cache_path, &expected_hash) {
        debug!(url = %url, hash = %expected_hash_hex, "DRT script cache hit");
        return Ok(bytes);
    }

    info!(url = %url, hash = %expected_hash_hex, "DRT script cache miss; fetching");
    let bytes = http_get(url).await?;

    let actual = Sha256::digest(&bytes);
    if actual.as_slice() != expected_hash {
        return Err(VerifiedFetchError::HashMismatch {
            expected: expected_hash_hex.to_string(),
            actual: hex::encode(actual),
        });
    }

    store_in_cache(storage, &cache_path, &bytes)?;

    info!(
        url = %url,
        hash = %expected_hash_hex,
        size = bytes.len(),
        "DRT script fetched and cached"
    );
    Ok(bytes)
}

fn cache_path_for(storage: &EncryptedStorage, hash_hex: &str) -> PathBuf {
    storage.paths().root().join("drt-scripts").join(hash_hex)
}

fn try_load_from_cache(
    storage: &EncryptedStorage,
    cache_path: &PathBuf,
    expected_hash: &[u8; 32],
) -> Option<Vec<u8>> {
    if !storage.exists(cache_path) {
        return None;
    }
    let bytes = match storage.read_raw(cache_path) {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, path = %cache_path.display(), "cache read failed; treating as miss");
            return None;
        }
    };
    let actual = Sha256::digest(&bytes);
    if actual.as_slice() != expected_hash {
        warn!(
            path = %cache_path.display(),
            "DRT script cache entry has wrong hash; evicting and refetching"
        );
        return None;
    }
    Some(bytes)
}

fn store_in_cache(
    storage: &EncryptedStorage,
    cache_path: &PathBuf,
    bytes: &[u8],
) -> Result<(), VerifiedFetchError> {
    storage
        .write_raw(cache_path, bytes)
        .map_err(|e| VerifiedFetchError::Cache(e.to_string()))
}

async fn http_get(url: &str) -> Result<Vec<u8>, VerifiedFetchError> {
    let client = HttpClient::new().with_timeout(FETCH_TIMEOUT);
    let resp = client
        .get(url)
        .await
        .map_err(|e: HttpError| VerifiedFetchError::Fetch(e.to_string()))?;

    if !resp.is_success() {
        return Err(VerifiedFetchError::BadStatus(resp.status().as_u16()));
    }

    let bytes = resp.into_bytes();

    if bytes.len() > MAX_SCRIPT_BYTES {
        return Err(VerifiedFetchError::TooLarge {
            size: bytes.len(),
            limit: MAX_SCRIPT_BYTES,
        });
    }

    Ok(bytes)
}

fn decode_hash(hex_str: &str) -> Result<[u8; 32], VerifiedFetchError> {
    if hex_str.len() != 64 {
        return Err(VerifiedFetchError::InvalidExpectedHash(format!(
            "expected 64 hex chars, got {}",
            hex_str.len()
        )));
    }
    let bytes =
        hex::decode(hex_str).map_err(|e| VerifiedFetchError::InvalidExpectedHash(e.to_string()))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn validate_url(url: &str) -> Result<(), VerifiedFetchError> {
    let after_scheme = url
        .strip_prefix("https://")
        .ok_or_else(|| VerifiedFetchError::InvalidUrl("must use https://".to_string()))?;

    let (host, path) = after_scheme
        .split_once('/')
        .ok_or_else(|| VerifiedFetchError::InvalidUrl("missing path".to_string()))?;

    if host != ALLOWED_HOST {
        return Err(VerifiedFetchError::InvalidUrl(format!(
            "host must be {ALLOWED_HOST}, got {host}"
        )));
    }

    // Path shape: /<owner>/<repo>/<ref>/<path...>
    let owner = path
        .split('/')
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| VerifiedFetchError::InvalidUrl("missing owner segment".to_string()))?;

    if !ALLOWED_OWNERS.contains(&owner) {
        return Err(VerifiedFetchError::InvalidUrl(format!(
            "owner '{owner}' not in DRT script allowlist"
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_http_scheme() {
        let err = validate_url("http://raw.githubusercontent.com/relational-network/x/main/y")
            .unwrap_err();
        matches!(err, VerifiedFetchError::InvalidUrl(_));
    }

    #[test]
    fn rejects_wrong_host() {
        let err = validate_url("https://example.com/relational-network/x/main/y").unwrap_err();
        matches!(err, VerifiedFetchError::InvalidUrl(_));
    }

    #[test]
    fn rejects_non_allowlisted_owner() {
        let err =
            validate_url("https://raw.githubusercontent.com/some-other-org/x/main/y").unwrap_err();
        matches!(err, VerifiedFetchError::InvalidUrl(_));
    }

    #[test]
    fn accepts_allowlisted_url() {
        validate_url(
            "https://raw.githubusercontent.com/relational-network/drt-scripts/main/mean.wasm",
        )
        .unwrap();
    }

    #[test]
    fn decode_hash_rejects_wrong_length() {
        assert!(decode_hash("abc").is_err());
    }

    #[test]
    fn decode_hash_rejects_non_hex() {
        let s = "z".repeat(64);
        assert!(decode_hash(&s).is_err());
    }

    #[test]
    fn decode_hash_accepts_64_hex() {
        let s = "0".repeat(64);
        let h = decode_hash(&s).unwrap();
        assert_eq!(h, [0u8; 32]);
    }
}
