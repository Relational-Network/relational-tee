// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! The object store: every durable object the worker keeps, in Azure Blob
//! Storage ([`azure::AzureBlob`]) or, for development and tests, in local
//! files ([`files::LocalFiles`]).
//!
//! The store has four operations and nothing else: get (conditional on a
//! cached ETag), create-only put, compare-and-swap put, and list. There's no
//! delete or append: lifecycle rules expire what needs expiring, and nothing
//! is kept as a log. One store serves one container; [`sealed::Sealed`]
//! wraps the `state` container so it only ever sees ciphertext.

use std::fmt;

use bytes::Bytes;
use chrono::{DateTime, Utc};

pub use crate::tee::BoxFuture;

pub mod azure;
#[cfg(test)]
mod conformance;
#[cfg(any(test, feature = "dev"))]
pub mod files;
pub mod sealed;

/// The sealed container holding every document and dataset.
pub const STATE: &str = "state";

/// The public container of certificate chains and CSRs.
pub const TLS: &str = "tls";

/// Every container the worker creates at startup: `state`, and the public
/// `tls` and `reference-values` (signed manifests) that CD writes.
pub const CONTAINERS: [&str; 3] = [STATE, TLS, "reference-values"];

/// An opaque version tag for compare-and-swap writes, in quoted form.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ETag(pub String);

impl ETag {
    /// An ETag as a store reports it, with or without quotes.
    pub fn from_raw(raw: &str) -> Self {
        ETag(format!("\"{}\"", raw.trim().trim_matches('"')))
    }
}

/// The outcome of a get.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fetched {
    Found {
        body: Bytes,
        etag: ETag,
    },
    /// The cached ETag still matches.
    NotModified,
    Missing,
}

/// The outcome of a create-only put.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Created {
    New(ETag),
    AlreadyExists,
}

/// The outcome of a compare-and-swap put.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Replaced {
    Done(ETag),
    /// The ETag no longer matches, or the object is gone.
    Stale,
}

/// An object found by a list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listed {
    /// The full path, including the listed directory.
    pub path: String,
    pub etag: ETag,
    pub last_modified: DateTime<Utc>,
}

/// Storage failures.
#[derive(Debug)]
pub enum StoreError {
    /// A sealed object failed to open: tampered with, moved or corrupted.
    Integrity(String),
    /// The store couldn't be reached, or answered with a server error.
    Unavailable(String),
    /// The store rejected the request or answered unexpectedly.
    Invalid(String),
    /// A compare-and-swap kept losing to other writers.
    Contended,
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Integrity(m) => write!(f, "integrity check failed: {m}"),
            StoreError::Unavailable(m) => write!(f, "storage unavailable: {m}"),
            StoreError::Invalid(m) => write!(f, "storage request failed: {m}"),
            StoreError::Contended => f.write_str("the object kept changing while being updated"),
        }
    }
}

impl std::error::Error for StoreError {}

/// One container of objects.
pub trait ObjectStore: Send + Sync {
    /// The object at `path`; `NotModified` if its ETag is still `cached`.
    fn get<'a>(
        &'a self,
        path: &'a str,
        cached: Option<&'a ETag>,
    ) -> BoxFuture<'a, Result<Fetched, StoreError>>;

    /// Create the object unless one already exists at `path`.
    fn put_if_absent<'a>(
        &'a self,
        path: &'a str,
        body: Bytes,
    ) -> BoxFuture<'a, Result<Created, StoreError>>;

    /// Replace the object if its ETag is still `etag`.
    fn put_if_match<'a>(
        &'a self,
        path: &'a str,
        body: Bytes,
        etag: &'a ETag,
    ) -> BoxFuture<'a, Result<Replaced, StoreError>>;

    /// The objects directly under `dir`, which ends with `/`: names with no
    /// further `/`, in name order.
    fn list<'a>(&'a self, dir: &'a str) -> BoxFuture<'a, Result<Vec<Listed>, StoreError>>;
}

/// Whether `segment` may be one part of an object name: non-empty, not `.`
/// or `..`, and only ASCII letters, digits, `.`, `_` and `-`.
pub fn valid_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment != "."
        && segment != ".."
        && segment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Check every segment of an object path, or of a directory ending in `/`.
pub fn check_path(path: &str) -> Result<(), StoreError> {
    let trimmed = path.strip_suffix('/').unwrap_or(path);
    if trimmed.split('/').all(valid_segment) {
        Ok(())
    } else {
        Err(StoreError::Invalid(format!("invalid object path {path:?}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_accept_ids_and_reject_traversal() {
        for ok in [
            "pools/7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU.json",
            "pools/P/datasets/0f8fad5b-d9cb-469f-a165-70867728950e",
            "idempotency/user_2abc/ab12.json",
            "staged/",
        ] {
            assert!(check_path(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "/pools/x",
            "pools//x",
            "pools/../x",
            "pools/./x",
            "pools/x y",
            "pools/x%2F",
            "pools\\x",
            "pools/é",
        ] {
            assert!(check_path(bad).is_err(), "{bad}");
        }
        assert!(!valid_segment(".."));
        assert!(valid_segment("a.b_c-d"));
    }

    #[test]
    fn etags_are_kept_in_quoted_form() {
        assert_eq!(ETag::from_raw("0x8D1"), ETag("\"0x8D1\"".into()));
        assert_eq!(ETag::from_raw("\"0x8D1\""), ETag("\"0x8D1\"".into()));
    }
}
