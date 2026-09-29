// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! The storage traits: objects in an [`ObjectStore`] (Azure Blob) and rows in
//! an [`IndexStore`] (Azure Table). Implementations only ever see
//! ciphertext: the repositories seal everything before it reaches them (see
//! [`super::envelope`]).
//!
//! Container and table names are defined here and nowhere else.

use std::collections::BTreeMap;
use std::fmt;

use bytes::Bytes;
use chrono::{DateTime, Utc};

pub use crate::tee::BoxFuture;

/// Blob containers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Container {
    /// Initialisation and issuance CSVs; create-only, immutable once committed.
    Datasets,
    /// Wallet keypairs; create-only.
    Wallets,
    /// Encrypted, HMAC-tagged audit events; append blobs.
    Audit,
    /// Encrypted, HMAC-tagged revocation log; append blobs.
    Revocations,
    /// Daily table exports; create-only.
    Exports,
    /// Empty blobs for leader election and the readiness canary.
    Leases,
    /// CSRs and certificate chains for `tls-key`; public content.
    Tls,
    /// Signed reference values; public content.
    ReferenceValues,
}

impl Container {
    pub const ALL: [Container; 8] = [
        Container::Datasets,
        Container::Wallets,
        Container::Audit,
        Container::Revocations,
        Container::Exports,
        Container::Leases,
        Container::Tls,
        Container::ReferenceValues,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Container::Datasets => "datasets",
            Container::Wallets => "wallets",
            Container::Audit => "audit",
            Container::Revocations => "revocations",
            Container::Exports => "exports",
            Container::Leases => "leases",
            Container::Tls => "tls",
            Container::ReferenceValues => "reference-values",
        }
    }
}

/// Tables.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Table {
    Pools,
    Records,
    Revocations,
    Wallets,
    Transactions,
    Audit,
    Idempotency,
    Identities,
}

impl Table {
    pub const ALL: [Table; 8] = [
        Table::Pools,
        Table::Records,
        Table::Revocations,
        Table::Wallets,
        Table::Transactions,
        Table::Audit,
        Table::Idempotency,
        Table::Identities,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Table::Pools => "pools",
            Table::Records => "records",
            Table::Revocations => "revocations",
            Table::Wallets => "wallets",
            Table::Transactions => "transactions",
            Table::Audit => "audit",
            Table::Idempotency => "idempotency",
            Table::Identities => "identities",
        }
    }
}

/// An opaque version tag for compare-and-swap writes.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ETag(pub String);

/// An object's bytes and version.
#[derive(Clone, Debug)]
pub struct Object {
    pub body: Bytes,
    pub etag: ETag,
}

/// The outcome of a create-only write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PutOutcome {
    Created(ETag),
    AlreadyExists,
}

/// A row property. Rows carry their sensitive fields in one encrypted binary
/// property; plaintext properties are copies of filter fields only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Prop {
    Str(String),
    Bin(Vec<u8>),
    Bool(bool),
}

/// A table row: partition key, row key, properties and version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entity {
    pub pk: String,
    pub rk: String,
    pub props: BTreeMap<String, Prop>,
    /// Set on rows read from the store; ignored on writes.
    pub etag: Option<ETag>,
}

impl Entity {
    pub fn new(pk: impl Into<String>, rk: impl Into<String>) -> Self {
        Self {
            pk: pk.into(),
            rk: rk.into(),
            props: BTreeMap::new(),
            etag: None,
        }
    }

    pub fn with(mut self, name: &str, prop: Prop) -> Self {
        self.props.insert(name.to_string(), prop);
        self
    }

    pub fn str(&self, name: &str) -> Option<&str> {
        match self.props.get(name) {
            Some(Prop::Str(s)) => Some(s),
            _ => None,
        }
    }

    pub fn bin(&self, name: &str) -> Option<&[u8]> {
        match self.props.get(name) {
            Some(Prop::Bin(b)) => Some(b),
            _ => None,
        }
    }

    pub fn bool(&self, name: &str) -> Option<bool> {
        match self.props.get(name) {
            Some(Prop::Bool(b)) => Some(*b),
            _ => None,
        }
    }
}

/// The outcome of an insert-if-absent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InsertOutcome {
    Inserted(ETag),
    Conflict,
}

/// A row key range within one partition: `start` inclusive, `end` exclusive.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RkRange {
    pub start: Option<String>,
    pub end: Option<String>,
}

impl RkRange {
    pub fn all() -> Self {
        Self::default()
    }

    /// Row keys that start with `prefix`.
    pub fn prefix(prefix: &str) -> Self {
        Self {
            start: Some(prefix.to_string()),
            end: prefix_end(prefix),
        }
    }

    pub fn between(start: Option<String>, end: Option<String>) -> Self {
        Self { start, end }
    }

    #[cfg(any(test, feature = "dev"))]
    pub fn contains(&self, rk: &str) -> bool {
        self.start.as_deref().is_none_or(|s| rk >= s) && self.end.as_deref().is_none_or(|e| rk < e)
    }
}

/// The smallest string greater than every string starting with `prefix`.
fn prefix_end(prefix: &str) -> Option<String> {
    let mut chars: Vec<char> = prefix.chars().collect();
    while let Some(last) = chars.pop() {
        if let Some(next) = char::from_u32(last as u32 + 1) {
            chars.push(next);
            return Some(chars.into_iter().collect());
        }
    }
    None
}

/// One operation of an atomic batch within a single partition.
#[derive(Clone, Debug)]
pub enum BatchOp {
    Insert(Entity),
    UpdateIfMatch(Entity, ETag),
}

/// A filter on plaintext properties.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Filter {
    Eq(String, Prop),
    And(Vec<Filter>),
    Or(Vec<Filter>),
}

impl Filter {
    pub fn eq(name: &str, prop: Prop) -> Self {
        Filter::Eq(name.to_string(), prop)
    }

    #[cfg(any(test, feature = "dev"))]
    pub fn matches(&self, props: &BTreeMap<String, Prop>) -> bool {
        match self {
            Filter::Eq(name, value) => props.get(name) == Some(value),
            Filter::And(all) => all.iter().all(|f| f.matches(props)),
            Filter::Or(any) => any.iter().any(|f| f.matches(props)),
        }
    }
}

/// Where the next page of a query starts. Opaque and backend-specific.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Continuation(pub String);

/// One page of results.
#[derive(Clone, Debug)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next: Option<Continuation>,
}

/// Storage failures.
#[derive(Debug)]
pub enum StoreError {
    /// The object or row doesn't exist.
    NotFound,
    /// A compare-and-swap write lost: the ETag is stale.
    PreconditionFailed,
    /// The write conflicts with what's stored: a row that already exists,
    /// or an object under an immutability policy.
    Conflict,
    /// Stored data failed authentication: tampered, moved or corrupted.
    Integrity(String),
    /// The store couldn't be reached or answered with a server error.
    Unavailable(String),
    /// The store rejected the request or answered unexpectedly.
    Invalid(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::NotFound => f.write_str("not found"),
            StoreError::PreconditionFailed => f.write_str("precondition failed (stale ETag)"),
            StoreError::Conflict => f.write_str("conflicts with the stored state"),
            StoreError::Integrity(m) => write!(f, "integrity check failed: {m}"),
            StoreError::Unavailable(m) => write!(f, "storage unavailable: {m}"),
            StoreError::Invalid(m) => write!(f, "storage request failed: {m}"),
        }
    }
}

impl std::error::Error for StoreError {}

/// Blob storage.
pub trait ObjectStore: Send + Sync {
    /// The object's bytes and ETag, or `None` if it doesn't exist.
    fn get<'a>(
        &'a self,
        c: Container,
        path: &'a str,
    ) -> BoxFuture<'a, Result<Option<Object>, StoreError>>;

    /// Create the object unless one already exists at `path`.
    fn put_if_absent<'a>(
        &'a self,
        c: Container,
        path: &'a str,
        body: Bytes,
    ) -> BoxFuture<'a, Result<PutOutcome, StoreError>>;

    /// Replace the object if its ETag still matches.
    fn put_if_match<'a>(
        &'a self,
        c: Container,
        path: &'a str,
        body: Bytes,
        etag: &'a ETag,
    ) -> BoxFuture<'a, Result<ETag, StoreError>>;

    /// Append a block to an append blob, creating the blob if it's absent.
    fn append<'a>(
        &'a self,
        c: Container,
        path: &'a str,
        block: Bytes,
    ) -> BoxFuture<'a, Result<(), StoreError>>;

    /// Delete the object. A missing object counts as deleted; one under an
    /// immutability policy fails with [`StoreError::Conflict`].
    fn delete<'a>(&'a self, c: Container, path: &'a str) -> BoxFuture<'a, Result<(), StoreError>>;

    /// Forbid overwriting or deleting the object until `until`.
    fn set_immutability<'a>(
        &'a self,
        c: Container,
        path: &'a str,
        until: DateTime<Utc>,
    ) -> BoxFuture<'a, Result<(), StoreError>>;
}

/// Table storage.
pub trait IndexStore: Send + Sync {
    /// The row and its ETag, or `None` if it doesn't exist.
    fn get<'a>(
        &'a self,
        t: Table,
        pk: &'a str,
        rk: &'a str,
    ) -> BoxFuture<'a, Result<Option<Entity>, StoreError>>;

    /// Insert the row unless one with the same keys exists.
    fn insert(&self, t: Table, e: Entity) -> BoxFuture<'_, Result<InsertOutcome, StoreError>>;

    /// Replace the row if its ETag still matches.
    fn update_if_match<'a>(
        &'a self,
        t: Table,
        e: Entity,
        etag: &'a ETag,
    ) -> BoxFuture<'a, Result<ETag, StoreError>>;

    /// Insert or replace the row.
    fn upsert(&self, t: Table, e: Entity) -> BoxFuture<'_, Result<ETag, StoreError>>;

    /// Delete the row if its ETag still matches.
    fn delete_if_match<'a>(
        &'a self,
        t: Table,
        pk: &'a str,
        rk: &'a str,
        etag: &'a ETag,
    ) -> BoxFuture<'a, Result<(), StoreError>>;

    /// Rows of one partition in row key order, at most `top` per page.
    fn query<'a>(
        &'a self,
        t: Table,
        pk: &'a str,
        rk: RkRange,
        filter: Option<Filter>,
        top: usize,
        page: Option<Continuation>,
    ) -> BoxFuture<'a, Result<Page<Entity>, StoreError>>;

    /// Apply up to 100 operations on rows of partition `pk` atomically: all
    /// of them, or none.
    fn batch<'a>(
        &'a self,
        t: Table,
        pk: &'a str,
        ops: Vec<BatchOp>,
    ) -> BoxFuture<'a, Result<(), StoreError>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_ranges_cover_exactly_the_prefix() {
        let range = RkRange::prefix("log:");
        assert!(range.contains("log:"));
        assert!(range.contains("log:ffff:abc"));
        assert!(!range.contains("log;"));
        assert!(!range.contains("lo"));
        assert!(!range.contains("rec:1"));
    }

    #[test]
    fn ranges_include_the_start_and_exclude_the_end() {
        let range = RkRange::between(Some("b".into()), Some("d".into()));
        assert!(range.contains("b"));
        assert!(range.contains("c:1"));
        assert!(!range.contains("d"));
        assert!(!range.contains("a"));
        assert!(RkRange::all().contains(""));
    }

    #[test]
    fn filters_combine() {
        let props: BTreeMap<String, Prop> = [
            ("event_type".to_string(), Prop::Str("pool_created".into())),
            ("success".to_string(), Prop::Bool(true)),
        ]
        .into();
        let either = Filter::Or(vec![
            Filter::eq("event_type", Prop::Str("pool_created".into())),
            Filter::eq("event_type", Prop::Str("credential_issued".into())),
        ]);
        assert!(Filter::And(vec![
            either.clone(),
            Filter::eq("success", Prop::Bool(true))
        ])
        .matches(&props));
        assert!(
            !Filter::And(vec![either, Filter::eq("success", Prop::Bool(false))]).matches(&props)
        );
    }
}
