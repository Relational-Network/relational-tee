// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! In-memory [`ObjectStore`] and [`IndexStore`], for tests and for dev runs
//! that don't need Azurite. It follows the Azure semantics the worker relies
//! on: create-only writes, ETag compare-and-swap, append blobs, and row key
//! order within a partition. Data lives as long as the process.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

use bytes::Bytes;

use super::store::{
    BoxFuture, Container, Continuation, ETag, Entity, Filter, IndexStore, InsertOutcome, Object,
    ObjectStore, Page, Prop, PutOutcome, RkRange, StoreError, Table,
};

/// A row's properties and ETag, keyed by partition and row key.
type Rows = BTreeMap<(String, String), (BTreeMap<String, Prop>, ETag)>;

#[derive(Default)]
struct Inner {
    blobs: HashMap<(Container, String), (Vec<u8>, ETag)>,
    rows: HashMap<Table, Rows>,
    next_etag: u64,
}

impl Inner {
    fn etag(&mut self) -> ETag {
        self.next_etag += 1;
        ETag(format!("\"0x{:x}\"", self.next_etag))
    }
}

/// Both stores in one mutex-protected map.
#[derive(Default)]
pub struct MemoryStore {
    inner: Mutex<Inner>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // A panic while holding the lock leaves consistent data behind: every
        // operation mutates in one step.
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Overwrite a row's properties without changing its ETag, the way a
    /// storage administrator could.
    #[cfg(test)]
    pub fn tamper_row(
        &self,
        t: Table,
        pk: &str,
        rk: &str,
        f: impl FnOnce(&mut BTreeMap<String, Prop>),
    ) {
        let mut inner = self.lock();
        let row = inner
            .rows
            .get_mut(&t)
            .and_then(|rows| rows.get_mut(&(pk.to_string(), rk.to_string())))
            .expect("row exists");
        f(&mut row.0);
    }

    /// Overwrite an object's bytes, the way a storage administrator could.
    #[cfg(test)]
    pub fn tamper_blob(&self, c: Container, path: &str, f: impl FnOnce(&mut Vec<u8>)) {
        let mut inner = self.lock();
        let blob = inner
            .blobs
            .get_mut(&(c, path.to_string()))
            .expect("blob exists");
        f(&mut blob.0);
    }
}

impl ObjectStore for MemoryStore {
    fn get<'a>(
        &'a self,
        c: Container,
        path: &'a str,
    ) -> BoxFuture<'a, Result<Option<Object>, StoreError>> {
        let found = self
            .lock()
            .blobs
            .get(&(c, path.to_string()))
            .map(|(body, _)| Object {
                body: Bytes::copy_from_slice(body),
            });
        Box::pin(async move { Ok(found) })
    }

    fn put_if_absent<'a>(
        &'a self,
        c: Container,
        path: &'a str,
        body: Bytes,
    ) -> BoxFuture<'a, Result<PutOutcome, StoreError>> {
        let mut inner = self.lock();
        let key = (c, path.to_string());
        let outcome = if inner.blobs.contains_key(&key) {
            PutOutcome::AlreadyExists
        } else {
            let etag = inner.etag();
            inner.blobs.insert(key, (body.to_vec(), etag.clone()));
            PutOutcome::Created(etag)
        };
        Box::pin(async move { Ok(outcome) })
    }

    fn append<'a>(
        &'a self,
        c: Container,
        path: &'a str,
        block: Bytes,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        let mut inner = self.lock();
        let etag = inner.etag();
        let entry = inner
            .blobs
            .entry((c, path.to_string()))
            .or_insert_with(|| (Vec::new(), etag.clone()));
        entry.0.extend_from_slice(&block);
        entry.1 = etag;
        Box::pin(async move { Ok(()) })
    }
}

impl IndexStore for MemoryStore {
    fn get<'a>(
        &'a self,
        t: Table,
        pk: &'a str,
        rk: &'a str,
    ) -> BoxFuture<'a, Result<Option<Entity>, StoreError>> {
        let found = self
            .lock()
            .rows
            .get(&t)
            .and_then(|rows| rows.get(&(pk.to_string(), rk.to_string())))
            .map(|(props, etag)| Entity {
                pk: pk.to_string(),
                rk: rk.to_string(),
                props: props.clone(),
                etag: Some(etag.clone()),
            });
        Box::pin(async move { Ok(found) })
    }

    fn insert(&self, t: Table, e: Entity) -> BoxFuture<'_, Result<InsertOutcome, StoreError>> {
        let mut inner = self.lock();
        let etag = inner.etag();
        let outcome = match inner.rows.entry(t).or_default().entry((e.pk, e.rk)) {
            std::collections::btree_map::Entry::Occupied(_) => InsertOutcome::Conflict,
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert((e.props, etag.clone()));
                InsertOutcome::Inserted(etag)
            }
        };
        Box::pin(async move { Ok(outcome) })
    }

    fn update_if_match<'a>(
        &'a self,
        t: Table,
        e: Entity,
        etag: &'a ETag,
    ) -> BoxFuture<'a, Result<ETag, StoreError>> {
        let mut inner = self.lock();
        let fresh = inner.etag();
        let rows = inner.rows.entry(t).or_default();
        let result = match rows.get_mut(&(e.pk, e.rk)) {
            None => Err(StoreError::NotFound),
            Some(row) if &row.1 != etag => Err(StoreError::PreconditionFailed),
            Some(row) => {
                *row = (e.props, fresh.clone());
                Ok(fresh)
            }
        };
        Box::pin(async move { result })
    }

    fn upsert(&self, t: Table, e: Entity) -> BoxFuture<'_, Result<ETag, StoreError>> {
        let mut inner = self.lock();
        let etag = inner.etag();
        inner
            .rows
            .entry(t)
            .or_default()
            .insert((e.pk, e.rk), (e.props, etag.clone()));
        Box::pin(async move { Ok(etag) })
    }

    fn delete_if_match<'a>(
        &'a self,
        t: Table,
        pk: &'a str,
        rk: &'a str,
        etag: &'a ETag,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        let mut inner = self.lock();
        let rows = inner.rows.entry(t).or_default();
        let key = (pk.to_string(), rk.to_string());
        let result = match rows.get(&key) {
            None => Err(StoreError::NotFound),
            Some(row) if &row.1 != etag => Err(StoreError::PreconditionFailed),
            Some(_) => {
                rows.remove(&key);
                Ok(())
            }
        };
        Box::pin(async move { result })
    }

    fn query<'a>(
        &'a self,
        t: Table,
        pk: &'a str,
        rk: RkRange,
        filter: Option<Filter>,
        top: usize,
        page: Option<Continuation>,
    ) -> BoxFuture<'a, Result<Page<Entity>, StoreError>> {
        let inner = self.lock();
        let start_after = page.map(|c| c.0);
        let mut items = Vec::new();
        let mut next = None;
        if let Some(rows) = inner.rows.get(&t) {
            let matching = rows
                .range((pk.to_string(), String::new())..)
                .take_while(|((p, _), _)| p == pk)
                .filter(|((_, r), _)| rk.contains(r))
                .filter(|((_, r), _)| start_after.as_deref().is_none_or(|s| r.as_str() >= s))
                .filter(|(_, (props, _))| filter.as_ref().is_none_or(|f| f.matches(props)));
            for ((p, r), (props, etag)) in matching {
                if items.len() == top.max(1) {
                    next = Some(Continuation(r.clone()));
                    break;
                }
                items.push(Entity {
                    pk: p.clone(),
                    rk: r.clone(),
                    props: props.clone(),
                    etag: Some(etag.clone()),
                });
            }
        }
        Box::pin(async move { Ok(Page { items, next }) })
    }
}
