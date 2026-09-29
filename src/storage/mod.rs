// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Durable state: envelope-encrypted objects in Blob storage and rows in
//! Table storage, behind the [`store::ObjectStore`] and [`store::IndexStore`]
//! traits. The repositories ([`pools`], [`records`], [`revocations`],
//! [`wallets`], [`audit`]) seal everything before it
//! reaches a store, so a storage administrator sees only ciphertext and
//! hashed identifiers. Workers keep no durable local state.

use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use store::{
    Container, Continuation, ETag, Entity, Filter, IndexStore, ObjectStore, Page, Prop, PutOutcome,
    RkRange, Table,
};

pub mod audit;
pub mod azure;
#[cfg(test)]
mod conformance;
pub mod envelope;
#[cfg(any(test, feature = "dev"))]
pub mod memory;
pub mod pools;
pub mod records;
pub mod revocations;
pub mod store;
pub mod wallets;

// Re-exports for convenience.
pub use envelope::StorageKeys;
pub use store::StoreError;

/// The name of the encrypted row property.
const PAYLOAD: &str = "payload";

/// A table key for a point in time, newest first: `u64::MAX − unix_millis`,
/// as 16 zero-padded hex digits.
pub fn inverted_millis(at: chrono::DateTime<chrono::Utc>) -> String {
    format!("{:016x}", u64::MAX - at.timestamp_millis().max(0) as u64)
}

/// A client sent a cursor that this deployment didn't issue for this list.
#[derive(Debug)]
pub struct InvalidCursor;

impl From<InvalidCursor> for crate::error::ApiError {
    fn from(_: InvalidCursor) -> Self {
        Self::bad_request("invalid pagination cursor").with_code("invalid_cursor")
    }
}

#[derive(Serialize, Deserialize)]
struct CursorPayload {
    /// The list the cursor belongs to, so it can't be replayed on another.
    s: String,
    /// The store's continuation.
    c: String,
}

/// The stores, the storage keys and the worker's identity.
pub struct Storage {
    objects: Arc<dyn ObjectStore>,
    index: Arc<dyn IndexStore>,
    keys: StorageKeys,
    worker_id: String,
    totals: records::TotalsCache,
}

impl Storage {
    pub fn new(
        objects: Arc<dyn ObjectStore>,
        index: Arc<dyn IndexStore>,
        keys: StorageKeys,
        worker_id: String,
    ) -> Self {
        Self {
            objects,
            index,
            keys,
            worker_id,
            totals: records::TotalsCache::default(),
        }
    }

    /// Both stores in memory.
    #[cfg(any(test, feature = "dev"))]
    pub fn in_memory(keys: StorageKeys, worker_id: String) -> Self {
        let store = Arc::new(memory::MemoryStore::new());
        Self::new(store.clone(), store, keys, worker_id)
    }

    pub fn pools(&self) -> pools::Pools<'_> {
        pools::Pools::new(self)
    }

    pub fn records(&self) -> records::Records<'_> {
        records::Records::new(self)
    }

    pub fn revocations(&self) -> revocations::Revocations<'_> {
        revocations::Revocations::new(self)
    }

    pub fn wallets(&self) -> wallets::Wallets<'_> {
        wallets::Wallets::new(self)
    }

    pub fn audit(&self) -> audit::AuditLog<'_> {
        audit::AuditLog::new(self)
    }

    pub fn worker_id(&self) -> &str {
        &self.worker_id
    }

    /// The readiness canary: a read and a conditional write of this
    /// worker's `leases/canary/{worker_id}` blob.
    pub async fn canary(&self) -> Result<(), StoreError> {
        let path = format!("canary/{}", self.worker_id);
        let now = bytes::Bytes::from(chrono::Utc::now().to_rfc3339());
        match self.objects.get(Container::Leases, &path).await? {
            None => match self
                .objects
                .put_if_absent(Container::Leases, &path, now)
                .await?
            {
                PutOutcome::Created(_) | PutOutcome::AlreadyExists => Ok(()),
            },
            Some(current) => self
                .objects
                .put_if_match(Container::Leases, &path, now, &current.etag)
                .await
                .map(|_| ()),
        }
    }

    pub(crate) fn objects(&self) -> &dyn ObjectStore {
        self.objects.as_ref()
    }

    pub(crate) fn index(&self) -> &dyn IndexStore {
        self.index.as_ref()
    }

    pub(crate) fn keys(&self) -> &StorageKeys {
        &self.keys
    }

    pub(crate) fn totals_cache(&self) -> &records::TotalsCache {
        &self.totals
    }

    /// A row whose `payload` is `value`, sealed for this table and these keys.
    pub(crate) fn sealed_row<T: Serialize>(
        &self,
        table: Table,
        pk: &str,
        rk: &str,
        version: u32,
        value: &T,
    ) -> Result<Entity, StoreError> {
        let plaintext = zeroize::Zeroizing::new(
            serde_json::to_vec(value)
                .map_err(|e| StoreError::Invalid(format!("serializing a row: {e}")))?,
        );
        let payload = self.keys.seal_row(table, pk, rk, version, &plaintext);
        Ok(Entity::new(pk, rk).with(PAYLOAD, Prop::Bin(payload)))
    }

    /// The decrypted `payload` of a row.
    pub(crate) fn open_row<T: DeserializeOwned>(
        &self,
        table: Table,
        version: u32,
        entity: &Entity,
    ) -> Result<T, StoreError> {
        let payload = entity
            .bin(PAYLOAD)
            .ok_or_else(|| StoreError::Integrity("row has no payload".into()))?;
        let plaintext = self
            .keys
            .open_row(table, &entity.pk, &entity.rk, version, payload)?;
        serde_json::from_slice(&plaintext)
            .map_err(|e| StoreError::Integrity(format!("row payload doesn't parse: {e}")))
    }

    /// Read and decrypt one row.
    pub(crate) async fn get_sealed<T: DeserializeOwned>(
        &self,
        table: Table,
        pk: &str,
        rk: &str,
        version: u32,
    ) -> Result<Option<(T, ETag)>, StoreError> {
        let Some(entity) = self.index.get(table, pk, rk).await? else {
            return Ok(None);
        };
        let etag = entity
            .etag
            .clone()
            .ok_or_else(|| StoreError::Invalid("row read without an ETag".into()))?;
        Ok(Some((self.open_row(table, version, &entity)?, etag)))
    }

    /// Up to `limit` rows starting at `page`, following the store's
    /// continuations until the page is full or the rows run out.
    pub(crate) async fn query_rows(
        &self,
        table: Table,
        pk: &str,
        rk: RkRange,
        filter: Option<Filter>,
        limit: usize,
        mut page: Option<Continuation>,
    ) -> Result<Page<Entity>, StoreError> {
        let limit = limit.max(1);
        let mut items = Vec::new();
        loop {
            let got = self
                .index
                .query(
                    table,
                    pk,
                    rk.clone(),
                    filter.clone(),
                    limit - items.len(),
                    page,
                )
                .await?;
            items.extend(got.items);
            page = got.next;
            if items.len() >= limit || page.is_none() {
                return Ok(Page { items, next: page });
            }
        }
    }

    /// Every row in a range, across all pages.
    pub(crate) async fn query_all(
        &self,
        table: Table,
        pk: &str,
        rk: RkRange,
        filter: Option<Filter>,
    ) -> Result<Vec<Entity>, StoreError> {
        let mut all = Vec::new();
        let mut page = None;
        loop {
            let got = self
                .index
                .query(table, pk, rk.clone(), filter.clone(), 1000, page)
                .await?;
            all.extend(got.items);
            match got.next {
                Some(next) => page = Some(next),
                None => return Ok(all),
            }
        }
    }

    /// A cursor for the next page of the list named `scope`, signed so any
    /// worker in the deployment accepts it and nobody else can forge one.
    pub fn sign_cursor(&self, scope: &str, next: &Continuation) -> String {
        let payload = serde_json::to_vec(&CursorPayload {
            s: scope.to_string(),
            c: next.0.clone(),
        })
        .expect("cursor serializes");
        format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(&payload),
            self.keys.cursor_tag(&payload)
        )
    }

    /// The continuation in a cursor issued for `scope`.
    pub fn open_cursor(&self, scope: &str, cursor: &str) -> Result<Continuation, InvalidCursor> {
        let (encoded, tag) = cursor.rsplit_once('.').ok_or(InvalidCursor)?;
        let payload = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| InvalidCursor)?;
        if !self.keys.cursor_tag_valid(&payload, tag) {
            return Err(InvalidCursor);
        }
        let parsed: CursorPayload = serde_json::from_slice(&payload).map_err(|_| InvalidCursor)?;
        if parsed.s != scope {
            return Err(InvalidCursor);
        }
        Ok(Continuation(parsed.c))
    }

    /// Open an optional client cursor for `scope`.
    pub fn page_from(
        &self,
        scope: &str,
        cursor: Option<&str>,
    ) -> Result<Option<Continuation>, InvalidCursor> {
        cursor
            .filter(|c| !c.is_empty())
            .map(|c| self.open_cursor(scope, c))
            .transpose()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::tee::tests::fixed_key;

    /// A worker's storage over a fresh in-memory store.
    pub(crate) fn memory_storage() -> Storage {
        Storage::in_memory(StorageKeys::derive(&fixed_key(1)), "worker-a".into())
    }

    /// Two workers sharing one store and one storage root.
    pub(crate) fn two_workers() -> (Storage, Storage) {
        let store = Arc::new(memory::MemoryStore::new());
        let a = Storage::new(
            store.clone(),
            store.clone(),
            StorageKeys::derive(&fixed_key(1)),
            "worker-a".into(),
        );
        let b = Storage::new(
            store.clone(),
            store,
            StorageKeys::derive(&fixed_key(1)),
            "worker-b".into(),
        );
        (a, b)
    }

    #[test]
    fn cursors_verify_across_workers_but_not_across_lists_or_deployments() {
        let (a, b) = two_workers();
        let next = Continuation("rk-42".into());
        let cursor = a.sign_cursor("tx:w1", &next);
        assert_eq!(b.open_cursor("tx:w1", &cursor).unwrap(), next);
        assert!(b.open_cursor("tx:w2", &cursor).is_err());

        let other = Storage::in_memory(StorageKeys::derive(&fixed_key(2)), "x".into());
        assert!(other.open_cursor("tx:w1", &cursor).is_err());

        let mut forged = cursor.clone();
        forged.replace_range(..2, "ey");
        assert!(a.open_cursor("tx:w1", &format!("{forged}x")).is_err());
    }

    #[tokio::test]
    async fn the_canary_reads_and_conditionally_rewrites_its_blob() {
        let s = memory_storage();
        s.canary().await.unwrap();
        let first = s
            .objects()
            .get(Container::Leases, "canary/worker-a")
            .await
            .unwrap()
            .unwrap();
        s.canary().await.unwrap();
        let second = s
            .objects()
            .get(Container::Leases, "canary/worker-a")
            .await
            .unwrap()
            .unwrap();
        assert_ne!(first.etag, second.etag);
    }

    #[test]
    fn inverted_timestamps_sort_newest_first() {
        let older = chrono::DateTime::from_timestamp_millis(1_000).unwrap();
        let newer = chrono::DateTime::from_timestamp_millis(2_000).unwrap();
        assert!(inverted_millis(newer) < inverted_millis(older));
        assert_eq!(inverted_millis(older).len(), 16);
    }
}
