// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Sealing, and the per-worker cache, above an [`ObjectStore`].
//!
//! Two keys come from `storage-root`'s private scalar through HKDF-SHA256,
//! with salt `relational-tee/storage-root` and a versioned label as info:
//! `storage-key-v1` seals every object, and `index-hmac-v1` computes `h(x)`,
//! so Entra object IDs and emails never appear in object names.
//!
//! A sealed object is `"RTS1"` ‖ a random 96-bit nonce ‖ AES-256-GCM
//! ciphertext and tag, with associated data `relational-tee/state/v1` ‖ 0x00 ‖
//! container ‖ 0x00 ‖ path, so an object moved or copied elsewhere fails to
//! open.
//!
//! Decrypted objects are cached per worker in a bounded LRU keyed by path,
//! with their ETags. A read of a mutable object sends the cached ETag and
//! costs no body or decryption when nothing changed; immutable objects are
//! never revalidated. Writes are always conditional in the store, and each
//! worker's own writes go straight into its cache.

use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use bytes::Bytes;
use futures_util::stream::{self, StreamExt, TryStreamExt};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use lru::LruCache;
use p256::elliptic_curve::rand_core::{OsRng, RngCore};
use serde::de::DeserializeOwned;
use serde::Serialize;
use sha2::Sha256;
use zeroize::Zeroizing;

use super::{Created, ETag, Fetched, Listed, ObjectStore, Replaced, StoreError};
use crate::tee::EcKey;

const SALT: &[u8] = b"relational-tee/storage-root";
const MAGIC: &[u8; 4] = b"RTS1";
const AAD_PREFIX: &[u8] = b"relational-tee/state/v1";
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// Objects larger than this aren't cached.
const MAX_CACHED_BYTES: usize = 1 << 20;
/// Objects fetched at once when a list needs several.
const FETCH_CONCURRENCY: usize = 16;
/// Compare-and-swap attempts: the first try and three retries.
const CAS_ATTEMPTS: u32 = 4;

/// The keys derived from `storage-root`. They zeroize on drop.
pub struct StorageKeys {
    storage: Zeroizing<[u8; 32]>,
    index_hmac: Zeroizing<[u8; 32]>,
}

fn derive(ikm: &[u8], label: &str) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(SALT), ikm)
        .expand(label.as_bytes(), key.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    key
}

impl StorageKeys {
    pub fn derive(storage_root: &EcKey) -> Self {
        let ikm = Zeroizing::new(storage_root.secret().to_bytes());
        Self {
            storage: derive(&ikm, "storage-key-v1"),
            index_hmac: derive(&ikm, "index-hmac-v1"),
        }
    }

    /// `h(x)`: hex HMAC-SHA256 under the index key.
    pub fn index_hash(&self, value: &str) -> String {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(self.index_hmac.as_ref())
            .expect("HMAC takes any key length");
        mac.update(value.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    fn aad(container: &str, path: &str) -> Vec<u8> {
        let mut aad = AAD_PREFIX.to_vec();
        aad.push(0);
        aad.extend_from_slice(container.as_bytes());
        aad.push(0);
        aad.extend_from_slice(path.as_bytes());
        aad
    }

    fn cipher(&self) -> Aes256Gcm {
        Aes256Gcm::new_from_slice(self.storage.as_ref()).expect("32-byte key")
    }

    /// Seal `plaintext` for `container/path`.
    pub fn seal(&self, container: &str, path: &str, plaintext: &[u8]) -> Vec<u8> {
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let ciphertext = self
            .cipher()
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &Self::aad(container, path),
                },
            )
            .expect("AES-GCM encryption doesn't fail");
        let mut out = Vec::with_capacity(MAGIC.len() + NONCE_LEN + ciphertext.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        out
    }

    /// Open an object sealed for the same `container/path`.
    pub fn open(
        &self,
        container: &str,
        path: &str,
        sealed: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        let header = MAGIC.len() + NONCE_LEN;
        if sealed.len() < header + TAG_LEN || &sealed[..MAGIC.len()] != MAGIC {
            return Err(StoreError::Integrity(format!(
                "{path} isn't a sealed object"
            )));
        }
        self.cipher()
            .decrypt(
                Nonce::from_slice(&sealed[MAGIC.len()..header]),
                Payload {
                    msg: &sealed[header..],
                    aad: &Self::aad(container, path),
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| StoreError::Integrity(format!("{path} doesn't open at this path")))
    }
}

/// A decrypted object and its ETag.
#[derive(Clone)]
pub struct Doc {
    pub plain: Arc<Zeroizing<Vec<u8>>>,
    pub etag: ETag,
}

/// Whether an update changed the object.
pub enum Change {
    Changed,
    Unchanged,
}

/// A short random pause before retrying a lost compare-and-swap.
async fn backoff(attempt: u32) {
    let millis = 20 * u64::from(attempt) + u64::from(OsRng.next_u32() % 50);
    tokio::time::sleep(Duration::from_millis(millis)).await;
}

fn to_json<T: Serialize>(value: &T) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    serde_json::to_vec(value)
        .map(Zeroizing::new)
        .map_err(|e| StoreError::Invalid(format!("serializing a document: {e}")))
}

fn from_json<T: DeserializeOwned>(path: &str, plain: &[u8]) -> Result<T, StoreError> {
    serde_json::from_slice(plain)
        .map_err(|e| StoreError::Integrity(format!("{path} doesn't parse: {e}")))
}

/// A sealed container with a per-worker cache.
pub struct Sealed {
    store: Arc<dyn ObjectStore>,
    container: &'static str,
    keys: StorageKeys,
    cache: Mutex<LruCache<String, Doc>>,
}

impl Sealed {
    pub fn new(
        store: Arc<dyn ObjectStore>,
        container: &'static str,
        keys: StorageKeys,
        cache_entries: usize,
    ) -> Self {
        Self {
            store,
            container,
            keys,
            cache: Mutex::new(LruCache::new(
                NonZeroUsize::new(cache_entries).expect("cache capacity must be > 0"),
            )),
        }
    }

    pub fn index_hash(&self, value: &str) -> String {
        self.keys.index_hash(value)
    }

    fn cached(&self, path: &str) -> Option<Doc> {
        self.cache.lock().ok()?.get(path).cloned()
    }

    fn remember(&self, path: &str, doc: &Doc) {
        if doc.plain.len() <= MAX_CACHED_BYTES {
            if let Ok(mut cache) = self.cache.lock() {
                cache.put(path.to_string(), doc.clone());
            }
        }
    }

    fn forget(&self, path: &str) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.pop(path);
        }
    }

    /// The object at `path`, revalidating any cached copy by its ETag.
    pub async fn read(&self, path: &str) -> Result<Option<Doc>, StoreError> {
        let cached = self.cached(path);
        match self
            .store
            .get(path, cached.as_ref().map(|d| &d.etag))
            .await?
        {
            Fetched::NotModified => Ok(cached),
            Fetched::Missing => {
                self.forget(path);
                Ok(None)
            }
            Fetched::Found { body, etag } => {
                let doc = Doc {
                    plain: Arc::new(self.keys.open(self.container, path, &body)?),
                    etag,
                };
                self.remember(path, &doc);
                Ok(Some(doc))
            }
        }
    }

    /// The object at `path`, from the cache without a store call if it's
    /// there. Only for objects that never change once written.
    pub async fn read_immutable(&self, path: &str) -> Result<Option<Doc>, StoreError> {
        match self.cached(path) {
            Some(doc) => Ok(Some(doc)),
            None => self.read(path).await,
        }
    }

    /// The object at `path`, opened, without caching it: for large objects
    /// that a caller caches itself.
    pub async fn read_uncached(
        &self,
        path: &str,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, StoreError> {
        match self.store.get(path, None).await? {
            Fetched::Found { body, .. } => Ok(Some(self.keys.open(self.container, path, &body)?)),
            Fetched::Missing => Ok(None),
            Fetched::NotModified => Err(StoreError::Invalid(format!(
                "{path} was \"not modified\" on an unconditional read"
            ))),
        }
    }

    /// Create the object unless `path` is taken.
    pub async fn create(&self, path: &str, plain: &[u8]) -> Result<Created, StoreError> {
        let sealed = self.keys.seal(self.container, path, plain);
        let created = self.store.put_if_absent(path, Bytes::from(sealed)).await?;
        if let Created::New(etag) = &created {
            self.remember(
                path,
                &Doc {
                    plain: Arc::new(Zeroizing::new(plain.to_vec())),
                    etag: etag.clone(),
                },
            );
        }
        Ok(created)
    }

    /// Create the object unless `path` is taken, without caching it.
    pub async fn create_uncached(&self, path: &str, plain: &[u8]) -> Result<Created, StoreError> {
        let sealed = self.keys.seal(self.container, path, plain);
        self.store.put_if_absent(path, Bytes::from(sealed)).await
    }

    /// Replace the object if its ETag is still `etag`.
    pub async fn replace(
        &self,
        path: &str,
        plain: &[u8],
        etag: &ETag,
    ) -> Result<Replaced, StoreError> {
        let sealed = self.keys.seal(self.container, path, plain);
        let replaced = self
            .store
            .put_if_match(path, Bytes::from(sealed), etag)
            .await?;
        match &replaced {
            Replaced::Done(etag) => self.remember(
                path,
                &Doc {
                    plain: Arc::new(Zeroizing::new(plain.to_vec())),
                    etag: etag.clone(),
                },
            ),
            Replaced::Stale => self.forget(path),
        }
        Ok(replaced)
    }

    /// The objects directly under `dir`.
    pub async fn list(&self, dir: &str) -> Result<Vec<Listed>, StoreError> {
        self.store.list(dir).await
    }

    /// A listed object, fetched only if the cache doesn't hold its ETag.
    pub async fn read_listed(&self, listed: &Listed) -> Result<Option<Doc>, StoreError> {
        match self.cached(&listed.path) {
            Some(doc) if doc.etag == listed.etag => Ok(Some(doc)),
            _ => self.read(&listed.path).await,
        }
    }

    /// The JSON document at `path`, and its ETag.
    pub async fn get_json<T: DeserializeOwned>(
        &self,
        path: &str,
    ) -> Result<Option<(T, ETag)>, StoreError> {
        match self.read(path).await? {
            Some(doc) => Ok(Some((from_json(path, &doc.plain)?, doc.etag))),
            None => Ok(None),
        }
    }

    /// A JSON document that never changes once written.
    pub async fn get_immutable_json<T: DeserializeOwned>(
        &self,
        path: &str,
    ) -> Result<Option<T>, StoreError> {
        match self.read_immutable(path).await? {
            Some(doc) => Ok(Some(from_json(path, &doc.plain)?)),
            None => Ok(None),
        }
    }

    pub async fn create_json<T: Serialize>(
        &self,
        path: &str,
        value: &T,
    ) -> Result<Created, StoreError> {
        self.create(path, &to_json(value)?).await
    }

    pub async fn replace_json<T: Serialize>(
        &self,
        path: &str,
        value: &T,
        etag: &ETag,
    ) -> Result<Replaced, StoreError> {
        self.replace(path, &to_json(value)?, etag).await
    }

    /// Apply `change` to the document by compare-and-swap. `change` runs
    /// against the current document on every attempt and may refuse by
    /// returning an error; after three lost retries this gives up with
    /// [`StoreError::Contended`]. Returns `None` if there's no document.
    pub async fn update_json<T, E>(
        &self,
        path: &str,
        mut change: impl FnMut(&mut T) -> Result<Change, E>,
    ) -> Result<Option<T>, E>
    where
        T: Serialize + DeserializeOwned,
        E: From<StoreError>,
    {
        for attempt in 1..=CAS_ATTEMPTS {
            let Some((mut value, etag)) = self.get_json::<T>(path).await? else {
                return Ok(None);
            };
            if let Change::Unchanged = change(&mut value)? {
                return Ok(Some(value));
            }
            match self.replace_json(path, &value, &etag).await? {
                Replaced::Done(_) => return Ok(Some(value)),
                Replaced::Stale if attempt < CAS_ATTEMPTS => backoff(attempt).await,
                Replaced::Stale => {}
            }
        }
        Err(StoreError::Contended.into())
    }

    /// Every JSON document directly under `dir` whose name `wanted`
    /// accepts, in name order. Only changed documents are fetched.
    pub async fn list_json<T: DeserializeOwned>(
        &self,
        dir: &str,
        wanted: impl Fn(&str) -> bool,
    ) -> Result<Vec<T>, StoreError> {
        let listed: Vec<Listed> = self
            .list(dir)
            .await?
            .into_iter()
            .filter(|l| wanted(&l.path))
            .collect();
        let docs: Vec<Option<Doc>> = stream::iter(listed.iter().cloned())
            .map(|l| async move { self.read_listed(&l).await })
            .buffered(FETCH_CONCURRENCY)
            .try_collect()
            .await?;
        listed
            .iter()
            .zip(docs)
            .filter_map(|(l, doc)| doc.map(|d| (l, d)))
            .map(|(l, doc)| from_json(&l.path, &doc.plain))
            .collect()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::store::files::LocalFiles;
    use crate::tee::tests::fixed_key;

    pub(crate) fn keys() -> StorageKeys {
        StorageKeys::derive(&fixed_key(1))
    }

    #[test]
    fn derivation_is_pinned() {
        // HKDF-SHA256(salt "relational-tee/storage-root", ikm = the scalar
        // 0x42 00…00 01, info = label), computed independently.
        let k = keys();
        assert_eq!(
            hex::encode(k.storage.as_ref()),
            "0be794273f019286d78e117db40b7660309ebf9e5144a277186af0f926aeb17d"
        );
        assert_eq!(
            hex::encode(k.index_hmac.as_ref()),
            "3c051f8d7a0f291acfa74ffe442b148edd089f24cb39cbf32c2a4b1d1cf9ce60"
        );
        assert_eq!(
            k.index_hash("user-1"),
            "5cae7ade181cdb0bb1d43fd3a3d1c7e8077cd23e97963daebd60ba7b66fb9c2e"
        );
    }

    #[test]
    fn objects_open_only_at_their_own_path_with_their_own_key() {
        let k = keys();
        let sealed = k.seal("state", "pools/P1.json", b"{\"a\":1}");
        assert_eq!(&sealed[..4], b"RTS1");
        assert_eq!(
            k.open("state", "pools/P1.json", &sealed)
                .unwrap()
                .as_slice(),
            b"{\"a\":1}"
        );
        // Moved, even to another container, or flipped: it doesn't open.
        assert!(k.open("state", "pools/P2.json", &sealed).is_err());
        assert!(k.open("tls", "pools/P1.json", &sealed).is_err());
        let mut flipped = sealed.clone();
        *flipped.last_mut().unwrap() ^= 1;
        assert!(k.open("state", "pools/P1.json", &flipped).is_err());
        // Another environment's storage root can't open it either.
        let other = StorageKeys::derive(&fixed_key(2));
        assert!(matches!(
            other.open("state", "pools/P1.json", &sealed),
            Err(StoreError::Integrity(_))
        ));
    }

    /// Two workers' sealed stores over one set of files.
    fn two_workers() -> (Sealed, Sealed, Arc<LocalFiles>) {
        let files = Arc::new(LocalFiles::temporary());
        let a = Sealed::new(files.clone(), "state", keys(), 16);
        let b = Sealed::new(files.clone(), "state", keys(), 16);
        (a, b, files)
    }

    #[tokio::test]
    async fn a_write_on_one_worker_is_visible_to_the_next_read_on_another() {
        let (a, b, _files) = two_workers();
        a.create_json("wallets/w1.json", &serde_json::json!({"status": "active"}))
            .await
            .unwrap();
        let (seen, _) = b
            .get_json::<serde_json::Value>("wallets/w1.json")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(seen["status"], "active");

        a.update_json::<serde_json::Value, StoreError>("wallets/w1.json", |v| {
            v["status"] = "suspended".into();
            Ok(Change::Changed)
        })
        .await
        .unwrap();
        // b's cached copy is revalidated by its ETag and replaced.
        let (seen, _) = b
            .get_json::<serde_json::Value>("wallets/w1.json")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(seen["status"], "suspended");
    }

    #[tokio::test]
    async fn a_stale_etag_loses_and_updates_retry_until_they_land() {
        let (a, b, _files) = two_workers();
        let path = "pools/P1.json";
        let Created::New(first) = a.create_json(path, &vec![0u32]).await.unwrap() else {
            panic!("new document");
        };
        assert_eq!(
            a.create_json(path, &vec![9u32]).await.unwrap(),
            Created::AlreadyExists
        );
        let Replaced::Done(_) = b.replace_json(path, &vec![1u32], &first).await.unwrap() else {
            panic!("current ETag");
        };
        assert_eq!(
            a.replace_json(path, &vec![2u32], &first).await.unwrap(),
            Replaced::Stale
        );

        // Concurrent appends on two workers both land.
        let push = |n: u32| {
            move |v: &mut Vec<u32>| -> Result<Change, StoreError> {
                v.push(n);
                Ok(Change::Changed)
            }
        };
        let (x, y) = tokio::join!(a.update_json(path, push(10)), b.update_json(path, push(20)));
        x.unwrap();
        y.unwrap();
        let (value, _) = a.get_json::<Vec<u32>>(path).await.unwrap().unwrap();
        assert!(value.contains(&10) && value.contains(&20) && value.len() == 3);
        assert!(a
            .update_json::<Vec<u32>, StoreError>("pools/none.json", push(1))
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn a_moved_object_fails_to_open() {
        let (a, _b, files) = two_workers();
        a.create_json("wallets/w1.json", &"one").await.unwrap();
        let Fetched::Found { body, .. } = files.get("wallets/w1.json", None).await.unwrap() else {
            panic!("stored");
        };
        // A storage administrator copies the object to another name.
        files.put_if_absent("wallets/w2.json", body).await.unwrap();
        assert!(matches!(
            a.get_json::<String>("wallets/w2.json").await,
            Err(StoreError::Integrity(_))
        ));
    }

    #[tokio::test]
    async fn lists_fetch_only_what_changed_and_filter_names() {
        let (a, b, _files) = two_workers();
        for id in ["w1", "w2"] {
            a.create_json(&format!("wallets/{id}.json"), &id)
                .await
                .unwrap();
        }
        a.create("wallets/w1/keypair", b"secret").await.unwrap();
        let docs: Vec<String> = b
            .list_json("wallets/", |p| p.ends_with(".json"))
            .await
            .unwrap();
        assert_eq!(docs, ["w1", "w2"]);
        assert!(b.cached("wallets/w2.json").is_some());
    }
}
