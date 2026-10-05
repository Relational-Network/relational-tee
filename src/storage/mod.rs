// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Durable state: sealed JSON documents in the `state` container.
//!
//! - `pools/{pool_pda}.json`: a pool's metadata, schema, uploads and
//!   revocations ([`pools`]); `pools/{pool_pda}/datasets/{upload_id}`: one
//!   uploaded CSV.
//! - `wallets/{wallet_id}.json` and `wallets/{wallet_id}/keypair`, and
//!   `owners/{user_id}.json`, the user's current wallet ([`wallets`]).
//! - `identities/{h(tid ‖ oid)}.json` and `identities/email/{h(email)}.json`
//!   ([`identities`]).
//! - `scripts/{sha256}`: analysis definitions, by hash ([`scripts`]).
//! - `config/employer-scopes.json`: the rows each Entra group may see
//!   ([`scopes`]).
//! - `audit/analyses/{pool_pda}/{date}/{request_id}.json`: one record per
//!   analysis request ([`analysis_log`]).
//! - `staged/{op_id}.json`: in-flight chain sagas ([`staged`]), and
//!   `idempotency/…`, the idempotency records ([`crate::idempotency`]).
//! - `canary/{worker_id}`: the readiness canary.
//!
//! Every object is sealed inside the worker ([`crate::store::sealed`]), and
//! every write is conditional, so no worker needs a lock and workers keep
//! nothing durable of their own.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::store::sealed::Sealed;
use crate::store::{valid_segment, ObjectStore, Replaced, STATE};

pub mod analysis_log;
pub mod identities;
pub mod pools;
pub mod scopes;
pub mod scripts;
pub mod staged;
pub mod wallets;

pub use crate::store::sealed::{Change, StorageKeys};
pub use crate::store::StoreError;

/// Decrypted objects each worker caches.
const CACHE_ENTRIES: usize = 4096;

/// The `state` container, sealed, and this worker's identity.
pub struct Storage {
    state: Sealed,
    worker_id: String,
}

#[derive(Serialize, Deserialize)]
struct Canary {
    at: DateTime<Utc>,
}

/// An ID from a request, if it can be part of an object name.
pub(crate) fn id(value: &str) -> Option<&str> {
    valid_segment(value).then_some(value)
}

impl Storage {
    pub fn new(store: Arc<dyn ObjectStore>, keys: StorageKeys, worker_id: String) -> Self {
        Self {
            state: Sealed::new(store, STATE, keys, CACHE_ENTRIES),
            worker_id,
        }
    }

    pub fn pools(&self) -> pools::Pools<'_> {
        pools::Pools::new(self)
    }

    pub fn wallets(&self) -> wallets::Wallets<'_> {
        wallets::Wallets::new(self)
    }

    pub fn sagas(&self) -> staged::Sagas<'_> {
        staged::Sagas::new(self)
    }

    pub fn scripts(&self) -> scripts::Scripts<'_> {
        scripts::Scripts::new(self)
    }

    pub fn employer_scopes(&self) -> scopes::Scopes<'_> {
        scopes::Scopes::new(self)
    }

    pub fn analysis_log(&self) -> analysis_log::AnalysisLog<'_> {
        analysis_log::AnalysisLog::new(self)
    }

    pub fn identities(&self) -> identities::Identities<'_> {
        identities::Identities::new(self)
    }

    pub fn worker_id(&self) -> &str {
        &self.worker_id
    }

    pub(crate) fn state(&self) -> &Sealed {
        &self.state
    }

    /// The readiness canary: a read and a conditional write of this worker's
    /// sealed `canary/{worker_id}`, which also proves `storage-root` works.
    pub async fn canary(&self) -> Result<(), StoreError> {
        let path = format!("canary/{}", self.worker_id);
        let now = Canary { at: Utc::now() };
        match self.state.get_json::<Canary>(&path).await? {
            None => {
                self.state.create_json(&path, &now).await?;
            }
            Some((_, etag)) => {
                if let Replaced::Stale = self.state.replace_json(&path, &now, &etag).await? {
                    return Err(StoreError::Invalid(
                        "the canary changed under this worker".into(),
                    ));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::store::files::LocalFiles;
    use crate::store::{Fetched, ObjectStore};
    use crate::tee::tests::fixed_key;

    /// A worker's storage over a fresh temporary directory.
    pub(crate) fn files_storage() -> Storage {
        Storage::new(
            Arc::new(LocalFiles::temporary()),
            StorageKeys::derive(&fixed_key(1)),
            "worker-a".into(),
        )
    }

    /// Two workers sharing one set of files and one storage root, and the
    /// files themselves.
    pub(crate) fn two_workers() -> (Storage, Storage, Arc<LocalFiles>) {
        let files = Arc::new(LocalFiles::temporary());
        let worker =
            |id: &str| Storage::new(files.clone(), StorageKeys::derive(&fixed_key(1)), id.into());
        (worker("worker-a"), worker("worker-b"), files)
    }

    #[tokio::test]
    async fn the_canary_reads_and_conditionally_rewrites_its_object() {
        let (s, _, files) = two_workers();
        s.canary().await.unwrap();
        let Fetched::Found { etag: first, .. } = files.get("canary/worker-a", None).await.unwrap()
        else {
            panic!("written");
        };
        s.canary().await.unwrap();
        let Fetched::Found { etag: second, .. } = files.get("canary/worker-a", None).await.unwrap()
        else {
            panic!("rewritten");
        };
        assert_ne!(first, second);
    }

    #[test]
    fn request_ids_that_could_name_other_objects_are_refused() {
        assert_eq!(
            id("0f8fad5b-d9cb-469f-a165-70867728950e"),
            Some("0f8fad5b-d9cb-469f-a165-70867728950e")
        );
        assert_eq!(id("../owners/x"), None);
        assert_eq!(id(""), None);
    }
}
