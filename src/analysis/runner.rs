// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Running analyses on a worker. Definitions are cached by hash, decrypted
//! datasets by upload, and scoped tables by pool version and scope, each
//! loaded once and kept within a memory budget, so a warm query reads no
//! dataset and a new upload loads only its own. SQLite work runs on
//! blocking threads, about one per CPU at a time.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;
use tracing::info;
use zeroize::Zeroizing;

use super::cache::{Cache, Weigh};
use super::definition::Definition;
use super::table::{Scope, Table};
use crate::error::ApiError;
use crate::storage::pools::{PoolDoc, Upload};
use crate::storage::{Storage, StoreError};

/// Memory for decrypted datasets.
const DATASET_BUDGET: usize = 512 << 20;
/// Memory for scoped tables.
const TABLE_BUDGET: usize = 1 << 30;
/// How long a request waits for a free thread before it gets 503.
const QUEUE_WAIT: Duration = Duration::from_secs(1);

/// How long one statement may run: well inside the request time limit.
pub const DEADLINE: Duration = Duration::from_secs(10);

struct Dataset(Zeroizing<Vec<u8>>);

impl Weigh for Dataset {
    fn bytes(&self) -> usize {
        self.0.len()
    }
}

impl Weigh for Table {
    fn bytes(&self) -> usize {
        self.bytes
    }
}

/// What a table holds: the rows of these uploads that this scope allows,
/// read with this definition.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TableKey {
    pool_pda: String,
    definition: [u8; 32],
    uploads: Vec<String>,
    scope: Scope,
}

pub struct Analyses {
    definitions: Mutex<HashMap<String, Arc<Definition>>>,
    datasets: Cache<(String, String), Dataset>,
    tables: Cache<TableKey, Table>,
    threads: Arc<Semaphore>,
}

impl Default for Analyses {
    fn default() -> Self {
        let cpus = std::thread::available_parallelism().map_or(2, |n| n.get());
        Self {
            definitions: Mutex::default(),
            datasets: Cache::new(DATASET_BUDGET),
            tables: Cache::new(TABLE_BUDGET),
            threads: Arc::new(Semaphore::new(cpus)),
        }
    }
}

fn busy() -> ApiError {
    let mut e =
        ApiError::service_unavailable("the worker is busy with other analyses; retry shortly")
            .with_code("analysis_busy");
    e.retry_after = Some(1);
    e
}

impl Analyses {
    /// The definition stored as `scripts/{sha256}`, whose bytes are hashed
    /// again when they're read.
    pub async fn definition(
        &self,
        storage: &Storage,
        sha256: &str,
    ) -> Result<Arc<Definition>, ApiError> {
        let cached = self
            .definitions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(sha256)
            .cloned();
        if let Some(definition) = cached {
            return Ok(definition);
        }
        let bytes = storage
            .scripts()
            .get(sha256)
            .await?
            .ok_or_else(|| ApiError::internal("the pool's analysis definition isn't stored"))?;
        let definition = Arc::new(Definition::parse(&bytes).map_err(|e| {
            ApiError::internal(format!("the stored analysis definition isn't valid: {e}"))
        })?);
        self.definitions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(sha256.to_string(), definition.clone());
        Ok(definition)
    }

    /// The rows of `doc`'s uploads that `scope` allows, as a table. Revoked
    /// uploads' rows are left out.
    pub async fn table(
        &self,
        storage: &Storage,
        doc: &PoolDoc,
        definition: &Arc<Definition>,
        scope: &Scope,
    ) -> Result<Arc<Table>, ApiError> {
        let uploads: Vec<&Upload> = doc
            .uploads()
            .filter(|u| !doc.is_revoked(&u.record_id))
            .collect();
        let key = TableKey {
            pool_pda: doc.pool_pda.clone(),
            definition: definition.sha256,
            uploads: uploads.iter().map(|u| u.upload_id.clone()).collect(),
            scope: scope.clone(),
        };
        self.tables
            .get_or_load(key, || async {
                let mut datasets = Vec::with_capacity(uploads.len());
                for upload in &uploads {
                    datasets.push(self.dataset(storage, &doc.pool_pda, upload).await?);
                }
                let (definition, scope) = (definition.clone(), scope.clone());
                let pool_pda = doc.pool_pda.clone();
                self.blocking(move || {
                    let csvs: Vec<&[u8]> = datasets.iter().map(|d| d.0.as_slice()).collect();
                    let table = Table::build(&definition, &csvs, &scope).map_err(|e| {
                        ApiError::internal(format!("building the analysis table failed: {e}"))
                    })?;
                    info!(pool = %pool_pda, rows = table.rows, bytes = table.bytes,
                        "Built an analysis table");
                    Ok(table)
                })
                .await
            })
            .await
    }

    async fn dataset(
        &self,
        storage: &Storage,
        pool_pda: &str,
        upload: &Upload,
    ) -> Result<Arc<Dataset>, ApiError> {
        let key = (pool_pda.to_string(), upload.upload_id.clone());
        self.datasets
            .get_or_load(key, || async {
                let csv = storage
                    .pools()
                    .read_dataset(pool_pda, &upload.upload_id)
                    .await?
                    .ok_or_else(|| {
                        ApiError::internal(format!("upload {} has no dataset", upload.record_id))
                    })?;
                if hex::encode(Sha256::digest(csv.as_slice())) != upload.sha256 {
                    return Err(StoreError::Integrity(format!(
                        "upload {}'s dataset doesn't match its digest",
                        upload.record_id
                    ))
                    .into());
                }
                Ok(Dataset(csv))
            })
            .await
    }

    /// Run `work` on a blocking thread once one is free, or 503 if none
    /// frees up within a second.
    pub async fn blocking<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> Result<T, ApiError> + Send + 'static,
    ) -> Result<T, ApiError> {
        let permit = tokio::time::timeout(QUEUE_WAIT, self.threads.clone().acquire_owned())
            .await
            .map_err(|_| busy())?
            .map_err(|_| ApiError::internal("the analysis threads are closed"))?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            work()
        })
        .await
        .map_err(|e| ApiError::internal(format!("an analysis task failed: {e}")))?
    }

    /// The datasets and tables loaded so far, and their bytes.
    #[cfg(test)]
    pub fn usage(&self) -> ((usize, usize), (usize, usize)) {
        (self.datasets.usage(), self.tables.usage())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};

    use bytes::Bytes;
    use chrono::Utc;

    use super::*;
    use crate::analysis::definition::tests::AWARDS_REPORT;
    use crate::analysis::table::tests::only;
    use crate::data_validation::tests::AWARDS_HEADER;
    use crate::storage::pools::tests::pool;
    use crate::storage::pools::{Revocation, INITIAL};
    use crate::storage::StorageKeys;
    use crate::store::files::LocalFiles;
    use crate::store::{BoxFuture, Created, ETag, Fetched, Listed, ObjectStore, Replaced};
    use crate::tee::tests::fixed_key;

    /// Local files that count the dataset reads.
    struct Counting {
        files: LocalFiles,
        dataset_reads: AtomicUsize,
    }

    impl Default for Counting {
        fn default() -> Self {
            Self {
                files: LocalFiles::temporary(),
                dataset_reads: AtomicUsize::new(0),
            }
        }
    }

    impl ObjectStore for Counting {
        fn get<'a>(
            &'a self,
            path: &'a str,
            cached: Option<&'a ETag>,
        ) -> BoxFuture<'a, Result<Fetched, StoreError>> {
            if path.contains("/datasets/") {
                self.dataset_reads.fetch_add(1, SeqCst);
            }
            self.files.get(path, cached)
        }
        fn put_if_absent<'a>(
            &'a self,
            path: &'a str,
            body: Bytes,
        ) -> BoxFuture<'a, Result<Created, StoreError>> {
            self.files.put_if_absent(path, body)
        }
        fn put_if_match<'a>(
            &'a self,
            path: &'a str,
            body: Bytes,
            etag: &'a ETag,
        ) -> BoxFuture<'a, Result<Replaced, StoreError>> {
            self.files.put_if_match(path, body, etag)
        }
        fn list<'a>(&'a self, dir: &'a str) -> BoxFuture<'a, Result<Vec<Listed>, StoreError>> {
            self.files.list(dir)
        }
    }

    /// An upload of one row per `(employer, employer group)`, stored.
    async fn upload(storage: &Storage, record_id: &str, rows: &[(&str, &str)]) -> Upload {
        let mut csv = format!("{AWARDS_HEADER}\n");
        for (i, (employer, group)) in rows.iter().enumerate() {
            csv.push_str(&format!(
                "{i:06},M{i},Mx,Sam,Example,01/01/1990,{employer},{group},Certificate,Pass,01/01/2026\n"
            ));
        }
        let upload_id = format!("u-{record_id}");
        storage
            .pools()
            .put_dataset("P1", &upload_id, csv.as_bytes())
            .await
            .unwrap();
        Upload {
            record_id: record_id.into(),
            upload_id,
            sha256: hex::encode(Sha256::digest(csv.as_bytes())),
            rows: rows.len() as u64,
            uploaded_by: "alice".into(),
            uploaded_at: Utc::now(),
            signature: None,
            commitment: None,
        }
    }

    #[tokio::test]
    async fn warm_tables_read_no_dataset_and_a_new_upload_loads_only_its_own() {
        let store = Arc::new(Counting::default());
        let storage = Storage::new(
            store.clone(),
            StorageKeys::derive(&fixed_key(1)),
            "worker-a".into(),
        );
        let hash = storage
            .scripts()
            .put(AWARDS_REPORT.as_bytes())
            .await
            .unwrap();
        let mut doc = pool("P1", "w1");
        doc.initial = Some(
            upload(
                &storage,
                INITIAL,
                &[("Bank A", "Group A"), ("Bank C", "Group C")],
            )
            .await,
        );
        let analyses = Analyses::default();
        let definition = analyses.definition(&storage, &hash).await.unwrap();
        let group_a = only(&[&[("employer_group", "Group A")]]);
        let reads = || store.dataset_reads.load(SeqCst);

        // Ten concurrent first queries build one table from one read.
        let tables = futures_util::future::join_all(
            (0..10).map(|_| analyses.table(&storage, &doc, &definition, &group_a)),
        )
        .await;
        let first = tables[0].as_ref().unwrap();
        assert!(tables
            .iter()
            .all(|t| Arc::ptr_eq(t.as_ref().unwrap(), first)));
        assert_eq!((first.rows, reads()), (1, 1));

        // Warm, nothing is read; another scope reuses the dataset.
        let again = analyses
            .table(&storage, &doc, &definition, &group_a)
            .await
            .unwrap();
        assert!(Arc::ptr_eq(&again, first));
        let all = analyses
            .table(&storage, &doc, &definition, &Scope::All)
            .await
            .unwrap();
        assert_eq!((all.rows, reads()), (2, 1));

        // A grant changes the document, not the table.
        doc.grants
            .push(crate::storage::pools::tests::grant("g-1", "ana", 1));
        let granted = analyses
            .table(&storage, &doc, &definition, &group_a)
            .await
            .unwrap();
        assert!(Arc::ptr_eq(&granted, first));

        // A new upload loads only its own dataset; a revocation drops its
        // rows and loads nothing.
        doc.issuances
            .push(upload(&storage, "r-2", &[("Bank A Network", "Group A")]).await);
        let grown = analyses
            .table(&storage, &doc, &definition, &group_a)
            .await
            .unwrap();
        assert_eq!((grown.rows, reads()), (2, 2));
        doc.revocations.push(Revocation {
            credential_id: "r-2".into(),
            revoked_by: "alice".into(),
            revoked_at: Utc::now(),
            reason: None,
        });
        let shrunk = analyses
            .table(&storage, &doc, &definition, &group_a)
            .await
            .unwrap();
        assert!(Arc::ptr_eq(&shrunk, first), "the same uploads as at first");
        assert_eq!(reads(), 2);
        let ((dataset_bytes, datasets), (_, tables)) = analyses.usage();
        assert!(dataset_bytes > 0);
        assert_eq!((datasets, tables), (2, 3));

        // A dataset that doesn't match its upload's digest is refused.
        let mut tampered = doc.clone();
        tampered
            .issuances
            .push(upload(&storage, "r-3", &[("Bank A", "Group A")]).await);
        tampered.issuances[1].sha256 = "00".repeat(32);
        let refused = analyses
            .table(&storage, &tampered, &definition, &group_a)
            .await
            .err()
            .unwrap();
        assert_eq!(refused.code, "integrity_error");
    }

    #[tokio::test]
    async fn work_waits_for_a_free_thread_and_then_gives_up() {
        let analyses = Analyses {
            threads: Arc::new(Semaphore::new(1)),
            ..Analyses::default()
        };
        let (started, release) = (
            Arc::new(tokio::sync::Notify::new()),
            Arc::new(std::sync::Barrier::new(2)),
        );
        let (notify, wait) = (started.clone(), release.clone());
        let busy = analyses.blocking(move || {
            notify.notify_one();
            wait.wait();
            Ok(1)
        });
        let refused = async {
            started.notified().await;
            let refused = analyses.blocking(|| Ok(2)).await;
            release.wait();
            refused
        };
        let (busy, refused) = tokio::join!(busy, refused);
        assert_eq!(busy.unwrap(), 1);
        let refused = refused.unwrap_err();
        assert_eq!(
            (refused.code, refused.retry_after),
            ("analysis_busy", Some(1))
        );
        assert_eq!(analyses.blocking(|| Ok(3)).await.unwrap(), 3);
    }
}
