// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Running analyses on a worker. Definitions are cached by hash, decrypted
//! datasets by upload, scoped tables by pool version and scope, and the
//! counts of scope values by pool version, each loaded once and kept within
//! a memory budget, so a warm query reads no dataset and a new upload loads
//! only its own. Datasets and tables also reserve their memory from the
//! worker's budget before they load, and hold it while anything uses them.
//! SQLite and counting work runs on blocking threads, about one per CPU at a
//! time, and stops at its deadline or once no request waits for it. Work on
//! a table waits for the table's earlier work before it takes a thread, so
//! a busy table can't hold every thread. Exports run at most half as many
//! at a time as there are threads, and each reserves the memory its file
//! may need before it writes it.

use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use lru::LruCache;
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;
use tracing::info;
use zeroize::Zeroizing;

use super::cache::{Cache, Weigh};
use super::definition::Definition;
use super::export::{self, Format, Limits};
use super::query::Query;
use super::table::{Scope, ScopeCounts, Table, TableError};
use crate::budget::{Budget, Reservation};
use crate::config::MAX_BODY_SIZE;
use crate::error::ApiError;
use crate::storage::pools::{PoolDoc, Upload};
use crate::storage::{Storage, StoreError};
use crate::work::{Cancelled, Stop, Threads, QUEUE_WAIT};

/// Memory for decrypted datasets.
const DATASET_BUDGET: usize = 512 << 20;
/// Memory for scoped tables.
const TABLE_BUDGET: usize = 1 << 30;
/// Memory for counts of scope values.
const COUNTS_BUDGET: usize = 64 << 20;
/// The most values each cache keeps, however small.
const MAX_ENTRIES: usize = 1024;
/// The most parsed definitions kept.
const MAX_DEFINITIONS: NonZeroUsize = NonZeroUsize::new(256).expect("not zero");
/// How long a load waits for memory before it gets 503.
const MEMORY_WAIT: Duration = Duration::from_secs(5);
/// What building a table reserves per byte of its datasets' CSV, before it
/// knows the table's size: SQLite's pages and indexes, and the parsed rows.
const TABLE_BYTES_PER_CSV_BYTE: usize = 4;
/// How long building a table or counting scope values may take: well inside
/// the request time limit.
const BUILD_TIME: Duration = Duration::from_secs(30);

/// How long one statement may run: well inside the request time limit.
pub const DEADLINE: Duration = Duration::from_secs(10);
/// How long an export waits for a slot before it gets 503.
const EXPORT_WAIT: Duration = Duration::from_secs(5);

struct Dataset {
    csv: Zeroizing<Vec<u8>>,
    _held: Reservation,
}

impl Weigh for Dataset {
    fn bytes(&self) -> usize {
        self.csv.len()
    }
}

impl Weigh for Table {
    fn bytes(&self) -> usize {
        self.bytes
    }
}

impl Weigh for ScopeCounts {
    fn bytes(&self) -> usize {
        self.combinations
            .iter()
            .map(|c| {
                32 + c
                    .values
                    .iter()
                    .map(|v| 24 + v.as_ref().map_or(0, String::len))
                    .sum::<usize>()
            })
            .sum()
    }
}

/// A pool version: the uploads that count, read with this definition.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Version {
    pool_pda: String,
    definition: [u8; 32],
    uploads: Vec<String>,
}

/// What a table holds: the rows of a pool version that this scope allows.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TableKey {
    version: Version,
    scope: Scope,
}

/// `doc`'s uploads that count (revoked ones don't), and the pool version
/// they make with `definition`.
fn version<'a>(doc: &'a PoolDoc, definition: &Definition) -> (Version, Vec<&'a Upload>) {
    let uploads: Vec<&Upload> = doc
        .uploads()
        .filter(|u| !doc.is_revoked(&u.record_id))
        .collect();
    let version = Version {
        pool_pda: doc.pool_pda.clone(),
        definition: definition.sha256,
        uploads: uploads.iter().map(|u| u.upload_id.clone()).collect(),
    };
    (version, uploads)
}

pub struct Analyses {
    definitions: Mutex<LruCache<String, Arc<Definition>>>,
    datasets: Cache<(String, String), Dataset>,
    tables: Cache<TableKey, Table>,
    counts: Cache<Version, ScopeCounts>,
    threads: Threads,
    memory: Arc<Budget>,
    exports: Exports,
}

/// What exports may hold, and how many run at once.
struct Exports {
    limits: Limits,
    slots: Arc<Semaphore>,
    /// How long an export waits for a slot.
    wait: Duration,
}

/// An export's file and how many rows it holds. The file holds its share
/// of the worker's memory until the last of its bytes is dropped, wherever
/// they are by then, such as in a connection's buffers.
pub struct Exported {
    pub file: Bytes,
    pub rows: u64,
}

/// A file with the reservation that counts its allocation.
struct HeldFile {
    file: Vec<u8>,
    _held: Reservation,
}

impl AsRef<[u8]> for HeldFile {
    fn as_ref(&self) -> &[u8] {
        &self.file
    }
}

impl Default for Analyses {
    fn default() -> Self {
        Self::new(Arc::new(Budget::default()))
    }
}

fn busy() -> ApiError {
    let mut e =
        ApiError::service_unavailable("the worker is busy with other analyses; retry shortly")
            .with_code("analysis_busy");
    e.retry_after = Some(1);
    e
}

/// A table build's or count's error, as the API reports it.
fn build_error(what: &str, e: TableError) -> ApiError {
    match e {
        TableError::Stopped => {
            ApiError::unprocessable(format!("{what} ran out of time; try again shortly"))
                .with_code("analysis_timeout")
        }
        e => ApiError::internal(format!("{what} failed: {e}")),
    }
}

impl Analyses {
    /// Analyses whose datasets and tables reserve their memory from `memory`,
    /// with a thread per CPU.
    pub fn new(memory: Arc<Budget>) -> Self {
        Self::with_threads(memory, Threads::default())
    }

    /// [`Self::new`], with CPU-heavy work on `threads`, and half as many
    /// exports at a time.
    pub fn with_threads(memory: Arc<Budget>, threads: Threads) -> Self {
        let slots = (threads.count() / 2).max(1);
        Self {
            definitions: Mutex::new(LruCache::new(MAX_DEFINITIONS)),
            datasets: Cache::new(DATASET_BUDGET, MAX_ENTRIES),
            tables: Cache::new(TABLE_BUDGET, MAX_ENTRIES),
            counts: Cache::new(COUNTS_BUDGET, MAX_ENTRIES),
            threads,
            memory,
            exports: Exports {
                limits: Limits::default(),
                slots: Arc::new(Semaphore::new(slots)),
                wait: EXPORT_WAIT,
            },
        }
    }

    /// These analyses, with exports held to `limits` and waiting `wait` for
    /// a slot.
    #[cfg(test)]
    pub fn with_exports(mut self, limits: Limits, wait: Duration) -> Self {
        self.exports.limits = limits;
        self.exports.wait = wait;
        self
    }

    /// The slots exports take, one each while they run.
    #[cfg(test)]
    pub fn export_slots(&self) -> &Arc<Semaphore> {
        &self.exports.slots
    }

    /// The worker's memory budget, which uploads reserve from too.
    pub fn memory(&self) -> &Arc<Budget> {
        &self.memory
    }

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
            .put(sha256.to_string(), definition.clone());
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
        let (version, uploads) = version(doc, definition);
        let key = TableKey {
            version,
            scope: scope.clone(),
        };
        self.tables
            .get_or_load(key, || async {
                let datasets = self.datasets(storage, &doc.pool_pda, &uploads).await?;
                let csv_bytes: usize = datasets.iter().map(|d| d.csv.len()).sum();
                let mut held = self
                    .memory
                    .reserve(
                        csv_bytes.saturating_mul(TABLE_BYTES_PER_CSV_BYTE),
                        MEMORY_WAIT,
                    )
                    .await?;
                let (definition, scope) = (definition.clone(), scope.clone());
                let pool_pda = doc.pool_pda.clone();
                let mut table = self
                    .threads
                    .run(Stop::after(BUILD_TIME), move |stop| {
                        let csvs: Vec<&[u8]> = datasets.iter().map(|d| d.csv.as_slice()).collect();
                        let table = Table::build(&definition, &csvs, &scope, stop)
                            .map_err(|e| build_error("building the analysis table", e))?;
                        info!(pool = %pool_pda, rows = table.rows, bytes = table.bytes,
                            "Built an analysis table");
                        Ok(table)
                    })
                    .await?;
                held.resize(&self.memory, table.bytes, MEMORY_WAIT).await?;
                table.hold(held);
                Ok(table)
            })
            .await
    }

    /// How many rows of `doc`'s uploads hold each combination of
    /// `definition`'s scope values. Revoked uploads' rows are left out, as
    /// tables leave them out.
    pub async fn scope_counts(
        &self,
        storage: &Storage,
        doc: &PoolDoc,
        definition: &Arc<Definition>,
    ) -> Result<Arc<ScopeCounts>, ApiError> {
        let (version, uploads) = version(doc, definition);
        self.counts
            .get_or_load(version, || async {
                let datasets = self.datasets(storage, &doc.pool_pda, &uploads).await?;
                let definition = definition.clone();
                self.threads
                    .run(Stop::after(BUILD_TIME), move |stop| {
                        let csvs: Vec<&[u8]> = datasets.iter().map(|d| d.csv.as_slice()).collect();
                        ScopeCounts::count(&definition, &csvs, stop)
                            .map_err(|e| build_error("counting the pool's scope values", e))
                    })
                    .await
            })
            .await
    }

    async fn datasets(
        &self,
        storage: &Storage,
        pool_pda: &str,
        uploads: &[&Upload],
    ) -> Result<Vec<Arc<Dataset>>, ApiError> {
        let mut datasets = Vec::with_capacity(uploads.len());
        for upload in uploads {
            datasets.push(self.dataset(storage, pool_pda, upload).await?);
        }
        Ok(datasets)
    }

    /// The decrypted CSV of `upload`, cached by pool and upload, and checked
    /// against its digest. Loading it reserves memory for the sealed and the
    /// decrypted copy, by the upload's recorded size or, without one, the
    /// largest an upload can be.
    async fn dataset(
        &self,
        storage: &Storage,
        pool_pda: &str,
        upload: &Upload,
    ) -> Result<Arc<Dataset>, ApiError> {
        let key = (pool_pda.to_string(), upload.upload_id.clone());
        self.datasets
            .get_or_load(key, || async {
                // The sealed copy and the decrypted one, while both live.
                let size = upload
                    .bytes
                    .and_then(|b| usize::try_from(b).ok())
                    .unwrap_or(MAX_BODY_SIZE);
                let mut held = self
                    .memory
                    .reserve(size.saturating_mul(2), MEMORY_WAIT)
                    .await?;
                let csv = storage
                    .pools()
                    .read_dataset(pool_pda, &upload.upload_id)
                    .await?
                    .ok_or_else(|| {
                        ApiError::internal(format!("upload {} has no dataset", upload.record_id))
                    })?;
                let digest =
                    crate::work::cpu_for(csv.len(), || hex::encode(Sha256::digest(csv.as_slice())));
                if digest != upload.sha256 {
                    return Err(StoreError::Integrity(format!(
                        "upload {}'s dataset doesn't match its digest",
                        upload.record_id
                    ))
                    .into());
                }
                held.resize(&self.memory, csv.len(), MEMORY_WAIT).await?;
                Ok(Dataset { csv, _held: held })
            })
            .await
    }

    /// Run `work` on `table` once the table's earlier work is done and a
    /// thread is free, waiting up to a second for each, or 503. `work`
    /// stops after [`DEADLINE`], or once this future is dropped.
    pub async fn on_table<T: Send + 'static>(
        &self,
        table: Arc<Table>,
        work: impl FnOnce(&Table, &Stop) -> Result<T, ApiError> + Send + 'static,
    ) -> Result<T, ApiError> {
        self.on_table_for(table, DEADLINE, None, work).await
    }

    /// [`Self::on_table`], with `work` stopping after `time`, and once
    /// `cancelled` is set when there is one.
    async fn on_table_for<T: Send + 'static>(
        &self,
        table: Arc<Table>,
        time: Duration,
        cancelled: Option<&Cancelled>,
        work: impl FnOnce(&Table, &Stop) -> Result<T, ApiError> + Send + 'static,
    ) -> Result<T, ApiError> {
        let turn = tokio::time::timeout(QUEUE_WAIT, table.turn())
            .await
            .map_err(|_| busy())?
            .ok_or_else(|| ApiError::internal("the table's queue is closed"))?;
        let stop = match cancelled {
            Some(cancelled) => Stop::after(time).linked(cancelled),
            None => Stop::after(time),
        };
        self.threads
            .run(stop, move |stop| {
                let _turn = turn;
                work(&table, stop)
            })
            .await
    }

    /// The file of `format` holding every row of `table` that `query`
    /// matches, in its sort. An export waits up to a few seconds for one of
    /// the export slots (`503 analysis_busy`), then counts the rows, refusing
    /// more than its limit allows; reserves twice the largest file it may
    /// make, which the file's own allocation replaces once it's written; and
    /// writes the file, a row at a time, under the table's turn. Counting
    /// and writing each stop at the export's deadline, and once `cancelled`
    /// is set.
    pub async fn export(
        &self,
        table: Arc<Table>,
        definition: Arc<Definition>,
        query: Query,
        format: Format,
        cancelled: &Cancelled,
    ) -> Result<Exported, ApiError> {
        let limits = self.exports.limits;
        let _slot = tokio::time::timeout(
            self.exports.wait,
            self.exports.slots.clone().acquire_owned(),
        )
        .await
        .map_err(|_| busy())?
        .map_err(|_| ApiError::internal("the export slots are closed"))?;
        let query = Arc::new(query);
        let (def, asked) = (definition.clone(), query.clone());
        self.on_table_for(
            table.clone(),
            limits.deadline,
            Some(cancelled),
            move |table, stop| Ok(export::count(table, &def, &asked, limits, stop)?),
        )
        .await?;
        let mut held = self
            .memory
            .reserve(limits.max_bytes.saturating_mul(2), MEMORY_WAIT)
            .await?;
        let (file, rows) = self
            .on_table_for(
                table,
                limits.deadline,
                Some(cancelled),
                move |table, stop| {
                    Ok(export::write(
                        table,
                        &definition,
                        &query,
                        format,
                        limits,
                        stop,
                    )?)
                },
            )
            .await?;
        // The writer's buffer grows by doubling, so the file's allocation can
        // be up to twice its length, and shrinking it may leave the memory
        // where it is.
        held.resize(&self.memory, file.capacity(), MEMORY_WAIT)
            .await?;
        Ok(Exported {
            file: Bytes::from_owner(HeldFile { file, _held: held }),
            rows,
        })
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
            bytes: Some(csv.len() as u64),
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

        // Scope counts read the cached datasets and leave the revoked
        // upload out, as tables do, once.
        let counts = analyses
            .scope_counts(&storage, &doc, &definition)
            .await
            .unwrap();
        assert_eq!((counts.rows(), reads()), (2, 2));
        let again = analyses
            .scope_counts(&storage, &doc, &definition)
            .await
            .unwrap();
        assert!(Arc::ptr_eq(&again, &counts));
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
    async fn loads_hold_the_workers_memory_and_what_cant_fit_is_refused() {
        let storage = Storage::new(
            Arc::new(LocalFiles::temporary()),
            StorageKeys::derive(&fixed_key(1)),
            "worker-a".into(),
        );
        let hash = storage
            .scripts()
            .put(AWARDS_REPORT.as_bytes())
            .await
            .unwrap();
        let memory = Arc::new(Budget::new(8 << 20));
        let analyses = Analyses::new(memory.clone());
        let definition = analyses.definition(&storage, &hash).await.unwrap();
        let mut doc = pool("P1", "w1");
        doc.initial = Some(upload(&storage, INITIAL, &[("Bank A", "Group A")]).await);

        let table = analyses
            .table(&storage, &doc, &definition, &Scope::All)
            .await
            .unwrap();
        let held = memory.bytes() - memory.available();
        assert!(held > table.bytes, "the dataset and the table: {held}");

        // An upload larger than the whole budget is refused, holding nothing
        // and leaving nothing cached.
        let mut big = upload(&storage, "r-2", &[("Bank A", "Group A")]).await;
        big.bytes = Some(1 << 30);
        doc.issuances.push(big);
        let refused = analyses
            .table(&storage, &doc, &definition, &Scope::All)
            .await
            .err()
            .unwrap();
        assert_eq!(refused.code, "too_large_for_memory");
        assert_eq!(memory.bytes() - memory.available(), held);
        let ((_, datasets), (_, tables)) = analyses.usage();
        assert_eq!((datasets, tables), (1, 1));
    }

    #[tokio::test]
    async fn a_busy_table_queues_its_own_work_and_leaves_threads_for_others() {
        let storage = Storage::new(
            Arc::new(LocalFiles::temporary()),
            StorageKeys::derive(&fixed_key(1)),
            "worker-a".into(),
        );
        let hash = storage
            .scripts()
            .put(AWARDS_REPORT.as_bytes())
            .await
            .unwrap();
        let analyses = Analyses::with_threads(Arc::new(Budget::default()), Threads::new(2));
        let definition = analyses.definition(&storage, &hash).await.unwrap();
        let mut doc = pool("P1", "w1");
        doc.initial = Some(
            upload(
                &storage,
                INITIAL,
                &[("Bank A", "Group A"), ("Bank C", "Group C")],
            )
            .await,
        );
        let busy = analyses
            .table(&storage, &doc, &definition, &Scope::All)
            .await
            .unwrap();
        let other = analyses
            .table(
                &storage,
                &doc,
                &definition,
                &only(&[&[("employer_group", "Group A")]]),
            )
            .await
            .unwrap();

        // A slow request holds the busy table, and five more queue for it.
        let release = Arc::new(std::sync::Barrier::new(2));
        let (started, running) = tokio::sync::oneshot::channel();
        let slow = {
            let release = release.clone();
            analyses.on_table(busy.clone(), move |table, _| {
                let _ = started.send(());
                release.wait();
                Ok(table.rows)
            })
        };
        let queued = futures_util::future::join_all(
            (0..5).map(|_| analyses.on_table(busy.clone(), |table, _| Ok(table.rows))),
        );
        let meanwhile = async {
            running.await.unwrap();
            tokio::task::yield_now().await;
            assert_eq!(
                analyses.threads.available(),
                1,
                "queued work holds no thread"
            );
            let rows = analyses
                .on_table(other.clone(), |table, _| Ok(table.rows))
                .await;
            release.wait();
            rows
        };
        let (slow, queued, meanwhile) = tokio::join!(slow, queued, meanwhile);
        assert_eq!(slow.unwrap(), 2);
        assert_eq!(meanwhile.unwrap(), 1, "the other table didn't wait");
        assert!(queued.into_iter().all(|rows| rows.unwrap() == 2));
        assert_eq!(analyses.threads.available(), 2);
    }
}
