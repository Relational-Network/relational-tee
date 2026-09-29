// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Datasets and their records.
//!
//! - Blob `datasets/{pool_pda}/{record_id}.csv.enc`: the uploaded CSV,
//!   create-only. Its data key lives only in the record's row (the envelope
//!   names it with `dek_ref`), so deleting the key from the row erases the
//!   blob even while it's immutable.
//! - Table `records`, partition `{pool_pda}`: `rec:{record_id}` holds the
//!   record, its status and the wrapped data key; once committed, a log row
//!   `log:{inverted_ts}:{record_id}` holds the record without the key,
//!   newest first.
//!
//! A record is staged first (its row claims the record ID, then the blob is
//! written) and committed later, in one atomic batch that updates the row
//! and adds the log row. The issuance log and the pool's totals only ever
//! see committed records.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::warn;

use super::store::{
    BatchOp, Container, Continuation, ETag, Entity, InsertOutcome, Page, Prop, PutOutcome, RkRange,
    StoreError, Table,
};
use super::{inverted_millis, Storage};

const PAYLOAD_VERSION: u32 = 1;
const LOG_PREFIX: &str = "log:";
/// How long cached totals are trusted without a newer log row. Another
/// worker's commit can land behind the newest log row (its clock may lag),
/// so the newest row alone can't reveal every change.
const TOTALS_TTL: Duration = Duration::from_secs(10);

/// Whether a record's side effects are complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordStatus {
    /// The dataset is stored, but the record isn't final yet.
    Staged,
    Committed,
}

impl RecordStatus {
    fn as_str(self) -> &'static str {
        match self {
            RecordStatus::Staged => "staged",
            RecordStatus::Committed => "committed",
        }
    }
}

/// A record: one uploaded dataset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordMeta {
    /// `initial` for the initialisation upload, a UUID for issuances.
    pub record_id: String,
    /// SHA-256 of the CSV bytes, hex.
    pub sha256: String,
    /// CSV rows, excluding the header.
    pub rows: u64,
    pub uploaded_by: String,
    pub uploaded_at: DateTime<Utc>,
    pub status: RecordStatus,
    /// The append-DRT burn, for issuances.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redeem_tx_signature: Option<String>,
    /// The grant commitment of that burn, hex.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commitment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub committed_at: Option<DateTime<Utc>>,
}

/// The payload of a `rec:` row.
#[derive(Serialize, Deserialize)]
struct RecRow {
    #[serde(flatten)]
    meta: RecordMeta,
    /// The dataset's wrapped data key, base64url. Removing it erases the dataset.
    #[serde(skip_serializing_if = "Option::is_none")]
    wrapped_dek: Option<String>,
}

/// A staged record, ready to commit or discard.
pub struct Staged {
    pub meta: RecordMeta,
    wrapped_dek: String,
    etag: ETag,
}

/// The outcome of [`Records::stage`].
pub enum StageOutcome {
    Staged(Staged),
    /// A record with this ID already exists.
    Exists(RecordMeta),
}

/// Per-worker cache of a pool's committed totals. An entry is used while
/// the pool's newest log row is unchanged, for at most [`TOTALS_TTL`], and
/// this worker's own commits drop it.
#[derive(Default)]
pub(crate) struct TotalsCache {
    entries: Mutex<HashMap<String, CachedTotals>>,
}

#[derive(Clone)]
struct CachedTotals {
    newest: Option<(String, Option<ETag>)>,
    totals: RecordTotals,
    cached_at: Instant,
}

impl TotalsCache {
    fn forget(&self, pool_pda: &str) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.remove(pool_pda);
        }
    }
}

/// Totals over a pool's committed records.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RecordTotals {
    /// CSV rows across every committed upload, initialisation included.
    pub rows: u64,
    /// When the newest committed issuance (not the initialisation) committed.
    pub last_issue_at: Option<DateTime<Utc>>,
}

/// Dataset and record storage.
pub struct Records<'a> {
    s: &'a Storage,
}

fn rec_rk(record_id: &str) -> String {
    format!("rec:{record_id}")
}

fn dataset_path(pool_pda: &str, record_id: &str) -> String {
    format!("{pool_pda}/{record_id}.csv.enc")
}

impl<'a> Records<'a> {
    pub(crate) fn new(s: &'a Storage) -> Self {
        Self { s }
    }

    fn rec_row(&self, pool_pda: &str, row: &RecRow) -> Result<Entity, StoreError> {
        Ok(self
            .s
            .sealed_row(
                Table::Records,
                pool_pda,
                &rec_rk(&row.meta.record_id),
                PAYLOAD_VERSION,
                row,
            )?
            .with("status", Prop::Str(row.meta.status.as_str().into()))
            .with("created_at", Prop::Str(row.meta.uploaded_at.to_rfc3339())))
    }

    /// Stage a dataset: insert the staged row, which claims the record ID,
    /// then write the dataset create-only.
    pub async fn stage(
        &self,
        pool_pda: &str,
        mut meta: RecordMeta,
        csv: &[u8],
    ) -> Result<StageOutcome, StoreError> {
        meta.status = RecordStatus::Staged;
        let path = dataset_path(pool_pda, &meta.record_id);
        let dek_ref = format!(
            "{}/{pool_pda}/{}",
            Table::Records.name(),
            rec_rk(&meta.record_id)
        );
        let (sealed, wrapped) =
            self.s
                .keys()
                .seal_detached(Container::Datasets, &path, &dek_ref, csv);
        let row = RecRow {
            meta,
            wrapped_dek: Some(URL_SAFE_NO_PAD.encode(wrapped)),
        };
        let etag = match self
            .s
            .index()
            .insert(Table::Records, self.rec_row(pool_pda, &row)?)
            .await?
        {
            InsertOutcome::Inserted(etag) => etag,
            InsertOutcome::Conflict => {
                let existing = self
                    .get(pool_pda, &row.meta.record_id)
                    .await?
                    .ok_or(StoreError::PreconditionFailed)?;
                return Ok(StageOutcome::Exists(existing));
            }
        };

        let body = Bytes::from(sealed);
        if self
            .s
            .objects()
            .put_if_absent(Container::Datasets, &path, body.clone())
            .await?
            == PutOutcome::AlreadyExists
        {
            // Left by an attempt whose row is gone; this row owns the ID now.
            self.s.objects().delete(Container::Datasets, &path).await?;
            if self
                .s
                .objects()
                .put_if_absent(Container::Datasets, &path, body)
                .await?
                == PutOutcome::AlreadyExists
            {
                return Err(StoreError::Conflict);
            }
        }
        Ok(StageOutcome::Staged(Staged {
            meta: row.meta,
            wrapped_dek: row.wrapped_dek.unwrap_or_default(),
            etag,
        }))
    }

    /// Commit a staged record: in one batch, mark its row committed and add
    /// its log row. Then make the dataset immutable until `retain_until`.
    pub async fn commit(
        &self,
        pool_pda: &str,
        staged: Staged,
        redeem_tx_signature: Option<String>,
        commitment: Option<String>,
        retain_until: DateTime<Utc>,
    ) -> Result<RecordMeta, StoreError> {
        let now = Utc::now();
        let mut meta = staged.meta;
        meta.status = RecordStatus::Committed;
        meta.redeem_tx_signature = redeem_tx_signature;
        meta.commitment = commitment;
        meta.committed_at = Some(now);

        let rec = self.rec_row(
            pool_pda,
            &RecRow {
                meta: meta.clone(),
                wrapped_dek: Some(staged.wrapped_dek),
            },
        )?;
        let log_rk = format!("{LOG_PREFIX}{}:{}", inverted_millis(now), meta.record_id);
        let log = self
            .s
            .sealed_row(Table::Records, pool_pda, &log_rk, PAYLOAD_VERSION, &meta)?
            .with("status", Prop::Str(meta.status.as_str().into()))
            .with("created_at", Prop::Str(meta.uploaded_at.to_rfc3339()));
        self.s
            .index()
            .batch(
                Table::Records,
                pool_pda,
                vec![
                    BatchOp::UpdateIfMatch(rec, staged.etag),
                    BatchOp::Insert(log),
                ],
            )
            .await?;
        self.s.totals_cache().forget(pool_pda);

        let path = dataset_path(pool_pda, &meta.record_id);
        if let Err(e) = self
            .s
            .objects()
            .set_immutability(Container::Datasets, &path, retain_until)
            .await
        {
            warn!(pool = %pool_pda, record_id = %meta.record_id, error = %e,
                "Couldn't set the dataset's immutability policy");
        }
        Ok(meta)
    }

    /// Remove a staged record that won't commit: its dataset, then its row.
    pub async fn discard(&self, pool_pda: &str, staged: &Staged) -> Result<(), StoreError> {
        let path = dataset_path(pool_pda, &staged.meta.record_id);
        self.s.objects().delete(Container::Datasets, &path).await?;
        match self
            .s
            .index()
            .delete_if_match(
                Table::Records,
                pool_pda,
                &rec_rk(&staged.meta.record_id),
                &staged.etag,
            )
            .await
        {
            Ok(()) | Err(StoreError::NotFound) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Discard a staged record found by ID, whoever staged it.
    pub async fn discard_abandoned(
        &self,
        pool_pda: &str,
        record_id: &str,
    ) -> Result<(), StoreError> {
        let Some(entity) = self
            .s
            .index()
            .get(Table::Records, pool_pda, &rec_rk(record_id))
            .await?
        else {
            return Ok(());
        };
        let row: RecRow = self.s.open_row(Table::Records, PAYLOAD_VERSION, &entity)?;
        if row.meta.status != RecordStatus::Staged {
            return Err(StoreError::Conflict);
        }
        let staged = Staged {
            meta: row.meta,
            wrapped_dek: row.wrapped_dek.unwrap_or_default(),
            etag: entity.etag.clone().ok_or(StoreError::PreconditionFailed)?,
        };
        self.discard(pool_pda, &staged).await
    }

    /// The record, staged or committed.
    pub async fn get(
        &self,
        pool_pda: &str,
        record_id: &str,
    ) -> Result<Option<RecordMeta>, StoreError> {
        Ok(self
            .s
            .get_sealed::<RecRow>(
                Table::Records,
                pool_pda,
                &rec_rk(record_id),
                PAYLOAD_VERSION,
            )
            .await?
            .map(|(row, _)| row.meta))
    }

    /// One page of the pool's committed records, newest first.
    pub async fn log(
        &self,
        pool_pda: &str,
        limit: usize,
        page: Option<Continuation>,
    ) -> Result<Page<RecordMeta>, StoreError> {
        let rows = self
            .s
            .query_rows(
                Table::Records,
                pool_pda,
                RkRange::prefix(LOG_PREFIX),
                None,
                limit,
                page,
            )
            .await?;
        Ok(Page {
            items: rows
                .items
                .iter()
                .map(|e| self.s.open_row(Table::Records, PAYLOAD_VERSION, e))
                .collect::<Result<_, _>>()?,
            next: rows.next,
        })
    }

    /// Totals over the pool's committed records, from this worker's cache
    /// while that's still valid (see [`TotalsCache`]).
    pub async fn totals(&self, pool_pda: &str) -> Result<RecordTotals, StoreError> {
        let newest = self
            .s
            .index()
            .query(
                Table::Records,
                pool_pda,
                RkRange::prefix(LOG_PREFIX),
                None,
                1,
                None,
            )
            .await?
            .items
            .into_iter()
            .next()
            .map(|e| (e.rk, e.etag));
        let cache = &self.s.totals_cache().entries;
        if let Some(hit) = cache.lock().ok().and_then(|c| c.get(pool_pda).cloned()) {
            if hit.newest == newest && hit.cached_at.elapsed() < TOTALS_TTL {
                return Ok(hit.totals);
            }
        }

        let mut totals = RecordTotals::default();
        for row in self
            .s
            .query_all(Table::Records, pool_pda, RkRange::prefix(LOG_PREFIX), None)
            .await?
        {
            let meta: RecordMeta = self.s.open_row(Table::Records, PAYLOAD_VERSION, &row)?;
            totals.rows += meta.rows;
            if meta.record_id != "initial" {
                totals.last_issue_at = totals.last_issue_at.max(meta.committed_at);
            }
        }
        if let Ok(mut cache) = cache.lock() {
            cache.insert(
                pool_pda.to_string(),
                CachedTotals {
                    newest,
                    totals,
                    cached_at: Instant::now(),
                },
            );
        }
        Ok(totals)
    }

    /// Read a committed or staged dataset back.
    #[cfg(test)]
    pub async fn read_dataset(
        &self,
        pool_pda: &str,
        record_id: &str,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, StoreError> {
        let (row, _) = self
            .s
            .get_sealed::<RecRow>(
                Table::Records,
                pool_pda,
                &rec_rk(record_id),
                PAYLOAD_VERSION,
            )
            .await?
            .ok_or(StoreError::NotFound)?;
        let wrapped = row
            .wrapped_dek
            .as_deref()
            .and_then(|w| URL_SAFE_NO_PAD.decode(w).ok())
            .ok_or_else(|| StoreError::Integrity("the dataset's data key is gone".into()))?;
        let path = dataset_path(pool_pda, record_id);
        let object = self
            .s
            .objects()
            .get(Container::Datasets, &path)
            .await?
            .ok_or(StoreError::NotFound)?;
        self.s
            .keys()
            .open_detached(Container::Datasets, &path, &object.body, &wrapped)
    }

    /// Erase a dataset by deleting its data key from the record's row.
    #[cfg(test)]
    pub async fn shred(&self, pool_pda: &str, record_id: &str) -> Result<(), StoreError> {
        let (mut row, etag) = self
            .s
            .get_sealed::<RecRow>(
                Table::Records,
                pool_pda,
                &rec_rk(record_id),
                PAYLOAD_VERSION,
            )
            .await?
            .ok_or(StoreError::NotFound)?;
        row.wrapped_dek = None;
        self.s
            .index()
            .update_if_match(Table::Records, self.rec_row(pool_pda, &row)?, &etag)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::tests::{memory_storage, two_workers};

    fn record(id: &str, rows: u64) -> RecordMeta {
        RecordMeta {
            record_id: id.into(),
            sha256: "00".repeat(32),
            rows,
            uploaded_by: "alice".into(),
            uploaded_at: Utc::now(),
            status: RecordStatus::Staged,
            redeem_tx_signature: None,
            commitment: None,
            committed_at: None,
        }
    }

    fn retain() -> DateTime<Utc> {
        Utc::now() + chrono::Duration::days(7)
    }

    async fn stage(records: &Records<'_>, id: &str, rows: u64) -> Staged {
        match records
            .stage("P1", record(id, rows), b"id\n1\n")
            .await
            .unwrap()
        {
            StageOutcome::Staged(s) => s,
            StageOutcome::Exists(_) => panic!("{id} is new"),
        }
    }

    #[tokio::test]
    async fn only_committed_records_count_or_appear_in_the_log() {
        let (a, b) = two_workers();
        let records = a.records();
        let initial = stage(&records, "initial", 3).await;
        records
            .commit("P1", initial, None, None, retain())
            .await
            .unwrap();
        let _staged_only = stage(&records, "r-staged", 100).await;
        assert_eq!(b.records().totals("P1").await.unwrap().rows, 3);

        // Log rows are ordered by commit time, in milliseconds.
        tokio::time::sleep(Duration::from_millis(3)).await;
        let issued = stage(&records, "r1", 2).await;
        let committed = records
            .commit(
                "P1",
                issued,
                Some("sig".into()),
                Some("ab".into()),
                retain(),
            )
            .await
            .unwrap();
        // The other worker's cached totals see the new log row.
        let totals = b.records().totals("P1").await.unwrap();
        assert_eq!(totals.rows, 5);
        assert_eq!(totals.last_issue_at, committed.committed_at);

        let log = b.records().log("P1", 10, None).await.unwrap();
        let ids: Vec<_> = log.items.iter().map(|r| r.record_id.as_str()).collect();
        assert_eq!(ids, ["r1", "initial"]);
        assert_eq!(
            b.records()
                .get("P1", "r-staged")
                .await
                .unwrap()
                .unwrap()
                .status,
            RecordStatus::Staged
        );
    }

    #[tokio::test]
    async fn a_workers_own_commit_refreshes_its_totals_even_behind_the_newest_row() {
        let s = memory_storage();
        let first = stage(&s.records(), "r1", 1).await;
        s.records()
            .commit("P1", first, None, None, retain())
            .await
            .unwrap();
        assert_eq!(s.records().totals("P1").await.unwrap().rows, 1);

        // A log row with a later timestamp than any commit to come, as a
        // worker with a fast clock would write.
        let meta = record("r-future", 10);
        let future = Utc::now() + chrono::Duration::hours(1);
        let row = s
            .sealed_row(
                Table::Records,
                "P1",
                &format!("{LOG_PREFIX}{}:r-future", inverted_millis(future)),
                PAYLOAD_VERSION,
                &RecordMeta {
                    status: RecordStatus::Committed,
                    ..meta
                },
            )
            .unwrap();
        s.index().insert(Table::Records, row).await.unwrap();
        assert_eq!(s.records().totals("P1").await.unwrap().rows, 11);

        // This commit's log row sorts behind the future one.
        let second = stage(&s.records(), "r2", 2).await;
        s.records()
            .commit("P1", second, None, None, retain())
            .await
            .unwrap();
        assert_eq!(s.records().totals("P1").await.unwrap().rows, 13);
    }

    #[tokio::test]
    async fn a_record_id_is_staged_once() {
        let s = memory_storage();
        let first = stage(&s.records(), "initial", 1).await;
        assert!(matches!(
            s.records().stage("P1", record("initial", 9), b"x").await.unwrap(),
            StageOutcome::Exists(meta) if meta.rows == 1
        ));
        s.records().discard("P1", &first).await.unwrap();
        assert!(s.records().get("P1", "initial").await.unwrap().is_none());
        assert!(matches!(
            s.records().read_dataset("P1", "initial").await,
            Err(StoreError::NotFound)
        ));
        // With the row gone the ID can be staged again.
        stage(&s.records(), "initial", 4).await;
    }

    #[tokio::test]
    async fn deleting_the_data_key_erases_an_immutable_dataset() {
        let s = memory_storage();
        let staged = stage(&s.records(), "r1", 1).await;
        s.records()
            .commit("P1", staged, None, None, retain())
            .await
            .unwrap();
        assert_eq!(
            s.records()
                .read_dataset("P1", "r1")
                .await
                .unwrap()
                .as_slice(),
            b"id\n1\n"
        );

        // The blob is immutable, so it stays; without its key it's unreadable.
        assert!(matches!(
            s.objects()
                .delete(Container::Datasets, "P1/r1.csv.enc")
                .await,
            Err(StoreError::Conflict)
        ));
        s.records().shred("P1", "r1").await.unwrap();
        assert!(matches!(
            s.records().read_dataset("P1", "r1").await,
            Err(StoreError::Integrity(_))
        ));
    }

    #[tokio::test]
    async fn swapped_datasets_fail_their_integrity_check() {
        let store = std::sync::Arc::new(crate::storage::memory::MemoryStore::new());
        let s = Storage::new(
            store.clone(),
            store.clone(),
            crate::storage::StorageKeys::derive(&crate::tee::tests::fixed_key(1)),
            "w".into(),
        );
        for id in ["r1", "r2"] {
            let staged = stage(&s.records(), id, 1).await;
            s.records()
                .commit("P1", staged, None, None, retain())
                .await
                .unwrap();
        }
        let one = s
            .objects()
            .get(Container::Datasets, "P1/r1.csv.enc")
            .await
            .unwrap()
            .unwrap();
        let two = s
            .objects()
            .get(Container::Datasets, "P1/r2.csv.enc")
            .await
            .unwrap()
            .unwrap();
        store.tamper_blob(Container::Datasets, "P1/r1.csv.enc", |b| {
            *b = two.body.to_vec()
        });
        store.tamper_blob(Container::Datasets, "P1/r2.csv.enc", |b| {
            *b = one.body.to_vec()
        });
        for id in ["r1", "r2"] {
            assert!(matches!(
                s.records().read_dataset("P1", id).await,
                Err(StoreError::Integrity(_))
            ));
        }
    }
}
