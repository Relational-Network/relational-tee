// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Embedded ACID database backed by [`redb`], for pool state.
//!
//! Tables:
//! - `pool_metadata`    — pool_pda → PoolMetadata JSON bytes
//! - `pool_by_owner`    — `{owner_wallet_id}|{pool_pda}` → `""`
//! - `issuance_records` — `{pool_pda}|{!timestamp}|{record_id}` → record JSON
//! - `revocations`      — `{pool_pda}|{credential_id}` → revocation JSON
//! - `nonces`           — nonce → unix timestamp

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use std::path::Path;

// ── Table definitions ──────────────────────────────────────────────

/// Nonce replay protection: nonce_string → unix_timestamp (i64 LE bytes).
const NONCES: TableDefinition<&str, &[u8]> = TableDefinition::new("nonces");
/// Pool metadata: `pool_pda` → PoolMetadata JSON bytes.
const POOL_METADATA: TableDefinition<&str, &[u8]> = TableDefinition::new("pool_metadata");
/// Pool-by-owner index: `{owner_wallet_id}|{pool_pda}` → `""` (key-only index).
const POOL_BY_OWNER: TableDefinition<&str, &str> = TableDefinition::new("pool_by_owner");
/// Issuance records: `{pool_pda}|{!timestamp_be}|{record_id}` → DatasetFileMeta JSON bytes.
const ISSUANCE_RECORDS: TableDefinition<&str, &[u8]> = TableDefinition::new("issuance_records");
/// Revocations: `{pool_pda}|{credential_id}` → RevocationEntry JSON bytes.
const REVOCATIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("revocations");

/// Result alias for tx database operations.
pub type TxDbResult<T> = Result<T, TxDbError>;

/// Transaction database error.
#[derive(Debug)]
pub enum TxDbError {
    Redb(redb::Error),
    Database(redb::DatabaseError),
    TableError(redb::TableError),
    StorageError(redb::StorageError),
    TransactionError(redb::TransactionError),
    CommitError(redb::CommitError),
    Json(serde_json::Error),
}

impl std::fmt::Display for TxDbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Redb(e) => write!(f, "redb: {e}"),
            Self::Database(e) => write!(f, "database: {e}"),
            Self::TableError(e) => write!(f, "table: {e}"),
            Self::StorageError(e) => write!(f, "storage: {e}"),
            Self::TransactionError(e) => write!(f, "transaction: {e}"),
            Self::CommitError(e) => write!(f, "commit: {e}"),
            Self::Json(e) => write!(f, "json: {e}"),
        }
    }
}

impl std::error::Error for TxDbError {}

impl From<redb::Error> for TxDbError {
    fn from(e: redb::Error) -> Self {
        Self::Redb(e)
    }
}
impl From<redb::DatabaseError> for TxDbError {
    fn from(e: redb::DatabaseError) -> Self {
        Self::Database(e)
    }
}
impl From<redb::TableError> for TxDbError {
    fn from(e: redb::TableError) -> Self {
        Self::TableError(e)
    }
}
impl From<redb::StorageError> for TxDbError {
    fn from(e: redb::StorageError) -> Self {
        Self::StorageError(e)
    }
}
impl From<redb::TransactionError> for TxDbError {
    fn from(e: redb::TransactionError) -> Self {
        Self::TransactionError(e)
    }
}
impl From<redb::CommitError> for TxDbError {
    fn from(e: redb::CommitError) -> Self {
        Self::CommitError(e)
    }
}
impl From<serde_json::Error> for TxDbError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

impl From<TxDbError> for crate::error::ApiError {
    fn from(e: TxDbError) -> Self {
        tracing::error!(error = %e, "Transaction database error");
        Self::internal("internal database error")
    }
}

/// Embedded ACID store.
pub struct TxDatabase {
    db: Database,
}

impl TxDatabase {
    /// Open (or create) the redb database at the given path.
    pub fn open(path: &Path) -> TxDbResult<Self> {
        let db = Database::create(path)?;

        // Ensure tables exist.
        let write_txn = db.begin_write()?;
        {
            let _ = write_txn.open_table(NONCES)?;
            let _ = write_txn.open_table(POOL_METADATA)?;
            let _ = write_txn.open_table(POOL_BY_OWNER)?;
            let _ = write_txn.open_table(ISSUANCE_RECORDS)?;
            let _ = write_txn.open_table(REVOCATIONS)?;
        }
        write_txn.commit()?;

        Ok(Self { db })
    }

    /// Start a read transaction.  Used by the readiness probe to verify
    /// the database file is intact and readable.
    pub fn begin_read_txn(&self) -> TxDbResult<()> {
        let _txn = self.db.begin_read()?;
        Ok(())
    }

    // ── Pool metadata & issuance ───────────────────────────────────

    /// Insert or update pool metadata in redb.
    pub fn upsert_pool_meta(&self, meta: &super::pool_metadata::PoolMetadata) -> TxDbResult<()> {
        let json_bytes = serde_json::to_vec(meta)?;
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(POOL_METADATA)?;
            table.insert(meta.pool_pda.as_str(), json_bytes.as_slice())?;

            // Maintain the owner index.
            let mut idx = write_txn.open_table(POOL_BY_OWNER)?;
            let key = format!("{}|{}", meta.owner_wallet_id, meta.pool_pda);
            idx.insert(key.as_str(), "")?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// List all pool metadata entries (full table scan).
    pub fn list_all_pool_metas(&self) -> TxDbResult<Vec<super::pool_metadata::PoolMetadata>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(POOL_METADATA)?;
        let mut result = Vec::new();
        for entry in table.iter()? {
            let (_k, v) = entry?;
            if let Ok(meta) =
                serde_json::from_slice::<super::pool_metadata::PoolMetadata>(v.value())
            {
                result.push(meta);
            }
        }
        Ok(result)
    }

    /// List pools owned by a specific wallet (prefix scan on POOL_BY_OWNER).
    pub fn list_pools_by_owner(
        &self,
        owner_wallet_id: &str,
    ) -> TxDbResult<Vec<super::pool_metadata::PoolMetadata>> {
        let read_txn = self.db.begin_read()?;
        let idx = read_txn.open_table(POOL_BY_OWNER)?;
        let meta_table = read_txn.open_table(POOL_METADATA)?;
        let prefix = format!("{owner_wallet_id}|");
        let mut result = Vec::new();

        let range = idx.range(prefix.as_str()..)?;
        for entry in range {
            let (key_guard, _) = entry?;
            let key_str = key_guard.value();
            if !key_str.starts_with(&prefix) {
                break;
            }
            // Extract pool_pda from key: "owner_wallet_id|pool_pda"
            if let Some(pool_pda) = key_str.strip_prefix(&prefix) {
                if let Some(bytes) = meta_table.get(pool_pda)? {
                    if let Ok(meta) =
                        serde_json::from_slice::<super::pool_metadata::PoolMetadata>(bytes.value())
                    {
                        result.push(meta);
                    }
                }
            }
        }
        Ok(result)
    }

    /// Insert an issuance record for a pool.
    pub fn upsert_issuance_record(
        &self,
        pool_pda: &str,
        record_id: &str,
        timestamp: i64,
        json_bytes: &[u8],
    ) -> TxDbResult<()> {
        let key = make_pool_ts_key(pool_pda, timestamp, record_id);
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(ISSUANCE_RECORDS)?;
            table.insert(key.as_str(), json_bytes)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// List issuance records for a pool with pagination (newest first).
    pub fn list_issuance_records(
        &self,
        pool_pda: &str,
        limit: usize,
        offset: usize,
    ) -> TxDbResult<Vec<serde_json::Value>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(ISSUANCE_RECORDS)?;
        let prefix = format!("{pool_pda}|");
        let mut results = Vec::new();
        let mut skipped = 0usize;

        let range = table.range(prefix.as_str()..)?;
        for entry in range {
            let (key_guard, val_guard) = entry?;
            let key_str = key_guard.value();
            if !key_str.starts_with(&prefix) {
                break;
            }
            if skipped < offset {
                skipped += 1;
                continue;
            }
            if results.len() >= limit {
                break;
            }
            if let Ok(val) = serde_json::from_slice::<serde_json::Value>(val_guard.value()) {
                results.push(val);
            }
        }
        Ok(results)
    }

    /// Count total issuance records for a pool.
    pub fn count_issuance_records(&self, pool_pda: &str) -> TxDbResult<usize> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(ISSUANCE_RECORDS)?;
        let prefix = format!("{pool_pda}|");
        let mut count = 0;
        let range = table.range(prefix.as_str()..)?;
        for entry in range {
            let (key_guard, _) = entry?;
            if !key_guard.value().starts_with(&prefix) {
                break;
            }
            count += 1;
        }
        Ok(count)
    }

    /// Insert a revocation entry for a pool.
    pub fn upsert_revocation(
        &self,
        pool_pda: &str,
        credential_id: &str,
        json_bytes: &[u8],
    ) -> TxDbResult<()> {
        let key = format!("{pool_pda}|{credential_id}");
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(REVOCATIONS)?;
            table.insert(key.as_str(), json_bytes)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// List revocations for a pool with pagination.
    pub fn list_revocations(
        &self,
        pool_pda: &str,
        limit: usize,
        offset: usize,
    ) -> TxDbResult<Vec<serde_json::Value>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(REVOCATIONS)?;
        let prefix = format!("{pool_pda}|");
        let mut results = Vec::new();
        let mut skipped = 0usize;

        let range = table.range(prefix.as_str()..)?;
        for entry in range {
            let (key_guard, val_guard) = entry?;
            let key_str = key_guard.value();
            if !key_str.starts_with(&prefix) {
                break;
            }
            if skipped < offset {
                skipped += 1;
                continue;
            }
            if results.len() >= limit {
                break;
            }
            if let Ok(val) = serde_json::from_slice::<serde_json::Value>(val_guard.value()) {
                results.push(val);
            }
        }
        Ok(results)
    }

    /// Count total revocations for a pool.
    pub fn count_revocations(&self, pool_pda: &str) -> TxDbResult<usize> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(REVOCATIONS)?;
        let prefix = format!("{pool_pda}|");
        let mut count = 0;
        let range = table.range(prefix.as_str()..)?;
        for entry in range {
            let (key_guard, _) = entry?;
            if !key_guard.value().starts_with(&prefix) {
                break;
            }
            count += 1;
        }
        Ok(count)
    }

    // ── Nonce replay protection ────────────────────────────────────

    /// Record a nonce. Returns `true` if the nonce was **new** (inserted),
    /// `false` if it was already present (replay detected).
    ///
    /// Currently no production handler calls this; tests exercise the
    /// contract.
    #[allow(dead_code)]
    pub fn record_nonce(&self, nonce: &str) -> TxDbResult<bool> {
        let write_txn = self.db.begin_write()?;
        let is_new = {
            let mut table = write_txn.open_table(NONCES)?;
            if table.get(nonce)?.is_some() {
                false
            } else {
                let now = chrono::Utc::now().timestamp().to_le_bytes();
                table.insert(nonce, now.as_slice())?;
                true
            }
        };
        write_txn.commit()?;
        Ok(is_new)
    }

    /// Purge nonces older than `max_age_secs` to prevent unbounded growth.
    pub fn purge_expired_nonces(&self, max_age_secs: i64) -> TxDbResult<usize> {
        let cutoff = chrono::Utc::now().timestamp() - max_age_secs;
        let write_txn = self.db.begin_write()?;
        let mut removed = 0usize;
        {
            let mut table = write_txn.open_table(NONCES)?;
            let mut to_remove = Vec::new();
            {
                let iter = table.iter()?;
                for entry in iter {
                    let entry = entry?;
                    let nonce_key = entry.0.value().to_string();
                    let ts_bytes: [u8; 8] = entry.1.value().try_into().unwrap_or([0u8; 8]);
                    let ts = i64::from_le_bytes(ts_bytes);
                    if ts < cutoff {
                        to_remove.push(nonce_key);
                    }
                }
            }
            for key in &to_remove {
                table.remove(key.as_str())?;
                removed += 1;
            }
        }
        write_txn.commit()?;
        Ok(removed)
    }
}

// ── Index key helpers ──────────────────────────────────────────────

/// Build a composite string key: `{prefix}|{!timestamp_be_hex}|{suffix}`.
///
/// Timestamp is bitwise-inverted for reverse-chronological ordering.
fn make_pool_ts_key(prefix: &str, timestamp: i64, suffix: &str) -> String {
    let inverted_ts = !timestamp as u64;
    format!("{prefix}|{inverted_ts:016x}|{suffix}")
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Open a fresh on-disk database under a unique temp path.
    fn fresh_db() -> (TxDatabase, std::path::PathBuf) {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "relational-tee-test-{}-{}.redb",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let db = TxDatabase::open(&path).expect("open temp redb");
        (db, path)
    }

    /// Confirms the nonce-replay contract: the same nonce can only be
    /// inserted once.
    #[test]
    fn record_nonce_rejects_replay() {
        let (db, path) = fresh_db();

        assert!(
            db.record_nonce("nonce-abc").expect("record"),
            "first insertion of a nonce must succeed (returns true == new)",
        );
        assert!(
            !db.record_nonce("nonce-abc").expect("record"),
            "replayed nonce must be detected (returns false == already present)",
        );
        assert!(
            db.record_nonce("nonce-xyz").expect("record"),
            "unrelated nonce must remain accepted",
        );

        let _ = std::fs::remove_file(path);
    }

    /// Confirms expired nonces are dropped so the table can't grow forever.
    /// Passing a negative `max_age_secs` forces every entry past the cutoff.
    #[test]
    fn purge_expired_nonces_removes_old_entries() {
        let (db, path) = fresh_db();

        db.record_nonce("nonce-old").expect("record");
        let removed = db.purge_expired_nonces(-1).expect("purge");
        assert_eq!(
            removed, 1,
            "purge with negative max age must drop the entry"
        );
        assert!(
            db.record_nonce("nonce-old").expect("record"),
            "after purge the nonce slot is free again",
        );

        let _ = std::fs::remove_file(path);
    }
}
