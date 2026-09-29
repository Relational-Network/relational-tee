// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Embedded ACID transaction database backed by [`redb`].
//!
//! Tables:
//! - `transactions`      — signature (str) → StoredTransaction JSON bytes
//! - `wallet_tx_index`   — composite key → direction ("sent" / "received")
//! - `address_wallet_map` — base58 address → wallet_id (UUID)
//! - `indexer_state`     — key → checkpoint bytes

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use std::path::Path;

use super::grants::{GrantRecord, GrantStatus};
use super::repository::transactions::{StoredTransaction, TxStatus};

// ── Table definitions ──────────────────────────────────────────────

const TRANSACTIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("transactions");
const WALLET_TX_INDEX: TableDefinition<&[u8], &str> = TableDefinition::new("wallet_tx_index");
const ADDRESS_WALLET_MAP: TableDefinition<&str, &str> = TableDefinition::new("address_wallet_map");
const INDEXER_STATE: TableDefinition<&str, &[u8]> = TableDefinition::new("indexer_state");
/// Nonce replay protection: nonce_string → unix_timestamp (i64 LE bytes).
const NONCES: TableDefinition<&str, &[u8]> = TableDefinition::new("nonces");

// ── Phase 2: Wallet owner index ────────────────────────────────────
/// Maps `owner_user_id` → `wallet_id` for O(1) user → wallet lookup.
/// Enforces 1-wallet-per-user constraint.
const WALLET_BY_OWNER: TableDefinition<&str, &str> = TableDefinition::new("wallet_by_owner");

// ── Phase 3: Pool metadata & issuance ──────────────────────────────
/// Pool metadata: `pool_pda` → PoolMetadata JSON bytes.
const POOL_METADATA: TableDefinition<&str, &[u8]> = TableDefinition::new("pool_metadata");
/// Pool-by-owner index: `{owner_wallet_id}|{pool_pda}` → `""` (key-only index).
const POOL_BY_OWNER: TableDefinition<&str, &str> = TableDefinition::new("pool_by_owner");
/// Issuance records: `{pool_pda}|{!timestamp_be}|{record_id}` → DatasetFileMeta JSON bytes.
const ISSUANCE_RECORDS: TableDefinition<&str, &[u8]> = TableDefinition::new("issuance_records");
/// Revocations: `{pool_pda}|{credential_id}` → RevocationEntry JSON bytes.
const REVOCATIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("revocations");

// ── Phase 4: Audit trail index ─────────────────────────────────────
/// Audit events: `{event_id}` → AuditEvent JSON bytes.
const AUDIT_EVENTS: TableDefinition<&str, &[u8]> = TableDefinition::new("audit_events");
/// Audit-by-resource index: `{resource_id}|{!timestamp_be}|{event_id}` → `""`.
const AUDIT_BY_RESOURCE: TableDefinition<&str, &str> = TableDefinition::new("audit_by_resource");
/// Audit-by-date index: `{YYYY-MM-DD}|{event_id}` → `""`.
const AUDIT_BY_DATE: TableDefinition<&str, &str> = TableDefinition::new("audit_by_date");

// ── Phase 5: DRT grant mirror ──────────────────────────────────────
/// Per-pool grant store: `{pool_pda}|{analyst_id}|{drt_name}` → GrantRecord JSON.
const GRANTS_BY_POOL: TableDefinition<&str, &[u8]> = TableDefinition::new("grants_by_pool");
/// Per-analyst index: `{analyst_id}|{pool_pda}|{drt_name}` → `""`.
/// Revoked grants are removed from this index so analysts see only active access.
const GRANTS_BY_ANALYST: TableDefinition<&str, &str> = TableDefinition::new("grants_by_analyst");

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
    /// Client provided a tampered or invalid pagination cursor.
    InvalidCursor,
    /// User already has a wallet (1-wallet-per-user constraint).
    DuplicateWallet(String),
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
            Self::InvalidCursor => write!(f, "invalid pagination cursor"),
            Self::DuplicateWallet(id) => write!(f, "user already has wallet: {id}"),
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
        match &e {
            TxDbError::InvalidCursor => Self::bad_request("invalid pagination cursor"),
            TxDbError::DuplicateWallet(id) => {
                Self::bad_request(format!("user already has a wallet: {id}"))
            }
            _ => {
                tracing::error!(error = %e, "Transaction database error");
                Self::internal("internal database error")
            }
        }
    }
}

/// Embedded ACID transaction store.
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
            let _ = write_txn.open_table(TRANSACTIONS)?;
            let _ = write_txn.open_table(WALLET_TX_INDEX)?;
            let _ = write_txn.open_table(ADDRESS_WALLET_MAP)?;
            let _ = write_txn.open_table(INDEXER_STATE)?;
            let _ = write_txn.open_table(NONCES)?;
            // Phase 2
            let _ = write_txn.open_table(WALLET_BY_OWNER)?;
            // Phase 3
            let _ = write_txn.open_table(POOL_METADATA)?;
            let _ = write_txn.open_table(POOL_BY_OWNER)?;
            let _ = write_txn.open_table(ISSUANCE_RECORDS)?;
            let _ = write_txn.open_table(REVOCATIONS)?;
            // Phase 4
            let _ = write_txn.open_table(AUDIT_EVENTS)?;
            let _ = write_txn.open_table(AUDIT_BY_RESOURCE)?;
            let _ = write_txn.open_table(AUDIT_BY_DATE)?;
            // Phase 5
            let _ = write_txn.open_table(GRANTS_BY_POOL)?;
            let _ = write_txn.open_table(GRANTS_BY_ANALYST)?;
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

    /// Insert or update a transaction, with direction entries for each involved address.
    ///
    /// `directions` is a list of `(address, direction)` pairs — e.g.,
    /// `[("SenderAddr", "sent"), ("ReceiverAddr", "received")]`.
    pub fn upsert_transaction(
        &self,
        tx: &StoredTransaction,
        directions: &[(String, &str)],
    ) -> TxDbResult<()> {
        let json_bytes = serde_json::to_vec(tx)?;
        let write_txn = self.db.begin_write()?;
        {
            // Main transaction record.
            let mut table = write_txn.open_table(TRANSACTIONS)?;
            table.insert(tx.signature.as_str(), json_bytes.as_slice())?;

            // Wallet→tx index entries.
            let mut idx = write_txn.open_table(WALLET_TX_INDEX)?;
            for (address, direction) in directions {
                let key = make_index_key(address, tx.created_at.timestamp(), &tx.signature);
                idx.insert(key.as_slice(), *direction)?;
            }
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Get a single transaction by signature.
    pub fn get_transaction(&self, signature: &str) -> TxDbResult<Option<StoredTransaction>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(TRANSACTIONS)?;
        match table.get(signature)? {
            Some(bytes) => {
                let tx: StoredTransaction = serde_json::from_slice(bytes.value())?;
                Ok(Some(tx))
            }
            None => Ok(None),
        }
    }

    /// List transactions for a wallet address with cursor-based pagination.
    ///
    /// Returns `(entries, next_cursor)` where each entry is `(StoredTransaction, direction)`.
    #[allow(clippy::type_complexity)]
    pub fn list_by_wallet(
        &self,
        address: &str,
        cursor: Option<&str>,
        limit: usize,
    ) -> TxDbResult<(Vec<(StoredTransaction, String)>, Option<String>)> {
        let read_txn = self.db.begin_read()?;
        let idx = read_txn.open_table(WALLET_TX_INDEX)?;
        let tx_table = read_txn.open_table(TRANSACTIONS)?;

        // Build start key from cursor or scan from the beginning of the address prefix.
        let prefix = format!("{address}|");
        let start = match cursor {
            Some(c) => verify_cursor(c)
                .ok_or(TxDbError::InvalidCursor)?
                .into_bytes(),
            None => prefix.as_bytes().to_vec(),
        };

        let mut results = Vec::new();
        let mut next_cursor = None;

        let range = idx.range(start.as_slice()..)?;
        for entry in range {
            let (key_guard, val_guard) = entry?;
            let key_bytes = key_guard.value();
            let key_str = std::str::from_utf8(key_bytes).unwrap_or("");

            // Stop once we leave this address's prefix.
            if !key_str.starts_with(&prefix) {
                break;
            }

            if results.len() >= limit {
                next_cursor = Some(sign_cursor(key_str));
                break;
            }

            let direction = val_guard.value().to_string();
            // Extract signature from key: "address|!timestamp|signature"
            if let Some(sig) = key_str.rsplit('|').next() {
                if let Some(bytes) = tx_table.get(sig)? {
                    if let Ok(tx) = serde_json::from_slice::<StoredTransaction>(bytes.value()) {
                        results.push((tx, direction));
                    }
                }
            }
        }

        Ok((results, next_cursor))
    }

    /// Update status, slot, and fee of an existing transaction.
    #[allow(dead_code)]
    pub fn update_status(
        &self,
        signature: &str,
        status: TxStatus,
        slot: Option<u64>,
        fee: Option<u64>,
    ) -> TxDbResult<()> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(TRANSACTIONS)?;

            // Read the existing record into owned bytes first to release borrow.
            let existing_bytes = { table.get(signature)?.map(|guard| guard.value().to_vec()) };

            if let Some(bytes) = existing_bytes {
                let mut tx: StoredTransaction = serde_json::from_slice(&bytes)?;
                tx.status = status;
                if let Some(s) = slot {
                    tx.slot = Some(s);
                }
                if let Some(f) = fee {
                    tx.fee_lamports = Some(f);
                }
                tx.updated_at = chrono::Utc::now();
                let json_bytes = serde_json::to_vec(&tx)?;
                table.insert(signature, json_bytes.as_slice())?;
            }
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Register a Solana address → wallet_id mapping (for the indexer).
    pub fn register_address(&self, address: &str, wallet_id: &str) -> TxDbResult<()> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(ADDRESS_WALLET_MAP)?;
            table.insert(address, wallet_id)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Look up which wallet owns an address. Called by the transaction indexer
    /// (`indexer/poller.rs`) to attribute on-chain counterparties to wallets.
    pub fn get_wallet_id_for_address(&self, address: &str) -> TxDbResult<Option<String>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(ADDRESS_WALLET_MAP)?;
        Ok(table.get(address)?.map(|v| v.value().to_string()))
    }

    /// Get all registered addresses (for the indexer to poll).
    pub fn get_all_addresses(&self) -> TxDbResult<Vec<(String, String)>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(ADDRESS_WALLET_MAP)?;
        let mut result = Vec::new();
        for entry in table.iter()? {
            let (k, v) = entry?;
            result.push((k.value().to_string(), v.value().to_string()));
        }
        Ok(result)
    }

    /// Read indexer checkpoint (e.g., last processed signature).
    pub fn get_indexer_state(&self, key: &str) -> TxDbResult<Option<Vec<u8>>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(INDEXER_STATE)?;
        Ok(table.get(key)?.map(|v| v.value().to_vec()))
    }

    /// Write indexer checkpoint.
    pub fn set_indexer_state(&self, key: &str, value: &[u8]) -> TxDbResult<()> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(INDEXER_STATE)?;
            table.insert(key, value)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    // ── Phase 2: Wallet owner index ────────────────────────────────

    /// Register a user → wallet_id mapping. Returns an error if the user
    /// already owns a wallet (1-wallet-per-user constraint).
    pub fn register_wallet_owner(&self, owner_user_id: &str, wallet_id: &str) -> TxDbResult<()> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(WALLET_BY_OWNER)?;
            // Enforce 1-wallet-per-user: check if user already has a wallet.
            if let Some(existing) = table.get(owner_user_id)? {
                let existing_id = existing.value().to_string();
                drop(existing);
                return Err(TxDbError::DuplicateWallet(existing_id));
            }
            table.insert(owner_user_id, wallet_id)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Look up the wallet_id for a user. Returns `None` if the user has no wallet.
    pub fn get_wallet_id_by_owner(&self, owner_user_id: &str) -> TxDbResult<Option<String>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(WALLET_BY_OWNER)?;
        Ok(table.get(owner_user_id)?.map(|v| v.value().to_string()))
    }

    /// Remove the user → wallet_id mapping (on wallet deletion).
    pub fn remove_wallet_owner(&self, owner_user_id: &str) -> TxDbResult<()> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(WALLET_BY_OWNER)?;
            table.remove(owner_user_id)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    // ── Phase 3: Pool metadata & issuance ──────────────────────────

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

    /// Read pool metadata by PDA.
    #[allow(dead_code)] // TODO
    pub fn get_pool_meta(
        &self,
        pool_pda: &str,
    ) -> TxDbResult<Option<super::pool_metadata::PoolMetadata>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(POOL_METADATA)?;
        match table.get(pool_pda)? {
            Some(bytes) => {
                let meta = serde_json::from_slice(bytes.value())?;
                Ok(Some(meta))
            }
            None => Ok(None),
        }
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

    /// Delete pool metadata from redb (and owner index).
    ///
    /// Currently unused — kept so that an "admin forget pool" endpoint can
    /// clean up enclave state when the on-chain pool is no longer interesting.
    #[allow(dead_code)]
    pub fn delete_pool_meta(&self, pool_pda: &str) -> TxDbResult<()> {
        // First, read the owner to clean up the index.
        let owner_wallet_id = {
            let read_txn = self.db.begin_read()?;
            let table = read_txn.open_table(POOL_METADATA)?;
            table.get(pool_pda)?.and_then(|bytes| {
                serde_json::from_slice::<super::pool_metadata::PoolMetadata>(bytes.value())
                    .ok()
                    .map(|m| m.owner_wallet_id)
            })
        };

        let write_txn = self.db.begin_write()?;
        {
            let mut meta_table = write_txn.open_table(POOL_METADATA)?;
            meta_table.remove(pool_pda)?;

            if let Some(owner) = owner_wallet_id {
                let mut idx = write_txn.open_table(POOL_BY_OWNER)?;
                let key = format!("{owner}|{pool_pda}");
                idx.remove(key.as_str())?;
            }
        }
        write_txn.commit()?;
        Ok(())
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

    // ── Phase 4: Audit trail index ─────────────────────────────────

    /// Log an audit event to redb (writes to all 3 audit tables).
    pub fn log_audit_event(&self, event: &super::audit::AuditEvent) -> TxDbResult<()> {
        let json_bytes = serde_json::to_vec(event)?;
        let write_txn = self.db.begin_write()?;
        {
            // Main event store.
            let mut events = write_txn.open_table(AUDIT_EVENTS)?;
            events.insert(event.event_id.as_str(), json_bytes.as_slice())?;

            // Resource index (if resource_id is set).
            if let Some(ref resource_id) = event.resource_id {
                let mut by_resource = write_txn.open_table(AUDIT_BY_RESOURCE)?;
                let key =
                    make_pool_ts_key(resource_id, event.timestamp.timestamp(), &event.event_id);
                by_resource.insert(key.as_str(), "")?;
            }

            // Date index.
            let date = event.timestamp.format("%Y-%m-%d").to_string();
            let mut by_date = write_txn.open_table(AUDIT_BY_DATE)?;
            let key = format!("{date}|{}", event.event_id);
            by_date.insert(key.as_str(), "")?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// List audit events for a resource with pagination (newest first).
    pub fn list_audit_by_resource(
        &self,
        resource_id: &str,
        limit: usize,
        offset: usize,
    ) -> TxDbResult<Vec<super::audit::AuditEvent>> {
        let read_txn = self.db.begin_read()?;
        let idx = read_txn.open_table(AUDIT_BY_RESOURCE)?;
        let events = read_txn.open_table(AUDIT_EVENTS)?;
        let prefix = format!("{resource_id}|");
        let mut results = Vec::new();
        let mut skipped = 0usize;

        let range = idx.range(prefix.as_str()..)?;
        for entry in range {
            let (key_guard, _) = entry?;
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
            // Extract event_id: last segment after "|"
            if let Some(event_id) = key_str.rsplit('|').next() {
                if let Some(bytes) = events.get(event_id)? {
                    if let Ok(ev) =
                        serde_json::from_slice::<super::audit::AuditEvent>(bytes.value())
                    {
                        results.push(ev);
                    }
                }
            }
        }
        Ok(results)
    }

    /// Count audit events for a resource.
    pub fn count_audit_by_resource(&self, resource_id: &str) -> TxDbResult<usize> {
        let read_txn = self.db.begin_read()?;
        let idx = read_txn.open_table(AUDIT_BY_RESOURCE)?;
        let prefix = format!("{resource_id}|");
        let mut count = 0;
        let range = idx.range(prefix.as_str()..)?;
        for entry in range {
            let (key_guard, _) = entry?;
            if !key_guard.value().starts_with(&prefix) {
                break;
            }
            count += 1;
        }
        Ok(count)
    }

    /// List audit events for a specific date with pagination.
    pub fn list_audit_by_date(
        &self,
        date: &str,
        limit: usize,
        offset: usize,
    ) -> TxDbResult<Vec<super::audit::AuditEvent>> {
        let read_txn = self.db.begin_read()?;
        let idx = read_txn.open_table(AUDIT_BY_DATE)?;
        let events = read_txn.open_table(AUDIT_EVENTS)?;
        let prefix = format!("{date}|");
        let mut results = Vec::new();
        let mut skipped = 0usize;

        let range = idx.range(prefix.as_str()..)?;
        for entry in range {
            let (key_guard, _) = entry?;
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
            // Extract event_id from key: "YYYY-MM-DD|event_id"
            if let Some(event_id) = key_str.strip_prefix(&prefix) {
                if let Some(bytes) = events.get(event_id)? {
                    if let Ok(ev) =
                        serde_json::from_slice::<super::audit::AuditEvent>(bytes.value())
                    {
                        results.push(ev);
                    }
                }
            }
        }
        Ok(results)
    }

    /// Count audit events for a specific date.
    #[allow(dead_code)] // TODO
    pub fn count_audit_by_date(&self, date: &str) -> TxDbResult<usize> {
        let read_txn = self.db.begin_read()?;
        let idx = read_txn.open_table(AUDIT_BY_DATE)?;
        let prefix = format!("{date}|");
        let mut count = 0;
        let range = idx.range(prefix.as_str()..)?;
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
    /// Currently no production handler calls this — `/v1/data/upload` was
    /// removed and `initialize_pool` / `issue_credentials` have not yet
    /// adopted replay-nonce checks (security-hardening.md N6). Tests exercise
    /// the contract so behaviour is preserved for when N6 lands.
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

    // ── Phase 5: DRT grants ─────────────────────────────────────────

    /// Insert or update a grant record (idempotent re-grant of a previously
    /// revoked DRT flips `status` back to active).
    pub fn upsert_grant(&self, record: &GrantRecord) -> TxDbResult<()> {
        let pool_key = format!(
            "{}|{}|{}",
            record.pool_pda, record.analyst_id, record.drt_name
        );
        let analyst_key = format!(
            "{}|{}|{}",
            record.analyst_id, record.pool_pda, record.drt_name
        );
        let bytes = serde_json::to_vec(record)?;
        let write_txn = self.db.begin_write()?;
        {
            let mut by_pool = write_txn.open_table(GRANTS_BY_POOL)?;
            by_pool.insert(pool_key.as_str(), bytes.as_slice())?;
            let mut by_analyst = write_txn.open_table(GRANTS_BY_ANALYST)?;
            // Only index active grants for the analyst-facing view.
            if matches!(record.status, GrantStatus::Active) {
                by_analyst.insert(analyst_key.as_str(), "")?;
            } else {
                by_analyst.remove(analyst_key.as_str())?;
            }
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Mark a grant as revoked. Returns `false` if no matching record exists.
    pub fn revoke_grant_local(
        &self,
        pool_pda: &str,
        analyst_id: &str,
        drt_name: &str,
        revoked_sig: &str,
    ) -> TxDbResult<bool> {
        let pool_key = format!("{pool_pda}|{analyst_id}|{drt_name}");
        let analyst_key = format!("{analyst_id}|{pool_pda}|{drt_name}");
        let write_txn = self.db.begin_write()?;
        let updated;
        {
            let mut by_pool = write_txn.open_table(GRANTS_BY_POOL)?;
            let existing_bytes = by_pool.get(pool_key.as_str())?.map(|v| v.value().to_vec());
            updated = if let Some(bytes) = existing_bytes {
                let mut rec: GrantRecord = serde_json::from_slice(&bytes)?;
                rec.status = GrantStatus::Revoked;
                rec.revoked_at = Some(chrono::Utc::now().timestamp());
                rec.revoked_sig = Some(revoked_sig.to_string());
                let new_bytes = serde_json::to_vec(&rec)?;
                by_pool.insert(pool_key.as_str(), new_bytes.as_slice())?;
                true
            } else {
                false
            };
            let mut by_analyst = write_txn.open_table(GRANTS_BY_ANALYST)?;
            by_analyst.remove(analyst_key.as_str())?;
        }
        write_txn.commit()?;
        Ok(updated)
    }

    /// List all grants for a pool (active + revoked).
    pub fn list_pool_grants(&self, pool_pda: &str) -> TxDbResult<Vec<GrantRecord>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(GRANTS_BY_POOL)?;
        let prefix_start = format!("{pool_pda}|");
        let prefix_end = format!("{pool_pda}|\u{10FFFF}");
        let mut out = Vec::new();
        let range = table.range(prefix_start.as_str()..prefix_end.as_str())?;
        for entry in range {
            let entry = entry?;
            let rec: GrantRecord = serde_json::from_slice(entry.1.value())?;
            out.push(rec);
        }
        Ok(out)
    }

    /// List active grants for an analyst across all pools. Returns the
    /// `GrantRecord` for each, looked up from the per-pool store.
    pub fn list_grants_by_analyst(&self, analyst_id: &str) -> TxDbResult<Vec<GrantRecord>> {
        let read_txn = self.db.begin_read()?;
        let idx = read_txn.open_table(GRANTS_BY_ANALYST)?;
        let by_pool = read_txn.open_table(GRANTS_BY_POOL)?;
        let prefix_start = format!("{analyst_id}|");
        let prefix_end = format!("{analyst_id}|\u{10FFFF}");
        let mut out = Vec::new();
        let range = idx.range(prefix_start.as_str()..prefix_end.as_str())?;
        for entry in range {
            let entry = entry?;
            let key = entry.0.value();
            // key = "{analyst_id}|{pool_pda}|{drt_name}" → flip to pool-key form
            let mut parts = key.splitn(3, '|');
            let (_a, pool, drt) = match (parts.next(), parts.next(), parts.next()) {
                (Some(a), Some(p), Some(d)) => (a, p, d),
                _ => continue,
            };
            let pool_key = format!("{pool}|{analyst_id}|{drt}");
            if let Some(v) = by_pool.get(pool_key.as_str())? {
                let rec: GrantRecord = serde_json::from_slice(v.value())?;
                if matches!(rec.status, GrantStatus::Active) {
                    out.push(rec);
                }
            }
        }
        Ok(out)
    }

    /// Returns `true` iff `analyst_id` currently has an **active** grant for
    /// the given DRT on the given pool.
    pub fn is_grant_active(
        &self,
        analyst_id: &str,
        pool_pda: &str,
        drt_name: &str,
    ) -> TxDbResult<bool> {
        let read_txn = self.db.begin_read()?;
        let idx = read_txn.open_table(GRANTS_BY_ANALYST)?;
        let key = format!("{analyst_id}|{pool_pda}|{drt_name}");
        Ok(idx.get(key.as_str())?.is_some())
    }
}

// ── Index key helpers ──────────────────────────────────────────────

/// Build a composite index key: `{address}|{!timestamp_be}|{signature}`.
///
/// Timestamp is bitwise-inverted so that lexicographic ordering gives
/// reverse chronological order (newest first).
fn make_index_key(address: &str, timestamp: i64, signature: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(address.len() + 1 + 8 + 1 + signature.len());
    key.extend_from_slice(address.as_bytes());
    key.push(b'|');
    key.extend_from_slice(&(!timestamp as u64).to_be_bytes());
    key.push(b'|');
    key.extend_from_slice(signature.as_bytes());
    key
}

/// Build a composite string key: `{prefix}|{!timestamp_be_hex}|{suffix}`.
///
/// Used for pool issuance records, audit indexes, etc.
/// Timestamp is bitwise-inverted for reverse-chronological ordering.
fn make_pool_ts_key(prefix: &str, timestamp: i64, suffix: &str) -> String {
    let inverted_ts = !timestamp as u64;
    format!("{prefix}|{inverted_ts:016x}|{suffix}")
}

// ── Signed pagination cursor helpers ───────────────────────────────

use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Derive an HMAC key specifically for cursor signing from the enclave's
/// **private** scalar (not the public `kid`).
fn cursor_hmac_key() -> [u8; 32] {
    crate::crypto::enclave_key().hmac_key(b"cursor-hmac-v1")
}

/// Sign a raw cursor value, returning an opaque token: `base64url(raw).hmac_hex`.
pub fn sign_cursor(raw: &str) -> String {
    let key = cursor_hmac_key();
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw.as_bytes());
    let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC can take any key size");
    mac.update(raw.as_bytes());
    let tag = hex::encode(mac.finalize().into_bytes());
    format!("{encoded}.{tag}")
}

/// Verify a signed cursor and return the raw cursor value, or `None` if forged.
pub fn verify_cursor(token: &str) -> Option<String> {
    let (encoded, tag) = token.rsplit_once('.')?;
    let raw_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .ok()?;
    let raw = String::from_utf8(raw_bytes).ok()?;
    let key = cursor_hmac_key();
    let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC can take any key size");
    mac.update(raw.as_bytes());
    let expected = hex::encode(mac.finalize().into_bytes());
    if expected == tag {
        Some(raw)
    } else {
        None
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Open a fresh on-disk database under a unique temp path.
    ///
    /// We use `std::env::temp_dir()` + the test process id so we don't add
    /// `tempfile` as a dev-dependency just for a couple of tests. The file
    /// is removed on success; on panic the OS cleans `/tmp` eventually.
    fn fresh_db() -> (TxDatabase, std::path::PathBuf) {
        let mut path = std::env::temp_dir();
        let unique = format!(
            "relational-sdk-test-{}-{}.redb",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        );
        path.push(unique);
        let db = TxDatabase::open(&path).expect("open temp redb");
        (db, path)
    }

    /// Confirms the nonce-replay contract: the same nonce can only be
    /// inserted once. HTTP handlers wire this to a 409 on replay.
    /// Today only `/v1/data/query`-adjacent flows can adopt this; the
    /// `initialize_pool` / `issue_credentials` endpoints still need
    /// per-request `record_nonce` wiring (security-hardening.md N6).
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
