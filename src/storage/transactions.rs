// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Wallet transaction history, in Table `transactions`:
//!
//! - `{wallet_id}` / `{inverted_ts}:{signature}`: one row per transaction
//!   per wallet it touches, newest first.
//! - `sig:{signature}` / `{wallet_id}`: the same row, found by signature.
//! - `sync` / `{address}`: the last signature seen and the last sync time.
//!   On-demand syncs claim the row by compare-and-swap, so every worker
//!   shares one cooldown per address.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::store::{Continuation, ETag, InsertOutcome, Page, Prop, RkRange, StoreError, Table};
use super::{inverted_millis, Storage};

const PAYLOAD_VERSION: u32 = 1;
const SYNC_PK: &str = "sync";

/// Whether a transfer was native SOL or an SPL token.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TokenType {
    /// Native SOL transfer.
    Native,
    /// SPL token transfer, identified by mint address.
    SplToken(String),
}

/// On-chain confirmation status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TxStatus {
    Pending,
    Confirmed,
    Failed,
}

impl TxStatus {
    fn as_str(&self) -> &'static str {
        match self {
            TxStatus::Pending => "pending",
            TxStatus::Confirmed => "confirmed",
            TxStatus::Failed => "failed",
        }
    }
}

/// A stored transaction.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct StoredTransaction {
    pub signature: String,
    pub wallet_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub counterparty_wallet_id: Option<String>,
    pub from: String,
    pub to: String,
    pub amount: String,
    /// Precise amount in lamports (1 SOL = 1_000_000_000 lamports).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount_lamports: Option<u64>,
    pub token: TokenType,
    pub network: String,
    pub status: TxStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slot: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee_lamports: Option<u64>,
    pub explorer_url: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A transaction as one wallet sees it.
#[derive(Serialize, Deserialize)]
struct TxRow {
    tx: StoredTransaction,
    /// `sent` or `received`.
    direction: String,
}

/// Sync state for one address.
#[derive(Serialize, Deserialize, Default)]
struct SyncState {
    last_signature: Option<String>,
    last_sync_at: Option<DateTime<Utc>>,
}

/// A claimed sync: the caller may poll the chain for this address.
pub struct SyncClaim {
    address: String,
    /// The newest signature already stored; poll only for newer ones.
    pub until: Option<String>,
    claimed_at: DateTime<Utc>,
    etag: ETag,
}

/// Transaction storage.
pub struct Transactions<'a> {
    s: &'a Storage,
}

impl<'a> Transactions<'a> {
    pub(crate) fn new(s: &'a Storage) -> Self {
        Self { s }
    }

    /// Store a transaction in `wallet_id`'s history. Upserts, so storing
    /// the same transaction again changes nothing.
    pub async fn upsert(
        &self,
        wallet_id: &str,
        tx: &StoredTransaction,
        direction: &str,
    ) -> Result<(), StoreError> {
        let row = TxRow {
            tx: tx.clone(),
            direction: direction.to_string(),
        };
        let rk = format!("{}:{}", inverted_millis(tx.created_at), tx.signature);
        for (pk, rk) in [
            (wallet_id.to_string(), rk),
            (format!("sig:{}", tx.signature), wallet_id.to_string()),
        ] {
            let entity = self
                .s
                .sealed_row(Table::Transactions, &pk, &rk, PAYLOAD_VERSION, &row)?
                .with("status", Prop::Str(tx.status.as_str().into()))
                .with("created_at", Prop::Str(tx.created_at.to_rfc3339()));
            self.s.index().upsert(Table::Transactions, entity).await?;
        }
        Ok(())
    }

    /// A transaction in `wallet_id`'s history, with its direction.
    pub async fn get(
        &self,
        wallet_id: &str,
        signature: &str,
    ) -> Result<Option<(StoredTransaction, String)>, StoreError> {
        Ok(self
            .s
            .get_sealed::<TxRow>(
                Table::Transactions,
                &format!("sig:{signature}"),
                wallet_id,
                PAYLOAD_VERSION,
            )
            .await?
            .map(|(row, _)| (row.tx, row.direction)))
    }

    /// One page of `wallet_id`'s history, newest first.
    pub async fn list(
        &self,
        wallet_id: &str,
        limit: usize,
        page: Option<Continuation>,
    ) -> Result<Page<(StoredTransaction, String)>, StoreError> {
        let rows = self
            .s
            .query_rows(
                Table::Transactions,
                wallet_id,
                RkRange::all(),
                None,
                limit,
                page,
            )
            .await?;
        Ok(Page {
            items: rows
                .items
                .iter()
                .map(|e| {
                    self.s
                        .open_row::<TxRow>(Table::Transactions, PAYLOAD_VERSION, e)
                        .map(|row| (row.tx, row.direction))
                })
                .collect::<Result<_, _>>()?,
            next: rows.next,
        })
    }

    /// Claim the right to sync `address` unless any worker synced it less
    /// than `cooldown` ago. `None` means skip this sync.
    pub async fn claim_sync(
        &self,
        address: &str,
        cooldown: chrono::Duration,
    ) -> Result<Option<SyncClaim>, StoreError> {
        let now = Utc::now();
        let existing = self
            .s
            .get_sealed::<SyncState>(Table::Transactions, SYNC_PK, address, PAYLOAD_VERSION)
            .await?;
        let mut state = match &existing {
            Some((state, _)) => SyncState {
                last_signature: state.last_signature.clone(),
                last_sync_at: state.last_sync_at,
            },
            None => SyncState::default(),
        };
        if state.last_sync_at.is_some_and(|at| now - at < cooldown) {
            return Ok(None);
        }
        let until = state.last_signature.clone();
        state.last_sync_at = Some(now);
        let row = self.s.sealed_row(
            Table::Transactions,
            SYNC_PK,
            address,
            PAYLOAD_VERSION,
            &state,
        )?;
        let etag = match existing {
            Some((_, etag)) => match self
                .s
                .index()
                .update_if_match(Table::Transactions, row, &etag)
                .await
            {
                Ok(etag) => etag,
                // Another worker claimed it first.
                Err(StoreError::PreconditionFailed | StoreError::NotFound) => return Ok(None),
                Err(e) => return Err(e),
            },
            None => match self.s.index().insert(Table::Transactions, row).await? {
                InsertOutcome::Inserted(etag) => etag,
                InsertOutcome::Conflict => return Ok(None),
            },
        };
        Ok(Some(SyncClaim {
            address: address.to_string(),
            until,
            claimed_at: now,
            etag,
        }))
    }

    /// Record the newest signature a claimed sync saw.
    pub async fn finish_sync(
        &self,
        claim: SyncClaim,
        newest: Option<String>,
    ) -> Result<(), StoreError> {
        let Some(newest) = newest else {
            return Ok(());
        };
        let state = SyncState {
            last_signature: Some(newest),
            last_sync_at: Some(claim.claimed_at),
        };
        let row = self.s.sealed_row(
            Table::Transactions,
            SYNC_PK,
            &claim.address,
            PAYLOAD_VERSION,
            &state,
        )?;
        match self
            .s
            .index()
            .update_if_match(Table::Transactions, row, &claim.etag)
            .await
        {
            // A later sync already moved the row on; its signature wins.
            Ok(_) | Err(StoreError::PreconditionFailed) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::tests::{memory_storage, two_workers};

    fn tx(signature: &str, at_millis: i64) -> StoredTransaction {
        let at = DateTime::from_timestamp_millis(at_millis).unwrap();
        StoredTransaction {
            signature: signature.into(),
            wallet_id: "w1".into(),
            counterparty_wallet_id: None,
            from: "a".into(),
            to: "b".into(),
            amount: "1".into(),
            amount_lamports: Some(1),
            token: TokenType::Native,
            network: "Solana Devnet".into(),
            status: TxStatus::Confirmed,
            slot: None,
            fee_lamports: None,
            explorer_url: String::new(),
            created_at: at,
            updated_at: at,
        }
    }

    #[tokio::test]
    async fn history_is_newest_first_and_pages_identically_on_any_worker() {
        let (a, b) = two_workers();
        for i in 0..7 {
            a.transactions()
                .upsert("w1", &tx(&format!("sig{i}"), 1_000 + i), "sent")
                .await
                .unwrap();
        }
        // Storing the same transaction again doesn't duplicate it.
        a.transactions()
            .upsert("w1", &tx("sig3", 1_003), "sent")
            .await
            .unwrap();

        let mut via_a = Vec::new();
        let mut via_b = Vec::new();
        for (reader, out) in [(&a, &mut via_a), (&b, &mut via_b)] {
            let mut cursor: Option<String> = None;
            loop {
                let page = reader.page_from("tx:w1", cursor.as_deref()).unwrap();
                let got = reader.transactions().list("w1", 3, page).await.unwrap();
                out.extend(got.items.into_iter().map(|(t, _)| t.signature));
                // Continue with a cursor signed by the other worker.
                let other = if std::ptr::eq(reader, &a) { &b } else { &a };
                match got.next {
                    Some(next) => cursor = Some(other.sign_cursor("tx:w1", &next)),
                    None => break,
                }
            }
        }
        let expected: Vec<String> = (0..7).rev().map(|i| format!("sig{i}")).collect();
        assert_eq!(via_a, expected);
        assert_eq!(via_b, expected);

        let (found, direction) = b.transactions().get("w1", "sig2").await.unwrap().unwrap();
        assert_eq!(
            (found.signature.as_str(), direction.as_str()),
            ("sig2", "sent")
        );
        assert!(b.transactions().get("w2", "sig2").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn sync_claims_share_one_cooldown() {
        let (a, b) = two_workers();
        let cooldown = chrono::Duration::seconds(10);
        let claim = a
            .transactions()
            .claim_sync("addr", cooldown)
            .await
            .unwrap()
            .unwrap();
        assert!(claim.until.is_none());
        assert!(b
            .transactions()
            .claim_sync("addr", cooldown)
            .await
            .unwrap()
            .is_none());
        a.transactions()
            .finish_sync(claim, Some("sig9".into()))
            .await
            .unwrap();

        let s = memory_storage();
        assert!(s
            .transactions()
            .claim_sync("addr", cooldown)
            .await
            .unwrap()
            .is_some());
        let later = a
            .transactions()
            .claim_sync("addr", chrono::Duration::zero())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(later.until.as_deref(), Some("sig9"));
    }
}
