// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Credential pools, in Table `pools`:
//!
//! - `pool` / `{pool_pda}`: the pool's metadata and schema.
//! - `owner:{owner_wallet_id}` / `{pool_pda}`: the owner index, a pointer
//!   whose target is checked on read.
//!
//! Changes are compare-and-swap writes on the pool row, so no worker needs a
//! lock. Totals (rows issued, revocations) aren't stored here: they're
//! computed from the committed records and the revocation index.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::store::{
    Continuation, ETag, Entity, InsertOutcome, Page, Prop, RkRange, StoreError, Table,
};
use super::wallets::{cas_backoff, CAS_ATTEMPTS};
use super::Storage;
use crate::data_validation::{FieldSchema, ValidationMode};

const POOL_PK: &str = "pool";
const PAYLOAD_VERSION: u32 = 1;

/// Operational shape of the pool.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolKind {
    /// CSV-driven pool. Admin uploads CSVs; schema mandatory, headers-only validation.
    #[default]
    Malta,
}

/// Pool lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolState {
    NeedsInit,
    Ready,
}

impl PoolState {
    pub fn as_str(self) -> &'static str {
        match self {
            PoolState::NeedsInit => "needs_init",
            PoolState::Ready => "ready",
        }
    }
}

/// Per-DRT bookkeeping, mirroring what `register_drt` put on-chain, so pool
/// pages render without calling the chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrtMetadata {
    /// 16-byte right_id (hex).
    pub right_id_hex: String,
    /// Mint pubkey (base58).
    pub mint: String,
    /// Supply minted at registration.
    pub supply: u64,
    /// Script URL (empty for `append`).
    pub code_repo_url: String,
    /// SHA-256 of the script as hex (zero for `append`).
    pub code_hash_hex: String,
}

/// A pool: the encrypted payload of its `pool` row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolMetadata {
    /// Pool PDA (base58-encoded Solana address).
    pub pool_pda: String,
    /// Human-readable pool name (not on-chain).
    pub pool_name: String,
    pub kind: PoolKind,
    /// 16-byte pool UUID (hex). Matches the seed used to derive `pool_pda`.
    pub pool_uuid_hex: String,
    /// DRT name → on-chain configuration (right_id, mint, supply, code).
    pub drts: BTreeMap<String, DrtMetadata>,
    /// Wallet ID of the pool owner.
    pub owner_wallet_id: String,
    /// Solana public key of the pool owner (base58).
    pub owner_pubkey: Option<String>,
    /// Schema id label.
    pub schema_id: String,
    /// The CSV schema uploads are validated against.
    pub schema: Vec<FieldSchema>,
    /// CSV validation strictness.
    pub validation_mode: ValidationMode,
    pub state: PoolState,
    pub created_onchain_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initialized_at: Option<DateTime<Utc>>,
    /// Incremented on every update.
    pub version: u64,
}

/// Whether an update changed the pool.
pub enum Change {
    Changed,
    Unchanged,
}

/// Pool storage.
pub struct Pools<'a> {
    s: &'a Storage,
}

fn owner_pk(wallet_id: &str) -> String {
    format!("owner:{wallet_id}")
}

impl<'a> Pools<'a> {
    pub(crate) fn new(s: &'a Storage) -> Self {
        Self { s }
    }

    fn pool_row(&self, meta: &PoolMetadata) -> Result<super::store::Entity, StoreError> {
        Ok(self
            .s
            .sealed_row(Table::Pools, POOL_PK, &meta.pool_pda, PAYLOAD_VERSION, meta)?
            .with("state", Prop::Str(meta.state.as_str().into()))
            .with(
                "created_at",
                Prop::Str(meta.created_onchain_at.to_rfc3339()),
            ))
    }

    /// Store a new pool and its owner index row.
    pub async fn create(&self, meta: &PoolMetadata) -> Result<(), StoreError> {
        if self
            .s
            .index()
            .insert(Table::Pools, self.pool_row(meta)?)
            .await?
            == InsertOutcome::Conflict
        {
            return Err(StoreError::Conflict);
        }
        let pointer = Entity::new(owner_pk(&meta.owner_wallet_id), &meta.pool_pda);
        self.s.index().upsert(Table::Pools, pointer).await?;
        Ok(())
    }

    /// The pool and its row's ETag.
    pub async fn get(&self, pool_pda: &str) -> Result<Option<PoolMetadata>, StoreError> {
        Ok(self.get_versioned(pool_pda).await?.map(|(meta, _)| meta))
    }

    async fn get_versioned(
        &self,
        pool_pda: &str,
    ) -> Result<Option<(PoolMetadata, ETag)>, StoreError> {
        self.s
            .get_sealed(Table::Pools, POOL_PK, pool_pda, PAYLOAD_VERSION)
            .await
    }

    /// Apply `change` to the pool by compare-and-swap, retrying on a lost
    /// race. `change` runs again on each retry, against the fresh row, and
    /// may refuse the update by returning an error. Returns `None` if the
    /// pool doesn't exist.
    pub async fn update<E: From<StoreError>>(
        &self,
        pool_pda: &str,
        mut change: impl FnMut(&mut PoolMetadata) -> Result<Change, E>,
    ) -> Result<Option<PoolMetadata>, E> {
        let mut attempt = 0;
        loop {
            attempt += 1;
            let Some((mut meta, etag)) = self.get_versioned(pool_pda).await? else {
                return Ok(None);
            };
            if let Change::Unchanged = change(&mut meta)? {
                return Ok(Some(meta));
            }
            meta.version += 1;
            match self
                .s
                .index()
                .update_if_match(Table::Pools, self.pool_row(&meta)?, &etag)
                .await
            {
                Ok(_) => return Ok(Some(meta)),
                Err(StoreError::PreconditionFailed) if attempt < CAS_ATTEMPTS => {
                    cas_backoff(attempt).await
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// Every pool.
    pub async fn all(&self) -> Result<Vec<PoolMetadata>, StoreError> {
        self.s
            .query_all(Table::Pools, POOL_PK, RkRange::all())
            .await?
            .iter()
            .map(|e| self.s.open_row(Table::Pools, PAYLOAD_VERSION, e))
            .collect()
    }

    /// One page of the pools a wallet owns, in pool PDA order.
    pub async fn owned_by(
        &self,
        wallet_id: &str,
        limit: usize,
        page: Option<Continuation>,
    ) -> Result<Page<PoolMetadata>, StoreError> {
        let pointers = self
            .s
            .query_rows(
                Table::Pools,
                &owner_pk(wallet_id),
                RkRange::all(),
                limit,
                page,
            )
            .await?;
        let mut items = Vec::with_capacity(pointers.items.len());
        for pointer in &pointers.items {
            // The index row isn't authenticated; the pool row decides.
            if let Some(meta) = self.get(&pointer.rk).await? {
                if meta.owner_wallet_id == wallet_id {
                    items.push(meta);
                }
            }
        }
        Ok(Page {
            items,
            next: pointers.next,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::data_validation::FieldType;
    use crate::storage::tests::memory_storage;

    pub(crate) fn pool(pda: &str, owner: &str) -> PoolMetadata {
        PoolMetadata {
            pool_pda: pda.into(),
            pool_name: format!("Pool {pda}"),
            kind: PoolKind::Malta,
            pool_uuid_hex: "00".repeat(16),
            drts: BTreeMap::new(),
            owner_wallet_id: owner.into(),
            owner_pubkey: Some("OwnerPubkey".into()),
            schema_id: "s1".into(),
            schema: vec![FieldSchema {
                name: "id".into(),
                field_type: FieldType::Integer,
                nullable: false,
            }],
            validation_mode: ValidationMode::HeadersOnly,
            state: PoolState::NeedsInit,
            created_onchain_at: Utc::now(),
            initialized_at: None,
            version: 0,
        }
    }

    #[tokio::test]
    async fn pools_are_created_once_and_updated_by_compare_and_swap() {
        let s = memory_storage();
        let pools = s.pools();
        pools.create(&pool("P1", "w1")).await.unwrap();
        assert!(matches!(
            pools.create(&pool("P1", "w1")).await,
            Err(StoreError::Conflict)
        ));

        let updated = pools
            .update::<StoreError>("P1", |m| {
                m.state = PoolState::Ready;
                Ok(Change::Changed)
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!((updated.state, updated.version), (PoolState::Ready, 1));
        let same = pools
            .update::<StoreError>("P1", |_| Ok(Change::Unchanged))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(same.version, 1, "no-op updates don't write");
        assert!(pools
            .update::<StoreError>("nope", |_| Ok(Change::Changed))
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn concurrent_updates_both_land() {
        let (a, b) = crate::storage::tests::two_workers();
        a.pools().create(&pool("P1", "w1")).await.unwrap();
        let rename = |name: &'static str| {
            move |m: &mut PoolMetadata| -> Result<Change, StoreError> {
                m.pool_name.push_str(name);
                Ok(Change::Changed)
            }
        };
        let (pools_a, pools_b) = (a.pools(), b.pools());
        let (x, y) = tokio::join!(
            pools_a.update("P1", rename("-a")),
            pools_b.update("P1", rename("-b"))
        );
        x.unwrap();
        y.unwrap();
        let meta = a.pools().get("P1").await.unwrap().unwrap();
        assert_eq!(meta.version, 2);
        assert!(meta.pool_name.contains("-a") && meta.pool_name.contains("-b"));
    }

    #[tokio::test]
    async fn owner_listing_pages_and_ignores_forged_pointers() {
        let s = memory_storage();
        for i in 0..3 {
            s.pools()
                .create(&pool(&format!("P{i}"), "w1"))
                .await
                .unwrap();
        }
        s.pools().create(&pool("Q", "w2")).await.unwrap();
        // A pointer for w1 to a pool w1 doesn't own.
        s.index()
            .upsert(Table::Pools, Entity::new(owner_pk("w1"), "Q"))
            .await
            .unwrap();

        let first = s.pools().owned_by("w1", 2, None).await.unwrap();
        let second = s.pools().owned_by("w1", 2, first.next).await.unwrap();
        let pdas: Vec<_> = first
            .items
            .iter()
            .chain(&second.items)
            .map(|p| p.pool_pda.as_str())
            .collect();
        assert_eq!(pdas, ["P0", "P1", "P2"]);
        assert_eq!(s.pools().all().await.unwrap().len(), 4);
    }
}
