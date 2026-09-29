// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Credential pools: one sealed document per pool, `pools/{pool_pda}.json`,
//! holding its metadata, schema, who created it with the creation
//! signature, the initial upload, the issuance log and the revocations. It
//! is the pool's audit trail. Every pool view reads this one document, and
//! every change is a compare-and-swap on it.
//!
//! Each uploaded CSV is its own create-only object,
//! `pools/{pool_pda}/datasets/{upload_id}`.
//!
//! Totals aren't stored: they're computed from the document's own entries,
//! so they can't drift.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{id, Change, Storage, StoreError};
use crate::data_validation::{FieldSchema, ValidationMode};
use crate::store::Created;

/// The record ID of a pool's initial upload.
pub const INITIAL: &str = "initial";

/// Operational shape of the pool.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolKind {
    /// CSV-driven pool. Admin uploads CSVs; schema mandatory, headers-only validation.
    #[default]
    Malta,
}

impl PoolKind {
    pub fn as_str(self) -> &'static str {
        match self {
            PoolKind::Malta => "malta",
        }
    }
}

/// Pool lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// One uploaded dataset: the initialisation or an issuance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Upload {
    /// [`INITIAL`] for the initialisation; the `upload_id` for an issuance.
    pub record_id: String,
    /// Names the dataset object.
    pub upload_id: String,
    /// SHA-256 of the CSV bytes, hex.
    pub sha256: String,
    /// CSV rows, excluding the header.
    pub rows: u64,
    pub uploaded_by: String,
    pub uploaded_at: DateTime<Utc>,
    /// The append-DRT burn, for an issuance: the on-chain anchor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// The grant commitment of that burn, hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commitment: Option<String>,
}

/// A revoked credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revocation {
    pub credential_id: String,
    pub revoked_by: String,
    pub revoked_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// The pool document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolDoc {
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
    pub owner_pubkey: String,
    /// Schema id label.
    pub schema_id: String,
    /// The CSV schema uploads are validated against.
    pub schema: Vec<FieldSchema>,
    /// CSV validation strictness.
    pub validation_mode: ValidationMode,
    /// The `user_id` who created the pool.
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    /// The transaction that created, registered and sealed the pool.
    pub creation_signature: String,
    /// Set once: the pool is `ready` from then on.
    #[serde(default)]
    pub initial: Option<Upload>,
    /// The issuance log, oldest first.
    #[serde(default)]
    pub issuances: Vec<Upload>,
    #[serde(default)]
    pub revocations: Vec<Revocation>,
}

/// Totals computed from a pool document.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Totals {
    /// CSV rows across every upload, initialisation included.
    pub rows: u64,
    pub revoked: u64,
    /// When the newest issuance (not the initialisation) was uploaded.
    pub last_issue_at: Option<DateTime<Utc>>,
}

impl PoolDoc {
    pub fn state(&self) -> PoolState {
        if self.initial.is_some() {
            PoolState::Ready
        } else {
            PoolState::NeedsInit
        }
    }

    pub fn totals(&self) -> Totals {
        Totals {
            rows: self.uploads().map(|u| u.rows).sum(),
            revoked: self.revocations.len() as u64,
            last_issue_at: self.issuances.iter().map(|u| u.uploaded_at).max(),
        }
    }

    /// The initial upload, then every issuance, oldest first.
    pub fn uploads(&self) -> impl DoubleEndedIterator<Item = &Upload> {
        self.initial.iter().chain(&self.issuances)
    }

    pub fn upload(&self, record_id: &str) -> Option<&Upload> {
        self.uploads().find(|u| u.record_id == record_id)
    }

    pub fn is_revoked(&self, credential_id: &str) -> bool {
        self.revocations
            .iter()
            .any(|r| r.credential_id == credential_id)
    }
}

fn doc_path(pool_pda: &str) -> String {
    format!("pools/{pool_pda}.json")
}

fn dataset_path(pool_pda: &str, upload_id: &str) -> String {
    format!("pools/{pool_pda}/datasets/{upload_id}")
}

/// Pool storage.
pub struct Pools<'a> {
    s: &'a Storage,
}

impl<'a> Pools<'a> {
    pub(crate) fn new(s: &'a Storage) -> Self {
        Self { s }
    }

    /// Store a new pool document; `AlreadyExists` if the pool has one.
    pub async fn create(&self, doc: &PoolDoc) -> Result<Created, StoreError> {
        self.s
            .state()
            .create_json(&doc_path(&doc.pool_pda), doc)
            .await
    }

    /// The pool's document, or `None` if there's none (or the PDA can't be one).
    pub async fn get(&self, pool_pda: &str) -> Result<Option<PoolDoc>, StoreError> {
        let Some(pda) = id(pool_pda) else {
            return Ok(None);
        };
        Ok(self
            .s
            .state()
            .get_json(&doc_path(pda))
            .await?
            .map(|(doc, _)| doc))
    }

    /// Apply `change` to the pool's document by compare-and-swap (see
    /// [`crate::store::sealed::Sealed::update_json`]). Returns `None` if the
    /// pool has no document.
    pub async fn update<E: From<StoreError>>(
        &self,
        pool_pda: &str,
        change: impl FnMut(&mut PoolDoc) -> Result<Change, E>,
    ) -> Result<Option<PoolDoc>, E> {
        let Some(pda) = id(pool_pda) else {
            return Ok(None);
        };
        self.s.state().update_json(&doc_path(pda), change).await
    }

    /// Every pool, in PDA order.
    pub async fn all(&self) -> Result<Vec<PoolDoc>, StoreError> {
        self.s
            .state()
            .list_json("pools/", |p| p.ends_with(".json"))
            .await
    }

    /// Store an uploaded CSV, create-only. The worker never reads datasets
    /// back, so they aren't cached.
    pub async fn put_dataset(
        &self,
        pool_pda: &str,
        upload_id: &str,
        csv: &[u8],
    ) -> Result<Created, StoreError> {
        let path = dataset_path(pool_pda, upload_id);
        self.s.state().create_uncached(&path, csv).await
    }

    #[cfg(test)]
    pub async fn read_dataset(
        &self,
        pool_pda: &str,
        upload_id: &str,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self
            .s
            .state()
            .read(&dataset_path(pool_pda, upload_id))
            .await?
            .map(|doc| doc.plain.to_vec()))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::data_validation::FieldType;
    use crate::storage::tests::{files_storage, two_workers};

    pub(crate) fn pool(pda: &str, owner: &str) -> PoolDoc {
        PoolDoc {
            pool_pda: pda.into(),
            pool_name: format!("Pool {pda}"),
            kind: PoolKind::Malta,
            pool_uuid_hex: "00".repeat(16),
            drts: BTreeMap::new(),
            owner_wallet_id: owner.into(),
            owner_pubkey: "OwnerPubkey".into(),
            schema_id: "s1".into(),
            schema: vec![FieldSchema {
                name: "id".into(),
                field_type: FieldType::Integer,
                nullable: false,
            }],
            validation_mode: ValidationMode::HeadersOnly,
            created_by: "alice".into(),
            created_at: Utc::now(),
            creation_signature: "sig-create".into(),
            initial: None,
            issuances: Vec::new(),
            revocations: Vec::new(),
        }
    }

    pub(crate) fn upload(record_id: &str, rows: u64) -> Upload {
        Upload {
            record_id: record_id.into(),
            upload_id: format!("u-{record_id}"),
            sha256: "00".repeat(32),
            rows,
            uploaded_by: "alice".into(),
            uploaded_at: Utc::now(),
            signature: None,
            commitment: None,
        }
    }

    #[tokio::test]
    async fn a_pool_is_created_once_and_its_totals_are_computed() {
        let s = files_storage();
        let pools = s.pools();
        assert!(matches!(
            pools.create(&pool("P1", "w1")).await.unwrap(),
            Created::New(_)
        ));
        assert_eq!(
            pools.create(&pool("P1", "w1")).await.unwrap(),
            Created::AlreadyExists
        );

        let doc = pools
            .update::<StoreError>("P1", |d| {
                d.initial = Some(upload(INITIAL, 3));
                d.issuances.push(upload("r1", 2));
                d.revocations.push(Revocation {
                    credential_id: "r1".into(),
                    revoked_by: "bob".into(),
                    revoked_at: Utc::now(),
                    reason: None,
                });
                Ok(Change::Changed)
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(doc.state(), PoolState::Ready);
        let totals = doc.totals();
        assert_eq!((totals.rows, totals.revoked), (5, 1));
        assert_eq!(totals.last_issue_at, Some(doc.issuances[0].uploaded_at));
        let ids: Vec<_> = doc.uploads().rev().map(|u| u.record_id.as_str()).collect();
        assert_eq!(ids, ["r1", INITIAL]);
        assert!(doc.is_revoked("r1") && !doc.is_revoked(INITIAL));

        assert!(pools.get("../wallets/x").await.unwrap().is_none());
        assert!(pools
            .update::<StoreError>("nope", |_| Ok(Change::Changed))
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn every_worker_sees_the_same_pools_and_datasets_open_only_in_place() {
        let (a, b, _files) = two_workers();
        for pda in ["P2", "P1"] {
            a.pools().create(&pool(pda, "w1")).await.unwrap();
        }
        let pdas: Vec<_> = b
            .pools()
            .all()
            .await
            .unwrap()
            .into_iter()
            .map(|p| p.pool_pda)
            .collect();
        assert_eq!(pdas, ["P1", "P2"]);

        a.pools().put_dataset("P1", "u1", b"id\n1\n").await.unwrap();
        assert_eq!(
            a.pools().put_dataset("P1", "u1", b"id\n2\n").await.unwrap(),
            Created::AlreadyExists
        );
        assert_eq!(
            b.pools().read_dataset("P1", "u1").await.unwrap().unwrap(),
            b"id\n1\n"
        );
    }
}
