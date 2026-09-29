// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Custodial wallets.
//!
//! - Blob `wallets/{wallet_id}/keypair.enc`: the Ed25519 keypair in an
//!   envelope; create-only. Key Vault has no Ed25519 keys, so the worker
//!   encrypts them itself.
//! - Table `wallets`: `wallet` / `{wallet_id}` holds the metadata; the owner
//!   index `owner:{h(user_id)}` / `wallet` holds one row per user, so a user
//!   has at most one wallet; the address index `addr` / `{public_address}`
//!   maps on-chain addresses back to wallets.
//!
//! Status changes are compare-and-swap writes, retried a few times on
//! conflict. Plaintext `status` and `created_at` properties are copies for
//! filtering; the worker only trusts the encrypted payload.

use std::time::Duration;

use bytes::Bytes;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::warn;
use zeroize::Zeroizing;

use super::store::{
    Container, Continuation, ETag, InsertOutcome, Page, Prop, PutOutcome, RkRange, StoreError,
    Table,
};
use super::Storage;

const WALLET_PK: &str = "wallet";
const OWNER_RK: &str = "wallet";
const ADDRESS_PK: &str = "addr";
const PAYLOAD_VERSION: u32 = 1;
/// Compare-and-swap attempts (the first try and three retries) before a write
/// gives up with a conflict.
pub(crate) const CAS_ATTEMPTS: u32 = 4;

/// Wallet lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletStatus {
    Active,
    Suspended,
    Deleted,
}

impl WalletStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            WalletStatus::Active => "active",
            WalletStatus::Suspended => "suspended",
            WalletStatus::Deleted => "deleted",
        }
    }
}

/// Wallet metadata: the encrypted payload of a `wallet` row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletMetadata {
    pub wallet_id: String,
    pub owner_user_id: String,
    pub public_address: String,
    pub created_at: DateTime<Utc>,
    pub status: WalletStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Incremented on every update.
    #[serde(default)]
    pub version: u64,
}

/// API-facing wallet response (**never** contains private key material).
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct WalletResponse {
    pub wallet_id: String,
    pub public_address: String,
    pub created_at: DateTime<Utc>,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

impl From<WalletMetadata> for WalletResponse {
    fn from(m: WalletMetadata) -> Self {
        Self {
            wallet_id: m.wallet_id,
            public_address: m.public_address,
            created_at: m.created_at,
            status: m.status.as_str().to_string(),
            label: m.label,
        }
    }
}

/// The payload of an index row: the wallet it points to.
#[derive(Serialize, Deserialize)]
struct WalletPointer {
    wallet_id: String,
}

/// The outcome of [`Wallets::create`].
#[derive(Debug, PartialEq, Eq)]
pub enum CreateOutcome {
    Created,
    /// The owner already has this (non-deleted) wallet.
    OwnerHasWallet(String),
}

/// Wallet storage.
pub struct Wallets<'a> {
    s: &'a Storage,
}

fn keypair_path(wallet_id: &str) -> String {
    format!("{wallet_id}/keypair.enc")
}

/// A short random pause before retrying a lost compare-and-swap.
pub(crate) async fn cas_backoff(attempt: u32) {
    use p256::elliptic_curve::rand_core::{OsRng, RngCore};
    let millis = 20 * u64::from(attempt) + u64::from(OsRng.next_u32() % 50);
    tokio::time::sleep(Duration::from_millis(millis)).await;
}

impl<'a> Wallets<'a> {
    pub(crate) fn new(s: &'a Storage) -> Self {
        Self { s }
    }

    fn owner_pk(&self, user_id: &str) -> String {
        format!("owner:{}", self.s.keys().index_hash(user_id))
    }

    fn wallet_row(&self, meta: &WalletMetadata) -> Result<super::store::Entity, StoreError> {
        Ok(self
            .s
            .sealed_row(
                Table::Wallets,
                WALLET_PK,
                &meta.wallet_id,
                PAYLOAD_VERSION,
                meta,
            )?
            .with("status", Prop::Str(meta.status.as_str().into()))
            .with("created_at", Prop::Str(meta.created_at.to_rfc3339())))
    }

    /// Create a wallet: first claim the owner's index row (one wallet per
    /// user), then store the keypair create-only, then the wallet and address
    /// rows. An index row left by an interrupted create, or pointing at a
    /// deleted wallet, is taken over.
    pub async fn create(
        &self,
        meta: &WalletMetadata,
        keypair: &[u8],
    ) -> Result<CreateOutcome, StoreError> {
        let owner_pk = self.owner_pk(&meta.owner_user_id);
        let pointer = WalletPointer {
            wallet_id: meta.wallet_id.clone(),
        };
        let owner_row = self.s.sealed_row(
            Table::Wallets,
            &owner_pk,
            OWNER_RK,
            PAYLOAD_VERSION,
            &pointer,
        )?;
        let mut attempt = 0;
        loop {
            attempt += 1;
            match self
                .s
                .index()
                .insert(Table::Wallets, owner_row.clone())
                .await?
            {
                InsertOutcome::Inserted(_) => break,
                InsertOutcome::Conflict => {}
            }
            let Some((existing, etag)) = self
                .s
                .get_sealed::<WalletPointer>(Table::Wallets, &owner_pk, OWNER_RK, PAYLOAD_VERSION)
                .await?
            else {
                continue; // deleted in between: try the insert again
            };
            if let Some(wallet) = self.get(&existing.wallet_id).await? {
                if wallet.status != WalletStatus::Deleted {
                    return Ok(CreateOutcome::OwnerHasWallet(existing.wallet_id));
                }
            }
            match self
                .s
                .index()
                .update_if_match(Table::Wallets, owner_row.clone(), &etag)
                .await
            {
                Ok(_) => break,
                Err(StoreError::PreconditionFailed | StoreError::NotFound)
                    if attempt < CAS_ATTEMPTS =>
                {
                    cas_backoff(attempt).await
                }
                Err(e) => return Err(e),
            }
        }

        let path = keypair_path(&meta.wallet_id);
        let sealed = self.s.keys().seal_blob(Container::Wallets, &path, keypair);
        if self
            .s
            .objects()
            .put_if_absent(Container::Wallets, &path, Bytes::from(sealed))
            .await?
            == PutOutcome::AlreadyExists
        {
            return Err(StoreError::Invalid(format!(
                "wallet {} already has a keypair",
                meta.wallet_id
            )));
        }
        if self
            .s
            .index()
            .insert(Table::Wallets, self.wallet_row(meta)?)
            .await?
            == InsertOutcome::Conflict
        {
            return Err(StoreError::Invalid(format!(
                "wallet {} already exists",
                meta.wallet_id
            )));
        }
        let address_row = self.s.sealed_row(
            Table::Wallets,
            ADDRESS_PK,
            &meta.public_address,
            PAYLOAD_VERSION,
            &pointer,
        )?;
        self.s.index().upsert(Table::Wallets, address_row).await?;
        Ok(CreateOutcome::Created)
    }

    /// The wallet and its row's ETag.
    async fn get_versioned(
        &self,
        wallet_id: &str,
    ) -> Result<Option<(WalletMetadata, ETag)>, StoreError> {
        self.s
            .get_sealed(Table::Wallets, WALLET_PK, wallet_id, PAYLOAD_VERSION)
            .await
    }

    pub async fn get(&self, wallet_id: &str) -> Result<Option<WalletMetadata>, StoreError> {
        Ok(self.get_versioned(wallet_id).await?.map(|(meta, _)| meta))
    }

    /// The ID of the user's wallet, if they have one.
    pub async fn wallet_id_for_owner(&self, user_id: &str) -> Result<Option<String>, StoreError> {
        Ok(self
            .s
            .get_sealed::<WalletPointer>(
                Table::Wallets,
                &self.owner_pk(user_id),
                OWNER_RK,
                PAYLOAD_VERSION,
            )
            .await?
            .map(|(pointer, _)| pointer.wallet_id))
    }

    /// Set the wallet's status by compare-and-swap. Returns the updated
    /// wallet, or `None` if it doesn't exist. Already being in the target
    /// status counts as success.
    pub async fn set_status(
        &self,
        wallet_id: &str,
        status: WalletStatus,
    ) -> Result<Option<WalletMetadata>, StoreError> {
        let mut attempt = 0;
        loop {
            attempt += 1;
            let Some((mut meta, etag)) = self.get_versioned(wallet_id).await? else {
                return Ok(None);
            };
            if meta.status == status {
                return Ok(Some(meta));
            }
            meta.status = status;
            meta.version += 1;
            match self
                .s
                .index()
                .update_if_match(Table::Wallets, self.wallet_row(&meta)?, &etag)
                .await
            {
                Ok(_) => return Ok(Some(meta)),
                Err(StoreError::PreconditionFailed) if attempt < CAS_ATTEMPTS => {
                    cas_backoff(attempt).await
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Mark the wallet deleted, then drop its owner's index row so the owner
    /// can create another. The keypair is kept.
    pub async fn soft_delete(&self, wallet: &WalletMetadata) -> Result<(), StoreError> {
        self.set_status(&wallet.wallet_id, WalletStatus::Deleted)
            .await?;
        let owner_pk = self.owner_pk(&wallet.owner_user_id);
        if let Some((pointer, etag)) = self
            .s
            .get_sealed::<WalletPointer>(Table::Wallets, &owner_pk, OWNER_RK, PAYLOAD_VERSION)
            .await?
        {
            if pointer.wallet_id == wallet.wallet_id {
                match self
                    .s
                    .index()
                    .delete_if_match(Table::Wallets, &owner_pk, OWNER_RK, &etag)
                    .await
                {
                    // A concurrent create already took the row over.
                    Ok(()) | Err(StoreError::PreconditionFailed | StoreError::NotFound) => {}
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(())
    }

    /// One page of all wallets, in wallet ID order.
    pub async fn list(
        &self,
        limit: usize,
        page: Option<Continuation>,
    ) -> Result<Page<WalletMetadata>, StoreError> {
        let rows = self
            .s
            .query_rows(Table::Wallets, WALLET_PK, RkRange::all(), None, limit, page)
            .await?;
        Ok(Page {
            items: rows
                .items
                .iter()
                .map(|e| self.s.open_row(Table::Wallets, PAYLOAD_VERSION, e))
                .collect::<Result<_, _>>()?,
            next: rows.next,
        })
    }

    /// Every wallet.
    pub async fn all(&self) -> Result<Vec<WalletMetadata>, StoreError> {
        self.s
            .query_all(Table::Wallets, WALLET_PK, RkRange::all(), None)
            .await?
            .iter()
            .map(|e| self.s.open_row(Table::Wallets, PAYLOAD_VERSION, e))
            .collect()
    }

    /// The wallet's 64-byte Ed25519 keypair. **Internal use only.**
    pub async fn read_keypair(&self, wallet_id: &str) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        let path = keypair_path(wallet_id);
        let object = self
            .s
            .objects()
            .get(Container::Wallets, &path)
            .await?
            .ok_or(StoreError::NotFound)?;
        self.s
            .keys()
            .open_blob(Container::Wallets, &path, &object.body)
    }

    /// The wallet that owns an on-chain address, if it's one of ours.
    pub async fn wallet_id_for_address(&self, address: &str) -> Result<Option<String>, StoreError> {
        Ok(self
            .s
            .get_sealed::<WalletPointer>(Table::Wallets, ADDRESS_PK, address, PAYLOAD_VERSION)
            .await?
            .map(|(pointer, _)| pointer.wallet_id))
    }

    /// Every `(address, wallet_id)` pair.
    pub async fn addresses(&self) -> Result<Vec<(String, String)>, StoreError> {
        let rows = self
            .s
            .query_all(Table::Wallets, ADDRESS_PK, RkRange::all(), None)
            .await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            match self
                .s
                .open_row::<WalletPointer>(Table::Wallets, PAYLOAD_VERSION, &row)
            {
                Ok(pointer) => out.push((row.rk.clone(), pointer.wallet_id)),
                Err(e) => {
                    warn!(address = %row.rk, error = %e, "Skipping an unreadable address row")
                }
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::memory::MemoryStore;
    use crate::storage::tests::memory_storage;
    use crate::storage::StorageKeys;
    use crate::tee::tests::fixed_key;
    use std::sync::Arc;

    fn wallet(id: &str, owner: &str) -> WalletMetadata {
        WalletMetadata {
            wallet_id: id.into(),
            owner_user_id: owner.into(),
            public_address: format!("addr-{id}"),
            created_at: Utc::now(),
            status: WalletStatus::Active,
            label: None,
            version: 0,
        }
    }

    #[tokio::test]
    async fn one_wallet_per_user_until_it_is_deleted() {
        let s = memory_storage();
        let wallets = s.wallets();
        let first = wallet("w1", "alice");
        assert_eq!(
            wallets.create(&first, &[7; 64]).await.unwrap(),
            CreateOutcome::Created
        );
        assert_eq!(
            wallets
                .create(&wallet("w2", "alice"), &[8; 64])
                .await
                .unwrap(),
            CreateOutcome::OwnerHasWallet("w1".into())
        );
        assert_eq!(
            wallets
                .wallet_id_for_owner("alice")
                .await
                .unwrap()
                .as_deref(),
            Some("w1")
        );
        assert_eq!(
            wallets.read_keypair("w1").await.unwrap().as_slice(),
            &[7; 64]
        );
        assert_eq!(
            wallets
                .wallet_id_for_address("addr-w1")
                .await
                .unwrap()
                .as_deref(),
            Some("w1")
        );

        wallets.soft_delete(&first).await.unwrap();
        assert_eq!(wallets.wallet_id_for_owner("alice").await.unwrap(), None);
        assert_eq!(
            wallets.get("w1").await.unwrap().unwrap().status,
            WalletStatus::Deleted
        );
        assert_eq!(
            wallets
                .create(&wallet("w2", "alice"), &[8; 64])
                .await
                .unwrap(),
            CreateOutcome::Created
        );
    }

    #[tokio::test]
    async fn an_index_row_left_by_an_interrupted_create_is_taken_over() {
        let s = memory_storage();
        let wallets = s.wallets();
        // Only the owner index row of a create that died before the wallet row.
        let pointer = WalletPointer {
            wallet_id: "ghost".into(),
        };
        let row = s
            .sealed_row(
                Table::Wallets,
                &wallets.owner_pk("bob"),
                OWNER_RK,
                PAYLOAD_VERSION,
                &pointer,
            )
            .unwrap();
        s.index().insert(Table::Wallets, row).await.unwrap();

        assert_eq!(
            wallets
                .create(&wallet("w9", "bob"), &[1; 64])
                .await
                .unwrap(),
            CreateOutcome::Created
        );
        assert_eq!(
            wallets.wallet_id_for_owner("bob").await.unwrap().as_deref(),
            Some("w9")
        );
    }

    #[tokio::test]
    async fn status_changes_are_compare_and_swap_and_idempotent() {
        let s = memory_storage();
        let wallets = s.wallets();
        wallets
            .create(&wallet("w1", "carol"), &[1; 64])
            .await
            .unwrap();
        let suspended = wallets
            .set_status("w1", WalletStatus::Suspended)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(suspended.version, 1);
        let again = wallets
            .set_status("w1", WalletStatus::Suspended)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(again.version, 1, "already in the target status: no write");
        assert!(wallets
            .set_status("nope", WalletStatus::Active)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn storage_sees_no_owner_ids_and_tampered_rows_fail() {
        let store = Arc::new(MemoryStore::new());
        let s = Storage::new(
            store.clone(),
            store.clone(),
            StorageKeys::derive(&fixed_key(1)),
            "w".into(),
        );
        s.wallets()
            .create(&wallet("w1", "user_2abcSECRET"), &[1; 64])
            .await
            .unwrap();
        let owner_pk = s.wallets().owner_pk("user_2abcSECRET");
        assert!(!owner_pk.contains("SECRET"));

        // A storage admin flips the plaintext status: the payload still rules.
        store.tamper_row(Table::Wallets, WALLET_PK, "w1", |props| {
            props.insert("status".into(), Prop::Str("suspended".into()));
        });
        assert_eq!(
            s.wallets().get("w1").await.unwrap().unwrap().status,
            WalletStatus::Active
        );

        // Moving the payload to another row fails the AAD.
        let payload = s
            .index()
            .get(Table::Wallets, WALLET_PK, "w1")
            .await
            .unwrap()
            .unwrap();
        let mut moved = payload.clone();
        moved.rk = "w2".into();
        s.index().upsert(Table::Wallets, moved).await.unwrap();
        assert!(matches!(
            s.wallets().get("w2").await,
            Err(StoreError::Integrity(_))
        ));
    }

    #[tokio::test]
    async fn wallet_lists_page_with_cursors_across_workers() {
        let (a, b) = crate::storage::tests::two_workers();
        for i in 0..5 {
            a.wallets()
                .create(&wallet(&format!("w{i}"), &format!("user{i}")), &[1; 64])
                .await
                .unwrap();
        }
        let first = a.wallets().list(2, None).await.unwrap();
        assert_eq!(first.items.len(), 2);
        let cursor = a.sign_cursor("wallets", first.next.as_ref().unwrap());
        let page = b.page_from("wallets", Some(&cursor)).unwrap();
        let second = b.wallets().list(2, page).await.unwrap();
        let ids: Vec<_> = first
            .items
            .iter()
            .chain(&second.items)
            .map(|w| w.wallet_id.as_str())
            .collect();
        assert_eq!(ids, ["w0", "w1", "w2", "w3"]);
        assert_eq!(b.wallets().all().await.unwrap().len(), 5);
    }
}
