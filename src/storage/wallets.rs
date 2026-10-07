// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Custodial wallets.
//!
//! - `wallets/{wallet_id}.json`: owner, address, label and status; created
//!   once, then changed by compare-and-swap.
//! - `wallets/{wallet_id}/keypair`: the Ed25519 keypair, create-only. Key
//!   Vault has no Ed25519 keys, so the worker seals them itself.
//! - `owners/{user_id}.json`: the user's current wallet. There's one per
//!   user, which is what keeps a user to one wallet.
//!
//! Creating a wallet points the owner at it first, then stores the keypair,
//! then the wallet document, so every step can be repeated.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{id, Change, Storage, StoreError};
use crate::store::{Created, Replaced};

/// An owner pointer naming a wallet still missing this long after it was
/// set belongs to a create that died, and can be taken over.
const ABANDONED_AFTER: chrono::Duration = chrono::Duration::minutes(10);
/// Pointer compare-and-swap attempts before giving up.
const POINTER_ATTEMPTS: u32 = 4;

/// Wallet lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum WalletStatus {
    Active,
    Suspended,
    Deleted,
}

/// The wallet document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletMetadata {
    pub wallet_id: String,
    pub owner_user_id: String,
    pub public_address: String,
    pub created_at: DateTime<Utc>,
    pub status: WalletStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// API-facing wallet response (**never** contains private key material).
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct WalletResponse {
    pub wallet_id: String,
    pub public_address: String,
    pub created_at: DateTime<Utc>,
    pub status: WalletStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

impl From<WalletMetadata> for WalletResponse {
    fn from(m: WalletMetadata) -> Self {
        Self {
            wallet_id: m.wallet_id,
            public_address: m.public_address,
            created_at: m.created_at,
            status: m.status,
            label: m.label,
        }
    }
}

/// `owners/{user_id}.json`.
#[derive(Serialize, Deserialize)]
struct OwnerPointer {
    /// `None` once the wallet is deleted.
    wallet_id: Option<String>,
    updated_at: DateTime<Utc>,
}

/// The outcome of [`Wallets::create`].
#[derive(Debug)]
pub enum CreateOutcome {
    Created(WalletMetadata),
    /// The owner has this other wallet.
    OwnerHasWallet(String),
}

/// A new wallet's keypair: its 64 bytes and base58 address.
pub struct NewKeypair {
    pub bytes: Zeroizing<Vec<u8>>,
    pub address: String,
}

fn wallet_path(wallet_id: &str) -> String {
    format!("wallets/{wallet_id}.json")
}

fn keypair_path(wallet_id: &str) -> String {
    format!("wallets/{wallet_id}/keypair")
}

fn owner_path(user_id: &str) -> Result<String, StoreError> {
    id(user_id)
        .map(|u| format!("owners/{u}.json"))
        .ok_or_else(|| StoreError::Invalid("the user ID can't name an object".into()))
}

/// Wallet storage.
pub struct Wallets<'a> {
    s: &'a Storage,
}

impl<'a> Wallets<'a> {
    pub(crate) fn new(s: &'a Storage) -> Self {
        Self { s }
    }

    /// Create wallet `wallet_id` for `owner`: point the owner at it, store
    /// `keypair` create-only (or reuse one stored by an earlier attempt,
    /// whose address `address_of` reads), then create the wallet document.
    pub async fn create(
        &self,
        owner: &str,
        wallet_id: &str,
        label: Option<String>,
        keypair: NewKeypair,
        address_of: impl Fn(&[u8]) -> Option<String>,
    ) -> Result<CreateOutcome, StoreError> {
        if let Some(other) = self.point_owner_at(owner, wallet_id).await? {
            return Ok(CreateOutcome::OwnerHasWallet(other));
        }

        let state = self.s.state();
        let address = match state
            .create(&keypair_path(wallet_id), &keypair.bytes)
            .await?
        {
            Created::New(_) => keypair.address,
            Created::AlreadyExists => {
                let stored = self.read_keypair(wallet_id).await?;
                address_of(&stored).ok_or_else(|| {
                    StoreError::Integrity(format!("wallet {wallet_id}'s keypair doesn't parse"))
                })?
            }
        };

        let wallet = WalletMetadata {
            wallet_id: wallet_id.to_string(),
            owner_user_id: owner.to_string(),
            public_address: address,
            created_at: Utc::now(),
            status: WalletStatus::Active,
            label,
        };
        match state.create_json(&wallet_path(wallet_id), &wallet).await? {
            Created::New(_) => Ok(CreateOutcome::Created(wallet)),
            Created::AlreadyExists => self
                .get(wallet_id)
                .await?
                .map(CreateOutcome::Created)
                .ok_or_else(|| StoreError::Invalid(format!("wallet {wallet_id} vanished"))),
        }
    }

    /// Point `owner` at `wallet_id`, unless they have another wallet, which
    /// is returned. A pointer to a deleted wallet, or to one still missing
    /// after [`ABANDONED_AFTER`], is taken over.
    async fn point_owner_at(
        &self,
        owner: &str,
        wallet_id: &str,
    ) -> Result<Option<String>, StoreError> {
        let path = owner_path(owner)?;
        let state = self.s.state();
        let mine = OwnerPointer {
            wallet_id: Some(wallet_id.to_string()),
            updated_at: Utc::now(),
        };
        for _ in 0..POINTER_ATTEMPTS {
            let Some((pointer, etag)) = state.get_json::<OwnerPointer>(&path).await? else {
                match state.create_json(&path, &mine).await? {
                    Created::New(_) => return Ok(None),
                    Created::AlreadyExists => continue,
                }
            };
            let replaceable = match &pointer.wallet_id {
                None => true,
                Some(current) if current == wallet_id => return Ok(None),
                Some(current) => match self.get(current).await? {
                    Some(wallet) => wallet.status == WalletStatus::Deleted,
                    None => Utc::now() - pointer.updated_at > ABANDONED_AFTER,
                },
            };
            if !replaceable {
                return Ok(pointer.wallet_id);
            }
            if let Replaced::Done(_) = state.replace_json(&path, &mine, &etag).await? {
                return Ok(None);
            }
        }
        Err(StoreError::Contended)
    }

    pub async fn get(&self, wallet_id: &str) -> Result<Option<WalletMetadata>, StoreError> {
        let Some(wallet_id) = id(wallet_id) else {
            return Ok(None);
        };
        Ok(self
            .s
            .state()
            .get_json(&wallet_path(wallet_id))
            .await?
            .map(|(wallet, _)| wallet))
    }

    /// The wallet the user's owner pointer names, if any.
    pub async fn wallet_id_for_owner(&self, user_id: &str) -> Result<Option<String>, StoreError> {
        Ok(self
            .s
            .state()
            .get_json::<OwnerPointer>(&owner_path(user_id)?)
            .await?
            .and_then(|(pointer, _)| pointer.wallet_id))
    }

    /// Set the wallet's status by compare-and-swap. Returns the wallet, or
    /// `None` if it doesn't exist. Already being in `status` is success.
    pub async fn set_status(
        &self,
        wallet_id: &str,
        status: WalletStatus,
    ) -> Result<Option<WalletMetadata>, StoreError> {
        let Some(wallet_id) = id(wallet_id) else {
            return Ok(None);
        };
        self.s
            .state()
            .update_json::<WalletMetadata, StoreError>(&wallet_path(wallet_id), |w| {
                if w.status == status {
                    return Ok(Change::Unchanged);
                }
                w.status = status;
                Ok(Change::Changed)
            })
            .await
    }

    /// Mark the wallet deleted, then clear its owner's pointer so they can
    /// create another. The keypair is kept.
    pub async fn soft_delete(&self, wallet: &WalletMetadata) -> Result<(), StoreError> {
        self.set_status(&wallet.wallet_id, WalletStatus::Deleted)
            .await?;
        self.s
            .state()
            .update_json::<OwnerPointer, StoreError>(&owner_path(&wallet.owner_user_id)?, |p| {
                if p.wallet_id.as_deref() != Some(&wallet.wallet_id) {
                    return Ok(Change::Unchanged);
                }
                p.wallet_id = None;
                p.updated_at = Utc::now();
                Ok(Change::Changed)
            })
            .await?;
        Ok(())
    }

    /// Every wallet, in wallet ID order.
    pub async fn all(&self) -> Result<Vec<WalletMetadata>, StoreError> {
        self.s
            .state()
            .list_json("wallets/", |p| p.ends_with(".json"))
            .await
    }

    /// The wallet's 64-byte Ed25519 keypair. **Internal use only.**
    pub async fn read_keypair(&self, wallet_id: &str) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        let path = keypair_path(
            id(wallet_id).ok_or_else(|| StoreError::Invalid("invalid wallet ID".into()))?,
        );
        let doc =
            self.s.state().read_immutable(&path).await?.ok_or_else(|| {
                StoreError::Integrity(format!("wallet {wallet_id} has no keypair"))
            })?;
        Ok(Zeroizing::new(doc.plain.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::tests::{files_storage, two_workers};

    fn keypair(seed: u8) -> NewKeypair {
        NewKeypair {
            bytes: Zeroizing::new(vec![seed; 64]),
            address: format!("addr-{seed}"),
        }
    }

    fn address_of(bytes: &[u8]) -> Option<String> {
        Some(format!("addr-{}", bytes[0]))
    }

    async fn create(s: &Storage, owner: &str, wallet_id: &str, seed: u8) -> CreateOutcome {
        s.wallets()
            .create(owner, wallet_id, None, keypair(seed), address_of)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn one_wallet_per_user_until_it_is_deleted() {
        let s = files_storage();
        let CreateOutcome::Created(first) = create(&s, "alice", "w1", 7).await else {
            panic!("created");
        };
        assert_eq!(first.public_address, "addr-7");
        assert!(matches!(
            create(&s, "alice", "w2", 8).await,
            CreateOutcome::OwnerHasWallet(w) if w == "w1"
        ));
        assert_eq!(
            s.wallets()
                .wallet_id_for_owner("alice")
                .await
                .unwrap()
                .as_deref(),
            Some("w1")
        );
        assert_eq!(
            s.wallets().read_keypair("w1").await.unwrap().as_slice(),
            &[7; 64]
        );

        s.wallets().soft_delete(&first).await.unwrap();
        assert_eq!(
            s.wallets().wallet_id_for_owner("alice").await.unwrap(),
            None
        );
        assert_eq!(
            s.wallets().get("w1").await.unwrap().unwrap().status,
            WalletStatus::Deleted
        );
        assert!(matches!(
            create(&s, "alice", "w2", 8).await,
            CreateOutcome::Created(_)
        ));
    }

    #[tokio::test]
    async fn a_repeated_create_reuses_its_keypair_and_document() {
        let (a, b, _files) = two_workers();
        let CreateOutcome::Created(first) = create(&a, "bob", "w1", 1).await else {
            panic!("created");
        };
        // A retry on another worker generates a new keypair but keeps the stored one.
        let CreateOutcome::Created(again) = create(&b, "bob", "w1", 2).await else {
            panic!("the same wallet");
        };
        assert_eq!(again.public_address, first.public_address);
        assert_eq!(
            b.wallets().read_keypair("w1").await.unwrap().as_slice(),
            &[1; 64]
        );
    }

    #[tokio::test]
    async fn a_pointer_to_a_wallet_that_never_appeared_is_taken_over_later() {
        let s = files_storage();
        // Only the pointer of a create that died before its wallet document.
        let stale = OwnerPointer {
            wallet_id: Some("ghost".into()),
            updated_at: Utc::now() - chrono::Duration::minutes(11),
        };
        s.state()
            .create_json("owners/carol.json", &stale)
            .await
            .unwrap();
        assert!(matches!(
            create(&s, "carol", "w9", 9).await,
            CreateOutcome::Created(_)
        ));

        // A fresh one is still in progress, so it isn't.
        let fresh = OwnerPointer {
            wallet_id: Some("pending".into()),
            updated_at: Utc::now(),
        };
        s.state()
            .create_json("owners/dave.json", &fresh)
            .await
            .unwrap();
        assert!(matches!(
            create(&s, "dave", "w10", 10).await,
            CreateOutcome::OwnerHasWallet(w) if w == "pending"
        ));
    }

    #[tokio::test]
    async fn status_changes_are_compare_and_swap_and_idempotent() {
        let s = files_storage();
        create(&s, "erin", "w1", 1).await;
        let suspended = s
            .wallets()
            .set_status("w1", WalletStatus::Suspended)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(suspended.status, WalletStatus::Suspended);
        assert!(s
            .wallets()
            .set_status("nope", WalletStatus::Active)
            .await
            .unwrap()
            .is_none());
        assert!(s.wallets().get("../x").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn wallet_lists_skip_keypairs() {
        let (a, b, _files) = two_workers();
        for (i, owner) in ["u1", "u2", "u3"].iter().enumerate() {
            create(&a, owner, &format!("w{i}"), i as u8).await;
        }
        let ids: Vec<_> = b
            .wallets()
            .all()
            .await
            .unwrap()
            .into_iter()
            .map(|w| w.wallet_id)
            .collect();
        assert_eq!(ids, ["w0", "w1", "w2"]);
    }
}
