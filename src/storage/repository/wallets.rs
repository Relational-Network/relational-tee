// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Wallet metadata persistence backed by [`EncryptedStorage`].
//!
//! Each wallet lives in `/data/wallets/{wallet_id}/`:
//! - `meta.json`    — public metadata (owner, address, status, label)
//! - `keypair.json` — 64-byte Ed25519 seed+pubkey array (**never exposed via API**)

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::storage::encrypted_fs::{EncryptedStorage, StorageError, StorageResult};
use crate::storage::ownership::{OwnedResource, OwnershipEnforcer};

// ============================================================================
// Domain types
// ============================================================================

/// Wallet lifecycle status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletStatus {
    Active,
    Suspended,
    Deleted,
}

/// Persisted wallet metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletMetadata {
    pub wallet_id: String,
    pub owner_user_id: String,
    pub public_address: String,
    pub created_at: DateTime<Utc>,
    pub status: WalletStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

impl OwnedResource for WalletMetadata {
    fn owner_user_id(&self) -> &str {
        &self.owner_user_id
    }
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
            status: serde_json::to_value(&m.status)
                .ok()
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_else(|| format!("{:?}", m.status).to_lowercase()),
            label: m.label,
        }
    }
}

// ============================================================================
// Repository
// ============================================================================

/// CRUD operations for wallets backed by encrypted filesystem.
pub struct WalletRepository<'a> {
    storage: &'a EncryptedStorage,
}

impl<'a> WalletRepository<'a> {
    pub fn new(storage: &'a EncryptedStorage) -> Self {
        Self { storage }
    }

    /// Check whether a wallet directory exists.
    pub fn exists(&self, wallet_id: &str) -> bool {
        self.storage
            .exists(self.storage.paths().wallet_meta(wallet_id))
    }

    /// Load wallet metadata.
    pub fn get(&self, wallet_id: &str) -> StorageResult<WalletMetadata> {
        let path = self.storage.paths().wallet_meta(wallet_id);
        self.storage.read_json(&path).map_err(|e| match e {
            StorageError::NotFound(_) => {
                StorageError::NotFound(format!("wallet {wallet_id} not found"))
            }
            other => other,
        })
    }

    /// Load wallet metadata and verify the caller owns it.
    pub fn get_owned(&self, wallet_id: &str, user_sub: &str) -> StorageResult<WalletMetadata> {
        let meta = self.get(wallet_id)?;
        meta.verify_ownership(user_sub)?;
        Ok(meta)
    }

    /// Create a new wallet (metadata + keypair). Fails if wallet already exists.
    pub fn create(&self, metadata: &WalletMetadata, keypair_bytes: &[u8]) -> StorageResult<()> {
        let wallet_id = &metadata.wallet_id;
        if self.exists(wallet_id) {
            return Err(StorageError::AlreadyExists(format!(
                "wallet {wallet_id} already exists"
            )));
        }

        // Create wallet directory.
        self.storage
            .create_dir(self.storage.paths().wallet_dir(wallet_id))?;

        // Write metadata.
        self.storage
            .write_json(self.storage.paths().wallet_meta(wallet_id), metadata)?;

        // Write keypair (as JSON byte array — e.g., [174, 47, 154, …]).
        let keypair_vec: Vec<u8> = keypair_bytes.to_vec();
        self.storage
            .write_json(self.storage.paths().wallet_keypair(wallet_id), &keypair_vec)?;

        Ok(())
    }

    /// Update wallet metadata (preserves keypair).
    pub fn update(&self, metadata: &WalletMetadata) -> StorageResult<()> {
        let wallet_id = &metadata.wallet_id;
        if !self.exists(wallet_id) {
            return Err(StorageError::NotFound(format!(
                "wallet {wallet_id} not found"
            )));
        }
        self.storage
            .write_json(self.storage.paths().wallet_meta(wallet_id), metadata)
    }

    /// Soft-delete: set status to `Deleted` (keypair preserved for recovery).
    pub fn soft_delete(&self, wallet_id: &str) -> StorageResult<()> {
        let mut meta = self.get(wallet_id)?;
        meta.status = WalletStatus::Deleted;
        self.update(&meta)
    }

    /// List all wallets owned by the given user (active + suspended, not deleted).
    #[allow(dead_code)] //TODO
    pub fn list_by_owner(&self, user_id: &str) -> StorageResult<Vec<WalletMetadata>> {
        self.list_all_wallets().map(|wallets| {
            wallets
                .into_iter()
                .filter(|w| w.owner_user_id == user_id && w.status != WalletStatus::Deleted)
                .collect()
        })
    }

    /// List all wallets (admin only).
    pub fn list_all_wallets(&self) -> StorageResult<Vec<WalletMetadata>> {
        let wallet_ids = self.storage.list_dirs(self.storage.paths().wallets_dir())?;
        let mut wallets = Vec::new();
        for id in wallet_ids {
            match self.get(&id) {
                Ok(meta) => wallets.push(meta),
                Err(StorageError::NotFound(_)) => continue, // race or corruption
                Err(e) => return Err(e),
            }
        }
        Ok(wallets)
    }

    /// Read raw keypair bytes (64 bytes for Ed25519). **Internal use only.**
    pub(crate) fn read_keypair(&self, wallet_id: &str) -> StorageResult<Vec<u8>> {
        let path = self.storage.paths().wallet_keypair(wallet_id);
        self.storage
            .read_json::<Vec<u8>>(&path)
            .map_err(|e| match e {
                StorageError::NotFound(_) => {
                    StorageError::NotFound(format!("keypair for wallet {wallet_id} not found"))
                }
                other => other,
            })
    }
}
