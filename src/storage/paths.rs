// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Filesystem path helpers for structured storage layout.

use std::path::{Path, PathBuf};

/// Encapsulates the `/data` directory structure.
#[derive(Debug, Clone)]
pub struct StoragePaths {
    root: PathBuf,
}

impl StoragePaths {
    /// Create paths rooted at the given directory.
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
        }
    }

    /// Root data directory (`/data`).
    pub fn root(&self) -> &Path {
        &self.root
    }

    // ── Wallets ──────────────────────────────────────────────────

    /// `/data/wallets/`
    pub fn wallets_dir(&self) -> PathBuf {
        self.root.join("wallets")
    }

    /// `/data/wallets/{wallet_id}/`
    pub fn wallet_dir(&self, wallet_id: &str) -> PathBuf {
        self.wallets_dir().join(wallet_id)
    }

    /// `/data/wallets/{wallet_id}/meta.json`
    pub fn wallet_meta(&self, wallet_id: &str) -> PathBuf {
        self.wallet_dir(wallet_id).join("meta.json")
    }

    /// `/data/wallets/{wallet_id}/keypair.json`
    pub fn wallet_keypair(&self, wallet_id: &str) -> PathBuf {
        self.wallet_dir(wallet_id).join("keypair.json")
    }

    // ── Audit ────────────────────────────────────────────────────

    /// `/data/audit/`
    pub fn audit_dir(&self) -> PathBuf {
        self.root.join("audit")
    }

    /// `/data/audit/{date}.jsonl` (e.g., `2026-02-24.jsonl`).
    pub fn audit_events_file(&self, date: &str) -> PathBuf {
        self.audit_dir().join(format!("{date}.jsonl"))
    }

    // ── Pools ─────────────────────────────────────────────────────

    /// `/data/pools/`
    pub fn pools_dir(&self) -> PathBuf {
        self.root.join("pools")
    }

    /// `/data/pools/{pool_pda}/`
    pub fn pool_dir(&self, pda: &str) -> PathBuf {
        self.pools_dir().join(pda)
    }

    /// `/data/pools/{pool_pda}/dataset/`
    pub fn pool_dataset_dir(&self, pda: &str) -> PathBuf {
        self.pool_dir(pda).join("dataset")
    }

    /// `/data/pools/{pool_pda}/pool.meta.json`
    pub fn pool_meta(&self, pda: &str) -> PathBuf {
        self.pool_dir(pda).join("pool.meta.json")
    }

    /// `/data/pools/{pool_pda}/revocations.jsonl`
    pub fn pool_revocations(&self, pda: &str) -> PathBuf {
        self.pool_dir(pda).join("revocations.jsonl")
    }

    /// `/data/pools/{pool_pda}/schema.json`
    pub fn pool_schema(&self, pda: &str) -> PathBuf {
        self.pool_dir(pda).join("schema.json")
    }

    // ── Transaction DB ───────────────────────────────────────────

    /// `/data/tx.redb`
    pub fn tx_db_path(&self) -> PathBuf {
        self.root.join("tx.redb")
    }
}
