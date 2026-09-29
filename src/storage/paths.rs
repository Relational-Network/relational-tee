// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Filesystem path helpers for structured storage layout.

use std::path::{Path, PathBuf};

/// Encapsulates the `DATA_DIR` directory structure.
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

    /// Root data directory (`DATA_DIR`).
    pub fn root(&self) -> &Path {
        &self.root
    }

    // ── Pools ─────────────────────────────────────────────────────

    /// `{data_dir}/pools/`
    pub fn pools_dir(&self) -> PathBuf {
        self.root.join("pools")
    }

    /// `{data_dir}/pools/{pool_pda}/`
    pub fn pool_dir(&self, pda: &str) -> PathBuf {
        self.pools_dir().join(pda)
    }

    /// `{data_dir}/pools/{pool_pda}/dataset/`
    pub fn pool_dataset_dir(&self, pda: &str) -> PathBuf {
        self.pool_dir(pda).join("dataset")
    }

    /// `{data_dir}/pools/{pool_pda}/pool.meta.json`
    pub fn pool_meta(&self, pda: &str) -> PathBuf {
        self.pool_dir(pda).join("pool.meta.json")
    }

    /// `{data_dir}/pools/{pool_pda}/revocations.jsonl`
    pub fn pool_revocations(&self, pda: &str) -> PathBuf {
        self.pool_dir(pda).join("revocations.jsonl")
    }

    /// `{data_dir}/pools/{pool_pda}/schema.json`
    pub fn pool_schema(&self, pda: &str) -> PathBuf {
        self.pool_dir(pda).join("schema.json")
    }

    // ── Transaction DB ───────────────────────────────────────────

    /// `{data_dir}/tx.redb`
    pub fn tx_db_path(&self) -> PathBuf {
        self.root.join("tx.redb")
    }
}
