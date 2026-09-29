// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Local storage layer rooted at `DATA_DIR`.
//!
//! Files are written with plain `std::fs` and are **not encrypted** on disk,
//! so local storage holds synthetic data only, until it is replaced with
//! envelope-encrypted Azure Blob and Table storage.
//!
//! # Layout
//!
//! ```text
//! {DATA_DIR}/
//! ├── wallets/{wallet_id}/
//! │   ├── meta.json
//! │   └── keypair.json
//! ├── pools/{pool_pda}/
//! │   ├── pool.meta.json
//! │   ├── dataset/
//! │   │   ├── initial.csv
//! │   │   ├── initial.meta.json     # DatasetAnchor: sha256 + record_id
//! │   │   ├── {uuid}.csv
//! │   │   └── {uuid}.meta.json      # DatasetAnchor: sha256 + commitment + record_id
//! │   └── revocations.jsonl
//! ├── audit/
//! │   ├── .hmac-key
//! │   └── 2026-02-24.jsonl
//! └── tx.redb
//! ```

pub mod audit;
pub mod encrypted_fs;
pub mod ownership;
pub mod paths;
pub mod pool_metadata;
pub mod repository;
pub mod tx_cache;
pub mod tx_database;

// Re-exports for convenience.
pub use encrypted_fs::EncryptedStorage;
pub use paths::StoragePaths;
