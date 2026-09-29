// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Local filesystem adapter.
//!
//! Structured JSON + raw I/O with atomic writes (write-to-temp then rename).
//! Files are plaintext on disk until envelope-encrypted Azure Storage
//! replaces this module.

use serde::{de::DeserializeOwned, Serialize};
use std::fs;
use std::io;
use std::path::Path;
use tracing::{debug, error};

use super::paths::StoragePaths;

/// Storage error kinds.
#[derive(Debug)]
pub enum StorageError {
    /// Underlying I/O failure.
    Io(io::Error),
    /// JSON (de)serialization failure.
    Json(serde_json::Error),
    /// Requested resource does not exist.
    NotFound(String),
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Json(e) => write!(f, "JSON error: {e}"),
            Self::NotFound(r) => write!(f, "not found: {r}"),
        }
    }
}

impl std::error::Error for StorageError {}

impl From<io::Error> for StorageError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<serde_json::Error> for StorageError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

/// Convert `StorageError` into an [`ApiError`](crate::error::ApiError).
impl From<StorageError> for crate::error::ApiError {
    fn from(e: StorageError) -> Self {
        match &e {
            StorageError::NotFound(msg) => Self::not_found(msg.clone()),
            StorageError::Io(_) | StorageError::Json(_) => {
                error!(error = %e, "Storage error");
                Self::internal("internal storage error")
            }
        }
    }
}

/// Result alias for storage operations.
pub type StorageResult<T> = Result<T, StorageError>;

/// Storage rooted at the configured data directory, using plain `std::fs`.
pub struct EncryptedStorage {
    paths: StoragePaths,
}

impl EncryptedStorage {
    /// Create storage at the given root directory.
    pub fn new(data_dir: impl AsRef<Path>) -> Self {
        Self {
            paths: StoragePaths::new(data_dir),
        }
    }

    /// Create required top-level directories. Call once at server startup.
    pub fn initialize(&mut self) -> StorageResult<()> {
        let dir = self.paths.pools_dir();
        fs::create_dir_all(&dir)?;
        debug!(path = %dir.display(), "Ensured storage directory");
        Ok(())
    }

    /// Return a reference to the underlying path helpers.
    pub fn paths(&self) -> &StoragePaths {
        &self.paths
    }

    // ── JSON I/O ──────────────────────────────────────────────────

    /// Read and deserialize a JSON file.
    pub fn read_json<T: DeserializeOwned>(&self, path: impl AsRef<Path>) -> StorageResult<T> {
        let path = path.as_ref();
        let data = fs::read(path).map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                StorageError::NotFound(path.display().to_string())
            } else {
                StorageError::Io(e)
            }
        })?;
        Ok(serde_json::from_slice(&data)?)
    }

    /// Serialize and write a JSON file atomically (write-to-temp + rename).
    pub fn write_json<T: Serialize>(&self, path: impl AsRef<Path>, value: &T) -> StorageResult<()> {
        let path = path.as_ref();
        let data = serde_json::to_vec_pretty(value)?;
        self.atomic_write(path, &data)
    }

    // ── Raw I/O ───────────────────────────────────────────────────

    /// Write raw bytes atomically.
    pub fn write_raw(&self, path: impl AsRef<Path>, data: &[u8]) -> StorageResult<()> {
        self.atomic_write(path.as_ref(), data)
    }

    // ── File / directory helpers ───────────────────────────────────

    /// Check if a path exists.
    pub fn exists(&self, path: impl AsRef<Path>) -> bool {
        path.as_ref().exists()
    }

    /// Create a directory (+ parents).
    pub fn create_dir(&self, path: impl AsRef<Path>) -> StorageResult<()> {
        Ok(fs::create_dir_all(path.as_ref())?)
    }

    // ── Internal helpers ──────────────────────────────────────────

    /// Atomic write: write to a `.tmp` sibling, then rename.
    fn atomic_write(&self, path: &Path, data: &[u8]) -> StorageResult<()> {
        // Ensure parent directory exists.
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let tmp = path.with_extension("tmp");
        fs::write(&tmp, data)?;
        fs::rename(&tmp, path)?;
        Ok(())
    }
}
