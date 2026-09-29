// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! [`ObjectStore`] on local files, for `just dev` and tests.
//!
//! Each container is a directory, each object a file, and an object's ETag
//! is the SHA-256 of its bytes. Writes go to a temporary file first: a
//! create-only put publishes it with a hard link, which fails if the name is
//! taken, and a compare-and-swap put checks the ETag and renames it, under
//! one lock. That serves one process, which is why the three-worker stack
//! uses Azurite instead.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use bytes::Bytes;
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

use super::{
    check_path, BoxFuture, Created, ETag, Fetched, Listed, ObjectStore, Replaced, StoreError,
};

/// Temporary files, inside the container so renames stay on one filesystem.
const TMP_DIR: &str = ".tmp";

/// One container in a directory.
pub struct LocalFiles {
    root: PathBuf,
    writes: Mutex<()>,
    /// Remove the directory when dropped (test stores).
    remove_on_drop: bool,
}

fn io_error(what: &str, path: &Path, e: std::io::Error) -> StoreError {
    StoreError::Unavailable(format!("{what} {}: {e}", path.display()))
}

fn etag_of(bytes: &[u8]) -> ETag {
    ETag(format!("\"{}\"", hex::encode(Sha256::digest(bytes))))
}

impl LocalFiles {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            writes: Mutex::new(()),
            remove_on_drop: false,
        }
    }

    /// A store in a fresh temporary directory, removed when it's dropped.
    #[cfg(test)]
    pub fn temporary() -> Self {
        let root = std::env::temp_dir().join(format!(
            "relational-tee-test-{}",
            uuid::Uuid::new_v4().simple()
        ));
        let mut store = Self::new(root);
        store.remove_on_drop = true;
        store
    }

    fn file(&self, path: &str) -> Result<PathBuf, StoreError> {
        check_path(path)?;
        Ok(self.root.join(path))
    }

    /// Write `body` to a new temporary file and return its path.
    fn stage(&self, body: &[u8]) -> Result<PathBuf, StoreError> {
        let dir = self.root.join(TMP_DIR);
        std::fs::create_dir_all(&dir).map_err(|e| io_error("creating", &dir, e))?;
        let tmp = dir.join(uuid::Uuid::new_v4().simple().to_string());
        std::fs::write(&tmp, body).map_err(|e| io_error("writing", &tmp, e))?;
        Ok(tmp)
    }

    fn read(file: &Path) -> Result<Option<Vec<u8>>, StoreError> {
        match std::fs::read(file) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io_error("reading", file, e)),
        }
    }

    fn create(&self, path: &str, body: &[u8]) -> Result<Created, StoreError> {
        let file = self.file(path)?;
        if let Some(parent) = file.parent() {
            std::fs::create_dir_all(parent).map_err(|e| io_error("creating", parent, e))?;
        }
        let tmp = self.stage(body)?;
        let linked = std::fs::hard_link(&tmp, &file);
        let _ = std::fs::remove_file(&tmp);
        match linked {
            Ok(()) => Ok(Created::New(etag_of(body))),
            Err(e) if e.kind() == ErrorKind::AlreadyExists => Ok(Created::AlreadyExists),
            Err(e) => Err(io_error("creating", &file, e)),
        }
    }

    fn replace(&self, path: &str, body: &[u8], etag: &ETag) -> Result<Replaced, StoreError> {
        let file = self.file(path)?;
        let _guard = self.writes.lock().unwrap_or_else(|p| p.into_inner());
        match Self::read(&file)? {
            Some(current) if etag_of(&current) == *etag => {}
            _ => return Ok(Replaced::Stale),
        }
        let tmp = self.stage(body)?;
        std::fs::rename(&tmp, &file).map_err(|e| io_error("replacing", &file, e))?;
        Ok(Replaced::Done(etag_of(body)))
    }

    fn listing(&self, dir: &str) -> Result<Vec<Listed>, StoreError> {
        if !dir.ends_with('/') {
            return Err(StoreError::Invalid(format!("{dir:?} isn't a directory")));
        }
        check_path(dir)?;
        let path = self.root.join(dir);
        let entries = match std::fs::read_dir(&path) {
            Ok(entries) => entries,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(io_error("listing", &path, e)),
        };
        let mut listed = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| io_error("listing", &path, e))?;
            let meta = entry
                .metadata()
                .map_err(|e| io_error("listing", &path, e))?;
            let Some(name) = entry.file_name().to_str().map(String::from) else {
                continue;
            };
            if !meta.is_file() || name.starts_with('.') {
                continue;
            }
            let Some(bytes) = Self::read(&entry.path())? else {
                continue;
            };
            listed.push(Listed {
                path: format!("{dir}{name}"),
                etag: etag_of(&bytes),
                last_modified: meta
                    .modified()
                    .map(DateTime::<Utc>::from)
                    .unwrap_or_default(),
            });
        }
        listed.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(listed)
    }
}

impl Drop for LocalFiles {
    fn drop(&mut self) {
        if self.remove_on_drop {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
}

impl ObjectStore for LocalFiles {
    fn get<'a>(
        &'a self,
        path: &'a str,
        cached: Option<&'a ETag>,
    ) -> BoxFuture<'a, Result<Fetched, StoreError>> {
        let result = self.file(path).and_then(|file| {
            Ok(match Self::read(&file)? {
                None => Fetched::Missing,
                Some(bytes) => {
                    let etag = etag_of(&bytes);
                    if cached == Some(&etag) {
                        Fetched::NotModified
                    } else {
                        Fetched::Found {
                            body: Bytes::from(bytes),
                            etag,
                        }
                    }
                }
            })
        });
        Box::pin(async move { result })
    }

    fn put_if_absent<'a>(
        &'a self,
        path: &'a str,
        body: Bytes,
    ) -> BoxFuture<'a, Result<Created, StoreError>> {
        let result = self.create(path, &body);
        Box::pin(async move { result })
    }

    fn put_if_match<'a>(
        &'a self,
        path: &'a str,
        body: Bytes,
        etag: &'a ETag,
    ) -> BoxFuture<'a, Result<Replaced, StoreError>> {
        let result = self.replace(path, &body, etag);
        Box::pin(async move { result })
    }

    fn list<'a>(&'a self, dir: &'a str) -> BoxFuture<'a, Result<Vec<Listed>, StoreError>> {
        let result = self.listing(dir);
        Box::pin(async move { result })
    }
}
