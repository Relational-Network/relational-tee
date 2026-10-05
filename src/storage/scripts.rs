// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Analysis definitions, by SHA-256: `scripts/{sha256}`, create-only. The
//! name is the integrity claim, so every read hashes the bytes again.

use sha2::{Digest, Sha256};

use super::{Storage, StoreError};

/// Analysis definition storage.
pub struct Scripts<'a> {
    s: &'a Storage,
}

fn path(sha256_hex: &str) -> String {
    format!("scripts/{sha256_hex}")
}

impl<'a> Scripts<'a> {
    pub(crate) fn new(s: &'a Storage) -> Self {
        Self { s }
    }

    /// Store `bytes` under their hash, which is returned.
    pub async fn put(&self, bytes: &[u8]) -> Result<String, StoreError> {
        let hash = hex::encode(Sha256::digest(bytes));
        self.s.state().create(&path(&hash), bytes).await?;
        Ok(hash)
    }

    /// The definition whose SHA-256 is `sha256_hex`.
    pub async fn get(&self, sha256_hex: &str) -> Result<Option<Vec<u8>>, StoreError> {
        let valid = sha256_hex.len() == 64
            && sha256_hex
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c));
        if !valid {
            return Ok(None);
        }
        let Some(doc) = self.s.state().read_immutable(&path(sha256_hex)).await? else {
            return Ok(None);
        };
        if hex::encode(Sha256::digest(doc.plain.as_slice())) != sha256_hex {
            return Err(StoreError::Integrity(format!(
                "scripts/{sha256_hex} doesn't hash to its name"
            )));
        }
        Ok(Some(doc.plain.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use crate::storage::tests::files_storage;
    use crate::storage::StoreError;

    #[tokio::test]
    async fn a_definition_that_no_longer_hashes_to_its_name_is_refused() {
        let storage = files_storage();
        let hash = hex::encode(Sha256::digest(b"analysis_id = \"x\""));
        storage
            .state()
            .create(&format!("scripts/{hash}"), b"analysis_id = \"y\"")
            .await
            .unwrap();
        assert!(matches!(
            storage.scripts().get(&hash).await,
            Err(StoreError::Integrity(_))
        ));
    }

    #[tokio::test]
    async fn definitions_are_stored_and_read_by_their_hash() {
        let storage = files_storage();
        let scripts = storage.scripts();
        let hash = scripts.put(b"analysis_id = \"x\"").await.unwrap();
        assert_eq!(hash.len(), 64);
        assert_eq!(
            scripts.put(b"analysis_id = \"x\"").await.unwrap(),
            hash,
            "storing again is harmless"
        );
        assert_eq!(
            scripts.get(&hash).await.unwrap().as_deref(),
            Some(&b"analysis_id = \"x\""[..])
        );
        assert_eq!(scripts.get(&"0".repeat(64)).await.unwrap(), None);
        assert_eq!(scripts.get("../pools/x").await.unwrap(), None);
    }
}
