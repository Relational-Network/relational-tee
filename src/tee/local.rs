// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! `KEY_PROVIDER=local` (dev builds only): keys come from dev key files
//! instead of the SKR sidecar, and attestation tokens are signed with the dev
//! MAA key.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde_json::Value;

use super::dev_keys::{key_path, previous_key_path, read_key};
use super::dev_maa::{DevMaa, DEFAULT_ISSUER};
use super::{
    AttestError, AttestationProvider, BoxFuture, KeyError, KeyName, KeyProvider, PreviousKey,
    ReleasedKey,
};

/// Reads `{dir}/{name}.jwk`, and `{dir}/{name}.previous.jwk` if present.
/// The current version replaced the previous one when `{name}.jwk` was last
/// written, so rotating a dev key means moving `{name}.jwk` to
/// `{name}.previous.jwk` and creating a new `{name}.jwk`.
pub struct LocalDev {
    dir: PathBuf,
}

impl LocalDev {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }
}

/// When `path` was last written.
fn modified(path: &Path) -> Result<DateTime<Utc>, KeyError> {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .map(DateTime::<Utc>::from)
        .map_err(|e| {
            KeyError::fatal(format!(
                "dev key {} has no modification time: {e}",
                path.display()
            ))
        })
}

impl KeyProvider for LocalDev {
    fn release(&self, key: KeyName) -> BoxFuture<'_, Result<ReleasedKey, KeyError>> {
        Box::pin(async move {
            let current_path = key_path(&self.dir, key);
            let current = read_key(&current_path)?;
            let previous_path = previous_key_path(&self.dir, key);
            let previous = if previous_path.exists() {
                Some(PreviousKey {
                    key: read_key(&previous_path)?,
                    replaced_at: modified(&current_path)?,
                })
            } else {
                None
            };
            Ok(ReleasedKey { current, previous })
        })
    }
}

impl AttestationProvider for LocalDev {
    /// Tokens name the fake sidecar's default address as their issuer, so
    /// they verify against its `/certs` when it runs with the same dev keys.
    fn attest<'a>(&'a self, runtime_data: &'a Value) -> BoxFuture<'a, Result<String, AttestError>> {
        Box::pin(async move {
            DevMaa::load(&self.dir, DEFAULT_ISSUER)
                .and_then(|maa| maa.token(runtime_data))
                .map_err(AttestError)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tee::dev_keys::generate_missing;
    use crate::tee::dev_maa::tests::verify;

    #[tokio::test]
    async fn releases_generated_keys_and_fails_clearly_without_them() {
        let dir =
            std::env::temp_dir().join(format!("relational-tee-local-{}", uuid::Uuid::new_v4()));
        let provider = LocalDev::new(dir.clone());
        let err = match provider.release(KeyName::StorageRoot).await {
            Err(e) => e,
            Ok(_) => panic!("no key files yet"),
        };
        assert!(!err.retryable);
        assert!(err.message.contains("just dev-keys"));

        generate_missing(&dir).expect("generate");
        let key = provider
            .release(KeyName::StorageRoot)
            .await
            .expect("release");
        assert!(key.previous.is_none());

        // A rotation: the old version moves aside and a new one is written.
        let current = key_path(&dir, KeyName::Transport);
        let old = read_key(&current).unwrap();
        std::fs::rename(&current, previous_key_path(&dir, KeyName::Transport)).unwrap();
        generate_missing(&dir).expect("a new version");
        let switched = chrono::Utc::now() - chrono::Duration::hours(3);
        std::fs::File::options()
            .write(true)
            .open(&current)
            .and_then(|f| f.set_modified(switched.into()))
            .unwrap();
        let rotated = provider.release(KeyName::Transport).await.expect("both");
        let previous = rotated.previous.expect("the previous version");
        assert_eq!(previous.key.public_key(), old.public_key());
        assert_ne!(rotated.current.public_key(), old.public_key());
        assert!((previous.replaced_at - switched).num_seconds().abs() <= 1);

        let runtime = serde_json::json!({ "keys": [key.current.public_jwk()] });
        let token = provider.attest(&runtime).await.expect("token");
        let jwks = DevMaa::load(&dir, DEFAULT_ISSUER).unwrap().jwks();
        assert_eq!(
            verify(&token, &jwks, DEFAULT_ISSUER)["x-ms-runtime"],
            runtime
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
