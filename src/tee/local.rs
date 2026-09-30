// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! `KEY_PROVIDER=local` (dev builds only): keys come from dev key files
//! instead of the SKR sidecar, and attestation tokens are signed with the dev
//! MAA key.

use std::path::PathBuf;

use serde_json::Value;

use super::dev_keys::{key_path, previous_key_path, read_key};
use super::dev_maa::{DevMaa, DEFAULT_ISSUER};
use super::{
    AttestError, AttestationProvider, BoxFuture, EcKey, KeyError, KeyName, KeyProvider, ReleasedKey,
};

/// Releases `{dir}/{name}.jwk` as a key's current version, and
/// `{dir}/{name}.previous.jwk` as its version `previous`, the only other one.
pub struct LocalDev {
    dir: PathBuf,
}

impl LocalDev {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }
}

impl KeyProvider for LocalDev {
    fn release(&self, key: KeyName) -> BoxFuture<'_, Result<ReleasedKey, KeyError>> {
        Box::pin(async move {
            Ok(ReleasedKey {
                current: read_key(&key_path(&self.dir, key))?,
            })
        })
    }

    fn release_version<'a>(
        &'a self,
        key: KeyName,
        version: &'a str,
    ) -> BoxFuture<'a, Result<EcKey, KeyError>> {
        Box::pin(async move {
            if version != "previous" {
                return Err(KeyError::fatal(format!(
                    "dev keys have no version {version:?}, only \"previous\""
                )));
            }
            read_key(&previous_key_path(&self.dir, key))
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
        let _ = key.current.thumbprint();
        assert!(provider
            .release_version(KeyName::Transport, "previous")
            .await
            .is_err());

        // A rotation: the old version moves aside and a new one is written.
        let current = key_path(&dir, KeyName::Transport);
        let old = read_key(&current).unwrap();
        std::fs::rename(&current, previous_key_path(&dir, KeyName::Transport)).unwrap();
        generate_missing(&dir).expect("a new version");
        let rotated = provider.release(KeyName::Transport).await.expect("current");
        assert_ne!(rotated.current.public_key(), old.public_key());
        let previous = provider
            .release_version(KeyName::Transport, "previous")
            .await
            .expect("the previous version");
        assert_eq!(previous.public_key(), old.public_key());
        assert!(provider
            .release_version(KeyName::Transport, "0a1b")
            .await
            .is_err());

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
