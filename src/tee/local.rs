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
    AttestError, AttestationProvider, BoxFuture, KeyError, KeyName, KeyProvider, ReleasedKey,
};

/// Reads `{dir}/{name}.jwk`, and `{dir}/{name}.previous.jwk` if present.
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
            let current = read_key(&key_path(&self.dir, key))?;
            let previous_path = previous_key_path(&self.dir, key);
            let previous = if previous_path.exists() {
                Some(read_key(&previous_path)?)
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
