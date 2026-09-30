// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Dev key files (dev builds only): one private JWK per worker key, in the
//! format the SKR sidecar releases, the dev MAA signing key, the dev token
//! signing key and the dev manifest key, under `dev/keys/` by default.
//!
//! These keys stand in for Key Vault. They are never used outside dev builds,
//! and the directory is gitignored.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::elliptic_curve::rand_core::OsRng;
use p256::SecretKey;
use serde_json::Value;
use zeroize::Zeroizing;

use super::{EcKey, KeyError, KeyName};

/// Where dev keys live unless `DEV_KEYS_DIR` says otherwise.
pub const DEFAULT_DIR: &str = "dev/keys";

/// `{dir}/{name}.jwk`: the current version of a key.
pub fn key_path(dir: &Path, name: KeyName) -> PathBuf {
    dir.join(format!("{name}.jwk"))
}

/// `{dir}/{name}.previous.jwk`: an optional previous version, for rotation.
pub fn previous_key_path(dir: &Path, name: KeyName) -> PathBuf {
    dir.join(format!("{name}.previous.jwk"))
}

/// The private JWK of `key`, as the SKR sidecar releases it.
pub fn private_jwk(key: &EcKey) -> Zeroizing<String> {
    let mut jwk = key.public_jwk();
    jwk["d"] = Value::String(URL_SAFE_NO_PAD.encode(key.secret().to_bytes()));
    Zeroizing::new(jwk.to_string())
}

/// Read a private JWK file.
pub fn read_key(path: &Path) -> Result<EcKey, KeyError> {
    let text = Zeroizing::new(fs::read_to_string(path).map_err(|e| {
        KeyError::fatal(format!(
            "dev key {} is unreadable ({e}); run `just dev-keys`",
            path.display()
        ))
    })?);
    let jwk: Value = serde_json::from_str(&text)
        .map_err(|e| KeyError::fatal(format!("dev key {} isn't JSON: {e}", path.display())))?;
    EcKey::from_jwk(&jwk)
}

/// Create any missing dev key files in `dir`: the four worker keys, the dev
/// MAA signing key, the dev token signing key and the dev manifest key.
/// Existing files are never overwritten. Returns the paths it created.
pub fn generate_missing(dir: &Path) -> io::Result<Vec<PathBuf>> {
    fs::create_dir_all(dir)?;
    let mut created = Vec::new();
    for name in KeyName::ALL {
        let path = key_path(dir, name);
        if path.exists() {
            continue;
        }
        let key = EcKey::new(SecretKey::random(&mut OsRng));
        write_private(&path, private_jwk(&key).as_bytes())?;
        created.push(path);
    }
    created.extend(super::dev_maa::generate_missing(dir)?);
    created.extend(crate::auth::dev_token::generate_missing(dir)?);
    created.extend(crate::reference_values::dev::generate_missing(dir)?);
    Ok(created)
}

/// Create `path` readable only by its owner.
pub(crate) fn write_private(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.write_all(contents)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "relational-tee-{label}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn generates_each_key_once_and_reads_it_back() {
        let dir = temp_dir("dev-keys");
        let created = generate_missing(&dir).expect("generate");
        assert_eq!(created.len(), KeyName::ALL.len() + 3);
        let first = read_key(&key_path(&dir, KeyName::Transport)).expect("read");

        assert!(generate_missing(&dir).expect("second run").is_empty());
        let again = read_key(&key_path(&dir, KeyName::Transport)).expect("read");
        assert_eq!(first.public_key(), again.public_key());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(key_path(&dir, KeyName::Tls))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let _ = fs::remove_dir_all(dir);
    }
}
