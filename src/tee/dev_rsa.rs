// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! RS256 signing for dev stand-ins and tests: the fake MAA and the dev
//! token signer. Compiled only into dev builds and tests. Signing goes
//! through aws-lc-rs; the `rsa` crate stays out of the dependency graph.

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::{KeyPair as RsaKeyPair, KeySize};
use aws_lc_rs::signature::{KeyPair as _, RSA_PKCS1_SHA256};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
#[cfg(feature = "dev")]
use {std::fs, std::path::Path, zeroize::Zeroizing};

/// An RSA signing key, with its public half as JWK members and its RFC 7638
/// thumbprint as its `kid`.
pub struct RsaSigner {
    key: RsaKeyPair,
    pub kid: String,
    pub n: String,
    pub e: String,
}

impl RsaSigner {
    /// A fresh RSA 2048 key.
    #[cfg(test)]
    pub fn generate() -> Result<Self, String> {
        let key = RsaKeyPair::generate(KeySize::Rsa2048)
            .map_err(|_| "RSA key generation failed".to_string())?;
        Ok(Self::from_key(key))
    }

    /// Load a PKCS#8 PEM file.
    #[cfg(feature = "dev")]
    pub fn load(path: &Path) -> Result<Self, String> {
        let pem = Zeroizing::new(fs::read(path).map_err(|e| {
            format!(
                "dev key {} is unreadable ({e}); run `just dev-keys`",
                path.display()
            )
        })?);
        let der = match rustls_pemfile::private_key(&mut pem.as_slice()) {
            Ok(Some(rustls::pki_types::PrivateKeyDer::Pkcs8(der))) => der,
            _ => return Err(format!("{} isn't a PKCS#8 private key", path.display())),
        };
        let key = RsaKeyPair::from_pkcs8(der.secret_pkcs8_der())
            .map_err(|e| format!("{} isn't an RSA key: {e}", path.display()))?;
        Ok(Self::from_key(key))
    }

    fn from_key(key: RsaKeyPair) -> Self {
        let public = key.public_key();
        let n = URL_SAFE_NO_PAD.encode(public.modulus().big_endian_without_leading_zero());
        let e = URL_SAFE_NO_PAD.encode(public.exponent().big_endian_without_leading_zero());
        let canonical = format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#);
        let kid = URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()));
        Self { key, kid, n, e }
    }

    /// The public key as a JWK, as MAA and Entra ID publish theirs.
    #[cfg(feature = "dev")]
    pub fn public_jwk(&self) -> Value {
        json!({
            "kty": "RSA", "use": "sig", "alg": "RS256",
            "kid": self.kid, "n": self.n, "e": self.e,
        })
    }

    /// A compact RS256 JWT of `claims`. `header` gets `alg`, `kid` and `typ`.
    pub fn sign(&self, mut header: Value, claims: &Value) -> Result<String, String> {
        header["alg"] = json!("RS256");
        header["kid"] = json!(self.kid);
        header["typ"] = json!("JWT");
        let signing_input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let mut signature = vec![0u8; self.key.public_modulus_len()];
        self.key
            .sign(
                &RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                signing_input.as_bytes(),
                &mut signature,
            )
            .map_err(|_| "RS256 signing failed".to_string())?;
        Ok(format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature)
        ))
    }
}

/// Create `path`, a PKCS#8 PEM RSA 2048 key readable only by its owner, if
/// it's missing. Returns whether it was created.
#[cfg(feature = "dev")]
pub fn generate_missing(path: &Path) -> std::io::Result<bool> {
    use aws_lc_rs::encoding::AsDer;
    use base64::engine::general_purpose::STANDARD;
    use std::io;

    if path.exists() {
        return Ok(false);
    }
    let key = RsaKeyPair::generate(KeySize::Rsa2048)
        .map_err(|_| io::Error::other("RSA key generation failed"))?;
    let der = key
        .as_der()
        .map_err(|_| io::Error::other("encoding the RSA key failed"))?;
    let body = Zeroizing::new(STANDARD.encode(der.as_ref()));
    let mut pem = Zeroizing::new(String::from("-----BEGIN PRIVATE KEY-----\n"));
    for line in body.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        pem.push('\n');
    }
    pem.push_str("-----END PRIVATE KEY-----\n");
    super::dev_keys::write_private(path, pem.as_bytes())?;
    Ok(true)
}
