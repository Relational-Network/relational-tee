// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! A dev stand-in for Microsoft Azure Attestation (dev builds only).
//!
//! It signs tokens shaped like MAA's SEV-SNP tokens, RS256 with a dev RSA key
//! whose public half is served as a JWKS at `{issuer}/certs`, as MAA serves
//! its keys. Clients therefore verify dev tokens with the same code as real
//! ones; only the authority differs. Signing goes through aws-lc-rs; the
//! `rsa` crate stays out of the dependency graph.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::{KeyPair as RsaKeyPair, KeySize};
use aws_lc_rs::signature::{KeyPair as _, RSA_PKCS1_SHA256};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::dev_keys::write_private;

/// The dev MAA signing key: a PKCS#8 PEM file next to the dev keys.
pub const SIGNING_KEY_FILE: &str = "maa-signing-key.pem";

/// Host data that dev tokens report, where MAA reports the SHA-256 of the
/// container group's CCE policy.
pub const DEV_HOST_DATA: &str = "dededededededededededededededededededededededededededededededede";

/// MAA tokens are valid for 8 hours.
pub const DEFAULT_TOKEN_LIFETIME: Duration = Duration::from_secs(8 * 3600);

/// Signs MAA-shaped tokens with the dev key.
pub struct DevMaa {
    key: RsaKeyPair,
    kid: String,
    n: String,
    e: String,
    issuer: String,
    lifetime: Duration,
}

impl DevMaa {
    /// Load `{dir}/maa-signing-key.pem`; tokens name `issuer` as their `iss`.
    pub fn load(dir: &Path, issuer: impl Into<String>) -> Result<Self, String> {
        let path = dir.join(SIGNING_KEY_FILE);
        let pem = Zeroizing::new(fs::read(&path).map_err(|e| {
            format!(
                "dev MAA key {} is unreadable ({e}); run `just dev-keys`",
                path.display()
            )
        })?);
        let der = match rustls_pemfile::private_key(&mut pem.as_slice()) {
            Ok(Some(rustls::pki_types::PrivateKeyDer::Pkcs8(der))) => der,
            _ => return Err(format!("{} isn't a PKCS#8 private key", path.display())),
        };
        let key = RsaKeyPair::from_pkcs8(der.secret_pkcs8_der())
            .map_err(|e| format!("{} isn't an RSA key: {e}", path.display()))?;
        let public = key.public_key();
        let n = URL_SAFE_NO_PAD.encode(public.modulus().big_endian_without_leading_zero());
        let e = URL_SAFE_NO_PAD.encode(public.exponent().big_endian_without_leading_zero());
        // RFC 7638 thumbprint over the required RSA members.
        let canonical = format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#);
        let kid = URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()));
        Ok(Self {
            key,
            kid,
            n,
            e,
            issuer: issuer.into(),
            lifetime: DEFAULT_TOKEN_LIFETIME,
        })
    }

    pub fn with_lifetime(mut self, lifetime: Duration) -> Self {
        self.lifetime = lifetime;
        self
    }

    /// The public signing keys, in the shape MAA serves at `/certs`.
    pub fn jwks(&self) -> Value {
        json!({ "keys": [{
            "kty": "RSA", "use": "sig", "alg": "RS256",
            "kid": self.kid, "n": self.n, "e": self.e,
        }] })
    }

    /// A token whose `x-ms-runtime` claim is `runtime`, with the claims MAA
    /// sets for a compliant, non-debuggable SEV-SNP container group.
    pub fn token(&self, runtime: &Value) -> Result<String, String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_secs();
        let header = json!({
            "alg": "RS256",
            "jku": format!("{}/certs", self.issuer.trim_end_matches('/')),
            "kid": self.kid,
            "typ": "JWT",
        });
        let claims = json!({
            "iss": self.issuer,
            "iat": now,
            "nbf": now,
            "exp": now + self.lifetime.as_secs(),
            "jti": uuid::Uuid::new_v4().to_string(),
            "x-ms-attestation-type": "sevsnpvm",
            "x-ms-compliance-status": "azure-compliant-uvm",
            "x-ms-runtime": runtime,
            "x-ms-sevsnpvm-hostdata": DEV_HOST_DATA,
            "x-ms-sevsnpvm-is-debuggable": false,
            "x-ms-sevsnpvm-vmpl": 0,
            "x-ms-ver": "1.0",
        });
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
            .map_err(|_| "signing the dev MAA token failed".to_string())?;
        Ok(format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature)
        ))
    }
}

/// Create `{dir}/maa-signing-key.pem` (RSA 2048) if it's missing.
pub fn generate_missing(dir: &Path) -> io::Result<Option<PathBuf>> {
    let path = dir.join(SIGNING_KEY_FILE);
    if path.exists() {
        return Ok(None);
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
    write_private(&path, pem.as_bytes())?;
    Ok(Some(path))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};

    /// Verify a dev token against a JWKS the way a client verifies MAA
    /// tokens, returning its claims.
    pub(crate) fn verify(token: &str, jwks: &Value, issuer: &str) -> Value {
        let kid = decode_header(token).expect("header").kid.expect("kid");
        let jwk = jwks["keys"]
            .as_array()
            .unwrap()
            .iter()
            .find(|k| k["kid"] == kid.as_str())
            .expect("signing key listed");
        let key = DecodingKey::from_rsa_components(
            jwk["n"].as_str().unwrap(),
            jwk["e"].as_str().unwrap(),
        )
        .expect("RSA key");
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[issuer]);
        validation.validate_aud = false;
        decode::<Value>(token, &key, &validation)
            .expect("valid RS256 token")
            .claims
    }

    #[test]
    fn tokens_verify_as_rs256_against_the_published_keys() {
        let dir = std::env::temp_dir().join(format!("relational-tee-maa-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        assert!(generate_missing(&dir).unwrap().is_some());
        assert!(generate_missing(&dir).unwrap().is_none());

        let maa = DevMaa::load(&dir, "http://localhost:9000").expect("load");
        let runtime = json!({ "keys": [{ "kty": "EC", "kid": "abc" }] });
        let token = maa.token(&runtime).expect("sign");
        let claims = verify(&token, &maa.jwks(), "http://localhost:9000");
        assert_eq!(claims["x-ms-runtime"], runtime);
        assert_eq!(claims["x-ms-sevsnpvm-hostdata"], DEV_HOST_DATA);
        assert_eq!(claims["x-ms-sevsnpvm-is-debuggable"], false);
        let _ = fs::remove_dir_all(dir);
    }
}
