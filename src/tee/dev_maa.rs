// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! A dev stand-in for Microsoft Azure Attestation (dev builds only).
//!
//! It signs tokens shaped like MAA's SEV-SNP tokens, RS256 with a dev RSA key
//! whose public half is served as a JWKS at `{issuer}/certs`, as MAA serves
//! its keys. Clients therefore verify dev tokens with the same code as real
//! ones; only the authority differs.

use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use super::dev_rsa::RsaSigner;

/// The dev MAA signing key: a PKCS#8 PEM file next to the dev keys.
pub const SIGNING_KEY_FILE: &str = "maa-signing-key.pem";

/// Host data that dev tokens report, where MAA reports the SHA-256 of the
/// container group's CCE policy.
pub const DEV_HOST_DATA: &str = "dededededededededededededededededededededededededededededededede";

/// What MAA reports for a confidential container group on a compliant
/// utility VM.
pub const ATTESTATION_TYPE: &str = "sevsnpvm";
pub const COMPLIANCE_STATUS: &str = "azure-compliant-uvm";

/// The reference-values claim set that approves the tokens `issuer` signs:
/// the claims every dev token carries.
pub fn claim_set(issuer: &str) -> Value {
    json!({
        "authority": issuer,
        "x-ms-attestation-type": ATTESTATION_TYPE,
        "x-ms-compliance-status": COMPLIANCE_STATUS,
        "x-ms-sevsnpvm-is-debuggable": false,
        "x-ms-sevsnpvm-vmpl": 0,
        "x-ms-sevsnpvm-hostdata": [DEV_HOST_DATA],
    })
}

/// Default issuer: the fake SKR sidecar's default address.
pub const DEFAULT_ISSUER: &str = "http://localhost:9000";

/// MAA tokens are valid for 8 hours.
pub const DEFAULT_TOKEN_LIFETIME: Duration = Duration::from_secs(8 * 3600);

/// Signs MAA-shaped tokens with the dev key.
pub struct DevMaa {
    signer: RsaSigner,
    issuer: String,
    lifetime: Duration,
    debuggable: bool,
}

impl DevMaa {
    /// Load `{dir}/maa-signing-key.pem`; tokens name `issuer` as their `iss`.
    pub fn load(dir: &Path, issuer: impl Into<String>) -> Result<Self, String> {
        Ok(Self {
            signer: RsaSigner::load(&dir.join(SIGNING_KEY_FILE))?,
            issuer: issuer.into(),
            lifetime: DEFAULT_TOKEN_LIFETIME,
            debuggable: false,
        })
    }

    pub fn with_lifetime(mut self, lifetime: Duration) -> Self {
        self.lifetime = lifetime;
        self
    }

    /// Tokens that say the workload is debuggable, which clients must
    /// refuse.
    pub fn debuggable(mut self, debuggable: bool) -> Self {
        self.debuggable = debuggable;
        self
    }

    /// The public signing keys, in the shape MAA serves at `/certs`.
    pub fn jwks(&self) -> Value {
        json!({ "keys": [self.signer.public_jwk()] })
    }

    /// A token whose `x-ms-runtime` claim is `runtime`, with the claims MAA
    /// sets for a compliant, non-debuggable SEV-SNP container group (unless
    /// it was made [`debuggable`](Self::debuggable)).
    pub fn token(&self, runtime: &Value) -> Result<String, String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_secs();
        let header = json!({
            "jku": format!("{}/certs", self.issuer.trim_end_matches('/')),
        });
        let claims = json!({
            "iss": self.issuer,
            "iat": now,
            "nbf": now,
            "exp": now + self.lifetime.as_secs(),
            "jti": uuid::Uuid::new_v4().to_string(),
            "x-ms-attestation-type": ATTESTATION_TYPE,
            "x-ms-compliance-status": COMPLIANCE_STATUS,
            "x-ms-runtime": runtime,
            "x-ms-sevsnpvm-hostdata": DEV_HOST_DATA,
            "x-ms-sevsnpvm-is-debuggable": self.debuggable,
            "x-ms-sevsnpvm-vmpl": 0,
            "x-ms-ver": "1.0",
        });
        self.signer
            .sign(header, &claims)
            .map_err(|e| format!("signing the dev MAA token: {e}"))
    }
}

/// Create `{dir}/maa-signing-key.pem` (RSA 2048) if it's missing.
pub fn generate_missing(dir: &Path) -> io::Result<Option<PathBuf>> {
    let path = dir.join(SIGNING_KEY_FILE);
    Ok(super::dev_rsa::generate_missing(&path)?.then_some(path))
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
        std::fs::create_dir_all(&dir).unwrap();
        assert!(generate_missing(&dir).unwrap().is_some());
        assert!(generate_missing(&dir).unwrap().is_none());

        let maa = DevMaa::load(&dir, "http://localhost:9000").expect("load");
        let runtime = json!({ "keys": [{ "kty": "EC", "kid": "abc" }] });
        let token = maa.token(&runtime).expect("sign");
        let jwks = maa.jwks();
        let claims = verify(&token, &jwks, "http://localhost:9000");
        assert_eq!(claims["x-ms-runtime"], runtime);
        assert_eq!(claims["x-ms-sevsnpvm-hostdata"], DEV_HOST_DATA);
        assert_eq!(claims["x-ms-sevsnpvm-is-debuggable"], false);

        let debuggable = maa.debuggable(true).token(&runtime).expect("sign");
        let claims = verify(&debuggable, &jwks, "http://localhost:9000");
        assert_eq!(claims["x-ms-sevsnpvm-is-debuggable"], true);
        let _ = std::fs::remove_dir_all(dir);
    }
}
