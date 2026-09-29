// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! JWK types and sealed-upload decryption.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::Engine;
use hkdf::Hkdf;
use p256::ecdh::diffie_hellman;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::PublicKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use utoipa::ToSchema;

use crate::tee::ReleasedKey;

/// JWK describing an EC public key (used for encryption or signing).
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct Jwk {
    pub kty: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

/// JWKS response from AVS.
#[derive(Clone, Deserialize)]
pub struct JwksResponse {
    pub keys: Vec<Jwk>,
}

/// Decrypt an ECDH-ES + AES-256-GCM payload sealed to the transport key,
/// trying its current version and then, during a rotation, the previous one.
///
/// The caller must provide base64/base64url encoded:
/// - `ciphertext_b64`: AES-GCM ciphertext + tag
/// - `ephemeral_public_key_b64`: ephemeral P-256 public key (SEC1 bytes)
/// - `nonce_b64`: 12-byte AES-GCM nonce
pub fn decrypt_ecdh_payload(
    transport: &ReleasedKey,
    ciphertext_b64: &str,
    ephemeral_public_key_b64: &str,
    nonce_b64: &str,
) -> Result<Vec<u8>, String> {
    let ciphertext = decode_base64_any(ciphertext_b64)
        .ok_or_else(|| "invalid encrypted_data encoding".to_string())?;
    let ephemeral_bytes = decode_base64_any(ephemeral_public_key_b64)
        .ok_or_else(|| "invalid ephemeral_public_key encoding".to_string())?;
    let nonce_bytes =
        decode_base64_any(nonce_b64).ok_or_else(|| "invalid nonce encoding".to_string())?;

    if nonce_bytes.len() != 12 {
        return Err("nonce must be 12 bytes for AES-GCM".to_string());
    }

    let peer_public = PublicKey::from_sec1_bytes(&ephemeral_bytes)
        .map_err(|_| "invalid ephemeral public key bytes".to_string())?;

    for version in transport.versions() {
        let shared_secret = diffie_hellman(
            version.secret().to_nonzero_scalar(),
            peer_public.as_affine(),
        );

        let hk = Hkdf::<Sha256>::new(None, shared_secret.raw_secret_bytes().as_slice());
        let mut key = zeroize::Zeroizing::new([0u8; 32]);
        hk.expand(b"relational-sdk:data-upload:v1", key.as_mut())
            .map_err(|_| "failed to derive encryption key".to_string())?;

        let cipher = Aes256Gcm::new_from_slice(key.as_ref())
            .map_err(|_| "failed to initialize cipher".to_string())?;
        if let Ok(plaintext) = cipher.decrypt(Nonce::from_slice(&nonce_bytes), ciphertext.as_ref())
        {
            return Ok(plaintext);
        }
    }
    Err("failed to decrypt encrypted_data".to_string())
}

/// Convert a P-256 public key into a JWK for browser-side encryption.
///
/// The `kid` (key ID) is derived from SHA-256 of the uncompressed point.
pub fn jwk_for_public_key(public_key: &p256::PublicKey) -> Jwk {
    let encoded = public_key.to_encoded_point(false);
    let bytes = encoded.as_bytes();
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes[1..33]);
    let y = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes[33..65]);
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let kid = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize());

    Jwk {
        kty: "EC".to_string(),
        crv: Some("P-256".to_string()),
        x: Some(x),
        y: Some(y),
        n: None,
        e: None,
        use_: Some("enc".to_string()),
        alg: Some("ECDH-ES".to_string()),
        kid: Some(kid),
    }
}

/// Decode base64 with multiple variant fallback.
///
/// Tries URL_SAFE_NO_PAD first (our canonical encoding), then falls back to
/// STANDARD, STANDARD_NO_PAD, and URL_SAFE for interop.
pub fn decode_base64_any(input: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(input)
        .ok()
        .or_else(|| base64::engine::general_purpose::STANDARD.decode(input).ok())
        .or_else(|| {
            base64::engine::general_purpose::STANDARD_NO_PAD
                .decode(input)
                .ok()
        })
        .or_else(|| base64::engine::general_purpose::URL_SAFE.decode(input).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tee::tests::fixed_key;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use p256::elliptic_curve::rand_core::OsRng;
    use p256::SecretKey;

    /// Seal `plaintext` to `recipient` the way the dashboard does.
    fn seal(recipient: &PublicKey, plaintext: &[u8]) -> (String, String, String) {
        let ephemeral = SecretKey::random(&mut OsRng);
        let shared = diffie_hellman(ephemeral.to_nonzero_scalar(), recipient.as_affine());
        let hk = Hkdf::<Sha256>::new(None, shared.raw_secret_bytes().as_slice());
        let mut key = [0u8; 32];
        hk.expand(b"relational-sdk:data-upload:v1", &mut key)
            .unwrap();
        let nonce = [7u8; 12];
        let ct = Aes256Gcm::new_from_slice(&key)
            .unwrap()
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .unwrap();
        (
            URL_SAFE_NO_PAD.encode(ct),
            URL_SAFE_NO_PAD.encode(ephemeral.public_key().to_encoded_point(false).as_bytes()),
            URL_SAFE_NO_PAD.encode(nonce),
        )
    }

    #[test]
    fn uploads_sealed_to_either_transport_key_version_open() {
        let transport = ReleasedKey {
            current: fixed_key(1),
            previous: Some(fixed_key(2)),
        };
        for version in [&transport.current, transport.previous.as_ref().unwrap()] {
            let (ct, epk, nonce) = seal(&version.public_key(), b"a,b\n1,2\n");
            let plain = decrypt_ecdh_payload(&transport, &ct, &epk, &nonce).expect("opens");
            assert_eq!(plain, b"a,b\n1,2\n");
        }

        let (ct, epk, nonce) = seal(&fixed_key(3).public_key(), b"x");
        assert!(decrypt_ecdh_payload(&transport, &ct, &epk, &nonce).is_err());
    }
}
