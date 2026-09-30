// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! JWK types.

use base64::Engine;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use utoipa::ToSchema;

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
