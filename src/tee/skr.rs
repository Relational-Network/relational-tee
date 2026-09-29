// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Client for Microsoft's SKR sidecar, which runs in the same confidential
//! container group and listens on localhost.
//!
//! `POST /key/release` takes `{ maa_endpoint, akv_endpoint, kid }` and
//! returns `{ "key": "<JWK as a JSON string>" }`, or 403 with `{ "error" }`
//! when the key's release policy doesn't match. The sidecar attests, calls
//! Key Vault with the group's managed identity, and unwraps the key with its
//! own RSA transfer key, so this crate needs no RSA code.
//!
//! `POST /attest/maa` takes `{ maa_endpoint, runtime_data }`, where
//! `runtime_data` is standard base64 of a JSON document, and returns
//! `{ "token" }`: an MAA token whose `x-ms-runtime` claim is that document.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::Deserialize;
use serde_json::{json, Value};
use zeroize::Zeroizing;

use super::{
    AttestError, AttestationProvider, BoxFuture, EcKey, KeyError, KeyName, KeyProvider, ReleasedKey,
};
use crate::http_client::HttpClient;

/// How to reach the sidecar and what to ask it for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkrConfig {
    /// Sidecar base URL, for example `http://localhost:9000`.
    pub endpoint: String,
    /// MAA host, without a scheme, for example `sharedweu.weu.attest.azure.net`.
    pub maa_endpoint: String,
    /// Key Vault host, without a scheme, for example `kv-iob-micres-pilot.vault.azure.net`.
    pub akv_endpoint: String,
    /// Key Vault key names, indexed like [`KeyName::ALL`].
    pub key_names: [String; 4],
}

impl SkrConfig {
    fn key_name(&self, key: KeyName) -> &str {
        let index = KeyName::ALL
            .iter()
            .position(|k| *k == key)
            .expect("KeyName::ALL lists every key");
        &self.key_names[index]
    }
}

/// The production [`KeyProvider`].
pub struct SkrSidecar {
    http: HttpClient,
    config: SkrConfig,
}

impl SkrSidecar {
    pub fn new(config: SkrConfig) -> Self {
        Self {
            http: HttpClient::new(),
            config,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.config.endpoint.trim_end_matches('/'))
    }
}

#[derive(Deserialize)]
struct ErrorBody {
    error: Value,
}

/// The sidecar's error message, or the raw body if it isn't the documented shape.
fn error_message(body: &[u8]) -> String {
    // The sidecar can write a second JSON object after the first, so read
    // only the first value.
    let mut values = serde_json::Deserializer::from_slice(body).into_iter::<ErrorBody>();
    match values.next() {
        Some(Ok(ErrorBody {
            error: Value::String(s),
        })) => s,
        Some(Ok(ErrorBody { error })) => error.to_string(),
        _ => String::from_utf8_lossy(body).chars().take(512).collect(),
    }
}

/// Parse `{ "key": ... }`. The sidecar sends the JWK as a JSON string;
/// a JWK object is accepted too.
pub(crate) fn parse_release_response(body: &[u8]) -> Result<EcKey, KeyError> {
    let parsed: Value = serde_json::from_slice(body)
        .map_err(|e| KeyError::retryable(format!("key release response isn't JSON: {e}")))?;
    match parsed.get("key") {
        Some(Value::String(jwk)) => {
            let jwk = Zeroizing::new(jwk.clone());
            let jwk: Value = serde_json::from_str(&jwk)
                .map_err(|e| KeyError::fatal(format!("released key isn't a JWK: {e}")))?;
            EcKey::from_jwk(&jwk)
        }
        Some(jwk @ Value::Object(_)) => EcKey::from_jwk(jwk),
        _ => Err(KeyError::fatal("key release response has no key")),
    }
}

impl KeyProvider for SkrSidecar {
    fn release(&self, key: KeyName) -> BoxFuture<'_, Result<ReleasedKey, KeyError>> {
        Box::pin(async move {
            let body = json!({
                "maa_endpoint": self.config.maa_endpoint,
                "akv_endpoint": self.config.akv_endpoint,
                "kid": self.config.key_name(key),
            });
            let response = self
                .http
                .post_json(&self.url("/key/release"), &body)
                .await
                .map_err(|e| KeyError::retryable(format!("SKR sidecar unreachable: {e}")))?;
            let status = response.status();
            let bytes = Zeroizing::new(
                response
                    .into_text()
                    .map(String::into_bytes)
                    .unwrap_or_default(),
            );
            if !status.is_success() {
                // 403 means the release policy didn't match. It stays
                // retryable: a policy can be mid-update during a rollout.
                return Err(KeyError::retryable(format!(
                    "SKR sidecar returned {status}: {}",
                    error_message(&bytes)
                )));
            }
            Ok(ReleasedKey {
                current: parse_release_response(&bytes)?,
                previous: None,
            })
        })
    }
}

#[derive(Deserialize)]
struct TokenBody {
    token: String,
}

impl AttestationProvider for SkrSidecar {
    fn attest<'a>(&'a self, runtime_data: &'a Value) -> BoxFuture<'a, Result<String, AttestError>> {
        Box::pin(async move {
            let body = json!({
                "maa_endpoint": self.config.maa_endpoint,
                "runtime_data": STANDARD.encode(runtime_data.to_string()),
            });
            let response = self
                .http
                .post_json(&self.url("/attest/maa"), &body)
                .await
                .map_err(|e| AttestError(format!("SKR sidecar unreachable: {e}")))?;
            let status = response.status();
            let text = response.into_text().unwrap_or_default();
            if !status.is_success() {
                return Err(AttestError(format!(
                    "SKR sidecar returned {status}: {}",
                    error_message(text.as_bytes())
                )));
            }
            let parsed: TokenBody = serde_json::Deserializer::from_str(&text)
                .into_iter()
                .next()
                .and_then(Result::ok)
                .ok_or_else(|| AttestError("attestation response has no token".into()))?;
            if parsed.token.is_empty() {
                return Err(AttestError(
                    "attestation response has an empty token".into(),
                ));
            }
            Ok(parsed.token)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tee::tests::fixed_key;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    fn private_jwk_string(key: &EcKey) -> String {
        let mut jwk = key.public_jwk();
        jwk.as_object_mut().unwrap().remove("kid");
        jwk["d"] = Value::String(URL_SAFE_NO_PAD.encode(key.secret().to_bytes()));
        jwk.to_string()
    }

    #[test]
    fn release_response_accepts_a_jwk_string_or_object() {
        let key = fixed_key(3);
        let as_string = json!({ "key": private_jwk_string(&key) }).to_string();
        let parsed = parse_release_response(as_string.as_bytes()).expect("string form");
        assert_eq!(parsed.public_key(), key.public_key());

        let object: Value = serde_json::from_str(&private_jwk_string(&key)).unwrap();
        let as_object = json!({ "key": object }).to_string();
        let parsed = parse_release_response(as_object.as_bytes()).expect("object form");
        assert_eq!(parsed.public_key(), key.public_key());

        assert!(parse_release_response(b"{}").is_err());
    }

    #[test]
    fn error_message_reads_the_first_json_object() {
        assert_eq!(
            error_message(br#"{"error":"policy mismatch"}{"token":""}"#),
            "policy mismatch"
        );
        assert_eq!(error_message(b"not json"), "not json");
    }
}
