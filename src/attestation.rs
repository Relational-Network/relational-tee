// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! `GET /v1/attestation`: an MAA token that vouches for the transport key.
//!
//! The worker asks its attestation provider for a token whose `x-ms-runtime`
//! claim is `{ "keys": [ <transport public JWK> ] }`, refreshes it at 80% of
//! its lifetime, and serves the cached token. Clients verify the token's
//! signature against MAA's keys and match its claims to the approved
//! workloads before they seal anything to the key. MAA is only contacted
//! from the background refresher, never on the request path.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use axum::{extract::State, Json};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Serialize;
use serde_json::{json, Value};
use tracing::{info, warn};
use utoipa::ToSchema;

use crate::error::ApiError;
use crate::state::AppState;
use crate::tee::{AttestError, AttestationProvider, EcKey};

const FIRST_RETRY_DELAY: Duration = Duration::from_secs(2);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(64);
/// Never refresh more often than this, whatever the token's lifetime.
const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(10);

/// A token and the claims the worker reads from it.
#[derive(Clone, Debug)]
pub struct CachedToken {
    pub token: String,
    pub expires_at: i64,
    /// `x-ms-sevsnpvm-hostdata`: the SHA-256 of the running CCE policy.
    pub host_data: Option<String>,
}

/// The transport key's attestation, refreshed in the background.
pub struct Attestation {
    transport_jwk: Value,
    kid: String,
    cached: RwLock<Option<CachedToken>>,
}

impl Attestation {
    pub fn new(transport: &EcKey) -> Self {
        Self {
            transport_jwk: transport.public_jwk(),
            kid: transport.thumbprint(),
            cached: RwLock::new(None),
        }
    }

    /// The runtime data the token must carry.
    pub fn runtime_data(&self) -> Value {
        json!({ "keys": [self.transport_jwk] })
    }

    /// The cached token, if it hasn't expired.
    pub fn token(&self) -> Option<CachedToken> {
        let now = chrono::Utc::now().timestamp();
        self.cached
            .read()
            .ok()?
            .as_ref()
            .filter(|t| t.expires_at > now)
            .cloned()
    }

    /// Fetch and cache a new token. Returns how long to wait before the next
    /// refresh: 80% of the token's lifetime from when it was issued.
    pub async fn refresh(
        &self,
        provider: &dyn AttestationProvider,
    ) -> Result<Duration, AttestError> {
        let token = provider.attest(&self.runtime_data()).await?;
        let claims = unverified_claims(&token)?;
        let issued_at = claims["iat"]
            .as_i64()
            .or_else(|| claims["nbf"].as_i64())
            .ok_or_else(|| AttestError("attestation token has no iat".into()))?;
        let expires_at = claims["exp"]
            .as_i64()
            .ok_or_else(|| AttestError("attestation token has no exp".into()))?;
        if expires_at <= issued_at {
            return Err(AttestError(
                "attestation token expires before it's issued".into(),
            ));
        }
        if claims["x-ms-runtime"] != self.runtime_data() {
            return Err(AttestError(
                "attestation token doesn't carry the transport key".into(),
            ));
        }
        let host_data = claims["x-ms-sevsnpvm-hostdata"].as_str().map(String::from);

        let refresh_at = issued_at + (expires_at - issued_at) * 4 / 5;
        let wait = (refresh_at - chrono::Utc::now().timestamp()).max(0) as u64;
        let fresh = CachedToken {
            token,
            expires_at,
            host_data,
        };
        info!(host_data = fresh.host_data.as_deref().unwrap_or("none"), kid = %self.kid,
            expires_at, "Attestation token cached");
        if let Ok(mut cached) = self.cached.write() {
            *cached = Some(fresh);
        }
        Ok(Duration::from_secs(wait).max(MIN_REFRESH_INTERVAL))
    }

    /// Keep the token fresh for the process lifetime. Failures back off and
    /// keep serving the previous token until it expires.
    pub fn spawn_refresher(self: &Arc<Self>, provider: Arc<dyn AttestationProvider>) {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let mut delay = FIRST_RETRY_DELAY;
            loop {
                match this.refresh(provider.as_ref()).await {
                    Ok(next) => {
                        info!(
                            refresh_in_secs = next.as_secs(),
                            "Next attestation refresh scheduled"
                        );
                        delay = FIRST_RETRY_DELAY;
                        tokio::time::sleep(next).await;
                    }
                    Err(e) => {
                        warn!(error = %e, retry_in_secs = delay.as_secs(),
                            "Attestation token refresh failed");
                        tokio::time::sleep(delay).await;
                        delay = (delay * 2).min(MAX_RETRY_DELAY);
                    }
                }
            }
        });
    }
}

/// The payload of a JWT, without verifying it. The token comes from the
/// sidecar in the same TEE; clients do the verification.
fn unverified_claims(token: &str) -> Result<Value, AttestError> {
    let payload = token
        .split('.')
        .nth(1)
        .ok_or_else(|| AttestError("attestation token isn't a JWT".into()))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .map_err(|_| AttestError("attestation token payload isn't base64url".into()))?;
    serde_json::from_slice(&bytes)
        .map_err(|_| AttestError("attestation token payload isn't JSON".into()))
}

/// Response of `GET /v1/attestation`.
#[derive(Debug, Serialize, ToSchema)]
pub struct AttestationResponse {
    /// MAA token (JWT) whose `x-ms-runtime.keys[0]` is `transport_jwk`.
    pub maa_token: String,
    /// The transport public key, as a JWK.
    #[schema(value_type = Object)]
    pub transport_jwk: Value,
    /// RFC 7638 thumbprint of `transport_jwk`.
    pub kid: String,
}

/// The transport key and the attestation token that vouches for it.
#[utoipa::path(
    get,
    path = "/v1/attestation",
    tag = "Attestation",
    summary = "Attestation token for the transport key",
    description = "Returns the worker's cached MAA token and the transport public key it vouches for. Verify the token and match its claims to the approved workloads before sealing anything to the key. 503 until the worker has its first token.",
    responses(
        (status = 200, description = "Token and transport key", body = AttestationResponse),
        (status = 503, description = "No token yet"),
    )
)]
pub async fn get_attestation(
    State(state): State<AppState>,
) -> Result<Json<AttestationResponse>, ApiError> {
    let token = state
        .attestation
        .token()
        .ok_or_else(|| ApiError::service_unavailable("no attestation token yet; retry shortly"))?;
    Ok(Json(AttestationResponse {
        maa_token: token.token,
        transport_jwk: state.attestation.transport_jwk.clone(),
        kid: state.attestation.kid.clone(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tee::tests::fixed_key;
    use crate::tee::BoxFuture;

    /// Issues unsigned tokens with a fixed lifetime around "now".
    struct FixedLifetime {
        lifetime: i64,
        echo_runtime: bool,
    }

    impl AttestationProvider for FixedLifetime {
        fn attest<'a>(
            &'a self,
            runtime_data: &'a Value,
        ) -> BoxFuture<'a, Result<String, AttestError>> {
            Box::pin(async move {
                let now = chrono::Utc::now().timestamp();
                let runtime = if self.echo_runtime {
                    runtime_data.clone()
                } else {
                    json!({ "keys": [] })
                };
                let claims = json!({
                    "iat": now, "exp": now + self.lifetime,
                    "x-ms-runtime": runtime, "x-ms-sevsnpvm-hostdata": "ab",
                });
                Ok(format!(
                    "e30.{}.sig",
                    URL_SAFE_NO_PAD.encode(claims.to_string())
                ))
            })
        }
    }

    #[tokio::test]
    async fn caches_the_token_and_refreshes_at_80_percent() {
        let attestation = Attestation::new(&fixed_key(1));
        assert!(attestation.token().is_none());
        let provider = FixedLifetime {
            lifetime: 1000,
            echo_runtime: true,
        };
        let next = attestation.refresh(&provider).await.expect("refresh");
        assert!((799..=800).contains(&next.as_secs()), "{next:?}");
        let token = attestation.token().expect("cached");
        assert_eq!(token.host_data.as_deref(), Some("ab"));
        assert_eq!(
            unverified_claims(&token.token).unwrap()["x-ms-runtime"]["keys"][0],
            fixed_key(1).public_jwk()
        );
    }

    #[tokio::test]
    async fn rejects_tokens_for_another_key_or_already_expired() {
        let attestation = Attestation::new(&fixed_key(1));
        let wrong_key = FixedLifetime {
            lifetime: 1000,
            echo_runtime: false,
        };
        assert!(attestation.refresh(&wrong_key).await.is_err());
        let expired = FixedLifetime {
            lifetime: -5,
            echo_runtime: true,
        };
        assert!(attestation.refresh(&expired).await.is_err());
        assert!(attestation.token().is_none());
    }
}
