// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! A fake SKR sidecar (dev builds only), started with
//! `relational-tee fake-skr`.
//!
//! It serves `POST /key/release` and `POST /attest/maa` with the request and
//! response shapes of Microsoft's sidecar, answering from dev keys and the
//! dev MAA signing key, so the production [`SkrSidecar`](super::skr::SkrSidecar)
//! client runs unchanged on a laptop. It also serves the dev MAA public keys
//! at `GET /certs`, as MAA does, so a dashboard can use it as its attestation
//! authority.
//!
//! `kid` is a key name, or `name/previous` for the optional previous version.
//! A key without a dev key file gets 403, like a release policy mismatch.
//!
//! Microsoft's sidecar is reachable only from its own container group, but
//! any user on a machine can reach a loopback port. So both `POST` routes
//! answer only a bearer of the credential in `skr-token` beside the dev
//! keys, which only their owner can read; the public keys stay open.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::{json, Value};
use tracing::{info, warn};
use zeroize::Zeroizing;

use super::dev_keys::{
    key_path, previous_key_path, private_jwk, read_key, read_skr_token, skr_token_path, DEFAULT_DIR,
};
use super::dev_maa::{DevMaa, DEFAULT_TOKEN_LIFETIME};
use super::KeyName;

/// Where the fake listens, and what it signs with.
#[derive(Debug, Clone)]
pub struct FakeSkrConfig {
    pub addr: SocketAddr,
    pub keys_dir: PathBuf,
    /// The `iss` of its tokens, and the base URL of `/certs`.
    pub issuer: String,
    pub token_lifetime: Duration,
    /// Whether its tokens say the workload is debuggable, for checking that
    /// clients refuse them.
    pub debuggable: bool,
}

impl FakeSkrConfig {
    /// Read `FAKE_SKR_ADDR` (default `127.0.0.1:9000`), `DEV_KEYS_DIR`,
    /// `FAKE_MAA_ISSUER` (default `http://localhost:{port}`),
    /// `FAKE_MAA_TOKEN_SECS` (default 8 hours) and `FAKE_MAA_DEBUGGABLE`
    /// (`on` or `off`, the default).
    pub fn from_env() -> Result<Self, String> {
        let var = |key: &str| std::env::var(key).ok().filter(|v| !v.is_empty());
        let addr: SocketAddr = var("FAKE_SKR_ADDR")
            .unwrap_or_else(|| "127.0.0.1:9000".into())
            .parse()
            .map_err(|e| format!("FAKE_SKR_ADDR isn't a socket address: {e}"))?;
        let token_lifetime = match var("FAKE_MAA_TOKEN_SECS") {
            Some(s) => Duration::from_secs(
                s.parse()
                    .map_err(|e| format!("FAKE_MAA_TOKEN_SECS isn't a number: {e}"))?,
            ),
            None => DEFAULT_TOKEN_LIFETIME,
        };
        Ok(Self {
            addr,
            keys_dir: var("DEV_KEYS_DIR")
                .unwrap_or_else(|| DEFAULT_DIR.into())
                .into(),
            issuer: var("FAKE_MAA_ISSUER")
                .unwrap_or_else(|| format!("http://localhost:{}", addr.port())),
            token_lifetime,
            debuggable: match var("FAKE_MAA_DEBUGGABLE").as_deref() {
                None | Some("off") => false,
                Some("on") => true,
                Some(other) => {
                    return Err(format!("FAKE_MAA_DEBUGGABLE {other:?} must be on or off"))
                }
            },
        })
    }
}

/// The fake's state: the dev keys directory, the dev MAA signer and the
/// credential its callers present.
pub struct FakeSkr {
    keys_dir: PathBuf,
    maa: DevMaa,
    token: Zeroizing<String>,
}

impl FakeSkr {
    pub fn load(config: &FakeSkrConfig) -> Result<Self, String> {
        Ok(Self {
            keys_dir: config.keys_dir.clone(),
            maa: DevMaa::load(&config.keys_dir, config.issuer.clone())?
                .with_lifetime(config.token_lifetime)
                .debuggable(config.debuggable),
            token: read_skr_token(&skr_token_path(&config.keys_dir))?,
        })
    }

    /// Whether `headers` carry this fake's credential as a bearer token.
    fn admits(&self, headers: &HeaderMap) -> bool {
        let given = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or_default();
        aws_lc_rs::constant_time::verify_slices_are_equal(given.as_bytes(), self.token.as_bytes())
            .is_ok()
    }
}

/// Run the fake until the process is stopped.
pub async fn serve(config: FakeSkrConfig) -> Result<(), String> {
    let fake = FakeSkr::load(&config)?;
    info!(addr = %config.addr, issuer = %config.issuer, keys = %config.keys_dir.display(),
        "Fake SKR sidecar listening (dev only)");
    if config.debuggable {
        warn!("FAKE_MAA_DEBUGGABLE=on: tokens say the workload is debuggable, so clients must refuse them");
    }
    axum_server::bind(config.addr)
        .serve(router(Arc::new(fake)).into_make_service())
        .await
        .map_err(|e| format!("fake SKR sidecar failed: {e}"))
}

pub fn router(fake: Arc<FakeSkr>) -> Router {
    Router::new()
        .route("/status", get(status))
        .route("/key/release", post(key_release))
        .route("/attest/maa", post(attest_maa))
        .route("/certs", get(certs))
        .with_state(fake)
}

fn error(status: StatusCode, message: impl Into<String>) -> Response {
    (status, Json(json!({ "error": message.into() }))).into_response()
}

/// A required string field, if present and non-empty.
fn field<'a>(body: &'a Value, name: &str) -> Option<&'a str> {
    body.get(name)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
}

/// The sidecar answers 400 when a required field is missing.
fn missing(name: &str) -> Response {
    error(
        StatusCode::BAD_REQUEST,
        format!("invalid request format: {name} is required"),
    )
}

/// 401 for a caller without the fake's credential.
fn unauthorized() -> Response {
    warn!("Fake SKR: refused a caller without its credential");
    error(
        StatusCode::UNAUTHORIZED,
        "the fake SKR sidecar answers only a bearer of the credential in skr-token, \
         beside the dev keys",
    )
}

async fn status() -> Json<Value> {
    Json(json!({ "message": "Status OK" }))
}

async fn key_release(
    State(fake): State<Arc<FakeSkr>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if !fake.admits(&headers) {
        return unauthorized();
    }
    for name in ["kid", "maa_endpoint", "akv_endpoint"] {
        if field(&body, name).is_none() {
            return missing(name);
        }
    }
    let kid = field(&body, "kid").unwrap_or_default();

    let (name, version) = kid.split_once('/').unwrap_or((kid, ""));
    let Some(key) = KeyName::ALL.into_iter().find(|k| k.as_str() == name) else {
        warn!(kid, "Fake SKR: no such dev key");
        return error(
            StatusCode::FORBIDDEN,
            format!("secure key release failed: no dev key named {name:?}"),
        );
    };
    let path = match version {
        "" => key_path(&fake.keys_dir, key),
        "previous" => previous_key_path(&fake.keys_dir, key),
        other => {
            return error(
                StatusCode::FORBIDDEN,
                format!("secure key release failed: unknown version {other:?}"),
            )
        }
    };
    match read_key(&path) {
        Ok(ec) => {
            info!(kid, "Fake SKR: released dev key");
            // Like the real sidecar, the JWK travels as a JSON string.
            Json(json!({ "key": private_jwk(&ec).as_str() })).into_response()
        }
        Err(e) => error(
            StatusCode::FORBIDDEN,
            format!("secure key release failed: {e}"),
        ),
    }
}

async fn attest_maa(
    State(fake): State<Arc<FakeSkr>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if !fake.admits(&headers) {
        return unauthorized();
    }
    for name in ["runtime_data", "maa_endpoint"] {
        if field(&body, name).is_none() {
            return missing(name);
        }
    }
    let runtime_data = field(&body, "runtime_data").unwrap_or_default();
    let Ok(bytes) = STANDARD.decode(runtime_data) else {
        return error(
            StatusCode::BAD_REQUEST,
            "decoding base64-encoded runtime data of request failed",
        );
    };
    let Ok(runtime) = serde_json::from_slice::<Value>(&bytes) else {
        return error(
            StatusCode::FORBIDDEN,
            "attestation failed: runtime data isn't JSON",
        );
    };
    match fake.maa.token(&runtime) {
        Ok(token) => Json(json!({ "token": token })).into_response(),
        Err(e) => error(StatusCode::FORBIDDEN, format!("attestation failed: {e}")),
    }
}

async fn certs(State(fake): State<Arc<FakeSkr>>) -> Response {
    let mut response = Json(fake.maa.jwks()).into_response();
    // Public keys, fetched by browsers from the dashboard's origin.
    response.headers_mut().insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    response
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::http_client::HttpClient;
    use crate::tee::dev_keys::generate_missing;
    use crate::tee::dev_maa::tests::verify;
    use crate::tee::skr::{SkrConfig, SkrSidecar};
    use crate::tee::KeyProvider;

    /// Start a fake on an ephemeral port with fresh dev keys. Returns its
    /// base URL and keys directory.
    pub(crate) async fn start_fake() -> (String, PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("relational-tee-fake-{}", uuid::Uuid::new_v4()));
        generate_missing(&dir).expect("dev keys");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");
        let addr = listener.local_addr().unwrap();
        let config = FakeSkrConfig {
            addr,
            keys_dir: dir.clone(),
            issuer: format!("http://{addr}"),
            token_lifetime: DEFAULT_TOKEN_LIFETIME,
            debuggable: false,
        };
        let fake = Arc::new(FakeSkr::load(&config).expect("load fake"));
        let server = axum_server::from_tcp(listener).expect("server");
        tokio::spawn(server.serve(router(fake).into_make_service()));
        (format!("http://{addr}"), dir)
    }

    /// The production client's settings for the fake at `endpoint`, with the
    /// credential in `dir`.
    pub(crate) fn skr_config(endpoint: &str, dir: &std::path::Path) -> SkrConfig {
        SkrConfig {
            endpoint: endpoint.to_string(),
            maa_endpoint: "sharedweu.weu.attest.azure.net".into(),
            akv_endpoint: "kv-dev.vault.azure.net".into(),
            key_names: KeyName::ALL.map(|k| k.as_str().to_string()),
            dev_token: Some(skr_token_path(dir)),
        }
    }

    #[tokio::test]
    async fn only_a_bearer_of_the_credential_gets_keys_or_tokens() {
        use crate::tee::AttestationProvider;
        let (url, dir) = start_fake().await;
        let wrong = dir.join("wrong-token");
        std::fs::write(&wrong, "0".repeat(64)).unwrap();
        for token in [None, Some(wrong)] {
            let mut config = skr_config(&url, &dir);
            config.dev_token = token;
            let sidecar = SkrSidecar::new(config);
            let Err(e) = sidecar.release(KeyName::StorageRoot).await else {
                panic!("a key went to a caller without the credential");
            };
            assert!(e.message.contains("401"), "{e}");
            let refused = sidecar.attest(&json!({ "keys": [] })).await.unwrap_err();
            assert!(refused.0.contains("401"), "{refused}");
        }

        let mut unreadable = skr_config(&url, &dir);
        unreadable.dev_token = Some(dir.join("no-such-file"));
        let Err(e) = SkrSidecar::new(unreadable).release(KeyName::Tls).await else {
            panic!("released without a credential file");
        };
        assert!(!e.retryable && e.message.contains("just dev-keys"), "{e}");

        let http = HttpClient::new();
        for open in ["/status", "/certs"] {
            let response = http.get(&format!("{url}{open}")).await.unwrap();
            assert!(response.is_success(), "{open}");
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn the_production_client_releases_dev_keys_from_the_fake() {
        let (url, dir) = start_fake().await;
        let sidecar = SkrSidecar::new(skr_config(&url, &dir));
        for name in KeyName::ALL {
            let released = sidecar.release(name).await.expect("released");
            let expected = read_key(&key_path(&dir, name)).unwrap();
            assert_eq!(released.current.public_key(), expected.public_key());
        }

        // A version, as `name/version`: the fake knows `previous`.
        assert!(sidecar
            .release_version(KeyName::Transport, "previous")
            .await
            .is_err());
        let old = read_key(&key_path(&dir, KeyName::Transport)).unwrap();
        std::fs::copy(
            key_path(&dir, KeyName::Transport),
            previous_key_path(&dir, KeyName::Transport),
        )
        .unwrap();
        let released = sidecar
            .release_version(KeyName::Transport, "previous")
            .await
            .expect("the previous version");
        assert_eq!(released.public_key(), old.public_key());
        assert!(sidecar
            .release_version(KeyName::Transport, "../storage-root")
            .await
            .is_err());

        let mut unknown = skr_config(&url, &dir);
        unknown.key_names[0] = "no-such-key".into();
        let err = match SkrSidecar::new(unknown).release(KeyName::Transport).await {
            Err(e) => e,
            Ok(_) => panic!("unknown key must be refused"),
        };
        assert!(err.message.contains("403"), "{err}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn attest_maa_returns_a_token_that_verifies_against_certs() {
        let (url, dir) = start_fake().await;
        let http = HttpClient::new();
        let credential = read_skr_token(&skr_token_path(&dir)).unwrap();
        let runtime = json!({ "keys": [{ "kty": "EC", "kid": "k1" }] });
        let response = http
            .post_json_with_bearer(
                &format!("{url}/attest/maa"),
                &json!({
                    "maa_endpoint": "sharedweu.weu.attest.azure.net",
                    "runtime_data": STANDARD.encode(runtime.to_string()),
                }),
                &credential,
            )
            .await
            .expect("attest");
        assert!(response.is_success());
        let token = response.into_json::<Value>().unwrap()["token"]
            .as_str()
            .unwrap()
            .to_string();

        let jwks: Value = http
            .get(&format!("{url}/certs"))
            .await
            .unwrap()
            .into_json()
            .unwrap();
        let claims = verify(&token, &jwks, &url);
        assert_eq!(claims["x-ms-runtime"], runtime);

        let missing = http
            .post_json_with_bearer(
                &format!("{url}/attest/maa"),
                &json!({ "runtime_data": "e30=" }),
                &credential,
            )
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::BAD_REQUEST);
        let _ = std::fs::remove_dir_all(dir);
    }
}
