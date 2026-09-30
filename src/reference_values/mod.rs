// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! `GET /v1/reference-values`: the signed manifest of approved workloads.
//!
//! The manifest is a compact JWS (ES256) naming the attestation claims,
//! transport keys and TLS key that clients may trust in this environment.
//! It's signed outside the worker and kept in the public `reference-values`
//! container as `{env}/{sequence}.jws`, the current one also as
//! `{env}/latest.jws`. Workers serve the latest as it is: it's signed, so
//! where it comes from doesn't matter, and clients verify it against the
//! manifest key pinned in their build. Each worker looks for it every 10
//! seconds until one loads and its listed transport key versions are
//! released, then every 5 minutes, and answers
//! `503 reference_values_unavailable` until the first one loads.
//!
//! The manifest also decides which transport key versions besides its
//! current one a worker opens uploads with (see [`TransportKeys`]).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use axum::extract::State;
use axum::http::header;
use axum::response::{IntoResponse, Response};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use tracing::{info, warn};

use crate::error::ApiError;
use crate::seal::{Listed, TransportKeys};
use crate::state::AppState;
use crate::store::{ETag, Fetched, ObjectStore};

#[cfg(feature = "dev")]
pub mod dev;

/// How often to look for a manifest before the first one loads.
const FIRST_POLL: Duration = Duration::from_secs(10);
/// How often to look for a newer manifest.
const POLL: Duration = Duration::from_secs(5 * 60);

/// What the worker reads from a manifest's payload, for its own checks.
#[derive(Deserialize)]
struct Payload {
    sequence: u64,
    not_after: DateTime<Utc>,
    keys: Keys,
}

#[derive(Deserialize)]
struct Keys {
    transport: Vec<TransportKey>,
}

#[derive(Deserialize)]
struct TransportKey {
    kid: String,
    /// The Key Vault key version, which workers release it by.
    #[serde(default)]
    version: Option<String>,
}

/// The payload of a compact JWS, if `jws` is one and its payload is a
/// manifest. The signature isn't checked: clients do that.
fn payload(jws: &[u8]) -> Option<Payload> {
    let text = std::str::from_utf8(jws).ok()?;
    let mut parts = text.split('.');
    let (Some(_), Some(payload), Some(_), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()
}

struct Served {
    jws: Bytes,
    etag: ETag,
    /// The transport key versions it lists.
    transport: Vec<Listed>,
}

/// The environment's manifest, refreshed in the background.
pub struct ReferenceValues {
    store: Arc<dyn ObjectStore>,
    /// `{env}/latest.jws`.
    path: String,
    /// The versions uploads open with; the manifest should list the current one.
    transport: Arc<TransportKeys>,
    served: RwLock<Option<Served>>,
    missing_logged: AtomicBool,
    /// Whether every listed transport key version was released.
    followed: AtomicBool,
}

impl ReferenceValues {
    /// The manifest of `environment` in `store` (the `reference-values`
    /// container), which decides the other versions `transport` accepts.
    pub fn new(
        store: Arc<dyn ObjectStore>,
        environment: &str,
        transport: Arc<TransportKeys>,
    ) -> Self {
        Self {
            store,
            path: format!("{environment}/latest.jws"),
            transport,
            served: RwLock::new(None),
            missing_logged: AtomicBool::new(false),
            followed: AtomicBool::new(false),
        }
    }

    /// The manifest being served, a compact JWS.
    pub fn current(&self) -> Option<Bytes> {
        self.served.read().ok()?.as_ref().map(|s| s.jws.clone())
    }

    /// Look for the manifest once, serve it if it changed, and accept the
    /// transport key versions it lists.
    pub async fn refresh(&self) -> Result<(), String> {
        let cached = self
            .served
            .read()
            .ok()
            .and_then(|s| s.as_ref().map(|s| s.etag.clone()));
        match self
            .store
            .get(&self.path, cached.as_ref())
            .await
            .map_err(|e| format!("reading {}: {e}", self.path))?
        {
            Fetched::NotModified => {}
            Fetched::Missing => {
                if !self.missing_logged.swap(true, Ordering::Relaxed) {
                    info!(manifest = %self.path,
                        "No reference-values manifest yet; clients can't verify this worker until there is one");
                }
            }
            Fetched::Found { body, etag } => self.load(body, etag)?,
        }
        let listed = self
            .served
            .read()
            .ok()
            .and_then(|s| s.as_ref().map(|s| s.transport.clone()));
        if let Some(listed) = listed {
            let result = self.transport.follow(&listed).await;
            self.followed.store(result.is_ok(), Ordering::Relaxed);
            result?;
        }
        Ok(())
    }

    fn load(&self, body: Bytes, etag: ETag) -> Result<(), String> {
        let jws = Bytes::copy_from_slice(body.trim_ascii());
        let manifest = payload(&jws)
            .ok_or_else(|| format!("{} isn't a compact JWS of a manifest", self.path))?;
        let kid = self.transport.current_kid();
        if !manifest.keys.transport.iter().any(|k| k.kid == kid) {
            warn!(alert = "reference_values_mismatch", kid, sequence = manifest.sequence,
                "The manifest doesn't list this worker's transport key, so clients won't seal uploads to it");
        }
        if manifest.not_after <= Utc::now() {
            warn!(sequence = manifest.sequence, not_after = %manifest.not_after.to_rfc3339(),
                "The reference-values manifest has expired, so clients will refuse it");
        }
        info!(manifest = %self.path, sequence = manifest.sequence,
            not_after = %manifest.not_after.to_rfc3339(), "Serving a new reference-values manifest");
        let transport = manifest
            .keys
            .transport
            .into_iter()
            .map(|k| Listed {
                kid: k.kid,
                version: k.version,
            })
            .collect();
        if let Ok(mut served) = self.served.write() {
            *served = Some(Served {
                jws,
                etag,
                transport,
            });
        }
        Ok(())
    }

    /// Keep the manifest fresh for the process lifetime.
    pub fn spawn(self: &Arc<Self>) {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                if let Err(e) = this.refresh().await {
                    warn!(error = %e, "Reference-values check failed");
                }
                let settled = this.served.read().is_ok_and(|s| s.is_some())
                    && this.followed.load(Ordering::Relaxed);
                tokio::time::sleep(if settled { POLL } else { FIRST_POLL }).await;
            }
        });
    }
}

/// The reference-values manifest: the approved workloads and keys.
#[utoipa::path(
    get,
    path = "/v1/reference-values",
    tag = "Attestation",
    summary = "Reference values",
    description = "The environment's signed manifest of approved workloads, transport keys and TLS keys: a compact JWS (ES256). Verify it against the manifest key pinned for the environment, and check its validity window and sequence, before trusting `GET /v1/attestation`. 503 until the worker has loaded one.",
    responses(
        (status = 200, description = "The manifest, as a compact JWS", body = String, content_type = "application/jose"),
        (status = 503, description = "No manifest yet"),
    )
)]
pub async fn get_reference_values(State(state): State<AppState>) -> Result<Response, ApiError> {
    let jws = state.reference_values.current().ok_or_else(|| {
        ApiError::service_unavailable("no reference-values manifest yet; retry shortly")
            .with_code("reference_values_unavailable")
    })?;
    Ok(([(header::CONTENT_TYPE, "application/jose")], jws).into_response())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::store::files::LocalFiles;
    use crate::store::Created;

    /// A compact JWS of `payload` with a made-up signature.
    pub(crate) fn unsigned_jws(payload: &serde_json::Value) -> String {
        format!(
            "{}.{}.c2ln",
            URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256"}"#),
            URL_SAFE_NO_PAD.encode(payload.to_string())
        )
    }

    fn manifest(sequence: u64, kid: &str) -> String {
        unsigned_jws(&serde_json::json!({
            "environment": "dev",
            "sequence": sequence,
            "not_before": "2026-01-01T00:00:00Z",
            "not_after": "2099-01-01T00:00:00Z",
            "claim_sets": [],
            "keys": { "transport": [{ "kid": kid }] },
            "provenance": { "commit": "abc" },
        }))
    }

    fn values(store: Arc<LocalFiles>) -> (ReferenceValues, Arc<TransportKeys>) {
        let transport = Arc::new(crate::seal::keys::tests::rotating());
        (
            ReferenceValues::new(store, "dev", transport.clone()),
            transport,
        )
    }

    #[tokio::test]
    async fn serves_the_latest_manifest_and_follows_its_replacements() {
        let store = Arc::new(LocalFiles::temporary());
        let (values, _) = values(store.clone());
        values.refresh().await.expect("nothing there yet is fine");
        assert!(values.current().is_none());

        let first = manifest(1, "kid-1");
        let Created::New(etag) = store
            .put_if_absent("dev/latest.jws", format!("{first}\n").into())
            .await
            .unwrap()
        else {
            panic!("created");
        };
        values.refresh().await.unwrap();
        assert_eq!(values.current().unwrap(), first.as_bytes(), "trimmed");
        values.refresh().await.unwrap();

        // Something that isn't a manifest is ignored; the last one stays.
        let etag = match store
            .put_if_match("dev/latest.jws", "not a jws".into(), &etag)
            .await
            .unwrap()
        {
            crate::store::Replaced::Done(etag) => etag,
            other => panic!("{other:?}"),
        };
        assert!(values.refresh().await.is_err());
        assert_eq!(values.current().unwrap(), first.as_bytes());

        let second = manifest(2, "kid-2");
        store
            .put_if_match("dev/latest.jws", second.clone().into(), &etag)
            .await
            .unwrap();
        values.refresh().await.unwrap();
        assert_eq!(values.current().unwrap(), second.as_bytes());
    }

    #[tokio::test]
    async fn the_manifest_decides_which_other_transport_key_versions_open() {
        use crate::tee::tests::fixed_key;
        let store = Arc::new(LocalFiles::temporary());
        let (values, transport) = values(store.clone());
        let (one, two) = (fixed_key(1).thumbprint(), fixed_key(2).thumbprint());
        let manifest = |transport: serde_json::Value| {
            unsigned_jws(&serde_json::json!({
                "sequence": 1, "not_after": "2099-01-01T00:00:00Z",
                "keys": { "transport": transport },
            }))
        };

        let rotating = manifest(serde_json::json!([
            { "kid": one }, { "kid": two, "version": "v2" },
        ]));
        let Created::New(etag) = store
            .put_if_absent("dev/latest.jws", rotating.into())
            .await
            .unwrap()
        else {
            panic!("created");
        };
        values.refresh().await.unwrap();
        assert_eq!(transport.kids(), [one.clone(), two.clone()]);

        let retired = manifest(serde_json::json!([{ "kid": one }]));
        store
            .put_if_match("dev/latest.jws", retired.into(), &etag)
            .await
            .unwrap();
        values.refresh().await.unwrap();
        assert_eq!(transport.kids(), [one]);
        assert!(transport.get(&two).is_none());
    }

    #[tokio::test]
    async fn the_route_serves_the_jws_to_the_dashboard_as_application_jose() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let store = Arc::new(LocalFiles::temporary());
        let mut state = AppState::for_tests();
        let kid = state.transport.current_kid().to_string();
        state.reference_values = Arc::new(ReferenceValues::new(
            store.clone(),
            "dev",
            state.transport.clone(),
        ));
        let jws = manifest(3, &kid);
        store
            .put_if_absent("dev/latest.jws", jws.clone().into())
            .await
            .unwrap();
        state.reference_values.refresh().await.unwrap();

        let request = Request::get("/v1/reference-values")
            .header(header::ORIGIN, "http://localhost:5173")
            .header(header::ACCEPT, "application/jose")
            .body(Body::empty())
            .unwrap();
        let response = crate::router(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let headers = response.headers();
        assert_eq!(headers[header::CONTENT_TYPE], "application/jose");
        assert_eq!(
            headers[header::ACCESS_CONTROL_ALLOW_ORIGIN],
            "http://localhost:5173"
        );
        let body = to_bytes(response.into_body(), 1 << 20).await.unwrap();
        assert_eq!(body, jws.as_bytes());
    }

    #[test]
    fn only_compact_jws_manifests_parse() {
        assert_eq!(payload(manifest(7, "k").as_bytes()).unwrap().sequence, 7);
        let no_keys = unsigned_jws(&serde_json::json!({
            "sequence": 1, "not_after": "2099-01-01T00:00:00Z",
        }));
        for bad in [
            "a.b",
            "a.b.c.d",
            "e30.e30.c2ln",
            no_keys.as_str(),
            &manifest(1, "k").replace('.', ".."),
        ] {
            assert!(payload(bad.as_bytes()).is_none(), "{bad}");
        }
    }
}
