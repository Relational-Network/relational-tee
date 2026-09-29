// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Idempotent mutations.
//!
//! Every mutating route requires an `Idempotency-Key` (a UUID) naming one
//! user action; clients reuse it on every retry. Its record lives at
//! `idempotency/{user_id}/{sha256(method ‖ route template ‖ key)}.json`,
//! sealed like every object, and holds a fingerprint of the request (SHA-256
//! of the method, the concrete path and the unsealed body), any signed
//! transaction a chain step stored, and the response once there is one.
//!
//! - A record with a response replays it, with `Idempotent-Replayed: true`.
//! - The same key with a different request returns `422`.
//! - Otherwise the request runs again, resuming wherever an earlier attempt
//!   stopped: every step of every mutation can be repeated.
//!
//! There are no leases and no in-progress state. Two attempts running at
//! once both run, every step converges on one effect, and the attempt that
//! stores its response second returns the stored one instead of its own.
//! The record is created just before the request's first write, so a
//! request that fails validation leaves nothing behind, and failures
//! aren't stored. A lifecycle rule deletes records after 7 days.

use axum::body::{Body, Bytes};
use axum::extract::{FromRequest, FromRequestParts, MatchedPath, Request};
use axum::http::{header, request::Parts, HeaderName, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::ApiError;
use crate::storage::{id, Storage};
use crate::store::{Created, ETag, Replaced, StoreError};

pub const KEY_HEADER: HeaderName = HeaderName::from_static("idempotency-key");
pub const REPLAYED_HEADER: HeaderName = HeaderName::from_static("idempotent-replayed");

/// Compare-and-swap attempts on a record before giving up.
const RECORD_ATTEMPTS: u32 = 4;

/// An idempotent request's key and scope.
#[derive(Debug, Clone)]
pub struct Idempotent {
    /// The `Idempotency-Key`, as a canonical lowercase UUID.
    pub key: String,
    method: Method,
    /// The route template, such as `/v1/drt/pools/{pool_pda}/issue`.
    route: String,
    /// The concrete path.
    path: String,
}

impl<S: Send + Sync> FromRequestParts<S> for Idempotent {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        let key = parts
            .headers
            .get(&KEY_HEADER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| uuid::Uuid::parse_str(v.trim()).ok())
            .ok_or_else(|| {
                ApiError::bad_request("this request needs an Idempotency-Key header with a UUID")
                    .with_code("idempotency_key_required")
            })?;
        let route = parts
            .extensions
            .get::<MatchedPath>()
            .map(|m| m.as_str().to_string())
            .ok_or_else(|| ApiError::internal("idempotent request without a matched route"))?;
        Ok(Self {
            key: key.hyphenated().to_string(),
            method: parts.method.clone(),
            route,
            path: parts.uri.path().to_string(),
        })
    }
}

#[cfg(test)]
impl Idempotent {
    /// A `POST` as the extractor would read it.
    pub(crate) fn post(key: &str, route: &str, path: &str) -> Self {
        Self {
            key: key.into(),
            method: Method::POST,
            route: route.into(),
            path: path.into(),
        }
    }
}

/// A JSON body, and the bytes an idempotency fingerprint covers.
pub struct JsonBody<T> {
    pub value: T,
    pub bytes: Bytes,
}

impl<S: Send + Sync, T: DeserializeOwned> FromRequest<S> for JsonBody<T> {
    type Rejection = Response;

    async fn from_request(request: Request<Body>, state: &S) -> Result<Self, Self::Rejection> {
        let is_json = request
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|ct| ct.starts_with("application/json"));
        if !is_json {
            return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response());
        }
        let bytes = Bytes::from_request(request, state)
            .await
            .map_err(IntoResponse::into_response)?;
        let Json(value) = Json::<T>::from_bytes(&bytes).map_err(IntoResponse::into_response)?;
        Ok(Self { value, bytes })
    }
}

/// A chain step's signed transaction, stored before it's sent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredTx {
    /// The bincode-serialized transaction, base64.
    pub transaction: String,
    pub signature: String,
    /// After this block height the transaction can never land.
    pub last_valid_block_height: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredResponse {
    status: u16,
    body: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Record {
    fingerprint: String,
    created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    chain: Option<StoredTx>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    response: Option<StoredResponse>,
}

/// What opening a record found.
pub enum Opened<'a> {
    /// The request completed before; this is its response.
    Replay(Response),
    Run(Operation<'a>),
}

/// One idempotent request, from validation to its stored response.
pub struct Operation<'a> {
    storage: &'a Storage,
    path: String,
    fingerprint: String,
    /// The record as last read or written.
    record: Option<(Record, ETag)>,
}

fn sha256_hex(parts: &[&[u8]]) -> String {
    let mut hash = Sha256::new();
    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            hash.update(b"\n");
        }
        hash.update(part);
    }
    hex::encode(hash.finalize())
}

fn mismatch() -> ApiError {
    ApiError::unprocessable("this Idempotency-Key was already used for a different request")
        .with_code("idempotency_mismatch")
}

fn replay(stored: &StoredResponse) -> Response {
    let status = StatusCode::from_u16(stored.status).unwrap_or(StatusCode::OK);
    let mut response = (status, Json(stored.body.clone())).into_response();
    response
        .headers_mut()
        .insert(REPLAYED_HEADER, HeaderValue::from_static("true"));
    response
}

impl<'a> Operation<'a> {
    /// Open `user_id`'s record for this request. `body` is what the
    /// fingerprint covers: the JSON body, or a sealed upload's plaintext.
    pub async fn open(
        storage: &'a Storage,
        user_id: &str,
        request: &Idempotent,
        body: &[u8],
    ) -> Result<Opened<'a>, ApiError> {
        let user = id(user_id)
            .ok_or_else(|| ApiError::internal("the caller's user ID can't name a record"))?;
        let scope = sha256_hex(&[
            request.method.as_str().as_bytes(),
            request.route.as_bytes(),
            request.key.as_bytes(),
        ]);
        let op = Operation {
            storage,
            path: format!("idempotency/{user}/{scope}.json"),
            fingerprint: sha256_hex(&[
                request.method.as_str().as_bytes(),
                request.path.as_bytes(),
                body,
            ]),
            record: None,
        };
        let record = storage.state().get_json::<Record>(&op.path).await?;
        if let Some((found, _)) = &record {
            if found.fingerprint != op.fingerprint {
                return Err(mismatch());
            }
            if let Some(response) = &found.response {
                return Ok(Opened::Replay(replay(response)));
            }
        }
        Ok(Opened::Run(Operation { record, ..op }))
    }

    /// The record's path, which a staged saga names.
    pub fn record_path(&self) -> &str {
        &self.path
    }

    /// Create the record, just before the request's first write.
    pub async fn begin(&mut self) -> Result<(), ApiError> {
        if self.record.is_some() {
            return Ok(());
        }
        let record = Record {
            fingerprint: self.fingerprint.clone(),
            created_at: Utc::now(),
            chain: None,
            response: None,
        };
        match self
            .storage
            .state()
            .create_json(&self.path, &record)
            .await?
        {
            Created::New(etag) => self.record = Some((record, etag)),
            // A concurrent attempt created it first.
            Created::AlreadyExists => {
                self.reload().await?;
            }
        }
        Ok(())
    }

    async fn reload(&mut self) -> Result<(), ApiError> {
        let record = self.storage.state().get_json::<Record>(&self.path).await?;
        if let Some((found, _)) = &record {
            if found.fingerprint != self.fingerprint {
                return Err(mismatch());
            }
        }
        self.record = record;
        Ok(())
    }

    /// The chain step's transaction, if an attempt stored one.
    pub fn stored_tx(&self) -> Option<&StoredTx> {
        self.record.as_ref().and_then(|(r, _)| r.chain.as_ref())
    }

    /// Store `tx` as the chain step's transaction, replacing the one whose
    /// signature is `replaces`. If another attempt stored a different one
    /// first, that one is returned instead, and must be used.
    pub async fn store_tx(
        &mut self,
        tx: StoredTx,
        replaces: Option<&str>,
    ) -> Result<StoredTx, ApiError> {
        self.begin().await?;
        for _ in 0..RECORD_ATTEMPTS {
            let Some((mut record, etag)) = self.record.clone() else {
                return Err(ApiError::internal("the idempotency record vanished"));
            };
            if let Some(stored) = &record.chain {
                if Some(stored.signature.as_str()) != replaces {
                    return Ok(stored.clone());
                }
            }
            record.chain = Some(tx.clone());
            match self
                .storage
                .state()
                .replace_json(&self.path, &record, &etag)
                .await?
            {
                Replaced::Done(etag) => {
                    self.record = Some((record, etag));
                    return Ok(tx);
                }
                Replaced::Stale => self.reload().await?,
            }
        }
        Err(StoreError::Contended.into())
    }

    /// Store the response and return it. If another attempt stored one
    /// first, that one is returned instead, as a replay.
    pub async fn finish<T: Serialize>(
        mut self,
        status: StatusCode,
        body: &T,
    ) -> Result<Response, ApiError> {
        let stored = StoredResponse {
            status: status.as_u16(),
            body: serde_json::to_value(body)?,
        };
        self.begin().await?;
        for _ in 0..RECORD_ATTEMPTS {
            let Some((mut record, etag)) = self.record.clone() else {
                return Err(ApiError::internal("the idempotency record vanished"));
            };
            if let Some(first) = &record.response {
                return Ok(replay(first));
            }
            record.response = Some(stored.clone());
            match self
                .storage
                .state()
                .replace_json(&self.path, &record, &etag)
                .await?
            {
                Replaced::Done(_) => return Ok((status, Json(stored.body)).into_response()),
                Replaced::Stale => self.reload().await?,
            }
        }
        Err(StoreError::Contended.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::tests::two_workers;

    fn request(key: &str, path: &str) -> Idempotent {
        Idempotent::post(key, "/v1/drt/pools/{pool_pda}/revoke", path)
    }

    const KEY: &str = "0f8fad5b-d9cb-469f-a165-70867728950e";

    async fn run<'a>(storage: &'a Storage, req: &Idempotent, body: &[u8]) -> Operation<'a> {
        match Operation::open(storage, "user-1", req, body).await.unwrap() {
            Opened::Run(op) => op,
            Opened::Replay(_) => panic!("expected to run"),
        }
    }

    async fn body_of(response: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn a_completed_request_replays_on_any_worker() {
        let (a, b, _files) = two_workers();
        let req = request(KEY, "/v1/drt/pools/P1/revoke");
        let mut op = run(&a, &req, b"{}").await;
        op.begin().await.unwrap();
        let first = op
            .finish(StatusCode::CREATED, &serde_json::json!({"revoked": 1}))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::CREATED);
        assert!(first.headers().get(&REPLAYED_HEADER).is_none());

        let Opened::Replay(again) = Operation::open(&b, "user-1", &req, b"{}").await.unwrap()
        else {
            panic!("expected a replay");
        };
        assert_eq!(again.status(), StatusCode::CREATED);
        assert_eq!(again.headers()[&REPLAYED_HEADER], "true");
        assert_eq!(body_of(again).await, serde_json::json!({"revoked": 1}));
    }

    #[tokio::test]
    async fn the_same_key_for_a_different_request_is_refused() {
        let (a, _, _files) = two_workers();
        let mut op = run(&a, &request(KEY, "/v1/drt/pools/P1/revoke"), b"{}").await;
        op.begin().await.unwrap();
        for (path, body) in [
            ("/v1/drt/pools/P1/revoke", &b"{\"x\":1}"[..]),
            ("/v1/drt/pools/P2/revoke", &b"{}"[..]),
        ] {
            let Err(err) = Operation::open(&a, "user-1", &request(KEY, path), body).await else {
                panic!("expected a mismatch");
            };
            assert_eq!(err.code, "idempotency_mismatch");
        }
        // Another user's same key is another record.
        assert!(matches!(
            Operation::open(
                &a,
                "user-2",
                &request(KEY, "/v1/drt/pools/P2/revoke"),
                b"{}"
            )
            .await
            .unwrap(),
            Opened::Run(_)
        ));
    }

    #[tokio::test]
    async fn a_request_that_fails_before_writing_leaves_nothing() {
        let (a, _, files) = two_workers();
        let req = request(KEY, "/v1/drt/pools/P1/revoke");
        drop(run(&a, &req, b"{}").await);
        let listed = crate::store::ObjectStore::list(files.as_ref(), "idempotency/user-1/")
            .await
            .unwrap();
        assert!(listed.is_empty());
    }

    #[tokio::test]
    async fn concurrent_attempts_converge_on_one_transaction_and_one_response() {
        let (a, b, _files) = two_workers();
        let req = request(KEY, "/v1/drt/pools/P1/revoke");
        let mut x = run(&a, &req, b"{}").await;
        let mut y = run(&b, &req, b"{}").await;
        let tx = |sig: &str| StoredTx {
            transaction: "AA==".into(),
            signature: sig.into(),
            last_valid_block_height: 10,
        };
        // Both build a transaction; the one stored first is the one both use.
        let first = x.store_tx(tx("sig-x"), None).await.unwrap();
        let second = y.store_tx(tx("sig-y"), None).await.unwrap();
        assert_eq!(
            (first.signature.as_str(), second.signature.as_str()),
            ("sig-x", "sig-x")
        );
        // Replacing needs the signature being replaced.
        let replaced = y.store_tx(tx("sig-z"), Some("sig-x")).await.unwrap();
        assert_eq!(replaced.signature, "sig-z");
        assert_eq!(
            x.store_tx(tx("sig-w"), Some("sig-x"))
                .await
                .unwrap()
                .signature,
            "sig-z",
            "a replacement of a replaced transaction uses the newer one"
        );

        // Both finish; the second gets the first's response.
        let one = x.finish(StatusCode::OK, &"x").await.unwrap();
        let two = y.finish(StatusCode::OK, &"y").await.unwrap();
        assert_eq!(body_of(one).await, "x");
        assert_eq!(two.headers()[&REPLAYED_HEADER], "true");
        assert_eq!(body_of(two).await, "x");
    }

    #[tokio::test]
    async fn a_route_needs_a_key_and_replays_what_it_ran_once() {
        use axum::extract::State;
        use axum::routing::post;
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::Arc;
        use tower::ServiceExt;

        type Shared = (Arc<Storage>, Arc<AtomicU32>);
        async fn handler(
            request: Idempotent,
            State((storage, runs)): State<Shared>,
            JsonBody { value, bytes }: JsonBody<serde_json::Value>,
        ) -> Result<Response, ApiError> {
            let mut op = match Operation::open(&storage, "user-1", &request, &bytes).await? {
                Opened::Replay(response) => return Ok(response),
                Opened::Run(op) => op,
            };
            op.begin().await?;
            let run = runs.fetch_add(1, Ordering::SeqCst) + 1;
            let body = serde_json::json!({ "run": run, "sent": value });
            op.finish(StatusCode::CREATED, &body).await
        }

        let (storage, _, _files) = two_workers();
        let runs = Arc::new(AtomicU32::new(0));
        let app = axum::Router::new()
            .route("/v1/things/{id}", post(handler))
            .with_state((Arc::new(storage), runs.clone()));
        let send = |path: &str, key: Option<&str>, content_type: &str, body: &str| {
            let mut request =
                axum::http::Request::post(path).header(header::CONTENT_TYPE, content_type);
            if let Some(key) = key {
                request = request.header(&KEY_HEADER, key);
            }
            app.clone()
                .oneshot(request.body(Body::from(body.to_string())).unwrap())
        };
        let json = "application/json";

        for key in [None, Some("not-a-uuid")] {
            let response = send("/v1/things/a", key, json, "{}").await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(body_of(response).await["code"], "idempotency_key_required");
        }
        let response = send("/v1/things/a", Some(KEY), "text/plain", "{}").await;
        assert_eq!(
            response.unwrap().status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );

        let first = send("/v1/things/a", Some(KEY), json, r#"{"n":1}"#)
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::CREATED);
        assert!(first.headers().get(&REPLAYED_HEADER).is_none());
        let first = body_of(first).await;

        // The key in upper case is the same key.
        let upper = KEY.to_uppercase();
        let again = send("/v1/things/a", Some(upper.as_str()), json, r#"{"n":1}"#)
            .await
            .unwrap();
        assert_eq!(again.status(), StatusCode::CREATED);
        assert_eq!(again.headers()[&REPLAYED_HEADER], "true");
        assert_eq!(body_of(again).await, first);

        for (path, body) in [
            ("/v1/things/a", r#"{"n":2}"#),
            ("/v1/things/b", r#"{"n":1}"#),
        ] {
            let response = send(path, Some(KEY), json, body).await.unwrap();
            assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
            assert_eq!(body_of(response).await["code"], "idempotency_mismatch");
        }
        assert_eq!(runs.load(Ordering::SeqCst), 1);
    }
}
