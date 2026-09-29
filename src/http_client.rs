// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Minimal async HTTP/HTTPS client built directly on `hyper` + `hyper-rustls`.
//!
//! Replaces `reqwest` to drop the entire `url` → `idna` → `icu_*` chain
//! (~25 transitive crates carrying Unicode normalization data tables) from
//! the dependency tree. [`HttpClient::get`] and [`HttpClient::post_json`]
//! cover JSON APIs; [`HttpClient::send`] takes any prepared request, for the
//! storage REST APIs. URLs are passed straight to `http::Uri` — no host
//! normalization, no redirects, no cookies, no proxy support.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{header, Method, Request, StatusCode};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioExecutor;
use rustls::{ClientConfig, RootCertStore};
use serde::{de::DeserializeOwned, Serialize};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

type HyperClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>;

/// Error returned by [`HttpClient`] operations.
#[derive(Debug)]
pub struct HttpError {
    message: String,
}

impl HttpError {
    fn new(msg: impl Into<String>) -> Self {
        Self {
            message: msg.into(),
        }
    }
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for HttpError {}

/// Cheap-to-clone async HTTP client. The underlying `hyper` client is
/// connection-pooled and reference-counted internally, so cloning yields
/// a handle to the same pool.
#[derive(Clone)]
pub struct HttpClient {
    inner: Arc<HyperClient>,
    timeout: Duration,
}

impl HttpClient {
    /// Build a client trusting Mozilla's webpki root CAs.
    pub fn new() -> Self {
        Self::build(default_root_store())
    }

    /// Build a client trusting the given PEM-encoded CA certificates *in
    /// addition to* the webpki roots. Used for development / private AVS
    /// deployments where the JWKS endpoint is signed by a custom CA.
    pub fn with_extra_ca_pem(pem: &[u8]) -> Result<Self, HttpError> {
        let mut roots = default_root_store();
        let mut cursor = std::io::Cursor::new(pem);
        let mut added = 0usize;
        for cert in rustls_pemfile::certs(&mut cursor) {
            let cert = cert.map_err(|e| HttpError::new(format!("invalid PEM: {e}")))?;
            roots
                .add(cert)
                .map_err(|e| HttpError::new(format!("failed to add CA certificate: {e}")))?;
            added += 1;
        }
        if added == 0 {
            return Err(HttpError::new("no certificates found in PEM input"));
        }
        Ok(Self::build(roots))
    }

    /// Override the per-request timeout (default: 30s).
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// GET `url`. The full response body is collected into [`Response`].
    pub async fn get(&self, url: &str) -> Result<Response, HttpError> {
        self.send_json(Method::GET, url, None).await
    }

    /// POST `url` with `body` serialized as JSON.
    pub async fn post_json<B: Serialize + ?Sized>(
        &self,
        url: &str,
        body: &B,
    ) -> Result<Response, HttpError> {
        let bytes = serde_json::to_vec(body)
            .map_err(|e| HttpError::new(format!("serialize request body: {e}")))?;
        self.send_json(Method::POST, url, Some(bytes)).await
    }

    /// Send a prepared request and collect the whole response. Adds a
    /// `User-Agent` header when the request has none.
    pub async fn send(&self, mut req: Request<Full<Bytes>>) -> Result<Response, HttpError> {
        if !req.headers().contains_key(header::USER_AGENT) {
            req.headers_mut().insert(
                header::USER_AGENT,
                header::HeaderValue::from_static(USER_AGENT),
            );
        }

        let resp = tokio::time::timeout(self.timeout, self.inner.request(req))
            .await
            .map_err(|_| HttpError::new(format!("request timed out after {:?}", self.timeout)))?
            .map_err(|e| HttpError::new(format!("request failed: {e}")))?;

        let status = resp.status();
        let collected = tokio::time::timeout(self.timeout, resp.into_body().collect())
            .await
            .map_err(|_| HttpError::new("timed out reading the response body"))?
            .map_err(|e| HttpError::new(format!("read response body: {e}")))?
            .to_bytes();

        Ok(Response {
            status,
            body: collected,
        })
    }

    fn build(roots: RootCertStore) -> Self {
        // The crypto provider (aws-lc-rs) is installed once at process start
        // in main.rs, so the no-arg builder picks it up.
        let tls = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();

        let connector = HttpsConnectorBuilder::new()
            .with_tls_config(tls)
            .https_or_http()
            .enable_http1()
            .build();

        let inner = Client::builder(TokioExecutor::new()).build::<_, Full<Bytes>>(connector);

        Self {
            inner: Arc::new(inner),
            timeout: DEFAULT_TIMEOUT,
        }
    }

    async fn send_json(
        &self,
        method: Method,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> Result<Response, HttpError> {
        let uri: hyper::Uri = url
            .parse()
            .map_err(|e| HttpError::new(format!("invalid URL {url:?}: {e}")))?;

        let mut builder = Request::builder()
            .method(&method)
            .uri(&uri)
            .header(header::ACCEPT, "application/json");

        let body_bytes = match body {
            Some(b) => {
                builder = builder.header(header::CONTENT_TYPE, "application/json");
                Bytes::from(b)
            }
            None => Bytes::new(),
        };

        let req = builder
            .body(Full::new(body_bytes))
            .map_err(|e| HttpError::new(format!("build request: {e}")))?;
        self.send(req).await
    }
}

impl Default for HttpClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Fully-buffered HTTP response.
pub struct Response {
    status: StatusCode,
    body: Bytes,
}

impl Response {
    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub fn is_success(&self) -> bool {
        self.status.is_success()
    }

    /// Consume the response, returning the body as a UTF-8 string.
    pub fn into_text(self) -> Result<String, HttpError> {
        String::from_utf8(self.body.to_vec())
            .map_err(|e| HttpError::new(format!("response not valid UTF-8: {e}")))
    }

    /// Consume the response, parsing the body as JSON.
    pub fn into_json<T: DeserializeOwned>(self) -> Result<T, HttpError> {
        serde_json::from_slice(&self.body)
            .map_err(|e| HttpError::new(format!("parse JSON response: {e}")))
    }
}

fn default_root_store() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    roots
}
