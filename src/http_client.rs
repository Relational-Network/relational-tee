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
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::{header, HeaderMap, Method, Request, StatusCode};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioExecutor;
use rustls::{ClientConfig, RootCertStore};
use serde::Serialize;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
/// The largest response body read unless a client allows more.
const DEFAULT_MAX_BODY: usize = 4 << 20;
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
    max_body: usize,
}

impl HttpClient {
    /// Build a client trusting Mozilla's webpki root CAs.
    pub fn new() -> Self {
        Self::build(default_root_store())
    }

    /// Override the time a request has, from sending it to the last byte of
    /// the response (default: 30s).
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Override the largest response body read (default: 4 MiB). A larger
    /// one is an error, and is never held whole.
    pub fn with_max_body(mut self, bytes: usize) -> Self {
        self.max_body = bytes;
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

        let deadline = tokio::time::Instant::now() + self.timeout;
        let resp = tokio::time::timeout_at(deadline, self.inner.request(req))
            .await
            .map_err(|_| HttpError::new(format!("request timed out after {:?}", self.timeout)))?
            .map_err(|e| HttpError::new(format!("request failed: {e}")))?;

        let status = resp.status();
        let (parts, body) = resp.into_parts();
        let too_large =
            || HttpError::new(format!("the response body is over {} bytes", self.max_body));
        let announced = parts
            .headers
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok()?.parse::<u64>().ok());
        if announced.is_some_and(|n| n > self.max_body as u64) {
            return Err(too_large());
        }
        let collected =
            tokio::time::timeout_at(deadline, Limited::new(body, self.max_body).collect())
                .await
                .map_err(|_| HttpError::new("timed out reading the response body"))?
                .map_err(|e| {
                    if e.downcast_ref::<LengthLimitError>().is_some() {
                        too_large()
                    } else {
                        HttpError::new(format!("read response body: {e}"))
                    }
                })?
                .to_bytes();

        Ok(Response {
            status,
            headers: parts.headers,
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
            max_body: DEFAULT_MAX_BODY,
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
    headers: HeaderMap,
    body: Bytes,
}

impl Response {
    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub fn is_success(&self) -> bool {
        self.status.is_success()
    }

    /// A response header, if present and valid ASCII.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    pub fn body(&self) -> &Bytes {
        &self.body
    }

    /// Consume the response, returning the raw body.
    pub fn into_body(self) -> Bytes {
        self.body
    }

    /// Consume the response, returning the body as a UTF-8 string.
    pub fn into_text(self) -> Result<String, HttpError> {
        String::from_utf8(self.body.to_vec())
            .map_err(|e| HttpError::new(format!("response not valid UTF-8: {e}")))
    }

    /// Consume the response, parsing the body as JSON.
    #[cfg(all(test, feature = "dev"))]
    pub fn into_json<T: serde::de::DeserializeOwned>(self) -> Result<T, HttpError> {
        serde_json::from_slice(&self.body)
            .map_err(|e| HttpError::new(format!("parse JSON response: {e}")))
    }
}

fn default_root_store() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    roots
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A local server whose `/` answers `length` bytes, streamed without a
    /// `Content-Length` if `chunked`. Returns its URL.
    fn serve(length: usize, chunked: bool) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let app = axum::Router::new().route(
            "/",
            axum::routing::get(move || async move {
                if chunked {
                    let chunks = (0..length.div_ceil(1024)).map(move |i| {
                        let n = 1024.min(length - i * 1024);
                        Ok::<_, std::io::Error>(Bytes::from(vec![b'a'; n]))
                    });
                    axum::body::Body::from_stream(futures_util::stream::iter(chunks))
                } else {
                    axum::body::Body::from(vec![b'a'; length])
                }
            }),
        );
        let server = axum_server::from_tcp(listener).unwrap();
        tokio::spawn(server.serve(app.into_make_service()));
        url
    }

    #[tokio::test]
    async fn bodies_over_the_limit_are_errors_announced_or_not() {
        let client = HttpClient::new().with_max_body(10_000);
        for chunked in [false, true] {
            let fits = client.get(&serve(10_000, chunked)).await.unwrap();
            assert_eq!(fits.body().len(), 10_000);
            let refused = client.get(&serve(10_001, chunked)).await.err().unwrap();
            assert_eq!(
                refused.to_string(),
                "the response body is over 10000 bytes",
                "chunked: {chunked}"
            );
        }
    }
}
