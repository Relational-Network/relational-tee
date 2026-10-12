// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! [`ObjectStore`] on Azure Blob Storage, over the crate's hyper client.
//!
//! Requests authenticate with Entra bearer tokens for
//! `https://storage.azure.com/`, from the managed-identity endpoint; the
//! storage account has shared keys disabled. Dev builds can also sign with
//! Azurite's well-known dev account key instead.
//!
//! Three REST calls cover the store: Get Blob (conditional with
//! `If-None-Match`), Put Blob (with `If-None-Match: *` or `If-Match`) and
//! List Blobs (with `delimiter=/`). API version 2021-12-02.

use std::sync::Arc;
use std::time::Duration;

#[cfg(feature = "dev")]
use base64::{engine::general_purpose::STANDARD, Engine};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use http_body_util::Full;
use hyper::{Method, Request, StatusCode};
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use serde_json::Value;
use std::sync::PoisonError;
use tokio::sync::watch;
use tokio::time::Instant;
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

use super::{
    check_path, BoxFuture, Created, ETag, Fetched, Listed, ObjectStore, Replaced, StoreError,
};
use crate::config::MAX_BODY_SIZE;
use crate::http_client::{HttpClient, Response};

const API_VERSION: &str = "2021-12-02";
const STORAGE_RESOURCE: &str = "https://storage.azure.com/";
const IMDS_TOKEN_URL: &str = "http://169.254.169.254/metadata/identity/oauth2/token";
/// Tokens are refreshed from this long before they expire, and not used
/// once they're this close.
const TOKEN_REFRESH_MARGIN_SECS: i64 = 300;
const TOKEN_EXPIRY_MARGIN_SECS: i64 = 60;
/// The wait after a failed token fetch, at first and at most.
const TOKEN_RETRY_WAIT: (Duration, Duration) = (Duration::from_secs(1), Duration::from_secs(60));
/// The most objects one List Blobs page returns.
const LIST_PAGE_SIZE: &str = "5000";
/// The most List Blobs pages one listing reads: 200,000 objects.
const MAX_LIST_PAGES: usize = 40;

/// Azurite's well-known dev account. Dev builds only.
#[cfg(feature = "dev")]
pub const AZURITE_ACCOUNT: &str = "devstoreaccount1";
#[cfg(feature = "dev")]
const AZURITE_KEY: &str =
    "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==";

/// Characters kept as-is in blob paths: unreserved ones and `/`.
const PATH: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~')
    .remove(b'/');
/// Characters kept as-is in query values.
const VALUE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

/// How the worker authenticates to Storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialConfig {
    /// Entra tokens from the managed-identity endpoint, for the identity
    /// `client_id` (or the only one assigned).
    ManagedIdentity { client_id: Option<String> },
    /// Azurite's well-known dev account key. Dev builds only.
    #[cfg(feature = "dev")]
    AzuriteDevAccount,
}

/// Where the storage account is and how to reach it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AzureConfig {
    /// For example `https://stexample.blob.core.windows.net`, or
    /// `http://127.0.0.1:10000/devstoreaccount1` for Azurite.
    pub blob_url: String,
    pub credential: CredentialConfig,
}

/// The Blob service's origin and path prefix. Azurite puts the account name
/// in the path instead of the host.
struct Endpoint {
    origin: String,
    prefix: String,
}

impl Endpoint {
    fn parse(url: &str) -> Result<Self, String> {
        let (scheme, rest) = url
            .split_once("://")
            .filter(|(s, _)| *s == "https" || *s == "http")
            .ok_or_else(|| format!("storage URL {url:?} must be http:// or https://"))?;
        let rest = rest.trim_end_matches('/');
        let (authority, prefix) = match rest.find('/') {
            Some(i) => rest.split_at_checked(i).unwrap_or((rest, "")),
            None => (rest, ""),
        };
        if authority.is_empty() {
            return Err(format!("storage URL {url:?} has no host"));
        }
        Ok(Self {
            origin: format!("{scheme}://{authority}"),
            prefix: prefix.to_string(),
        })
    }
}

struct CachedToken {
    token: Zeroizing<String>,
    expires_on: i64,
}

impl CachedToken {
    fn header(&self) -> String {
        format!("Bearer {}", self.token.as_str())
    }
}

#[derive(Default)]
struct TokenState {
    token: Option<CachedToken>,
    refreshing: bool,
    /// When the last fetch started, how many in a row have failed, and why
    /// the last one did.
    attempted_at: Option<Instant>,
    failures: u32,
    error: Option<String>,
}

/// Storage tokens from the managed identity endpoint. A token is used until
/// [`TOKEN_EXPIRY_MARGIN_SECS`] before it expires, and replaced from
/// [`TOKEN_REFRESH_MARGIN_SECS`] before, in the background while it still
/// works. One fetch runs at a time, in a task of its own, and every request
/// that needs a token waits for that fetch, failed or not; after a failure
/// the next fetch waits 1 second, doubling to a minute.
struct Tokens {
    http: HttpClient,
    /// The token endpoint, and the identity to ask for, if not the only one.
    endpoint: String,
    client_id: Option<String>,
    state: Arc<std::sync::Mutex<TokenState>>,
    /// How many fetches have finished.
    finished: watch::Sender<u64>,
}

enum Credential {
    ManagedIdentity(Tokens),
    #[cfg(feature = "dev")]
    SharedKey {
        account: String,
        key: Zeroizing<Vec<u8>>,
    },
}

/// The account's client and credential, shared by its containers.
struct Account {
    http: HttpClient,
    endpoint: Endpoint,
    credential: Credential,
}

/// One container of an Azure storage account.
pub struct AzureBlob {
    account: Arc<Account>,
    container: String,
}

/// A request before authentication. Header names are lowercase.
struct Req {
    method: Method,
    /// Percent-encoded, starting with the endpoint prefix.
    path: String,
    query: Vec<(&'static str, String)>,
    headers: Vec<(&'static str, String)>,
    body: Bytes,
}

impl Req {
    fn new(method: Method, path: String) -> Self {
        Self {
            method,
            path,
            query: Vec::new(),
            headers: Vec::new(),
            body: Bytes::new(),
        }
    }

    #[cfg(feature = "dev")]
    fn header(&self, name: &str) -> &str {
        self.headers
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.as_str())
            .unwrap_or("")
    }
}

impl AzureBlob {
    /// The container `container` of the account in `config`.
    pub fn new(config: &AzureConfig, container: &str) -> Result<Self, String> {
        let credential = match &config.credential {
            CredentialConfig::ManagedIdentity { client_id } => {
                Credential::ManagedIdentity(Tokens::new(IMDS_TOKEN_URL, client_id.clone()))
            }
            #[cfg(feature = "dev")]
            CredentialConfig::AzuriteDevAccount => Credential::SharedKey {
                account: AZURITE_ACCOUNT.to_string(),
                key: Zeroizing::new(STANDARD.decode(AZURITE_KEY).expect("valid base64")),
            },
        };
        Ok(Self {
            account: Arc::new(Account {
                // A sealed dataset is the largest object: an upload's body
                // and the seal's few bytes.
                http: HttpClient::new()
                    .with_timeout(Duration::from_secs(30))
                    .with_max_body(MAX_BODY_SIZE + (1 << 20)),
                endpoint: Endpoint::parse(&config.blob_url)?,
                credential,
            }),
            container: container.to_string(),
        })
    }

    /// Another container of the same account.
    pub fn container(&self, name: &str) -> Self {
        Self {
            account: self.account.clone(),
            container: name.to_string(),
        }
    }

    /// Create the container unless it exists.
    pub async fn ensure_container(&self) -> Result<(), StoreError> {
        let mut req = Req::new(
            Method::PUT,
            format!("{}/{}", self.account.endpoint.prefix, self.container),
        );
        req.query.push(("restype", "container".into()));
        let response = self.account.send(req).await?;
        match response.status() {
            StatusCode::CREATED => {
                info!(container = %self.container, "Created container");
                Ok(())
            }
            StatusCode::CONFLICT => Ok(()),
            _ => Err(unexpected("create container", &response)),
        }
    }

    fn blob_path(&self, path: &str) -> Result<String, StoreError> {
        check_path(path)?;
        Ok(format!(
            "{}/{}/{}",
            self.account.endpoint.prefix,
            self.container,
            utf8_percent_encode(path, PATH)
        ))
    }

    fn put(
        &self,
        path: &str,
        body: Bytes,
        condition: (&'static str, String),
    ) -> Result<Req, StoreError> {
        let mut req = Req::new(Method::PUT, self.blob_path(path)?);
        req.headers = vec![
            ("content-type", "application/octet-stream".into()),
            condition,
            ("x-ms-blob-type", "BlockBlob".into()),
        ];
        req.body = body;
        Ok(req)
    }
}

impl Account {
    async fn send(&self, mut req: Req) -> Result<Response, StoreError> {
        req.headers.push(("x-ms-date", http_date()));
        req.headers.push(("x-ms-version", API_VERSION.into()));
        req.headers
            .push(("content-length", req.body.len().to_string()));
        let authorization = match &self.credential {
            Credential::ManagedIdentity(tokens) => tokens.bearer().await?,
            #[cfg(feature = "dev")]
            Credential::SharedKey { account, key } => shared_key(account, key, &req),
        };

        let mut url = format!("{}{}", self.endpoint.origin, req.path);
        for (i, (name, value)) in req.query.iter().enumerate() {
            url.push(if i == 0 { '?' } else { '&' });
            url.push_str(name);
            url.push('=');
            url.extend(utf8_percent_encode(value, VALUE));
        }

        let mut builder = Request::builder()
            .method(req.method.clone())
            .uri(&url)
            .header("authorization", authorization);
        for (name, value) in &req.headers {
            builder = builder.header(*name, value);
        }
        let request = builder
            .body(Full::new(req.body.clone()))
            .map_err(|e| StoreError::Invalid(format!("building request: {e}")))?;
        debug!(method = %req.method, path = %req.path, "Storage request");
        self.http
            .send(request)
            .await
            .map_err(|e| StoreError::Unavailable(e.to_string()))
    }
}

impl Tokens {
    fn new(endpoint: &str, client_id: Option<String>) -> Self {
        Self {
            http: HttpClient::new()
                .with_timeout(Duration::from_secs(10))
                .with_max_body(64 << 10),
            endpoint: endpoint.to_string(),
            client_id,
            state: Arc::default(),
            finished: watch::Sender::new(0),
        }
    }

    fn url(&self) -> String {
        let mut url = format!(
            "{}?api-version=2018-02-01&resource={}",
            self.endpoint,
            utf8_percent_encode(STORAGE_RESOURCE, VALUE)
        );
        if let Some(id) = &self.client_id {
            url.push_str("&client_id=");
            url.extend(utf8_percent_encode(id, VALUE));
        }
        url
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, TokenState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A bearer token for Storage: the cached one while it works, or the
    /// one the current fetch brings.
    async fn bearer(&self) -> Result<String, StoreError> {
        let mut finished = self.finished.subscribe();
        let seen = *finished.borrow_and_update();
        let now = Utc::now().timestamp();
        let (usable, waiting) = {
            let mut state = self.lock();
            let usable = state
                .token
                .as_ref()
                .filter(|t| t.expires_on - TOKEN_EXPIRY_MARGIN_SECS > now)
                .map(CachedToken::header);
            let due = state
                .token
                .as_ref()
                .is_none_or(|t| t.expires_on - TOKEN_REFRESH_MARGIN_SECS <= now);
            if due {
                self.start_fetch(&mut state);
            }
            (usable, state.refreshing)
        };
        if let Some(header) = usable {
            return Ok(header);
        }
        if waiting {
            let _ = finished.wait_for(|n| *n > seen).await;
        }
        let now = Utc::now().timestamp();
        let state = self.lock();
        match state
            .token
            .as_ref()
            .filter(|t| t.expires_on - TOKEN_EXPIRY_MARGIN_SECS > now)
        {
            Some(token) => Ok(token.header()),
            None => Err(StoreError::Unavailable(
                state
                    .error
                    .clone()
                    .unwrap_or_else(|| "no storage token yet".into()),
            )),
        }
    }

    /// Start a fetch in a task of its own, unless one is running or the
    /// last one's failure hasn't been waited out.
    fn start_fetch(&self, state: &mut TokenState) {
        let now = Instant::now();
        let waited = state.attempted_at.is_none_or(|at| {
            now.duration_since(at) >= crate::work::backoff(state.failures, TOKEN_RETRY_WAIT)
        });
        if state.refreshing || !waited {
            return;
        }
        state.refreshing = true;
        state.attempted_at = Some(now);
        let (http, url, shared, finished) = (
            self.http.clone(),
            self.url(),
            self.state.clone(),
            self.finished.clone(),
        );
        tokio::spawn(async move {
            let fetched = managed_identity_token(&http, &url).await;
            {
                let mut state = shared.lock().unwrap_or_else(PoisonError::into_inner);
                state.refreshing = false;
                match fetched {
                    Ok(token) => {
                        info!(expires_on = token.expires_on, "Fetched a storage token");
                        // Keep whichever lasts longer.
                        if state
                            .token
                            .as_ref()
                            .is_none_or(|held| token.expires_on >= held.expires_on)
                        {
                            state.token = Some(token);
                        }
                        state.failures = 0;
                        state.error = None;
                    }
                    Err(e) => {
                        state.failures = state.failures.saturating_add(1);
                        warn!(error = %e, failures = state.failures,
                            "Fetching a storage token failed");
                        state.error = Some(e.to_string());
                    }
                }
            }
            finished.send_modify(|n| *n += 1);
        });
    }
}

async fn managed_identity_token(http: &HttpClient, url: &str) -> Result<CachedToken, StoreError> {
    let request = Request::builder()
        .method(Method::GET)
        .uri(url)
        .header("metadata", "true")
        .body(Full::new(Bytes::new()))
        .map_err(|e| StoreError::Invalid(format!("building token request: {e}")))?;
    let response = http
        .send(request)
        .await
        .map_err(|e| StoreError::Unavailable(format!("managed identity endpoint: {e}")))?;
    if !response.is_success() {
        return Err(StoreError::Unavailable(format!(
            "managed identity endpoint returned {}",
            response.status()
        )));
    }
    let body: Value = serde_json::from_slice(&response.into_body())
        .map_err(|_| StoreError::Unavailable("managed identity token isn't JSON".into()))?;
    let token = body["access_token"]
        .as_str()
        .ok_or_else(|| StoreError::Unavailable("managed identity response has no token".into()))?;
    // `expires_on` is epoch seconds, sent as a string.
    let expires_on = body["expires_on"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .or_else(|| body["expires_on"].as_i64())
        .ok_or_else(|| StoreError::Unavailable("managed identity token has no expiry".into()))?;
    Ok(CachedToken {
        token: Zeroizing::new(token.to_string()),
        expires_on,
    })
}

/// RFC 1123 date for `x-ms-date`.
fn http_date() -> String {
    Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

/// A Shared Key `Authorization` header.
#[cfg(feature = "dev")]
fn shared_key(account: &str, key: &[u8], req: &Req) -> String {
    use hmac::{Hmac, Mac};
    let mut mac =
        <Hmac<sha2::Sha256> as Mac>::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(string_to_sign(account, req).as_bytes());
    format!(
        "SharedKey {account}:{}",
        STANDARD.encode(mac.finalize().into_bytes())
    )
}

/// The Shared Key string-to-sign for a Blob request.
#[cfg(feature = "dev")]
fn string_to_sign(account: &str, req: &Req) -> String {
    let mut resource = format!("/{account}{}", req.path);
    let mut canonical_headers: Vec<(&str, &str)> = req
        .headers
        .iter()
        .filter(|(n, _)| n.starts_with("x-ms-"))
        .map(|(n, v)| (*n, v.as_str()))
        .collect();
    canonical_headers.sort();
    let mut query: Vec<&(&str, String)> = req.query.iter().collect();
    query.sort();
    for (name, value) in query {
        resource.push_str(&format!("\n{name}:{value}"));
    }
    let content_length = match req.header("content-length") {
        "0" => "",
        other => other,
    };
    let mut s = format!(
        "{}\n\n\n{content_length}\n\n{}\n\n\n{}\n{}\n\n\n",
        req.method,
        req.header("content-type"),
        req.header("if-match"),
        req.header("if-none-match"),
    );
    for (name, value) in canonical_headers {
        s.push_str(&format!("{name}:{value}\n"));
    }
    s.push_str(&resource);
    s
}

/// An error for a response the caller didn't expect.
fn unexpected(what: &str, response: &Response) -> StoreError {
    let code = response
        .header("x-ms-error-code")
        .unwrap_or("-")
        .to_string();
    let status = response.status();
    let message = format!("{what}: HTTP {status} ({code})");
    if status.is_server_error()
        || status == StatusCode::REQUEST_TIMEOUT
        || status == StatusCode::TOO_MANY_REQUESTS
    {
        StoreError::Unavailable(message)
    } else {
        StoreError::Invalid(message)
    }
}

fn etag_of(response: &Response) -> Result<ETag, StoreError> {
    response
        .header("etag")
        .map(ETag::from_raw)
        .ok_or_else(|| StoreError::Invalid("response has no ETag".into()))
}

/// The text of the first `<tag>…</tag>` in `xml`, unescaped; `Some("")` for
/// an empty or self-closing element.
fn element(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}");
    let mut from = 0;
    while let Some(i) = xml.get(from..)?.find(&open) {
        let start = from + i + open.len();
        let rest = xml.get(start..)?;
        // Skip longer names that share the prefix, such as `<BlobPrefix>`.
        match rest.chars().next() {
            Some('>') | Some(' ') => {}
            Some('/') => return Some(String::new()),
            _ => {
                from = start;
                continue;
            }
        }
        let body_start = start + rest.find('>')? + 1;
        if xml.get(..body_start)?.ends_with("/>") {
            return Some(String::new());
        }
        let body = xml.get(body_start..)?;
        let end = body.find(&format!("</{tag}>"))?;
        return Some(unescape(body.get(..end)?));
    }
    None
}

fn unescape(text: &str) -> String {
    text.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// The blobs of one List Blobs page, and its `NextMarker`.
fn parse_list(xml: &str) -> Result<(Vec<Listed>, Option<String>), StoreError> {
    let bad = |what: &str| StoreError::Invalid(format!("List Blobs response: {what}"));
    let mut listed = Vec::new();
    let mut rest = xml;
    while let Some(i) = rest.find("<Blob>") {
        let (_, from_blob) = rest.split_at_checked(i).ok_or_else(|| bad("unreadable"))?;
        let end = from_blob
            .find("</Blob>")
            .ok_or_else(|| bad("unclosed Blob"))?;
        let (blob, after) = from_blob
            .split_at_checked(end)
            .ok_or_else(|| bad("unreadable"))?;
        let path = element(blob, "Name").ok_or_else(|| bad("a Blob has no Name"))?;
        let etag = element(blob, "Etag").ok_or_else(|| bad("a Blob has no Etag"))?;
        let modified = element(blob, "Last-Modified").ok_or_else(|| bad("no Last-Modified"))?;
        listed.push(Listed {
            path,
            etag: ETag::from_raw(&etag),
            last_modified: DateTime::parse_from_rfc2822(&modified)
                .map_err(|_| bad("Last-Modified isn't an HTTP date"))?
                .with_timezone(&Utc),
        });
        rest = after;
    }
    let next = element(xml, "NextMarker").filter(|m| !m.is_empty());
    Ok((listed, next))
}

impl ObjectStore for AzureBlob {
    fn get<'a>(
        &'a self,
        path: &'a str,
        cached: Option<&'a ETag>,
    ) -> BoxFuture<'a, Result<Fetched, StoreError>> {
        Box::pin(async move {
            let mut req = Req::new(Method::GET, self.blob_path(path)?);
            if let Some(etag) = cached {
                req.headers.push(("if-none-match", etag.0.clone()));
            }
            let response = self.account.send(req).await?;
            match response.status() {
                StatusCode::OK => {
                    let etag = etag_of(&response)?;
                    Ok(Fetched::Found {
                        body: response.into_body(),
                        etag,
                    })
                }
                StatusCode::NOT_MODIFIED => Ok(Fetched::NotModified),
                StatusCode::NOT_FOUND => Ok(Fetched::Missing),
                _ => Err(unexpected("get blob", &response)),
            }
        })
    }

    fn put_if_absent<'a>(
        &'a self,
        path: &'a str,
        body: Bytes,
    ) -> BoxFuture<'a, Result<Created, StoreError>> {
        Box::pin(async move {
            let req = self.put(path, body, ("if-none-match", "*".into()))?;
            let response = self.account.send(req).await?;
            match response.status() {
                StatusCode::CREATED => Ok(Created::New(etag_of(&response)?)),
                StatusCode::CONFLICT | StatusCode::PRECONDITION_FAILED => {
                    Ok(Created::AlreadyExists)
                }
                _ => Err(unexpected("put blob", &response)),
            }
        })
    }

    fn put_if_match<'a>(
        &'a self,
        path: &'a str,
        body: Bytes,
        etag: &'a ETag,
    ) -> BoxFuture<'a, Result<Replaced, StoreError>> {
        Box::pin(async move {
            let req = self.put(path, body, ("if-match", etag.0.clone()))?;
            let response = self.account.send(req).await?;
            match response.status() {
                StatusCode::CREATED => Ok(Replaced::Done(etag_of(&response)?)),
                StatusCode::PRECONDITION_FAILED | StatusCode::NOT_FOUND => Ok(Replaced::Stale),
                _ => Err(unexpected("put blob", &response)),
            }
        })
    }

    fn list<'a>(&'a self, dir: &'a str) -> BoxFuture<'a, Result<Vec<Listed>, StoreError>> {
        Box::pin(async move {
            if !dir.ends_with('/') {
                return Err(StoreError::Invalid(format!("{dir:?} isn't a directory")));
            }
            check_path(dir)?;
            let mut listed = Vec::new();
            let mut marker: Option<String> = None;
            for page in 1.. {
                if page > MAX_LIST_PAGES {
                    return Err(StoreError::Invalid(format!(
                        "{dir} holds more objects than a listing reads"
                    )));
                }
                let mut req = Req::new(
                    Method::GET,
                    format!("{}/{}", self.account.endpoint.prefix, self.container),
                );
                req.query = vec![
                    ("restype", "container".into()),
                    ("comp", "list".into()),
                    ("prefix", dir.into()),
                    ("delimiter", "/".into()),
                    ("maxresults", LIST_PAGE_SIZE.into()),
                ];
                if let Some(m) = &marker {
                    req.query.push(("marker", m.clone()));
                }
                let response = self.account.send(req).await?;
                if response.status() != StatusCode::OK {
                    return Err(unexpected("list blobs", &response));
                }
                let xml = String::from_utf8_lossy(response.body()).into_owned();
                let (page, next) = parse_list(&xml)?;
                listed.extend(page);
                match next {
                    Some(next) => marker = Some(next),
                    None => break,
                }
            }
            listed.sort_by(|a, b| a.path.cmp(&b.path));
            Ok(listed)
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering::SeqCst};

    use super::*;

    /// A managed identity endpoint that counts its token requests, takes
    /// 50 ms over each, and fails while `fail` is set.
    #[derive(Default)]
    struct Imds {
        requests: AtomicUsize,
        fail: AtomicBool,
        /// Seconds each token lasts.
        lifetime: AtomicI64,
    }

    fn serve(imds: Arc<Imds>) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}/token", listener.local_addr().unwrap());
        let app = axum::Router::new().route(
            "/token",
            axum::routing::get(move || {
                let imds = imds.clone();
                async move {
                    let n = imds.requests.fetch_add(1, SeqCst) + 1;
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    if imds.fail.load(SeqCst) {
                        return (StatusCode::INTERNAL_SERVER_ERROR, String::new());
                    }
                    let expires_on = Utc::now().timestamp() + imds.lifetime.load(SeqCst);
                    let body = serde_json::json!({
                        "access_token": format!("t{n}"),
                        "expires_on": expires_on.to_string(),
                    });
                    (StatusCode::OK, body.to_string())
                }
            }),
        );
        tokio::spawn(
            axum_server::from_tcp(listener)
                .unwrap()
                .serve(app.into_make_service()),
        );
        url
    }

    #[tokio::test]
    async fn one_token_fetch_serves_every_caller_and_failures_back_off() {
        let imds = Arc::new(Imds::default());
        imds.lifetime.store(3600, SeqCst);
        imds.fail.store(true, SeqCst);
        let tokens = Arc::new(Tokens::new(&serve(imds.clone()), None));
        let requests = || imds.requests.load(SeqCst);
        let callers = futures_util::future::join_all((0..100).map(|_| {
            let tokens = tokens.clone();
            async move { tokens.bearer().await }
        }))
        .await;
        assert!(callers.iter().all(Result::is_err));
        assert_eq!(requests(), 1, "one fetch answered all hundred");

        // Its failure holds for a second.
        let refused = tokens.bearer().await.unwrap_err();
        assert!(refused.to_string().contains("500"), "{refused}");
        assert_eq!(requests(), 1);
        imds.fail.store(false, SeqCst);
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert_eq!(tokens.bearer().await.unwrap(), "Bearer t2");
        for _ in 0..10 {
            assert_eq!(tokens.bearer().await.unwrap(), "Bearer t2");
        }
        assert_eq!(requests(), 2);
    }

    #[tokio::test]
    async fn a_token_near_expiry_works_while_it_is_replaced() {
        let imds = Arc::new(Imds::default());
        // Inside the refresh margin, outside the expiry margin.
        imds.lifetime.store(200, SeqCst);
        let tokens = Tokens::new(&serve(imds.clone()), None);
        assert_eq!(tokens.bearer().await.unwrap(), "Bearer t1");
        imds.fail.store(true, SeqCst);
        // Used at once, while a replacement is fetched; still used after
        // that fails.
        assert_eq!(tokens.bearer().await.unwrap(), "Bearer t1");
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(imds.requests.load(SeqCst), 2);
        assert_eq!(tokens.bearer().await.unwrap(), "Bearer t1");

        // Once the failure is waited out, the next call fetches again, and
        // the token that brings replaces the old one.
        imds.fail.store(false, SeqCst);
        imds.lifetime.store(3600, SeqCst);
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert_eq!(tokens.bearer().await.unwrap(), "Bearer t1");
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(tokens.bearer().await.unwrap(), "Bearer t3");
        assert_eq!(imds.requests.load(SeqCst), 3);
    }

    #[test]
    fn endpoints_split_azurite_prefixes() {
        let azure = Endpoint::parse("https://acct.blob.core.windows.net/").unwrap();
        assert_eq!(azure.origin, "https://acct.blob.core.windows.net");
        assert_eq!(azure.prefix, "");
        let azurite = Endpoint::parse("http://127.0.0.1:10000/devstoreaccount1").unwrap();
        assert_eq!(azurite.origin, "http://127.0.0.1:10000");
        assert_eq!(azurite.prefix, "/devstoreaccount1");
        assert!(Endpoint::parse("ftp://x").is_err());
    }

    #[test]
    fn list_pages_parse_blobs_and_skip_prefixes() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<EnumerationResults ServiceEndpoint="https://acct.blob.core.windows.net/" ContainerName="state">
  <Prefix>pools/</Prefix><Delimiter>/</Delimiter>
  <Blobs>
    <Blob><Name>pools/A.json</Name><Properties>
      <Creation-Time>Tue, 29 Sep 2026 10:00:00 GMT</Creation-Time>
      <Last-Modified>Tue, 29 Sep 2026 10:05:00 GMT</Last-Modified>
      <Etag>0x8DDA1</Etag><Content-Length>12</Content-Length>
    </Properties></Blob>
    <BlobPrefix><Name>pools/A/</Name></BlobPrefix>
    <Blob><Name>pools/B&amp;C.json</Name><Properties>
      <Last-Modified>Tue, 29 Sep 2026 11:00:00 GMT</Last-Modified>
      <Etag>"0x8DDA2"</Etag>
    </Properties></Blob>
  </Blobs>
  <NextMarker>2!72!MDAw</NextMarker>
</EnumerationResults>"#;
        let (listed, next) = parse_list(xml).unwrap();
        let paths: Vec<_> = listed.iter().map(|l| l.path.as_str()).collect();
        assert_eq!(paths, ["pools/A.json", "pools/B&C.json"]);
        assert_eq!(listed[0].etag, ETag("\"0x8DDA1\"".into()));
        assert_eq!(listed[1].etag, ETag("\"0x8DDA2\"".into()));
        assert_eq!(
            listed[0].last_modified.to_rfc3339(),
            "2026-09-29T10:05:00+00:00"
        );
        assert_eq!(next.as_deref(), Some("2!72!MDAw"));

        let (empty, next) =
            parse_list("<EnumerationResults><Blobs /><NextMarker /></EnumerationResults>").unwrap();
        assert!(empty.is_empty());
        assert_eq!(next, None);
    }
}
