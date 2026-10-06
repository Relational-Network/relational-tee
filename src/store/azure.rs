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
use tokio::sync::Mutex;
use tracing::{debug, info};
use zeroize::Zeroizing;

use super::{
    check_path, BoxFuture, Created, ETag, Fetched, Listed, ObjectStore, Replaced, StoreError,
};
use crate::http_client::{HttpClient, Response};

const API_VERSION: &str = "2021-12-02";
const STORAGE_RESOURCE: &str = "https://storage.azure.com/";
const IMDS_TOKEN_URL: &str = "http://169.254.169.254/metadata/identity/oauth2/token";
/// Tokens are refreshed this long before they expire.
const TOKEN_REFRESH_MARGIN_SECS: i64 = 300;
/// The most objects one List Blobs page returns.
const LIST_PAGE_SIZE: &str = "5000";

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
            Some(i) => (&rest[..i], &rest[i..]),
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

enum Credential {
    ManagedIdentity {
        client_id: Option<String>,
        cached: Mutex<Option<CachedToken>>,
    },
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
            CredentialConfig::ManagedIdentity { client_id } => Credential::ManagedIdentity {
                client_id: client_id.clone(),
                cached: Mutex::new(None),
            },
            #[cfg(feature = "dev")]
            CredentialConfig::AzuriteDevAccount => Credential::SharedKey {
                account: AZURITE_ACCOUNT.to_string(),
                key: Zeroizing::new(STANDARD.decode(AZURITE_KEY).expect("valid base64")),
            },
        };
        Ok(Self {
            account: Arc::new(Account {
                http: HttpClient::new().with_timeout(Duration::from_secs(30)),
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
            Credential::ManagedIdentity { client_id, cached } => {
                self.bearer(client_id.as_deref(), cached).await?
            }
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

    /// A bearer token for Storage, cached until shortly before it expires.
    async fn bearer(
        &self,
        client_id: Option<&str>,
        cached: &Mutex<Option<CachedToken>>,
    ) -> Result<String, StoreError> {
        let mut cached = cached.lock().await;
        let now = Utc::now().timestamp();
        if let Some(token) = cached.as_ref() {
            if token.expires_on - TOKEN_REFRESH_MARGIN_SECS > now {
                return Ok(format!("Bearer {}", token.token.as_str()));
            }
        }
        let fresh = self.managed_identity_token(client_id).await?;
        let header = format!("Bearer {}", fresh.token.as_str());
        *cached = Some(fresh);
        Ok(header)
    }

    async fn managed_identity_token(
        &self,
        client_id: Option<&str>,
    ) -> Result<CachedToken, StoreError> {
        let mut url = format!(
            "{IMDS_TOKEN_URL}?api-version=2018-02-01&resource={}",
            utf8_percent_encode(STORAGE_RESOURCE, VALUE)
        );
        if let Some(id) = client_id {
            url.push_str("&client_id=");
            url.extend(utf8_percent_encode(id, VALUE));
        }
        let request = Request::builder()
            .method(Method::GET)
            .uri(&url)
            .header("metadata", "true")
            .body(Full::new(Bytes::new()))
            .map_err(|e| StoreError::Invalid(format!("building token request: {e}")))?;
        let response = self
            .http
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
        let token = body["access_token"].as_str().ok_or_else(|| {
            StoreError::Unavailable("managed identity response has no token".into())
        })?;
        // `expires_on` is epoch seconds, sent as a string.
        let expires_on = body["expires_on"]
            .as_str()
            .and_then(|s| s.parse().ok())
            .or_else(|| body["expires_on"].as_i64())
            .ok_or_else(|| {
                StoreError::Unavailable("managed identity token has no expiry".into())
            })?;
        Ok(CachedToken {
            token: Zeroizing::new(token.to_string()),
            expires_on,
        })
    }
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
    while let Some(i) = xml[from..].find(&open) {
        let start = from + i + open.len();
        let rest = &xml[start..];
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
        if xml[..body_start].ends_with("/>") {
            return Some(String::new());
        }
        let end = xml[body_start..].find(&format!("</{tag}>"))?;
        return Some(unescape(&xml[body_start..body_start + end]));
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
        let end = rest[i..]
            .find("</Blob>")
            .ok_or_else(|| bad("unclosed Blob"))?;
        let blob = &rest[i..i + end];
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
        rest = &rest[i + end..];
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
            loop {
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
    use super::*;

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
