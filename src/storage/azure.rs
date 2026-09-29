// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Azure Blob and Table storage over the crate's hyper client.
//!
//! Requests authenticate with Entra bearer tokens for
//! `https://storage.azure.com/`, from the managed-identity endpoint; the
//! storage account has shared keys disabled. Dev builds can also sign with
//! Azurite's well-known dev account key instead.
//!
//! Both services use API version 2021-12-02. Table requests use JSON with
//! minimal metadata, so rows read from queries carry their ETags.

use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use bytes::Bytes;
use http_body_util::Full;
use hyper::{Method, Request, StatusCode};
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use serde_json::{Map, Value};
use tokio::sync::Mutex;
use tracing::{debug, info};
use zeroize::Zeroizing;

use chrono::{DateTime, Utc};

use super::store::{
    BatchOp, BoxFuture, Container, Continuation, ETag, Entity, Filter, IndexStore, InsertOutcome,
    Object, ObjectStore, Page, Prop, PutOutcome, RkRange, StoreError, Table,
};
use crate::http_client::{HttpClient, Response};

const API_VERSION: &str = "2021-12-02";
const STORAGE_RESOURCE: &str = "https://storage.azure.com/";
const IMDS_TOKEN_URL: &str = "http://169.254.169.254/metadata/identity/oauth2/token";
/// Tokens are refreshed this long before they expire.
const TOKEN_REFRESH_MARGIN_SECS: i64 = 300;
const TABLE_ACCEPT: &str = "application/json;odata=minimalmetadata";
const ODATA_VERSION: &str = "3.0;NetFx";

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
/// Characters kept as-is in query values and table keys.
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
    /// For example `https://stiobmicrespilot.blob.core.windows.net`, or
    /// `http://127.0.0.1:10000/devstoreaccount1` for Azurite.
    pub blob_url: String,
    pub table_url: String,
    pub credential: CredentialConfig,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Service {
    Blob,
    Table,
}

/// A service's origin and path prefix. Azurite puts the account name in the
/// path instead of the host.
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

/// The Azure implementation of both storage traits.
pub struct AzureStore {
    http: HttpClient,
    blob: Endpoint,
    table: Endpoint,
    credential: Credential,
}

/// A request before authentication. Header names are lowercase.
struct Req {
    service: Service,
    method: Method,
    /// Percent-encoded, starting with the endpoint prefix.
    path: String,
    query: Vec<(&'static str, String)>,
    headers: Vec<(&'static str, String)>,
    body: Bytes,
}

impl Req {
    #[cfg(feature = "dev")]
    fn header(&self, name: &str) -> &str {
        self.headers
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.as_str())
            .unwrap_or("")
    }
}

impl AzureStore {
    pub fn new(config: &AzureConfig) -> Result<Self, String> {
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
            http: HttpClient::new().with_timeout(Duration::from_secs(30)),
            blob: Endpoint::parse(&config.blob_url)?,
            table: Endpoint::parse(&config.table_url)?,
            credential,
        })
    }

    /// Create any missing container or table. Existing ones are left alone.
    pub async fn ensure_layout(&self) -> Result<(), StoreError> {
        for container in Container::ALL {
            let response = self
                .send(Req {
                    service: Service::Blob,
                    method: Method::PUT,
                    path: format!("{}/{}", self.blob.prefix, container.name()),
                    query: vec![("restype", "container".into())],
                    headers: vec![],
                    body: Bytes::new(),
                })
                .await?;
            match response.status() {
                StatusCode::CREATED => info!(container = container.name(), "Created container"),
                StatusCode::CONFLICT => {}
                _ => return Err(unexpected("create container", &response)),
            }
        }
        for table in Table::ALL {
            let body = serde_json::json!({ "TableName": table.name() }).to_string();
            let response = self
                .send(Req {
                    service: Service::Table,
                    method: Method::POST,
                    path: format!("{}/Tables", self.table.prefix),
                    query: vec![],
                    headers: table_headers(true, vec![("prefer", "return-no-content".into())]),
                    body: Bytes::from(body),
                })
                .await?;
            match response.status() {
                StatusCode::CREATED | StatusCode::NO_CONTENT => {
                    info!(table = table.name(), "Created table")
                }
                StatusCode::CONFLICT => {}
                _ => return Err(unexpected("create table", &response)),
            }
        }
        Ok(())
    }

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

        let endpoint = match req.service {
            Service::Blob => &self.blob,
            Service::Table => &self.table,
        };
        let mut url = format!("{}{}", endpoint.origin, req.path);
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
        let now = chrono::Utc::now().timestamp();
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

    fn blob_path(&self, c: Container, path: &str) -> String {
        format!(
            "{}/{}/{}",
            self.blob.prefix,
            c.name(),
            utf8_percent_encode(path, PATH)
        )
    }

    fn entity_path(&self, t: Table, pk: &str, rk: &str) -> String {
        format!(
            "{}/{}(PartitionKey='{}',RowKey='{}')",
            self.table.prefix,
            t.name(),
            table_key(pk),
            table_key(rk)
        )
    }
}

/// RFC 1123 date for `x-ms-date`.
fn http_date() -> String {
    chrono::Utc::now()
        .format("%a, %d %b %Y %H:%M:%S GMT")
        .to_string()
}

/// A table key inside `'…'` in a URL path: quotes doubled, then encoded.
fn table_key(key: &str) -> String {
    utf8_percent_encode(&key.replace('\'', "''"), VALUE).to_string()
}

fn table_headers(
    with_body: bool,
    mut extra: Vec<(&'static str, String)>,
) -> Vec<(&'static str, String)> {
    let mut headers = vec![
        ("accept", TABLE_ACCEPT.to_string()),
        ("dataserviceversion", ODATA_VERSION.to_string()),
        ("maxdataserviceversion", ODATA_VERSION.to_string()),
    ];
    if with_body {
        headers.push(("content-type", "application/json".to_string()));
    }
    headers.append(&mut extra);
    headers
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

/// The Shared Key string-to-sign for Blob and Table requests.
#[cfg(feature = "dev")]
fn string_to_sign(account: &str, req: &Req) -> String {
    let mut resource = format!("/{account}{}", req.path);
    match req.service {
        Service::Blob => {
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
        Service::Table => {
            if let Some((_, comp)) = req.query.iter().find(|(n, _)| *n == "comp") {
                resource.push_str(&format!("?comp={comp}"));
            }
            format!(
                "{}\n\n{}\n{}\n{resource}",
                req.method,
                req.header("content-type"),
                req.header("x-ms-date"),
            )
        }
    }
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
        .map(|e| ETag(e.to_string()))
        .ok_or_else(|| StoreError::Invalid("response has no ETag".into()))
}

impl ObjectStore for AzureStore {
    fn get<'a>(
        &'a self,
        c: Container,
        path: &'a str,
    ) -> BoxFuture<'a, Result<Option<Object>, StoreError>> {
        Box::pin(async move {
            let response = self
                .send(Req {
                    service: Service::Blob,
                    method: Method::GET,
                    path: self.blob_path(c, path),
                    query: vec![],
                    headers: vec![],
                    body: Bytes::new(),
                })
                .await?;
            match response.status() {
                StatusCode::OK => {
                    let etag = etag_of(&response)?;
                    Ok(Some(Object {
                        body: response.into_body(),
                        etag,
                    }))
                }
                StatusCode::NOT_FOUND => Ok(None),
                _ => Err(unexpected("get blob", &response)),
            }
        })
    }

    fn put_if_absent<'a>(
        &'a self,
        c: Container,
        path: &'a str,
        body: Bytes,
    ) -> BoxFuture<'a, Result<PutOutcome, StoreError>> {
        Box::pin(async move {
            let response = self
                .send(Req {
                    service: Service::Blob,
                    method: Method::PUT,
                    path: self.blob_path(c, path),
                    query: vec![],
                    headers: vec![
                        ("content-type", "application/octet-stream".into()),
                        ("if-none-match", "*".into()),
                        ("x-ms-blob-type", "BlockBlob".into()),
                    ],
                    body,
                })
                .await?;
            match response.status() {
                StatusCode::CREATED => Ok(PutOutcome::Created(etag_of(&response)?)),
                StatusCode::CONFLICT | StatusCode::PRECONDITION_FAILED => {
                    Ok(PutOutcome::AlreadyExists)
                }
                _ => Err(unexpected("put blob", &response)),
            }
        })
    }

    fn put_if_match<'a>(
        &'a self,
        c: Container,
        path: &'a str,
        body: Bytes,
        etag: &'a ETag,
    ) -> BoxFuture<'a, Result<ETag, StoreError>> {
        Box::pin(async move {
            let response = self
                .send(Req {
                    service: Service::Blob,
                    method: Method::PUT,
                    path: self.blob_path(c, path),
                    query: vec![],
                    headers: vec![
                        ("content-type", "application/octet-stream".into()),
                        ("if-match", etag.0.clone()),
                        ("x-ms-blob-type", "BlockBlob".into()),
                    ],
                    body,
                })
                .await?;
            match response.status() {
                StatusCode::CREATED => etag_of(&response),
                StatusCode::PRECONDITION_FAILED => Err(StoreError::PreconditionFailed),
                StatusCode::NOT_FOUND => Err(StoreError::NotFound),
                StatusCode::CONFLICT => Err(StoreError::Conflict),
                _ => Err(unexpected("put blob", &response)),
            }
        })
    }

    fn append<'a>(
        &'a self,
        c: Container,
        path: &'a str,
        block: Bytes,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            let append_block = || Req {
                service: Service::Blob,
                method: Method::PUT,
                path: self.blob_path(c, path),
                query: vec![("comp", "appendblock".into())],
                headers: vec![],
                body: block.clone(),
            };
            let response = self.send(append_block()).await?;
            if response.status() == StatusCode::CREATED {
                return Ok(());
            }
            if response.status() != StatusCode::NOT_FOUND {
                return Err(unexpected("append block", &response));
            }

            // The first append of the hour creates the blob.
            let created = self
                .send(Req {
                    service: Service::Blob,
                    method: Method::PUT,
                    path: self.blob_path(c, path),
                    query: vec![],
                    headers: vec![
                        ("if-none-match", "*".into()),
                        ("x-ms-blob-type", "AppendBlob".into()),
                    ],
                    body: Bytes::new(),
                })
                .await?;
            if !matches!(
                created.status(),
                StatusCode::CREATED | StatusCode::CONFLICT | StatusCode::PRECONDITION_FAILED
            ) {
                return Err(unexpected("create append blob", &created));
            }
            let retried = self.send(append_block()).await?;
            if retried.status() == StatusCode::CREATED {
                Ok(())
            } else {
                Err(unexpected("append block", &retried))
            }
        })
    }

    fn delete<'a>(&'a self, c: Container, path: &'a str) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            let response = self
                .send(Req {
                    service: Service::Blob,
                    method: Method::DELETE,
                    path: self.blob_path(c, path),
                    query: vec![],
                    headers: vec![],
                    body: Bytes::new(),
                })
                .await?;
            match response.status() {
                StatusCode::ACCEPTED | StatusCode::NOT_FOUND => Ok(()),
                StatusCode::CONFLICT => Err(StoreError::Conflict),
                _ => Err(unexpected("delete blob", &response)),
            }
        })
    }

    fn set_immutability<'a>(
        &'a self,
        c: Container,
        path: &'a str,
        until: DateTime<Utc>,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            let response = self
                .send(Req {
                    service: Service::Blob,
                    method: Method::PUT,
                    path: self.blob_path(c, path),
                    query: vec![("comp", "immutabilityPolicies".into())],
                    headers: vec![
                        (
                            "x-ms-immutability-policy-until-date",
                            until.format("%a, %d %b %Y %H:%M:%S GMT").to_string(),
                        ),
                        ("x-ms-immutability-policy-mode", "Unlocked".into()),
                    ],
                    body: Bytes::new(),
                })
                .await?;
            match response.status() {
                StatusCode::OK => Ok(()),
                StatusCode::NOT_FOUND => Err(StoreError::NotFound),
                _ => Err(unexpected("set immutability policy", &response)),
            }
        })
    }
}

/// Render an entity as Table JSON.
fn entity_json(e: &Entity) -> Value {
    let mut map = Map::new();
    map.insert("PartitionKey".into(), Value::String(e.pk.clone()));
    map.insert("RowKey".into(), Value::String(e.rk.clone()));
    for (name, prop) in &e.props {
        match prop {
            Prop::Str(s) => {
                map.insert(name.clone(), Value::String(s.clone()));
            }
            Prop::Bool(b) => {
                map.insert(name.clone(), Value::Bool(*b));
            }
            Prop::Bin(bytes) => {
                map.insert(format!("{name}@odata.type"), "Edm.Binary".into());
                map.insert(name.clone(), Value::String(STANDARD.encode(bytes)));
            }
        }
    }
    Value::Object(map)
}

/// Parse a Table JSON entity. `etag` overrides the body's `odata.etag`.
fn entity_from_json(value: &Value, etag: Option<ETag>) -> Result<Entity, StoreError> {
    let map = value
        .as_object()
        .ok_or_else(|| StoreError::Invalid("entity isn't a JSON object".into()))?;
    let key = |name: &str| {
        map.get(name)
            .and_then(Value::as_str)
            .map(String::from)
            .ok_or_else(|| StoreError::Invalid(format!("entity has no {name}")))
    };
    let mut entity = Entity::new(key("PartitionKey")?, key("RowKey")?);
    entity.etag = etag.or_else(|| {
        map.get("odata.etag")
            .and_then(Value::as_str)
            .map(|e| ETag(e.to_string()))
    });
    for (name, value) in map {
        if name.starts_with("odata.")
            || name.contains('@')
            || matches!(name.as_str(), "PartitionKey" | "RowKey" | "Timestamp")
        {
            continue;
        }
        let binary = map
            .get(&format!("{name}@odata.type"))
            .and_then(Value::as_str)
            == Some("Edm.Binary");
        let prop = match value {
            Value::String(s) if binary => Prop::Bin(
                STANDARD
                    .decode(s)
                    .map_err(|_| StoreError::Invalid(format!("{name} isn't base64")))?,
            ),
            Value::String(s) => Prop::Str(s.clone()),
            Value::Bool(b) => Prop::Bool(*b),
            _ => continue,
        };
        entity.props.insert(name.clone(), prop);
    }
    Ok(entity)
}

/// An OData string literal.
fn literal(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

fn render_filter(filter: &Filter) -> Result<String, StoreError> {
    Ok(match filter {
        Filter::Eq(name, Prop::Str(s)) => format!("{name} eq {}", literal(s)),
        Filter::Eq(name, Prop::Bool(b)) => format!("{name} eq {b}"),
        Filter::Eq(_, Prop::Bin(_)) => {
            return Err(StoreError::Invalid(
                "binary properties can't be filtered".into(),
            ))
        }
        Filter::And(all) => all
            .iter()
            .map(|f| render_filter(f).map(|s| format!("({s})")))
            .collect::<Result<Vec<_>, _>>()?
            .join(" and "),
        Filter::Or(any) => any
            .iter()
            .map(|f| render_filter(f).map(|s| format!("({s})")))
            .collect::<Result<Vec<_>, _>>()?
            .join(" or "),
    })
}

impl IndexStore for AzureStore {
    fn get<'a>(
        &'a self,
        t: Table,
        pk: &'a str,
        rk: &'a str,
    ) -> BoxFuture<'a, Result<Option<Entity>, StoreError>> {
        Box::pin(async move {
            let response = self
                .send(Req {
                    service: Service::Table,
                    method: Method::GET,
                    path: self.entity_path(t, pk, rk),
                    query: vec![],
                    headers: table_headers(false, vec![]),
                    body: Bytes::new(),
                })
                .await?;
            match response.status() {
                StatusCode::OK => {
                    let etag = response.header("etag").map(|e| ETag(e.to_string()));
                    let value: Value = serde_json::from_slice(&response.into_body())
                        .map_err(|_| StoreError::Invalid("entity isn't JSON".into()))?;
                    entity_from_json(&value, etag).map(Some)
                }
                StatusCode::NOT_FOUND => Ok(None),
                _ => Err(unexpected("get entity", &response)),
            }
        })
    }

    fn insert(&self, t: Table, e: Entity) -> BoxFuture<'_, Result<InsertOutcome, StoreError>> {
        Box::pin(async move {
            let response = self
                .send(Req {
                    service: Service::Table,
                    method: Method::POST,
                    path: format!("{}/{}", self.table.prefix, t.name()),
                    query: vec![],
                    headers: table_headers(true, vec![("prefer", "return-no-content".into())]),
                    body: Bytes::from(entity_json(&e).to_string()),
                })
                .await?;
            match response.status() {
                StatusCode::NO_CONTENT | StatusCode::CREATED => {
                    Ok(InsertOutcome::Inserted(etag_of(&response)?))
                }
                StatusCode::CONFLICT => Ok(InsertOutcome::Conflict),
                _ => Err(unexpected("insert entity", &response)),
            }
        })
    }

    fn update_if_match<'a>(
        &'a self,
        t: Table,
        e: Entity,
        etag: &'a ETag,
    ) -> BoxFuture<'a, Result<ETag, StoreError>> {
        Box::pin(async move {
            let response = self
                .send(Req {
                    service: Service::Table,
                    method: Method::PUT,
                    path: self.entity_path(t, &e.pk, &e.rk),
                    query: vec![],
                    headers: table_headers(true, vec![("if-match", etag.0.clone())]),
                    body: Bytes::from(entity_json(&e).to_string()),
                })
                .await?;
            match response.status() {
                StatusCode::NO_CONTENT => etag_of(&response),
                StatusCode::PRECONDITION_FAILED => Err(StoreError::PreconditionFailed),
                StatusCode::NOT_FOUND => Err(StoreError::NotFound),
                _ => Err(unexpected("update entity", &response)),
            }
        })
    }

    fn upsert(&self, t: Table, e: Entity) -> BoxFuture<'_, Result<ETag, StoreError>> {
        Box::pin(async move {
            let response = self
                .send(Req {
                    service: Service::Table,
                    method: Method::PUT,
                    path: self.entity_path(t, &e.pk, &e.rk),
                    query: vec![],
                    headers: table_headers(true, vec![]),
                    body: Bytes::from(entity_json(&e).to_string()),
                })
                .await?;
            match response.status() {
                StatusCode::NO_CONTENT => etag_of(&response),
                _ => Err(unexpected("upsert entity", &response)),
            }
        })
    }

    fn delete_if_match<'a>(
        &'a self,
        t: Table,
        pk: &'a str,
        rk: &'a str,
        etag: &'a ETag,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            let response = self
                .send(Req {
                    service: Service::Table,
                    method: Method::DELETE,
                    path: self.entity_path(t, pk, rk),
                    query: vec![],
                    headers: table_headers(false, vec![("if-match", etag.0.clone())]),
                    body: Bytes::new(),
                })
                .await?;
            match response.status() {
                StatusCode::NO_CONTENT => Ok(()),
                StatusCode::PRECONDITION_FAILED => Err(StoreError::PreconditionFailed),
                StatusCode::NOT_FOUND => Err(StoreError::NotFound),
                _ => Err(unexpected("delete entity", &response)),
            }
        })
    }

    fn query<'a>(
        &'a self,
        t: Table,
        pk: &'a str,
        rk: RkRange,
        filter: Option<Filter>,
        top: usize,
        page: Option<Continuation>,
    ) -> BoxFuture<'a, Result<Page<Entity>, StoreError>> {
        Box::pin(async move {
            let mut clauses = vec![format!("PartitionKey eq {}", literal(pk))];
            if let Some(start) = &rk.start {
                clauses.push(format!("RowKey ge {}", literal(start)));
            }
            if let Some(end) = &rk.end {
                clauses.push(format!("RowKey lt {}", literal(end)));
            }
            if let Some(filter) = &filter {
                clauses.push(format!("({})", render_filter(filter)?));
            }
            let mut query = vec![
                ("$filter", clauses.join(" and ")),
                ("$top", top.clamp(1, 1000).to_string()),
            ];
            if let Some(Continuation(token)) = &page {
                let (next_pk, next_rk) = token
                    .split_once('\n')
                    .ok_or_else(|| StoreError::Invalid("bad continuation".into()))?;
                query.push(("NextPartitionKey", next_pk.to_string()));
                if !next_rk.is_empty() {
                    query.push(("NextRowKey", next_rk.to_string()));
                }
            }
            let response = self
                .send(Req {
                    service: Service::Table,
                    method: Method::GET,
                    path: format!("{}/{}()", self.table.prefix, t.name()),
                    query,
                    headers: table_headers(false, vec![]),
                    body: Bytes::new(),
                })
                .await?;
            if response.status() != StatusCode::OK {
                return Err(unexpected("query entities", &response));
            }
            let next = response
                .header("x-ms-continuation-NextPartitionKey")
                .map(|npk| {
                    let nrk = response
                        .header("x-ms-continuation-NextRowKey")
                        .unwrap_or("");
                    Continuation(format!("{npk}\n{nrk}"))
                });
            let body: Value = serde_json::from_slice(&response.into_body())
                .map_err(|_| StoreError::Invalid("query response isn't JSON".into()))?;
            let items = body["value"]
                .as_array()
                .ok_or_else(|| StoreError::Invalid("query response has no value".into()))?
                .iter()
                .map(|v| entity_from_json(v, None))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Page { items, next })
        })
    }

    fn batch<'a>(
        &'a self,
        t: Table,
        pk: &'a str,
        ops: Vec<BatchOp>,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            if ops.is_empty() {
                return Ok(());
            }
            if ops.len() > 100 {
                return Err(StoreError::Invalid(
                    "a batch holds at most 100 operations".into(),
                ));
            }
            let id = uuid::Uuid::new_v4().simple().to_string();
            let batch = format!("batch_{id}");
            let changeset = format!("changeset_{id}");
            let mut body =
                format!("--{batch}\r\nContent-Type: multipart/mixed; boundary={changeset}\r\n\r\n");
            for op in &ops {
                let (method, entity, if_match) = match op {
                    BatchOp::Insert(e) => ("POST", e, None),
                    BatchOp::UpdateIfMatch(e, etag) => ("PUT", e, Some(etag)),
                };
                if entity.pk != pk {
                    return Err(StoreError::Invalid(
                        "batch rows must share a partition".into(),
                    ));
                }
                let url = match op {
                    BatchOp::Insert(_) => {
                        format!("{}{}/{}", self.table.origin, self.table.prefix, t.name())
                    }
                    BatchOp::UpdateIfMatch(..) => format!(
                        "{}{}",
                        self.table.origin,
                        self.entity_path(t, &entity.pk, &entity.rk)
                    ),
                };
                body.push_str(&format!(
                    "--{changeset}\r\nContent-Type: application/http\r\nContent-Transfer-Encoding: binary\r\n\r\n\
                     {method} {url} HTTP/1.1\r\nContent-Type: application/json\r\nAccept: {TABLE_ACCEPT}\r\n\
                     DataServiceVersion: 3.0;\r\nPrefer: return-no-content\r\n"
                ));
                if let Some(etag) = if_match {
                    body.push_str(&format!("If-Match: {}\r\n", etag.0));
                }
                body.push_str(&format!("\r\n{}\r\n", entity_json(entity)));
            }
            body.push_str(&format!("--{changeset}--\r\n--{batch}--\r\n"));

            let response = self
                .send(Req {
                    service: Service::Table,
                    method: Method::POST,
                    path: format!("{}/$batch", self.table.prefix),
                    query: vec![],
                    headers: vec![
                        ("accept", TABLE_ACCEPT.to_string()),
                        ("content-type", format!("multipart/mixed; boundary={batch}")),
                        ("dataserviceversion", ODATA_VERSION.to_string()),
                        ("maxdataserviceversion", ODATA_VERSION.to_string()),
                    ],
                    body: Bytes::from(body),
                })
                .await?;
            if response.status() != StatusCode::ACCEPTED {
                return Err(unexpected("table batch", &response));
            }
            // The changeset either succeeds as a whole or reports the one
            // operation that failed.
            let text = String::from_utf8_lossy(response.body()).into_owned();
            let failed = text
                .lines()
                .filter_map(|line| line.strip_prefix("HTTP/1.1 "))
                .filter_map(|rest| rest.get(..3)?.parse::<u16>().ok())
                .find(|status| !(200..300).contains(status));
            match failed {
                None => Ok(()),
                Some(409) => Err(StoreError::Conflict),
                Some(412) => Err(StoreError::PreconditionFailed),
                Some(404) => Err(StoreError::NotFound),
                Some(status) => Err(StoreError::Invalid(format!(
                    "table batch operation failed with HTTP {status}"
                ))),
            }
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
    fn entities_round_trip_through_table_json() {
        let entity = Entity::new("owner:abc", "wallet")
            .with("status", Prop::Str("active".into()))
            .with("success", Prop::Bool(true))
            .with("payload", Prop::Bin(vec![0, 1, 2, 255]));
        let json = entity_json(&entity);
        assert_eq!(json["payload@odata.type"], "Edm.Binary");
        let parsed = entity_from_json(&json, Some(ETag("W/\"1\"".into()))).unwrap();
        assert_eq!(parsed.props, entity.props);
        assert_eq!(parsed.etag, Some(ETag("W/\"1\"".into())));
    }

    #[test]
    fn filters_render_as_odata() {
        let filter = Filter::And(vec![
            Filter::Or(vec![
                Filter::eq("event_type", Prop::Str("pool_created".into())),
                Filter::eq("event_type", Prop::Str("o'brien".into())),
            ]),
            Filter::eq("success", Prop::Bool(false)),
        ]);
        assert_eq!(
            render_filter(&filter).unwrap(),
            "((event_type eq 'pool_created') or (event_type eq 'o''brien')) and (success eq false)"
        );
        assert_eq!(table_key("owner:ab"), "owner%3Aab");
    }
}
