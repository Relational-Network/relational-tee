// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Fetching analysis definitions when a pool is created: only under the
//! allowlisted raw GitHub prefix, only from public addresses, within a size
//! cap and a deadline. Each connection resolves the host itself and drops
//! every private, loopback or link-local answer, so whatever DNS says, a
//! fetch never reaches the worker's own network.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{header, Request, StatusCode, Uri};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::connect::dns::Name;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioExecutor;

use super::definition::MAX_DEFINITION_BYTES;
use crate::blockchain::drt::types::MAX_CODE_REPO_URL_LEN;
use crate::tee::BoxFuture;

/// Every definition URL starts with this.
pub const ALLOWED_PREFIX: &str = "https://raw.githubusercontent.com/relational-network/";
const FETCH_TIMEOUT: Duration = Duration::from_secs(20);
const USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

/// Why a definition couldn't be fetched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchError {
    /// The URL, or what it answered, will never do: a retry can't help.
    Refused(String),
    /// GitHub couldn't be reached, or failed: a retry may help.
    Unavailable(String),
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(message) | Self::Unavailable(message) => f.write_str(message),
        }
    }
}

/// Where definitions come from.
pub trait Fetcher: Send + Sync {
    fn fetch<'a>(&'a self, url: &'a str) -> BoxFuture<'a, Result<Vec<u8>, FetchError>>;
}

/// Refuse a URL outside `https://raw.githubusercontent.com/relational-network/<repo>/<ref>/<path>`,
/// or one with a query, a fragment, an escape or a dot segment.
pub fn check_url(url: &str) -> Result<(), FetchError> {
    let refuse = |why: &str| Err(FetchError::Refused(format!("{url:?} {why}")));
    let Some(path) = url.strip_prefix(ALLOWED_PREFIX) else {
        return refuse(&format!("isn't under {ALLOWED_PREFIX}"));
    };
    if url.len() > MAX_CODE_REPO_URL_LEN {
        return refuse(&format!("is over {MAX_CODE_REPO_URL_LEN} bytes"));
    }
    if url
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '?' | '#' | '%' | '\\'))
    {
        return refuse("has a character a definition URL can't");
    }
    let segments: Vec<&str> = path.split('/').collect();
    if segments.len() < 3
        || segments
            .iter()
            .any(|s| s.is_empty() || *s == "." || *s == "..")
    {
        return refuse("must name a repository, a ref and a file");
    }
    Ok(())
}

fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_multicast()
                || a == 0
                || (a == 100 && (64..128).contains(&b))
                || (a == 192 && b == 0 && c == 0)
                || a >= 240)
        }
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_public(IpAddr::V4(v4)),
            None => {
                !(v6.is_loopback()
                    || v6.is_unspecified()
                    || v6.is_multicast()
                    || v6.is_unique_local()
                    || v6.is_unicast_link_local())
            }
        },
    }
}

/// Resolves a host, keeping only its public addresses.
#[derive(Clone)]
struct PublicOnly;

impl tower_service::Service<Name> for PublicOnly {
    type Response = std::vec::IntoIter<SocketAddr>;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, name: Name) -> Self::Future {
        Box::pin(async move {
            let found: Vec<SocketAddr> = tokio::net::lookup_host((name.as_str(), 0))
                .await?
                .filter(|a| is_public(a.ip()))
                .collect();
            if found.is_empty() {
                return Err(std::io::Error::other(format!(
                    "{name} has no public address"
                )));
            }
            Ok(found.into_iter())
        })
    }
}

/// Fetches definitions from GitHub over HTTPS.
pub struct GitHub {
    client: Client<hyper_rustls::HttpsConnector<HttpConnector<PublicOnly>>, Full<Bytes>>,
}

impl GitHub {
    pub fn new() -> Self {
        let mut http = HttpConnector::new_with_resolver(PublicOnly);
        http.enforce_http(false);
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let https = HttpsConnectorBuilder::new()
            .with_tls_config(tls)
            .https_only()
            .enable_http1()
            .wrap_connector(http);
        Self {
            client: Client::builder(TokioExecutor::new()).build(https),
        }
    }

    async fn get(&self, url: &str) -> Result<Vec<u8>, FetchError> {
        let refused = |e: &dyn std::fmt::Display| FetchError::Refused(format!("{url}: {e}"));
        let uri: Uri = url.parse().map_err(|e| refused(&e))?;
        let request = Request::get(uri)
            .header(header::USER_AGENT, USER_AGENT)
            .body(Full::new(Bytes::new()))
            .map_err(|e| refused(&e))?;
        let response = self
            .client
            .request(request)
            .await
            .map_err(|e| FetchError::Unavailable(format!("couldn't fetch {url}: {e}")))?;
        match response.status() {
            StatusCode::OK => {}
            status if status.is_server_error() => {
                return Err(FetchError::Unavailable(format!("{url} answered {status}")));
            }
            status => return Err(FetchError::Refused(format!("{url} answered {status}"))),
        }
        let body = Limited::new(response.into_body(), MAX_DEFINITION_BYTES)
            .collect()
            .await
            .map_err(|e| refused(&e))?;
        Ok(body.to_bytes().to_vec())
    }
}

impl Fetcher for GitHub {
    fn fetch<'a>(&'a self, url: &'a str) -> BoxFuture<'a, Result<Vec<u8>, FetchError>> {
        Box::pin(async move {
            check_url(url)?;
            tokio::time::timeout(FETCH_TIMEOUT, self.get(url))
                .await
                .map_err(|_| {
                    FetchError::Unavailable(format!("{url} took longer than {FETCH_TIMEOUT:?}"))
                })?
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use super::*;

    /// The Awards Report's URL in tests.
    pub(crate) const AWARDS_REPORT_URL: &str =
        "https://raw.githubusercontent.com/relational-network/\
        relational-tee/0123456789abcdef0123456789abcdef01234567/drt-examples/awards-report/\
        awards-report-v1.toml";

    /// Serves fixed files, and counts fetches.
    #[derive(Default)]
    pub(crate) struct Fixed {
        pub files: BTreeMap<String, Vec<u8>>,
        pub fetched: Mutex<Vec<String>>,
    }

    impl Fixed {
        pub(crate) fn awards_report() -> Self {
            Self {
                files: BTreeMap::from([(
                    AWARDS_REPORT_URL.to_string(),
                    crate::analysis::definition::tests::AWARDS_REPORT
                        .as_bytes()
                        .to_vec(),
                )]),
                fetched: Mutex::default(),
            }
        }
    }

    impl Fetcher for Fixed {
        fn fetch<'a>(&'a self, url: &'a str) -> BoxFuture<'a, Result<Vec<u8>, FetchError>> {
            Box::pin(async move {
                check_url(url)?;
                self.fetched.lock().unwrap().push(url.to_string());
                self.files
                    .get(url)
                    .cloned()
                    .ok_or_else(|| FetchError::Refused(format!("{url} answered 404 Not Found")))
            })
        }
    }

    #[test]
    fn only_allowlisted_github_urls_pass() {
        check_url(AWARDS_REPORT_URL).unwrap();
        for bad in [
            "https://raw.githubusercontent.com/someone-else/repo/main/a.toml",
            "http://raw.githubusercontent.com/relational-network/repo/main/a.toml",
            "https://raw.githubusercontent.com.evil.example/relational-network/repo/main/a.toml",
            "https://raw.githubusercontent.com/relational-network/repo/main/../../a.toml",
            "https://raw.githubusercontent.com/relational-network/repo/main/%2e%2e/a.toml",
            "https://raw.githubusercontent.com/relational-network/repo/main/a.toml?x=1",
            "https://raw.githubusercontent.com/relational-network/repo/main/a.toml#x",
            "https://raw.githubusercontent.com/relational-network/repo//a.toml",
            "https://raw.githubusercontent.com/relational-network/repo",
            "https://raw.githubusercontent.com/relational-network/repo/main/a b.toml",
        ] {
            assert!(check_url(bad).is_err(), "{bad}");
        }
        let long = format!("{ALLOWED_PREFIX}repo/main/{}.toml", "a".repeat(300));
        assert!(check_url(&long).is_err());
    }

    #[test]
    fn only_public_addresses_are_used() {
        for public in ["185.199.108.133", "8.8.8.8", "2606:50c0:8000::154"] {
            assert!(is_public(public.parse().unwrap()), "{public}");
        }
        for private in [
            "10.0.0.1",
            "172.16.5.4",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "192.0.0.8",
            "240.0.0.1",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:10.0.0.1",
            "::ffff:169.254.169.254",
        ] {
            assert!(!is_public(private.parse().unwrap()), "{private}");
        }
    }
}
