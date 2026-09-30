// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! TLS with `tls-key`.
//!
//! The private key is `tls-key`, released to attested workers and never
//! written anywhere. Its certificate chain lives in the public `tls`
//! container at `{spki_sha256}/chain.pem`, where `spki_sha256` is the
//! lowercase hex SHA-256 of the key's SubjectPublicKeyInfo, so a chain
//! belongs to one key version and clients can pin the key across renewals.
//!
//! While a key has no chain, the worker writes a CSR for the API hostname,
//! signed with `tls-key`, to `{spki_sha256}/csr.pem`, create-only: the first
//! worker's write wins and the others find it there. Something outside the
//! worker (the certificate job) signs it and writes `chain.pem`. The worker
//! checks for the chain every 10 seconds until it has one, then every 5
//! minutes, and swaps a new one in through the certificate resolver, with no
//! restart. It serves a chain only if the leaf's public key is `tls-key`'s;
//! any other chain is ignored and raises an alert.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use chrono::{DateTime, NaiveDateTime, Utc};
use p256::pkcs8::EncodePrivateKey;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PublicKeyData};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::{CertifiedKey, SigningKey};
use sha2::{Digest, Sha256};
use tracing::{error, info, warn};

use crate::store::{Created, ETag, Fetched, ObjectStore};
use crate::tee::EcKey;

/// How often to look for a chain before the first one loads.
const FIRST_CHAIN_POLL: Duration = Duration::from_secs(10);
/// How often to look for a renewed chain.
const CHAIN_POLL: Duration = Duration::from_secs(5 * 60);

/// A chain being served.
struct Served {
    certified: Arc<CertifiedKey>,
    not_after: Option<DateTime<Utc>>,
    etag: ETag,
}

/// `tls-key`, its CSR, and the chain currently served for it.
pub struct Certificates {
    key: Arc<dyn SigningKey>,
    spki_sha256: String,
    csr_pem: String,
    store: Arc<dyn ObjectStore>,
    served: RwLock<Option<Served>>,
    csr_written: AtomicBool,
}

impl fmt::Debug for Certificates {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Certificates")
            .field("spki_sha256", &self.spki_sha256)
            .finish_non_exhaustive()
    }
}

/// What `/health` reports about the served chain.
pub struct Status {
    pub spki_sha256: String,
    pub loaded: bool,
    pub not_after: Option<DateTime<Utc>>,
}

/// The names a CSR asks for: the API hostname and, for `localhost`, the
/// loopback addresses too.
fn csr_names(hostname: &str) -> Vec<String> {
    let mut names = vec![hostname.to_string()];
    if hostname == "localhost" {
        names.extend(["127.0.0.1".to_string(), "::1".to_string()]);
    }
    names
}

impl Certificates {
    /// Prepare `tls_key` to serve `hostname`, with chains and CSRs in `store`
    /// (the `tls` container).
    pub fn new(
        tls_key: &EcKey,
        hostname: &str,
        store: Arc<dyn ObjectStore>,
    ) -> Result<Self, String> {
        let pkcs8 = tls_key
            .secret()
            .to_pkcs8_der()
            .map_err(|e| format!("encoding tls-key: {e}"))?;
        let der = PrivatePkcs8KeyDer::from(pkcs8.as_bytes());
        let key =
            rustls::crypto::aws_lc_rs::sign::any_ecdsa_type(&PrivateKeyDer::Pkcs8(der.clone_key()))
                .map_err(|e| format!("loading tls-key: {e}"))?;
        let key_pair = KeyPair::try_from(&der).map_err(|e| format!("loading tls-key: {e}"))?;
        let spki_sha256 = hex::encode(Sha256::digest(key_pair.subject_public_key_info()));

        let mut params =
            CertificateParams::new(csr_names(hostname)).map_err(|e| format!("CSR names: {e}"))?;
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, hostname);
        let csr_pem = params
            .serialize_request(&key_pair)
            .and_then(|csr| csr.pem())
            .map_err(|e| format!("creating the CSR: {e}"))?;

        Ok(Self {
            key,
            spki_sha256,
            csr_pem,
            store,
            served: RwLock::new(None),
            csr_written: AtomicBool::new(false),
        })
    }

    pub fn spki_sha256(&self) -> &str {
        &self.spki_sha256
    }

    fn chain_path(&self) -> String {
        format!("{}/chain.pem", self.spki_sha256)
    }

    fn csr_path(&self) -> String {
        format!("{}/csr.pem", self.spki_sha256)
    }

    /// Whether a chain is loaded and its leaf hasn't expired.
    pub fn valid(&self) -> bool {
        self.served.read().is_ok_and(|served| {
            served
                .as_ref()
                .is_some_and(|s| s.not_after.is_some_and(|t| t > Utc::now()))
        })
    }

    pub fn status(&self) -> Status {
        let served = self.served.read().ok();
        let served = served.as_ref().and_then(|s| s.as_ref());
        Status {
            spki_sha256: self.spki_sha256.clone(),
            loaded: served.is_some(),
            not_after: served.and_then(|s| s.not_after),
        }
    }

    /// Look for the chain once: load a new one, or write the CSR if there's
    /// none yet.
    pub async fn refresh(&self) -> Result<(), String> {
        let cached = self
            .served
            .read()
            .ok()
            .and_then(|s| s.as_ref().map(|s| s.etag.clone()));
        let path = self.chain_path();
        match self
            .store
            .get(&path, cached.as_ref())
            .await
            .map_err(|e| format!("reading {path}: {e}"))?
        {
            Fetched::NotModified => Ok(()),
            Fetched::Missing => self.write_csr().await,
            Fetched::Found { body, etag } => self.load(&body, etag),
        }
    }

    async fn write_csr(&self) -> Result<(), String> {
        if self.csr_written.load(Ordering::Relaxed) {
            return Ok(());
        }
        let path = self.csr_path();
        let created = self
            .store
            .put_if_absent(&path, self.csr_pem.clone().into())
            .await
            .map_err(|e| format!("writing {path}: {e}"))?;
        match created {
            Created::New(_) => {
                info!(csr = %path, "Wrote a CSR for tls-key; waiting for its chain")
            }
            Created::AlreadyExists => {
                info!(csr = %path, "Waiting for the chain of tls-key's CSR")
            }
        }
        self.csr_written.store(true, Ordering::Relaxed);
        Ok(())
    }

    fn load(&self, pem: &[u8], etag: ETag) -> Result<(), String> {
        let chain = rustls_pemfile::certs(&mut &pem[..])
            .collect::<Result<Vec<CertificateDer<'static>>, _>>()
            .map_err(|e| format!("reading {}: {e}", self.chain_path()))?;
        let Some(leaf) = chain.first() else {
            return Err(format!("{} holds no certificate", self.chain_path()));
        };
        let not_after = not_after(leaf.as_ref());
        let certified = CertifiedKey::new(chain, self.key.clone());
        if let Err(e) = certified.keys_match() {
            error!(
                alert = "tls_chain_mismatch",
                chain = %self.chain_path(),
                error = %e,
                "Ignoring a certificate chain whose key isn't tls-key"
            );
            return Err(format!("{} doesn't match tls-key", self.chain_path()));
        }
        info!(
            chain = %self.chain_path(),
            not_after = ?not_after.map(|t| t.to_rfc3339()),
            "Serving a new certificate chain"
        );
        if let Ok(mut served) = self.served.write() {
            *served = Some(Served {
                certified: Arc::new(certified),
                not_after,
                etag,
            });
        }
        Ok(())
    }

    /// Look for chains in the background, for the process lifetime.
    pub fn spawn(self: &Arc<Self>) {
        let certificates = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                if let Err(e) = certificates.refresh().await {
                    warn!(error = %e, "Certificate chain check failed");
                }
                let loaded = certificates.served.read().is_ok_and(|s| s.is_some());
                tokio::time::sleep(if loaded { CHAIN_POLL } else { FIRST_CHAIN_POLL }).await;
            }
        });
    }

    /// The rustls configuration serving the current chain: TLS 1.3 only
    /// (rustls is built without TLS 1.2), with aws-lc-rs's AES-GCM and
    /// ChaCha20-Poly1305 suites.
    pub fn server_config(self: &Arc<Self>) -> Arc<rustls::ServerConfig> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("aws-lc-rs supports TLS 1.3")
            .with_no_client_auth()
            .with_cert_resolver(self.clone());
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Arc::new(config)
    }
}

impl ResolvesServerCert for Certificates {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.served
            .read()
            .ok()?
            .as_ref()
            .map(|s| s.certified.clone())
    }
}

/// One DER element: its tag, its contents, and what follows it.
fn element(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = match first {
        l if l < 0x80 => (l as usize, rest),
        0x81..=0x84 => {
            let n = (first & 0x7f) as usize;
            if rest.len() < n {
                return None;
            }
            let len = rest[..n]
                .iter()
                .fold(0usize, |acc, b| (acc << 8) | *b as usize);
            (len, &rest[n..])
        }
        _ => return None,
    };
    (rest.len() >= len).then(|| (tag, &rest[..len], &rest[len..]))
}

const SEQUENCE: u8 = 0x30;
const UTC_TIME: u8 = 0x17;
const GENERALIZED_TIME: u8 = 0x18;
const VERSION: u8 = 0xa0;

/// The `notAfter` of a DER certificate.
pub fn not_after(der: &[u8]) -> Option<DateTime<Utc>> {
    let (tag, certificate, _) = element(der)?;
    (tag == SEQUENCE).then_some(())?;
    let (tag, tbs, _) = element(certificate)?;
    (tag == SEQUENCE).then_some(())?;
    let mut fields = tbs;
    if fields.first() == Some(&VERSION) {
        fields = element(fields)?.2;
    }
    // serialNumber, signature, issuer, then validity.
    for _ in 0..3 {
        fields = element(fields)?.2;
    }
    let (tag, validity, _) = element(fields)?;
    (tag == SEQUENCE).then_some(())?;
    let (_, _, rest) = element(validity)?;
    let (tag, time, _) = element(rest)?;
    let text = std::str::from_utf8(time).ok()?;
    let parsed = match tag {
        UTC_TIME => {
            // Two-digit years: 50–99 are 19xx, 00–49 are 20xx (RFC 5280).
            let year: u32 = text.get(..2)?.parse().ok()?;
            let century = if year >= 50 { "19" } else { "20" };
            NaiveDateTime::parse_from_str(&format!("{century}{text}"), "%Y%m%d%H%M%SZ").ok()?
        }
        GENERALIZED_TIME => NaiveDateTime::parse_from_str(text, "%Y%m%d%H%M%SZ").ok()?,
        _ => return None,
    };
    Some(parsed.and_utc())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::store::files::LocalFiles;
    use crate::tee::tests::fixed_key;

    fn der(tag: u8, contents: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if contents.len() < 0x80 {
            out.push(contents.len() as u8);
        } else {
            out.push(0x82);
            out.extend_from_slice(&(contents.len() as u16).to_be_bytes());
        }
        out.extend_from_slice(contents);
        out
    }

    /// A certificate skeleton with the given validity times.
    fn certificate(not_before: (u8, &str), not_after: (u8, &str), padding: usize) -> Vec<u8> {
        let tbs = [
            der(VERSION, &der(0x02, &[2])),
            der(0x02, &[1]),
            der(SEQUENCE, &[]),
            der(SEQUENCE, &vec![0x05; padding]),
            der(
                SEQUENCE,
                &[
                    der(not_before.0, not_before.1.as_bytes()),
                    der(not_after.0, not_after.1.as_bytes()),
                ]
                .concat(),
            ),
        ]
        .concat();
        der(SEQUENCE, &der(SEQUENCE, &tbs))
    }

    #[test]
    fn reads_utc_and_generalized_times() {
        let utc = certificate((UTC_TIME, "250101000000Z"), (UTC_TIME, "351231235959Z"), 0);
        assert_eq!(
            not_after(&utc).unwrap().to_rfc3339(),
            "2035-12-31T23:59:59+00:00"
        );
        let generalized = certificate(
            (UTC_TIME, "250101000000Z"),
            (GENERALIZED_TIME, "20600101000000Z"),
            300,
        );
        assert_eq!(
            not_after(&generalized).unwrap().to_rfc3339(),
            "2060-01-01T00:00:00+00:00"
        );
        assert!(not_after(&utc[..utc.len() - 4]).is_none());
        assert!(not_after(b"not der").is_none());
    }

    /// A self-signed PEM certificate for `key`, valid for `days` from now
    /// (negative: already expired).
    pub(crate) fn self_signed(key: &EcKey, days: i64) -> String {
        use chrono::Datelike;
        let ymd = |t: DateTime<Utc>| rcgen::date_time_ymd(t.year(), t.month() as u8, t.day() as u8);
        let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params.not_before = ymd(Utc::now() - chrono::Duration::days(days.abs() + 2));
        params.not_after = ymd(Utc::now() + chrono::Duration::days(days));
        params.self_signed(&key_pair(key)).unwrap().pem()
    }

    fn key_pair(key: &EcKey) -> KeyPair {
        let pkcs8 = key.secret().to_pkcs8_der().unwrap();
        KeyPair::try_from(&PrivatePkcs8KeyDer::from(pkcs8.as_bytes())).unwrap()
    }

    /// Certificates for test key 3 over `store`.
    fn certificates(store: Arc<LocalFiles>) -> Certificates {
        Certificates::new(&fixed_key(3), "localhost", store).unwrap()
    }

    /// Certificates serving a valid self-signed chain, for readiness tests.
    pub(crate) fn serving() -> Arc<Certificates> {
        let store = Arc::new(LocalFiles::temporary());
        let certificates = certificates(store);
        let pem = self_signed(&fixed_key(3), 30);
        certificates
            .load(pem.as_bytes(), ETag("\"test\"".into()))
            .unwrap();
        Arc::new(certificates)
    }

    async fn body(store: &LocalFiles, path: &str) -> Option<String> {
        match store.get(path, None).await.unwrap() {
            Fetched::Found { body, .. } => Some(String::from_utf8(body.to_vec()).unwrap()),
            _ => None,
        }
    }

    #[tokio::test]
    async fn writes_one_csr_then_serves_only_a_chain_for_tls_key() {
        let store = Arc::new(LocalFiles::temporary());
        let a = certificates(store.clone());
        let b = certificates(store.clone());
        assert_eq!(a.spki_sha256().len(), 64);
        assert_eq!(a.spki_sha256(), b.spki_sha256(), "keyed by the public key");

        a.refresh().await.unwrap();
        b.refresh().await.unwrap();
        let csr = body(&store, &a.csr_path()).await.expect("a CSR");
        assert_eq!(csr, a.csr_pem, "the first write wins");
        let csr_der = rustls_pemfile::csr(&mut csr.as_bytes())
            .unwrap()
            .expect("a PEM CSR");
        let spki = key_pair(&fixed_key(3)).subject_public_key_info();
        assert!(
            csr_der.as_ref().windows(spki.len()).any(|w| w == spki),
            "the CSR is for tls-key"
        );
        assert!(!a.valid() && !a.status().loaded);

        // A chain for another key is ignored.
        let foreign = self_signed(&fixed_key(4), 30);
        store
            .put_if_absent(&a.chain_path(), foreign.into())
            .await
            .unwrap();
        assert!(a.refresh().await.is_err());
        assert!(!a.valid());

        // The right one is served, and swapped when it changes.
        let store = Arc::new(LocalFiles::temporary());
        let c = certificates(store.clone());
        store
            .put_if_absent(&c.chain_path(), self_signed(&fixed_key(3), 30).into())
            .await
            .unwrap();
        c.refresh().await.unwrap();
        assert!(c.valid());
        let first = c.status().not_after.unwrap();
        assert!(first > Utc::now() + chrono::Duration::days(29));
        c.refresh().await.unwrap();

        let Fetched::Found { etag, .. } = store.get(&c.chain_path(), None).await.unwrap() else {
            panic!("chain");
        };
        store
            .put_if_match(
                &c.chain_path(),
                self_signed(&fixed_key(3), 60).into(),
                &etag,
            )
            .await
            .unwrap();
        c.refresh().await.unwrap();
        assert!(c.status().not_after.unwrap() > first + chrono::Duration::days(29));
    }

    #[test]
    fn an_expired_chain_is_loaded_but_not_valid() {
        let store = Arc::new(LocalFiles::temporary());
        let certificates = certificates(store);
        let pem = self_signed(&fixed_key(3), -1);
        certificates
            .load(pem.as_bytes(), ETag("\"x\"".into()))
            .unwrap();
        assert!(certificates.status().loaded);
        assert!(!certificates.valid());
    }

    #[test]
    fn localhost_csrs_also_name_the_loopback_addresses() {
        assert_eq!(csr_names("api.pilot.example"), vec!["api.pilot.example"]);
        assert_eq!(
            csr_names("localhost"),
            vec!["localhost", "127.0.0.1", "::1"]
        );
    }
}
